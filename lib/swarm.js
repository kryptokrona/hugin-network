'use strict'

// hugin-network/swarm: Hugin swarms on upstream hyperdht / hyperswarm, with the Hugin `mid` field
// in the Noise handshake.
//
// Hugin peers put one extra field in the Noise handshake payload,
//
//   flags |= 128, and after every upstream field: mid = fixed64
//
// and refuse any handshake whose `mid` does not verify against the topic base public key, or
// whose remote DHT key is that base public key itself. The
// payload format is the one hyperdht-hugin 1.0.3 introduced. The topic and mid derivation is
// domain-separated (README "Protocol"):
//
//   topicKey = fill32(key)                        (Buffer.alloc(32).fill(key))
//   base     = crypto_sign_seed_keypair(topicKey)
//   topic    = keccak256(UTF-8("hugin/topic") || base.publicKey)        43 bytes in, 32 out
//   mid      = ed25519_sign(UTF-8("hugin/mid") || dhtPublicKey, base)   41-byte message
//
// keccak256 is the original Keccak padding (CryptoNote `cn_fast_hash`). Clients using the
// earlier derivation cannot connect: they look for another topic and sign (and check) the bare
// DHT public key, so they neither find a client on this derivation nor complete a handshake
// with one, in either direction. There is no fallback to the earlier derivation.
//
// How it is added without forking:
//   * `midNoisePayload` (lib/noise-payload.js) wraps upstream `messages.noisePayload`: it
//     encodes/decodes the upstream fields with the upstream codec and handles bit 128 + the
//     trailing 64 bytes itself.
//   * `MidNoiseWrap extends NoiseWrap` uses that codec. It looks up the *local* key pair of the
//     handshake in a `MidRegistry`; only registered identities send a `mid` and verify the
//     remote one. Every other handshake is byte-identical to upstream.
//   * `MidDHT extends HyperDHT` adds `createHandshake` (an option of both `dht.connect()` and
//     `dht.createServer()` in hyperdht 6.x) into every connect/server, so Hyperswarm instances
//     on this DHT get the behaviour for free.
//
// CommonJS and no Node-only APIs: runs under Node and Bare.

const HyperDHT = require('hyperdht')
const NoiseWrap = require('hyperdht/lib/noise-wrap.js')
const Hyperswarm = require('hyperswarm')
const c = require('compact-encoding')
const sodium = require('sodium-universal')
const b4a = require('b4a')
const { keccak256 } = require('js-sha3')
const { MID_FLAG, MID_BYTES, midNoisePayload } = require('./noise-payload.js')
const { TOPIC_DOMAIN, MID_DOMAIN } = require('./constants.js')

const TOPIC_DOMAIN_BYTES = b4a.from(TOPIC_DOMAIN, 'utf8')
const MID_DOMAIN_BYTES = b4a.from(MID_DOMAIN, 'utf8')

// ---------------------------------------------------------------------------------------------
// key helpers (sodium-universal works on Node and Bare)

/**
 * `Buffer.alloc(32).fill(value)` without Buffer: repeats the UTF-8 bytes of a string (or the
 * bytes of a Uint8Array) over 32 bytes. An empty value gives 32 zero bytes, like Buffer.fill.
 */
function fill32(value) {
  let src
  if (typeof value === 'string') src = b4a.from(value, 'utf8')
  else if (value instanceof Uint8Array) src = value
  else throw new TypeError('fill32: value must be a string or a Uint8Array')
  const out = b4a.alloc(32)
  if (src.byteLength === 0) return out
  for (let i = 0; i < 32; i++) out[i] = src[i % src.byteLength]
  return out
}

/** ed25519 key pair from a 32-byte seed (same as `HyperDHT.keyPair(seed)`). */
function keyPairFromSeed(seed) {
  const publicKey = b4a.alloc(32)
  const secretKey = b4a.alloc(64)
  sodium.crypto_sign_seed_keypair(publicKey, secretKey, seed)
  return { publicKey, secretKey }
}

function randomKeyPair() {
  const publicKey = b4a.alloc(32)
  const secretKey = b4a.alloc(64)
  sodium.crypto_sign_keypair(publicKey, secretKey)
  return { publicKey, secretKey }
}

function checkPublicKey(name, publicKey) {
  if (!(publicKey instanceof Uint8Array) || publicKey.byteLength !== 32) {
    throw new TypeError(name + ' must be a 32-byte public key')
  }
}

/**
 * DHT topic for a topic base public key:
 * `keccak256(UTF-8("hugin/topic") || basePublicKey)` (32 bytes).
 */
function huginTopic(basePublicKey) {
  checkPublicKey('huginTopic: basePublicKey', basePublicKey)
  return b4a.from(keccak256(b4a.concat([TOPIC_DOMAIN_BYTES, basePublicKey])), 'hex')
}

/**
 * Everything a Hugin swarm derives from its key (`get_new_peer_keys(key)` in the apps). `key` is
 * the string (or bytes) Hugin passes, already hashed where Hugin hashes (e.g. the node-mesh key
 * is `hex(cn_fast_hash(networkAddress))`).
 */
function huginTopicFromKey(key) {
  const topicKey = fill32(key)
  const base = keyPairFromSeed(topicKey)
  return { topicKey, base, topic: huginTopic(base.publicKey) }
}

/** The message a `mid` signs: `UTF-8("hugin/mid") || dhtPublicKey` (41 bytes). */
function midMessage(dhtPublicKey) {
  checkPublicKey('midMessage: dhtPublicKey', dhtPublicKey)
  return b4a.concat([MID_DOMAIN_BYTES, dhtPublicKey])
}

/** `mid` of a DHT public key: ed25519 detached signature over `midMessage` with the topic base key. */
function signMid(baseSecretKey, dhtPublicKey) {
  const sig = b4a.alloc(MID_BYTES)
  sodium.crypto_sign_detached(sig, midMessage(dhtPublicKey), baseSecretKey)
  return sig
}

/** True if `mid` is the base key's signature over `midMessage(dhtPublicKey)`. */
function verifyMid(mid, dhtPublicKey, basePublicKey) {
  if (!(mid instanceof Uint8Array) || mid.byteLength !== MID_BYTES) return false
  if (!(dhtPublicKey instanceof Uint8Array) || dhtPublicKey.byteLength !== 32) return false
  if (!(basePublicKey instanceof Uint8Array) || basePublicKey.byteLength !== 32) return false
  return sodium.crypto_sign_verify_detached(mid, midMessage(dhtPublicKey), basePublicKey)
}

// ---------------------------------------------------------------------------------------------
// registry

class MidRejectedError extends Error {
  constructor(message) {
    super(message)
    this.name = 'MidRejectedError'
    this.code = 'HUGIN_MID_REJECTED'
  }
}

/**
 * Maps a local DHT public key (hex) to the Hugin identity it belongs to:
 * `{ mid: Uint8Array(64), basePublicKey: Uint8Array(32) | null, topic, onreject? }`.
 * `basePublicKey === null` means "send the given mid, do not verify the remote one" (such an
 * identity may only dial out; it accepts no inbound handshakes).
 * `onreject(localPublicKey, remotePublicKey, reason)` on an entry is called for rejections of
 * that identity only, after the registry-wide `registry.onreject`.
 */
class MidRegistry {
  constructor() {
    this.identities = new Map()
    /** remote public key hex -> { at, reason } of the last mid rejection. */
    this.rejections = new Map()
    this.onreject = null
  }

  add(localPublicKey, entry) {
    this.identities.set(b4a.toString(localPublicKey, 'hex'), entry)
  }

  delete(localPublicKey) {
    this.identities.delete(b4a.toString(localPublicKey, 'hex'))
  }

  get(localPublicKey) {
    if (!localPublicKey) return null
    return this.identities.get(b4a.toString(localPublicKey, 'hex')) || null
  }

  _reject(localPublicKey, remotePublicKey, reason) {
    const key = b4a.toString(remotePublicKey, 'hex')
    this.rejections.set(key, { at: Date.now(), reason })
    if (this.rejections.size > 4096) {
      const first = this.rejections.keys().next().value
      this.rejections.delete(first)
    }
    // A throwing callback must not replace the MidRejectedError the caller is about to throw.
    try {
      if (this.onreject) this.onreject(localPublicKey, remotePublicKey, reason)
    } catch {}
    const id = this.get(localPublicKey)
    try {
      if (id && id.onreject) id.onreject(localPublicKey, remotePublicKey, reason)
    } catch {}
  }

  /** True if `remotePublicKey` failed mid verification within the last `ms`. */
  recentlyRejected(remotePublicKey, ms = 60000) {
    const r = this.rejections.get(b4a.toString(remotePublicKey, 'hex'))
    return !!r && Date.now() - r.at < ms
  }
}

class MidNoiseWrap extends NoiseWrap {
  constructor(registry, keyPair, remotePublicKey) {
    super(keyPair, remotePublicKey)
    this.registry = registry
    this.identity = registry.get(keyPair.publicKey)
    this.remoteMid = null
  }

  /**
   * The identity as the registry has it *now* (an identity added while the handshake is in
   * flight applies to it). One that was registered when the handshake started and has been
   * removed since fails the handshake instead of turning it into a plain one.
   */
  _currentIdentity() {
    const id = this.registry.get(this.keyPair.publicKey)
    if (!id && this.identity) {
      this.registry._reject(this.keyPair.publicKey, this.remotePublicKey || b4a.alloc(32), 'identity removed')
      throw new MidRejectedError('Hugin identity removed during the handshake')
    }
    this.identity = id
    return id
  }

  send(payload) {
    const id = this._currentIdentity()
    const p = id ? { ...payload, mid: id.mid } : payload
    return this.handshake.send(c.encode(midNoisePayload, p))
  }

  recv(buf) {
    const payload = c.decode(midNoisePayload, this.handshake.recv(buf))
    this.remotePublicKey = b4a.toBuffer(this.handshake.rs)
    this.remoteMid = payload.mid
    const id = this._currentIdentity()
    if (id && !id.basePublicKey && !this.isInitiator) {
      // A precomputed mid without the topic key cannot verify anyone: such an identity may dial
      // peers it chose, but must not accept inbound handshakes from anybody (fail closed).
      this.registry._reject(this.keyPair.publicKey, this.remotePublicKey, 'unverifiable identity')
      throw new MidRejectedError('Hugin identity without topic key accepts no inbound handshakes')
    }
    if (id && id.basePublicKey) {
      if (b4a.equals(this.remotePublicKey, id.basePublicKey)) {
        this.registry._reject(this.keyPair.publicKey, this.remotePublicKey, 'base key')
        throw new MidRejectedError('Hugin peer uses the topic base key')
      }
      if (!payload.mid) {
        this.registry._reject(this.keyPair.publicKey, this.remotePublicKey, 'missing mid')
        throw new MidRejectedError('Hugin mid missing')
      }
      if (!verifyMid(payload.mid, this.remotePublicKey, id.basePublicKey)) {
        this.registry._reject(this.keyPair.publicKey, this.remotePublicKey, 'invalid mid')
        throw new MidRejectedError('Hugin mid does not verify')
      }
    }
    return payload
  }
}

/**
 * HyperDHT whose connects and servers use `MidNoiseWrap`. Construct with the usual hyperdht
 * options plus `midRegistry` (created if absent).
 */
class MidDHT extends HyperDHT {
  constructor(opts = {}) {
    super(opts)
    this.midRegistry = opts.midRegistry || new MidRegistry()
    const registry = this.midRegistry
    this._createMidHandshake = (keyPair, remotePublicKey) =>
      new MidNoiseWrap(registry, keyPair, remotePublicKey)
  }

  // The mid handshake is applied last, so caller options (Hyperswarm's, or anyone's) cannot
  // replace it with an unverified one.
  connect(remotePublicKey, opts = {}) {
    return super.connect(remotePublicKey, {
      ...opts,
      createHandshake: this._createMidHandshake
    })
  }

  createServer(opts, onconnection) {
    if (typeof opts === 'function') return this.createServer({}, opts)
    return super.createServer({ ...(opts || {}), createHandshake: this._createMidHandshake }, onconnection)
  }
}

/**
 * A MidDHT that several Hyperswarm instances share (one per room or DM swarm, each with its own
 * DHT key pair and Hugin identity). Hyperswarm#destroy, #suspend and #resume call the DHT's
 * `destroy`, `suspend` and `resume`; on this class those calls do nothing, so one swarm closing or
 * suspending leaves the others running. The owner closes, suspends and resumes the DHT itself
 * with `destroyShared`, `suspendShared` and `resumeShared` (a suspend also suspends the servers
 * of every swarm on it, a resume resumes them).
 */
class SharedMidDHT extends MidDHT {
  constructor(opts = {}) {
    super(opts)
    this.shared = true
    this._destroying = null
  }

  /** Called by Hyperswarm#destroy of a swarm on this DHT: does nothing (see destroyShared). */
  destroy() {
    return this._destroying ? this._destroying.then(noop, noop) : Promise.resolve()
  }

  /** Called by Hyperswarm#suspend of a swarm on this DHT: does nothing (see suspendShared). */
  suspend() {
    return Promise.resolve()
  }

  /** Called by Hyperswarm#resume of a swarm on this DHT: does nothing (see resumeShared). */
  resume() {
    return Promise.resolve()
  }

  /** Destroys the DHT (once; every call returns the same promise). */
  destroyShared(opts) {
    if (!this._destroying) this._destroying = super.destroy(opts)
    return this._destroying
  }

  /** Suspends the DHT and every server on it. */
  suspendShared(opts) {
    if (this._destroying) return Promise.resolve()
    return super.suspend(opts)
  }

  /** Resumes the DHT and every server on it. */
  resumeShared(opts) {
    if (this._destroying) return Promise.resolve()
    return super.resume(opts)
  }
}

function noop() {}

function isSharedDht(dht) {
  return !!dht && dht.shared === true && typeof dht.destroyShared === 'function'
}

/** Listeners Hyperswarm adds to its DHT in its constructor. */
const SWARM_DHT_EVENTS = ['network-change', 'network-update']

function dhtListeners(dht) {
  const out = new Map()
  for (const name of SWARM_DHT_EVENTS) out.set(name, typeof dht.listeners === 'function' ? dht.listeners(name) : [])
  return out
}

// ---------------------------------------------------------------------------------------------
// conveniences for the Hugin apps

function checkKeyPair(keyPair) {
  const ok =
    keyPair &&
    keyPair.publicKey instanceof Uint8Array &&
    keyPair.publicKey.byteLength === 32 &&
    keyPair.secretKey instanceof Uint8Array &&
    keyPair.secretKey.byteLength === 64 &&
    b4a.equals(keyPair.secretKey.subarray(32), keyPair.publicKey)
  if (!ok) {
    throw new TypeError(
      'keyPair must be an ed25519 { publicKey (32 bytes), secretKey (64 bytes) } pair, ' +
        'e.g. keyPairFromSeed(seed) or HyperDHT.keyPair(seed) (not a keypear Keychain)'
    )
  }
  return keyPair
}

/**
 * `get_new_peer_keys(key)` of the Hugin apps: the topic of `key`, a DHT key pair (fresh random
 * one, or the given fixed `keyPair`) and its `mid` signed with the topic base key.
 * Returns `{ topic, keyPair, sig, base, basePublicKey }`.
 */
function getNewPeerKeys(key, keyPair) {
  const { base, topic } = huginTopicFromKey(key)
  const kp = keyPair ? checkKeyPair(keyPair) : randomKeyPair()
  const sig = signMid(base.secretKey, kp.publicKey)
  return { topic, keyPair: kp, sig, base, basePublicKey: base.publicKey }
}

/**
 * One Hugin swarm (what `new Hyperswarm(opts, sig, dht_keys, keychain)` was in the apps):
 * an upstream Hyperswarm on a MidDHT whose key pair is registered as a Hugin identity for `key`.
 *
 * Without `dht` a new MidDHT is created for this swarm (like the fork, which starts one DHT per
 * swarm); `swarm.destroy()` then also destroys it. With `dht` (a MidDHT) the swarm shares it,
 * and `swarm.destroy()` would destroy the shared DHT too (upstream Hyperswarm behaviour). With a
 * `SharedMidDHT`, `swarm.destroy()` leaves the DHT running and also removes what the swarm left
 * on it: its Hugin identity in the registry, the DHT listeners Hyperswarm added, and its
 * connections (open or still connecting).
 *
 * A registry holds one identity per local DHT public key: two Hugin topics on the same DHT key
 * pair (hugin-node's private + public node) need separate DHTs, which is the default. Swarms
 * without a fixed `keyPair` get a fresh random one each, so any number of them can share a DHT.
 *
 * @param {object} opts
 * @param {string|Uint8Array} opts.key  Hugin swarm key (as passed to get_new_peer_keys)
 * @param {{publicKey, secretKey}} [opts.keyPair]  fixed DHT key pair (default: fresh random)
 * @param {MidDHT} [opts.dht]          existing MidDHT to use
 * @param {Array<{host, port}>} [opts.bootstrap]  DHT bootstrap (only when `dht` is not given)
 * @param {number} [opts.port]         UDP port (only when `dht` is not given)
 * @param {number} [opts.maxPeers]     Hyperswarm `maxPeers`
 * @param {(remotePublicKey, payload) => boolean} [opts.firewall]  Hyperswarm `firewall`
 * @param {MidRegistry} [opts.registry] registry for a new DHT (must be `dht.midRegistry` if both)
 * @param {(localPublicKey, remotePublicKey, reason) => void} [opts.onreject]
 */
function createHuginSwarm(opts = {}) {
  const { key, keyPair, dht, bootstrap, port, maxPeers, firewall, onreject } = opts
  if (key === undefined || key === null) throw new TypeError('createHuginSwarm: key is required')

  let registry = opts.registry || null
  if (dht) {
    // duck-typed so that two installed copies of this module still work together
    if (!dht.midRegistry || typeof dht.midRegistry.get !== 'function' || !dht._createMidHandshake) {
      throw new TypeError('createHuginSwarm: dht must be a MidDHT')
    }
    if (registry && registry !== dht.midRegistry) {
      throw new Error('createHuginSwarm: registry is not the registry of the given dht')
    }
    registry = dht.midRegistry
  }
  if (!registry) registry = new MidRegistry()

  const keys = getNewPeerKeys(key, keyPair)
  const existing = registry.get(keys.keyPair.publicKey)
  if (existing && !(existing.topic && b4a.equals(existing.topic, keys.topic))) {
    throw new Error(
      'createHuginSwarm: this DHT key pair is already a Hugin identity for another topic; ' +
        'use a separate dht (or another key pair)'
    )
  }

  const identity = {
    mid: keys.sig,
    basePublicKey: keys.basePublicKey,
    topic: keys.topic,
    onreject: onreject || null
  }
  registry.add(keys.keyPair.publicKey, identity)

  let swarmDht = dht
  let swarm
  try {
    if (!swarmDht) {
      const dhtOpts = { keyPair: keys.keyPair, midRegistry: registry }
      if (bootstrap) dhtOpts.bootstrap = bootstrap
      if (port) dhtOpts.port = port
      swarmDht = new MidDHT(dhtOpts)
    }
    const swarmOpts = { dht: swarmDht, keyPair: keys.keyPair }
    if (maxPeers !== undefined && maxPeers !== null) swarmOpts.maxPeers = maxPeers
    if (firewall) swarmOpts.firewall = firewall
    const before = isSharedDht(swarmDht) ? dhtListeners(swarmDht) : null
    swarm = new Hyperswarm(swarmOpts)
    if (before) detachOnDestroy(swarm, swarmDht, before, registry, keys.keyPair.publicKey, identity)
  } catch (err) {
    if (registry.get(keys.keyPair.publicKey) === identity) registry.delete(keys.keyPair.publicKey)
    if (swarmDht && !dht) swarmDht.destroy().catch(() => {})
    throw err
  }

  return {
    swarm,
    dht: swarmDht,
    topic: keys.topic,
    keyPair: keys.keyPair,
    mid: keys.sig,
    basePublicKey: keys.basePublicKey,
    registry,
    identity
  }
}

/**
 * On a shared DHT, `swarm.destroy()` (which leaves the DHT running there) also destroys the
 * swarm's connections, removes the DHT listeners its constructor added and removes its identity
 * from the registry (only when the entry is still this swarm's).
 */
function detachOnDestroy(swarm, dht, before, registry, publicKey, identity) {
  const added = new Map()
  for (const name of SWARM_DHT_EVENTS) {
    const old = before.get(name)
    const now = typeof dht.listeners === 'function' ? dht.listeners(name) : []
    added.set(name, now.filter((fn) => !old.includes(fn)))
  }
  let detached = false
  const detach = () => {
    if (detached) return
    detached = true
    for (const [name, fns] of added) for (const fn of fns) dht.removeListener(name, fn)
    if (registry.get(publicKey) === identity) registry.delete(publicKey)
  }
  const destroy = swarm.destroy
  swarm.destroy = async function (opts) {
    try {
      return await destroy.call(this, opts)
    } finally {
      // Hyperswarm leaves its connections to the DHT's destroy; this DHT stays, so close them here
      const conns = this._allConnections ? [...this._allConnections] : [...(this.connections || [])]
      for (const conn of conns) {
        try {
          conn.destroy()
        } catch {}
      }
      detach()
    }
  }
}

module.exports = {
  TOPIC_DOMAIN,
  MID_DOMAIN,
  MID_FLAG,
  MID_BYTES,
  fill32,
  keyPairFromSeed,
  huginTopic,
  huginTopicFromKey,
  midMessage,
  signMid,
  verifyMid,
  MidRejectedError,
  MidRegistry,
  MidNoiseWrap,
  MidDHT,
  SharedMidDHT,
  isSharedDht,
  getNewPeerKeys,
  createHuginSwarm
}
