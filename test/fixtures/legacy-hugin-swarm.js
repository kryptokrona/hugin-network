'use strict'

// Test-only: the swarm derivation clients used before hugin-network 3.0 (hyperswarm-hugin
// 1.0.4 / hyperdht-hugin 1.0.3, and the 3.0.0 alphas of this package up to alpha.3). The tests
// use it to show that the topic and mid derivation of hugin-network 3.0 (domain-separated)
// keeps such clients out: a different DHT topic and a `mid` neither side accepts. Nothing
// outside test/ may use it; the library has no way back to this derivation.
//
//   topicKey = fill32(key), base = crypto_sign_seed_keypair(topicKey)   (unchanged in 3.0)
//   topic    = fill32(hex(base.publicKey))
//   mid      = ed25519_sign(dhtPublicKey, base.secretKey)               (32-byte message)
//
// The Noise payload format (flag 128 + 64 trailing bytes) did not change, so the payload codec
// is shared with lib/noise-payload.js. Everything else is written out here on purpose, without
// lib/swarm.js. Node and Bare (b4a, sodium-universal).

const HyperDHT = require('hyperdht')
const NoiseWrap = require('hyperdht/lib/noise-wrap.js')
const Hyperswarm = require('hyperswarm')
const c = require('compact-encoding')
const sodium = require('sodium-universal')
const b4a = require('b4a')
const { midNoisePayload } = require('../../lib/noise-payload.js')

/** Buffer.alloc(32).fill(value) */
function legacyFill32(value) {
  const src = typeof value === 'string' ? b4a.from(value, 'utf8') : value
  const out = b4a.alloc(32)
  if (src.byteLength === 0) return out
  for (let i = 0; i < 32; i++) out[i] = src[i % src.byteLength]
  return out
}

function seedKeyPair(seed) {
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

/** `{ topicKey, base, topic }` the way clients before hugin-network 3.0 derived them. */
function legacyTopicFromKey(key) {
  const topicKey = legacyFill32(key)
  const base = seedKeyPair(topicKey)
  const topic = legacyFill32(b4a.toString(base.publicKey, 'hex'))
  return { topicKey, base, topic }
}

/** Earlier `mid`: ed25519 over the bare 32-byte DHT public key. */
function legacySignMid(baseSecretKey, dhtPublicKey) {
  const sig = b4a.alloc(64)
  sodium.crypto_sign_detached(sig, dhtPublicKey, baseSecretKey)
  return sig
}

function legacyVerifyMid(mid, dhtPublicKey, basePublicKey) {
  if (!mid || mid.byteLength !== 64) return false
  return sodium.crypto_sign_verify_detached(mid, dhtPublicKey, basePublicKey)
}

/**
 * Noise handshake of an earlier-version client: sends its `mid`, refuses a peer whose `mid` does
 * not verify the earlier way. `identity = { mid, basePublicKey, onreject(remotePublicKey, reason) }`.
 */
class LegacyNoiseWrap extends NoiseWrap {
  constructor(identity, keyPair, remotePublicKey) {
    super(keyPair, remotePublicKey)
    this.identity = identity
  }

  send(payload) {
    return this.handshake.send(c.encode(midNoisePayload, { ...payload, mid: this.identity.mid }))
  }

  recv(buf) {
    const payload = c.decode(midNoisePayload, this.handshake.recv(buf))
    this.remotePublicKey = b4a.toBuffer(this.handshake.rs)
    if (!payload.mid || !legacyVerifyMid(payload.mid, this.remotePublicKey, this.identity.basePublicKey)) {
      const reason = payload.mid ? 'invalid mid' : 'missing mid'
      try {
        if (this.identity.onreject) this.identity.onreject(this.remotePublicKey, reason)
      } catch {}
      throw new Error('earlier-version Hugin mid check failed: ' + reason)
    }
    return payload
  }
}

/** HyperDHT whose every connect and server uses `LegacyNoiseWrap` for `opts.legacyIdentity`. */
class LegacyDHT extends HyperDHT {
  constructor(opts = {}) {
    super(opts)
    const identity = opts.legacyIdentity
    this._createLegacyHandshake = (keyPair, remotePublicKey) =>
      new LegacyNoiseWrap(identity, keyPair, remotePublicKey)
  }

  connect(remotePublicKey, opts = {}) {
    return super.connect(remotePublicKey, { ...opts, createHandshake: this._createLegacyHandshake })
  }

  createServer(opts, onconnection) {
    if (typeof opts === 'function') return this.createServer({}, opts)
    return super.createServer({ ...(opts || {}), createHandshake: this._createLegacyHandshake }, onconnection)
  }
}

/**
 * An earlier-version Hugin swarm: a plain upstream Hyperswarm on a LegacyDHT (its own DHT node,
 * destroyed with the swarm). Returns `{ swarm, dht, topic, keyPair, mid, basePublicKey }`.
 */
function createLegacySwarm({ key, keyPair, bootstrap, onreject } = {}) {
  const t = legacyTopicFromKey(key)
  const kp = keyPair || randomKeyPair()
  const mid = legacySignMid(t.base.secretKey, kp.publicKey)
  const identity = { mid, basePublicKey: t.base.publicKey, onreject: onreject || null }
  const dht = new LegacyDHT({ bootstrap, keyPair: kp, legacyIdentity: identity })
  const swarm = new Hyperswarm({ dht, keyPair: kp })
  return { swarm, dht, topic: t.topic, keyPair: kp, mid, basePublicKey: t.base.publicKey }
}

module.exports = {
  legacyFill32,
  legacyTopicFromKey,
  legacySignMid,
  legacyVerifyMid,
  LegacyNoiseWrap,
  LegacyDHT,
  createLegacySwarm
}
