'use strict'

// Tests of hugin-network/swarm.
//
// The topic and mid derivation of hugin-network 3.0 is domain-separated; clients using the earlier
// derivation cannot connect. The tests that used to check byte equality with hyperswarm-hugin
// 1.0.4 / hyperdht-hugin 1.0.3 (topic vectors, mids, testnet) now check that the earlier
// derivation (test/fixtures/legacy-hugin-swarm.js) and the current one never meet, while what did
// not change (topic key, base key, Noise payload format) still matches.

const test = require('brittle')
const b4a = require('b4a')
const c = require('compact-encoding')
const sodium = require('sodium-universal')
const { keccak256 } = require('js-sha3')
const Hyperswarm = require('hyperswarm')
const createTestnet = require('hyperdht/testnet.js')
const { midNoisePayload } = require('../lib/noise-payload.js')
const {
  TOPIC_DOMAIN: SWARM_TOPIC_DOMAIN,
  MID_DOMAIN: SWARM_MID_DOMAIN,
  MID_FLAG,
  MID_BYTES,
  fill32,
  keyPairFromSeed,
  huginTopic,
  huginTopicFromKey,
  midMessage,
  signMid,
  verifyMid,
  MidRegistry,
  MidNoiseWrap,
  MidDHT,
  getNewPeerKeys,
  createHuginSwarm
} = require('../lib/swarm.js')
const keys = require('../lib/keys.js')
const { PROTOCOL, TOPIC_DOMAIN, MID_DOMAIN } = require('../lib/constants.js')
const {
  legacyTopicFromKey,
  legacySignMid,
  legacyVerifyMid,
  LegacyNoiseWrap,
  createLegacySwarm
} = require('./fixtures/legacy-hugin-swarm.js')
const VEC = require('./fixtures/derivation-vectors.inputs.json')

const hex = (buf) => b4a.toString(buf, 'hex')
const noop = () => {}
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms))

const NETWORK_ADDRESS = 'xkr96c0f8a36e951b399681d447922f6c54c28c6ef3cad1c65d3568008151337'
// hex(cn_fast_hash(NETWORK_ADDRESS)) as hugin-node computes it (kryptokrona-utils), see
// xkr crates/xkr-p2p-hyper/src/topic.rs `hugin_vectors`.
const NODE_MESH_KEY = 'c9b4d847ffa97a1d49c74d8085b9529c191080704e325cef9229717a8f769614'

// ---------------------------------------------------------------------------------------------
// independent reference of the derivation (js-sha3 + sodium directly, nothing from lib/swarm.js)

const REF_TOPIC_DOMAIN = 'hugin/topic'
const REF_MID_DOMAIN = 'hugin/mid'

function refFill32(key) {
  const src = typeof key === 'string' ? b4a.from(key, 'utf8') : key
  const out = b4a.alloc(32)
  for (let i = 0; i < 32; i++) out[i] = src[i % src.byteLength]
  return out
}

function refSeedKeyPair(seed) {
  const publicKey = b4a.alloc(32)
  const secretKey = b4a.alloc(64)
  sodium.crypto_sign_seed_keypair(publicKey, secretKey, seed)
  return { publicKey, secretKey }
}

function refSha512(bytes) {
  const out = b4a.alloc(64)
  sodium.crypto_hash_sha512(out, bytes)
  return out
}

/** The derivation from first principles: topic key, base key, topic and the mid of `dht`. */
function refDerive(key, dht) {
  const topicKey = refFill32(key)
  const base = refSeedKeyPair(topicKey)
  const topicInput = b4a.concat([b4a.from(REF_TOPIC_DOMAIN, 'utf8'), base.publicKey])
  const topic = b4a.from(keccak256(topicInput), 'hex')
  const midInput = b4a.concat([b4a.from(REF_MID_DOMAIN, 'utf8'), dht.publicKey])
  const mid = b4a.alloc(64)
  sodium.crypto_sign_detached(mid, midInput, base.secretKey)
  return { topicKey, base, topicInput, topic, midInput, mid }
}

const keyHex = (key) => (typeof key === 'string' ? hex(b4a.from(key, 'utf8')) : hex(key))

/** Swarm key of one vector input: `ref` computed here, `lib` and `libTopic` through lib/keys.js. */
function vectorKey(v) {
  if (v.invite) {
    return { ref: refSha512(b4a.from(v.invite, 'hex')), lib: keys.roomSwarmKey(v.invite), libTopic: keys.roomTopic(v.invite) }
  }
  if (v.derivation_hash) {
    return {
      ref: refSha512(b4a.from(v.derivation_hash, 'hex')),
      lib: keys.dmSwarmKey(v.derivation_hash),
      libTopic: keys.dmTopic(v.derivation_hash)
    }
  }
  if (v.name === 'public nodes') return { ref: v.key, lib: keys.nodeSwarmKey({ pub: true }), libTopic: keys.nodeTopic({ pub: true }) }
  if (v.name === 'private node') return { ref: v.key, lib: keys.nodeSwarmKey({ address: v.key }), libTopic: keys.nodeTopic({ address: v.key }) }
  return { ref: v.key, lib: v.key, libTopic: keys.topicFromSwarmKey(v.key) }
}

// ---------------------------------------------------------------------------------------------
// domains and vectors

test('derivation domains; the app channel name is unchanged', (t) => {
  t.is(TOPIC_DOMAIN, 'hugin/topic')
  t.is(MID_DOMAIN, 'hugin/mid')
  t.is(SWARM_TOPIC_DOMAIN, TOPIC_DOMAIN, 'hugin-network/swarm re-exports the topic domain')
  t.is(SWARM_MID_DOMAIN, MID_DOMAIN, 'hugin-network/swarm re-exports the mid domain')
  t.is(PROTOCOL, 'hugin-messages', 'protomux channel name unchanged')
  t.is(VEC.topic_domain, TOPIC_DOMAIN)
  t.is(VEC.mid_domain, MID_DOMAIN)
})

test('derivation vectors: lib = independent keccak256 + sodium computation', (t) => {
  const dht = refSeedKeyPair(b4a.from(VEC.dht_seed, 'hex'))
  t.is(hex(dht.publicKey), VEC.dht_public_key, 'DHT key pair of seed 32 x 0x07')
  t.alike(keyPairFromSeed(b4a.from(VEC.dht_seed, 'hex')), dht, 'keyPairFromSeed')
  t.is(VEC.keys.length, 5)

  const out = {
    topic_domain: TOPIC_DOMAIN,
    mid_domain: MID_DOMAIN,
    dht_seed: VEC.dht_seed,
    dht_public_key: hex(dht.publicKey),
    keys: []
  }
  for (const v of VEC.keys) {
    if (v.network_address) {
      t.is(v.network_address, NETWORK_ADDRESS)
      t.is(keccak256(b4a.from(v.network_address, 'utf8')), v.key, 'node mesh key = hex(cn_fast_hash(NETWORK_ADDRESS))')
      t.is(v.key, NODE_MESH_KEY)
    }
    const k = vectorKey(v)
    t.is(keyHex(k.lib), keyHex(k.ref), v.name + ': swarm key')

    const ref = refDerive(k.ref, dht)
    t.is(ref.topicInput.byteLength, 43, v.name + ': 11 + 32 topic input bytes')
    t.is(ref.midInput.byteLength, 41, v.name + ': 9 + 32 mid message bytes')

    const h = huginTopicFromKey(k.lib)
    t.is(hex(h.topicKey), hex(ref.topicKey), v.name + ': topic key')
    t.is(hex(h.base.publicKey), hex(ref.base.publicKey), v.name + ': base public key')
    t.is(hex(h.topic), hex(ref.topic), v.name + ': topic')
    t.is(hex(huginTopic(h.base.publicKey)), hex(ref.topic), v.name + ': huginTopic')
    t.is(hex(k.libTopic.discoveryKey), hex(ref.topic), v.name + ': keys discoveryKey')
    t.is(k.libTopic.topic, hex(ref.base.publicKey), v.name + ': keys topic string = hex(base)')

    const p = getNewPeerKeys(k.lib, dht)
    t.is(hex(p.topic), hex(ref.topic), v.name + ': getNewPeerKeys topic')
    t.is(hex(p.sig), hex(ref.mid), v.name + ': mid')
    t.is(hex(signMid(h.base.secretKey, dht.publicKey)), hex(ref.mid), v.name + ': signMid')
    t.is(hex(midMessage(dht.publicKey)), hex(ref.midInput), v.name + ': midMessage')
    t.ok(verifyMid(ref.mid, dht.publicKey, ref.base.publicKey), v.name + ': verifyMid')

    // separation from the earlier derivation of the same key
    const old = legacyTopicFromKey(k.lib)
    t.alike(old.base.publicKey, h.base.publicKey, v.name + ': base key unchanged')
    t.unlike(old.topic, h.topic, v.name + ': topic differs from the earlier one')
    t.absent(verifyMid(legacySignMid(old.base.secretKey, dht.publicKey), dht.publicKey, h.base.publicKey), v.name + ': earlier mid refused')

    out.keys.push({
      name: v.name,
      swarm_key: keyHex(k.ref),
      topic_key: hex(ref.topicKey),
      base_public_key: hex(ref.base.publicKey),
      topic_input: hex(ref.topicInput),
      topic: hex(ref.topic),
      mid_message: hex(ref.midInput),
      mid: hex(ref.mid)
    })
  }
  // for the export to test/fixtures/derivation-vectors.json and the Rust side
  t.comment('derivation-vectors ' + JSON.stringify(out))
})

// ---------------------------------------------------------------------------------------------
// separation from the earlier derivation

// Values of the earlier derivation (hyperswarm-hugin 1.0.4 / hyperdht-hugin 1.0.3, computed
// with hugin-node's code path: kryptokrona-utils cn_fast_hash(toHex(s)), Buffer.alloc(32).fill(key),
// keypear.from(hyperdht-hugin.keyPair(secret))). The topic key and base key are still equal to
// them; the topic is not.
const LEGACY_TOPIC_VECTORS = [
  {
    name: 'node mesh: hex(cn_fast_hash(NETWORK_ADDRESS))',
    key: NODE_MESH_KEY,
    seed: '6339623464383437666661393761316434396337346438303835623935323963',
    basePub: 'a341b41cb1f327f229cc1a71596094e1bd05f0256d836ed135b6fe377fb874f3',
    topic: '6133343162343163623166333237663232396363316137313539363039346531'
  },
  {
    name: 'public nodes: NETWORK_ADDRESS',
    key: NETWORK_ADDRESS,
    seed: '786b723936633066386133366539353162333939363831643434373932326636',
    basePub: '5f70ed4fd39ca7305ba72377d815dade9083749f3fd9d18b99c618cf81146112',
    topic: '3566373065643466643339636137333035626137323337376438313564616465'
  },
  {
    name: 'private node: the node XKR address',
    key: 'SEKReYU57DLLvUjNzmjVhaK7jqc8SdZZ3cyKJS5f4gWXK4NQQYChzKUUwzCGhgqUPkWQypeR94rqpgMPjXWG9ijnZKNw2LWXnZU',
    seed: '53454b526559553537444c4c76556a4e7a6d6a5668614b376a71633853645a5a',
    basePub: '4137128773a971b710878df51973b42358b37fb016b6ee3bd837cdd356c42b95',
    topic: '3431333731323837373361393731623731303837386466353139373362343233'
  },
  {
    name: 'short key repeats like Buffer.fill',
    key: 'abc',
    seed: '6162636162636162636162636162636162636162636162636162636162636162',
    basePub: '204aaed5e86cd99a149c0d51d033261996cdbd67a2becb24dfaa43a4828181e8',
    topic: '3230346161656435653836636439396131343963306435316430333332363139'
  }
]

test('separation: same key and base key as the earlier derivation, different DHT topic', (t) => {
  const dht = keyPairFromSeed(b4a.alloc(32, 7))
  for (const v of LEGACY_TOPIC_VECTORS) {
    const old = legacyTopicFromKey(v.key)
    t.is(hex(old.topicKey), v.seed, v.name + ': fixture topic key = earlier vector')
    t.is(hex(old.base.publicKey), v.basePub, v.name + ': fixture base key = earlier vector')
    t.is(hex(old.topic), v.topic, v.name + ': fixture topic = earlier vector')

    const h = huginTopicFromKey(v.key)
    t.is(hex(h.topicKey), v.seed, v.name + ': topic key unchanged')
    t.is(hex(h.base.publicKey), v.basePub, v.name + ': base public key unchanged')
    t.not(hex(h.topic), v.topic, v.name + ': topic is not the earlier topic')
    t.is(hex(h.topic), hex(refDerive(v.key, dht).topic), v.name + ': topic = reference')

    const k = getNewPeerKeys(v.key)
    t.not(hex(k.topic), v.topic, v.name + ': getNewPeerKeys topic is not the earlier topic')
    t.is(hex(k.basePublicKey), v.basePub, v.name + ': getNewPeerKeys base')
  }
})

test('fill32 behaves like Buffer.alloc(32).fill(value)', async (t) => {
  t.is(hex(fill32('')), '00'.repeat(32))
  t.is(hex(fill32(b4a.from('abc'))), LEGACY_TOPIC_VECTORS[3].seed, 'bytes repeat like a string')
  const long = b4a.alloc(40)
  for (let i = 0; i < long.byteLength; i++) long[i] = i
  t.alike(fill32(long), long.subarray(0, 32), 'longer input is truncated')
  // the full private-node invite (address + hex dht key) gives the same topic as the address
  const address = LEGACY_TOPIC_VECTORS[2].key
  const invite = address + 'ab'.repeat(32)
  t.alike(huginTopicFromKey(invite).topic, huginTopicFromKey(address).topic)
  await t.exception.all(() => fill32(42), /string or a Uint8Array/)
})

// ---------------------------------------------------------------------------------------------
// mid

test('mid sign/verify round trip', async (t) => {
  t.is(MID_FLAG, 128)
  t.is(MID_BYTES, 64)
  const base = keyPairFromSeed(b4a.alloc(32, 1))
  const dht = keyPairFromSeed(b4a.alloc(32, 2))
  const other = keyPairFromSeed(b4a.alloc(32, 3))
  const mid = signMid(base.secretKey, dht.publicKey)
  t.is(mid.byteLength, 64)
  t.ok(verifyMid(mid, dht.publicKey, base.publicKey), 'valid mid verifies')
  t.absent(verifyMid(mid, other.publicKey, base.publicKey), 'mid of another dht key')
  t.absent(verifyMid(mid, dht.publicKey, other.publicKey), 'mid of another topic')
  t.absent(verifyMid(null, dht.publicKey, base.publicKey), 'no mid')
  t.absent(verifyMid(mid.subarray(0, 63), dht.publicKey, base.publicKey), 'short mid')
  t.absent(verifyMid(mid, dht.publicKey.subarray(0, 31), base.publicKey), 'short dht key')
  t.absent(verifyMid(mid, dht.publicKey, null), 'no base key')

  // what is signed: UTF-8("hugin/mid") || dhtPublicKey
  const message = b4a.concat([b4a.from('hugin/mid', 'utf8'), dht.publicKey])
  t.alike(midMessage(dht.publicKey), message)
  t.ok(sodium.crypto_sign_verify_detached(mid, message, base.publicKey), 'signature over the 41-byte message')
  await t.exception.all(() => midMessage(b4a.alloc(31)), /32-byte public key/)
  await t.exception.all(() => huginTopic(b4a.alloc(31)), /32-byte public key/)
})

test('separation: an earlier mid fails verification and a current mid fails the earlier check', (t) => {
  const base = keyPairFromSeed(b4a.alloc(32, 1))
  const dht = keyPairFromSeed(b4a.alloc(32, 2))
  const mid = signMid(base.secretKey, dht.publicKey)
  const old = legacySignMid(base.secretKey, dht.publicKey)
  t.unlike(mid, old, 'different signatures with the same base key')
  t.ok(verifyMid(mid, dht.publicKey, base.publicKey), 'current mid accepted')
  t.absent(verifyMid(old, dht.publicKey, base.publicKey), 'earlier mid refused')
  t.ok(legacyVerifyMid(old, dht.publicKey, base.publicKey), 'the earlier check accepts the earlier mid')
  t.absent(legacyVerifyMid(mid, dht.publicKey, base.publicKey), 'the earlier check refuses a current mid')
})

test('getNewPeerKeys: random or fixed DHT key pair, mid signed by the topic key', async (t) => {
  const a = getNewPeerKeys(NETWORK_ADDRESS)
  const b = getNewPeerKeys(NETWORK_ADDRESS)
  t.unlike(a.keyPair.publicKey, b.keyPair.publicKey, 'fresh random key pair each call')
  t.ok(verifyMid(a.sig, a.keyPair.publicKey, a.basePublicKey))
  t.alike(a.basePublicKey, a.base.publicKey)

  const fixed = keyPairFromSeed(b4a.alloc(32, 9))
  const f = getNewPeerKeys(NETWORK_ADDRESS, fixed)
  t.is(f.keyPair, fixed, 'given key pair is used')
  t.ok(verifyMid(f.sig, fixed.publicKey, f.basePublicKey))
  t.alike(f.sig, signMid(f.base.secretKey, fixed.publicKey), 'ed25519 signatures are deterministic')

  await t.exception.all(() => getNewPeerKeys('k', { publicKey: fixed.publicKey }), /keyPair must be/)
  await t.exception.all(
    () => getNewPeerKeys('k', { publicKey: b4a.alloc(32), secretKey: fixed.secretKey }),
    /keyPair must be/
  )
})

// ---------------------------------------------------------------------------------------------
// wire format

const MID = b4a.from(Array.from({ length: 64 }, (_, i) => i))

// Produced by hyperdht-hugin 1.0.3 lib/messages.js (`c.encode(m.noisePayload, payload)`), copied
// from xkr bridge/test/mid.test.js.
const FORK_VECTORS = [
  {
    payload: {
      error: 0,
      firewall: 1,
      holepunch: null,
      addresses4: [{ host: '192.168.1.10', port: 49737 }],
      addresses6: [],
      udx: { reusableSocket: false, id: 7, seq: 0 },
      secretStream: {},
      relayThrough: null,
      mid: MID
    },
    hex:
      '019a000101c0a8010a49c20100070001' +
      '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f' +
      '202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f'
  },
  {
    payload: {
      error: 0,
      firewall: 1,
      holepunch: null,
      addresses4: [{ host: '192.168.1.10', port: 49737 }],
      addresses6: [],
      udx: { reusableSocket: false, id: 7, seq: 0 },
      secretStream: {},
      relayThrough: null,
      mid: null
    },
    hex: '011a000101c0a8010a49c20100070001'
  },
  {
    payload: {
      error: 0,
      firewall: 0,
      holepunch: {
        id: 3,
        relays: [{ relayAddress: { host: '1.2.3.4', port: 5 }, peerAddress: { host: '5.6.7.8', port: 9 } }]
      },
      addresses4: [],
      addresses6: null,
      udx: { reusableSocket: true, id: 300, seq: 0 },
      secretStream: {},
      relayThrough: null,
      relayAddresses: [{ host: '9.9.9.9', port: 1000 }],
      mid: MID
    },
    hex:
      '01d9000003010102030405000506070809000101fd2c0100010109090909e803' +
      '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f' +
      '202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f'
  }
]

test('noise payload with mid: format unchanged, byte-identical to hyperdht-hugin', (t) => {
  for (const v of FORK_VECTORS) {
    const enc = c.encode(midNoisePayload, v.payload)
    t.is(hex(enc), v.hex)
    const dec = c.decode(midNoisePayload, enc)
    if (v.payload.mid) t.alike(dec.mid, v.payload.mid)
    else t.is(dec.mid, null)
    t.is(dec.udx.id, v.payload.udx.id)
  }
})

test('bytes after the mid are refused', async (t) => {
  const enc = c.encode(midNoisePayload, FORK_VECTORS[0].payload)
  const longer = b4a.concat([enc, b4a.from([0])])
  await t.exception.all(() => c.decode(midNoisePayload, longer), /trailing bytes/)
  t.is(c.decode(midNoisePayload, c.encode(midNoisePayload, FORK_VECTORS[1].payload)).mid, null)
})

// ---------------------------------------------------------------------------------------------
// handshake without a network

const PAYLOAD = FORK_VECTORS[1].payload

function register(registry, keyPair, key) {
  const h = huginTopicFromKey(key)
  registry.add(keyPair.publicKey, {
    mid: signMid(h.base.secretKey, keyPair.publicKey),
    basePublicKey: h.base.publicKey,
    topic: h.topic
  })
}

function rejectionOf(fn) {
  try {
    fn()
  } catch (err) {
    return err
  }
  return null
}

test('full Noise handshake between two identities of the same topic', (t) => {
  const registry = new MidRegistry()
  const a = keyPairFromSeed(b4a.alloc(32, 21))
  const b = keyPairFromSeed(b4a.alloc(32, 22))
  register(registry, a, NETWORK_ADDRESS)
  register(registry, b, NETWORK_ADDRESS)

  const initiator = new MidNoiseWrap(registry, a, b.publicKey)
  const responder = new MidNoiseWrap(registry, b, null)
  const p1 = responder.recv(initiator.send(PAYLOAD))
  t.alike(p1.mid, registry.get(a.publicKey).mid, 'responder got the initiator mid')
  const p2 = initiator.recv(responder.send(PAYLOAD))
  t.alike(p2.mid, registry.get(b.publicKey).mid, 'initiator got the responder mid')
  t.alike(initiator.final().tx, responder.final().rx, 'same session keys')
})

test('wrong, missing and unverifiable mids are rejected', (t) => {
  const a = keyPairFromSeed(b4a.alloc(32, 21))
  const b = keyPairFromSeed(b4a.alloc(32, 22))

  {
    // initiator signs for another topic
    const registry = new MidRegistry()
    const seen = []
    registry.onreject = (local, remote, reason) => seen.push(reason)
    register(registry, a, 'another topic')
    register(registry, b, NETWORK_ADDRESS)
    const msg = new MidNoiseWrap(registry, a, b.publicKey).send(PAYLOAD)
    const err = rejectionOf(() => new MidNoiseWrap(registry, b, null).recv(msg))
    t.is(err && err.code, 'HUGIN_MID_REJECTED', 'wrong mid')
    t.alike(seen, ['invalid mid'])
    t.ok(registry.recentlyRejected(a.publicKey))
  }
  {
    // initiator is a plain upstream peer
    const registry = new MidRegistry()
    register(registry, b, NETWORK_ADDRESS)
    const msg = new MidNoiseWrap(registry, a, b.publicKey).send(PAYLOAD)
    const err = rejectionOf(() => new MidNoiseWrap(registry, b, null).recv(msg))
    t.is(err && err.code, 'HUGIN_MID_REJECTED', 'missing mid')
  }
  {
    // a precomputed mid without the topic key accepts nobody
    const registry = new MidRegistry()
    registry.add(b.publicKey, { mid: MID, basePublicKey: null, topic: b4a.alloc(32) })
    const msg = new MidNoiseWrap(registry, a, b.publicKey).send(PAYLOAD)
    const err = rejectionOf(() => new MidNoiseWrap(registry, b, null).recv(msg))
    t.is(err && err.code, 'HUGIN_MID_REJECTED', 'unverifiable identity')
  }
  {
    // an identity removed during the handshake fails it instead of skipping verification
    const registry = new MidRegistry()
    register(registry, a, NETWORK_ADDRESS)
    register(registry, b, NETWORK_ADDRESS)
    const responder = new MidNoiseWrap(registry, b, null)
    registry.delete(b.publicKey)
    const msg = new MidNoiseWrap(registry, a, b.publicKey).send(PAYLOAD)
    const err = rejectionOf(() => responder.recv(msg))
    t.is(err && err.code, 'HUGIN_MID_REJECTED', 'identity removed')
  }
  {
    // unregistered key pairs speak plain upstream (no mid sent, nothing verified)
    const registry = new MidRegistry()
    const msg = new MidNoiseWrap(registry, a, b.publicKey).send(PAYLOAD)
    const payload = new MidNoiseWrap(registry, b, null).recv(msg)
    t.is(payload.mid, null)
  }
})

test('separation: earlier-derivation and current peers fail the Noise handshake both ways', (t) => {
  const key = NETWORK_ADDRESS
  const a = keyPairFromSeed(b4a.alloc(32, 21))
  const old = keyPairFromSeed(b4a.alloc(32, 23))
  const old2 = keyPairFromSeed(b4a.alloc(32, 24))

  const registry = new MidRegistry()
  const seen = []
  registry.onreject = (local, remote, reason) => seen.push([hex(remote), reason])
  register(registry, a, key)

  const earlier = legacyTopicFromKey(key)
  const oldSeen = []
  const legacyIdentity = (kp) => ({
    mid: legacySignMid(earlier.base.secretKey, kp.publicKey),
    basePublicKey: earlier.base.publicKey,
    onreject: (remote, reason) => oldSeen.push([hex(remote), reason])
  })

  {
    // earlier-derivation initiator -> current responder
    const msg = new LegacyNoiseWrap(legacyIdentity(old), old, a.publicKey).send(PAYLOAD)
    const err = rejectionOf(() => new MidNoiseWrap(registry, a, null).recv(msg))
    t.is(err && err.code, 'HUGIN_MID_REJECTED', 'current responder refuses')
    t.alike(seen, [[hex(old.publicKey), 'invalid mid']])
  }
  {
    // current initiator -> earlier-derivation responder
    const msg = new MidNoiseWrap(registry, a, old.publicKey).send(PAYLOAD)
    const err = rejectionOf(() => new LegacyNoiseWrap(legacyIdentity(old), old, null).recv(msg))
    t.ok(err, 'earlier-derivation responder refuses')
    t.alike(oldSeen, [[hex(a.publicKey), 'invalid mid']])
  }
  {
    // control: two earlier-derivation peers still complete it with each other (the fixture works)
    const initiator = new LegacyNoiseWrap(legacyIdentity(old), old, old2.publicKey)
    const responder = new LegacyNoiseWrap(legacyIdentity(old2), old2, null)
    responder.recv(initiator.send(PAYLOAD))
    initiator.recv(responder.send(PAYLOAD))
    t.alike(initiator.final().tx, responder.final().rx, 'earlier peers agree on session keys')
    t.is(oldSeen.length, 1, 'no further rejections')
  }
})

// ---------------------------------------------------------------------------------------------
// end to end on a local testnet

async function waitFor(fn, ms = 30000) {
  const start = Date.now()
  while (!fn()) {
    if (Date.now() - start > ms) throw new Error('timeout')
    await new Promise((resolve) => setTimeout(resolve, 50))
  }
}

function watch(swarm, log) {
  swarm.on('connection', (conn) => {
    const remote = hex(conn.remotePublicKey)
    log.connections.push(remote)
    conn.on('error', noop)
    conn.on('data', (data) => log.data.push([remote, b4a.toString(data)]))
    conn.write(b4a.from('hello'))
  })
}

const newLog = () => ({ connections: [], data: [] })

test(
  'same key connects; a wrong mid and a plain Hyperswarm are rejected',
  { timeout: 120000 },
  async (t) => {
    const testnet = await createTestnet(3, t.teardown)
    const { bootstrap } = testnet

    const rejects = []
    const onreject = (name) => (local, remote, reason) =>
      rejects.push({ name, remote: hex(remote), reason })

    const a = createHuginSwarm({ key: NETWORK_ADDRESS, bootstrap, onreject: onreject('a') })
    t.teardown(() => a.swarm.destroy())
    const b = createHuginSwarm({ key: NETWORK_ADDRESS, bootstrap, onreject: onreject('b') })
    t.teardown(() => b.swarm.destroy())

    t.alike(a.topic, huginTopicFromKey(NETWORK_ADDRESS).topic)
    t.ok(a.dht instanceof MidDHT)
    t.is(a.registry.get(a.keyPair.publicKey), a.identity)
    t.ok(verifyMid(a.mid, a.keyPair.publicKey, a.basePublicKey))

    const logA = newLog()
    const logB = newLog()
    watch(a.swarm, logA)
    watch(b.swarm, logB)

    await a.swarm.join(a.topic, { server: true, client: true }).flushed()
    await b.swarm.join(b.topic, { server: true, client: true }).flushed()

    await waitFor(() => logA.data.length > 0 && logB.data.length > 0)
    t.ok(logA.connections.includes(hex(b.keyPair.publicKey)), 'a sees b')
    t.ok(logB.connections.includes(hex(a.keyPair.publicKey)), 'b sees a')
    t.alike(logA.data[0], [hex(b.keyPair.publicKey), 'hello'], 'data flows b -> a')
    t.alike(logB.data[0], [hex(a.keyPair.publicKey), 'hello'], 'data flows a -> b')

    // a Hugin peer whose mid is signed for another key, dialing a's topic
    const wrong = createHuginSwarm({
      key: 'some other hugin key',
      bootstrap,
      onreject: onreject('wrong')
    })
    t.teardown(() => wrong.swarm.destroy())
    const logWrong = newLog()
    watch(wrong.swarm, logWrong)
    wrong.swarm.join(a.topic, { server: false, client: true })

    // a plain upstream Hyperswarm (no mid at all) dialing a's topic
    const plain = new Hyperswarm({ bootstrap })
    t.teardown(() => plain.destroy())
    const logPlain = newLog()
    watch(plain, logPlain)
    plain.join(a.topic, { server: false, client: true })

    const wrongKey = hex(wrong.keyPair.publicKey)
    const plainKey = hex(plain.keyPair.publicKey)
    await waitFor(
      () =>
        rejects.some((r) => r.remote === wrongKey && r.reason === 'invalid mid') &&
        rejects.some((r) => r.remote === plainKey && r.reason === 'missing mid')
    )
    t.pass('onreject fired for the wrong mid and for the plain peer')
    t.ok(a.registry.recentlyRejected(wrong.keyPair.publicKey) || b.registry.recentlyRejected(wrong.keyPair.publicKey))

    // give any (wrongly) accepted connection time to show up
    await new Promise((resolve) => setTimeout(resolve, 1000))
    t.absent(logA.connections.includes(wrongKey) || logB.connections.includes(wrongKey), 'no connection to wrong')
    t.absent(logA.connections.includes(plainKey) || logB.connections.includes(plainKey), 'no connection to plain')
    t.is(logWrong.connections.length, 0, 'wrong never connected')
    t.is(logPlain.connections.length, 0, 'plain never connected')
    t.ok(logA.connections.every((k) => k === hex(b.keyPair.publicKey)), 'a only has b')
    t.ok(logB.connections.every((k) => k === hex(a.keyPair.publicKey)), 'b only has a')
  }
)

test(
  'firewall passthrough (private-node invite check) and one identity per key pair',
  { timeout: 120000 },
  async (t) => {
    const testnet = await createTestnet(3, t.teardown)
    const { bootstrap } = testnet
    const address = LEGACY_TOPIC_VECTORS[2].key

    // two "private nodes" on the same topic with fixed key pairs (hugin-node derives its own from
    // the view key); only the one in the invite may be used by the client
    const invited = createHuginSwarm({
      key: address,
      keyPair: keyPairFromSeed(b4a.alloc(32, 31)),
      bootstrap
    })
    t.teardown(() => invited.swarm.destroy())
    const other = createHuginSwarm({
      key: address,
      keyPair: keyPairFromSeed(b4a.alloc(32, 32)),
      bootstrap
    })
    t.teardown(() => other.swarm.destroy())

    await invited.swarm.join(invited.topic, { server: true, client: false }).flushed()
    await other.swarm.join(other.topic, { server: true, client: false }).flushed()

    const invite = address + hex(invited.keyPair.publicKey)
    const checked = new Map()
    const client = createHuginSwarm({
      key: invite, // fill32 keeps 32 bytes: same topic as the bare address
      bootstrap,
      firewall(remotePublicKey, payload) {
        const firewalled = hex(remotePublicKey) !== invite.slice(-64)
        checked.set(hex(remotePublicKey), firewalled)
        return firewalled
      }
    })
    t.teardown(() => client.swarm.destroy())
    t.alike(client.topic, invited.topic)

    const logClient = newLog()
    watch(client.swarm, logClient)
    client.swarm.join(client.topic, { server: false, client: true })

    const otherKey = hex(other.keyPair.publicKey)
    const invitedKey = hex(invited.keyPair.publicKey)
    await waitFor(() => logClient.connections.length > 0 && checked.has(otherKey))
    t.is(checked.get(otherKey), true, 'firewall refused the uninvited node')
    t.is(checked.get(invitedKey), false, 'firewall allowed the invited node')
    t.ok(logClient.connections.includes(invitedKey), 'connected to the invited node')
    t.ok(logClient.connections.every((k) => k === invitedKey), 'and to nobody else')

    // a key pair can carry one Hugin identity per DHT/registry
    const dht = new MidDHT({ bootstrap })
    const kp = keyPairFromSeed(b4a.alloc(32, 33))
    const one = createHuginSwarm({ key: 'topic one', keyPair: kp, dht })
    t.teardown(() => one.swarm.destroy()) // also destroys `dht`
    t.is(one.dht, dht)
    t.is(one.registry, dht.midRegistry)
    await t.exception.all(() => createHuginSwarm({ key: 'topic two', keyPair: kp, dht }), /another topic/)
    await t.exception.all(() => createHuginSwarm({ key: 'x', dht: {} }), /must be a MidDHT/)
  }
)

test(
  'separation on a testnet: earlier-derivation and current peers on the same key never connect',
  { timeout: 180000 },
  async (t) => {
    const testnet = await createTestnet(3, t.teardown)
    const { bootstrap } = testnet
    const key = NETWORK_ADDRESS

    const rejects = []
    const onreject = (name) => (local, remote, reason) => rejects.push({ name, remote: hex(remote), reason })
    const oldRejects = []
    const onOldReject = (name) => (remote, reason) => oldRejects.push({ name, remote: hex(remote), reason })

    const a = createHuginSwarm({ key, bootstrap, onreject: onreject('a') })
    t.teardown(() => a.swarm.destroy())
    const b = createHuginSwarm({ key, bootstrap, onreject: onreject('b') })
    t.teardown(() => b.swarm.destroy())
    const oldA = createLegacySwarm({ key, bootstrap, onreject: onOldReject('oldA') })
    t.teardown(() => oldA.swarm.destroy())
    const oldB = createLegacySwarm({ key, bootstrap, onreject: onOldReject('oldB') })
    t.teardown(() => oldB.swarm.destroy())

    t.alike(oldA.basePublicKey, a.basePublicKey, 'same key, same base key')
    t.unlike(oldA.topic, a.topic, 'different DHT topic')
    t.alike(oldA.topic, legacyTopicFromKey(key).topic)

    const logs = { a: newLog(), b: newLog(), oldA: newLog(), oldB: newLog() }
    watch(a.swarm, logs.a)
    watch(b.swarm, logs.b)
    watch(oldA.swarm, logs.oldA)
    watch(oldB.swarm, logs.oldB)

    const both = { server: true, client: true }
    await Promise.all([a, b, oldA, oldB].map((p) => p.swarm.join(p.topic, both).flushed()))

    const current = [a, b].map((p) => hex(p.keyPair.publicKey))
    const earlier = [oldA, oldB].map((p) => hex(p.keyPair.publicKey))
    const onlyAmong = (log, allowed) => log.connections.every((k) => allowed.includes(k))
    const crossed = () =>
      !onlyAmong(logs.a, current) ||
      !onlyAmong(logs.b, current) ||
      !onlyAmong(logs.oldA, earlier) ||
      !onlyAmong(logs.oldB, earlier)

    // via the topic: each pair finds its own kind only
    await waitFor(() => Object.values(logs).every((l) => l.connections.length > 0))
    t.ok(logs.a.connections.includes(current[1]), 'two current peers connect')
    t.ok(logs.oldA.connections.includes(earlier[1]), 'two earlier-derivation peers connect (fixture works)')
    await sleep(1000)
    t.absent(crossed(), 'no connection across the two derivations via the topic')
    t.is(rejects.length, 0, 'no earlier-derivation peer even reached a current handshake via the topic')
    t.is(oldRejects.length, 0, 'and no current peer an earlier one')

    // direct dial by public key, earlier -> current: refused at the handshake
    oldA.swarm.joinPeer(a.keyPair.publicKey)
    await waitFor(() => rejects.some((r) => r.name === 'a' && r.remote === earlier[0] && r.reason === 'invalid mid'))
    t.pass('current peer refused the earlier-derivation dial at the handshake')

    // direct dial by public key, current -> earlier: refused at the handshake
    b.swarm.joinPeer(oldB.keyPair.publicKey)
    await waitFor(() => oldRejects.some((r) => r.name === 'oldB' && r.remote === current[1] && r.reason === 'invalid mid'))
    t.pass('earlier-derivation peer refused the current dial at the handshake')

    await sleep(1000)
    t.absent(crossed(), 'no connection across the two derivations after direct dials')
    t.ok(logs.a.data.every(([remote]) => current.includes(remote)), 'no data from an earlier-derivation peer')
    t.ok(logs.oldB.data.every(([remote]) => earlier.includes(remote)), 'no data from a current peer')
  }
)
