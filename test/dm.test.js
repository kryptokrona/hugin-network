'use strict'

// hugin-network/dm (lib/dm.js): DM payloads and the per-contact ML-KEM handshake between in-memory
// contacts. The crypto provider is test/fixtures/fake-hugin-crypto.js (hugin-crypto's function
// names; see there what stands in for what) with the key derivation on ed25519 points, as
// CryptoNote's (`makeEdNet` below): lib/dm.js makes each message's key pair r, txKey = r*G
// itself, and the receiver derives from txKey. The payload layout is checked against a payload
// built in the test from the same primitives. Hosts keep contact states as JSON strings, as a
// database column would.

const test = require('brittle')
const b4a = require('b4a')
const sodium = require('sodium-universal')
const { keccak256 } = require('js-sha3')
const {
  DmCrypto,
  DmError,
  STATUS,
  ACCEPTED_FLAGS,
  normalizeState,
  nextState,
  dmViewTag,
  dmSigningPayload,
  handshakeDigest,
  decodeWire,
  decodeOuter,
  generateTxKey,
  secretKeyToPublicKey,
  scalarReduce,
  txKeyBackend,
  sha256Hex,
  CRYPTO_FUNCTIONS,
  NODE_PAYLOAD_BUDGET
} = require('../lib/dm.js')
const push = require('../lib/push.js')
const { makeNet, cnFastHash } = require('./fixtures/fake-hugin-crypto.js')
const V = require('./fixtures/hugin-relay.json')

const T0 = 1731500000000
const DAY = 24 * 60 * 60 * 1000
const fromHex = (h) => new Uint8Array(b4a.from(h, 'hex'))
const toHex = (bytes) => b4a.toString(b4a.from(bytes), 'hex')

/** l, the order of the ed25519 base point */
const L = (BigInt(1) << BigInt(252)) + BigInt('27742317777372353535851937790883648493')
const leToBigInt = (bytes) => {
  let v = BigInt(0)
  for (let i = bytes.length - 1; i >= 0; i--) v = (v << BigInt(8)) | BigInt(bytes[i])
  return v
}

/** SHA-256 with libsodium (to check lib/dm.js's own). */
function sodiumSha256(bytes) {
  const out = b4a.alloc(32)
  sodium.crypto_hash_sha256(out, b4a.from(bytes))
  return toHex(out)
}

/** A scalar below l from a seed (BLAKE2b-512 reduced mod l). */
function edScalar(seed) {
  const wide = b4a.alloc(64)
  sodium.crypto_generichash(wide, b4a.from('dm-test:' + seed, 'utf8'))
  const s = b4a.alloc(32)
  sodium.crypto_core_ed25519_scalar_reduce(s, wide)
  return s
}

function edBase(scalar) {
  const q = b4a.alloc(32)
  sodium.crypto_scalarmult_ed25519_base_noclamp(q, scalar)
  return q
}

/** The key derivation stand-in on ed25519 points: priv*pub (CryptoNote also multiplies by 8). */
function edDerive(privateKeyHex, publicKeyHex) {
  const q = b4a.alloc(32)
  sodium.crypto_scalarmult_ed25519_noclamp(q, b4a.from(privateKeyHex, 'hex'), b4a.from(publicKeyHex, 'hex'))
  return toHex(q)
}

/**
 * The fake provider with view keys, addresses and key derivation on ed25519 points: view private
 * key v (a scalar), view public key v*G, `friendRequestSecretSender(r, to)` = r*V and the
 * wallet's `keyDerivation(txKey)` = v*txKey, so a txKey made by lib/dm.js (r*G) opens. The
 * provider's `ephemeralKeypair` is counted in `calls` and fails.
 */
function makeEdNet() {
  const net = makeNet()
  const base = net.crypto
  const registry = new Map()
  const calls = { ephemeralKeypair: 0 }
  const crypto = {
    ...base,
    async ephemeralKeypair() {
      calls.ephemeralKeypair++
      throw new Error('ephemeralKeypair is not used')
    },
    async friendRequestSecretSender(privateKey, toAddress) {
      return edDerive(privateKey, await base.addressToViewPub(toAddress))
    },
    async friendRequestSecretReceiver(txKey, privateViewKey) {
      return edDerive(privateViewKey, txKey)
    },
    async verify(message, address, signature) {
      const pk = registry.get(address)
      if (!pk || typeof signature !== 'string' || signature.length !== 128) return false
      try {
        return sodium.crypto_sign_verify_detached(b4a.from(signature, 'hex'), b4a.from(message, 'utf8'), pk)
      } catch {
        return false
      }
    }
  }
  function wallet(name) {
    const w = net.wallet(name)
    const privateViewKey = toHex(edScalar('view:' + name))
    const viewPub = toHex(edBase(fromHex(privateViewKey)))
    const address = 'SEKR' + viewPub + keccak256(name).slice(0, 31)
    registry.set(address, b4a.from(w.privateSpendKey.slice(64), 'hex'))
    return {
      name,
      address,
      viewPub,
      privateViewKey,
      privateSpendKey: w.privateSpendKey,
      keyDerivation: (publicKey) => edDerive(privateViewKey, publicKey),
      sign: w.sign
    }
  }
  return { crypto, wallet, calls }
}

/** One side: a test wallet, its stores, a host and a DmCrypto. `store` / `clock` may be shared. */
function party(net, name, { store, clock, host: extra = {} } = {}) {
  const w = net.wallet(name)
  const st = store || { contacts: new Map(), kem: null, kemSaves: 0, saves: 0 }
  const clk = clock || { now: T0 }
  const host = {
    identity: () => ({ address: w.address, name }),
    sign: (message) => w.sign(message),
    keyDerivation: async (publicKey) => w.keyDerivation(publicKey),
    loadContactCrypto: async (address) => (st.contacts.has(address) ? JSON.parse(st.contacts.get(address)) : null),
    saveContactCrypto: async (address, state) => {
      st.saves++
      st.contacts.set(address, JSON.stringify(state))
    },
    loadKemIdentity: async () => st.kem,
    saveKemIdentity: async (kp) => {
      st.kemSaves++
      st.kem = kp
    },
    now: () => clk.now,
    ...extra
  }
  const dm = new DmCrypto({ crypto: net.crypto, host })
  return { name, w, address: w.address, st, clk, host, dm }
}

/**
 * `side.dm.open`; a result without `message` (any status but ok) gets an empty one, so that a
 * failed open shows as failed assertions on its fields instead of a TypeError.
 */
async function open(side, payload, opts) {
  const r = await side.dm.open(payload, opts)
  return r && r.message ? r : { ...r, message: {} }
}

/** `from` writes `text` to `to`, one second after the last message. */
async function send(from, to, text, opts = {}) {
  from.clk.now += 1000
  return from.dm.encrypt(to.address, text, opts)
}

function stored(side, other) {
  return side.st.contacts.get(other.address) || null
}

/** A sends an initial, B replies with the capsule, A answers under the key. */
async function establish(t, A, B) {
  const r1 = await open(B, (await send(A, B, 'hello')).payload)
  const r2 = await open(A, (await send(B, A, 'hello back')).payload)
  const r3 = await open(B, (await send(A, B, 'and again')).payload)
  t.ok(r1.status === STATUS.OK && r2.status === STATUS.OK && r3.status === STATUS.OK, 'handshake done')
  const a = await A.dm.contactState(B.address)
  const b = await B.dm.contactState(A.address)
  t.is(a.messageKey, b.messageKey, 'one key on both sides')
  return a.messageKey
}

// =============================================================================================

test('dm: handshake between two contacts, then messages both ways', async (t) => {
  const net = makeEdNet()
  const clock = { now: T0 }
  const A = party(net, 'alice', { clock })
  const B = party(net, 'bob', { clock })

  const m1 = await send(A, B, 'hi bob')
  t.is(m1.handshake, 'initial', 'no key: our ML-KEM public key goes along')
  t.is(m1.kind, 'dm')
  t.is(m1.to, B.address)
  t.is(m1.timestamp, clock.now)
  t.is(m1.hash, net.crypto.messageHash(m1.payload), 'message id: messageHash of the payload')
  t.is(stored(A, B), null, 'sending changes no state')

  const r1 = await open(B, m1.payload)
  t.is(r1.status, STATUS.OK)
  t.alike(r1.message, {
    from: A.address,
    message: 'hi bob',
    name: 'alice',
    timestamp: m1.timestamp,
    hash: m1.hash,
    type: 'friend-request',
    established: true
  })
  const kemA = await A.dm.kemIdentity()
  const b1 = await B.dm.contactState(A.address)
  t.is(b1.messageKey.length, 64, 'bob made a key')
  t.is(b1.pendingKemCapsule.length, 1536, 'and owes alice its capsule')
  t.is(b1.peerKemPub, toHex(kemA.publicKey), "for alice's ML-KEM key")
  t.is(b1.keyTime, m1.timestamp)

  const m2 = await send(B, A, 'hi alice')
  t.is(m2.handshake, 'reply', 'key and capsule')
  const r2 = await open(A, m2.payload)
  t.is(r2.status, STATUS.OK)
  t.is(r2.message.type, 'message', 'opened with the key from the capsule')
  t.is(r2.message.message, 'hi alice')
  t.is(r2.message.name, 'bob')
  const a2 = await A.dm.contactState(B.address)
  t.is(a2.messageKey, b1.messageKey, 'alice holds the same key')
  t.is(a2.pendingKemCapsule, '')

  const m3 = await send(B, A, 'are you there')
  t.is(m3.handshake, 'reply', 'bob sends the capsule until alice uses the key')
  t.is((await open(A, m3.payload)).status, STATUS.OK)

  const m4 = await send(A, B, 'yes')
  t.is(m4.handshake, 'established', 'alice sends under the key only')
  const r4 = await open(B, m4.payload)
  t.is(r4.status, STATUS.OK)
  t.is(r4.message.type, 'message')
  t.is((await B.dm.contactState(A.address)).pendingKemCapsule, '', "alice's message under the key ends bob's capsule")

  const m5 = await send(B, A, 'good')
  t.is(m5.handshake, 'established')
  const r5 = await open(A, m5.payload)
  t.is(r5.message.message, 'good')
  t.is(r5.message.type, 'message')
})

test('dm: payload layout, built here from its parts, in all three handshake states', async (t) => {
  const net = makeEdNet()
  const A = party(net, 'alice')
  const B = party(net, 'bob')
  const kemA = await A.dm.kemIdentity()
  const c = net.crypto

  /**
   * The payload as the layout in lib/dm.js describes it, from the provider's primitives. txKey is
   * the payload's own (lib/dm.js draws r for every message); the derivation is the recipient's.
   */
  async function expected({ payload, recipient, to, t: ts, flags, from, kem, name, text, signer, messageKey }) {
    const txKey = fromHex(payload.slice(18, 82))
    const d = recipient.w.keyDerivation(toHex(txKey))
    const vt = await c.viewTag(d)
    const outerKey = await c.boxKey(d)
    const hs = kem ? sodiumSha256(kem) : ''
    const signature = fromHex(await signer.sign('hugin/dm\n' + JSON.stringify([to, ts, text, flags, hs])))
    const nameBytes = b4a.from(name, 'utf8')
    const body = b4a.concat([b4a.from([nameBytes.length]), nameBytes, signature, b4a.from(text, 'utf8')])
    const rest = messageKey ? c.secretboxEncrypt(body, txKey.slice(0, 24), fromHex(messageKey)) : body
    const outer = b4a.concat([b4a.from([flags]), b4a.from(from, 'ascii'), ...(kem ? [kem] : []), rest])
    const box = c.secretboxEncrypt(outer, c.nonceFromTimestamp(ts), outerKey)
    const time = b4a.alloc(8)
    new DataView(time.buffer, time.byteOffset, 8).setBigUint64(0, BigInt(ts))
    return toHex(b4a.concat([b4a.from([1]), time, txKey, fromHex(vt), box]))
  }

  // initial: flags 1, kem_pub (800 bytes) in the outer box, the body in the clear inside it
  const m1 = await A.dm.encrypt(B.address, 'hello', { timestamp: T0 + 1 })
  t.is(m1.handshake, 'initial')
  t.is(m1.payload, await expected({ payload: m1.payload, recipient: B, to: B.address, t: T0 + 1, flags: 1, from: A.address, kem: kemA.publicKey, name: 'alice', text: 'hello', signer: A.w }))
  t.is(m1.payload.slice(0, 2), '01', 'version')
  t.is(m1.payload.slice(2, 18), (T0 + 1).toString(16).padStart(16, '0'), 'timestamp, 8 bytes big-endian')
  t.is(m1.payload.length, 2 * (1023 + 5 + 5), '1023 bytes + name + text')
  const w1 = decodeWire(m1.payload)
  t.is(w1.version, 1)
  t.is(w1.t, T0 + 1)
  t.is(w1.txKey, m1.payload.slice(18, 82), 'txKey')
  t.is(w1.vt, m1.payload.slice(82, 84))
  t.is(m1.hash, c.messageHash(m1.payload), 'message id: messageHash of the payload')
  const r1 = await open(B, m1.payload)
  t.is(r1.status, STATUS.OK)
  t.is(r1.message.type, 'friend-request')
  t.is(r1.message.message, 'hello')
  t.is(r1.message.name, 'alice')
  t.is(r1.message.timestamp, T0 + 1)

  // reply: flags 6, kem_ct (768 bytes), the body in the inner box under bob's key
  const sb = await B.dm.contactState(A.address)
  const m2 = await B.dm.encrypt(A.address, 'hello back', { timestamp: T0 + 2 })
  t.is(m2.handshake, 'reply')
  t.is(
    m2.payload,
    await expected({ payload: m2.payload, recipient: A, to: A.address, t: T0 + 2, flags: 6, from: B.address, kem: fromHex(sb.pendingKemCapsule), name: 'bob', text: 'hello back', signer: B.w, messageKey: sb.messageKey })
  )
  t.is(m2.payload.length, 2 * (1007 + 3 + 10), '1007 bytes + name + text')
  const r2 = await open(A, m2.payload)
  t.is(r2.status, STATUS.OK)
  t.is(r2.message.type, 'message')
  t.is(r2.message.message, 'hello back')

  // established: flags 4, the inner box only
  const m3 = await A.dm.encrypt(B.address, 'established ✓', { timestamp: T0 + 3 })
  t.is(m3.handshake, 'established')
  t.is(m3.payload, await expected({ payload: m3.payload, recipient: B, to: B.address, t: T0 + 3, flags: 4, from: A.address, name: 'alice', text: 'established ✓', signer: A.w, messageKey: sb.messageKey }))
  t.is(m3.payload.length, 2 * (239 + 5 + b4a.byteLength('established ✓')), '239 bytes + name + text')
  const r3 = await open(B, m3.payload)
  t.is(r3.status, STATUS.OK)
  t.is(r3.message.message, 'established ✓')
  t.is(r3.message.type, 'message')

  // an empty name is a zero length byte
  const m4 = await A.dm.encrypt(B.address, 'no name', { timestamp: T0 + 4, name: '' })
  t.is(m4.payload.length, 2 * (239 + 0 + 7))
  t.is((await open(B, m4.payload)).message.name, '')

  // what is not this layout
  t.is(decodeWire('02' + m3.payload.slice(2)), null, 'another version')
  t.is(decodeWire(m3.payload.slice(0, 2 * 222)), null, 'shorter than the smallest payload')
  t.is(decodeWire('01' + 'ff'.repeat(8) + m3.payload.slice(18)), null, 'a timestamp above 2^53 - 1')
  t.is(decodeWire(toHex(b4a.from(JSON.stringify({ box: 'ab', t: 1, txKey: 'cd'.repeat(32), vt: 'ef' }), 'utf8'))), null, 'the earlier hex(JSON) form')
})

test('dm: handshake payloads fit a hugin-node post', async (t) => {
  const net = makeEdNet()
  const A = party(net, 'alice')
  const B = party(net, 'bob')
  // the largest post fields: a call (64-character view tag), a 32-character job id, one share
  const jobId = 'x'.repeat(32)
  const powField = {
    version: 2,
    job: { job_id: jobId, blob: V.pow.job.blob, target: '285c8f02' },
    shares: [{ job_id: jobId, nonce: 'a1b2c3d4', result: 'c'.repeat(64) }],
    auth: { pub: 'd'.repeat(64), sig: 'e'.repeat(128), nonce: 'a1b2c3d4' }
  }
  const packetBytes = (m) =>
    b4a.byteLength(push.encodePacket(push.postPacket({ cipher: m.payload, hash: m.hash, viewtag: m.viewTag, kind: m.kind, timestamp: T0, pow: powField })), 'utf8')
  t.is(packetBytes({ payload: '', hash: 'a'.repeat(64), viewTag: 'f'.repeat(64), kind: 'call' }) <= 905, true, 'a post without its cipher is at most 905 bytes')

  const text = 'Hej! '.repeat(60) // 300 characters
  const initial = await A.dm.encrypt(B.address, text, { call: true })
  t.is(initial.handshake, 'initial')
  t.ok(initial.fitsNode)
  t.ok(packetBytes(initial) <= 9000, 'kem_pub and 300 characters: ' + packetBytes(initial) + ' bytes')
  t.is((await open(B, initial.payload)).status, STATUS.OK)

  const reply = await B.dm.encrypt(A.address, text, { call: true })
  t.is(reply.handshake, 'reply')
  t.ok(reply.fitsNode)
  t.ok(packetBytes(reply) <= 9000, 'kem_ct and 300 characters: ' + packetBytes(reply) + ' bytes')
  t.is((await open(A, reply.payload)).message.message, text)

  // the longest texts within NODE_PAYLOAD_BUDGET (7600 hex characters = 3800 bytes) for the
  // name 'bob' (3 bytes): reply 3800 - 1007 - 3 = 2790 bytes; initial 3800 - 1023 - 3 = 2774
  t.is(NODE_PAYLOAD_BUDGET, 7600)
  const longest = await B.dm.encrypt(A.address, 'y'.repeat(2790), { call: true })
  t.is(longest.payload.length, NODE_PAYLOAD_BUDGET)
  t.ok(longest.fitsNode)
  t.ok(packetBytes(longest) <= 9000 - 400, 'still about 500 bytes to spare: ' + packetBytes(longest))
  t.absent((await B.dm.encrypt(A.address, 'y'.repeat(2791))).fitsNode, 'one byte more is over the budget')
  const C = party(net, 'carol')
  const first = await C.dm.encrypt(A.address, 'z'.repeat(2774), { name: 'bob', call: true })
  t.is(first.handshake, 'initial')
  t.is(first.payload.length, NODE_PAYLOAD_BUDGET)
  t.ok(packetBytes(first) <= 9000)
})

test('dm: out of order and duplicate deliveries keep one key', async (t) => {
  const net = makeEdNet()
  const clock = { now: T0 }
  const A = party(net, 'alice', { clock })
  const B = party(net, 'bob', { clock })

  const a1 = await send(A, B, 'first')
  const a1b = await send(A, B, 'second before any answer')
  t.is(a1b.handshake, 'initial', 'alice keeps sending her kem_pub until she has a key')
  t.is((await open(B, a1.payload)).status, STATUS.OK)
  const keyB = (await B.dm.contactState(A.address)).messageKey
  t.is((await open(B, a1b.payload)).status, STATUS.OK)
  t.is((await B.dm.contactState(A.address)).messageKey, keyB, 'a second kem_pub from alice keeps bob key')
  const before = stored(B, A)
  t.is((await open(B, a1.payload)).status, STATUS.OK, 'a duplicate opens again')
  t.is(stored(B, A), before, 'and changes nothing')

  // bob's two replies reach alice the other way round: both carry the capsule
  const b1 = await send(B, A, 'reply one')
  const b2 = await send(B, A, 'reply two')
  const r2 = await open(A, b2.payload)
  const r1 = await open(A, b1.payload)
  t.is(r2.status, STATUS.OK)
  t.is(r1.status, STATUS.OK)
  t.is(r2.message.message, 'reply two')
  t.is(r1.message.message, 'reply one')
  t.is((await A.dm.contactState(B.address)).messageKey, keyB)
  const aState = stored(A, B)
  t.is((await open(A, b2.payload)).status, STATUS.OK)
  t.is(stored(A, B), aState, 'a duplicate reply changes nothing')

  // alice answers under the key; late copies of the early messages change nothing
  t.is((await open(B, (await send(A, B, 'got it')).payload)).status, STATUS.OK)
  const bState = stored(B, A)
  t.is(JSON.parse(bState).pendingKemCapsule, '')
  t.is((await open(B, a1.payload)).status, STATUS.OK, "a late copy of alice's first message")
  t.is((await open(B, a1b.payload)).status, STATUS.OK)
  t.is(stored(B, A), bState, 'does not start a new handshake')
  t.is((await open(A, b1.payload)).status, STATUS.OK, 'a late reply with the capsule')
  t.is(stored(A, B), aState, 'changes nothing either')
  t.is((await A.dm.contactState(B.address)).messageKey, keyB)

  const r = await open(B, (await send(A, B, 'still one key')).payload)
  t.is(r.message.type, 'message')
  const r6 = await open(A, (await send(B, A, 'yes')).payload)
  t.is(r6.message.message, 'yes')
})

test('dm: both sides starting at once settle on one key, in either delivery order', async (t) => {
  for (const order of ['alice first', 'bob first']) {
    const net = makeEdNet()
    const clock = { now: T0 }
    const A = party(net, 'alice', { clock })
    const B = party(net, 'bob', { clock })

    const a1 = await send(A, B, 'hi from alice')
    const b1 = await send(B, A, 'hi from bob')
    t.is(a1.handshake, 'initial')
    t.is(b1.handshake, 'initial')
    t.is((await open(A, b1.payload)).status, STATUS.OK)
    t.is((await open(B, a1.payload)).status, STATUS.OK)
    const ka = (await A.dm.contactState(B.address)).messageKey
    const kb = (await B.dm.contactState(A.address)).messageKey
    t.not(ka, kb, order + ': two keys, one per side')

    const a2 = await send(A, B, 'reply from alice')
    const b2 = await send(B, A, 'reply from bob')
    t.is(a2.handshake, 'reply')
    t.is(b2.handshake, 'reply')
    const deliver = order === 'alice first' ? [[B, a2], [A, b2]] : [[A, b2], [B, a2]]
    for (const [side, m] of deliver) t.is((await open(side, m.payload)).status, STATUS.OK, order + ': crossing reply opens')

    const sa = await A.dm.contactState(B.address)
    const sb = await B.dm.contactState(A.address)
    const smaller = ka < kb ? ka : kb
    t.is(sa.messageKey, smaller, order + ': alice keeps the smaller key')
    t.is(sb.messageKey, smaller, order + ': bob keeps the smaller key')

    const a3 = await send(A, B, 'under one key')
    const b3 = await send(B, A, 'under one key too')
    t.is((await open(B, a3.payload)).message.message, 'under one key')
    t.is((await open(A, b3.payload)).message.message, 'under one key too')
    const a4 = await send(A, B, 'done')
    const b4 = await send(B, A, 'done too')
    t.is(a4.handshake, 'established', order + ': alice has no capsule left')
    t.is(b4.handshake, 'established', order + ': bob has no capsule left')
    t.is((await open(B, a4.payload)).status, STATUS.OK)
    t.is((await open(A, b4.payload)).status, STATUS.OK)
    // the losing key's late messages still open
    t.is((await open(A, b2.payload)).status, STATUS.OK, order + ': a late crossing reply still opens')
    t.is((await A.dm.contactState(B.address)).messageKey, smaller)
  }
})

test('dm: refused payloads change no state', async (t) => {
  const net = makeEdNet()
  const clock = { now: T0 }
  const A = party(net, 'alice', { clock })
  const B = party(net, 'bob', { clock })
  const C = party(net, 'carol', { clock })
  await establish(t, A, B)
  const bState = stored(B, A)

  // another recipient
  const m = await send(A, B, 'for bob only')
  const atC = await open(C, m.payload)
  t.ok(atC.status === STATUS.NOT_FOR_US || atC.status === STATUS.REFUSED, 'carol cannot open it (' + atC.status + ')')
  t.is(C.st.contacts.size, 0)

  // a changed box
  const flip = (hex, at) => hex.slice(0, at) + (hex[at] === '0' ? '1' : '0') + hex.slice(at + 1)
  const changed = flip(m.payload, 120) // inside the box
  t.alike(await B.dm.open(changed), { status: STATUS.REFUSED, reason: 'outer box' })
  // another timestamp than the one the box was made with
  const shifted = flip(m.payload, 17) // the last hex digit of the timestamp
  t.is((await open(B, shifted)).status, STATUS.REFUSED)

  // from the DM swarm of another contact
  t.alike(await B.dm.open(m.payload, { from: C.address }), { status: STATUS.REFUSED, reason: 'not the contact' })
  t.is((await open(B, m.payload, { from: A.address + 'chat-id-suffix' })).status, STATUS.OK, 'the contact (a longer chat id is cut to the address)')

  // someone writing as alice without alice's spend key
  const M = party(net, 'mallory', { clock })
  const fake = party(net, 'mallory-as-alice', { clock, host: { identity: () => ({ address: A.address, name: 'alice' }), sign: (msg) => M.w.sign(msg) } })
  const mismatched = await send(fake, B, 'i am alice')
  t.alike(await B.dm.open(mismatched.payload), { status: STATUS.REFUSED, reason: 'signature' })

  // a key that is not the shared one
  const D = party(net, 'dave', { clock })
  const E = party(net, 'erin', { clock })
  await establish(t, D, E)
  const dState = JSON.parse(stored(D, E))
  D.st.contacts.set(E.address, JSON.stringify({ ...dState, messageKey: 'ab'.repeat(32), pendingKemCapsule: '' }))
  const eState = stored(E, D)
  t.alike(await E.dm.open((await send(D, E, 'wrong key')).payload), { status: STATUS.REFUSED, reason: 'inner box' })
  t.is(stored(E, D), eState)

  // not DM payloads
  t.is((await open(B, '')).status, STATUS.NOT_DM)
  t.is((await open(B, 'zz')).status, STATUS.NOT_DM)
  t.is((await open(B, toHex(b4a.from(JSON.stringify({ sb: 'a group message' }), 'utf8')))).status, STATUS.NOT_DM)
  t.is((await open(B, 42)).status, STATUS.NOT_DM)
  t.is((await open(B, 'ab'.repeat(40000))).status, STATUS.NOT_DM, 'longer than maxPayloadLength (65536)')

  // a failing host hook
  const B2 = party(net, 'bob', { store: B.st, clock, host: { keyDerivation: async () => { throw new Error('wallet locked') } } })
  const err = await open(B2, m.payload)
  t.is(err.status, STATUS.ERROR)
  t.ok(/wallet locked/.test(err.reason))

  t.is(stored(B, A), bState, "bob's state for alice is unchanged")
})

test('dm: state is persisted and reloaded by new instances', async (t) => {
  const net = makeEdNet()
  const clock = { now: T0 }
  const A = party(net, 'alice', { clock })
  const B = party(net, 'bob', { clock })

  // mid-handshake restart: bob's capsule survives
  t.is((await open(B, (await send(A, B, 'before restart')).payload)).status, STATUS.OK)
  const B2 = party(net, 'bob', { store: B.st, clock })
  const reply = await send(B2, A, 'after restart')
  t.is(reply.handshake, 'reply', 'the reloaded bob still sends the capsule')
  t.is((await open(A, reply.payload)).message.type, 'message')

  const A2 = party(net, 'alice', { store: A.st, clock })
  const m = await send(A2, B2, 'from a new alice instance')
  t.is(m.handshake, 'established')
  t.is((await open(B2, m.payload)).message.message, 'from a new alice instance')
  t.is((await open(A2, (await send(B2, A2, 'and back')).payload)).message.message, 'and back')

  // alice made her ML-KEM identity for her first message (kem_pub); a new instance loads it
  t.is(A.st.kemSaves, 1, 'alice made one ML-KEM identity')
  const kemA = await A.dm.kemIdentity()
  const kemA2 = await A2.dm.kemIdentity()
  t.alike(toHex(kemA2.publicKey), toHex(kemA.publicKey), 'the new alice instance loads the same identity')
  t.alike(toHex(kemA2.secretKey), toHex(kemA.secretKey))
  t.is(A.st.kemSaves, 1, 'and does not make another')
  // bob answered with a capsule for alice's key and never sent a kem_pub or opened a kem_ct:
  // an identity is made only when one is needed
  t.is(B.st.kemSaves, 0, 'bob needed no ML-KEM identity')
  t.is(B.st.kem, null)
  const saved = JSON.parse(stored(A, B))
  t.alike(Object.keys(saved).sort(), ['keyTime', 'messageKey', 'peerKemPub', 'pendingKemCapsule', 'previousKeys'])
  t.is(saved.messageKey.length, 64)
  t.alike(saved.previousKeys, [])
  t.alike(normalizeState(saved), saved, 'stored states are normalised')
  t.is(typeof A.st.kem.publicKey, 'string', 'the identity is stored as hex')
  t.is(A.st.kem.publicKey.length, 1600)
  t.is(A.st.kem.secretKey.length, 3264)

  // a failing identity load is not replaced by a new identity
  const broken = party(net, 'alice', { store: A.st, clock, host: { loadKemIdentity: async () => { throw new Error('keychain locked') } } })
  await t.exception(broken.dm.kemIdentity(), /keychain locked/)
  t.is(A.st.kemSaves, 1)
})

test('dm: a contact that starts over (new install) gets a new key; late messages under the old key still open', async (t) => {
  const net = makeEdNet()
  const clock = { now: T0 }
  const A = party(net, 'alice', { clock })
  const B = party(net, 'bob', { clock })
  const oldKey = await establish(t, A, B)
  const late = await send(B, A, 'sent under the old key')

  // bob's new install: same wallet, empty stores, a new ML-KEM identity
  const Bn = party(net, 'bob', { clock })
  const n1 = await send(Bn, A, 'new phone')
  t.is(n1.handshake, 'initial')
  const r1 = await open(A, n1.payload)
  t.is(r1.status, STATUS.OK)
  t.is(r1.message.type, 'friend-request')
  const sa = await A.dm.contactState(B.address)
  t.not(sa.messageKey, oldKey, 'alice made a new key')
  t.is(sa.pendingKemCapsule.length, 1536)
  t.alike(sa.previousKeys, [oldKey], 'the old key is kept for late messages')

  const n2 = await send(A, Bn, 'welcome back')
  t.is(n2.handshake, 'reply')
  t.is((await open(Bn, n2.payload)).message.type, 'message')
  t.is((await Bn.dm.contactState(A.address)).messageKey, sa.messageKey)

  const rl = await open(A, late.payload)
  t.is(rl.status, STATUS.OK)
  t.is(rl.message.message, 'sent under the old key')
  t.is((await A.dm.contactState(B.address)).messageKey, sa.messageKey, 'a late message does not change the key')

  t.is((await open(A, (await send(Bn, A, 'all set')).payload)).message.type, 'message')
  t.is((await send(A, Bn, 'established again')).handshake, 'established')
})

test('dm: node pool entries', async (t) => {
  const net = makeEdNet()
  const clock = { now: T0 }
  const A = party(net, 'alice', { clock })
  const B = party(net, 'bob', { clock })
  const C = party(net, 'carol', { clock })
  const D = party(net, 'dave', { clock })
  await establish(t, A, B)

  const m1 = await send(A, B, 'pool one')
  const m2 = await send(A, B, 'pool two')
  const m3 = await send(A, B, 'pool three')
  const other = await send(C, D, 'not for bob')
  const entry = (m) => ({ hash: m.hash, cipher: m.payload, timestamp: m.timestamp })
  const group = { hash: 'cd'.repeat(32), cipher: toHex(b4a.from(JSON.stringify({ sb: 'x'.repeat(200) }), 'utf8')), timestamp: T0 }
  const entries = [entry(m3), entry(other), entry(m1), group, { hash: 'ef'.repeat(32), cipher: 'abcd' }, { hash: 'nothex', cipher: m2.payload }, null, entry(m2)]

  const res = await B.dm.openPool(entries)
  t.alike(res.messages.map((m) => m.message), ['pool one', 'pool two', 'pool three'], 'opened, by timestamp')
  t.alike(res.messages.map((m) => m.hash), [m1.hash, m2.hash, m3.hash], 'with the pool hash')
  t.alike(res.others, [group], 'not a DM payload: left to the host')
  t.is(res.skipped, 3, 'too short, bad hash, not an object')
  t.is(res.errors, 0)
  t.ok(B.dm.knowsPoolHash(m1.hash))
  t.ok(B.dm.knowsPoolHash(other.hash), 'a payload for someone else is remembered too')

  const again = await B.dm.openPool(entries)
  t.is(again.messages.length, 0, 'each hash is opened once')
  t.is(again.skipped, entries.length)

  // a failing hook: the entry is tried again in a later batch
  let locked = true
  const B2 = party(net, 'bob', {
    store: B.st,
    clock,
    host: { keyDerivation: async (pub) => { if (locked) throw new Error('locked'); return B.w.keyDerivation(pub) } }
  })
  const m4 = await send(A, B, 'after unlock')
  const first = await B2.dm.openPool([entry(m4)])
  t.is(first.errors, 1)
  t.is(first.messages.length, 0)
  locked = false
  const second = await B2.dm.openPool([entry(m4)])
  t.alike(second.messages.map((m) => m.message), ['after unlock'])

  // a hook that keeps failing: the entry is given up after maxPoolTries (3) attempts
  const B3 = party(net, 'bob', { store: B.st, clock, host: { keyDerivation: async () => { throw new Error('broken') } } })
  const m5 = await send(A, B, 'never opened')
  for (let i = 0; i < 3; i++) t.is((await B3.dm.openPool([entry(m5)])).errors, 1, 'attempt ' + (i + 1))
  t.alike(await B3.dm.openPool([entry(m5)]), { messages: [], others: [], skipped: 1, errors: 0 }, 'then skipped')

  const seeded = new DmCrypto({ crypto: net.crypto, host: B.host, knownPoolHashes: [m1.hash.toUpperCase()] })
  t.is((await seeded.openPool([entry(m1)])).skipped, 1, 'knownPoolHashes seeds the remembered hashes')
  t.alike(await B.dm.openPool('not a list'), { messages: [], others: [], skipped: 0, errors: 0 })
})

test('dm: DM swarm derivation hash and push view tags', async (t) => {
  const net = makeEdNet()
  const clock = { now: T0 }
  const A = party(net, 'alice', { clock })
  const B = party(net, 'bob', { clock })

  const ha = await A.dm.derivationHash(B.address)
  const hb = await B.dm.derivationHash(A.address)
  t.is(ha, hb, 'both sides derive the same DM swarm key')
  t.is(ha, cnFastHash(A.w.keyDerivation(B.w.viewPub)), 'cn_fast_hash of the key derivation')
  t.is((await A.dm.derivationHash(B.address + 'longer chat id')), ha)

  const now = T0 + 12345
  t.is(await A.dm.pushViewTag(B.address, { now }), push.dmViewTag(B.w.viewPub, { now }))
  t.is(await A.dm.pushViewTag(B.address, { now, call: true }), push.dmViewTag(B.w.viewPub, { now, long: true }))
  for (const at of [0, T0, T0 + 7 * 24 * 3600 * 1000]) {
    t.is(dmViewTag(B.w.viewPub, { now: at }), push.dmViewTag(B.w.viewPub, { now: at }))
  }

  const m = await send(A, B, 'tagged')
  t.is(m.viewTag, push.dmViewTag(B.w.viewPub, { now: clock.now }), "the recipient's tag for this week")
  t.is(m.viewTag.length, 3)
  const call = await send(A, B, JSON.stringify({ call: 'ab'.repeat(64) }), { call: true })
  t.is(call.kind, 'call')
  t.is(call.viewTag.length, 64)
  t.is((await open(B, call.payload)).message.message, JSON.stringify({ call: 'ab'.repeat(64) }))
})

test('dm: nextState rules', (t) => {
  const K = (c) => c.repeat(64)
  const CT = 'c'.repeat(1536)
  const P = (c) => c.repeat(1600)
  let n = 0
  const enc = () => ({ messageKey: K(String(++n)), kemCapsule: CT })
  const empty = normalizeState(null)
  t.alike(empty, { messageKey: '', pendingKemCapsule: '', peerKemPub: '', keyTime: 0, previousKeys: [] })

  // a kem_pub without a key: our key and capsule
  const own = nextState(empty, { t: 10, keyUsed: null, capsuleKey: null, peerKemPub: P('a') }, enc)
  t.alike(own, { messageKey: K('1'), pendingKemCapsule: CT, peerKemPub: P('a'), keyTime: 10, previousKeys: [] })
  t.alike(nextState(own, { t: 20, peerKemPub: P('a') }, enc), own, 'the same kem_pub again: the contact has not got our capsule')
  t.alike(nextState(own, { t: 5, peerKemPub: P('b') }, enc), own, 'another kem_pub older than the key: a late copy')
  const rekeyed = nextState(own, { t: 30, peerKemPub: P('b') }, enc)
  t.alike(rekeyed, { messageKey: K('2'), pendingKemCapsule: CT, peerKemPub: P('b'), keyTime: 30, previousKeys: [K('1')] }, 'a newer kem_pub: a new key')

  // the contact uses our key
  const confirmed = nextState(own, { t: 40, keyUsed: K('1') }, enc)
  t.is(confirmed.pendingKemCapsule, '')
  t.is(confirmed.keyTime, 40)
  t.alike(nextState(confirmed, { t: 35, peerKemPub: P('a') }, enc), confirmed, 'its old kem_pub after that: a late copy')
  const lost = nextState(confirmed, { t: 50, peerKemPub: P('a') }, enc)
  t.is(lost.messageKey, K('3'), 'the same kem_pub newer than the key: the contact lost its key')
  t.alike(lost.previousKeys, [K('1')])

  // capsules
  t.alike(nextState(empty, { t: 10, keyUsed: K('a'), capsuleKey: K('a') }, enc), { messageKey: K('a'), pendingKemCapsule: '', peerKemPub: '', keyTime: 10, previousKeys: [] }, 'no key: take the capsule key')
  const pendingB = { ...empty, messageKey: K('b'), pendingKemCapsule: CT, peerKemPub: P('a'), keyTime: 10 }
  const tookA = nextState(pendingB, { t: 11, keyUsed: K('a'), capsuleKey: K('a') }, enc)
  t.is(tookA.messageKey, K('a'), 'both answered: the smaller key wins')
  t.is(tookA.pendingKemCapsule, '')
  t.alike(tookA.previousKeys, [K('b')])
  const pendingA = { ...pendingB, messageKey: K('a') }
  const keptA = nextState(pendingA, { t: 11, keyUsed: K('b'), capsuleKey: K('b') }, enc)
  t.is(keptA.messageKey, K('a'), 'our smaller key stays')
  t.is(keptA.pendingKemCapsule, CT, 'and its capsule goes on')
  t.alike(keptA.previousKeys, [K('b')])
  const settled = { ...empty, messageKey: K('a'), keyTime: 50 }
  t.alike(nextState(settled, { t: 40, keyUsed: K('d'), capsuleKey: K('d') }, enc).messageKey, K('a'), 'an older capsule is kept for opening only')
  t.alike(nextState(settled, { t: 40, keyUsed: K('d'), capsuleKey: K('d') }, enc).previousKeys, [K('d')])
  const restarted = nextState(settled, { t: 60, keyUsed: K('d'), capsuleKey: K('d') }, enc)
  t.is(restarted.messageKey, K('d'), 'a newer capsule: the contact started over')
  t.alike(restarted.previousKeys, [K('a')])
  t.alike(nextState(settled, { t: 70, keyUsed: K('e') }, enc), settled, 'a previous key opening a message changes nothing')

  // a capsule not newer than our pending key is a late copy, even with a smaller key
  for (const at of [9, 10]) {
    const late = nextState(pendingB, { t: at, keyUsed: K('a'), capsuleKey: K('a') }, enc)
    t.is(late.messageKey, K('b'), 'a late capsule (t ' + at + ', keyTime 10) keeps the pending key')
    t.is(late.pendingKemCapsule, CT, 'and its capsule')
    t.is(late.keyTime, 10, 'keyTime stays')
    t.alike(late.previousKeys, [K('a')], 'the late key is kept for opening only')
  }
  // keyTime never goes back
  const ahead = { ...empty, keyTime: 100 }
  const tookOld = nextState(ahead, { t: 50, keyUsed: K('a'), capsuleKey: K('a') }, enc)
  t.is(tookOld.messageKey, K('a'))
  t.is(tookOld.keyTime, 100, 'a key taken from an older message does not lower keyTime')
  t.is(nextState(ahead, { t: 50, peerKemPub: P('a') }, enc).keyTime, 100)

  // at most maxPreviousKeys
  let s = settled
  for (const [i, c] of ['1', '2', '3', '4', '5'].entries()) s = nextState(s, { t: 100 + i, keyUsed: K(c), capsuleKey: K(c) }, enc)
  t.alike(s.previousKeys, [K('4'), K('3'), K('2')])
  t.is(s.messageKey, K('5'))
})

test('dm: normalizeState accepts app field forms and drops malformed values', (t) => {
  const key = new Uint8Array(32).fill(7)
  const s = normalizeState({ messageKey: key, pendingKemCapsule: new Uint8Array(768), peerKemPubHex: 'AB'.repeat(800), keyTime: 5, previousKeys: ['CD'.repeat(32), 'zz', 'cd'.repeat(32)] })
  t.is(s.messageKey, '07'.repeat(32))
  t.is(s.pendingKemCapsule, '00'.repeat(768))
  t.is(s.peerKemPub, 'ab'.repeat(800))
  t.alike(s.previousKeys, ['cd'.repeat(32)])
  t.alike(normalizeState({ messageKey: 'xyz', pendingKemCapsule: 'c'.repeat(1536), keyTime: -1, previousKeys: 'no' }), {
    messageKey: '',
    pendingKemCapsule: '',
    peerKemPub: '',
    keyTime: 0,
    previousKeys: []
  }, 'no capsule without a key')
})

test('dm: arguments and the crypto provider', async (t) => {
  const net = makeEdNet()
  t.exception(() => new DmCrypto({ host: {} }), /crypto/)
  t.exception(() => new DmCrypto({ crypto: { viewTag() {} }, host: {} }), /lacks friendRequestSecretSender/)
  t.absent(CRYPTO_FUNCTIONS.includes('ephemeralKeypair'), 'the per-message key is not the provider\'s')
  t.exception(() => new DmCrypto({ crypto: net.crypto }), /host/)
  t.ok(CRYPTO_FUNCTIONS.every((name) => typeof net.crypto[name] === 'function'))

  const A = party(net, 'alice')
  const B = party(net, 'bob')
  await t.exception(A.dm.encrypt('not an address', 'x'), /XKR address/)
  await t.exception(A.dm.encrypt(B.address, ''), /non-empty/)
  await t.exception(A.dm.encrypt(B.address, 'x', { timestamp: 1.5 }), /timestamp/)
  const anon = new DmCrypto({ crypto: net.crypto, host: { ...A.host, identity: () => ({}) } })
  const err = await anon.encrypt(B.address, 'x').catch((e) => e)
  t.ok(err instanceof DmError)
  t.is(err.code, 'HUGIN_DM_HOST')
  const unsigned = new DmCrypto({ crypto: net.crypto, host: { ...A.host, sign: async () => { throw new Error('no key') } } })
  await t.exception(unsigned.encrypt(B.address, 'x'), /host.sign failed/)
  await t.exception(A.dm.contactState('short'), /XKR address/)
})

test('dm: lib/dm.js loads only pure JavaScript modules', (t) => {
  const fs = require('#fs')
  const read = (name) => b4a.toString(fs.readFileSync(__dirname + '/../lib/' + name))
  const requires = (src) => [...src.matchAll(/require\('([^']+)'\)/g)].map((m) => m[1])
  t.alike(requires(read('dm.js')).sort(), ['./constants.js', 'b4a', 'js-sha3'])
  t.alike(requires(read('constants.js')), [], 'constants.js requires nothing')
  t.ok(read('dm.js').includes("const SODIUM_MODULE = 'sodium-universal'"), 'sodium-universal is loaded through a variable, where it is installed')
})

// ---------------------------------------------------------------------------------------------
// per-message key

/** secret_key_to_public_key vector of kryptokrona-crypto (tests/crypto.ts, "Secret Key to Public Key"). */
const CN_VECTOR = {
  secret: '4a078e76cd41a3d3b534b83dc6f2ea2de500b653ca82273b7bfad8045d85a400',
  public: '7849297236cd7c0d6c69a3c8c179c038d3c1c434735741bb3c8995c3c9d6f2ac'
}

test('dm: per-message key: scalar*G equals CryptoNote secret_key_to_public_key', (t) => {
  t.is(txKeyBackend(), 'sodium', 'sodium-universal is used under Node and Bare')
  t.is(secretKeyToPublicKey(CN_VECTOR.secret), CN_VECTOR.public, 'known answer (sodium)')
  t.is(secretKeyToPublicKey(CN_VECTOR.secret, { js: true }), CN_VECTOR.public, 'known answer (JavaScript arithmetic)')
  t.is(toHex(edBase(fromHex(CN_VECTOR.secret))), CN_VECTOR.public, 'crypto_scalarmult_ed25519_base_noclamp of the same scalar')
  const one = '01' + '00'.repeat(31)
  const basePoint = '58' + '66'.repeat(31)
  t.is(secretKeyToPublicKey(one), basePoint, '1*G is the base point')
  t.is(secretKeyToPublicKey(one, { js: true }), basePoint)
  const lMinusOne = (L - BigInt(1)).toString(16).padStart(64, '0').match(/../g).reverse().join('')
  t.is(secretKeyToPublicKey(lMinusOne, { js: true }), secretKeyToPublicKey(lMinusOne), '(l - 1)*G')

  for (let i = 0; i < 16; i++) {
    const s = toHex(edScalar('scalar ' + i))
    t.is(secretKeyToPublicKey(s, { js: true }), toHex(edBase(fromHex(s))), 'JavaScript and sodium agree (' + i + ')')
  }

  t.exception(() => secretKeyToPublicKey('ff'.repeat(32)), /below l/)
  t.exception(() => secretKeyToPublicKey('00'.repeat(32)), /non-zero/)
  t.exception(() => secretKeyToPublicKey('abc'), /64 hex/)
})

test('dm: per-message key: 64 random bytes reduced mod l', (t) => {
  const inputs = [new Uint8Array(64).fill(0xff), new Uint8Array(64), Uint8Array.from({ length: 64 }, (_, i) => i)]
  for (let i = 0; i < 8; i++) {
    const wide = b4a.alloc(64)
    sodium.randombytes_buf(wide)
    inputs.push(new Uint8Array(wide))
  }
  for (const wide of inputs) {
    const expected = leToBigInt(wide) % L
    t.is(leToBigInt(scalarReduce(wide)), expected, 'sodium crypto_core_ed25519_scalar_reduce')
    t.is(leToBigInt(scalarReduce(wide, { js: true })), expected, 'JavaScript')
  }

  const seen = new Set()
  for (let i = 0; i < 32; i++) {
    const k = generateTxKey()
    t.ok(/^[0-9a-f]{64}$/.test(k.privateKey) && /^[0-9a-f]{64}$/.test(k.publicKey))
    const r = leToBigInt(fromHex(k.privateKey))
    t.ok(r > BigInt(0) && r < L, 'r is a non-zero scalar below l')
    t.is(k.publicKey, toHex(edBase(fromHex(k.privateKey))), 'txKey = r*G')
    t.is(secretKeyToPublicKey(k.privateKey, { js: true }), k.publicKey)
    seen.add(k.privateKey)
  }
  t.is(seen.size, 32, 'a new scalar every time')
})

test('dm: the provider\'s ephemeralKeypair is never called; payloads round-trip', async (t) => {
  const net = makeEdNet()
  const clock = { now: T0 }
  const A = party(net, 'alice', { clock })
  const B = party(net, 'bob', { clock })

  const texts = ['hello', 'åäö ✓ 🦊', 'x'.repeat(2000), JSON.stringify({ call: 'ab'.repeat(64) })]
  const kinds = []
  for (const text of [...texts, ...texts]) {
    for (const [from, to] of [[A, B], [B, A]]) {
      const m = await send(from, to, text, { name: from.name + ' ✓' })
      kinds.push(m.handshake)
      const w = decodeWire(m.payload)
      t.is(w.txKey, m.payload.slice(18, 82))
      t.is(w.vt, (await net.crypto.viewTag(to.w.keyDerivation(w.txKey))).toLowerCase(), "the recipient's view tag of txKey")
      const r = await open(to, m.payload)
      t.is(r.status, STATUS.OK)
      t.alike(
        r.message,
        { from: from.address, message: text, name: from.name + ' ✓', timestamp: m.timestamp, hash: m.hash, type: r.message.type, established: true },
        'round trip: ' + m.handshake
      )
    }
  }
  t.ok(kinds.includes('initial') && kinds.includes('reply') && kinds.includes('established'), 'all three handshake states')
  const keys = new Set()
  for (let i = 0; i < 8; i++) keys.add(decodeWire((await send(A, B, 'same text')).payload).txKey)
  t.is(keys.size, 8, 'a new txKey for every message')
  t.is(net.calls.ephemeralKeypair, 0, "the provider's ephemeralKeypair was never called")

  // a provider without ephemeralKeypair
  const { ephemeralKeypair, ...provider } = net.crypto
  t.is(typeof ephemeralKeypair, 'function')
  const C = party(net, 'carol', { clock })
  const dm = new DmCrypto({ crypto: provider, host: C.host })
  const m = await dm.encrypt(A.address, 'without ephemeralKeypair')
  t.is((await open(A, m.payload)).message.message, 'without ephemeralKeypair')
  t.is(net.calls.ephemeralKeypair, 0)
})

// ---------------------------------------------------------------------------------------------
// signed string, flags, pool ids, clock

/** The outer plaintext of `payload` for recipient `R`, and how to seal an edited one again. */
async function outerOf(net, payload, R) {
  const c = net.crypto
  const w = decodeWire(payload)
  const key = await c.boxKey(R.w.keyDerivation(w.txKey))
  const nonce = c.nonceFromTimestamp(w.t)
  const plain = c.secretboxOpen(w.box, nonce, key)
  return { w, plain, seal: (outer) => payload.slice(0, 84) + toHex(c.secretboxEncrypt(outer, nonce, key)) }
}

/** `{ flags, from, kem, rest }` of an outer plaintext (kem: kem_pub or kem_ct bytes). */
function splitOuter(plain) {
  const flags = plain[0]
  const from = plain.slice(1, 100)
  const kemLength = flags === 1 ? 800 : flags === 6 ? 768 : 0
  return { flags, from, kem: plain.slice(100, 100 + kemLength), rest: plain.slice(100 + kemLength) }
}

test('dm: SHA-256 of the handshake field', (t) => {
  t.is(sha256Hex(new Uint8Array(0)), 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')
  t.is(sha256Hex(b4a.from('abc')), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad')
  t.is(sha256Hex(b4a.from('abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq')), '248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1')
  for (const n of [0, 1, 55, 56, 63, 64, 65, 119, 120, 128, 768, 800, 4097]) {
    const bytes = b4a.alloc(n)
    sodium.randombytes_buf(bytes)
    t.is(sha256Hex(new Uint8Array(bytes)), sodiumSha256(bytes), n + ' bytes, as libsodium')
  }
  const pub = new Uint8Array(800).fill(1)
  const ct = new Uint8Array(768).fill(2)
  t.is(handshakeDigest(pub, null), sodiumSha256(pub))
  t.is(handshakeDigest(null, ct), sodiumSha256(ct))
  t.is(handshakeDigest(null, null), '')
})

test('dm: signed string binds flags and the handshake field', async (t) => {
  const to = 'SEKR' + 'a'.repeat(95)
  const hs = 'b'.repeat(64)
  t.is(dmSigningPayload(to, 5, 'hi', 1, hs), 'hugin/dm\n' + JSON.stringify([to, 5, 'hi', 1, hs]))
  t.is(dmSigningPayload(to, 5, 'hi', 6, hs.toUpperCase()), 'hugin/dm\n' + JSON.stringify([to, 5, 'hi', 6, hs]))
  t.is(dmSigningPayload(to, 5, 'hi', 4, ''), 'hugin/dm\n' + JSON.stringify([to, 5, 'hi', 4, '']))
  for (const [flags, h] of [[1, ''], [6, ''], [4, hs], [5, hs], [0, ''], [7, hs]]) {
    t.exception(() => dmSigningPayload(to, 5, 'hi', flags, h), /flags|hs/, 'flags ' + flags + ', hs ' + (h ? '64 hex' : "''"))
  }
  t.alike(ACCEPTED_FLAGS, [1, 6, 4])

  const net = makeEdNet()
  const clock = { now: T0 }
  const A = party(net, 'alice', { clock })
  const B = party(net, 'bob', { clock })
  const M = party(net, 'mallory', { clock })
  const kemM = await M.dm.kemIdentity()

  // an initial (flags 1) with another kem_pub
  const a1 = await send(A, B, 'hello')
  {
    const o = await outerOf(net, a1.payload, B)
    const p = splitOuter(o.plain)
    t.is(p.flags, 1)
    const swapped = o.seal(b4a.concat([b4a.from([1]), p.from, kemM.publicKey, p.rest]))
    t.alike(await B.dm.open(swapped), { status: STATUS.REFUSED, reason: 'signature' }, 'another kem_pub in an initial is refused')
    t.is(stored(B, A), null, 'no state for alice')
  }
  t.is((await open(B, a1.payload)).status, STATUS.OK, 'the initial as sent opens')

  // a reply (flags 6) with another kem_ct, its inner box made under that capsule's key
  const b1 = await send(B, A, 'hello back')
  {
    const sb = await B.dm.contactState(A.address)
    const kemA = await A.dm.kemIdentity()
    const o = await outerOf(net, b1.payload, A)
    const p = splitOuter(o.plain)
    t.is(p.flags, 6)
    const nonce = fromHex(o.w.txKey).slice(0, 24)
    const body = net.crypto.secretboxOpen(p.rest, nonce, fromHex(sb.messageKey))
    t.ok(body, 'the test opens the inner box with bob\'s key')
    const other = net.crypto.encapsulate(kemA.publicKey)
    const inner = net.crypto.secretboxEncrypt(body, nonce, other.sharedSecret)
    const swapped = o.seal(b4a.concat([b4a.from([6]), p.from, other.ciphertext, inner]))
    const before = stored(A, B)
    t.alike(await A.dm.open(swapped), { status: STATUS.REFUSED, reason: 'signature' }, 'another kem_ct in a reply is refused')
    t.is(stored(A, B), before, "alice's state is unchanged")
  }
  t.is((await open(A, b1.payload)).status, STATUS.OK, 'the reply as sent opens')
  t.is((await A.dm.contactState(B.address)).messageKey, (await B.dm.contactState(A.address)).messageKey)

  // an established message (flags 4) sealed again with a kem_pub (flags 5)
  t.is((await open(B, (await send(A, B, 'under the key')).payload)).status, STATUS.OK)
  const a3 = await send(A, B, 'established')
  t.is(a3.handshake, 'established')
  {
    const o = await outerOf(net, a3.payload, B)
    const p = splitOuter(o.plain)
    t.is(p.flags, 4)
    const five = b4a.concat([b4a.from([5]), p.from, kemM.publicKey, p.rest])
    t.is(decodeOuter(new Uint8Array(five)), null, 'decodeOuter refuses flags 5')
    const before = stored(B, A)
    t.alike(await B.dm.open(o.seal(five)), { status: STATUS.REFUSED, reason: 'outer' }, 'flags 5 is refused')
    t.is(stored(B, A), before, "bob's state is unchanged")
  }
  t.is((await open(B, a3.payload)).message.message, 'established')
})

test('dm: decodeOuter takes only the flags encrypt writes', (t) => {
  const from = b4a.from('SEKR' + 'a'.repeat(95), 'ascii')
  const body = new Uint8Array(1 + 64 + 2)
  const inner = new Uint8Array(16 + body.length)
  const pub = new Uint8Array(800)
  const ct = new Uint8Array(768)
  const outer = (flags, ...parts) => new Uint8Array(b4a.concat([b4a.from([flags]), from, ...parts]))
  t.is(decodeOuter(outer(1, pub, body)).flags, 1)
  t.is(decodeOuter(outer(6, ct, inner)).flags, 6)
  t.is(decodeOuter(outer(4, inner)).flags, 4)
  t.is(decodeOuter(outer(5, pub, inner)), null, 'flags 5: kem_pub with an inner box')
  t.is(decodeOuter(outer(7, pub, ct, inner)), null, 'flags 7: kem_pub and kem_ct with an inner box')
  t.is(decodeOuter(outer(0, body)), null, 'flags 0')
  t.is(decodeOuter(outer(2, ct, body)), null, 'flags 2')
  t.is(decodeOuter(outer(3, pub, ct, body)), null, 'flags 3')
  t.is(decodeOuter(outer(8, inner)), null, 'unknown bits')
})

test('dm: an older reply arriving late does not replace a pending key', async (t) => {
  // until bob's first key is the smaller one, which the "keep the smaller key" rule would take
  let done = false
  for (let attempt = 0; attempt < 64 && !done; attempt++) {
    const net = makeEdNet()
    const clock = { now: T0 }
    const A = party(net, 'alice', { clock })
    const B = party(net, 'bob', { clock })
    await open(B, (await send(A, B, 'hello')).payload)
    const oldReply = await send(B, A, 'hello back')
    await open(A, oldReply.payload)
    await open(B, (await send(A, B, 'under the key')).payload)
    const oldKey = (await A.dm.contactState(B.address)).messageKey

    // bob's new install: alice makes a new key and sends it with its capsule
    const Bn = party(net, 'bob', { clock })
    t.is((await open(A, (await send(Bn, A, 'new phone')).payload)).status, STATUS.OK)
    const pending = await A.dm.contactState(B.address)
    if (!(oldKey < pending.messageKey)) continue
    done = true
    t.is(pending.pendingKemCapsule.length, 1536)
    t.ok(pending.keyTime > oldReply.timestamp)

    const before = stored(A, B)
    const r = await open(A, oldReply.payload)
    t.is(r.status, STATUS.OK, 'the old reply still opens')
    t.is(r.message.message, 'hello back')
    const after = await A.dm.contactState(B.address)
    t.is(after.messageKey, pending.messageKey, 'the pending key stays')
    t.is(after.pendingKemCapsule, pending.pendingKemCapsule)
    t.is(after.keyTime, pending.keyTime, 'keyTime is not lowered')
    t.is(stored(A, B), before, 'nothing is saved')

    const n2 = await send(A, Bn, 'welcome back')
    t.is(n2.handshake, 'reply')
    t.is((await open(Bn, n2.payload)).message.type, 'message', "the new install takes alice's pending key")
  }
  t.ok(done, 'a run where the old key is the smaller one')
})

test('dm: node pool ids are messageHash(cipher); a body is delivered once', async (t) => {
  const net = makeEdNet()
  const clock = { now: T0 }
  const A = party(net, 'alice', { clock })
  const B = party(net, 'bob', { clock })
  await establish(t, A, B)
  const entry = (m) => ({ hash: m.hash, cipher: m.payload, timestamp: m.timestamp })

  const m1 = await send(A, B, 'pool one')
  const m2 = await send(A, B, 'pool two')
  const other = (h) => ({ hash: h, cipher: m1.payload, timestamp: m1.timestamp })
  const res = await B.dm.openPool([entry(m1), other('ab'.repeat(32)), { hash: 'cd'.repeat(32), cipher: m2.payload }, entry(m2)])
  t.alike(res.messages.map((m) => m.message), ['pool one', 'pool two'], 'each message once')
  t.alike(res.messages.map((m) => m.hash), [m1.hash, m2.hash])
  t.is(res.skipped, 2, 'the entries under another hash')
  t.is((await B.dm.openPool([other('ef'.repeat(32))])).messages.length, 0, 'the same cipher under another hash, later')

  // the body of m3 sealed again under a new txKey (another payload, another message id)
  const m3 = await send(A, B, 'sealed twice')
  const key = (await B.dm.contactState(A.address)).messageKey
  const c = net.crypto
  const o = await outerOf(net, m3.payload, B)
  const p = splitOuter(o.plain)
  const body = c.secretboxOpen(p.rest, fromHex(o.w.txKey).slice(0, 24), fromHex(key))
  const eph = generateTxKey()
  const txKey = fromHex(eph.publicKey)
  const d = await c.friendRequestSecretSender(eph.privateKey, B.address)
  const outer = b4a.concat([b4a.from([4]), p.from, c.secretboxEncrypt(body, txKey.slice(0, 24), fromHex(key))])
  const box = c.secretboxEncrypt(outer, c.nonceFromTimestamp(o.w.t), await c.boxKey(d))
  const copy = '01' + m3.payload.slice(2, 18) + toHex(txKey) + (await c.viewTag(d)) + toHex(box)
  const copyHash = c.messageHash(copy)
  t.not(copyHash, m3.hash)
  t.is((await open(B, copy)).message.message, 'sealed twice', 'the copy opens on its own')

  const both = await B.dm.openPool([entry(m3), { hash: copyHash, cipher: copy, timestamp: m3.timestamp }])
  t.alike(both.messages.map((m) => m.message), ['sealed twice'], 'delivered once')
  t.is(both.skipped, 1)
  t.alike(both.messages[0].hash, m3.hash)

  // the ids and signatures are remembered per DmCrypto (knownPoolHashes seeds the ids)
  const B2 = party(net, 'bob', { store: B.st, clock })
  t.is((await B2.dm.openPool([entry(m1), entry(m2)])).messages.length, 2, 'a new DmCrypto knows only what it opened')
})

test('dm: a message dated more than a day ahead delivers but changes no handshake state', async (t) => {
  const net = makeEdNet()
  const clock = { now: T0 }
  const A = party(net, 'alice', { clock })
  const B = party(net, 'bob', { clock })
  const C = party(net, 'carol', { clock })

  // an initial: a friend request, no key made
  const ahead = await C.dm.encrypt(B.address, 'from the future', { timestamp: clock.now + DAY + 1000 })
  const r1 = await open(B, ahead.payload)
  t.is(r1.status, STATUS.OK)
  t.is(r1.message.type, 'friend-request')
  t.is(r1.message.established, false)
  t.is(stored(B, C), null, 'no state for carol')

  // bob owes alice his capsule; a message under the key dated ahead does not end it
  t.is((await open(B, (await send(A, B, 'hello')).payload)).status, STATUS.OK)
  t.is((await open(A, (await send(B, A, 'hello back')).payload)).status, STATUS.OK)
  const before = stored(B, A)
  t.is(JSON.parse(before).pendingKemCapsule.length, 1536)
  const late = await A.dm.encrypt(B.address, 'ahead', { timestamp: clock.now + 2 * DAY })
  const r2 = await open(B, late.payload)
  t.is(r2.status, STATUS.OK)
  t.is(r2.message.message, 'ahead')
  t.is(r2.message.type, 'message')
  t.is(stored(B, A), before, "bob's state is unchanged")

  // within a day ahead: the usual rules
  const soon = await A.dm.encrypt(B.address, 'soon', { timestamp: clock.now + DAY - 1000 })
  t.is((await open(B, soon.payload)).status, STATUS.OK)
  t.is((await B.dm.contactState(A.address)).pendingKemCapsule, '', 'the capsule arrived')
})
