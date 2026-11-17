'use strict'

const test = require('brittle')
const b4a = require('b4a')
const sodium = require('sodium-universal')
const push = require('../lib/push.js')
const pow = require('../lib/pow.js')
const { NETWORK_ADDRESS, PUSH_SERVER_PUBKEY } = require('../lib/constants.js')
const { utf8ToHex } = require('../lib/bytes.js')
const { keyPairFromSeed } = require('../lib/ed25519.js')
const desktop = require('./fixtures/legacy-desktop.js')
const native = require('./fixtures/legacy-native.js')
const V = require('./fixtures/hugin-relay.json')
const { NODE, ADDRESS, HASH, PAST } = require('./helpers.js')

// cn_fast_hash values computed with kryptokrona-utils (`cn_fast_hash(toHex(s))`):
//   NETWORK_ADDRESS: test/swarm.test.js NODE_MESH_KEY (hugin-node's node-mesh key)
//   '0f' x 32:       test/fixtures/hugin-relay.json identity.hashed
const CN_FAST_HASH_VECTORS = [
  [NETWORK_ADDRESS, 'c9b4d847ffa97a1d49c74d8085b9529c191080704e325cef9229717a8f769614'],
  ['0f'.repeat(32), V.identity.hashed]
]

const INVITE = 'a0'.repeat(32) + 'b1'.repeat(32)

function serverKeys() {
  const publicKey = b4a.alloc(32)
  const secretKey = b4a.alloc(32)
  sodium.crypto_box_keypair(publicKey, secretKey)
  return { publicKey, secretKey }
}

const SHARE = { job_id: V.pow.job.job_id, nonce: V.pow.nonce, result: V.pow.result }

function powFor(hash, timestamp, context) {
  const auth = pow.buildPowAuth({ hash, timestamp, shares: [SHARE], context, keyPair: keyPairFromSeed(b4a.alloc(32, 7)) })
  return pow.powField({ job: V.pow.job, shares: [SHARE], auth })
}

// ---------------------------------------------------------------------------------------------
// view tags

test('cn_fast_hash (keccak-256) vectors', (t) => {
  for (const [input, expected] of CN_FAST_HASH_VECTORS) {
    t.is(push.cnFastHash(b4a.from(input, 'utf8')), expected, input.slice(0, 16))
    t.is(push.cnFastHashHex(utf8ToHex(input)), expected, 'hex input')
  }
})

test('view tags', (t) => {
  const now = PAST
  t.is(push.weekNumber(now), 2862)
  const viewPub = 'ab'.repeat(32)
  const full = push.cnFastHashHex(utf8ToHex(viewPub + '2862'))
  t.is(push.dmViewTag(viewPub, { now }), full.slice(0, 3))
  t.is(push.dmViewTag(viewPub, { now, long: true }), full)
  t.is(push.roomViewTag(INVITE), push.cnFastHash(b4a.from(INVITE, 'hex')).slice(0, 5))
  t.is(push.roomViewTag(INVITE).length, 5)
})

// ---------------------------------------------------------------------------------------------
// push payloads

test('nonceFromTimestamp: same bytes as desktop and native (no longer used by room pushes)', (t) => {
  for (const ts of [PAST, 1, 123, String(PAST), 1731500000123]) {
    const ours = Array.from(push.nonceFromTimestamp(ts))
    t.is(ours.length, 24)
    t.alike(ours, Array.from(desktop.nonceFromTimestamp(ts)), 'desktop ' + ts)
    if (NODE) t.alike(ours, Array.from(native.nonceFromTimestamp(ts)), 'native ' + ts)
  }
})

test('room push: seal, open envelope, open inner box (random nonce in front of the box)', (t) => {
  const keys = serverKeys()
  const message = { hash: HASH, room: INVITE, address: ADDRESS, message: 'hi', name: 'nils', reply: '', signature: '', timestamp: PAST, tip: false }
  const payload = push.roomPushPayload(message)
  t.alike(payload, message, 'the payload is the room message as sent')
  const wire = push.sealRoomPush({ invite: INVITE, payload, timestamp: PAST, serverPublicKey: keys.publicKey })
  t.ok(/^[0-9a-f]+$/.test(wire))

  const outer = push.openPushEnvelope(wire, keys)
  t.is(outer.t, PAST)
  t.is(outer.payload.viewTag, push.roomViewTag(INVITE))

  // hex(nonce || crypto_secretbox_easy(JSON(payload), nonce, invite[0:64]))
  const box = b4a.from(outer.payload.box, 'hex')
  const nonce = box.subarray(0, sodium.crypto_secretbox_NONCEBYTES)
  const plain = b4a.from(JSON.stringify(payload), 'utf8')
  const expected = b4a.alloc(plain.byteLength + sodium.crypto_secretbox_MACBYTES)
  sodium.crypto_secretbox_easy(expected, plain, nonce, b4a.from(INVITE.slice(0, 64), 'hex'))
  t.alike(box.subarray(sodium.crypto_secretbox_NONCEBYTES), expected, 'secretbox under the nonce in front')
  t.not(b4a.toString(nonce, 'hex'), b4a.toString(push.nonceFromTimestamp(PAST), 'hex'), 'not the timestamp nonce')

  const a = push.roomPushBox({ invite: INVITE, payload })
  const b = push.roomPushBox({ invite: INVITE, payload })
  t.not(a, b, 'a new nonce for every box, also for the same payload and time')
  t.not(a.slice(0, 48), b.slice(0, 48))
  const fixed = b4a.alloc(24, 9)
  t.is(push.roomPushBox({ invite: INVITE, payload, nonce: fixed }), push.roomPushBox({ invite: INVITE, payload, nonce: fixed }), 'deterministic with a given nonce')
  t.exception(() => push.roomPushBox({ invite: INVITE, payload, nonce: b4a.alloc(8) }), /nonce/)

  const roomKeys = [{ key: 'ff'.repeat(64), name: 'other' }, { key: INVITE, name: 'room' }]
  t.alike(push.openRoomPush({ cipherHex: outer.payload.box, roomKeys }), { ...payload, roomKey: INVITE, roomName: 'room' })
  t.alike(push.openRoomPush({ cipherHex: a, timestamp: 1, roomKeys }), { ...payload, roomKey: INVITE, roomName: 'room' }, 'the timestamp does not matter')
  const flipped = (b4a.from(a, 'hex')[0] ^ 1).toString(16).padStart(2, '0') + a.slice(2)
  t.is(push.openRoomPush({ cipherHex: flipped, roomKeys }), false, 'another nonce does not open')
  t.is(push.openRoomPush({ cipherHex: a, roomKeys: [{ key: 'ff'.repeat(64) }] }), false, 'wrong room key')
  t.is(push.openRoomPush({ cipherHex: a.slice(0, 80), roomKeys }), false, 'too short')
  t.is(push.openPushEnvelope(wire, serverKeys()), null, 'wrong server key')
  t.exception(() => push.sealRoomPush({ invite: 'xyz', payload, timestamp: PAST }))
})

test('push registration', (t) => {
  const keys = serverKeys()
  const wire = push.sealRegistration({ deviceId: 'dev', viewTag: 'abc', type: 'call', timestamp: PAST, serverPublicKey: keys.publicKey })
  t.alike(push.openPushEnvelope(wire, keys), { t: PAST, payload: { deviceId: 'dev', viewTag: 'abc', type: 'call' } })
  const plain = push.sealRegistration({ deviceId: 'dev', viewTag: 'abc', timestamp: PAST, serverPublicKey: keys.publicKey })
  t.alike(push.openPushEnvelope(plain, keys).payload, { deviceId: 'dev', viewTag: 'abc' })
  t.is(push.sealRegistration({ deviceId: 'd', viewTag: 'v' }).length > 0, true, 'default server key')
  t.is(PUSH_SERVER_PUBKEY.length, 64)
})

test('push registration: same envelope as native encrypt_push_registration', { skip: !NODE }, (t) => {
  const keys = serverKeys()
  const pubHex = b4a.toString(keys.publicKey, 'hex')
  for (const reg of [{ deviceId: 'dev', viewTag: 'abc' }, { deviceId: 'dev', viewTag: 'abc', type: 'call' }]) {
    const theirs = push.openPushEnvelope(native.encrypt_push_registration(reg, PAST, pubHex), keys)
    const ours = push.openPushEnvelope(push.sealRegistration({ ...reg, timestamp: PAST, serverPublicKey: pubHex }), keys)
    t.alike(ours, theirs)
  }
})

// ---------------------------------------------------------------------------------------------
// hugin-node packets

test('sync request always carries a numeric timestamp', (t) => {
  t.alike(push.syncRequest(), { request: true, type: 'some', timestamp: 0, id: 0 })
  t.alike(push.syncRequest({ since: undefined }), { request: true, type: 'some', timestamp: 0, id: 0 })
  t.alike(push.syncRequest({ since: 'x' }), { request: true, type: 'some', timestamp: 0, id: 0 })
  t.alike(push.syncRequest({ since: PAST }), { request: true, type: 'some', timestamp: PAST, id: PAST })
  t.alike(push.syncRequest({ since: PAST, id: 7 }), { request: true, type: 'some', timestamp: PAST, id: 7 })
  t.alike(push.jobRequest('abc'), { type: 'job_request', id: 'abc' })
})

test('post packet: byte-identical to the apps', (t) => {
  const cipher = 'cd'.repeat(40)
  const timestamp = 1731500000000
  const hash = 'ab'.repeat(32)
  const viewtag = 'f00'
  const kind = 'dm'
  const p = powFor(hash, timestamp, pow.postAuthContext(kind, cipher))
  // desktop swarm.cjs NodeConnection.message build_post / native swarm.js message build_payload
  const baseMessage = { cipher, timestamp, hash, id: timestamp, push: true, viewtag, kind }
  const apps = { type: 'post', message: { ...baseMessage, pow: { version: 2, job: p.job, shares: p.shares, auth: p.auth } } }
  const ours = push.postPacket({ cipher, hash, viewtag, kind, timestamp, pow: p })
  t.is(JSON.stringify(ours), JSON.stringify(apps))
  t.is(p.auth.sig, V.auth[0].sig, 'auth matches the hugin-relay vector for this post')
  t.ok(push.encodePacket(ours).length <= 9000)
})

test('register packet: byte-identical to the apps', (t) => {
  const data = JSON.stringify(['sealed-hex'])
  const timestamp = PAST
  const hash = 'ef'.repeat(32)
  const p = powFor(hash, timestamp, pow.registerAuthContext(data))
  const apps = { register: true, data, timestamp, id: timestamp, hash, pow: { version: 2, job: p.job, shares: p.shares, auth: p.auth } }
  t.is(JSON.stringify(push.registerPacket({ data, timestamp, hash, pow: p })), JSON.stringify(apps))
})

test('packet checks and size guard', (t) => {
  const p = powFor('ab'.repeat(32), PAST, '')
  t.exception(() => push.postMessage({ cipher: 'xyz', hash: 'ab', timestamp: PAST }), /cipher/)
  t.exception(() => push.postMessage({ cipher: 'abcd', hash: 'ab', timestamp: PAST, kind: 'other' }), /kind/)
  t.exception(() => push.postMessage({ cipher: 'abcd', hash: 'zz', timestamp: PAST }), /hash/)
  t.exception(() => push.postMessage({ cipher: 'abcd', hash: 'ab' }), /timestamp/)
  t.exception(() => push.postPacket({ cipher: 'abcd', hash: 'ab', timestamp: PAST, pow: { ...p, version: 1 } }), /pow.version/)
  t.exception(() => push.postPacket({ cipher: 'abcd', hash: 'ab', timestamp: PAST, pow: { ...p, shares: [] } }), /pow.shares/)
  const big = push.postPacket({ cipher: 'ab'.repeat(4500), hash: 'ab', timestamp: PAST, pow: p })
  t.exception(() => push.encodePacket(big), /larger than 9000/)
})

test('parseNodePacket follows the apps routing order', (t) => {
  const cases = [
    [{ type: 'new-message', messages: [{ a: 1 }] }, { kind: 'messages', messages: [] }],
    [{ type: 'new-message', messages: [{ hash: HASH, cipher: 'abcd', timestamp: PAST, pow: {}, x: 1 }] }, { kind: 'messages', messages: [{ hash: HASH, cipher: 'abcd', timestamp: PAST }] }],
    [{ address: ADDRESS, version: '2.0.0' }, { kind: 'address', address: ADDRESS, version: '2.0.0' }],
    [{ address: 'short', version: '2.0.0' }, { kind: 'ignored', reason: 'address' }],
    [{ type: 'job', job: V.pow.job }, { kind: 'job', job: V.pow.job, id: undefined, valid: true, reason: undefined }],
    [{ type: 'job', job: { job_id: 'x' }, id: 3 }, { kind: 'job', job: { job_id: 'x' }, id: 3, valid: false, reason: 'invalid_blob' }],
    [{ type: 'job_pending', id: 3 }, { kind: 'job_pending', id: 3 }],
    [{ chunks: true, id: 1, response: [1] }, { kind: 'chunk', id: 1, response: [1] }],
    [{ done: true, id: 1 }, { kind: 'done', id: 1 }],
    [{ success: true, id: 1 }, { kind: 'result', id: 1, success: true }],
    [{ success: true, duplicate: true, id: 1 }, { kind: 'result', id: 1, success: true, duplicate: true }],
    [{ success: false, reason: 'pool_reject', rejects: ['low'], id: 1 }, { kind: 'result', id: 1, success: false, reason: 'pool_reject', rejects: ['low'] }],
    [{ response: [], id: 1 }, { kind: 'response', id: 1, response: [] }],
    [{ version: '2.0.0' }, { kind: 'hello', version: '2.0.0' }],
    [{ other: 1 }, { kind: 'ignored', reason: 'unknown' }],
    ['not json', { kind: 'invalid', reason: 'not_json' }],
    ['[1]', { kind: 'invalid', reason: 'not_object' }]
  ]
  for (const [input, expected] of cases) {
    const raw = typeof input === 'string' ? input : JSON.stringify(input)
    t.alike(push.parseNodePacket(raw), expected, raw.slice(0, 40))
  }
  t.is(push.parseNodePacket(b4a.from(JSON.stringify({ version: '1' }))).kind, 'hello', 'bytes input')
})

test('nodeResult and syncMessages', (t) => {
  const parse = (o) => push.parseNodePacket(JSON.stringify(o))
  t.alike(push.nodeResult(parse({ success: true, id: 5, extra: 1 })), { success: true, id: 5 })
  t.alike(push.nodeResult(parse({ success: true, duplicate: true, id: 5 })), { success: true, id: 5, duplicate: true })
  t.alike(push.nodeResult(parse({ success: false, reason: 'pool_reject', rejects: ['low'], id: 'a' })), {
    success: false,
    id: 'a',
    reason: 'pool_reject',
    rejects: ['low']
  })
  t.alike(push.nodeResult(parse({ success: 'yes', id: 1 })), { success: false, id: 1 }, 'only true is success')
  t.alike(push.nodeResult(parse({ response: [] })), { success: false, reason: 'unknown' })
  const ok = { hash: HASH, cipher: 'ab'.repeat(10), timestamp: PAST }
  t.alike(push.syncMessages([{ a: 1 }, null, 3, [1], ok]), [ok])
  t.alike(push.syncMessages(undefined), [])
})

test('node messages: only well-formed fields reach the host', (t) => {
  const ok = { hash: HASH, cipher: 'ab'.repeat(10), timestamp: PAST }
  t.alike(push.nodeMessage(ok), ok)
  t.alike(push.nodeMessage({ ...ok, viewtag: 'abc', kind: 'room', pow: { job: 1 }, id: 5, push: true, extra: 'x' }), { ...ok, viewtag: 'abc', kind: 'room' }, 'known fields only')
  t.alike(push.nodeMessage({ ...ok, viewtag: 'xyz', kind: 'other' }), ok, 'malformed optional fields dropped')
  t.alike(push.nodeMessage({ ...ok, hash: HASH.toUpperCase() }), { ...ok, hash: HASH.toUpperCase() }, 'hex of either case')
  const bad = [
    { ...ok, hash: HASH.slice(1) },
    { ...ok, hash: ' '.repeat(64) },
    { ...ok, hash: 'g'.repeat(64) },
    { ...ok, hash: 5 },
    { ...ok, cipher: 'abc' },
    { ...ok, cipher: 'zz' },
    { ...ok, cipher: '' },
    { ...ok, cipher: 'ab'.repeat(4501) },
    { ...ok, timestamp: '1' },
    { ...ok, timestamp: NaN },
    { ...ok, timestamp: Infinity },
    { cipher: ok.cipher, timestamp: PAST },
    null,
    [ok],
    'x'
  ]
  for (const m of bad) t.is(push.nodeMessage(m), null, JSON.stringify(m) ? JSON.stringify(m).slice(0, 60) : String(m))
  t.ok(push.nodeMessage({ ...ok, cipher: 'ab'.repeat(4500) }), '9000 hex characters')
  const many = new Array(600).fill(ok)
  t.is(push.nodeMessages(many).length, 500, 'at most 500')
  t.is(push.nodeMessages(many, 3).length, 3)
  t.is(push.parseNodePacket(JSON.stringify({ type: 'new-message', messages: many })).messages.length, 500)
})
