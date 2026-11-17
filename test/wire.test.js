'use strict'

const test = require('brittle')
const b4a = require('b4a')
const wire = require('../lib/wire.js')
const desktop = require('./fixtures/legacy-desktop.js')
const native = require('./fixtures/legacy-native.js')
const p2p2 = require('./fixtures/legacy-hugin-p2p-2.js')
const { ADDRESS, ADDRESS_2, HASH, HASH_2, CONTENT_HASH, TOPIC, DRIVE_KEY, PAST, legacy } = require('./helpers.js')

const INVITE = 'a0'.repeat(64)
const ID_SIG = 'i'.repeat(128)
const SIG = 's'.repeat(128)
/** A room message signature has the XKR format: 128 hex characters. */
const RSIG = '5a'.repeat(64)
const AVATAR = 'QUJDRA=='

const roundTrip = (msg, opts) => wire.decode(wire.encode(msg), opts)

// ---------------------------------------------------------------------------------------------
// builders: round trips and acceptance by both old validators

test('joined', (t) => {
  const msg = wire.joined({
    address: ADDRESS,
    name: 'nils',
    avatar: AVATAR,
    topic: TOPIC,
    signature: 'ab'.repeat(64),
    idSig: ID_SIG,
    time: PAST,
    video: true,
    messages: [{ hash: HASH, room: INVITE, address: ADDRESS_2, message: 'm', name: 'x', timestamp: PAST }],
    driveKey: DRIVE_KEY
  })
  t.is(msg.message, TOPIC, 'message carries the topic')
  t.is(msg.voice, true, 'video implies voice')
  t.is(msg.time, String(PAST))
  t.is(msg.driveKey, DRIVE_KEY)
  t.ok(legacy(desktop.sanitize_join_swarm_data, msg), 'desktop accepts')
  t.ok(legacy(native.sanitize_join_swarm_data, msg), 'native accepts')

  const r = roundTrip(msg)
  t.is(r.type, 'joined')
  t.is(r.value.address, ADDRESS)
  t.is(r.value.driveKey, DRIVE_KEY)
  t.is(r.value.avatar, AVATAR)
  t.is(r.value.messages.length, 1)

  const plain = wire.joined({ address: ADDRESS, name: 'n', topic: TOPIC, idSig: ID_SIG, time: '1', driveKey: null, avatar: 'A'.repeat(266668) })
  t.absent('driveKey' in plain, 'no driveKey key unless it is 64 hex')
  t.is(plain.avatar, '', 'an avatar desktop would refuse is not sent')
  t.is(plain.signature, '')
  t.ok(legacy(desktop.sanitize_join_swarm_data, plain))
  t.ok(legacy(native.sanitize_join_swarm_data, plain))

  t.exception(() => wire.joined({ address: 'a'.repeat(100), name: 'n', topic: TOPIC, idSig: ID_SIG, time: 1 }), /address/)
  t.exception(() => wire.joined({ address: ADDRESS, name: 'n', topic: 'short', idSig: ID_SIG, time: 1 }), /topic/)
  t.exception(() => wire.joined({ address: ADDRESS, name: 'n', topic: TOPIC, idSig: '', time: 1 }), /idSig/)
  t.exception(() => wire.joined({ address: ADDRESS, name: 'n', topic: TOPIC, idSig: ID_SIG, time: 1, signature: 'x' }), /signature/)
})

test('room message', (t) => {
  const msg = wire.roomMessage({ hash: HASH, room: INVITE, address: ADDRESS, message: 'hello', name: 'nils', signature: RSIG, timestamp: PAST, tip: { amount: 5, receiver: ADDRESS_2 } })
  t.alike(Object.keys(msg), ['hash', 'room', 'address', 'message', 'name', 'reply', 'signature', 'timestamp', 'tip'])
  t.ok(legacy(desktop.sanitize_group_message, msg), 'desktop accepts')
  t.ok(legacy(native.sanitize_group_message, msg), 'native accepts')
  const r = roundTrip(msg)
  t.is(r.type, 'room-message')
  t.alike(r.value, { message: 'hello', address: ADDRESS, signature: RSIG, room: INVITE, timestamp: PAST, name: 'nils', reply: '', hash: HASH, tip: { amount: 5, receiver: ADDRESS_2 } })

  // the signature is required, in the XKR format, on both sides
  const base = { hash: HASH, room: INVITE, address: ADDRESS, message: 'x', name: 'n', timestamp: PAST }
  t.exception(() => wire.roomMessage(base), /signature/, 'unsigned')
  t.exception(() => wire.roomMessage({ ...base, signature: 'sig' }), /signature/, "native's old placeholder")
  t.exception(() => wire.roomMessage({ ...base, signature: 'ab'.repeat(63) }), /signature/, '126 hex')
  t.exception(() => wire.roomMessage({ ...base, signature: 'zz'.repeat(64) }), /signature/, 'not hex')
  t.exception(() => wire.roomMessage({ ...base, signature: RSIG, timestamp: PAST + 0.5 }), /timestamp/, 'not an integer')
  const unsigned = roundTrip({ ...msg, signature: '' })
  t.is(unsigned.type, 'invalid', 'an unsigned room message is refused')
  t.is(unsigned.ban, false, 'dropped, not a ban')
  t.is(roundTrip({ ...msg, signature: 'sig' }).type, 'invalid')
  t.is(roundTrip({ ...msg, signature: RSIG.toUpperCase() }).type, 'room-message', 'either case')
  const future = Date.now() + 3600000
  t.is(roundTrip({ ...msg, timestamp: future }).value.timestamp, future, 'a future timestamp is kept as signed (lib/room.js drops it)')

  t.exception(() => wire.roomMessage({ hash: 'a'.repeat(65), room: INVITE, address: ADDRESS, message: 'x', name: 'n', signature: RSIG, timestamp: PAST }), /hash/)
  t.exception(() => wire.roomMessage({ hash: HASH, room: INVITE, address: 'a'.repeat(100), message: 'x', name: 'n', signature: RSIG, timestamp: PAST }), /address/)
  t.exception(() => wire.roomMessage({ hash: HASH, room: INVITE, address: ADDRESS, message: 'x'.repeat(778), name: 'n', signature: RSIG, timestamp: PAST }), /message/)
  t.exception(() => wire.roomMessage({ hash: HASH, room: INVITE, address: ADDRESS, message: 'x', name: 'n', signature: RSIG, timestamp: '1' }), /timestamp/)
  t.exception(() => wire.roomMessage({ hash: HASH, room: INVITE, address: ADDRESS, message: 'x', name: 'n', signature: RSIG, timestamp: PAST, tip: { amount: 1, receiver: 'r'.repeat(101) } }), /tip.receiver/)
})

test('room message signing payload: exact encoding', (t) => {
  const m = { hash: HASH, room: INVITE, address: ADDRESS, message: 'hello "world"\n', name: 'nils', reply: HASH_2, signature: RSIG, timestamp: PAST, tip: { amount: 5, receiver: ADDRESS_2 } }
  t.is(wire.ROOM_MESSAGE_DOMAIN, 'hugin/room-message\n')
  t.is(
    wire.roomMessageSigningPayload(m),
    'hugin/room-message\n["' + INVITE + '","' + HASH + '",' + PAST + ',"' + ADDRESS + '","nils","hello \\"world\\"\\n","' + HASH_2 + '",[5,"' + ADDRESS_2 + '"]]'
  )
  t.is(
    wire.roomMessageSigningPayload({ ...m, message: 'hi', reply: '', tip: false }),
    'hugin/room-message\n["' + INVITE + '","' + HASH + '",' + PAST + ',"' + ADDRESS + '","nils","hi","",null]',
    'no reply, no tip'
  )
  // the builder output, a validated message and the same fields with other extras sign alike
  const built = wire.roomMessage(m)
  const decoded = wire.decode(wire.encode(built)).value
  t.is(wire.roomMessageSigningPayload(decoded), wire.roomMessageSigningPayload(m))
  t.is(wire.roomMessageSigningPayload({ ...m, signature: 'other', sent: true, channel: 'channel' }), wire.roomMessageSigningPayload(m), 'signature and extra columns are not signed')
  t.is(wire.roomMessageSigningPayload({ ...m, hash: HASH.toUpperCase() }), wire.roomMessageSigningPayload(m), 'the hash in lower case')
  t.is(wire.roomMessageSigningPayload({ ...m, reply: undefined, tip: undefined }), wire.roomMessageSigningPayload({ ...m, reply: '', tip: false }))
  t.is(wire.roomMessageSigningPayload({ ...m, tip: null }), wire.roomMessageSigningPayload({ ...m, tip: false }))

  t.exception(() => wire.roomMessageSigningPayload({ ...m, timestamp: String(PAST) }), /timestamp/)
  t.exception(() => wire.roomMessageSigningPayload({ ...m, timestamp: 1.5 }), /timestamp/)
  t.exception(() => wire.roomMessageSigningPayload({ ...m, timestamp: 2 ** 53 }), /timestamp/)
  t.exception(() => wire.roomMessageSigningPayload({ ...m, message: 42 }), /message/)
  t.exception(() => wire.roomMessageSigningPayload({ ...m, tip: { amount: '5', receiver: ADDRESS } }), /tip/)
  t.exception(() => wire.roomMessageSigningPayload({ ...m, hash: 'not hex' }), /hash/)
  t.exception(() => wire.roomMessageSigningPayload(null), /message/)
})

test('room message hash: derived from the content', (t) => {
  const m = { room: INVITE, address: ADDRESS, message: 'hi', name: 'nils', reply: '', timestamp: PAST, tip: false }
  const h = wire.roomMessageHash(m)
  t.ok(/^[0-9a-f]{64}$/.test(h), '64 lower-case hex characters')
  t.is(wire.roomMessageHash({ ...m, hash: HASH, signature: RSIG }), h, 'hash and signature are not part of it')
  t.is(wire.roomMessageHash({ ...m, reply: undefined, tip: null }), h, 'no reply and no tip as in the signed payload')
  for (const change of [{ room: 'b0'.repeat(64) }, { address: ADDRESS_2 }, { message: 'ho' }, { name: 'n' }, { reply: HASH }, { timestamp: PAST + 1 }, { tip: { amount: 1, receiver: ADDRESS_2 } }]) {
    t.not(wire.roomMessageHash({ ...m, ...change }), h, 'covers ' + Object.keys(change)[0])
  }
  t.ok(wire.isRoomMessageHash({ ...m, hash: h }))
  t.ok(wire.isRoomMessageHash({ ...m, hash: h.toUpperCase() }), 'either case')
  t.absent(wire.isRoomMessageHash({ ...m, hash: HASH }))
  t.absent(wire.isRoomMessageHash({ ...m, hash: h, timestamp: 1.5 }), 'malformed: false')
  t.exception(() => wire.roomMessageHash({ ...m, message: 42 }), /message/)
})

test('room message signing payload: different messages never share a payload', (t) => {
  const base = { hash: HASH, room: INVITE, address: ADDRESS, message: 'ab', name: 'nils', reply: '', timestamp: PAST, tip: false }
  const variants = [
    base,
    // field-boundary shifts between neighbouring text fields
    { ...base, message: 'a', reply: 'b' },
    { ...base, name: 'nilsab', message: '' },
    { ...base, name: 'nil', message: 'sab' },
    { ...base, name: 'nils","ab', message: '' },
    { ...base, message: 'ab","' },
    { ...base, message: 'ab",' + PAST, reply: '' },
    { ...base, address: ADDRESS + 'nils', name: '' },
    { ...base, room: INVITE + HASH, hash: HASH },
    // tip encodings
    { ...base, tip: { amount: 0, receiver: '' } },
    { ...base, tip: { amount: 5, receiver: ADDRESS_2 } },
    { ...base, tip: { amount: 52, receiver: ADDRESS_2.slice(1) } },
    { ...base, message: 'abnull' },
    { ...base, message: 'ab', reply: 'null' },
    // numbers vs strings, lone surrogates vs the replacement character
    { ...base, timestamp: PAST + 1 },
    { ...base, message: '\ud800' },
    { ...base, message: '\ufffd' },
    { ...base, message: '\u0000' },
    { ...base, message: '' }
  ]
  const payloads = variants.map((v) => wire.roomMessageSigningPayload(v))
  t.is(new Set(payloads).size, payloads.length, 'all distinct')
  // as UTF-8 bytes (what kryptokrona-utils signs) too
  t.is(new Set(payloads.map((p) => b4a.toString(b4a.from(p, 'utf8'), 'hex'))).size, payloads.length, 'distinct as UTF-8')
  // and the payload decodes back to exactly the fields
  for (const v of variants) {
    const p = wire.roomMessageSigningPayload(v)
    const fields = JSON.parse(p.slice(wire.ROOM_MESSAGE_DOMAIN.length))
    t.alike(fields, [v.room, v.hash.toLowerCase(), v.timestamp, v.address, v.name, v.message, v.reply, v.tip ? [v.tip.amount, v.tip.receiver] : null])
  }
})

test('typing, ban, disconnected', (t) => {
  t.alike(roundTrip(wire.typing(true)), { type: 'typing', value: { typing: true } })
  t.exception(() => wire.typing('yes'))
  t.alike(roundTrip(wire.ban(ADDRESS)), { type: 'ban', value: { type: 'ban', address: ADDRESS } })
  t.alike(roundTrip(wire.disconnected()), { type: 'disconnected', value: { type: 'disconnected' } })
  t.ok(desktop.sanitize_typing_message(wire.typing(false))[1])
})

test('feed', (t) => {
  const msg = wire.feed({ message: 'post', nickname: 'nils', address: ADDRESS, hash: HASH, timestamp: PAST, signature: SIG })
  t.alike(Object.keys(msg), ['type', 'message', 'nickname', 'address', 'reply', 'tip', 'hash', 'timestamp', 'signature'])
  t.ok(legacy(desktop.sanitize_feed_message, msg), 'desktop accepts')
  const r = roundTrip(msg)
  t.is(r.type, 'feed')
  t.is(r.value.signature, SIG)
  t.exception(() => wire.feed({ message: 'post', nickname: 'nils', address: ADDRESS, hash: HASH, timestamp: PAST, signature: '' }), /signature/)
  t.exception(() => wire.feed({ message: 'post', nickname: 'nils', address: ADDRESS, hash: HASH, timestamp: PAST + 0.5, signature: SIG }), /timestamp/)
})

test('feed signing payload and hash: exact encoding, every field covered', (t) => {
  const m = { message: 'hello "world"', nickname: 'nils', address: ADDRESS, reply: HASH_2, tip: { amount: 5, receiver: ADDRESS_2 }, hash: HASH, timestamp: PAST }
  t.is(
    wire.feedSigningPayload(m),
    'hugin/feed\n["' + HASH + '",' + PAST + ',"' + ADDRESS + '","nils","hello \\"world\\"","' + HASH_2 + '",[5,"' + ADDRESS_2 + '"]]'
  )
  t.is(wire.feedSigningPayload({ ...m, reply: undefined, tip: false }), 'hugin/feed\n["' + HASH + '",' + PAST + ',"' + ADDRESS + '","nils","hello \\"world\\"","",null]')
  t.is(wire.feedSigningPayload({ ...m, hash: HASH.toUpperCase() }), wire.feedSigningPayload(m), 'the hash in lower case')
  t.is(wire.feedSigningPayload({ ...m, signature: 'x', type: 'feed' }), wire.feedSigningPayload(m), 'signature and type are not signed')
  for (const change of [{ message: 'other' }, { nickname: 'other' }, { address: ADDRESS_2 }, { reply: '' }, { tip: false }, { tip: { amount: 6, receiver: ADDRESS_2 } }, { timestamp: PAST + 1 }, { hash: HASH_2 }]) {
    t.not(wire.feedSigningPayload({ ...m, ...change }), wire.feedSigningPayload(m), 'covers ' + Object.keys(change)[0])
  }
  t.exception(() => wire.feedSigningPayload({ ...m, timestamp: String(PAST) }), /timestamp/)
  t.exception(() => wire.feedSigningPayload({ ...m, hash: 'not hex' }), /hash/)

  const h = wire.feedMessageHash(m)
  t.ok(/^[0-9a-f]{64}$/.test(h), '64 lower-case hex characters')
  t.is(wire.feedMessageHash({ ...m, hash: 'anything', signature: 'x' }), h, 'hash and signature are not part of it')
  t.not(wire.feedMessageHash({ ...m, message: 'other' }), h)
  t.ok(wire.isFeedMessageHash({ ...m, hash: h }))
  t.ok(wire.isFeedMessageHash({ ...m, hash: h.toUpperCase() }), 'either case')
  t.absent(wire.isFeedMessageHash({ ...m, hash: HASH }))
  t.absent(wire.isFeedMessageHash({ ...m, hash: h, timestamp: 'x' }), 'malformed: false')
})

test('Ping and history messages', (t) => {
  const file = { fileName: 'cat.png', hash: HASH, contentHash: CONTENT_HASH, size: 10, time: PAST, address: ADDRESS, name: 'nils', topic: TOPIC, signature: SIG, info: 'file-shared', type: 'file' }
  const ping = wire.ping({ peers: [TOPIC, 'bad'], files: [file], hashes: [HASH, HASH_2, 'not-a-hash'] })
  t.alike(ping, { type: 'Ping', peers: [TOPIC], files: [file], hashes: [HASH, HASH_2] }, 'non-64-hex entries are dropped')
  const r = roundTrip(ping)
  t.is(r.type, 'ping')
  t.alike(r.value.hashes, [HASH, HASH_2])
  t.alike(r.value.files, [file])
  const withoutContentHash = { ...file }
  delete withoutContentHash.contentHash
  t.alike(roundTrip(wire.ping({ files: [withoutContentHash, file] })).value.files, [file], 'a listed file without contentHash is skipped')
  t.exception(() => wire.ping({ hashes: new Array(26).fill(HASH) }), /hashes/)
  t.exception(() => wire.ping({ files: new Array(11).fill(file) }), /files/)

  t.alike(roundTrip(wire.requestMessages([HASH])), { type: 'request-messages', value: { type: 'request-messages', hashes: [HASH] } })
  const room = wire.roomMessage({ hash: HASH, room: INVITE, address: ADDRESS, message: 'm', name: 'n', signature: RSIG, timestamp: PAST })
  t.is(roundTrip(wire.missingMessages([room])).value.messages.length, 1)
  t.alike(roundTrip(wire.requestHistory([file])).value.files, [file])
  const sh = roundTrip(wire.sendHistory({ messages: [room], files: [file] }))
  t.is(sh.type, 'send-history')
  t.is(sh.value.files.length, 1)
  t.alike(roundTrip(wire.requestFeed()), { type: 'request-feed', value: { type: 'request-feed' } })
  const feed = wire.feed({ message: 'post', nickname: 'nils', address: ADDRESS, hash: HASH, timestamp: PAST, signature: SIG })
  t.is(roundTrip(wire.sendFeedHistory([feed])).value.messages.length, 1)

  const files = [{ time: 3 }, { time: 1 }, { time: 2 }]
  t.alike(wire.recentFiles(files, 2), [{ time: 2 }, { time: 3 }])
})

test('voice status and SDP', (t) => {
  const msg = wire.voiceStatus({ address: ADDRESS, avatar: AVATAR, signature: SIG, topic: TOPIC, name: 'nils', voice: true, video: false, audioMute: false, videoMute: false, screenshare: false })
  t.is(msg.message, TOPIC)
  t.absent('signature' in msg, 'voice status is not signed')
  const r = roundTrip(msg)
  t.is(r.type, 'voice')
  t.absent('signature' in r.value)
  const withSig = roundTrip({ ...msg, signature: SIG })
  t.is(withSig.type, 'voice', 'a signature field is ignored')
  t.absent('signature' in withSig.value)
  t.is(wire.voiceSigningPayload, undefined, 'nothing to sign')

  t.alike(wire.sdpFlags({ type: 'offer', data: { sdp: 'x' } }), { offer: true, retry: false })
  t.alike(wire.sdpFlags({ type: 'answer', data: { sdp: 'x' } }), { offer: false, retry: false })
  t.alike(wire.sdpFlags({ type: 'offer', data: { renegotiate: true } }), { offer: false, retry: false })
  t.alike(wire.sdpFlags({ type: 'offer', data: 'compressed', retry: true }), { offer: true, retry: true })
  const sdp = wire.sdp({ data: { sdp: 'v=0' }, offer: true, address: ADDRESS, topic: TOPIC })
  t.alike(roundTrip(sdp), { type: 'sdp', value: { data: { sdp: 'v=0' }, offer: true, address: ADDRESS, topic: TOPIC, retry: false } })
})

test('file announcement', (t) => {
  const msg = wire.fileShared({ fileName: 'cat.png', address: ADDRESS, name: 'nils', topic: TOPIC, size: 1234, time: PAST, hash: HASH, contentHash: CONTENT_HASH, signature: SIG })
  t.absent('driveKey' in msg)
  t.is(msg.contentHash, CONTENT_HASH)
  t.ok(legacy(desktop.sanitize_file_message, msg), 'desktop accepts')
  t.ok(legacy(native.sanitize_file_message, msg), 'native accepts')
  const r = roundTrip(msg)
  t.is(r.type, 'file')
  t.is(r.value.size, 1234)
  t.is(r.value.contentHash, CONTENT_HASH)
  t.is(
    wire.fileSigningPayload({ topic: TOPIC, hash: HASH, contentHash: CONTENT_HASH, size: 1234, time: PAST, fileName: 'cat.png', address: ADDRESS }),
    'hugin/file\n["' + TOPIC + '","' + HASH + '","' + CONTENT_HASH + '",1234,' + PAST + ',"cat.png","' + ADDRESS + '"]'
  )
  t.is(
    wire.fileSigningPayload({ ...msg, topic: TOPIC.toUpperCase(), hash: HASH.toUpperCase(), contentHash: CONTENT_HASH.toUpperCase() }),
    wire.fileSigningPayload(msg),
    'topic, hash and contentHash in lower case'
  )
  t.not(wire.fileSigningPayload({ ...msg, contentHash: HASH_2 }), wire.fileSigningPayload(msg), 'the content hash is signed')
  t.exception(() => wire.fileSigningPayload({ ...msg, topic: 'x' }), /topic/)
  t.exception(() => wire.fileSigningPayload({ ...msg, contentHash: undefined }), /contentHash/)
  t.exception(() => wire.fileSigningPayload({ ...msg, contentHash: 'ab'.repeat(31) }), /contentHash/)
  t.exception(() => wire.fileSigningPayload({ ...msg, size: 1.5 }), /size/)
  t.exception(() => wire.fileSigningPayload({ ...msg, address: undefined }), /address/)
  const fields = { fileName: 'cat.png', address: ADDRESS, name: 'n', topic: TOPIC, size: 1, time: 1, hash: HASH, contentHash: CONTENT_HASH, signature: SIG }
  t.exception(() => wire.fileShared({ ...fields, fileName: 'f'.repeat(101) }), /fileName/)
  t.exception(() => wire.fileShared({ ...fields, contentHash: undefined }), /contentHash/)
  t.exception(() => wire.fileShared({ ...fields, contentHash: 'zz'.repeat(32) }), /contentHash/)
})

// ---------------------------------------------------------------------------------------------
// what the apps send today (built as their code builds it) decodes

function goldenMessages() {
  const historyRowDesktop = { message: 'old', address: ADDRESS_2, signature: '', room: INVITE, timestamp: PAST, name: 'x', reply: '', hash: HASH_2, sent: 1, tip: JSON.stringify({ amount: 1, receiver: ADDRESS }) }
  const historyRowNative = { address: ADDRESS_2, message: 'old', room: INVITE, reply: '', timestamp: PAST, nickname: 'x', hash: HASH_2, sent: 0 }
  const file = { name: 'nils', topic: TOPIC, time: PAST, size: 10, hash: HASH, fileName: 'cat.png', address: ADDRESS, signature: SIG, info: 'file-shared', type: 'file' }

  // desktop swarm.cjs send_joined_message 1598-1642
  const desktopJoined = { address: ADDRESS, signature: 'ab'.repeat(64), avatar: AVATAR, message: INVITE, joined: true, topic: TOPIC, name: 'nils', voice: false, channels: [], video: false, time: String(PAST), idSig: ID_SIG, audioMute: false, videoMute: false, screenshare: false, messages: [historyRowDesktop], driveKey: DRIVE_KEY }
  // native swarm.js send_joined_message 1058-1106
  const nativeJoined = { address: ADDRESS, channels: [], joined: true, message: TOPIC, name: 'nils', avatar: 'A'.repeat(300000), signature: '', time: PAST, topic: TOPIC, video: false, voice: false, idSig: ID_SIG, audioMute: false, videoMute: false, screenshare: false, messages: [historyRowNative], driveKey: DRIVE_KEY }
  // desktop: renderer message -> hugin-p2p 2.1.0 sanitize_group_message -> sent = true (messages.cjs:884-894)
  const desktopRoom = p2p2.sanitize_group_message({ message: 'hi', room: INVITE, reply: '', address: ADDRESS, timestamp: String(PAST), name: 'nils', hash: HASH, swarm: true, sent: true, tip: false })
  desktopRoom.sent = true
  // native swarm.js send_message 1029-1045
  const nativeRoom = { hash: HASH, room: INVITE, address: ADDRESS, message: 'hi', name: 'nils', reply: '', signature: 'sig', timestamp: PAST, tip: false }
  // desktop swarm.cjs send_feed_message 1367-1391 (tip false), native swarm.js 2045-2059 (reply may be undefined)
  const desktopFeed = { type: 'feed', message: 'post', nickname: 'nils', address: ADDRESS, reply: '', tip: false, hash: HASH, timestamp: PAST, signature: SIG }
  const nativeFeed = { type: 'feed', message: 'post', nickname: 'nils', address: ADDRESS, tip: false, hash: HASH, timestamp: PAST, signature: SIG }
  // desktop share_file 1857-1881 (with driveKey), native share_file_info 1700-1770
  const desktopFile = { fileName: 'cat.png', address: ADDRESS, name: 'nils', topic: TOPIC, info: 'file-shared', type: 'file', size: 10, time: PAST, hash: HASH, signature: SIG, driveKey: DRIVE_KEY }
  const nativeFile = { address: ADDRESS, fileName: 'cat.png', name: 'nils', hash: HASH, info: 'file-shared', size: 10, time: PAST, topic: TOPIC, type: 'file', signature: SIG }
  // voice status: desktop 958-1001, native 1845-1890
  const voice = { address: ADDRESS, avatar: AVATAR, signature: SIG, message: TOPIC, voice: true, topic: TOPIC, name: 'nils', video: false, audioMute: false, videoMute: true, screenshare: false }
  // SDP: desktop get_sdp 1999-2025 / native send_sdp 1810-1835
  const sdp = { data: { type: 'offer', sdp: 'v=0' }, offer: true, address: ADDRESS, topic: TOPIC, retry: false }
  // Ping: desktop check_online_state 1689-1726, native check_if_online 2092-2141
  const ping = { type: 'Ping', peers: [TOPIC], files: [file], hashes: [HASH, HASH_2] }

  return [
    ['desktop joined', desktopJoined, 'joined'],
    ['native joined (avatar over 200 000 bytes)', nativeJoined, 'joined'],
    // unsigned: refused since hugin-network 3.0 (room messages carry the author's XKR signature)
    ['desktop room message (unsigned: refused)', desktopRoom, 'invalid'],
    ['native room message (signature: sig: refused)', nativeRoom, 'invalid'],
    ['room message signed as in hugin-network 3.0', { ...nativeRoom, signature: RSIG }, 'room-message'],
    ['typing', { typing: true }, 'typing'],
    ['desktop feed', desktopFeed, 'feed'],
    ['native feed', nativeFeed, 'feed'],
    // without a content hash: refused since hugin-network 3.0 (contentHash is part of the signed file string)
    ['desktop file-shared (no contentHash: refused)', desktopFile, 'invalid'],
    ['native file-shared (no contentHash: refused)', nativeFile, 'invalid'],
    ['file-shared with a content hash as in hugin-network 3.0', { ...nativeFile, contentHash: CONTENT_HASH }, 'file'],
    ['voice status', voice, 'voice'],
    ['sdp', sdp, 'sdp'],
    ['ping', ping, 'ping'],
    ['ping without hashes (idle connection)', { type: 'Ping', peers: [], files: [], hashes: [] }, 'ping'],
    ['request-messages', { type: 'request-messages', hashes: [HASH] }, 'request-messages'],
    ['missing-messages (desktop rows)', { type: 'missing-messages', messages: [historyRowDesktop] }, 'missing-messages'],
    ['request-history', { type: 'request-history', files: [file] }, 'request-history'],
    ['send-history', { type: 'send-history', messages: [historyRowNative], files: [file] }, 'send-history'],
    ['request-feed', { type: 'request-feed' }, 'request-feed'],
    ['send-feed-history', { type: 'send-feed-history', messages: [desktopFeed] }, 'send-feed-history'],
    ['ban', { type: 'ban', address: ADDRESS_2 }, 'ban'],
    ['disconnected', { type: 'disconnected' }, 'disconnected']
  ]
}

test('every message the apps send today is accepted (room messages only signed, files only with a content hash)', (t) => {
  for (const [name, msg, type] of goldenMessages()) {
    const r = wire.decode(JSON.stringify(msg))
    t.is(r.type, type, name)
  }
  const golden = Object.fromEntries(goldenMessages().map(([name, msg]) => [name, msg]))
  const row = golden['missing-messages (desktop rows)'].messages[0]
  t.is(wire.decode(JSON.stringify({ type: 'missing-messages', messages: [row] })).value.messages.length, 0, 'an unsigned row is dropped')
  const rows = wire.decode(JSON.stringify({ type: 'missing-messages', messages: [{ ...row, signature: RSIG }] }))
  t.alike(rows.value.messages[0].tip, { amount: 1, receiver: ADDRESS }, 'tip stored as JSON in desktop rows')
  const nativeJoined = wire.decode(JSON.stringify(goldenMessages()[1][1]))
  t.is(nativeJoined.value.avatar.length, 300000, 'a large native avatar is kept')
})

test('desktop room message as sent is the shape the builder makes, plus two keys', (t) => {
  const golden = goldenMessages()[2][1]
  t.alike(Object.keys(golden).sort(), ['address', 'channel', 'hash', 'message', 'name', 'reply', 'room', 'sent', 'signature', 'timestamp', 'tip'])
  t.is(golden.signature, '')
})

// ---------------------------------------------------------------------------------------------
// decode rules

test('decode: DM swarms, non-JSON, version and size guards', (t) => {
  const dmPayload = 'ab'.repeat(200)
  t.alike(wire.decode(dmPayload, { dm: true }), { type: 'dm', value: dmPayload })
  t.alike(wire.decode('1234', { dm: true }), { type: 'dm', value: '1234' }, 'digits-only payload still a DM payload')
  t.alike(wire.decode(dmPayload), { type: 'invalid', reason: 'not_json', ban: true }, 'non-JSON in a room: ban (both apps)')
  t.is(wire.decode(JSON.stringify(goldenMessages()[3][1]), { dm: true }).type, 'ignored', 'room message in a DM swarm')
  t.is(wire.decode(JSON.stringify({ typing: true }), { dm: true }).type, 'typing')
  t.alike(wire.decode('null'), { type: 'invalid', reason: 'not_object', ban: false })
  t.alike(wire.decode('[]'), { type: 'invalid', reason: 'not_object', ban: false })

  t.alike(wire.decode(JSON.stringify({ v: 2, typing: true })), { type: 'ignored', reason: 'version' })
  t.is(wire.decode(JSON.stringify({ v: 1, typing: true })).type, 'typing')

  const huge = JSON.stringify({ typing: true, pad: 'x'.repeat(wire.MAX_WIRE_BYTES) })
  t.alike(wire.decode(huge), { type: 'invalid', reason: 'too_large', ban: false })
  t.exception(() => wire.encode({ pad: 'x'.repeat(wire.MAX_WIRE_BYTES) }), /larger than/)
  t.is(wire.decode(b4a.from(JSON.stringify({ typing: false }))).type, 'typing', 'bytes input')

  const bad = wire.decode(JSON.stringify({ type: 'Ping', hashes: new Array(26).fill(HASH) }))
  t.is(bad.type, 'invalid')
  t.is(bad.ban, true)
  t.is(wire.decode(JSON.stringify({ type: 'friend', hugin: ADDRESS })).type, 'ignored', 'unknown type')
  t.is(wire.decode(JSON.stringify({ message: 'no other fields' })).ban, false, 'invalid room message: dropped, no ban')
})
