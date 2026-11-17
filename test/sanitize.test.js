'use strict'

const test = require('brittle')
const S = require('../lib/sanitize.js')
const desktop = require('./fixtures/legacy-desktop.js')
const native = require('./fixtures/legacy-native.js')
const { ADDRESS, HASH, CONTENT_HASH, TOPIC, DRIVE_KEY, PAST, NODE, legacy } = require('./helpers.js')

const INVITE = 'a0'.repeat(64)

// ---------------------------------------------------------------------------------------------
// Limit constants of the old validators, with their source lines:
//   desktop = hugin-desktop src/backend/utils.cjs, native = hugin-native bare/utils.js
// `null` = not checked by that app.

const LIMITS = {
  room: {
    // sanitize_group_message: desktop utils.cjs:331-375, native utils.js:316-360
    timestamp: { desktop: [334, 20], native: [319, 20] },
    room: { desktop: [336, 128], native: [321, 128] },
    message: { desktop: [338, 777], native: [323, 777] },
    address: { desktop: [340, 128], native: [325, 99] },
    reply: { desktop: [345, 64], native: [327, 64] },
    signature: { desktop: [347, 200], native: [329, 200] },
    name: { desktop: [349, 50], native: [331, 50] },
    hash: { desktop: [351, 128], native: [333, 64] },
    tipReceiver: { desktop: [356, 100], native: [337, null] }
  },
  joined: {
    // sanitize_join_swarm_data: desktop utils.cjs:256-329, native utils.js:234-314
    address: { desktop: [257, 99], native: [235, 99] },
    message: { desktop: [259, 128], native: [237, 128] },
    signature: { desktop: [261, 128], native: [239, 128] },
    topic: { desktop: [263, 64], native: [242, 64] }, // exact length
    name: { desktop: [265, 50], native: [244, 50] },
    time: { desktop: [267, 50], native: [246, 50] },
    idSig: { desktop: [279, 128], native: [258, 128] },
    avatarBytes: { desktop: [294, 200000], native: [274, null] }, // decoded bytes
    avatarBase64Chars: { desktop: [292, null], native: [280, 614400] } // base64 regex + length
  },
  voice: {
    // sanitize_voice_status_data: desktop utils.cjs:377-428, native utils.js:362-398
    address: { desktop: [379, 99], native: [364, 99] },
    message: { desktop: [381, 64], native: [366, 64] },
    signature: { desktop: [383, 128], native: [368, 128] },
    topic: { desktop: [385, 64], native: [370, 64] },
    name: { desktop: [387, 50], native: [372, 50] },
    avatarBytes: { desktop: [407, 200000], native: [362, null] }
  },
  file: {
    // sanitize_file_message: desktop utils.cjs:430-488, native utils.js:400-457
    fileName: { desktop: [433, 100], native: [403, 100] },
    address: { desktop: [436, 99], native: [406, 99] },
    topic: { desktop: [439, 64], native: [409, 64] },
    type: { desktop: [442, 25], native: [412, 25] },
    info: { desktop: [445, 25], native: [415, 25] },
    size: { desktop: [448, 20], native: [418, 20] },
    time: { desktop: [451, 25], native: [421, 25] },
    signature: { desktop: [454, 128], native: [424, 128] },
    key: { desktop: [459, 128], native: [434, 128] },
    hash: { desktop: [463, 64], native: [438, 64] },
    name: { desktop: [468, 100], native: [428, 100] }
  },
  feed: {
    // sanitize_feed_message: desktop utils.cjs:490-524 (native has no feed validator)
    address: { desktop: [492, 99], native: [null, null] },
    message: { desktop: [494, 777], native: [null, null] },
    signature: { desktop: [496, 128], native: [null, null] },
    nickname: { desktop: [498, 50], native: [null, null] },
    hash: { desktop: [500, 64], native: [null, null] },
    timestamp: { desktop: [502, 25], native: [null, null] },
    reply: { desktop: [504, 64], native: [null, null] },
    tipReceiver: { desktop: [509, 100], native: [null, null] }
  },
  ping: {
    // desktop swarm.cjs:1275 / native swarm.js:1422 (hashes), 1288 / 1436 (peers),
    // 1495-1496 / 1573-1574 (files; the 'Ban' return value is not used, the list is ignored)
    hashes: { desktop: [1275, 25], native: [1422, 25] },
    peers: { desktop: [1288, 100], native: [1436, 100] },
    files: { desktop: [1496, 10], native: [1574, 10] }
  }
}

const unionLimit = (l) => (l.desktop[1] === null || l.native[1] === null ? (l.native[0] === null ? l.desktop[1] : null) : Math.max(l.desktop[1], l.native[1]))
const intersectionLimit = (l) => [l.desktop[1], l.native[1]].filter((x) => x !== null).reduce((a, b) => Math.min(a, b))

test('accept limits are the union, send limits the intersection', (t) => {
  for (const [group, fields] of Object.entries(LIMITS)) {
    for (const [field, l] of Object.entries(fields)) {
      if (field === 'avatarBytes' || field === 'avatarBase64Chars') continue
      if (S.ACCEPT[group] && field in S.ACCEPT[group]) {
        t.is(S.ACCEPT[group][field], unionLimit(l), `ACCEPT.${group}.${field}`)
      }
      const sendField = field === 'hash' ? 'hashHex' : field
      if (S.SEND[group] && sendField in S.SEND[group]) {
        t.is(S.SEND[group][sendField], intersectionLimit(l), `SEND.${group}.${sendField}`)
      }
    }
  }
  t.is(S.ACCEPT.joined.avatarBytes, LIMITS.joined.avatarBytes.desktop[1])
  t.is(S.ACCEPT.joined.avatarBase64Chars, LIMITS.joined.avatarBase64Chars.native[1])
  t.is(S.SEND.joined.avatarBytes, LIMITS.joined.avatarBytes.desktop[1])
  t.is(S.SEND.voice.avatarBytes, LIMITS.voice.avatarBytes.desktop[1])
})

// ---------------------------------------------------------------------------------------------
// base messages

/** XKR message signature format (hugin-network 3.0 room messages): 128 hex characters. */
const RSIG = '5a'.repeat(64)

const roomBase = () => ({
  hash: HASH,
  room: INVITE,
  address: ADDRESS,
  message: 'hello',
  name: 'nils',
  reply: '',
  signature: RSIG,
  timestamp: PAST,
  tip: false
})

const joinedBase = () => ({
  address: ADDRESS,
  signature: '',
  avatar: '',
  message: TOPIC,
  joined: true,
  topic: TOPIC,
  name: 'nils',
  voice: false,
  channels: [],
  video: false,
  time: String(PAST),
  idSig: 's'.repeat(64),
  audioMute: false,
  videoMute: false,
  screenshare: false,
  messages: []
})

const voiceBase = () => ({
  address: ADDRESS,
  avatar: '',
  signature: 's'.repeat(64),
  message: TOPIC,
  voice: true,
  topic: TOPIC,
  name: 'nils',
  video: false,
  audioMute: false,
  videoMute: false,
  screenshare: false
})

const fileBase = () => ({
  fileName: 'cat.png',
  address: ADDRESS,
  name: 'nils',
  topic: TOPIC,
  info: 'file-shared',
  type: 'file',
  size: 1234,
  time: PAST,
  hash: HASH,
  contentHash: CONTENT_HASH,
  signature: 's'.repeat(64)
})

const feedBase = () => ({
  type: 'feed',
  message: 'post',
  nickname: 'nils',
  address: ADDRESS,
  reply: '',
  tip: false,
  hash: HASH,
  timestamp: PAST,
  signature: 's'.repeat(64)
})

const with_ = (base, patch) => Object.assign(base(), patch)
const without = (base, key) => {
  const o = base()
  delete o[key]
  return o
}

/**
 * Asserts ours accepts exactly what at least one old validator accepts (and, when given, what
 * `also` accepts as well: room messages must be signed since hugin-network 3.0).
 */
function union(t, name, ours, data, d, n, also = () => true) {
  const expected = (!!legacy(d, data) || !!(n && legacy(n, data))) && also(data)
  t.is(ours(data).ok, expected, name + (expected ? ' (accepted)' : ' (refused)'))
}

// ---------------------------------------------------------------------------------------------

test('room message: union of both validators at every boundary, signed', (t) => {
  const cases = {
    'base': roomBase(),
    'address 99': with_(roomBase, { address: 'a'.repeat(99) }),
    'address 100': with_(roomBase, { address: 'a'.repeat(100) }),
    'address 128': with_(roomBase, { address: 'a'.repeat(128) }),
    'address 129': with_(roomBase, { address: 'a'.repeat(129) }),
    'hash 64': with_(roomBase, { hash: 'a'.repeat(64) }),
    'hash 65': with_(roomBase, { hash: 'a'.repeat(65) }),
    'hash 128': with_(roomBase, { hash: 'a'.repeat(128) }),
    'hash 129': with_(roomBase, { hash: 'a'.repeat(129) }),
    'no hash': without(roomBase, 'hash'),
    'message 777': with_(roomBase, { message: 'm'.repeat(777) }),
    'message 778': with_(roomBase, { message: 'm'.repeat(778) }),
    'no message': without(roomBase, 'message'),
    'room 128': with_(roomBase, { room: 'r'.repeat(128) }),
    'room 129': with_(roomBase, { room: 'r'.repeat(129) }),
    'no room': without(roomBase, 'room'),
    'reply 64': with_(roomBase, { reply: HASH }),
    'reply 65': with_(roomBase, { reply: HASH + 'a' }),
    'no reply': without(roomBase, 'reply'),
    'signature 200': with_(roomBase, { signature: 's'.repeat(200) }),
    'signature 201': with_(roomBase, { signature: 's'.repeat(201) }),
    'no signature': without(roomBase, 'signature'),
    'empty signature (old desktop)': with_(roomBase, { signature: '' }),
    'native signature sig': with_(roomBase, { signature: 'sig' }),
    'signature 128 hex upper case': with_(roomBase, { signature: RSIG.toUpperCase() }),
    'signature 126 hex': with_(roomBase, { signature: RSIG.slice(2) }),
    'signature 130 hex': with_(roomBase, { signature: RSIG + 'ab' }),
    'signature 128 non-hex': with_(roomBase, { signature: 'zz'.repeat(64) }),
    'name 50': with_(roomBase, { name: 'n'.repeat(50) }),
    'name 51': with_(roomBase, { name: 'n'.repeat(51) }),
    'nickname instead of name': (() => { const o = without(roomBase, 'name'); o.nickname = 'nick'; return o })(),
    'no name': without(roomBase, 'name'),
    'timestamp string 20': with_(roomBase, { timestamp: '0'.repeat(19) + '1' }),
    'timestamp string 21': with_(roomBase, { timestamp: '0'.repeat(20) + '1' }),
    'timestamp desktop string': with_(roomBase, { timestamp: String(PAST) }),
    'timestamp in the future (long string)': with_(roomBase, { timestamp: '9'.repeat(25) }),
    'no timestamp': without(roomBase, 'timestamp'),
    'tip receiver 100': with_(roomBase, { tip: { amount: 5, receiver: 'r'.repeat(100) } }),
    'tip receiver 101': with_(roomBase, { tip: { amount: 5, receiver: 'r'.repeat(101) } }),
    'tip amount string': with_(roomBase, { tip: { amount: '5', receiver: ADDRESS } }),
    'tip "false"': with_(roomBase, { tip: 'false' }),
    'tip empty string': with_(roomBase, { tip: '' }),
    'desktop extra fields': with_(roomBase, { sent: true, channel: 'channel', swarm: true })
  }
  for (const [name, data] of Object.entries(cases)) {
    union(t, name, S.roomMessage, data, desktop.sanitize_group_message, native.sanitize_group_message, (d) => S.isRoomSignature(d.signature) && !(typeof d.timestamp === 'string' && d.timestamp.length > 20))
  }
})

test('room message: normalized value', (t) => {
  const r = S.roomMessage(with_(roomBase, { timestamp: String(PAST), sent: true, channel: 'channel', reply: undefined }))
  t.ok(r.ok)
  t.alike(r.value, {
    message: 'hello',
    address: ADDRESS,
    signature: RSIG,
    room: INVITE,
    timestamp: PAST,
    name: 'nils',
    reply: '',
    hash: HASH,
    tip: false
  })
  const now = 1800000000000
  t.is(S.roomMessage(with_(roomBase, { timestamp: now + 5000 }), { now }).value.timestamp, now + 5000, 'a future timestamp is kept: it is signed (lib/room.js drops it when too far ahead)')
  t.absent(S.roomMessage(with_(roomBase, { signature: '' })).ok, 'unsigned')
  t.is(S.roomMessage(with_(roomBase, { signature: 'sig' })).reason, 'signature')
})

test('isRoomSignature: the XKR signature format', (t) => {
  t.ok(S.isRoomSignature(RSIG))
  t.ok(S.isRoomSignature(RSIG.toUpperCase()))
  t.absent(S.isRoomSignature(RSIG.slice(1)))
  t.absent(S.isRoomSignature(RSIG + 'a'))
  t.absent(S.isRoomSignature('g'.repeat(128)))
  t.absent(S.isRoomSignature(''))
  t.absent(S.isRoomSignature(undefined))
  t.absent(S.isRoomSignature(['a'.repeat(128)]))
})

test('room message: a tip stored as a JSON string (desktop history rows) is read', (t) => {
  const tip = { amount: 5, receiver: ADDRESS }
  const data = with_(roomBase, { tip: JSON.stringify(tip) })
  t.absent(legacy(desktop.sanitize_group_message, data), 'desktop validator refuses it')
  t.absent(legacy(native.sanitize_group_message, data), 'native validator refuses it')
  const r = S.roomMessage(data)
  t.ok(r.ok)
  t.alike(r.value.tip, tip)
  t.is(S.roomMessage(with_(roomBase, { tip: '{not json' })).ok, false)
  t.is(S.roomMessage(with_(roomBase, { tip: JSON.stringify(false) })).value.tip, false)
})

test('room message: refuses values no app sends', (t) => {
  t.absent(S.roomMessage(with_(roomBase, { message: 42 })).ok, 'non-string message')
  t.absent(S.roomMessage(with_(roomBase, { address: 42 })).ok, 'non-string address')
  t.absent(S.roomMessage(with_(roomBase, { timestamp: 'abc' })).ok, 'non-numeric timestamp')
  t.absent(S.roomMessage(with_(roomBase, { reply: 7 })).ok, 'non-string reply')
  t.absent(S.roomMessage(with_(roomBase, { tip: true })).ok, 'tip true')
  t.absent(S.roomMessage(null).ok)
  t.absent(S.roomMessage([]).ok)
})

test('room history: keeps valid messages with a 64-character hash', (t) => {
  const list = [
    roomBase(),
    with_(roomBase, { hash: 'short' }),
    with_(roomBase, { message: 'm'.repeat(800) }),
    'nope',
    with_(roomBase, { hash: 'b'.repeat(64), name: undefined, nickname: 'rn-row' })
  ]
  const out = S.roomHistory(list)
  t.is(out.length, 2)
  t.is(out[1].name, 'rn-row')
  t.alike(S.roomHistory('nope'), [])
  t.is(S.roomHistory([roomBase(), with_(roomBase, { signature: '' }), with_(roomBase, { signature: 'sig' })]).length, 1, 'unsigned entries are skipped')
})

test('joined: union of both validators at every boundary', (t) => {
  const cases = {
    'base': joinedBase(),
    'address 99': with_(joinedBase, { address: 'a'.repeat(99) }),
    'address 100': with_(joinedBase, { address: 'a'.repeat(100) }),
    'message 128 (desktop sends the invite)': with_(joinedBase, { message: INVITE }),
    'message 129': with_(joinedBase, { message: INVITE + 'a' }),
    'signature 128': with_(joinedBase, { signature: 'ab'.repeat(64) }),
    'signature 129': with_(joinedBase, { signature: 'ab'.repeat(64) + 'a' }),
    'topic 63': with_(joinedBase, { topic: TOPIC.slice(1) }),
    'topic 65': with_(joinedBase, { topic: TOPIC + 'a' }),
    'name 50': with_(joinedBase, { name: 'n'.repeat(50) }),
    'name 51': with_(joinedBase, { name: 'n'.repeat(51) }),
    'time 50': with_(joinedBase, { time: '1'.repeat(50) }),
    'time 51': with_(joinedBase, { time: '1'.repeat(51) }),
    'time number (native)': with_(joinedBase, { time: PAST }),
    'idSig 128': with_(joinedBase, { idSig: 'i'.repeat(128) }),
    'idSig 129': with_(joinedBase, { idSig: 'i'.repeat(129) }),
    'idSig missing': without(joinedBase, 'idSig'),
    'voice missing': without(joinedBase, 'voice'),
    'joined false': with_(joinedBase, { joined: false }),
    'video string': with_(joinedBase, { video: 'true' }),
    'screenshare missing': without(joinedBase, 'screenshare'),
    'messages not an array': with_(joinedBase, { messages: 'x' }),
    'avatar 199998 bytes': with_(joinedBase, { avatar: 'A'.repeat(266664) }),
    'avatar 200001 bytes (native only)': with_(joinedBase, { avatar: 'A'.repeat(266668) }),
    'avatar 614400 chars (native only)': with_(joinedBase, { avatar: 'A'.repeat(614400) }),
    'avatar 614404 chars (neither)': with_(joinedBase, { avatar: 'A'.repeat(614404) }),
    // Desktop decodes a malformed avatar leniently with Node's Buffer; the copied validator is
    // only a faithful oracle for that on Node (Bare's Buffer.from throws instead).
    ...(NODE
      ? {
          'avatar not base64, small (desktop only)': with_(joinedBase, { avatar: '!!!!' }),
          'avatar not base64, large (neither)': with_(joinedBase, { avatar: '!'.repeat(1000) + 'A'.repeat(270000) })
        }
      : {}),
    'driveKey 64 hex': with_(joinedBase, { driveKey: DRIVE_KEY }),
    'driveKey 64 non-hex (native only)': with_(joinedBase, { driveKey: 'z'.repeat(64) }),
    'driveKey 63 hex (native only)': with_(joinedBase, { driveKey: DRIVE_KEY.slice(1) }),
    'driveKey null (native only)': with_(joinedBase, { driveKey: null })
  }
  for (const [name, data] of Object.entries(cases)) {
    union(t, name, S.joined, data, desktop.sanitize_join_swarm_data, native.sanitize_join_swarm_data)
  }
})

test('joined: normalized value', (t) => {
  const r = S.joined(with_(joinedBase, { time: PAST, driveKey: 'z'.repeat(64), avatar: 'QUJD', messages: [roomBase()] }))
  t.ok(r.ok)
  t.is(r.value.time, String(PAST))
  t.is(r.value.driveKey, null, 'a driveKey that is not 64 hex is dropped')
  t.is(r.value.avatar, 'QUJD')
  t.is(r.value.messages.length, 1)
  t.alike(r.value.channels, [])
  t.is(S.joined(with_(joinedBase, { avatar: '!!!!' })).value.avatar, '', 'accepted, avatar dropped')
  t.is(S.joined(with_(joinedBase, { driveKey: DRIVE_KEY })).value.driveKey, DRIVE_KEY)
})

test('voice status: union of both validators', (t) => {
  const cases = {
    'base': voiceBase(),
    'address 100': with_(voiceBase, { address: 'a'.repeat(100) }),
    'message 64': with_(voiceBase, { message: 'm'.repeat(64) }),
    'message 65': with_(voiceBase, { message: 'm'.repeat(65) }),
    'topic 65': with_(voiceBase, { topic: TOPIC + 'a' }),
    'name 51': with_(voiceBase, { name: 'n'.repeat(51) }),
    'voice string': with_(voiceBase, { voice: 'yes' }),
    'avatar ok': with_(voiceBase, { avatar: 'QUJD' }),
    'avatar not base64 (native only)': with_(voiceBase, { avatar: '!!!!' }),
    'avatar 200001 bytes (native only)': with_(voiceBase, { avatar: 'A'.repeat(266668) })
  }
  for (const [name, data] of Object.entries(cases)) {
    union(t, name, S.voiceStatus, data, desktop.sanitize_voice_status_data, native.sanitize_voice_status_data)
  }
  t.is(S.voiceStatus(with_(voiceBase, { avatar: '!!!!' })).value.avatar, '')
  // not signed since hugin-network 3.0: any signature field is ignored and not kept
  for (const data of [without(voiceBase, 'signature'), with_(voiceBase, { signature: 's'.repeat(129) }), with_(voiceBase, { signature: 42 })]) {
    const r = S.voiceStatus(data)
    t.ok(r.ok, 'accepted without looking at the signature')
    t.absent('signature' in r.value)
  }
})

test('file announcement: same as both validators', (t) => {
  const cases = {
    'base': fileBase(),
    'desktop driveKey extra': with_(fileBase, { driveKey: DRIVE_KEY }),
    'fileName 100': with_(fileBase, { fileName: 'f'.repeat(100) }),
    'fileName 101': with_(fileBase, { fileName: 'f'.repeat(101) }),
    'address 100': with_(fileBase, { address: 'a'.repeat(100) }),
    'topic 65': with_(fileBase, { topic: TOPIC + 'a' }),
    'type 25': with_(fileBase, { type: 't'.repeat(25) }),
    'type 26': with_(fileBase, { type: 't'.repeat(26) }),
    'info 26': with_(fileBase, { info: 'i'.repeat(26) }),
    'size string 20': with_(fileBase, { size: '1'.repeat(20) }),
    'size string 21': with_(fileBase, { size: '1'.repeat(21) }),
    'time string 25': with_(fileBase, { time: '1'.repeat(25) }),
    'time string 26': with_(fileBase, { time: '1'.repeat(26) }),
    'signature 129': with_(fileBase, { signature: 's'.repeat(129) }),
    'key 128': with_(fileBase, { key: 'k'.repeat(128) }),
    'key 129': with_(fileBase, { key: 'k'.repeat(129) }),
    'hash 65': with_(fileBase, { hash: HASH + 'a' }),
    'no hash': without(fileBase, 'hash'),
    'name 101': with_(fileBase, { name: 'n'.repeat(101) }),
    'no name': without(fileBase, 'name'),
    'file flag': with_(fileBase, { file: true }),
    'download request (native)': with_(fileBase, { info: 'file', type: 'download-request', key: TOPIC })
  }
  for (const [name, data] of Object.entries(cases)) {
    const d = !!legacy(desktop.sanitize_file_message, data)
    const n = !!legacy(native.sanitize_file_message, data)
    t.is(d, n, name + ': apps agree')
    t.is(S.fileMessage(data).ok, d, name)
  }
  const r = S.fileMessage(with_(fileBase, { size: '1234', time: String(PAST) }))
  t.is(r.value.size, 1234)
  t.is(r.value.time, PAST)
  t.is(r.value.contentHash, CONTENT_HASH)
})

test('file announcement: contentHash must be 64 hex characters (hugin-network 3.0)', (t) => {
  t.is(S.ACCEPT.file.contentHashHex, 64)
  t.is(S.SEND.file.contentHashHex, 64)
  const refused = {
    'no contentHash': without(fileBase, 'contentHash'),
    'contentHash 63': with_(fileBase, { contentHash: CONTENT_HASH.slice(1) }),
    'contentHash 65': with_(fileBase, { contentHash: CONTENT_HASH + 'a' }),
    'contentHash not hex': with_(fileBase, { contentHash: 'zz'.repeat(32) }),
    'contentHash number': with_(fileBase, { contentHash: 5 })
  }
  for (const [name, data] of Object.entries(refused)) {
    t.alike(S.fileMessage(data), { ok: false, reason: 'contentHash' }, name)
  }
  t.ok(S.fileMessage(with_(fileBase, { contentHash: CONTENT_HASH.toUpperCase() })).ok, 'upper case hex')
  t.is(S.inspect(without(fileBase, 'contentHash')).ban, true, 'like any malformed announcement')
  t.is(S.fileList([without(fileBase, 'contentHash'), with_(fileBase, { contentHash: 'x' }), fileBase()]).length, 1, 'list entries without one are skipped')
  t.is(S.fileList([fileBase()])[0].contentHash, CONTENT_HASH)
})

test('feed: same as desktop validator (native has none)', (t) => {
  const cases = {
    'base': feedBase(),
    'address 100': with_(feedBase, { address: 'a'.repeat(100) }),
    'message 777': with_(feedBase, { message: 'm'.repeat(777) }),
    'message 778': with_(feedBase, { message: 'm'.repeat(778) }),
    'signature 129': with_(feedBase, { signature: 's'.repeat(129) }),
    'no signature (history rows)': without(feedBase, 'signature'),
    'nickname 51': with_(feedBase, { nickname: 'n'.repeat(51) }),
    'no nickname': without(feedBase, 'nickname'),
    'hash 65': with_(feedBase, { hash: HASH + 'a' }),
    'hash number': with_(feedBase, { hash: 5 }),
    'timestamp string 25': with_(feedBase, { timestamp: '1'.repeat(25) }),
    'timestamp string 26': with_(feedBase, { timestamp: '1'.repeat(26) }),
    'reply 65': with_(feedBase, { reply: HASH + 'a' }),
    'no reply (native may omit it)': without(feedBase, 'reply'),
    'tip receiver 101': with_(feedBase, { tip: { amount: 1, receiver: 'r'.repeat(101) } })
  }
  for (const [name, data] of Object.entries(cases)) {
    union(t, name, S.feedMessage, data, desktop.sanitize_feed_message, null)
  }
})

test('typing', (t) => {
  for (const data of [{ typing: true }, { typing: false }, { typing: 'yes' }, {}]) {
    const [, checked] = desktop.sanitize_typing_message(data)
    const [, checkedN] = native.sanitize_typing_message(data)
    t.is(checked, checkedN)
    t.is(S.typing(data).ok, checked, JSON.stringify(data))
  }
})

test('classify follows the apps dispatch order', (t) => {
  const cases = [
    [{ type: 'feed', typing: true }, 'feed'],
    [{ type: 'disconnected', typing: true }, 'disconnected'],
    [{ typing: true, info: 'x' }, 'typing'],
    [{ info: 'file-shared', offer: true }, 'file'],
    [{ offer: true, joined: true }, 'sdp'],
    [{ joined: true, voice: true }, 'joined'],
    [{ voice: true, type: 'Ping' }, 'voice'],
    [{ type: 5 }, 'invalid-type'],
    [{ type: 'ban' }, 'ban'],
    [{ type: 'Ping' }, 'ping'],
    [{ type: 'request-messages' }, 'request-messages'],
    [{ type: 'missing-messages' }, 'missing-messages'],
    [{ type: 'request-history' }, 'request-history'],
    [{ type: 'send-history' }, 'send-history'],
    [{ type: 'request-feed' }, 'request-feed'],
    [{ type: 'send-feed-history' }, 'send-feed-history'],
    [{ type: 'friend', hugin: ADDRESS }, 'unknown-type'],
    [roomBase(), 'room-message'],
    [[], 'invalid'],
    [null, 'invalid']
  ]
  for (const [data, kind] of cases) t.is(S.classify(data), kind, kind)
})

test('inspect: ban decisions', (t) => {
  const h = (n) => Array.from({ length: n }, (_, i) => i.toString(16).padStart(64, '0'))
  const banned = [
    [{ type: 'Ping', hashes: h(26) }, 'more than 25 hashes (desktop swarm.cjs:1275, native swarm.js:1422)'],
    [{ type: 'Ping', hashes: h(1), peers: h(101) }, 'more than 100 peers (desktop swarm.cjs:1288, native swarm.js:1436)'],
    [{ type: 'request-messages', hashes: h(26) }, 'request-messages with more than 25 hashes'],
    [{ type: 'whatever', hashes: h(26) }, 'unknown type with more than 25 hashes'],
    [{ type: 7 }, 'non-string type (desktop swarm.cjs:1225)'],
    [with_(joinedBase, { topic: 'short' }), 'invalid joined'],
    [with_(fileBase, { fileName: 'f'.repeat(101) }), 'invalid file announcement'],
    [with_(voiceBase, { topic: 'short' }), 'invalid voice status'],
    [with_(feedBase, { message: 'm'.repeat(800) }), 'invalid feed message (desktop swarm.cjs:1088)']
  ]
  for (const [data, name] of banned) {
    const r = S.inspect(data)
    t.is(r.ok, false, name)
    t.is(r.ban, true, name + ': ban')
    t.ok(S.isMalformedPeerMessage(data), name + ': isMalformedPeerMessage')
    t.ok(typeof S.malformedReason(data) === 'string')
  }

  const notBanned = [
    [with_(roomBase, { message: 'm'.repeat(800) }), 'invalid room message is dropped'],
    [{ typing: 'yes' }, 'invalid typing'],
    [{ offer: true }, 'incomplete sdp'],
    [{ type: 'friend', hugin: ADDRESS }, 'unknown type'],
    [{ type: 'Ping', hashes: h(3), files: new Array(11).fill(fileBase()) }, 'too many files: list ignored'],
    [{ type: 'send-feed-history', messages: 'x' }, 'bad feed history']
  ]
  for (const [data, name] of notBanned) {
    t.absent(S.isMalformedPeerMessage(data), name)
  }
  t.alike(S.inspect({ type: 'Ping', hashes: h(3), files: new Array(11).fill(fileBase()) }).value.files, [])
})

test('inspect: Ping, history and feed history are normalized', (t) => {
  const ping = S.inspect({ type: 'Ping', peers: [TOPIC, 'bad'], files: [fileBase(), { hash: 'x' }], hashes: [HASH, 'short'] })
  t.ok(ping.ok)
  t.alike(ping.value.peers, [TOPIC])
  t.alike(ping.value.hashes, [HASH])
  t.is(ping.value.files.length, 1)
  t.is(ping.value.files[0].hash, HASH)

  const noHashes = S.inspect({ type: 'Ping', peers: [], files: [] })
  t.is(noHashes.value.hashes, null, 'a Ping without hashes')

  const missing = S.inspect({ type: 'missing-messages', messages: [roomBase(), { hash: 'x' }] })
  t.is(missing.value.messages.length, 1)

  const feedHistory = S.inspect({ type: 'send-feed-history', messages: [feedBase(), { nope: 1 }] })
  t.is(feedHistory.value.messages.length, 1)

  const feed = S.inspect(feedBase())
  t.is(feed.value.type, 'feed')

  const dm = S.inspect(roomBase(), { dm: true })
  t.absent(dm.ok)
  t.absent(dm.ban, 'a JSON message in a DM swarm is ignored')
})

test('sendableAvatar keeps only avatars every old peer accepts', (t) => {
  t.is(S.sendableAvatar('QUJD'), 'QUJD')
  t.is(S.sendableAvatar('A'.repeat(266664)).length, 266664)
  t.is(S.sendableAvatar('A'.repeat(266668)), '', 'over 200 000 bytes')
  t.is(S.sendableAvatar('!!!!'), '', 'not base64')
  t.is(S.sendableAvatar(undefined), '')
  for (const avatar of ['QUJD', 'A'.repeat(266664)]) {
    const data = with_(joinedBase, { avatar })
    t.ok(legacy(desktop.sanitize_join_swarm_data, data), 'desktop accepts')
    t.ok(legacy(native.sanitize_join_swarm_data, data), 'native accepts')
  }
})
