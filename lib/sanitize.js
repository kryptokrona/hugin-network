'use strict'

// Validation of everything a peer can send on the hugin-messages channel: type and length checks
// (this file), plus the shared HTML/text sanitiser re-exported from html.js (`sanitizeHtml`,
// `sanitizeText`, `escapeText`). The validators never rewrite text; hosts apply `sanitizeText`
// (desktop's behaviour) or `sanitizeHtml` where they display it.
//
// Compatibility rule: during the rollout old desktop, old native and new peers
// share rooms, so
//   * ACCEPT is the union of what the two old validators accept (hugin-desktop
//     `src/backend/utils.cjs`, hugin-native `bare/utils.js`), extended where an old app sends
//     something neither old validator reads correctly (a tip stored as a JSON string in
//     desktop's history rows);
//   * SEND (used by `wire.js` builders) is the intersection, so every old peer accepts what a new
//     peer sends.
// Inputs that no app sends (non-string text fields, non-numeric timestamps) are refused even
// where an old validator let them through, so the union never admits garbage.
//
// Every validator returns `{ ok: true, value }` (a new, normalized object) or
// `{ ok: false, reason }`.
//
// Exception since hugin-network 3.0 (old clients are separated by the topic/mid derivation): room
// messages are signed by the sender's XKR key (`wire.roomMessageSigningPayload`), so the room
// message validator, on both sides, requires a signature in the format of the apps' XKR message
// signatures (`isRoomSignature`: 128 hex characters). Old unsigned room messages are refused.

const b4a = require('b4a')
const { TYPES } = require('./constants.js')
const html = require('./html.js')

// ---------------------------------------------------------------------------------------------
// limits

/**
 * Accept limits. `null` = no limit of its own (the frame size guard in wire.js still applies).
 * Sources: desktop utils.cjs / native utils.js line numbers in test/sanitize.test.js.
 */
const ACCEPT = Object.freeze({
  room: Object.freeze({
    timestamp: 20, // string length (both)
    room: 128,
    message: 777,
    address: 128, // desktop 128, native 99
    reply: 64,
    signatureHex: 128, // exactly 128 hex characters (hugin-network 3.0; the old apps took any string of 200)
    name: 50,
    hash: 128, // desktop 128, native 64
    tipReceiver: null // desktop 100, native unlimited
  }),
  joined: Object.freeze({
    address: 99,
    message: 128,
    signature: 128,
    topic: 64, // exact length
    name: 50,
    time: 50,
    idSig: 128,
    avatarBase64Chars: 614400, // native: base64 and at most this many characters
    avatarBytes: 200000 // desktop: at most this many decoded bytes
  }),
  voice: Object.freeze({
    address: 99,
    message: 64,
    topic: 64, // exact length
    name: 50,
    avatarBytes: 200000
  }),
  file: Object.freeze({
    fileName: 100,
    address: 99,
    topic: 64,
    type: 25,
    info: 25,
    size: 20, // string length when sent as a string
    time: 25, // string length when sent as a string
    signature: 128,
    key: 128,
    hash: 64,
    contentHashHex: 64, // exactly 64 hex characters (BLAKE2b-256 of the file bytes)
    name: 100
  }),
  feed: Object.freeze({
    address: 99,
    message: 777,
    signature: 128,
    nickname: 50,
    hash: 64,
    timestamp: 25,
    reply: 64,
    tipReceiver: 100
  }),
  sdp: Object.freeze({
    address: 99,
    topic: 64
  }),
  ban: Object.freeze({
    address: 99
  }),
  ping: Object.freeze({
    hashes: 25, // more: ban (both)
    peers: 100, // more: ban (both)
    files: 10 // more: the list is ignored (both)
  })
})

/** Send limits (intersection of both old validators; wire.js builders enforce them). */
const SEND = Object.freeze({
  room: Object.freeze({
    room: 128,
    message: 777,
    address: 99,
    reply: 64,
    signatureHex: 128, // exactly 128 hex characters (XKR message signature)
    name: 50,
    hashHex: 64, // exactly 64 hex characters
    tipReceiver: 100
  }),
  joined: Object.freeze({
    address: 99,
    signature: 128,
    name: 50,
    time: 50,
    idSig: 128,
    avatarBytes: 200000 // base64, at most this many decoded bytes, else no avatar is sent
  }),
  voice: Object.freeze({
    address: 99,
    name: 50,
    avatarBytes: 200000
  }),
  file: Object.freeze({
    fileName: 100,
    address: 99,
    name: 100,
    signature: 128,
    hashHex: 64,
    contentHashHex: 64 // exactly 64 hex characters (BLAKE2b-256 of the file bytes)
  }),
  feed: Object.freeze({
    address: 99,
    message: 777,
    signature: 128,
    nickname: 50,
    hashHex: 64,
    reply: 64,
    tipReceiver: 100
  }),
  ping: Object.freeze({
    hashes: 25,
    peers: 100,
    files: 10
  })
})

const BASE64_RE = /^[A-Za-z0-9+/]+={0,2}$/
const HEX64_RE = /^[0-9a-f]{64}$/i
const SIG_RE = /^[0-9a-f]{128}$/i

// ---------------------------------------------------------------------------------------------
// helpers

const ok = (value) => ({ ok: true, value })
const fail = (reason) => ({ ok: false, reason })

function isObject(v) {
  return v !== null && typeof v === 'object' && !Array.isArray(v)
}

function isStr(v, max) {
  return typeof v === 'string' && (max === null || max === undefined || v.length <= max)
}

function isHash64(v) {
  return typeof v === 'string' && v.length === 64
}

function isHex64(v) {
  return typeof v === 'string' && HEX64_RE.test(v)
}

/**
 * An XKR message signature as the apps' `host.sign` produces it (kryptokrona-utils
 * `signMessage`: the 64-byte CryptoNote signature in hex, 128 characters; either case is taken).
 * Only the format: whether it verifies is the host's `verify`.
 */
function isRoomSignature(v) {
  return typeof v === 'string' && SIG_RE.test(v)
}

/**
 * `str` cut to at most `max` UTF-16 code units (the unit every length limit here counts) on a
 * code point boundary, so a surrogate pair is never split. A non-string gives ''.
 */
function clampText(str, max) {
  if (typeof str !== 'string') return ''
  if (str.length <= max) return str
  let out = ''
  for (const ch of str) {
    if (out.length + ch.length > max) break
    out += ch
  }
  return out
}

/**
 * Timestamp as both apps treat it: a numeric string of at most `maxLen` characters or a number;
 * a value in the future becomes `now`. Returns an integer or null.
 */
function timestampOf(value, maxLen, now) {
  if (value === undefined || value === null) return null
  let n
  if (typeof value === 'number') n = value
  else if (typeof value === 'string') n = parseInt(value, 10)
  else return null
  if (!Number.isFinite(n)) return null
  if (n > now) return Math.trunc(now)
  if (typeof value === 'string' && maxLen !== null && value.length > maxLen) return null
  return Math.trunc(n)
}

/** Number (or numeric string of at most `maxLen` characters), as an integer, or null. */
function numberOf(value, maxLen) {
  if (typeof value === 'number') return Number.isFinite(value) ? Math.trunc(value) : null
  if (typeof value === 'string') {
    if (maxLen !== null && value.length > maxLen) return null
    const n = parseInt(value, 10)
    return Number.isFinite(n) ? n : null
  }
  return null
}

/**
 * Tip as both apps read it: falsy or 'false' -> false; else `{ amount: number, receiver: string }`.
 * Desktop history rows carry the tip as a JSON string; it is parsed here. Returns null when
 * invalid.
 */
function tipOf(tip, maxReceiver) {
  if (!tip || tip === 'false') return false
  let t = tip
  if (typeof t === 'string') {
    try {
      t = JSON.parse(t)
    } catch {
      return null
    }
    if (!t || t === 'false') return false
  }
  if (!isObject(t)) return null
  if (typeof t.amount !== 'number') return null
  if (!isStr(t.receiver, maxReceiver)) return null
  return { amount: t.amount, receiver: t.receiver }
}

function base64Bytes(str) {
  if (BASE64_RE.test(str)) {
    let pad = 0
    if (str.endsWith('==')) pad = 2
    else if (str.endsWith('=')) pad = 1
    return ((str.length * 3) >>> 2) - pad
  }
  // Not well-formed: Node's lenient base64 decoder (what desktop's Buffer.from uses) skips
  // characters outside the alphabet and stops at the first '='. Bare's throws instead, so count
  // the decodable characters here and derive the length the same way on both runtimes.
  const stop = str.indexOf('=')
  const body = (stop === -1 ? str : str.slice(0, stop)).replace(/[^A-Za-z0-9+/\-_]/g, '')
  return (body.length * 3) >>> 2
}

/**
 * Avatar of a `joined` message. Desktop accepts any string whose base64 decoding is at most
 * 200 000 bytes, native any base64 string of at most 614 400 characters; either is enough.
 * Returns the avatar to keep ('' when absent or not well-formed base64), or null to refuse.
 */
function joinedAvatarOf(avatar) {
  if (typeof avatar !== 'string' || avatar.length === 0) return ''
  const wellFormed = BASE64_RE.test(avatar)
  const nativeOk = wellFormed && avatar.length <= ACCEPT.joined.avatarBase64Chars
  const desktopOk = base64Bytes(avatar) <= ACCEPT.joined.avatarBytes
  if (!nativeOk && !desktopOk) return null
  return wellFormed ? avatar : ''
}

/** An avatar every old peer accepts (well-formed base64, at most `maxBytes` decoded), else ''. */
function sendableAvatar(avatar, maxBytes = SEND.joined.avatarBytes) {
  if (typeof avatar !== 'string' || avatar.length === 0) return ''
  if (!BASE64_RE.test(avatar)) return ''
  if (base64Bytes(avatar) > maxBytes) return ''
  return avatar
}

// ---------------------------------------------------------------------------------------------
// validators (accept side)

/**
 * Room message (live, `missing-messages`, `joined.messages`, `send-history`, and host rows
 * before they go out). The signature must have the XKR signature format (`isRoomSignature`);
 * whether it verifies is checked by lib/room.js through `host.verify`.
 *
 * The timestamp is signed, so it is kept as sent (as an integer; a numeric string is parsed),
 * never clamped to now: a changed timestamp would no longer verify, here or at the peers the
 * host later serves it to. lib/room.js drops messages too far in the future.
 * @param {object} data
 * @param {{ hexHash?: boolean }} [opts]  `hexHash`: the hash must be exactly 64 hex characters
 *   (what every hugin/3 client sends; lib/room.js accepts nothing else). Without it the old
 *   union limit applies (any string of at most 128 characters).
 */
function roomMessage(data, opts = {}) {
  if (!isObject(data)) return fail('not_object')
  const L = ACCEPT.room
  const timestamp = timestampOf(data.timestamp, L.timestamp, Infinity)
  if (timestamp === null) return fail('timestamp')
  if (!isStr(data.room, L.room)) return fail('room')
  if (!isStr(data.message, L.message)) return fail('message')
  if (!isStr(data.address, L.address)) return fail('address')
  const reply = data.reply === undefined || data.reply === null ? '' : data.reply
  if (!isStr(reply, L.reply)) return fail('reply')
  const signature = data.signature
  if (!isRoomSignature(signature)) return fail('signature')
  const name = data.name !== undefined && data.name !== null ? data.name : data.nickname
  if (!isStr(name, L.name)) return fail('name')
  if (opts.hexHash ? !isHex64(data.hash) : !isStr(data.hash, L.hash)) return fail('hash')
  const tip = tipOf(data.tip, L.tipReceiver)
  if (tip === null) return fail('tip')
  return ok({
    message: data.message,
    address: data.address,
    signature,
    room: data.room,
    timestamp,
    name,
    reply,
    hash: data.hash,
    tip
  })
}

/**
 * Room history (`joined.messages`, `missing-messages`, `send-history`): the valid (signed)
 * messages with a 64-character hash (both apps skip the others; with `opts.hexHash` it must be
 * 64 hex characters), in the given order. Entries without a well-formed signature are skipped.
 */
function roomHistory(messages, opts = {}) {
  if (!Array.isArray(messages)) return []
  const out = []
  for (const m of messages) {
    if (!isObject(m) || !(opts.hexHash ? isHex64(m.hash) : isHash64(m.hash))) continue
    const r = roomMessage(m, opts)
    if (r.ok) out.push(r.value)
  }
  return out
}

/** `joined` announcement. */
function joined(data) {
  if (!isObject(data)) return fail('not_object')
  const L = ACCEPT.joined
  if (!isStr(data.address, L.address)) return fail('address')
  if (!isStr(data.message, L.message)) return fail('message')
  if (!isStr(data.signature, L.signature)) return fail('signature')
  if (typeof data.topic !== 'string' || data.topic.length !== L.topic) return fail('topic')
  if (!isStr(data.name, L.name)) return fail('name')
  let time
  if (typeof data.time === 'string' && data.time.length <= L.time) time = data.time
  else if (typeof data.time === 'number' && Number.isFinite(data.time)) time = String(data.time)
  else return fail('time')
  if (typeof data.voice !== 'boolean') return fail('voice')
  if (typeof data.joined !== 'boolean') return fail('joined')
  if (typeof data.video !== 'boolean') return fail('video')
  if (!isStr(data.idSig, L.idSig)) return fail('idSig')
  if (typeof data.audioMute !== 'boolean') return fail('audioMute')
  if (typeof data.videoMute !== 'boolean') return fail('videoMute')
  if (typeof data.screenshare !== 'boolean') return fail('screenshare')
  const avatar = joinedAvatarOf(data.avatar)
  if (avatar === null) return fail('avatar')
  return ok({
    address: data.address,
    avatar,
    message: data.message,
    signature: data.signature,
    topic: data.topic,
    name: data.name,
    voice: data.voice,
    joined: data.joined,
    channels: [],
    video: data.video,
    time,
    idSig: data.idSig,
    audioMute: data.audioMute,
    videoMute: data.videoMute,
    screenshare: data.screenshare,
    messages: Array.isArray(data.messages) ? data.messages : [],
    driveKey: isHex64(data.driveKey) ? data.driveKey : null
  })
}

/**
 * Voice channel status. The avatar is optional; one that is not sendable is dropped. Voice
 * status is not signed since hugin-network 3.0: a `signature` field is ignored (and not kept).
 */
function voiceStatus(data) {
  if (!isObject(data)) return fail('not_object')
  const L = ACCEPT.voice
  if (!isStr(data.address, L.address)) return fail('address')
  if (!isStr(data.message, L.message)) return fail('message')
  if (typeof data.topic !== 'string' || data.topic.length !== L.topic) return fail('topic')
  if (!isStr(data.name, L.name)) return fail('name')
  for (const k of ['voice', 'video', 'audioMute', 'videoMute', 'screenshare']) {
    if (typeof data[k] !== 'boolean') return fail(k)
  }
  return ok({
    address: data.address,
    avatar: sendableAvatar(data.avatar, L.avatarBytes),
    message: data.message,
    topic: data.topic,
    name: data.name,
    voice: data.voice,
    video: data.video,
    audioMute: data.audioMute,
    videoMute: data.videoMute,
    screenshare: data.screenshare
  })
}

/**
 * Drive file metadata (file-shared announcement, entries of Ping/history `files`). `contentHash`
 * (BLAKE2b-256 of the file bytes) must be 64 hex characters.
 */
function fileMessage(data) {
  if (!isObject(data)) return fail('not_object')
  const L = ACCEPT.file
  if (!isStr(data.fileName, L.fileName)) return fail('fileName')
  if (!isStr(data.address, L.address)) return fail('address')
  if (!isStr(data.topic, L.topic)) return fail('topic')
  if (!isStr(data.type, L.type)) return fail('type')
  if (!isStr(data.info, L.info)) return fail('info')
  const size = numberOf(data.size, L.size)
  if (size === null) return fail('size')
  const time = numberOf(data.time, L.time)
  if (time === null) return fail('time')
  const signature = data.signature === undefined || data.signature === null ? '' : data.signature
  if (!isStr(signature, L.signature)) return fail('signature')
  if (data.key !== undefined && !isStr(data.key, L.key)) return fail('key')
  if (data.hash !== undefined && !isStr(data.hash, L.hash)) return fail('hash')
  if (!isHex64(data.contentHash)) return fail('contentHash')
  if (data.name !== undefined && !isStr(data.name, L.name)) return fail('name')
  if (typeof data.file === 'boolean') return fail('file')
  const value = {
    fileName: data.fileName,
    address: data.address,
    name: data.name === undefined ? '' : data.name,
    topic: data.topic,
    info: data.info,
    type: data.type,
    size,
    time,
    hash: data.hash === undefined ? '' : data.hash,
    contentHash: data.contentHash,
    signature
  }
  if (data.key !== undefined) value.key = data.key
  return ok(value)
}

/**
 * Entries of a `files` list (Ping, request-history, send-history). More than `ACCEPT.ping.files`
 * entries: the list is ignored (`[]`), as both apps do. Entries without a 64-character hash, a
 * 64-hex `contentHash` or a numeric time are skipped.
 */
function fileList(files) {
  if (!Array.isArray(files) || files.length > ACCEPT.ping.files) return []
  const out = []
  for (const f of files) {
    if (!isObject(f) || !isHash64(f.hash)) continue
    const time = numberOf(f.time, ACCEPT.file.time)
    const size = numberOf(f.size, ACCEPT.file.size)
    if (time === null || size === null) continue
    if (!isStr(f.fileName, ACCEPT.file.fileName)) continue
    if (!isHex64(f.contentHash)) continue
    const entry = { fileName: f.fileName, hash: f.hash, contentHash: f.contentHash, size, time }
    if (isStr(f.address, ACCEPT.file.address)) entry.address = f.address
    if (isStr(f.name, ACCEPT.file.name)) entry.name = f.name
    if (isStr(f.topic, ACCEPT.file.topic)) entry.topic = f.topic
    if (isStr(f.signature, ACCEPT.file.signature)) entry.signature = f.signature
    if (isStr(f.info, ACCEPT.file.info)) entry.info = f.info
    if (isStr(f.type, ACCEPT.file.type)) entry.type = f.type
    out.push(entry)
  }
  return out
}

/**
 * Feed message (live `feed` and `send-feed-history` entries); limits of desktop's
 * `sanitize_feed_message` (native has no feed validator). The hash and the signature
 * (`wire.feedMessageHash`, `wire.feedSigningPayload`, XKR spend key) are checked by lib/feed.js.
 */
function feedMessage(data) {
  if (!isObject(data)) return fail('not_object')
  const L = ACCEPT.feed
  if (!isStr(data.address, L.address)) return fail('address')
  if (!isStr(data.message, L.message)) return fail('message')
  const signature = data.signature === undefined || data.signature === null ? '' : data.signature
  if (!isStr(signature, L.signature)) return fail('signature')
  if (!isStr(data.nickname, L.nickname)) return fail('nickname')
  if (!isStr(data.hash, L.hash)) return fail('hash')
  const timestamp = timestampOf(data.timestamp, L.timestamp, Infinity)
  if (timestamp === null) return fail('timestamp')
  const reply = data.reply === undefined || data.reply === null ? '' : data.reply
  if (!isStr(reply, L.reply)) return fail('reply')
  const tip = tipOf(data.tip, L.tipReceiver)
  if (tip === null) return fail('tip')
  return ok({
    message: data.message,
    address: data.address,
    nickname: data.nickname,
    signature,
    reply,
    hash: data.hash,
    timestamp,
    tip
  })
}

/** `{ typing: boolean }` */
function typing(data) {
  if (!isObject(data) || typeof data.typing !== 'boolean') return fail('typing')
  return ok({ typing: data.typing })
}

/** Room call SDP relay `{ data, offer, address, topic, retry }` (neither app validates it). */
function sdp(data) {
  if (!isObject(data)) return fail('not_object')
  if (data.data === undefined || data.data === null) return fail('data')
  if (typeof data.data !== 'string' && !isObject(data.data)) return fail('data')
  if (typeof data.offer !== 'boolean') return fail('offer')
  if (!isStr(data.address, ACCEPT.sdp.address)) return fail('address')
  if (!isStr(data.topic, ACCEPT.sdp.topic)) return fail('topic')
  if (data.retry !== undefined && typeof data.retry !== 'boolean') return fail('retry')
  return ok({
    data: data.data,
    offer: data.offer,
    address: data.address,
    topic: data.topic,
    retry: data.retry === true
  })
}

function ban(data) {
  if (!isObject(data) || data.type !== TYPES.BAN) return fail('type')
  if (!isStr(data.address, ACCEPT.ban.address) || data.address.length === 0) return fail('address')
  return ok({ type: TYPES.BAN, address: data.address })
}

/** Hashes of Ping / request-messages: more than 25 is malformed; non-64-character entries skipped. */
function hashList(hashes) {
  if (!Array.isArray(hashes)) return null
  if (hashes.length > ACCEPT.ping.hashes) return null
  return hashes.filter(isHash64)
}

function ping(data) {
  if (!isObject(data) || data.type !== TYPES.PING) return fail('type')
  let hashes = null
  if (data.hashes !== undefined) {
    hashes = hashList(data.hashes)
    if (hashes === null) return fail('hashes')
  }
  let peers = []
  if (data.peers !== undefined) {
    if (!Array.isArray(data.peers) || data.peers.length > ACCEPT.ping.peers) return fail('peers')
    peers = data.peers.filter(isHex64)
  }
  return ok({ type: TYPES.PING, peers, files: fileList(data.files), hashes })
}

function requestMessages(data) {
  const hashes = hashList(data && data.hashes)
  if (hashes === null) return fail('hashes')
  return ok({ type: TYPES.REQUEST_MESSAGES, hashes })
}

function missingMessages(data, opts = {}) {
  if (!Array.isArray(data && data.messages)) return fail('messages')
  return ok({ type: TYPES.MISSING_MESSAGES, messages: roomHistory(data.messages, opts) })
}

function requestHistory(data) {
  return ok({ type: TYPES.REQUEST_HISTORY, files: fileList(data && data.files) })
}

function sendHistory(data, opts = {}) {
  const messages = Array.isArray(data && data.messages) ? roomHistory(data.messages, opts) : []
  return ok({ type: TYPES.SEND_HISTORY, messages, files: fileList(data && data.files) })
}

function requestFeed() {
  return ok({ type: TYPES.REQUEST_FEED })
}

function sendFeedHistory(data) {
  if (!Array.isArray(data && data.messages)) return fail('messages')
  const messages = []
  for (const m of data.messages) {
    const r = feedMessage(m)
    if (r.ok) messages.push(r.value)
  }
  return ok({ type: TYPES.SEND_FEED_HISTORY, messages })
}

// ---------------------------------------------------------------------------------------------
// classification and ban decisions

/** Kinds that are handled before the sender's `joined` was accepted (both apps). */
const PRE_JOIN_KINDS = Object.freeze(['feed', 'disconnected', 'typing', 'file', 'sdp', 'joined', 'voice'])

/**
 * Message kind of a parsed JSON value, in the order both apps dispatch
 * (desktop `check_data_message` swarm.cjs, native swarm.js):
 * feed, disconnected, typing, file (`info`), sdp (`offer`), joined, voice, then the `type`d
 * messages, then a room message.
 */
function classify(data) {
  if (!isObject(data)) return 'invalid'
  if (data.type === TYPES.FEED) return 'feed'
  if (data.type === TYPES.DISCONNECTED) return 'disconnected'
  if ('typing' in data) return 'typing'
  if ('info' in data) return 'file'
  if ('offer' in data) return 'sdp'
  if ('joined' in data) return 'joined'
  if ('voice' in data) return 'voice'
  if ('type' in data) {
    if (typeof data.type !== 'string') return 'invalid-type'
    switch (data.type) {
      case TYPES.BAN:
        return 'ban'
      case TYPES.PING:
        return 'ping'
      case TYPES.REQUEST_MESSAGES:
        return 'request-messages'
      case TYPES.MISSING_MESSAGES:
        return 'missing-messages'
      case TYPES.REQUEST_HISTORY:
        return 'request-history'
      case TYPES.SEND_HISTORY:
        return 'send-history'
      case TYPES.REQUEST_FEED:
        return 'request-feed'
      case TYPES.SEND_FEED_HISTORY:
        return 'send-feed-history'
      default:
        return 'unknown-type'
    }
  }
  return 'room-message'
}

/**
 * Classifies and validates a parsed message.
 * @param {*} data parsed JSON
 * @param {{ dm?: boolean, now?: number }} [opts]
 * @returns {{ kind: string, ok: boolean, value?: object, reason?: string, ban?: boolean }}
 *   `ban: true` marks a message that both apps (or the app that checks it at all) treat as a
 *   reason to ban the peer; such a message is never sent by an app.
 */
function inspect(data, opts = {}) {
  const kind = classify(data)
  const done = (r, banOnFail) =>
    r.ok ? { kind, ok: true, value: r.value } : { kind, ok: false, reason: r.reason, ban: !!banOnFail }

  switch (kind) {
    case 'invalid':
      return { kind, ok: false, reason: 'not_object', ban: false }
    case 'feed': {
      const r = feedMessage(data)
      if (r.ok) r.value.type = TYPES.FEED
      return done(r, true)
    }
    case 'disconnected':
      return { kind, ok: true, value: { type: TYPES.DISCONNECTED } }
    case 'typing':
      return done(typing(data), false)
    case 'file':
      return done(fileMessage(data), true)
    case 'sdp':
      return done(sdp(data), false)
    case 'joined':
      return done(joined(data), true)
    case 'voice':
      return done(voiceStatus(data), true)
    case 'invalid-type':
      return { kind, ok: false, reason: 'type', ban: true }
    case 'ban':
      return done(ban(data), false)
    case 'ping':
      return done(ping(data), true)
    case 'request-messages':
      return done(requestMessages(data), true)
    case 'missing-messages':
      return done(missingMessages(data, opts), false)
    case 'request-history':
      return done(requestHistory(data), false)
    case 'send-history':
      return done(sendHistory(data, opts), false)
    case 'request-feed':
      return done(requestFeed(data), false)
    case 'send-feed-history':
      return done(sendFeedHistory(data), false)
    case 'unknown-type': {
      // Both apps reject more than 25 `hashes` on any typed message that reaches that check.
      if (data.hashes !== undefined && hashList(data.hashes) === null) {
        return { kind, ok: false, reason: 'hashes', ban: true }
      }
      return { kind, ok: false, reason: 'unknown_type', ban: false }
    }
    case 'room-message':
      if (opts.dm) return { kind, ok: false, reason: 'json_in_dm', ban: false }
      return done(roomMessage(data, opts), false)
    default:
      return { kind, ok: false, reason: 'unknown', ban: false }
  }
}

/**
 * The reason to ban the sender of `data` (parsed JSON), or null. Only messages that no app sends
 * get a reason. Context checks (the connection's own address on voice status, `idSig`) are the
 * caller's.
 */
function malformedReason(data, opts = {}) {
  const r = inspect(data, opts)
  if (r.ok || !r.ban) return null
  return r.kind + ':' + r.reason
}

function isMalformedPeerMessage(data, opts = {}) {
  return malformedReason(data, opts) !== null
}

module.exports = {
  // HTML / text sanitiser (html.js)
  sanitizeHtml: html.sanitizeHtml,
  sanitizeText: html.sanitizeText,
  escapeText: html.escapeText,
  decodeEntities: html.decodeEntities,
  HTML_POLICY: html.DEFAULT_POLICY,
  // type and length validation
  ACCEPT,
  SEND,
  PRE_JOIN_KINDS,
  BASE64_RE,
  roomMessage,
  roomHistory,
  joined,
  voiceStatus,
  fileMessage,
  fileList,
  feedMessage,
  typing,
  sdp,
  ban,
  ping,
  requestMessages,
  missingMessages,
  requestHistory,
  sendHistory,
  requestFeed,
  sendFeedHistory,
  classify,
  inspect,
  malformedReason,
  isMalformedPeerMessage,
  sendableAvatar,
  joinedAvatarOf,
  timestampOf,
  tipOf,
  isHex64,
  isRoomSignature,
  clampText
}
