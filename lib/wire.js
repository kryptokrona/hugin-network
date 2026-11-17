'use strict'

// Builders and the decoder for every message on the hugin-messages channel (README "Protocol").
// Field names and value types are the ones both old apps read. Builders check their input
// against the send limits (sanitize.SEND, the intersection of both old validators) and throw a
// WireError instead of producing something an old peer would refuse or ban for.
//
// The wire carries no version field today. `decode` treats a message without `v` as version 1
// and ignores messages that declare a newer version, so later formats can be introduced without
// being misread by this release. Builders never add `v`.

const b4a = require('b4a')
const { TYPES, FILE_SHARED, FILE_TYPE, MAX_SHARED_FILES, SIGNING_DOMAINS, HASH_DOMAINS } = require('./constants.js')
const S = require('./sanitize.js')
const { blake2b256Hex } = require('./bytes.js')

const WIRE_VERSION = 1

/**
 * Size guard for one message (UTF-8 bytes of the JSON string). A `joined` with the largest
 * avatar native accepts (614 400 base64 characters) plus a page of room history stays far below.
 */
const MAX_WIRE_BYTES = 2 * 1024 * 1024

const HEX_RE = /^[0-9a-f]*$/i

class WireError extends Error {
  constructor(message, field) {
    super(message)
    this.name = 'WireError'
    this.code = 'HUGIN_WIRE_INVALID'
    this.field = field
  }
}

// ---------------------------------------------------------------------------------------------
// send-side checks

function need(cond, field, what) {
  if (!cond) throw new WireError(`${field}: ${what}`, field)
}

function needStr(v, field, max) {
  need(typeof v === 'string' && v.length <= max, field, `string of at most ${max} characters`)
  return v
}

function needHex(v, field, length) {
  need(typeof v === 'string' && v.length === length && HEX_RE.test(v), field, `${length} hex characters`)
  return v
}

function needBool(v, field) {
  need(typeof v === 'boolean', field, 'boolean')
  return v
}

function sendTip(tip, maxReceiver) {
  if (tip === undefined || tip === null || tip === false) return false
  need(tip && typeof tip === 'object' && !Array.isArray(tip), 'tip', 'false or { amount, receiver }')
  need(typeof tip.amount === 'number' && Number.isFinite(tip.amount), 'tip.amount', 'number')
  needStr(tip.receiver, 'tip.receiver', maxReceiver)
  return { ...tip }
}

/** 64-hex entries of `hashes` (others are dropped: receivers skip them anyway), at most `max`. */
function hashArray(hashes, field, max) {
  need(Array.isArray(hashes), field, 'array')
  const out = hashes.filter(S.isHex64)
  need(out.length <= max, field, `at most ${max} entries`)
  return out
}

function fileArray(files, field) {
  need(Array.isArray(files), field, 'array')
  need(files.length <= MAX_SHARED_FILES, field, `at most ${MAX_SHARED_FILES} entries`)
  return files.slice()
}

/**
 * The last `max` files by time, as both apps select them for Ping and history
 * (`allFiles.sort((a, b) => a.time - b.time).slice(-10)`).
 */
function recentFiles(files, max = MAX_SHARED_FILES) {
  if (!Array.isArray(files)) return []
  return files.slice().sort((a, b) => a.time - b.time).slice(-max)
}

// ---------------------------------------------------------------------------------------------
// encode / decode

/** JSON string of a message, refused above MAX_WIRE_BYTES. */
function encode(message) {
  const str = JSON.stringify(message)
  need(typeof str === 'string', 'message', 'JSON-serializable value')
  if (b4a.byteLength(str, 'utf8') > MAX_WIRE_BYTES) {
    throw new WireError(`message: larger than ${MAX_WIRE_BYTES} bytes`, 'size')
  }
  return str
}

/**
 * Decodes one channel message.
 * @param {string|Uint8Array} input
 * @param {{ dm?: boolean, now?: number }} [opts] `dm`: the swarm is a DM swarm, where non-JSON
 *   messages are DM payloads (hugin-crypto `encodeExtra` hex)
 * @returns {{ type: string, value?: any, reason?: string, ban?: boolean }}
 *   `type` is a sanitize kind (`joined`, `room-message`, `ping`, ...) with the normalized `value`,
 *   `dm` with the payload string, `ignored` (nothing to do), or `invalid` with `reason` and `ban`
 *   (true when both apps would ban the sender for it).
 */
function decode(input, opts = {}) {
  let str
  if (typeof input === 'string') str = input
  else if (input instanceof Uint8Array) str = b4a.toString(input, 'utf8')
  else return { type: 'invalid', reason: 'not_a_string', ban: false }

  if (b4a.byteLength(str, 'utf8') > MAX_WIRE_BYTES) {
    return { type: 'invalid', reason: 'too_large', ban: false }
  }

  let data
  try {
    data = JSON.parse(str)
  } catch {
    if (opts.dm) return { type: 'dm', value: str }
    return { type: 'invalid', reason: 'not_json', ban: true }
  }

  if (data === null || typeof data !== 'object' || Array.isArray(data)) {
    // A DM payload that happens to parse as a JSON number or string is still a DM payload.
    if (opts.dm && typeof data !== 'object') return { type: 'dm', value: str }
    return { type: 'invalid', reason: 'not_object', ban: false }
  }

  if (typeof data.v === 'number' && data.v > WIRE_VERSION) {
    return { type: 'ignored', reason: 'version' }
  }

  const r = S.inspect(data, opts)
  if (r.ok) return { type: r.kind, value: r.value }
  if (r.kind === 'unknown-type' && !r.ban) return { type: 'ignored', reason: r.reason }
  if (r.kind === 'room-message' && opts.dm) return { type: 'ignored', reason: r.reason }
  return { type: 'invalid', kind: r.kind, reason: r.reason, ban: r.ban }
}

// ---------------------------------------------------------------------------------------------
// builders

/**
 * `joined`: sent first on every new connection.
 * `message` carries the topic (both apps accept it; desktop used to put the room key there).
 * `driveKey` is left out unless it is 64 hex characters, `avatar` is left empty unless every old
 * peer accepts it, and `voice` is forced on while `video` is on (both apps do that).
 */
function joined(o) {
  needStr(o.address, 'address', S.SEND.joined.address)
  needStr(o.name, 'name', S.SEND.joined.name)
  needHex(o.topic, 'topic', 64)
  const signature = o.signature === undefined ? '' : o.signature
  need(signature === '' || (typeof signature === 'string' && signature.length === 128 && HEX_RE.test(signature)), 'signature', "'' or 128 hex characters")
  need(typeof o.idSig === 'string' && o.idSig.length > 0 && o.idSig.length <= S.SEND.joined.idSig, 'idSig', `non-empty string of at most ${S.SEND.joined.idSig} characters`)
  need(typeof o.time === 'number' || typeof o.time === 'string', 'time', 'number or string')
  const time = String(o.time)
  need(time.length <= S.SEND.joined.time, 'time', `at most ${S.SEND.joined.time} characters`)
  const video = o.video === undefined ? false : needBool(o.video, 'video')
  const voice = video ? true : o.voice === undefined ? false : needBool(o.voice, 'voice')
  const audioMute = o.audioMute === undefined ? false : needBool(o.audioMute, 'audioMute')
  const videoMute = o.videoMute === undefined ? false : needBool(o.videoMute, 'videoMute')
  const screenshare = o.screenshare === undefined ? false : needBool(o.screenshare, 'screenshare')
  const messages = o.messages === undefined ? [] : o.messages
  need(Array.isArray(messages), 'messages', 'array')

  const msg = {
    address: o.address,
    signature,
    avatar: S.sendableAvatar(o.avatar, S.SEND.joined.avatarBytes),
    message: o.topic,
    joined: true,
    topic: o.topic,
    name: o.name,
    voice,
    channels: [],
    video,
    time,
    idSig: o.idSig,
    audioMute,
    videoMute,
    screenshare,
    messages: messages.slice()
  }
  if (S.isHex64(o.driveKey)) msg.driveKey = o.driveKey
  return msg
}

/** Domain prefix of the signed room message payload (no version number in it: a later format gets a new prefix). */
const ROOM_MESSAGE_DOMAIN = SIGNING_DOMAINS.ROOM_MESSAGE

/** `tip` as the signed payloads carry it: null for no tip, else `[amount, receiver]`. */
function signedTip(tip) {
  if (tip === undefined || tip === null || tip === false) return null
  need(typeof tip === 'object' && typeof tip.amount === 'number' && Number.isFinite(tip.amount) && typeof tip.receiver === 'string', 'tip', 'false or { amount, receiver }')
  return [tip.amount, tip.receiver]
}

/** `reply` as the signed payloads carry it ('' when absent). */
function signedReply(reply) {
  const r = reply === undefined || reply === null ? '' : reply
  need(typeof r === 'string', 'reply', 'string')
  return r
}

/** The checked fields of a room message every derived value covers (all but hash and signature). */
function roomMessageFields(m) {
  need(m && typeof m === 'object', 'message', 'object')
  need(typeof m.room === 'string', 'room', 'string')
  need(Number.isSafeInteger(m.timestamp), 'timestamp', 'safe integer')
  need(typeof m.address === 'string', 'address', 'string')
  need(typeof m.name === 'string', 'name', 'string')
  need(typeof m.message === 'string', 'message', 'string')
  return [m.room, m.timestamp, m.address, m.name, m.message, signedReply(m.reply), signedTip(m.tip)]
}

/**
 * The hash of a room message, derived from its content (README "Protocol"): 64
 * lower-case hex characters,
 *
 *   hex(BLAKE2b-256(UTF-8("hugin/room-message-hash\n" + JSON.stringify([room, timestamp,
 *                                                     address, name, message, reply, tip]))))
 *
 * with `reply` and `tip` as in `roomMessageSigningPayload`. Receivers recompute it and drop a
 * message whose hash differs (compared in lower case). Throws a WireError for a value no valid
 * message has.
 */
function roomMessageHash(m) {
  return blake2b256Hex(HASH_DOMAINS.ROOM_MESSAGE + JSON.stringify(roomMessageFields(m)))
}

/** True when `m.hash` is the hash derived from the message's fields (either case). */
function isRoomMessageHash(m) {
  try {
    return typeof m.hash === 'string' && m.hash.toLowerCase() === roomMessageHash(m)
  } catch {
    return false
  }
}

/**
 * The string the sender's XKR spend key signs for a room message (README
 * "Protocol"): the domain prefix, then the JSON array of every field that carries meaning, in a
 * fixed order:
 *
 *   "hugin/room-message\n" + JSON.stringify([room, hash, timestamp, address, name, message,
 *                                            reply, tip])
 *
 * `hash` in lower case (stores may change its case; it is `roomMessageHash` of the other
 * fields), `timestamp` an integer (JSON number), `reply` '' when absent, `tip` null for no tip,
 * else `[amount, receiver]`. JSON.stringify of an array of strings, numbers and null is
 * one-to-one (every string is quoted and escaped, lone surrogates included since ES2019), so two
 * different messages never give the same payload, and its output is well-formed UTF-16, so the
 * host's UTF-8 encoding is one-to-one too. Takes the builder's output or a validated message
 * (lib/sanitize.js `roomMessage`). Throws a WireError for a value no valid message has.
 */
function roomMessageSigningPayload(m) {
  const [room, timestamp, address, name, message, reply, tip] = roomMessageFields(m)
  need(typeof m.hash === 'string' && HEX_RE.test(m.hash), 'hash', 'hex string')
  return ROOM_MESSAGE_DOMAIN + JSON.stringify([room, m.hash.toLowerCase(), timestamp, address, name, message, reply, tip])
}

/**
 * Room message, in the shape native sends. `hash` = `roomMessageHash` of the same fields
 * (64 hex characters; builders do not derive it, `Rooms#send` does), `signature` = host
 * signature of `roomMessageSigningPayload(...)` of the same fields (128 hex characters,
 * required).
 */
function roomMessage(o) {
  const L = S.SEND.room
  needHex(o.hash, 'hash', L.hashHex)
  needStr(o.room, 'room', L.room)
  needStr(o.address, 'address', L.address)
  needStr(o.message, 'message', L.message)
  needStr(o.name, 'name', L.name)
  const reply = o.reply === undefined || o.reply === null ? '' : needStr(o.reply, 'reply', L.reply)
  const signature = needHex(o.signature, 'signature', L.signatureHex)
  need(Number.isSafeInteger(o.timestamp), 'timestamp', 'integer')
  return {
    hash: o.hash,
    room: o.room,
    address: o.address,
    message: o.message,
    name: o.name,
    reply,
    signature,
    timestamp: o.timestamp,
    tip: sendTip(o.tip, L.tipReceiver)
  }
}

function typing(isTyping) {
  return { typing: needBool(isTyping, 'typing') }
}

/** The checked fields of a feed message every derived value covers (all but hash and signature). */
function feedFields(m) {
  need(m && typeof m === 'object', 'message', 'object')
  need(Number.isSafeInteger(m.timestamp), 'timestamp', 'safe integer')
  need(typeof m.address === 'string', 'address', 'string')
  need(typeof m.nickname === 'string', 'nickname', 'string')
  need(typeof m.message === 'string', 'message', 'string')
  return [m.timestamp, m.address, m.nickname, m.message, signedReply(m.reply), signedTip(m.tip)]
}

/**
 * The hash of a feed message, derived from its content like a room message's:
 *
 *   hex(BLAKE2b-256(UTF-8("hugin/feed-hash\n" + JSON.stringify([timestamp, address, nickname,
 *                                                         message, reply, tip]))))
 */
function feedMessageHash(m) {
  return blake2b256Hex(HASH_DOMAINS.FEED + JSON.stringify(feedFields(m)))
}

/** True when `m.hash` is the hash derived from the feed message's fields (either case). */
function isFeedMessageHash(m) {
  try {
    return typeof m.hash === 'string' && m.hash.toLowerCase() === feedMessageHash(m)
  } catch {
    return false
  }
}

/**
 * The string the XKR spend key signs for a feed message (README "Protocol"); it covers every field:
 *
 *   "hugin/feed\n" + JSON.stringify([hash, timestamp, address, nickname, message, reply, tip])
 *
 * `hash` in lower case, `timestamp` an integer, `reply` '' when absent, `tip` null or
 * `[amount, receiver]`. Takes the builder's output or a validated message. Throws a WireError
 * for a value no valid message has.
 */
function feedSigningPayload(m) {
  const [timestamp, address, nickname, message, reply, tip] = feedFields(m)
  need(typeof m.hash === 'string' && HEX_RE.test(m.hash), 'hash', 'hex string')
  return SIGNING_DOMAINS.FEED + JSON.stringify([m.hash.toLowerCase(), timestamp, address, nickname, message, reply, tip])
}

/**
 * Feed message; `hash` = `feedMessageHash` of the same fields, `signature` = host signature of
 * `feedSigningPayload(...)` of the same fields.
 */
function feed(o) {
  const L = S.SEND.feed
  needStr(o.message, 'message', L.message)
  needStr(o.nickname, 'nickname', L.nickname)
  needStr(o.address, 'address', L.address)
  const reply = o.reply === undefined || o.reply === null ? '' : needStr(o.reply, 'reply', L.reply)
  needHex(o.hash, 'hash', L.hashHex)
  need(Number.isSafeInteger(o.timestamp), 'timestamp', 'integer')
  need(typeof o.signature === 'string' && o.signature.length > 0 && o.signature.length <= L.signature, 'signature', `non-empty string of at most ${L.signature} characters`)
  return {
    type: TYPES.FEED,
    message: o.message,
    nickname: o.nickname,
    address: o.address,
    reply,
    tip: sendTip(o.tip, L.tipReceiver),
    hash: o.hash,
    timestamp: o.timestamp,
    signature: o.signature
  }
}

/** Room state Ping. `files`: drive metadata, at most 10 (see `recentFiles`). */
function ping({ peers = [], files = [], hashes = [] } = {}) {
  const msg = {
    type: TYPES.PING,
    peers: hashArray(peers, 'peers', S.SEND.ping.peers),
    files: fileArray(files, 'files'),
    hashes: hashArray(hashes, 'hashes', S.SEND.ping.hashes)
  }
  return msg
}

function requestMessages(hashes) {
  return { type: TYPES.REQUEST_MESSAGES, hashes: hashArray(hashes, 'hashes', S.SEND.ping.hashes) }
}

function missingMessages(messages) {
  need(Array.isArray(messages), 'messages', 'array')
  return { type: TYPES.MISSING_MESSAGES, messages: messages.slice() }
}

function requestHistory(files = []) {
  return { type: TYPES.REQUEST_HISTORY, files: fileArray(files, 'files') }
}

function sendHistory({ messages = [], files = [] } = {}) {
  need(Array.isArray(messages), 'messages', 'array')
  return { type: TYPES.SEND_HISTORY, messages: messages.slice(), files: fileArray(files, 'files') }
}

function requestFeed() {
  return { type: TYPES.REQUEST_FEED }
}

function sendFeedHistory(messages) {
  need(Array.isArray(messages), 'messages', 'array')
  return { type: TYPES.SEND_FEED_HISTORY, messages: messages.slice() }
}

/** Admin ban broadcast. Receivers honour it only from a peer whose admin signature verified. */
function ban(address) {
  return { type: TYPES.BAN, address: needStr(address, 'address', S.ACCEPT.ban.address) }
}

function disconnected() {
  return { type: TYPES.DISCONNECTED }
}

/**
 * Voice channel status. Not signed (hugin-network 3.0): it is acted on only from a joined peer
 * (whose `idSig` verified on that connection) and only when its `address` is that peer's.
 * Receivers ignore a `signature` field.
 */
function voiceStatus(o) {
  const L = S.SEND.voice
  needStr(o.address, 'address', L.address)
  needHex(o.topic, 'topic', 64)
  needStr(o.name, 'name', L.name)
  return {
    address: o.address,
    avatar: S.sendableAvatar(o.avatar, L.avatarBytes),
    message: o.topic,
    voice: needBool(o.voice, 'voice'),
    topic: o.topic,
    name: o.name,
    video: needBool(o.video, 'video'),
    audioMute: needBool(o.audioMute, 'audioMute'),
    videoMute: needBool(o.videoMute, 'videoMute'),
    screenshare: needBool(o.screenshare, 'screenshare')
  }
}

/**
 * `offer` / `retry` flags of an SDP the UI hands over (desktop `get_sdp`, native `send_sdp`):
 * an answer or a renegotiation is not an offer, `retry: true` asks the peer to expand it.
 */
function sdpFlags({ type, data, retry } = {}) {
  let offer = true
  if (type === 'answer') offer = false
  if (data && typeof data === 'object' && 'renegotiate' in data) offer = false
  return { offer, retry: retry === true }
}

/** SDP relay message to one peer; `address` is the sender's own address. */
function sdp(o) {
  need(o.data !== undefined && o.data !== null && (typeof o.data === 'string' || typeof o.data === 'object'), 'data', 'string or object')
  needStr(o.address, 'address', S.ACCEPT.sdp.address)
  needHex(o.topic, 'topic', 64)
  return {
    data: o.data,
    offer: needBool(o.offer, 'offer'),
    address: o.address,
    topic: o.topic,
    retry: o.retry === undefined ? false : needBool(o.retry, 'retry')
  }
}

/**
 * The string the XKR spend key signs for a file (announcement and drive metadata; README
 * "Protocol"):
 *
 *   "hugin/file\n" + JSON.stringify([topic, hash, contentHash, size, time, fileName, address])
 *
 * `topic`, `hash` and `contentHash` in lower case, `size` and `time` integers. `contentHash` is
 * the BLAKE2b-256 of the file bytes (`bytes.blake2b256Hex`), so the signature also covers the
 * content. A copy of the file in another peer's drive carries the author's address and
 * signature unchanged. Throws a WireError for a value no valid file has.
 */
function fileSigningPayload(f) {
  need(f && typeof f === 'object', 'file', 'object')
  need(typeof f.topic === 'string' && f.topic.length === 64 && HEX_RE.test(f.topic), 'topic', '64 hex characters')
  need(typeof f.hash === 'string' && f.hash.length === 64 && HEX_RE.test(f.hash), 'hash', '64 hex characters')
  need(typeof f.contentHash === 'string' && f.contentHash.length === 64 && HEX_RE.test(f.contentHash), 'contentHash', '64 hex characters')
  need(Number.isSafeInteger(f.size) && f.size >= 0, 'size', 'non-negative integer')
  need(Number.isSafeInteger(f.time), 'time', 'integer')
  need(typeof f.fileName === 'string', 'fileName', 'string')
  need(typeof f.address === 'string', 'address', 'string')
  return (
    SIGNING_DOMAINS.FILE +
    JSON.stringify([f.topic.toLowerCase(), f.hash.toLowerCase(), f.contentHash.toLowerCase(), f.size, f.time, f.fileName, f.address])
  )
}

/**
 * File announcement (`info: 'file-shared'`). No `driveKey`: receivers use the one from the
 * sender's `joined`. `contentHash` (64 hex) is the BLAKE2b-256 of the file bytes; a receiver
 * checks the downloaded bytes against it.
 */
function fileShared(o) {
  const L = S.SEND.file
  needStr(o.fileName, 'fileName', L.fileName)
  needStr(o.address, 'address', L.address)
  needStr(o.name, 'name', L.name)
  needHex(o.topic, 'topic', 64)
  need(Number.isSafeInteger(o.size) && o.size >= 0, 'size', 'non-negative integer')
  need(Number.isSafeInteger(o.time), 'time', 'integer')
  needHex(o.hash, 'hash', L.hashHex)
  needHex(o.contentHash, 'contentHash', L.contentHashHex)
  need(typeof o.signature === 'string' && o.signature.length <= L.signature, 'signature', `string of at most ${L.signature} characters`)
  return {
    fileName: o.fileName,
    address: o.address,
    name: o.name,
    topic: o.topic,
    info: FILE_SHARED,
    type: FILE_TYPE,
    size: o.size,
    time: o.time,
    hash: o.hash,
    contentHash: o.contentHash,
    signature: o.signature
  }
}

module.exports = {
  WIRE_VERSION,
  MAX_WIRE_BYTES,
  WireError,
  encode,
  decode,
  recentFiles,
  joined,
  roomMessage,
  roomMessageSigningPayload,
  roomMessageHash,
  isRoomMessageHash,
  ROOM_MESSAGE_DOMAIN,
  typing,
  feed,
  feedSigningPayload,
  feedMessageHash,
  isFeedMessageHash,
  ping,
  requestMessages,
  missingMessages,
  requestHistory,
  sendHistory,
  requestFeed,
  sendFeedHistory,
  ban,
  disconnected,
  voiceStatus,
  sdp,
  sdpFlags,
  fileShared,
  fileSigningPayload
}
