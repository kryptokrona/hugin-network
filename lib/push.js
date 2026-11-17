'use strict'

// hugin-node packets and push payloads, as pure builders and parsers.
//
// Part 1, hugin-node packets JSON bodies of bare-rpc PACKET (1)
// requests, as hugin-desktop (`swarm.cjs` NodeConnection) and hugin-native (`swarm.js`
// NodeConnection) build them.
//
// Part 2, push payloads for the push node (README "Protocol"): the room push (room-key secretbox inside
// a sealed box to the push server) and push registrations (desktop `messages.cjs`
// send_room_message_push, native `bare/messages.js`), and the view tags the node routes by.

const b4a = require('b4a')
const sodium = require('sodium-universal')
const { keccak256 } = require('js-sha3')
const { PUSH_SERVER_PUBKEY, MAX_NODE_PACKET_BYTES, MAX_NODE_SYNC_MESSAGES, XKR_ADDRESS_LENGTH, ONE_WEEK_MS } = require('./constants.js')
const { hexToUint, toHex, utf8ToHex, isHex, randomBytes } = require('./bytes.js')
const { validatePowJob, MAX_SHARES } = require('./pow.js')

class PacketError extends Error {
  constructor(message, field) {
    super(message)
    this.name = 'PacketError'
    this.code = 'HUGIN_PACKET_INVALID'
    this.field = field
  }
}

function need(cond, field, what) {
  if (!cond) throw new PacketError(`${field}: ${what}`, field)
}

// =============================================================================================
// Part 1: hugin-node packets

const POST_KINDS = Object.freeze(['dm', 'call', 'room'])

/**
 * Store-and-forward sync: `{ request: true, type: 'some', timestamp, id }`. The timestamp is
 * always a number (hugin-node bans a sync without one); `id` defaults to the timestamp as both
 * apps do.
 */
function syncRequest({ since, id } = {}) {
  const timestamp = typeof since === 'number' && Number.isFinite(since) ? since : 0
  return { request: true, type: 'some', timestamp, id: id === undefined ? timestamp : id }
}

function jobRequest(id) {
  need(id !== undefined && id !== null, 'id', 'required')
  return { type: 'job_request', id }
}

/**
 * Post message without its `pow` (needed first to compute the auth context):
 * `{ cipher, timestamp, hash, id: timestamp, push: true, viewtag, kind }`.
 */
function postMessage({ cipher, hash, viewtag, kind = 'dm', timestamp }) {
  need(typeof cipher === 'string' && isHex(cipher) && cipher.length <= MAX_NODE_PACKET_BYTES, 'cipher', `even-length hex of at most ${MAX_NODE_PACKET_BYTES} characters`)
  need(typeof hash === 'string' && hash.length > 0 && hash.length <= 64 && /^[0-9a-f]+$/i.test(hash), 'hash', 'hex of at most 64 characters')
  need(typeof timestamp === 'number' && Number.isFinite(timestamp), 'timestamp', 'number')
  need(POST_KINDS.includes(kind), 'kind', POST_KINDS.join('/'))
  need(viewtag === undefined || typeof viewtag === 'string', 'viewtag', 'string')
  return { cipher, timestamp, hash, id: timestamp, push: true, viewtag, kind }
}

function checkPow(pow) {
  need(pow && typeof pow === 'object', 'pow', 'object')
  need(pow.version === 2, 'pow.version', '2')
  need(validatePowJob(pow.job).ok, 'pow.job', 'valid job')
  need(Array.isArray(pow.shares) && pow.shares.length > 0 && pow.shares.length <= MAX_SHARES, 'pow.shares', `1-${MAX_SHARES} shares`)
  need(pow.auth && typeof pow.auth.pub === 'string' && typeof pow.auth.sig === 'string', 'pow.auth', '{ pub, sig, nonce }')
}

/** `{ type: 'post', message: { ...postMessage, pow } }` */
function postPacket({ cipher, hash, viewtag, kind = 'dm', timestamp, pow }) {
  checkPow(pow)
  return { type: 'post', message: { ...postMessage({ cipher, hash, viewtag, kind, timestamp }), pow } }
}

/** `{ register: true, data, timestamp, id: timestamp, hash, pow }` (push registration). */
function registerPacket({ data, timestamp, hash, pow }) {
  need(typeof data === 'string', 'data', 'string')
  need(typeof timestamp === 'number' && Number.isFinite(timestamp), 'timestamp', 'number')
  need(typeof hash === 'string' && hash.length > 0 && hash.length <= 64, 'hash', 'at most 64 characters')
  checkPow(pow)
  return { register: true, data, timestamp, id: timestamp, hash, pow }
}

/** JSON body of a PACKET request; refused above 9000 bytes (hugin-node bans larger ones). */
function encodePacket(packet) {
  const str = JSON.stringify(packet)
  need(typeof str === 'string', 'packet', 'JSON-serializable value')
  if (b4a.byteLength(str, 'utf8') > MAX_NODE_PACKET_BYTES) {
    throw new PacketError(`packet: larger than ${MAX_NODE_PACKET_BYTES} bytes`, 'size')
  }
  return str
}

/**
 * Classifies a packet from a node, in the order both apps route them (`handle_node_packet`):
 *   messages     `{ type: 'new-message', messages }` (pushed DMs; `nodeMessages`: only valid
 *                entries, at most MAX_NODE_SYNC_MESSAGES)
 *   address      `{ address, version }` hello from the node (address of 99 characters, else ignored)
 *   job          `{ type: 'job', job, id? }` (`valid` = validatePowJob; with a pending id it answers a job_request)
 *   job_pending  `{ type: 'job_pending', id }`
 *   chunk / done the chunked sync answer (`chunks` / `done` keys)
 *   result       `{ success, reason?, duplicate?, rejects?, id }` answer to a post/registration
 *   response     `{ response, id }` answer to a sync
 *   hello        `{ version }` without an address
 *   ignored / invalid
 */
function parseNodePacket(input) {
  let data = input
  if (typeof input === 'string' || input instanceof Uint8Array) {
    try {
      data = JSON.parse(typeof input === 'string' ? input : b4a.toString(input, 'utf8'))
    } catch {
      return { kind: 'invalid', reason: 'not_json' }
    }
  }
  if (!data || typeof data !== 'object' || Array.isArray(data)) return { kind: 'invalid', reason: 'not_object' }

  if (data.type === 'new-message' && Array.isArray(data.messages)) {
    return { kind: 'messages', messages: nodeMessages(data.messages) }
  }
  if ('address' in data) {
    if (typeof data.address !== 'string' || data.address.length !== XKR_ADDRESS_LENGTH) {
      return { kind: 'ignored', reason: 'address' }
    }
    return { kind: 'address', address: data.address, version: data.version }
  }
  if (data.type === 'job' && data.job) {
    const v = validatePowJob(data.job)
    return { kind: 'job', job: data.job, id: data.id, valid: v.ok, reason: v.reason }
  }
  if (data.type === 'job_pending') return { kind: 'job_pending', id: data.id }
  if ('chunks' in data) return { kind: 'chunk', id: data.id, response: data.response }
  if ('done' in data) return { kind: 'done', id: data.id }
  if ('success' in data) {
    const out = { kind: 'result', id: data.id, success: data.success === true }
    if (typeof data.reason === 'string') out.reason = data.reason
    if (data.duplicate === true) out.duplicate = true
    if (Array.isArray(data.rejects)) out.rejects = data.rejects
    return out
  }
  if ('response' in data) return { kind: 'response', id: data.id, response: data.response }
  if ('version' in data) return { kind: 'hello', version: data.version }
  return { kind: 'ignored', reason: 'unknown' }
}

/**
 * The answer object a post/registration resolves with, from a parsed `result` packet:
 * `{ success, id, reason?, duplicate?, rejects? }` (what both apps resolve `message()` and
 * `register()` with, minus unknown keys).
 */
function nodeResult(parsed) {
  if (!parsed || parsed.kind !== 'result') return { success: false, reason: 'unknown' }
  const out = { success: parsed.success === true, id: parsed.id }
  if (typeof parsed.reason === 'string') out.reason = parsed.reason
  if (parsed.duplicate === true) out.duplicate = true
  if (Array.isArray(parsed.rejects)) out.rejects = parsed.rejects
  return out
}

const HEX64_RE = /^[0-9a-f]{64}$/i

/**
 * One pooled message from a node (`new-message` push or sync answer), as hosts receive it:
 * `{ hash, cipher, timestamp[, viewtag][, kind] }`, or null when it is not one. `hash` is 64 hex
 * characters, `cipher` even-length hex of at most MAX_NODE_PACKET_BYTES characters, `timestamp`
 * a finite number; `viewtag` (hex of at most 64 characters) and `kind` ('dm', 'call' or 'room')
 * are kept when well-formed. No other field is kept.
 */
function nodeMessage(m) {
  if (!m || typeof m !== 'object' || Array.isArray(m)) return null
  if (typeof m.hash !== 'string' || !HEX64_RE.test(m.hash)) return null
  if (typeof m.cipher !== 'string' || m.cipher.length === 0 || m.cipher.length > MAX_NODE_PACKET_BYTES || !isHex(m.cipher)) return null
  if (typeof m.timestamp !== 'number' || !Number.isFinite(m.timestamp)) return null
  const out = { hash: m.hash, cipher: m.cipher, timestamp: m.timestamp }
  if (typeof m.viewtag === 'string' && m.viewtag.length > 0 && m.viewtag.length <= 64 && isHex(m.viewtag, m.viewtag.length)) out.viewtag = m.viewtag
  if (POST_KINDS.includes(m.kind)) out.kind = m.kind
  return out
}

/** The valid messages of a list (`nodeMessage`), at most `max`; always an array. */
function nodeMessages(list, max = MAX_NODE_SYNC_MESSAGES) {
  if (!Array.isArray(list)) return []
  const out = []
  for (const m of list) {
    if (out.length >= max) break
    const v = nodeMessage(m)
    if (v) out.push(v)
  }
  return out
}

/** Messages of a sync answer (`response`) or of one chunk of a chunked answer (`nodeMessages`). */
function syncMessages(response, max = MAX_NODE_SYNC_MESSAGES) {
  return nodeMessages(response, max)
}

// =============================================================================================
// Part 2: push payloads and view tags

/** Keccak-256 (CryptoNote `cn_fast_hash`) of bytes, as hex. */
function cnFastHash(bytes) {
  return keccak256(bytes)
}

/** `cn_fast_hash` of a hex string, as kryptokrona-utils takes its input. */
function cnFastHashHex(hex) {
  return cnFastHash(hexToUint(hex))
}

/** Week number used in DM view tags: `floor(now / one week)`. */
function weekNumber(now = Date.now()) {
  return Math.floor(now / ONE_WEEK_MS)
}

/**
 * DM view tag of a recipient: `cn_fast_hash(hex(viewPublicKey + week))`, first 3 hex characters
 * (all 64 for calls). Desktop `messages.cjs:generate_push_view_tag`, RN `wallet.js:generate_view_tag`.
 */
function dmViewTag(viewPublicKey, { now = Date.now(), long = false } = {}) {
  const hash = cnFastHashHex(utf8ToHex(String(viewPublicKey) + String(weekNumber(now))))
  return long ? hash : hash.substring(0, 3)
}

/** Room view tag: `cn_fast_hash(invite)`, first 5 hex characters (desktop and RN `generate_room_view_tag`). */
function roomViewTag(invite) {
  return cnFastHashHex(String(invite)).substring(0, 5)
}

/**
 * 24-byte secretbox nonce from a timestamp: the decimal digits read as hex bytes, zero-padded
 * (`nonceFromTimestamp` in desktop utils.cjs, RN crypto.ts and native messages.js). Room pushes
 * no longer use it (they carry a random nonce, see `roomPushBox`).
 */
function nonceFromTimestamp(timestamp) {
  const digits = hexToUint(String(timestamp))
  const nonce = new Uint8Array(sodium.crypto_secretbox_NONCEBYTES)
  nonce.set(digits.subarray(0, nonce.length))
  return nonce
}

/** Room push key: the first 64 hex characters of the invite (32 bytes). */
function roomPushKey(invite) {
  need(typeof invite === 'string' && isHex(invite.substring(0, 64), 64), 'invite', 'starts with 64 hex characters')
  return b4a.from(hexToUint(invite.substring(0, 64)))
}

/**
 * Payload of a room push: the room message as sent (native's choice, a superset of the fields
 * desktop puts there). Only the RN app opens room pushes.
 */
function roomPushPayload(message) {
  return {
    hash: message.hash,
    room: message.room,
    address: message.address,
    message: message.message,
    name: message.name,
    reply: message.reply,
    signature: message.signature,
    timestamp: message.timestamp,
    tip: message.tip
  }
}

function serverKey(serverPublicKey) {
  const key = serverPublicKey === undefined ? PUSH_SERVER_PUBKEY : serverPublicKey
  const bytes = typeof key === 'string' ? b4a.from(key, 'hex') : key
  need(bytes instanceof Uint8Array && bytes.byteLength === sodium.crypto_box_PUBLICKEYBYTES, 'serverPublicKey', '32 bytes')
  return bytes
}

/** `hex(JSON({ box: hex(crypto_box_seal(JSON(payload))), t }))` (native seal_to_push_server). */
function sealToPushServer(payload, timestamp, serverPublicKey) {
  const plain = b4a.from(JSON.stringify(payload), 'utf8')
  const sealed = b4a.alloc(plain.byteLength + sodium.crypto_box_SEALBYTES)
  sodium.crypto_box_seal(sealed, plain, serverKey(serverPublicKey))
  return utf8ToHex(JSON.stringify({ box: toHex(sealed), t: timestamp }))
}

/**
 * Inner room-push box (README "Protocol"): a random 24-byte nonce followed by
 * `crypto_secretbox(JSON(payload), nonce, roomKey)`, as hex:
 *
 *   hex(nonce || secretbox)
 *
 * `opts.nonce` (24 bytes) fixes the nonce (tests); `timestamp` is not used by the box.
 */
function roomPushBox({ invite, payload, nonce } = {}) {
  const key = roomPushKey(invite)
  const n = nonce === undefined ? randomBytes(sodium.crypto_secretbox_NONCEBYTES) : nonce
  need(n instanceof Uint8Array && n.byteLength === sodium.crypto_secretbox_NONCEBYTES, 'nonce', `${sodium.crypto_secretbox_NONCEBYTES} bytes`)
  const plain = b4a.from(JSON.stringify(payload), 'utf8')
  const box = b4a.alloc(plain.byteLength + sodium.crypto_secretbox_MACBYTES)
  sodium.crypto_secretbox_easy(box, plain, n, key)
  return toHex(n) + toHex(box)
}

/**
 * Room push wire hex for a `post` with `kind: 'room'`:
 * sealToPushServer({ box: roomPushBox(...), viewTag }, timestamp) (`timestamp` is the envelope's
 * `t`; the box carries its own random nonce).
 */
function sealRoomPush({ invite, payload, timestamp, viewTag, serverPublicKey, nonce }) {
  need(typeof timestamp === 'number' && Number.isFinite(timestamp), 'timestamp', 'number')
  const tag = viewTag === undefined ? roomViewTag(invite) : viewTag
  return sealToPushServer({ box: roomPushBox({ invite, payload, nonce }), viewTag: tag }, timestamp, serverPublicKey)
}

/** Push registration: sealed `{ deviceId, viewTag[, type] }` (native encrypt_push_registration). */
function sealRegistration({ deviceId, viewTag, type, timestamp = Date.now(), serverPublicKey }) {
  const payload = type ? { deviceId, viewTag, type } : { deviceId, viewTag }
  return sealToPushServer(payload, timestamp, serverPublicKey)
}

/** Opens the outer envelope with the push server's key pair (what the push server does). */
function openPushEnvelope(wireHex, { publicKey, secretKey }) {
  let envelope
  try {
    envelope = JSON.parse(b4a.toString(b4a.from(wireHex, 'hex'), 'utf8'))
  } catch {
    return null
  }
  if (!envelope || typeof envelope.box !== 'string') return null
  const sealed = b4a.from(envelope.box, 'hex')
  if (sealed.byteLength <= sodium.crypto_box_SEALBYTES) return null
  const plain = b4a.alloc(sealed.byteLength - sodium.crypto_box_SEALBYTES)
  const pk = typeof publicKey === 'string' ? b4a.from(publicKey, 'hex') : publicKey
  const sk = typeof secretKey === 'string' ? b4a.from(secretKey, 'hex') : secretKey
  if (!sodium.crypto_box_seal_open(plain, sealed, pk, sk)) return null
  try {
    return { t: envelope.t, payload: JSON.parse(b4a.toString(plain, 'utf8')) }
  } catch {
    return null
  }
}

/**
 * Opens an inner room-push box (`roomPushBox`: nonce, then the secretbox) with the first room
 * key that fits (native decrypt_room_push). `timestamp` is not used (the nonce is in the box).
 * @param {{ cipherHex: string, roomKeys: Array<{ key: string, name?: string }> }} opts
 * @returns {object|false} the payload plus `roomKey` and `roomName`
 */
function openRoomPush({ cipherHex, roomKeys } = {}) {
  if (typeof cipherHex !== 'string' || !isHex(cipherHex)) return false
  const all = b4a.from(cipherHex, 'hex')
  const NB = sodium.crypto_secretbox_NONCEBYTES
  if (all.byteLength <= NB + sodium.crypto_secretbox_MACBYTES) return false
  const nonce = all.subarray(0, NB)
  const cipher = all.subarray(NB)
  for (const room of roomKeys || []) {
    if (!room || typeof room.key !== 'string' || !isHex(room.key.substring(0, 64), 64)) continue
    const key = b4a.from(room.key.substring(0, 64), 'hex')
    const plain = b4a.alloc(cipher.byteLength - sodium.crypto_secretbox_MACBYTES)
    if (!sodium.crypto_secretbox_open_easy(plain, cipher, nonce, key)) continue
    try {
      const parsed = JSON.parse(b4a.toString(plain, 'utf8'))
      parsed.roomKey = room.key
      parsed.roomName = room.name
      return parsed
    } catch {
      continue
    }
  }
  return false
}

module.exports = {
  PacketError,
  POST_KINDS,
  syncRequest,
  jobRequest,
  postMessage,
  postPacket,
  registerPacket,
  encodePacket,
  parseNodePacket,
  nodeResult,
  nodeMessage,
  nodeMessages,
  syncMessages,
  cnFastHash,
  cnFastHashHex,
  weekNumber,
  dmViewTag,
  roomViewTag,
  nonceFromTimestamp,
  roomPushKey,
  roomPushPayload,
  roomPushBox,
  sealToPushServer,
  sealRoomPush,
  sealRegistration,
  openPushEnvelope,
  openRoomPush
}
