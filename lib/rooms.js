'use strict'

// All room and DM swarms of one Hugin identity (the future `p2p.rooms`): join and leave, send,
// typing, bans, and the mobile lifecycle (suspend / resume / idle). Each swarm is a Room
// (lib/room.js); voice state is shared across rooms (lib/voice.js, one voice channel at a time).
//
// Events leave through `emit(name, payload)` (the facade passes its own); without one, Rooms
// emits them itself (it is a bare-events EventEmitter). Event names: lib/events.js.
//
// Host hooks used here (README "Host hooks and events"): identity, sign, verify, roomMessageExists,
// getRoomHistory, getRoomMessage, getLatestRoomHashes, isBanned, isBlocked, log. Every value
// handed to a hook is validated first (hashes are 64 hex characters, room keys 128 hex
// characters), because hosts build storage queries from them.
//
// Room messages are signed by the sender's XKR key (hugin-network 3.0,
// `wire.roomMessageSigningPayload`) and their hash is derived from their content
// (`wire.roomMessageHash`): `send` derives the hash and signs through `host.sign` (the
// identity's address must be the signer's), and every received room message, live or from
// history, must carry the derived hash and is verified through `host.verify` (awaited) before it
// is emitted (lib/room.js). Hosts store the `signature` with the message and hand it back from
// `getRoomHistory` / `getRoomMessage`: rows without one (or whose hash is not the derived one)
// are not sent to peers.
//
// With `sharedDht: true` every room and DM swarm of this Rooms runs on one SharedMidDHT
// (lib/swarm.js) instead of a DHT node each: each swarm keeps its own random DHT key pair and
// Hugin identity on it, leaving a room closes only that room's swarm, `suspend` / `resume`
// suspend and resume the DHT once after / before every swarm, and `destroy` destroys it once,
// after every room is closed.
//
// No module-level state, no process signal handlers: runs under Node and Bare.

const EventEmitter = require('bare-events')
const b4a = require('b4a')
const { createHuginSwarm, SharedMidDHT } = require('./swarm.js')
const keys = require('./keys.js')
const wire = require('./wire.js')
const S = require('./sanitize.js')
const { isHex } = require('./bytes.js')
const { Room, DEFAULTS: ROOM_DEFAULTS, VERIFY, within } = require('./room.js')
const { Voice } = require('./voice.js')
const E = require('./events.js')
const { MAX_PING_HASHES, XKR_ADDRESS_LENGTH } = require('./constants.js')

const DEFAULTS = Object.freeze({
  ...ROOM_DEFAULTS,
  /** desktop: 100 connections per room swarm (DM swarms always 1) */
  roomMaxPeers: 100,
  /** native `idle`: in the background, connections are suspended after 10 s */
  idleSuspendMs: 10000,
  /** native `idle`: back in the foreground, discovery is refreshed unless a message came this recently */
  activityGraceMs: 2000
})

/** Stand in for the signature and the hash while the other fields of a room message are checked. */
const UNSIGNED = '0'.repeat(128)
const UNHASHED = '0'.repeat(64)

class RoomsError extends Error {
  constructor(message, code) {
    super(message)
    this.name = 'RoomsError'
    this.code = code
  }
}

function noop() {}

/** An identity every builder takes (see Rooms#identity). */
function normalizeIdentity(id) {
  return {
    ...id,
    address: typeof id.address === 'string' ? id.address : '',
    name: S.clampText(id.name, S.SEND.joined.name),
    avatar: S.sendableAvatar(id.avatar, S.SEND.joined.avatarBytes)
  }
}

class Rooms extends EventEmitter {
  /**
   * @param {object} [opts]
   * @param {object} [opts.host]  host hooks (README "Host hooks and events"); `sign` and `verify` are required
   *   for any connection to be admitted
   * @param {(level: string, msg: string, data?: object) => void} [opts.log]  default `host.log`
   * @param {(name: string, payload: object) => void} [opts.emit]  where events go (default: this)
   * @param {import('./files.js').Files} [opts.files]  drives per room; null for none
   * @param {object} [opts.feed]  the feed module (lib/feed.js `Feed`); may be set later (`rooms.feed`)
   * @param {Voice} [opts.voice]  shared voice state (created when not given)
   * @param {Array<{host, port}>} [opts.bootstrap]  DHT bootstrap (tests: a testnet)
   * @param {number} [opts.roomMaxPeers]  connections per room swarm (default 100)
   * @param {Function} [opts.createSwarm]  replaces `createHuginSwarm` (tests)
   * @param {boolean} [opts.sharedDht]  true: every swarm runs on one shared DHT (default false:
   *   one DHT node per swarm)
   * Timings (`pingIntervalMs`, `roomJoinTimeoutMs`, `dmJoinTimeoutMs`, `leaveFlushMs`,
   * `closeTimeoutMs`, `adminBanDelayMs`, `banLeaveDelayMs`, `idleSuspendMs`, ...) and limits
   * (`maxQueuedFrames`, `maxPreJoinFrames`, `historyMax`, `dialMaxPerPing`, ...) can be
   * overridden, see DEFAULTS here and in lib/room.js.
   */
  constructor(opts = {}) {
    super()
    this.host = opts.host || {}
    const options = {}
    for (const k of Object.keys(DEFAULTS)) {
      const v = opts[k]
      options[k] = typeof v === 'number' && Number.isFinite(v) && v >= 0 ? v : DEFAULTS[k]
    }
    this.options = options
    this._logHook = typeof opts.log === 'function' ? opts.log : typeof this.host.log === 'function' ? this.host.log : null
    this._emitHook = typeof opts.emit === 'function' ? opts.emit : null
    this.files = opts.files || null
    this.feed = opts.feed || null
    this.voice = opts.voice || new Voice({ host: this.host, rooms: this })
    if (!this.voice.rooms) this.voice.rooms = this
    this.bootstrap = opts.bootstrap || null
    this._createSwarm = typeof opts.createSwarm === 'function' ? opts.createSwarm : createHuginSwarm
    /** One DHT for every swarm (created with the first swarm), or one DHT node per swarm. */
    this.sharedDht = opts.sharedDht === true
    /** @type {SharedMidDHT | null} */
    this.dht = null

    this._rooms = new Map() // topic -> Room
    this._opening = new Map() // topic -> Promise
    this._closingRooms = new Map() // topic -> Promise of Room#close (leave)
    this._identityOverride = null
    this._timers = new Set()
    this._idleTimer = null
    this._lastActivity = 0

    /** Connections closed and swarms suspended (mobile background). */
    this.suspended = false
    /** The app is in the background: Ping is skipped. */
    this.idleState = false
    this.destroyed = false

    // host hooks handed to keys.signIdSig / verifyIdSig
    this._sign = (message) => {
      if (typeof this.host.sign !== 'function') throw new RoomsError('host.sign is required', 'HUGIN_ROOMS_HOST')
      return this.host.sign(message)
    }
    this._verify = (message, address, signature) => {
      if (typeof this.host.verify !== 'function') return false
      return this.host.verify(message, address, signature)
    }
  }

  // -------------------------------------------------------------------------------------------
  // identity

  /**
   * `{ address, name, avatar }`: `setIdentity` values over `host.identity()`, normalised so that
   * every message builder takes them: the name is cut to 50 characters (on a code point
   * boundary), an avatar that is not well-formed base64 of at most 200 000 bytes becomes '', a
   * non-string address ''.
   */
  identity() {
    const fn = this.host.identity
    let base = null
    try {
      base = typeof fn === 'function' ? fn() : fn
    } catch (err) {
      this._log('warn', 'host.identity failed', { message: err && err.message })
    }
    if (!base || typeof base !== 'object') base = {}
    return normalizeIdentity({ address: '', name: '', avatar: '', ...base, ...(this._identityOverride || {}) })
  }

  /** Overrides identity fields (native `update_bare_user`); later `joined` messages use them. */
  setIdentity({ address, name, avatar } = {}) {
    const next = { ...(this._identityOverride || {}) }
    if (address !== undefined) next.address = typeof address === 'string' ? address : ''
    if (name !== undefined) next.name = S.clampText(name, S.SEND.joined.name)
    if (avatar !== undefined) next.avatar = S.sendableAvatar(avatar, S.SEND.joined.avatarBytes)
    this._identityOverride = next
  }

  // -------------------------------------------------------------------------------------------
  // join / leave

  /**
   * Joins a room. `adminSeed` (64 hex, from `keys.createRoomInvite`) makes us the room admin
   * when its key is the one in the invite; any other seed is ignored.
   * @returns {Promise<{ key, topic, dm: false, admin }>}
   */
  async join({ invite, adminSeed } = {}) {
    if (!keys.isRoomInvite(invite)) throw new RoomsError('invite must be 128 hex characters', 'HUGIN_ROOMS_INVALID')
    const swarmKey = keys.roomSwarmKey(invite)
    const topic = keys.topicFromSwarmKey(swarmKey).topic
    let seed = null
    if (typeof adminSeed === 'string' && adminSeed.length > 0) {
      const fromInvite = keys.adminPublicKeyFromInvite(invite)
      if (fromInvite && b4a.equals(keys.adminKeyPair(adminSeed).publicKey, fromInvite)) seed = adminSeed
      else this._log('warn', 'admin seed does not match the invite; joining without admin rights')
    }
    return this._open({ key: invite, dm: false, swarmKey, topic, adminSeed: seed })
  }

  /**
   * Joins the DM swarm with a contact. `derivationHash` is the host's key derivation hash
   * (hex; it needs the private view key). Only `address` (its first 99 characters, as desktop
   * reads the chat id) is admitted in this swarm.
   * @returns {Promise<{ key, topic, dm: true, admin: false, address }>}
   */
  async joinDm({ address, derivationHash } = {}) {
    if (typeof address !== 'string' || address.length < XKR_ADDRESS_LENGTH) {
      throw new RoomsError('address must be an XKR address', 'HUGIN_ROOMS_INVALID')
    }
    if (!isHex(derivationHash) || derivationHash.length === 0) {
      throw new RoomsError('derivationHash must be hex', 'HUGIN_ROOMS_INVALID')
    }
    const contact = address.slice(0, XKR_ADDRESS_LENGTH)
    const swarmKey = keys.dmSwarmKey(derivationHash)
    const topic = keys.topicFromSwarmKey(swarmKey).topic
    return this._open({ key: contact, dm: true, contact, swarmKey, topic })
  }

  async _open(spec) {
    if (this.destroyed) throw new RoomsError('destroyed', 'HUGIN_ROOMS_DESTROYED')
    const existing = this._rooms.get(spec.topic)
    if (existing && !existing.closed) return existing.summary()
    if (this._opening.has(spec.topic)) return this._opening.get(spec.topic)

    const opening = (async () => {
      // the same room being left: its swarm and drive are closed first (bounded by Room#close)
      const closing = this._closingRooms.get(spec.topic)
      if (closing) await closing.catch(noop)
      if (this.destroyed) throw new RoomsError('destroyed', 'HUGIN_ROOMS_DESTROYED')
      const room = new Room(this, spec)
      this._rooms.set(room.topic, room)
      try {
        await room.open()
        if (this.destroyed) throw new RoomsError('destroyed', 'HUGIN_ROOMS_DESTROYED')
        if (this.suspended) await room.suspend()
        // left while joining: no room:joined for a room that is gone
        if (room.closed) throw new RoomsError('left while joining', 'HUGIN_ROOMS_LEFT')
      } catch (err) {
        const left = room.closed && !this.destroyed
        if (this._rooms.get(room.topic) === room) this._rooms.delete(room.topic)
        await room.close({ notify: false }).catch(noop)
        if (left && !(err instanceof RoomsError)) throw new RoomsError('left while joining', 'HUGIN_ROOMS_LEFT')
        throw err
      }
      room._announced = true
      this._log('info', 'joined swarm', { dm: room.dm })
      this._event(E.ROOM_JOINED, room.summary())
      return room.summary()
    })()
    this._opening.set(spec.topic, opening)
    try {
      return await opening
    } finally {
      this._opening.delete(spec.topic)
    }
  }

  /**
   * Leaves a room or DM swarm (by key, topic or contact address): our voice state there goes
   * offline, every connection gets `disconnected` (`peer:left` for each joined address), the
   * swarm is destroyed and the room's drive closed (each step bounded by `closeTimeoutMs`), then
   * `room:left` (only for a room whose `room:joined` went out; a room left while it was still
   * joining makes `join` reject with HUGIN_ROOMS_LEFT instead). A join of the same room waits
   * for this. Returns false when there is no such room.
   */
  async leave(keyOrAddress) {
    const room = this._find(keyOrAddress)
    if (!room) return false
    if (this._rooms.get(room.topic) === room) this._rooms.delete(room.topic)
    this.voice.onRoomLeft(room)
    const closing = room.close({ notify: true })
    this._closingRooms.set(room.topic, closing)
    try {
      await closing
    } finally {
      if (this._closingRooms.get(room.topic) === closing) this._closingRooms.delete(room.topic)
    }
    if (room._announced) this._event(E.ROOM_LEFT, { key: room.key, topic: room.topic, dm: room.dm })
    return true
  }

  // -------------------------------------------------------------------------------------------
  // lookups

  /** The Room for a room key, topic or DM contact address, or null. */
  get(keyOrTopicOrAddress) {
    if (typeof keyOrTopicOrAddress !== 'string' || keyOrTopicOrAddress.length === 0) return null
    const byTopic = this._rooms.get(keyOrTopicOrAddress)
    if (byTopic) return byTopic
    for (const room of this._rooms.values()) if (room.key === keyOrTopicOrAddress) return room
    return null
  }

  /** Every open Room. */
  all() {
    return [...this._rooms.values()]
  }

  /** `[{ key, topic, dm, admin, peers }]` (`peers`: joined peers). */
  list() {
    return this.all().map((room) => ({ ...room.summary(), peers: room.joinedPeers().length }))
  }

  /** True when a verified peer with `address` is connected in the room. */
  isPeerIn(key, address) {
    const room = this.get(key)
    return !!room && room.joinedPeers().some((p) => p.address === address)
  }

  /**
   * Joined peers across rooms. `dm: false` only room swarms (the feed's peers), `dm: true`
   * only DM swarms, omitted: all.
   */
  joinedPeers({ dm } = {}) {
    const out = []
    for (const room of this._rooms.values()) {
      if (dm === true && !room.dm) continue
      if (dm === false && room.dm) continue
      for (const peer of room.joinedPeers()) out.push(peer)
    }
    return out
  }

  // -------------------------------------------------------------------------------------------
  // sending

  /**
   * Signs a room message (`host.sign` over `wire.roomMessageSigningPayload`, by the identity's
   * address), sends it to the joined peers of the room and resolves with the wire object, which
   * the host stores as sent, `signature` included (it serves it to peers in history later).
   * `timestamp` (integer ms) defaults to now. The hash is derived from the message
   * (`wire.roomMessageHash`); a `hash` option is accepted only when it is that value (either
   * case), else the call rejects with a WireError (field `hash`). Rejects with a
   * WireError for a message that does not fit the send limits, a RoomsError
   * `HUGIN_ROOMS_UNKNOWN` for an unknown room (also when it was left while signing) and a
   * RoomsError `HUGIN_ROOMS_SIGN` when the host could not sign it (no `host.sign`, it threw, or
   * its answer is not a 128-hex signature). Nothing is sent when it rejects.
   * @returns {Promise<object>}
   */
  async send(key, { hash, message, reply = '', tip = false, timestamp } = {}) {
    const room = this.get(key)
    if (!room || room.dm) throw new RoomsError('not in this room', 'HUGIN_ROOMS_UNKNOWN')
    const id = this.identity()
    // every field is checked before anything is signed (hash and signature are placeholders)
    const checked = wire.roomMessage({
      hash: UNHASHED,
      room: room.key,
      address: id.address,
      message,
      name: id.name,
      reply,
      signature: UNSIGNED,
      timestamp: timestamp === undefined || timestamp === null ? Date.now() : timestamp,
      tip
    })
    const derived = wire.roomMessageHash(checked)
    if (hash !== undefined && hash !== null && (typeof hash !== 'string' || hash.toLowerCase() !== derived)) {
      throw new wire.WireError('hash: must be wire.roomMessageHash of the message', 'hash')
    }
    const draft = { ...checked, hash: derived }
    let signature
    try {
      signature = await this._sign(wire.roomMessageSigningPayload(draft))
    } catch (err) {
      throw new RoomsError('room message not signed: ' + ((err && err.message) || 'host.sign failed'), 'HUGIN_ROOMS_SIGN')
    }
    if (!S.isRoomSignature(signature)) throw new RoomsError('room message not signed: host.sign must return 128 hex characters', 'HUGIN_ROOMS_SIGN')
    if (room.closed || this.get(key) !== room) throw new RoomsError('not in this room', 'HUGIN_ROOMS_UNKNOWN')
    const msg = wire.roomMessage({ ...draft, signature })
    room.send(wire.encode(msg))
    return msg
  }

  /** Sends a DM payload (hugin-crypto `encodeExtra` hex) to the contact; returns the peers written to. */
  sendDm(address, wireString) {
    const room = this._dm(address)
    if (!room || typeof wireString !== 'string' || wireString.length === 0) return 0
    return room.send(wireString)
  }

  /** Typing indicator to a room or DM; returns the peers written to. */
  typing(keyOrAddress, typing) {
    const room = this._find(keyOrAddress)
    if (!room) return 0
    return room.send(wire.encode(wire.typing(typing === true)))
  }

  /**
   * Stores a file in the room's drive (lib/files.js `share`) and announces it (`file-shared`) to
   * the joined peers of the room or DM. Returns `{ announcement, sent }`. Throws what
   * `Files#share` throws, or a RoomsError without a Files instance or room.
   * @param {string} keyOrAddress
   * @param {string|Uint8Array} source  file path or bytes
   * @param {object} [meta]  `fileName`, `time`, `hash`, ... (see `Files#share`)
   */
  async shareFile(keyOrAddress, source, meta = {}) {
    const room = this._find(keyOrAddress)
    if (!room) throw new RoomsError('not in this room', 'HUGIN_ROOMS_UNKNOWN')
    if (!this.files || typeof this.files.share !== 'function') throw new RoomsError('no file storage', 'HUGIN_ROOMS_NO_FILES')
    const id = this.identity()
    const announcement = await this.files.share(room.topic, source, { address: id.address, name: id.name, ...meta })
    const sent = room.send(wire.encode(announcement))
    return { announcement, sent }
  }

  /**
   * Bans an address in a room: as admin a broadcast every peer honours, then locally (its
   * connections closed, `ban:peer` for the host to persist). Returns false for an unknown room.
   */
  async ban(key, address) {
    const room = this.get(key)
    if (!room) return false
    return room.ban(address)
  }

  /** `get`, or the DM swarm of a longer chat id that starts with the contact address. */
  _find(keyOrAddress) {
    return this.get(keyOrAddress) || this._dm(keyOrAddress)
  }

  _dm(address) {
    if (typeof address !== 'string') return null
    const contact = address.slice(0, XKR_ADDRESS_LENGTH)
    for (const room of this._rooms.values()) if (room.dm && room.contact === contact) return room
    return null
  }

  // -------------------------------------------------------------------------------------------
  // lifecycle (mobile host; desktop never calls these)

  /** Closes every connection and suspends every swarm. */
  async suspend() {
    if (this.destroyed || this.suspended) return
    this.suspended = true
    await Promise.all(this.all().map((room) => room.suspend()))
    // the shared DHT after its swarms (a swarm's own suspend leaves it running)
    if (this.dht && !this.destroyed && this.suspended) {
      await this._bounded(Promise.resolve().then(() => this.dht.suspendShared()))
    }
  }

  /** Resumes every swarm and refreshes discovery. */
  async resume() {
    if (this.destroyed || !this.suspended) return
    this.suspended = false
    // the shared DHT before its swarms
    if (this.dht) await this._bounded(Promise.resolve().then(() => this.dht.resumeShared()))
    await Promise.all(this.all().map((room) => room.resume()))
  }

  /**
   * Native `idle(background, force)`: `force` suspends at once; `background` marks the app idle
   * (Ping is skipped) and suspends after `idleSuspendMs`; back in the foreground the swarms are
   * resumed, or, when they were not suspended and no message came in the last
   * `activityGraceMs`, discovery is refreshed.
   */
  async idle({ background = false, force = false } = {}) {
    if (this.destroyed) return
    if (force) {
      this._clearIdleTimer()
      this.idleState = true
      await this.suspend()
      return
    }
    if (background) {
      this.idleState = true
      if (this._idleTimer || this.suspended) return
      this._idleTimer = setTimeout(() => {
        this._idleTimer = null
        if (this.idleState) this.suspend().catch(noop)
      }, this.options.idleSuspendMs)
      return
    }
    this.idleState = false
    this._clearIdleTimer()
    if (this.suspended) {
      await this.resume()
      return
    }
    if (Date.now() - this._lastActivity < this.options.activityGraceMs) return
    for (const room of this.all()) room.refresh()
  }

  _clearIdleTimer() {
    if (this._idleTimer) clearTimeout(this._idleTimer)
    this._idleTimer = null
  }

  /** Leaves every swarm without notifying peers and stops all timers. */
  async destroy() {
    if (this.destroyed) return
    this.destroyed = true
    this._clearIdleTimer()
    for (const t of this._timers) clearTimeout(t)
    this._timers.clear()
    this.voice.destroy()
    const rooms = this.all()
    this._rooms.clear()
    // every wait is bounded: a hanging open, swarm or drive never stops destroy
    const ms = this.options.closeTimeoutMs
    const bounded = (p) => (ms > 0 ? within(p, ms, undefined) : p)
    await bounded(Promise.all([...this._opening.values()].map((p) => p.catch(noop))))
    await Promise.all(rooms.map((room) => room.close({ notify: false }).catch(noop)))
    await bounded(Promise.all([...this._closingRooms.values()].map((p) => p.catch(noop))))
    // the shared DHT last, once, after every swarm on it is closed
    if (this.dht) {
      const dht = this.dht
      await bounded(dht.destroyShared().catch((err) => this._log('warn', 'shared DHT not destroyed cleanly', { message: err && err.message })))
    }
  }

  /**
   * The shared DHT of `sharedDht: true` (created on first use with `bootstrap`), or null for one
   * DHT node per swarm.
   */
  _swarmDht() {
    if (!this.sharedDht) return null
    if (this.destroyed) throw new RoomsError('destroyed', 'HUGIN_ROOMS_DESTROYED')
    if (!this.dht) {
      const opts = {}
      if (this.bootstrap) opts.bootstrap = this.bootstrap
      this.dht = new SharedMidDHT(opts)
    }
    return this.dht
  }

  /** `promise` bounded by `closeTimeoutMs` (never rejects). */
  _bounded(promise) {
    const ms = this.options.closeTimeoutMs
    const safe = Promise.resolve(promise).catch((err) => this._log('debug', 'shared DHT step failed', { message: err && err.message }))
    return ms > 0 ? within(safe, ms, undefined) : safe
  }

  // -------------------------------------------------------------------------------------------
  // host hooks (validated arguments; a failing hook never reaches a connection handler)

  /**
   * True when the host has the message. An invalid hash counts as stored (never requested); a
   * failing hook gives `onError` (default true: not requested, not taken).
   */
  async _messageExists(hash, onError = true) {
    if (!S.isHex64(hash)) return true
    const fn = this.host.roomMessageExists
    if (typeof fn !== 'function') return false
    try {
      return !!(await fn(hash))
    } catch {
      return onError
    }
  }

  /**
   * Checks a validated room message: its hash must be the one derived from it
   * (`wire.roomMessageHash`, else BAD), and its signature must verify,
   * `host.verify(payload, address, signature)`, awaited, exactly `true`. Never throws.
   * @returns {Promise<string>} one of VERIFY
   */
  async _verifyRoomMessage(m) {
    let payload
    try {
      if (!S.isRoomSignature(m.signature)) return VERIFY.INVALID
      payload = wire.roomMessageSigningPayload(m)
    } catch {
      return VERIFY.INVALID
    }
    if (!wire.isRoomMessageHash(m)) return VERIFY.BAD
    const fn = this.host.verify
    if (typeof fn !== 'function') {
      this._log('warn', 'room message dropped: no host.verify')
      return VERIFY.ERROR
    }
    try {
      return (await fn(payload, m.address, m.signature)) === true ? VERIFY.OK : VERIFY.BAD
    } catch (err) {
      this._log('warn', 'room message signature check failed', { message: err && err.message })
      return VERIFY.ERROR
    }
  }

  async _getMessage(hash) {
    if (!S.isHex64(hash)) return null
    const fn = this.host.getRoomMessage
    if (typeof fn !== 'function') return null
    try {
      const m = await fn(hash)
      return m && typeof m === 'object' && !Array.isArray(m) ? m : null
    } catch {
      return null
    }
  }

  async _roomHistory(key) {
    if (!keys.isRoomInvite(key)) return []
    const fn = this.host.getRoomHistory
    if (typeof fn !== 'function') return []
    try {
      const list = await fn(key)
      return Array.isArray(list) ? list.filter((m) => m && typeof m === 'object') : []
    } catch {
      return []
    }
  }

  async _latestHashes(key) {
    if (!keys.isRoomInvite(key)) return []
    const fn = this.host.getLatestRoomHashes
    if (typeof fn !== 'function') return []
    try {
      const list = await fn(key)
      return Array.isArray(list) ? list.filter(S.isHex64).slice(0, MAX_PING_HASHES) : []
    } catch {
      return []
    }
  }

  async _isBanned(address, topic) {
    if (typeof address !== 'string' || address.length === 0) return false
    const fn = this.host.isBanned
    if (typeof fn !== 'function') return false
    try {
      return !!(await fn(address, topic))
    } catch {
      return false
    }
  }

  async _isBlocked(address) {
    if (typeof address !== 'string' || address.length === 0) return false
    const fn = this.host.isBlocked
    if (typeof fn !== 'function') return false
    try {
      return !!(await fn(address))
    } catch {
      return false
    }
  }

  // -------------------------------------------------------------------------------------------
  // internals

  _eventHook() {
    return this._emitHook || ((name, payload) => this.emit(name, payload))
  }

  _event(name, payload) {
    try {
      this._eventHook()(name, payload)
    } catch (err) {
      this._log('warn', 'event handler failed', { event: name, message: err && err.message })
    }
  }

  _touch() {
    this._lastActivity = Date.now()
  }

  /** A timer that `destroy()` cancels. */
  _later(ms, fn) {
    if (this.destroyed) return
    const t = setTimeout(() => {
      this._timers.delete(t)
      if (this.destroyed) return
      try {
        const r = fn()
        if (r && typeof r.catch === 'function') r.catch(noop)
      } catch {}
    }, Math.max(0, ms))
    this._timers.add(t)
  }

  _log(level, msg, data) {
    if (!this._logHook) return
    try {
      this._logHook(level, msg, data)
    } catch {}
  }
}

module.exports = {
  Rooms,
  RoomsError,
  DEFAULTS,
  VERIFY
}
