'use strict'

// One Hugin swarm: a room (keyed by its invite) or a DM (keyed by the contact's address).
// Extracted from hugin-native `bare/swarm.js` (Room, create_swarm, new_connection,
// check_data_message, check_joined_message, check_if_online, ...), the reference behaviour,
// with hugin-desktop `src/backend/swarm.cjs` additions.
//
// Per connection (lib/peer.js):
//   1. the `hugin/3/messages` channel is opened (lib/channel.js) and the room's corestore
//      replicates on the same stream (lib/files.js);
//   2. we send `joined`: our address, name, avatar, voice fields, recent room history, drive key,
//      the admin signature of our DHT key when we hold the admin seed, and `idSig` (our XKR
//      address signs our DHT key and the swarm topic, `keys.idSigMessage`, `host.sign`; signed
//      once per swarm, the key is fixed). When our identity does not fit the builder (it should
//      not: Rooms#identity normalises it), a minimal `joined` without name, avatar and history
//      goes out instead;
//   3. the peer's `joined` is checked: `idSig` must verify for the connection's remote key and
//      this swarm's topic (`host.verify`, awaited), else the connection is closed and its key
//      banned in this swarm. In a DM swarm the verified address must be the contact's, else the connection is closed
//      and its key denied by the swarm's firewall from then on. The admin flag is the invite's
//      admin key signing the remote key;
//   4. only then is anything else the peer sends acted on. Frames that arrive before its
//      `joined` are dropped; frames behind a `joined` wait for its check (at most
//      `maxPreJoinFrames` of them, for at most the join timeout). A connection that has not
//      joined after `roomJoinTimeoutMs` / `dmJoinTimeoutMs` is closed.
//
// The frames of one connection are handled one at a time, in order (a promise chain per peer,
// at most `maxQueuedFrames` waiting; a peer that sends more is closed). Frames that arrived
// before the connection closed are still handled (unless the peer was closed for misbehaving),
// and `peer:left` follows them.
//
// Several connections may share one address in a room (a user's phone and desktop):
// `peer:joined` is emitted for the first connection of an address and `peer:left` when its
// last one has closed. A DM swarm keeps one connection to the contact: a second one is closed
// unless the first is no longer writable.
//
// Rooms also run the state sync (Ping every 10 s with the latest hashes, request-messages /
// missing-messages for the hashes we asked for), history for late joiners (request-history
// once, to a peer picked at random among those that joined before us; answered once per
// connection), typing, admin bans, file announcements (lib/files.js) and hand feed traffic to
// the feed module (lib/feed.js).
// DM swarms carry DM payloads, typing and file announcements.
//
// Room messages are signed by their author's XKR key (hugin-network 3.0,
// `wire.roomMessageSigningPayload`). Every received one (live, `joined.messages`,
// `missing-messages`) is checked with `host.verify` (awaited, must be `true`) before
// `room:message` is emitted, after the cheaper checks (room, author, hash, clock) and the host's
// `roomMessageExists` (a stored message is not verified again). A live message whose signature
// does not verify gets its sender banned in the swarm (the sender is its author); a history
// entry that does not verify is dropped, and a connection that relayed more than `maxBadHistory`
// of them is banned. A history batch is verified `verifyConcurrency` entries at a time; one
// connection's frames are handled one at a time, so that bounds the checks per connection.
// `send-history` messages are not taken (only its files are), as in both apps.
//
// Values from peers are validated (lib/wire.js decode, lib/sanitize.js) before they reach a
// host hook or an event. What a peer can make us do is bounded: history entries handled per
// batch, request-messages, Ping lookups, file announcements and dials of the peers a Ping lists
// are rate-limited (see DEFAULTS; counts of 0 allow nothing, durations of 0 turn a timeout off).

const b4a = require('b4a')
const wire = require('./wire.js')
const S = require('./sanitize.js')
const keys = require('./keys.js')
const { openHuginChannel } = require('./channel.js')
const { Peer, newRateState, takeRate, canTakeRate } = require('./peer.js')
const { randomInt } = require('./bytes.js')
const { FEED_RESULT } = require('./feed.js')
const E = require('./events.js')
const { PING_INTERVAL_MS, MAX_PING_HASHES, MAX_PING_PEERS, ONE_DAY_MS, FILE_SHARED } = require('./constants.js')

const DEFAULTS = Object.freeze({
  pingIntervalMs: PING_INTERVAL_MS,
  /**
   * Frames behind a `joined` wait for its check at most the join timeout of the swarm; this
   * bound is used only where that timeout is 0 (off).
   */
  joinWaitMs: 5000,
  /** desktop DM_JOIN_TIMEOUT_MS: a DM connection that has not joined by then is closed */
  dmJoinTimeoutMs: 30000,
  /** a room connection that has not joined by then is closed */
  roomJoinTimeoutMs: 30000,
  /** native: history is requested from at most one earlier peer per room */
  historyRequests: 1,
  /**
   * history is requested from a peer picked at random among the joined peers that started
   * before us, this long after the first of them joined (0: at once, from the first)
   */
  historyPickMs: 2000,
  /** native: a peer's Ping files older than a day are not offered */
  fileMaxAgeMs: ONE_DAY_MS,
  /** native/desktop: pause before leaving a room after the admin banned us */
  banLeaveDelayMs: 777,
  /** desktop: pause between the admin ban broadcast and the local ban */
  adminBanDelayMs: 200,
  /** desktop: pause between `disconnected` and closing the connections when leaving */
  leaveFlushMs: 200,
  /** every step of closing a room (and of Rooms#destroy) waits at most this long */
  closeTimeoutMs: 5000,
  /** remote keys kept on a room's deny list */
  maxDenied: 4096,
  /** addresses kept on a room's session ban list (the host persists bans too) */
  maxBannedAddresses: 4096,
  /** frames of one connection waiting to be handled; more closes the connection */
  maxQueuedFrames: 256,
  /** frames behind a `joined` that is still being checked; more are dropped */
  maxPreJoinFrames: 32,
  /** room messages handled per history batch (joined.messages, missing-messages) and sent per answer */
  historyMax: 50,
  /** signature checks (`host.verify`) of one history batch running at the same time */
  verifyConcurrency: 4,
  /** history entries with a bad signature one connection may relay; one more bans it */
  maxBadHistory: 3,
  /** room messages timestamped later than now + this are dropped (the timestamp is signed, so it is not clamped) */
  maxClockSkewMs: 5 * 60 * 1000,
  /** request-history answers per room and minute (each connection is answered once) */
  historyAnswersPerMinute: 30,
  /** request-messages answered per connection and minute */
  requestMessagesPerMinute: 30,
  /** Pings per connection and minute that may cause host lookups (stored? / listed files) */
  pingLookupsPerMinute: 12,
  /** file announcements per connection and minute handed to Files */
  fileAnnouncementsPerMinute: 30,
  /** new keys dialed from one Ping (native `find_missing_peers`) */
  dialMaxPerPing: 8,
  /** keys dialed per minute because of one connection's Pings */
  dialMaxPerPeerPerMinute: 8,
  /** keys dialed per room and minute */
  dialMaxPerMinute: 16,
  /** dials in progress per room (each explicit peer lowers Hyperswarm's connection budget) */
  maxPendingDials: 3,
  /** a dial that has not connected by then is given up (`leavePeer`); 0: only a connection ends it */
  dialTimeoutMs: 30000
})

/** Result of a room message signature check (`Rooms#_verifyRoomMessage`). */
const VERIFY = Object.freeze({
  OK: 'ok', // the signature verifies for the message's address
  BAD: 'bad', // it does not (the sender's or the relayer's fault)
  INVALID: 'invalid', // no payload can be built (a value no valid message has)
  ERROR: 'error' // host.verify is missing or failed
})

/** Hashes per connection we remember having asked for (four request-messages). */
const MAX_REQUESTED_HASHES = 4 * MAX_PING_HASHES

function noop() {}

/** `fn` over `items`, at most `limit` at a time; resolves with the results in order. */
async function mapLimit(items, limit, fn) {
  const out = new Array(items.length)
  let next = 0
  const worker = async () => {
    while (next < items.length) {
      const i = next++
      out[i] = await fn(items[i], i)
    }
  }
  const n = Math.min(items.length, Math.max(1, Math.floor(limit) || 1))
  await Promise.all(Array.from({ length: n }, worker))
  return out
}

function hex(bytes) {
  return b4a.toString(bytes, 'hex')
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

/** Resolves with `promise`'s value, or `fallback` after `ms` (or when it rejects). */
function within(promise, ms, fallback) {
  let timer = null
  const timeout = new Promise((resolve) => {
    timer = setTimeout(() => resolve(fallback), ms)
  })
  return Promise.race([Promise.resolve(promise).catch(() => fallback), timeout]).finally(() => clearTimeout(timer))
}

function destroyConn(conn) {
  if (!conn || conn.destroyed) return
  try {
    if (typeof conn.end === 'function') conn.end()
  } catch {}
  try {
    conn.destroy()
  } catch {}
}

function isHealthy(conn) {
  return !!conn && !conn.destroyed && !conn.destroying && conn.writable !== false
}

/** The local DHT key of a connection (what `idSig` and the admin signature sign). */
function localKey(conn, fallback) {
  const k = conn && conn.publicKey
  if (k instanceof Uint8Array && k.byteLength === 32) return k
  return fallback || null
}

/** The file fields Ping / history lists carry (drive metadata may hold more). */
function fileEntry(meta) {
  const out = {}
  for (const k of ['fileName', 'hash', 'contentHash', 'size', 'time', 'address', 'name', 'topic', 'signature', 'info', 'type']) {
    if (meta[k] !== undefined) out[k] = meta[k]
  }
  return out
}

/** `wire.encode` of a message that carries a history list, without it when it does not fit. */
function encodeWithHistory(msg) {
  try {
    return wire.encode(msg)
  } catch (err) {
    if (err && err.field === 'size' && Array.isArray(msg.messages) && msg.messages.length) {
      return wire.encode({ ...msg, messages: [] })
    }
    throw err
  }
}

/** Adds to an insertion-ordered set, dropping the oldest entries above `max`. */
function boundedAdd(set, value, max) {
  set.delete(value)
  set.add(value)
  while (set.size > max) set.delete(set.values().next().value)
}

class Room {
  /**
   * Created by Rooms (`join` / `joinDm`); not meant to be constructed by hosts.
   * @param {import('./rooms.js').Rooms} rooms
   * @param {object} spec
   * @param {string} spec.key  room invite, or the contact address for a DM
   * @param {boolean} spec.dm
   * @param {Uint8Array} spec.swarmKey  SHA-512 of the invite / derivation hash
   * @param {string} spec.topic  hex of the topic base public key
   * @param {string} [spec.contact]  DM: the only address admitted
   * @param {string} [spec.adminSeed]  room admin seed (only kept when it matches the invite)
   */
  constructor(rooms, spec) {
    this.rooms = rooms
    this.key = spec.key
    this.dm = !!spec.dm
    this.topic = spec.topic
    this.contact = this.dm ? spec.contact : null
    this._swarmKey = spec.swarmKey
    this._adminSeed = !this.dm && spec.adminSeed ? spec.adminSeed : null
    /** We hold the room's admin seed (its key is the one in the invite). */
    this.admin = !!this._adminSeed

    /** remote public key hex -> Peer */
    this.peers = new Map()
    /** When our swarm started (ms); peers that started earlier are asked for history. */
    this.time = Date.now()

    this.swarm = null
    this.discovery = null
    this.discoveryKey = null
    this.keyPair = null
    this.driveKey = null

    /** Remote DHT keys refused by this swarm's firewall (banned peers, DM non-contacts). */
    this.denied = new Set()
    /** Addresses banned in this room during this session (the host persists bans too). */
    this.bannedAddresses = new Set()
    // the swarm's own base key is never a peer's key (lib/swarm.js refuses it in the handshake too)
    this.firewall = (remotePublicKey) => {
      const key = hex(remotePublicKey)
      return key === this.topic || this.denied.has(key)
    }

    this.requests = 0
    /** peers that started before us, candidates for the history request */
    this._historyCandidates = new Set()
    this._historyTimer = null
    /** Set by our Ping tick; a received Ping is only acted on while set (native `active.search`). */
    this.search = false
    this.closed = false
    this.suspended = false

    this._pingTimer = null
    this._pingCount = 0
    this._pinging = false
    this._closing = null
    /** set by Rooms once `room:joined` was emitted */
    this._announced = false

    /** address -> admitted Peers whose `peer:left` is not out yet */
    this._byAddress = new Map()
    /** peer drive key -> Map(address -> admitted connections of that address that announced it) */
    this._driveRefs = new Map()
    /** `peer:left` work of closed connections (Room#close and #suspend wait for it) */
    this._detaching = new Set()
    /** remote key hex -> timer of a dial started because a Ping listed the key */
    this._dials = new Map()
    this._dialRate = newRateState()
    this._historyRate = newRateState()
    /** { k, p }: our idSig and admin signature for the swarm's DHT key and our address */
    this._sigCache = null
  }

  get options() {
    return this.rooms.options
  }

  /** `{ key, topic, dm, admin[, address] }` as `room:joined` carries it. */
  summary() {
    const out = { key: this.key, topic: this.topic, dm: this.dm, admin: this.admin }
    if (this.dm) out.address = this.contact
    return out
  }

  // -------------------------------------------------------------------------------------------
  // lifecycle

  /** Opens the room's drive (when there is a Files instance) and joins the swarm. */
  async open() {
    const files = this.rooms.files
    if (files) {
      try {
        this.driveKey = await files.openRoom(this.topic, { key: this.key, dm: this.dm })
      } catch (err) {
        this._log('warn', 'room drive not opened', { message: err && err.message })
      }
    }
    if (this.closed) throw new Error('room closed while opening')

    const opts = {
      key: this._swarmKey,
      maxPeers: this.dm ? 1 : this.rooms.options.roomMaxPeers,
      firewall: this.firewall
    }
    const dht = this.rooms._swarmDht()
    if (dht) opts.dht = dht
    else if (this.rooms.bootstrap) opts.bootstrap = this.rooms.bootstrap
    const created = this.rooms._createSwarm(opts)
    this.swarm = created.swarm
    this.keyPair = created.keyPair || null
    this.discoveryKey = created.topic
    this.swarm.on('connection', (conn, info) => this._onconnection(conn, info))
    this.discovery = this.swarm.join(this.discoveryKey, { server: true, client: true })
    if (!this.dm) this._startPing()
  }

  /** Resolves once the first discovery round is announced (`discovery.flushed()`). */
  async flushed() {
    if (this.discovery && typeof this.discovery.flushed === 'function') await this.discovery.flushed()
  }

  /** Closes every connection and suspends the swarm (mobile background). */
  async suspend() {
    if (this.closed || this.suspended) return
    this.suspended = true
    this._endAllDials()
    for (const peer of [...this.peers.values()]) peer.close('suspend')
    await this._bounded(this._drained())
    if (this.swarm && typeof this.swarm.suspend === 'function') {
      await this._bounded(
        Promise.resolve()
          .then(() => this.swarm.suspend())
          .catch((err) => this._log('debug', 'swarm suspend failed', { message: err && err.message }))
      )
    }
  }

  /** Resumes the swarm and refreshes discovery. */
  async resume() {
    if (this.closed || !this.suspended) return
    this.suspended = false
    if (this.swarm && typeof this.swarm.resume === 'function') {
      await this._bounded(
        Promise.resolve()
          .then(() => this.swarm.resume())
          .catch((err) => this._log('debug', 'swarm resume failed', { message: err && err.message }))
      )
    }
    this.refresh()
  }

  /** Announces and looks up the topic again (native `discovery.refresh`). */
  refresh() {
    if (this.closed || this.suspended || !this.discovery || typeof this.discovery.refresh !== 'function') return
    try {
      const p = this.discovery.refresh({ client: true, server: true })
      if (p && typeof p.catch === 'function') p.catch(noop)
    } catch {}
  }

  /**
   * Leaves the swarm. With `notify`, every connection first gets `disconnected` through the
   * channel (so peers drop us at once) and a short pause lets it leave. `peer:left` of every
   * joined address is emitted before this resolves. Each step (peer:left work, discovery,
   * swarm leave and destroy, closing the drive) waits at most `closeTimeoutMs`.
   */
  close({ notify = true } = {}) {
    if (this._closing) return this._closing
    this.closed = true
    if (this._pingTimer) clearInterval(this._pingTimer)
    this._pingTimer = null
    if (this._historyTimer) clearTimeout(this._historyTimer)
    this._historyTimer = null
    this._historyCandidates.clear()
    this._endAllDials()
    this._closing = (async () => {
      const peers = [...this.peers.values()]
      if (notify && peers.length) {
        const bye = wire.encode(wire.disconnected())
        let sent = 0
        for (const peer of peers) if (peer.send(bye)) sent++
        if (sent && this.options.leaveFlushMs > 0) await sleep(this.options.leaveFlushMs)
      }
      for (const peer of [...this.peers.values()]) peer.close('leave')
      await this._bounded(this._drained())
      if (this.discovery && typeof this.discovery.destroy === 'function') {
        await this._bounded(Promise.resolve().then(() => this.discovery.destroy()))
      }
      if (this.swarm) {
        if (this.discoveryKey && typeof this.swarm.leave === 'function') {
          await this._bounded(Promise.resolve().then(() => this.swarm.leave(this.discoveryKey)))
        }
        await this._bounded(Promise.resolve().then(() => this.swarm.destroy()))
      }
      const files = this.rooms.files
      if (files && typeof files.closeRoom === 'function') {
        await this._bounded(Promise.resolve().then(() => files.closeRoom(this.topic)))
      }
    })()
    return this._closing
  }

  /** `promise` bounded by `closeTimeoutMs` (never rejects). */
  _bounded(promise) {
    const ms = this.options.closeTimeoutMs
    if (ms > 0) return within(promise, ms, undefined)
    return Promise.resolve(promise).catch(noop)
  }

  /** Resolves when the `peer:left` work of every closed connection is done. */
  _drained() {
    return Promise.all([...this._detaching])
  }

  // -------------------------------------------------------------------------------------------
  // peers and sending

  /** Peers whose `joined` was verified and that are still connected. */
  joinedPeers() {
    const out = []
    for (const peer of this.peers.values()) if (peer.joined && !peer.closed) out.push(peer)
    return out
  }

  /** The joined peer with this address (a writable one first), or null. */
  peerByAddress(address) {
    if (typeof address !== 'string') return null
    let found = null
    for (const peer of this.joinedPeers()) {
      if (peer.address !== address) continue
      if (peer.writable) return peer
      found = found || peer
    }
    return found
  }

  /** Writes a string to every joined peer; returns how many it was written to. */
  send(str) {
    if (typeof str !== 'string' || this.closed) return 0
    let n = 0
    for (const peer of this.joinedPeers()) if (peer.send(str)) n++
    return n
  }

  /**
   * Bans an address in this room: as admin, the ban is first broadcast to every peer (they
   * honour it because our admin signature verifies); then the address's connections are closed
   * and their keys denied, and `ban:peer` asks the host to persist it.
   */
  async ban(address) {
    if (this.dm || this.closed) return false
    if (typeof address !== 'string' || address.length === 0 || address.length > S.ACCEPT.ban.address) return false
    if (this.admin) {
      this._broadcastBan(address)
      if (this.options.adminBanDelayMs > 0) await sleep(this.options.adminBanDelayMs)
    }
    this._banAddress(address, this.admin)
    return true
  }

  /** Sends a Ping now (also runs every `pingIntervalMs`). Every Ping carries our latest hashes. */
  async ping() {
    if (this.dm || this.closed || this.suspended || this._pinging) return 0
    this._pinging = true
    try {
      const files = await this._recentFiles()
      const hashes = await this.rooms._latestHashes(this.key)
      if (this.closed) return 0
      this.search = true
      // peers and files on the first Ping and every tenth (native's intent)
      const full = this._pingCount % 10 === 0
      this._pingCount++
      const peers = full ? [...new Set(this.joinedPeers().map((p) => p.remotePublicKey))].filter(S.isHex64).slice(-MAX_PING_PEERS) : []
      let str
      try {
        str = wire.encode(wire.ping({ peers, files: full ? files : [], hashes }))
      } catch (err) {
        this._log('warn', 'ping not sent', { message: err && err.message })
        return 0
      }
      let n = 0
      for (const peer of this.joinedPeers()) if (peer.send(str)) n++
      return n
    } finally {
      this._pinging = false
    }
  }

  _startPing() {
    const ms = this.options.pingIntervalMs
    if (!(ms > 0)) return
    this._pingTimer = setInterval(() => {
      if (this.rooms.idleState) return // skipped while the app is in the background
      this.ping().catch((err) => this._log('warn', 'ping failed', { message: err && err.message }))
    }, ms)
    if (typeof this._pingTimer.unref === 'function') this._pingTimer.unref()
  }

  // -------------------------------------------------------------------------------------------
  // connections

  _onconnection(conn, info) {
    if (conn && typeof conn.on === 'function') conn.on('error', noop)
    if (this.closed || this.suspended || this.rooms.destroyed || !conn || !conn.remotePublicKey) {
      destroyConn(conn)
      return
    }
    const remote = hex(conn.remotePublicKey)
    // a key we dialed is connected: Hyperswarm no longer needs to keep it as an explicit peer
    this._endDial(remote)
    if (remote === this.topic || this.denied.has(remote)) {
      destroyConn(conn)
      return
    }

    // one connection per remote key: keep a joined, healthy one, else replace it (native)
    const existing = this.peers.get(remote)
    if (existing && existing.connection !== conn) {
      if (existing.joined && !existing.closed && isHealthy(existing.connection)) {
        destroyConn(conn)
        return
      }
      existing.close('duplicate')
    }

    const peer = new Peer({ room: this, connection: conn, info })
    peer._onclose = (reason) => this._detach(peer, reason)
    this.peers.set(remote, peer)

    conn.on('close', () => peer.close('remote'))
    conn.on('error', () => peer.close('error'))

    peer.channel = openHuginChannel(conn, (str) => this._onmessage(peer, str), {
      onclose: () => peer.close('channel')
    })
    if (!peer.channel) {
      peer.close('channel')
      return
    }

    const files = this.rooms.files
    if (files && typeof files.replicate === 'function') {
      try {
        files.replicate(conn, this.topic)
      } catch (err) {
        this._log('warn', 'replication not started', { message: err && err.message })
      }
    }

    const joinTimeoutMs = this._joinTimeoutMs()
    if (joinTimeoutMs > 0) {
      peer._joinTimer = setTimeout(() => {
        peer._joinTimer = null
        if (!peer.joined) peer.close('join_timeout')
      }, joinTimeoutMs)
    }

    this._sendJoined(peer).catch((err) => {
      this._log('warn', 'joined not sent', { message: err && err.message })
      peer.close('joined_not_sent')
    })
  }

  _joinTimeoutMs() {
    return this.dm ? this.options.dmJoinTimeoutMs : this.options.roomJoinTimeoutMs
  }

  _detach(peer, reason) {
    if (this.peers.get(peer.remotePublicKey) === peer) this.peers.delete(peer.remotePublicKey)
    this._log('debug', 'connection closed', { dm: this.dm, reason })
    if (!peer.joined) return
    const done = this._afterClose(peer)
    this._detaching.add(done)
    done.then(() => this._detaching.delete(done))
  }

  /**
   * A joined connection closed: once the frames it sent before are handled (bounded), the feed
   * and the drive let go of it, and `peer:left` goes out when it was its address's last one.
   */
  async _afterClose(peer) {
    try {
      await this._bounded(peer._chain)
      if (!this.dm) this._feed('onPeerLeft', peer)
      this._releaseDrive(peer)
      const set = this._byAddress.get(peer.address)
      if (!set || !set.delete(peer) || set.size > 0) return
      this._byAddress.delete(peer.address)
      this.rooms._event(E.PEER_LEFT, { key: this.key, topic: this.topic, dm: this.dm, address: peer.address })
    } catch (err) {
      this._log('warn', 'peer:left not handled', { message: err && err.message })
    }
  }

  /** Our idSig (and admin signature) for this swarm's DHT key, signed once per key and address. */
  _signatures(dhtKey, address) {
    const k = hex(dhtKey) + ':' + address
    if (!this._sigCache || this._sigCache.k !== k) {
      const p = (async () => {
        const idSig = await keys.signIdSig({ dhtPublicKey: dhtKey, topic: this.topic }, this.rooms._sign)
        const signature = this._adminSeed ? hex(keys.signAdmin(this._adminSeed, dhtKey)) : ''
        return { idSig, signature }
      })()
      const entry = { k, p }
      this._sigCache = entry
      // a failed signature is asked for again on the next connection
      p.catch(() => {
        if (this._sigCache === entry) this._sigCache = null
      })
    }
    return this._sigCache.p
  }

  async _sendJoined(peer) {
    const dhtKey = localKey(peer.connection, this.keyPair && this.keyPair.publicKey)
    if (!dhtKey) throw new Error('no local DHT key')
    const id = this.rooms.identity()
    const { idSig, signature } = await this._signatures(dhtKey, id.address)
    const messages = this.dm ? [] : this._outgoingRows(await this.rooms._roomHistory(this.key))
    if (peer.closed) return
    const base = {
      address: id.address,
      signature,
      topic: this.topic,
      time: this.time,
      idSig,
      driveKey: this.driveKey,
      ...this.rooms.voice.local(this.topic)
    }
    let msg
    try {
      msg = wire.joined({ ...base, name: typeof id.name === 'string' ? id.name : '', avatar: id.avatar, messages })
    } catch (err) {
      // our own identity does not fit: a minimal joined still lets the peer admit us
      this._log('warn', 'joined sent without name, avatar and history', { field: err && err.field, message: err && err.message })
      msg = wire.joined({ ...base, name: '' })
    }
    peer.send(encodeWithHistory(msg))
  }

  // -------------------------------------------------------------------------------------------
  // inbound

  /** Called by the channel for every frame; queues it on the peer's chain. */
  _onmessage(peer, str) {
    if (peer.closed || this.closed) return
    this.rooms._touch()
    const msg = wire.decode(str, { dm: this.dm, hexHash: true })
    if (msg.type === 'ignored') return
    // invalid frames matter only when they get the sender banned
    if (msg.type === 'invalid' && !msg.ban) return
    const o = this.options

    let preJoin = false
    if (msg.type === 'joined') {
      if (peer.joined || peer._joinSeen) {
        this._log('debug', 'repeated joined ignored')
        return
      }
      peer._joinSeen = true
    } else if (!peer.joined && msg.type !== 'disconnected' && !(msg.type === 'invalid' && (msg.kind === 'joined' || !msg.kind))) {
      // nothing before a joined; what follows one waits for its check, a bounded number
      if (!peer._joinSeen) return
      if (peer._preJoin >= o.maxPreJoinFrames) {
        this._log('debug', 'frame dropped: too many while the joined check runs', { dm: this.dm })
        return
      }
      preJoin = true
    }

    if (peer._queued >= o.maxQueuedFrames) {
      this._log('info', 'connection closed: too many frames waiting', { dm: this.dm })
      peer._discard = true
      peer.close('queue_full')
      return
    }
    this._enqueue(peer, msg, preJoin)
  }

  _enqueue(peer, msg, preJoin) {
    peer._queued++
    if (preJoin) peer._preJoin++
    peer._chain = peer._chain.then(async () => {
      try {
        await this._handle(peer, msg)
      } catch (err) {
        this._log('warn', 'message handler failed', { message: err && err.message })
        peer.close('handler_error')
      } finally {
        peer._queued--
        if (preJoin) peer._preJoin--
      }
    })
  }

  async _handle(peer, msg) {
    if (this.closed || peer._discard) return
    if (msg.type === 'invalid') {
      // what no app sends gets the sender banned; typed messages count only once it has joined
      if (peer.joined || msg.kind === 'joined' || !msg.kind) this._banPeer(peer, 'malformed')
      return
    }

    const kind = msg.type
    const value = msg.value

    if (kind === 'joined') {
      if (peer.closed) return
      return this._onJoined(peer, value)
    }
    // the peer is going away; nothing is taken from it
    if (kind === 'disconnected') return peer.close('disconnected')

    // nothing else from a peer whose joined did not verify (frames behind a joined waited for
    // its check on this chain)
    if (!peer.joined) return
    // a DM swarm takes nothing from a blocked contact
    if (this.dm && (await this.rooms._isBlocked(peer.address))) return
    if (this.closed || peer._discard) return

    switch (kind) {
      case 'dm':
        if (this.dm) this.rooms._event(E.DM_WIRE, { address: this.key, topic: this.topic, wire: value })
        return
      case 'typing':
        this.rooms._event(E.TYPING, { key: this.key, topic: this.topic, address: peer.address, typing: value.typing, dm: this.dm })
        return
      case 'file':
        return this._onFile(peer, value)
      case 'sdp':
        if (!this.dm && !peer.closed) this.rooms.voice.handleSdp(this, peer, value)
        return
      case 'voice':
        if (this.dm) return
        if (!this.rooms.voice.handleStatus(this, peer, value)) this._banPeer(peer, 'voice_address')
        return
      case 'feed':
        if (!this.dm) await this._onFeed(peer, value)
        return
      case 'ban':
        return this._onBan(peer, value)
    }

    // a DM swarm carries DM payloads, typing and file announcements only
    if (this.dm) return
    // requests and messages from blocked users are not handled
    if (await this.rooms._isBlocked(peer.address)) return
    if (this.closed || peer._discard) return

    switch (kind) {
      case 'request-feed':
        if (!peer.closed) await this._feed('handleRequest', peer, value)
        return
      case 'send-feed-history':
        await this._feed('handleHistory', peer, value)
        return
      case 'request-history':
        return this._onRequestHistory(peer)
      case 'send-history':
        return this._onSendHistory(peer, value)
      case 'ping':
        if (!peer.closed) await this._onPing(peer, value)
        return
      case 'request-messages':
        if (!peer.closed) await this._sendMissing(peer, value.hashes)
        return
      case 'missing-messages':
        return this._onMissing(peer, value.messages)
      case 'room-message':
        return this._onRoomMessage(peer, value)
    }
  }

  async _onJoined(peer, value) {
    if (peer.joined || peer._joining) {
      this._log('debug', 'repeated joined ignored')
      return
    }
    peer._joining = this._checkJoined(peer, value).catch((err) => {
      this._log('warn', 'joined check failed', { message: err && err.message })
      peer.close('joined_check_failed')
      return false
    })
    // the frames behind it wait on this chain (bounded: the join timeout closes the peer)
    const ms = this._joinTimeoutMs() > 0 ? this._joinTimeoutMs() : this.options.joinWaitMs
    const ok = await (ms > 0 ? within(peer._joining, ms, false) : peer._joining)
    if (!ok || !peer.joined || this.closed || this.dm) return
    // the history it brought, before anything it sends later
    const list = Array.isArray(value.messages) ? value.messages.slice(0, this.options.historyMax) : []
    await this._processHistory(peer, S.roomHistory(list, { hexHash: true }), { live: false })
  }

  /** Verifies a `joined` and admits the peer. Resolves true when it was admitted. */
  async _checkJoined(peer, value) {
    const remoteKey = peer.connection.remotePublicKey
    // the peer's XKR address signed this connection's DHT key in this swarm (awaited host check)
    const verified = await keys.verifyIdSig({ dhtPublicKey: remoteKey, topic: this.topic, address: value.address, idSig: value.idSig }, this.rooms._verify)
    if (peer.closed || this.closed) return false
    if (!verified) {
      this._banPeer(peer, 'id_signature')
      return false
    }

    // DM: only the contact. Any other verified identity (also our own other device, which
    // derives the same topic) is closed and refused by the swarm's firewall from now on.
    if (this.dm && value.address !== this.contact) {
      this._deny(peer)
      peer.ban()
      peer.close('not_contact')
      return false
    }

    if (!this.dm && (this.bannedAddresses.has(value.address) || (await this.rooms._isBanned(value.address, this.topic)))) {
      if (peer.closed || this.closed) return false
      if (this.admin) this._broadcastBan(value.address)
      peer.address = value.address
      this._banAddress(value.address, this.admin)
      return false
    }
    if (peer.closed || this.closed) return false

    // DM: one connection to the contact. A healthy one stays and the new one is closed (no
    // churn when both sides connect at once); a connection that can no longer write is replaced.
    if (this.dm) {
      for (const other of [...this.peers.values()]) {
        if (other === peer || other.closed || !other.joined || other.address !== value.address) continue
        if (other.writable) {
          this._log('debug', 'second connection to the contact closed', { dm: true })
          peer.close('duplicate_address')
          return false
        }
        other.close('stale')
      }
    }

    peer.address = value.address
    peer.name = value.name
    peer.avatar = value.avatar
    peer.admin = !this.dm && keys.verifyAdmin(remoteKey, value.signature, this.key)
    const time = parseInt(value.time, 10)
    peer.time = Number.isFinite(time) ? time : null
    peer.voice = value.voice
    peer.video = value.video
    peer.audioMute = value.audioMute
    peer.videoMute = value.videoMute
    peer.screenshare = value.screenshare
    peer.driveKey = value.driveKey // null unless 64 hex (a malformed key is ignored)
    peer.joined = true
    if (peer._joinTimer) {
      clearTimeout(peer._joinTimer)
      peer._joinTimer = null
    }

    // rooms: several connections per address (a user's devices); peer:joined for the first
    let set = this._byAddress.get(peer.address)
    const first = !set || set.size === 0
    if (!set) {
      set = new Set()
      this._byAddress.set(peer.address, set)
    }
    set.add(peer)
    this._holdDrive(peer)

    if (first) this.rooms._event(E.PEER_JOINED, { key: this.key, topic: this.topic, dm: this.dm, peer: peer.toInfo() })

    if (!this.dm) {
      // ask a peer that was there before us for history (once per room)
      if (peer.time !== null && this.time > peer.time && this.requests < this.options.historyRequests) {
        this._historyCandidate(peer)
      }
      this._feed('onPeerJoined', peer)
    }
    this.rooms.voice.onPeerJoined(this, peer)
    return true
  }

  /**
   * A live room message: it must belong to this room, come from its author (the connection's
   * verified address), have a hash we can store and a timestamp not too far ahead; one the host
   * already has is dropped; then its signature must verify (`host.verify`). One that does not
   * verify gets the connection banned (its author signs, so the bad signature is its own).
   */
  async _onRoomMessage(peer, value) {
    if (value.room !== this.key) {
      this._log('debug', 'room message for another room ignored')
      return
    }
    if (value.address !== peer.address) {
      this._log('debug', 'room message with another sender address ignored')
      return
    }
    if (!S.isHex64(value.hash)) return
    if (this._tooFarAhead(value, Date.now())) {
      this._log('debug', 'room message from the future dropped', { hash: value.hash })
      return
    }
    // a stored copy is not verified again (a failing lookup: verify and let the host dedupe)
    if (await this.rooms._messageExists(value.hash, false)) return
    if (this.closed || peer._discard) return
    const result = await this.rooms._verifyRoomMessage(value)
    if (this.closed || peer._discard) return
    if (result === VERIFY.BAD) {
      this._log('info', 'room message with a bad signature: sender banned', { hash: value.hash })
      this._banPeer(peer, 'room_signature')
      return
    }
    if (result !== VERIFY.OK) return
    this.rooms._event(E.ROOM_MESSAGE, { key: this.key, topic: this.topic, message: value, history: false, live: true })
  }

  /** The signed timestamp is later than now + `maxClockSkewMs`. */
  _tooFarAhead(m, now) {
    return m.timestamp > now + this.options.maxClockSkewMs
  }

  /**
   * History batch (`joined.messages`, requested `missing-messages`; validated, hex hashes) from
   * `peer`: the first `historyMax` entries are looked at. Every message of this room that is not
   * ours, not in the batch already, not too far ahead and not stored yet is verified
   * (`verifyConcurrency` at a time); those that verify are emitted in batch order, then
   * `room:history`. Entries whose signature does not verify are dropped and counted against the
   * connection: more than `maxBadHistory` of them and it is banned.
   */
  async _processHistory(peer, list, { live }) {
    if (!Array.isArray(list) || list.length === 0) return
    const own = this.rooms.identity().address
    const now = Date.now()
    const inBatch = new Set()
    const candidates = []
    let ahead = 0
    for (const m of list.slice(0, this.options.historyMax).reverse()) {
      if (m.room !== this.key || m.address === own || !S.isHex64(m.hash)) continue
      const h = m.hash.toLowerCase()
      if (inBatch.has(h)) continue
      inBatch.add(h)
      if (this._tooFarAhead(m, now)) {
        ahead++
        continue
      }
      candidates.push(m)
    }
    if (ahead) this._log('debug', 'history entries from the future dropped', { count: ahead })

    const results = await mapLimit(candidates, this.options.verifyConcurrency, async (m) => {
      if (this.closed) return null
      if (await this.rooms._messageExists(m.hash)) return null
      if (this.closed) return null
      return this.rooms._verifyRoomMessage(m)
    })
    if (this.closed) return

    const out = []
    let bad = 0
    for (let i = 0; i < candidates.length; i++) {
      if (results[i] === VERIFY.OK) out.push(candidates[i])
      else if (results[i] === VERIFY.BAD) bad++
    }
    for (const m of out) {
      this.rooms._event(E.ROOM_MESSAGE, { key: this.key, topic: this.topic, message: m, history: true, live })
    }
    this.rooms._event(E.ROOM_HISTORY, { key: this.key, topic: this.topic, count: out.length, missing: live ? out : [] })

    if (bad > 0) {
      peer._badHistory += bad
      this._log('info', 'history entries with a bad signature dropped', { count: bad, total: peer._badHistory })
      if (peer._badHistory > this.options.maxBadHistory && !peer._discard) this._banPeer(peer, 'history_signature')
    }
  }

  /** `missing-messages`: only the messages we asked this peer for are taken. */
  async _onMissing(peer, messages) {
    const wanted = []
    for (const m of messages) {
      const h = m.hash.toLowerCase()
      if (!peer.requested.has(h)) continue
      peer.requested.delete(h)
      wanted.push(m)
    }
    if (wanted.length < messages.length) {
      this._log('debug', 'messages we did not ask for were dropped', { count: messages.length - wanted.length })
    }
    if (wanted.length === 0) return
    this.search = false
    await this._processHistory(peer, wanted, { live: true })
  }

  async _onPing(peer, value) {
    if (!this.search || value.hashes === null) return
    if (value.peers.length) this._dialPeers(peer, value.peers)
    const hashes = value.hashes.filter(S.isHex64).slice(0, MAX_PING_HASHES)
    const known = peer.knownHashes
    const same = known.length === hashes.length && known.every((h, i) => h === hashes[i])
    if (same && value.files.length === 0) return // already know the latest messages
    // the host lookups a Ping causes (stored? listed files) are rate-limited per connection
    if (!peer.rate('ping', this.options.pingLookupsPerMinute)) {
      this._log('debug', 'ping ignored: too many', { dm: false })
      return
    }
    if (value.files.length) this._offerFiles(peer, value.files).catch(noop)
    if (same) return
    const missing = []
    for (const hash of hashes) {
      if (peer.requested.has(hash.toLowerCase())) continue
      if (!(await this.rooms._messageExists(hash))) missing.push(hash)
    }
    peer.knownHashes = hashes
    if (missing.length === 0 || peer.closed || this.closed) return
    for (const hash of missing) boundedAdd(peer.requested, hash.toLowerCase(), MAX_REQUESTED_HASHES)
    this.search = false
    peer.write(wire.requestMessages(missing))
  }

  // -------------------------------------------------------------------------------------------
  // dialing the peers a Ping lists (native `find_missing_peers`)

  /**
   * Joins keys a Ping lists that we have no connection to, a few at a time: at most
   * `dialMaxPerPing` per Ping, `dialMaxPerPeerPerMinute` per announcing connection,
   * `dialMaxPerMinute` per room and `maxPendingDials` in progress. Keys we denied, are
   * connected to or dial already are skipped. A dial ends (`leavePeer`) once the key connects
   * or after `dialTimeoutMs`, so Hyperswarm does not retry it forever.
   */
  _dialPeers(from, list) {
    const swarm = this.swarm
    if (!swarm || typeof swarm.joinPeer !== 'function' || this.closed || this.suspended) return
    const o = this.options
    const own = this.keyPair ? hex(this.keyPair.publicKey) : null
    let added = 0
    for (const k of list) {
      if (added >= o.dialMaxPerPing || this._dials.size >= o.maxPendingDials) return
      if (!S.isHex64(k)) continue
      const key = k.toLowerCase()
      if (key === own || this.denied.has(key) || this.peers.has(key) || this._dials.has(key)) continue
      if (!canTakeRate(this._dialRate, o.dialMaxPerMinute) || !from.canRate('dial', o.dialMaxPerPeerPerMinute)) return
      takeRate(this._dialRate, o.dialMaxPerMinute)
      from.rate('dial', o.dialMaxPerPeerPerMinute)
      added++
      this._startDial(key)
    }
  }

  _startDial(key) {
    let timer = null
    const ms = this.options.dialTimeoutMs
    if (ms > 0) {
      timer = setTimeout(() => this._endDial(key), ms)
      if (typeof timer.unref === 'function') timer.unref()
    }
    this._dials.set(key, timer)
    try {
      this.swarm.joinPeer(b4a.from(key, 'hex'))
    } catch {
      this._endDial(key)
    }
  }

  _endDial(key) {
    if (!this._dials.has(key)) return
    const timer = this._dials.get(key)
    if (timer) clearTimeout(timer)
    this._dials.delete(key)
    const swarm = this.swarm
    if (swarm && typeof swarm.leavePeer === 'function') {
      try {
        swarm.leavePeer(b4a.from(key, 'hex'))
      } catch {}
    }
  }

  _endAllDials() {
    for (const key of [...this._dials.keys()]) this._endDial(key)
  }

  // -------------------------------------------------------------------------------------------
  // sync answers

  async _sendMissing(peer, hashes) {
    if (!peer.rate('request-messages', this.options.requestMessagesPerMinute)) {
      this._log('debug', 'request-messages ignored: too many')
      return
    }
    const seen = new Set()
    const rows = []
    for (const hash of hashes) {
      if (!S.isHex64(hash)) continue
      const h = hash.toLowerCase()
      if (seen.has(h)) continue
      seen.add(h)
      const m = await this.rooms._getMessage(hash)
      if (m) rows.push(m)
    }
    const messages = this._outgoingRows(rows)
    if (messages.length === 0 || peer.closed) return
    try {
      peer.send(wire.encode(wire.missingMessages(messages)))
    } catch (err) {
      this._log('warn', 'missing messages not sent', { message: err && err.message })
    }
  }

  /**
   * A joined peer that started before us: history is requested from `historyRequests` peers
   * picked at random among those still connected `historyPickMs` after the first candidate.
   */
  _historyCandidate(peer) {
    this._historyCandidates.add(peer)
    if (this._historyTimer || this.closed) return
    const ms = this.options.historyPickMs
    if (!(ms > 0)) {
      this._pickHistoryPeers()
      return
    }
    this._historyTimer = setTimeout(() => {
      this._historyTimer = null
      this._pickHistoryPeers()
    }, ms)
    if (typeof this._historyTimer.unref === 'function') this._historyTimer.unref()
  }

  _pickHistoryPeers() {
    const live = [...this._historyCandidates].filter((p) => p.joined && !p.closed && !p._discard)
    this._historyCandidates.clear()
    while (live.length && this.requests < this.options.historyRequests && !this.closed) {
      const peer = live.splice(randomInt(live.length), 1)[0]
      this.requests++
      this._requestHistory(peer).catch((err) => this._log('warn', 'history not requested', { message: err && err.message }))
    }
  }

  async _requestHistory(peer) {
    const files = await this._recentFiles()
    if (peer.closed) return
    peer._historyRequested = true
    if (!peer.write(wire.requestHistory(files))) peer._historyRequested = false
  }

  /** `request-history`: answered once per connection, `historyAnswersPerMinute` per room. */
  async _onRequestHistory(peer) {
    if (peer.closed || peer._historyAnswered) return
    peer._historyAnswered = true
    if (!takeRate(this._historyRate, this.options.historyAnswersPerMinute)) {
      this._log('debug', 'request-history ignored: too many')
      return
    }
    await this._sendHistory(peer)
  }

  /** `send-history`: taken once, as the answer to our request-history (its files are offered). */
  async _onSendHistory(peer, value) {
    if (!peer._historyRequested) {
      this._log('debug', 'send-history we did not ask for ignored')
      return
    }
    peer._historyRequested = false
    // receivers only use the files (message processing is off in both apps)
    this._offerFiles(peer, value.files).catch(noop)
  }

  async _sendHistory(peer) {
    const messages = this._outgoingRows(await this.rooms._roomHistory(this.key))
    const files = await this._recentFiles()
    if (peer.closed) return
    peer.send(encodeWithHistory(wire.sendHistory({ messages, files })))
  }

  /**
   * Host rows rebuilt as room messages (`wire.roomMessage`), only those of this room whose hash
   * is the derived one (`wire.roomMessageHash`) and with a well-formed signature (the one the
   * host stored with the message), at most `historyMax`; nothing else of a host row goes on the
   * wire. Rows are not verified here: the
   * receiver does that, and drops (and counts against us) any that do not verify.
   */
  _outgoingRows(rows) {
    const out = []
    if (!Array.isArray(rows)) return out
    let unsigned = 0
    for (const row of rows) {
      if (out.length >= this.options.historyMax) break
      const r = S.roomMessage(row, { hexHash: true })
      if (!r.ok) {
        if (r.reason === 'signature') unsigned++
        continue
      }
      if (r.value.room !== this.key) continue
      if (!wire.isRoomMessageHash(r.value)) {
        unsigned++
        continue
      }
      try {
        out.push(wire.roomMessage(r.value))
      } catch {}
    }
    if (unsigned) this._log('debug', 'stored room messages without a signature or derived hash not sent', { count: unsigned })
    return out
  }

  /** The 10 most recent files of our drive, for Ping and history. */
  async _recentFiles() {
    const files = this.rooms.files
    if (!files || typeof files.list !== 'function') return []
    try {
      const list = await files.list(this.topic)
      return wire.recentFiles(list.filter((m) => m && typeof m === 'object').map(fileEntry))
    } catch {
      return []
    }
  }

  // -------------------------------------------------------------------------------------------
  // files

  _onFile(peer, value) {
    if (value.info !== FILE_SHARED) return
    const files = this.rooms.files
    if (!files || typeof files.handleRemote !== 'function') return
    if (!peer.rate('file', this.options.fileAnnouncementsPerMinute)) {
      this._log('debug', 'file announcement ignored: too many')
      return
    }
    // attributed by Files: to this connection's verified address, or to the address its
    // signature verifies for
    Promise.resolve()
      .then(() => files.handleRemote(this.topic, value, { driveKey: peer.driveKey, address: peer.address, name: peer.name }))
      .catch((err) => this._log('warn', 'file announcement not handled', { message: err && err.message }))
  }

  /**
   * Files listed in a peer's Ping or send-history: recent ones are offered from its drive
   * (attributed by Files, as announcements are).
   */
  async _offerFiles(peer, list) {
    const files = this.rooms.files
    if (!files || typeof files.handleRemote !== 'function' || !peer.driveKey) return
    if (!Array.isArray(list)) return
    const now = Date.now()
    for (const f of list) {
      if (this.closed) return
      if (typeof f.time !== 'number' || now - f.time > this.options.fileMaxAgeMs) continue
      try {
        await files.handleRemote(this.topic, f, { driveKey: peer.driveKey, address: peer.address, name: peer.name })
      } catch (err) {
        this._log('warn', 'listed file not handled', { message: err && err.message })
      }
    }
  }

  /** The addresses of the admitted connections that announced a drive key. */
  _driveOwners(key) {
    const refs = this._driveRefs.get(key)
    return refs ? [...refs.keys()] : []
  }

  /**
   * An admitted connection announced a drive: Files opens and watches it (once per key), and
   * attributes its files to the addresses of the connections that announced it.
   */
  _holdDrive(peer) {
    const files = this.rooms.files
    if (!peer.driveKey || !files) return
    const key = peer.driveKey.toLowerCase()
    let refs = this._driveRefs.get(key)
    if (!refs) {
      refs = new Map()
      this._driveRefs.set(key, refs)
    }
    refs.set(peer.address, (refs.get(peer.address) || 0) + 1)
    if (typeof files.addPeer !== 'function') return
    Promise.resolve()
      .then(() => files.addPeer(this.topic, key, { owners: this._driveOwners(key) }))
      .then(() => {
        // the last connection that announced it may have closed while it opened
        if (!this._driveRefs.has(key) && !this.closed) this._dropDrive(key)
      })
      .catch((err) => this._log('warn', 'peer drive not added', { message: err && err.message }))
  }

  /**
   * A connection that announced a drive closed: Files releases the drive (`removePeer`) after
   * the last one, else its owners are updated (`setPeerOwners`).
   */
  _releaseDrive(peer) {
    const files = this.rooms.files
    if (!peer.driveKey || !files) return
    const key = peer.driveKey.toLowerCase()
    const refs = this._driveRefs.get(key)
    if (refs) {
      const n = (refs.get(peer.address) || 0) - 1
      if (n > 0) refs.set(peer.address, n)
      else refs.delete(peer.address)
      if (refs.size > 0) {
        if (typeof files.setPeerOwners === 'function') {
          try {
            files.setPeerOwners(this.topic, key, this._driveOwners(key))
          } catch {}
        }
        return
      }
    }
    this._driveRefs.delete(key)
    // a closing room closes every drive at once (Files#closeRoom)
    if (!this.closed) this._dropDrive(key)
  }

  _dropDrive(key) {
    const files = this.rooms.files
    if (!files || typeof files.removePeer !== 'function') return
    try {
      const r = files.removePeer(this.topic, key)
      if (r && typeof r.catch === 'function') r.catch(noop)
    } catch {}
  }

  // -------------------------------------------------------------------------------------------
  // feed

  /** A live feed message: a signature that does not verify gets its direct sender banned. */
  async _onFeed(peer, value) {
    const result = await this._feed('handle', peer, value)
    if (result === FEED_RESULT.UNVERIFIED && !peer._discard) this._banPeer(peer, 'feed_signature')
  }

  // -------------------------------------------------------------------------------------------
  // bans

  async _onBan(peer, value) {
    if (this.dm) return
    // only the room admin (its signature of the peer's key verified at `joined`) bans
    if (!peer.admin) {
      this._log('debug', 'ban ignored: not from the room admin')
      return
    }
    if (value.address === this.rooms.identity().address) {
      this.rooms._event(E.BAN_SELF, { key: this.key, topic: this.topic })
      this.rooms._later(this.options.banLeaveDelayMs, () => this.rooms.leave(this.topic))
      return
    }
    this._banAddress(value.address, true)
  }

  _broadcastBan(address) {
    let str
    try {
      str = wire.encode(wire.ban(address))
    } catch (err) {
      this._log('warn', 'ban not sent', { message: err && err.message })
      return 0
    }
    return this.send(str)
  }

  /** Local ban: the address's connections are closed and denied; the host persists it. */
  _banAddress(address, admin) {
    if (this.closed) return
    boundedAdd(this.bannedAddresses, address, this.options.maxBannedAddresses)
    this.rooms._event(E.BAN_PEER, { key: this.key, topic: this.topic, address, admin: !!admin })
    for (const peer of [...this.peers.values()]) {
      if (peer.address === address) this._banPeer(peer, 'banned_address')
    }
  }

  /** Closes a peer and refuses its DHT key in this swarm from now on. */
  _banPeer(peer, reason) {
    this._log('info', 'peer banned in swarm', { dm: this.dm, reason })
    peer._discard = true
    this._deny(peer)
    peer.ban()
    peer.close('banned')
  }

  _deny(peer) {
    if (!peer.remotePublicKey) return
    this._endDial(peer.remotePublicKey)
    boundedAdd(this.denied, peer.remotePublicKey, this.options.maxDenied)
  }

  // -------------------------------------------------------------------------------------------
  // helpers

  /**
   * Calls the feed module (absent in DM swarms or when there is none). Returns its result (a
   * promise is awaited by the caller); never throws or rejects.
   */
  _feed(method, peer, value) {
    const feed = this.rooms.feed
    if (!feed || this.dm || typeof feed[method] !== 'function') return undefined
    const failed = (err) => {
      this._log('warn', 'feed handler failed', { method, message: err && err.message })
      return undefined
    }
    try {
      const r = value === undefined ? feed[method](peer) : feed[method](peer, value)
      if (r && typeof r.then === 'function') return Promise.resolve(r).catch(failed)
      return r
    } catch (err) {
      return failed(err)
    }
  }

  _log(level, msg, data) {
    this.rooms._log(level, msg, data)
  }
}

module.exports = {
  Room,
  DEFAULTS,
  VERIFY,
  within,
  mapLimit
}
