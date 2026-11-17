'use strict'

// HuginP2P: the one object a host (hugin-desktop's main process, hugin-native's Bare worklet)
// creates. It builds the parts, wires them together and gives every event one
// way out:
//
//   p2p.rooms  Rooms (lib/rooms.js)       room and DM swarms, messages, typing, bans, history
//   p2p.voice  Voice (lib/voice.js)       room calls (one voice channel at a time)
//   p2p.feed   Feed  (lib/feed.js)        the public feed over every room connection
//   p2p.files  Files (lib/files.js)       drives per room, or null without `paths.storage`
//   p2p.node   NodeClient (lib/node-client.js)  hugin-node connection, sync, posts
//
// Every part's events come out of this emitter under the canonical names of lib/events.js.
// Rooms, Voice and Feed get the facade's `emit` hook; Files and NodeClient emit on their own
// emitters and the facade re-emits those names. `node:error` and a `file:error` of a download the
// UI asked for also come out as `error` `{ message, source }`, but only while an `error`
// listener exists, so an unhandled `error` never throws.
//
// The facade holds no protocol logic: every method delegates to a part. What it adds is the
// lifecycle across parts (suspend / resume / idle / destroy) and one identity for all of them
// (`setIdentity` overrides `host.identity()` for rooms, voice, feed and files).
//
// No module-level state, no process signal handlers, no Node-only APIs: runs under Node and Bare.
// lib/files.js (corestore, hyperdrive, the RocksDB addon) is only loaded when a host configures
// `paths.storage`.

const EventEmitter = require('bare-events')
const { Rooms } = require('./rooms.js')
const { Feed } = require('./feed.js')
const { Voice } = require('./voice.js')
const { NodeClient, PRESETS: NODE_PRESETS } = require('./node-client.js')
const E = require('./events.js')

/** Events Files emits on its own emitter (lib/files.js EVENTS). */
const FILE_EVENTS = Object.freeze([
  E.FILE_REMOTE,
  E.FILE_DOWNLOADING,
  E.FILE_PROGRESS,
  E.FILE_DOWNLOADED,
  E.FILE_UPLOADED,
  E.FILE_REMOVED,
  E.FILE_ERROR
])

/**
 * Events NodeClient emits on its own emitter. `node:pow-required` is a NodeClient event that
 * lib/events.js does not list yet; it is forwarded under its own name.
 */
const NODE_POW_REQUIRED = 'node:pow-required'
const NODE_EVENTS = Object.freeze([
  E.NODE_CONNECTED,
  E.NODE_DISCONNECTED,
  E.NODE_ADDRESS,
  E.NODE_MESSAGES,
  E.NODE_JOB,
  E.NODE_RESET,
  E.NODE_ERROR,
  NODE_POW_REQUIRED
])

/** Which part emits each canonical event (`facade`: derived by HuginP2P itself). */
const EVENT_SOURCES = Object.freeze({
  [E.ROOM_JOINED]: 'rooms',
  [E.ROOM_LEFT]: 'rooms',
  [E.PEER_JOINED]: 'rooms',
  [E.PEER_LEFT]: 'rooms',
  [E.ROOM_MESSAGE]: 'rooms',
  [E.ROOM_HISTORY]: 'rooms',
  [E.DM_WIRE]: 'rooms',
  [E.TYPING]: 'rooms',
  [E.BAN_SELF]: 'rooms',
  [E.BAN_PEER]: 'rooms',
  [E.FEED_MESSAGE]: 'feed',
  [E.VOICE_STATUS]: 'voice',
  [E.VOICE_CALL]: 'voice',
  [E.VOICE_OFFER]: 'voice',
  [E.VOICE_ANSWER]: 'voice',
  [E.VOICE_RETRY]: 'voice',
  [E.FILE_REMOTE]: 'files',
  [E.FILE_DOWNLOADING]: 'files',
  [E.FILE_PROGRESS]: 'files',
  [E.FILE_DOWNLOADED]: 'files',
  [E.FILE_UPLOADED]: 'files',
  [E.FILE_REMOVED]: 'files',
  [E.FILE_ERROR]: 'files',
  [E.NODE_CONNECTED]: 'node',
  [E.NODE_DISCONNECTED]: 'node',
  [E.NODE_ADDRESS]: 'node',
  [E.NODE_MESSAGES]: 'node',
  [E.NODE_JOB]: 'node',
  [E.NODE_RESET]: 'node',
  [E.NODE_ERROR]: 'node',
  [E.ERROR]: 'facade'
})

/** Invalid construction options (code `HUGIN_P2P_INVALID`), as FilesError / RoomsError do for their parts. */
class HuginP2PError extends Error {
  constructor(message, code = 'HUGIN_P2P_INVALID') {
    super(message)
    this.name = 'HuginP2PError'
    this.code = code
  }
}

/** True when the paths Files would use name a storage directory. */
function hasStorage(host, filesOpts) {
  let paths = filesOpts.paths !== undefined ? filesOpts.paths : host.paths
  if (typeof paths === 'function') {
    try {
      paths = paths()
    } catch {
      return false
    }
  }
  return !!paths && typeof paths === 'object' && typeof paths.storage === 'string' && paths.storage.length > 0
}

function numberOr(v, fallback) {
  return typeof v === 'number' && Number.isFinite(v) && v >= 0 ? v : fallback
}

/**
 * The host's hugin-pow backend: `host.powBackend`, else `{ findShare, hash }` from the hooks
 * `host.findShare(req)` (kryptokrona-crypto `findPowShare` shape) and `host.powHash(blobHex)`
 * (looked up at call time); null without them.
 */
function hostPowBackend(host) {
  if (host.powBackend && typeof host.powBackend === 'object') return host.powBackend
  if (typeof host.findShare !== 'function') return null
  const backend = { findShare: (req) => host.findShare(req) }
  if (typeof host.powHash === 'function') backend.hash = (blobHex) => host.powHash(blobHex)
  return backend
}

class HuginP2P extends EventEmitter {
  /**
   * @param {object} opts
   * @param {object} opts.host  host hooks (README "Host hooks and events")
   * @param {Array<{host, port}>} [opts.bootstrap]  DHT bootstrap for rooms and node (tests: a testnet)
   * @param {number} [opts.roomMaxPeers]  connections per room swarm (default 100; DM swarms: 1)
   * @param {boolean} [opts.sharedDht]  true: every room and DM swarm runs on one shared DHT
   *   (default false: one DHT node per swarm); the node client keeps its own DHT either way
   * @param {boolean | 'foreground' | (() => boolean)} [opts.gossip]  forward new feed messages:
   *   default: unless idle in the background (`idle({ background })`; desktop never is, so
   *   always), `'foreground'`: also not while suspended, true / false, or a function
   * @param {object} [opts.rooms]  Rooms options (timings, `createSwarm` for tests)
   * @param {object} [opts.feed]  Feed options (timings, `maxHistory`, ...)
   * @param {object} [opts.voice]  Voice options (`callDelayMs`, `joinCallDelayMs`)
   * @param {object|false} [opts.files]  Files options (`saveDownloads`, `pruneMaxBytes`, `fs`,
   *   `paths`, ...); false: no file storage even with `paths.storage`
   * @param {object} [opts.node]  NodeClient options (`preset`, `backend`, `findShare`, `hash`,
   *   `poll`, `powMaxDifficulty`, `powMaxTooHardJobs`, `createSwarm` for tests, ...); without `backend`, `findShare` and `hash` the PoW
   *   backend is `host.powBackend`, else one built from `host.findShare` (and `host.powHash`)
   */
  constructor(opts = {}) {
    super()
    const host = opts.host
    if (!host || typeof host !== 'object') throw new HuginP2PError('HuginP2P: opts.host is required')
    if (opts.node && opts.node.preset && !Object.prototype.hasOwnProperty.call(NODE_PRESETS, opts.node.preset)) {
      // checked here so that NodeClient's own TypeError is never what a host sees
      throw new HuginP2PError(`HuginP2P: unknown node preset '${opts.node.preset}'`)
    }
    this.host = host
    this.destroyed = false
    this._destroying = null
    this._idleTimer = null

    const log = (level, msg, data) => this._log(level, msg, data)
    const emit = (name, payload) => this._emitEvent(name, payload)
    const bootstrap = opts.bootstrap || null

    // The host as Feed and Files see it: every hook of `host` (looked up at call time, so a host
    // may replace hooks later), with `identity()` answered by Rooms (setIdentity overrides).
    const partHost = Object.create(host)
    Object.defineProperty(partHost, 'identity', { value: () => this.identity(), enumerable: true })

    // files: only with a storage directory (else lib/files.js and RocksDB are never loaded)
    const filesOpts = opts.files === false ? null : opts.files && typeof opts.files === 'object' ? opts.files : {}
    /** @type {import('./files.js').Files | null} */
    this.files = null
    if (filesOpts && hasStorage(host, filesOpts)) {
      const { Files } = require('./files.js')
      this.files = new Files({ log, ...filesOpts, host: partHost })
      this._forward(this.files, FILE_EVENTS, 'files')
    }

    this.voice = new Voice({ ...(opts.voice || {}), host, log, emit })

    const roomOpts = opts.rooms && typeof opts.rooms === 'object' ? opts.rooms : {}
    this.rooms = new Rooms({
      ...roomOpts,
      host,
      log,
      emit,
      files: this.files,
      voice: this.voice,
      bootstrap: roomOpts.bootstrap || bootstrap,
      sharedDht: opts.sharedDht === true || roomOpts.sharedDht === true,
      roomMaxPeers: numberOr(opts.roomMaxPeers, numberOr(roomOpts.roomMaxPeers, 100))
    })

    const feedOpts = opts.feed && typeof opts.feed === 'object' ? opts.feed : {}
    const gossip = opts.gossip !== undefined ? opts.gossip : feedOpts.gossip
    this.feed = new Feed({
      ...feedOpts,
      host: partHost,
      log,
      emit,
      peers: () => this.rooms.joinedPeers({ dm: false }),
      // default: gossip unless the app is idle in the background (desktop never is)
      gossip: gossip === 'foreground' ? () => this.foreground : gossip === undefined ? () => !this.rooms.idleState : gossip
    })
    this.rooms.feed = this.feed

    // NodeClient is created here, not on the first connect: its constructor only sets state (no
    // swarm, no timer until `connect`), and an object that exists from the start lets the host
    // subscribe and call `p2p.node.*` without a null check.
    const nodeOpts = { ...(opts.node || {}) }
    if (nodeOpts.backend === undefined && nodeOpts.hash === undefined && nodeOpts.findShare === undefined) {
      const backend = hostPowBackend(host)
      if (backend) nodeOpts.backend = backend
    }
    if (nodeOpts.bootstrap === undefined && bootstrap) nodeOpts.bootstrap = bootstrap
    this.node = new NodeClient({ log, ...nodeOpts })
    this._forward(this.node, NODE_EVENTS, 'node')
  }

  // -------------------------------------------------------------------------------------------
  // identity

  /** `{ address, name, avatar }`: `setIdentity` values over `host.identity()`. */
  identity() {
    return this.rooms.identity()
  }

  /**
   * Updates our identity (native `update_bare_user`). Later `joined` messages, room and feed
   * messages, voice status and file announcements use it. Returns the identity now in use.
   */
  setIdentity({ address, name, avatar } = {}) {
    this.rooms.setIdentity({ address, name, avatar })
    return this.identity()
  }

  /** False while the app is idle in the background or suspended (native gossip rule). */
  get foreground() {
    return !this.rooms.idleState && !this.rooms.suspended
  }

  // -------------------------------------------------------------------------------------------
  // lifecycle (the mobile host calls these; desktop only calls destroy)

  /** Closes every room and node connection and suspends the swarms. */
  async suspend() {
    if (this.destroyed) return
    this._clearIdleTimer()
    await Promise.all([this.rooms.suspend(), this.node.suspend()])
  }

  /**
   * Resumes the swarms, refreshes room discovery and reconnects to the node. The idle state is
   * left as it is (`idle({ background: false })` ends it).
   */
  async resume() {
    if (this.destroyed) return
    this._clearIdleTimer()
    await Promise.all([this.rooms.resume(), this.node.resume()])
  }

  /**
   * Native `idle(background, force)` for rooms and the node: `force` suspends both at once;
   * `background` marks the app idle (no Ping, no feed gossip unless `gossip` says otherwise) and
   * suspends both after `rooms.options.idleSuspendMs`; back in the foreground both are resumed,
   * or room discovery is refreshed (Rooms#idle) and a dropped node connection reconnects.
   */
  async idle({ background = false, force = false } = {}) {
    if (this.destroyed) return
    if (force) {
      this._clearIdleTimer()
      await Promise.all([this.rooms.idle({ force: true }), this.node.suspend()])
      return
    }
    if (background) {
      await this.rooms.idle({ background: true })
      if (this._idleTimer || this.node.suspended || this.destroyed) return
      this._idleTimer = setTimeout(() => {
        this._idleTimer = null
        if (this.destroyed || !this.rooms.idleState) return
        this.node.suspend().catch((err) => this._fail('node not suspended', err))
      }, this.rooms.options.idleSuspendMs)
      return
    }
    this._clearIdleTimer()
    await this.rooms.idle({ background: false })
    if (this.destroyed) return
    if (this.node.suspended) await this.node.resume()
    else if (this.node.swarm && !this.node.connected) this.node.reconnect()
  }

  /**
   * Leaves every swarm (without notifying peers), disconnects from the node, stops the feed
   * queue and the voice call timers, and closes every drive. Idempotent: every call returns the same promise. Drive
   * watchers are destroyed but not awaited (lib/files.js).
   */
  destroy() {
    if (this._destroying) return this._destroying
    this.destroyed = true
    this._clearIdleTimer()
    this._destroying = (async () => {
      this.feed.destroy()
      this.voice.destroy() // Rooms#destroy does it too; its call timers end here at the latest
      await Promise.all([
        this.rooms.destroy().catch((err) => this._log('warn', 'rooms not destroyed cleanly', { message: err && err.message })),
        this.node.destroy().catch((err) => this._log('warn', 'node client not destroyed cleanly', { message: err && err.message }))
      ])
      // after the rooms: their drives are closed first (Room#close -> Files#closeRoom)
      if (this.files) {
        await this.files.close().catch((err) => this._log('warn', 'files not closed cleanly', { message: err && err.message }))
      }
    })()
    return this._destroying
  }

  // -------------------------------------------------------------------------------------------
  // internals

  _clearIdleTimer() {
    if (this._idleTimer) clearTimeout(this._idleTimer)
    this._idleTimer = null
  }

  /** Re-emits a part's own events; error events also surface as `error` (see `_surface`). */
  _forward(part, names, source) {
    for (const name of names) {
      part.on(name, (payload) => {
        this._emitEvent(name, payload)
        if (name === E.NODE_ERROR) this._surface(source, payload)
        // a failed download the UI asked for; auto-sync failures stay `file:error` only
        else if (name === E.FILE_ERROR && !(payload && payload.auto === true)) this._surface(source, payload)
      })
    }
  }

  /** The one emit every part uses. A listener that throws is logged, never thrown into a part. */
  _emitEvent(name, payload) {
    if (name === E.ERROR && this.listenerCount(E.ERROR) === 0) return false
    try {
      return this.emit(name, payload)
    } catch (err) {
      this._log('warn', 'event handler failed', { event: name, message: err && err.message })
      return false
    }
  }

  /** `error` `{ message, source }`, only while someone listens for it. */
  _surface(source, payload) {
    if (this.listenerCount(E.ERROR) === 0) return
    const message = payload && typeof payload.message === 'string' && payload.message ? payload.message : source + ' error'
    this._emitEvent(E.ERROR, { message, source })
  }

  _fail(message, err) {
    this._log('warn', message, { message: err && err.message })
    this._surface('facade', { message: message + (err && err.message ? ': ' + err.message : '') })
  }

  _log(level, msg, data) {
    const fn = this.host.log
    if (typeof fn !== 'function') return
    try {
      fn(level, msg, data)
    } catch {}
  }
}

module.exports = {
  HuginP2P,
  HuginP2PError,
  EVENT_SOURCES,
  FILE_EVENTS,
  NODE_EVENTS,
  NODE_POW_REQUIRED
}
