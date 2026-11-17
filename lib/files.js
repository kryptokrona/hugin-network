'use strict'

// hugin-network/files: the file storage and sync of hugin-desktop (`src/backend/storage.cjs`) and
// hugin-native (`bare/storage.js`) in one class, on corestore 7 + hyperdrive 13 (hypercore 11)
// for both apps.
//
// Model (unchanged from both apps):
//   * one corestore and one hyperdrive per room or DM swarm, keyed by the swarm topic (hex of the
//     topic base public key), stored under `<paths.storage>/<topic>/files`;
//   * the drive key is announced in `joined.driveKey`; a peer's drive is opened from that key on
//     the same corestore and replicated over the room connection (`corestore.replicate(conn)`,
//     protomux `hypercore/alpha` next to the `hugin-messages` channel);
//   * files live in the drive under `/<hash>` with the announcement fields as metadata;
//   * every file carries `contentHash`, the BLAKE2b-256 of its bytes (computed by `share`, part
//     of the signed file string); a fetched file is kept only when its bytes match it;
//   * a file fetched from a peer drive is copied into our own drive, so we serve it onwards;
//   * auto-sync is a host decision (`autoSyncFiles`), otherwise `file:remote` lets the UI offer a
//     download button.
//
// Attribution (hugin-network 3.0): a peer drive's files are offered for the verified addresses of
// the room connections that announced that drive (its "owners", set by the room through
// `addPeer` / `setPeerOwners`; for an announcement or a listed file, the connection it came
// on). A file whose `address` is an owner's is taken as that owner's; any other file is taken
// only when its `signature` verifies for its own `address` (`host.verify` over
// `wire.fileSigningPayload`, which includes the room topic). A file that carries a signature
// is always checked, and one whose signature does not verify is dropped. Our own files are
// signed (`share`).
//
// Filesystem access goes through `require('#fs')` (package `imports`: `bare-fs` on Bare, `fs`
// on Node) or an `fs` option. Paths are joined with `/`. No other Node-only API is used, so the
// module runs under Node (Electron main) and Bare.

const EventEmitter = require('bare-events')
const b4a = require('b4a')
const Corestore = require('corestore')
const Hyperdrive = require('hyperdrive')
const defaultFs = require('#fs')
const wire = require('./wire.js')
const S = require('./sanitize.js')
const { randomKey, utf8Length, blake2b256Hex, blake2b256Hasher } = require('./bytes.js')
const { ONE_WEEK_MS, FILE_SHARED, FILE_TYPE } = require('./constants.js')

/** Canonical event names (README "Host hooks and events"). */
const EVENTS = Object.freeze({
  REMOTE: 'file:remote',
  DOWNLOADING: 'file:downloading',
  PROGRESS: 'file:progress',
  DOWNLOADED: 'file:downloaded',
  UPLOADED: 'file:uploaded',
  REMOVED: 'file:removed',
  ERROR: 'file:error'
})

const DEFAULTS = Object.freeze({
  storageLimit: 100000000000, // both apps: 100 GB
  downloadTimeoutMs: 30000, // both apps: per block request
  pruneIntervalMs: 60 * 60 * 1000, // both apps: hourly
  pruneMaxAgeMs: ONE_WEEK_MS, // both apps: files not saved to disk are removed after a week
  pruneMaxBytes: 1024 * 1024 * 1024, // desktop 1 GiB; native passes 500 MiB
  maxPeerDrives: 100, // one per peer, room maxPeers
  maxNotified: 1000, // hashes per room already offered with file:remote (oldest forgotten first)
  remotePerMinute: 30, // file:remote events per peer drive and minute
  autoSyncMaxBytes: 50 * 1024 * 1024, // larger files are offered (file:remote), not auto-synced
  autoSyncPerMinute: 10, // auto-sync downloads started per peer drive and minute
  verifyPerMinute: 120 // file signature checks (host.verify) per peer drive and minute
})

/** Longest file name accepted (characters, the announcement limit) and its UTF-8 byte cap. */
const MAX_FILE_NAME = S.ACCEPT.file.fileName
const MAX_FILE_NAME_BYTES = 255

const TOPIC_RE = /^[0-9a-f]{64}$/i
const NUMERIC_RE = /^-?\d+(\.\d+)?$/
// eslint-disable-next-line no-control-regex
const CONTROL_RE = /[\u0000-\u001f\u007f]/
// Characters Windows refuses in file names, and bidirectional overrides (they reorder the display).
const REPLACE_RE = /[<>:"|?*‪-‮⁦-⁩]/g
const WINDOWS_DEVICE_RE = /^(con|prn|aux|nul|com[0-9¹²³]|lpt[0-9¹²³])(\..*)?$/i

class FilesError extends Error {
  constructor(message, code) {
    super(message)
    this.name = 'FilesError'
    this.code = code
  }
}

function noop() {}

/**
 * The name a peer-supplied file name is written under, or null when it is refused.
 *
 * File names in announcements and peer drive metadata come from other peers, and the only place
 * they reach the filesystem is the downloads directory. A name is refused when it is not a
 * string, is empty, longer than 100 characters or 255 UTF-8 bytes, contains a path separator
 * (`/` or `\`), a control character, or `..`, or consists only of dots, so the result is always
 * a single entry inside the target directory. Characters Windows does not allow (`<>:"|?*`) and
 * bidirectional overrides become `_`, trailing dots and spaces are removed, and Windows device
 * names (CON, NUL, COM1, ...) get a `_` prefix. The name is NFC-normalised where the runtime
 * supports it.
 */
function safeFileName(name) {
  if (typeof name !== 'string') return null
  let s = name
  try {
    s = s.normalize('NFC')
  } catch {}
  if (s.length === 0 || s.length > MAX_FILE_NAME) return null
  if (s.includes('/') || s.includes('\\')) return null
  if (CONTROL_RE.test(s)) return null
  if (s.includes('..')) return null
  s = s.replace(REPLACE_RE, '_').replace(/[. ]+$/, '')
  if (s.length === 0 || /^\.+$/.test(s)) return null
  if (WINDOWS_DEVICE_RE.test(s)) s = '_' + s
  if (utf8Length(s) > MAX_FILE_NAME_BYTES) return null
  return s
}

/** A finite number, or a numeric string of at most `maxLen` characters; else null. */
function toNumber(v, maxLen = 25) {
  if (typeof v === 'number') return Number.isFinite(v) ? v : null
  if (typeof v === 'string' && v.length <= maxLen && NUMERIC_RE.test(v)) return Number(v)
  return null
}

function optStr(v, max) {
  if (v === undefined || v === null) return ''
  return typeof v === 'string' && v.length <= max ? v : null
}

/**
 * File metadata as a peer or the UI hands it over (announcement, Ping/history list entry, drive
 * metadata, remote file of the UI), checked against the accept limits. Returns
 * `{ hash, contentHash, fileName, size, time, address, name, signature }` (`contentHash` in
 * lower case) or null; a file without a 64-hex `contentHash` is refused.
 */
function normalizeFile(raw) {
  if (!raw || typeof raw !== 'object') return null
  const L = S.ACCEPT.file
  if (!S.isHex64(raw.hash)) return null
  if (!S.isHex64(raw.contentHash)) return null
  if (typeof raw.fileName !== 'string' || raw.fileName.length > L.fileName) return null
  const size = toNumber(raw.size, L.size)
  if (size === null || size < 0) return null
  const time = toNumber(raw.time, L.time)
  if (time === null) return null
  const address = optStr(raw.address, L.address)
  const name = optStr(raw.name, L.name)
  const signature = optStr(raw.signature, L.signature)
  if (address === null || name === null || signature === null) return null
  return { hash: raw.hash, contentHash: raw.contentHash.toLowerCase(), fileName: raw.fileName, size, time, address, name, signature }
}

function hexKey(v) {
  return typeof v === 'string' && TOPIC_RE.test(v) ? v.toLowerCase() : null
}

function topicOf(topic) {
  const t = hexKey(topic)
  if (!t) throw new FilesError('topic must be 64 hex characters', 'HUGIN_FILES_INVALID')
  return t
}

function baseName(path) {
  const parts = String(path).split(/[\\/]/)
  return parts[parts.length - 1]
}

/** Stored size of a drive entry: the blob length, else the metadata size. */
function entrySize(entry) {
  const blob = entry && entry.value ? entry.value.blob : null
  if (blob && Number.isFinite(blob.byteLength)) return blob.byteLength
  const meta = entry && entry.value ? entry.value.metadata : null
  return (meta && toNumber(meta.size)) || 0
}

/** Insertion-ordered set with a size bound (the oldest entry is dropped first). */
class BoundedSet {
  constructor(max) {
    this.max = Math.max(1, max)
    this.set = new Set()
  }

  has(value) {
    return this.set.has(value)
  }

  add(value) {
    this.set.delete(value)
    this.set.add(value)
    while (this.set.size > this.max) this.set.delete(this.set.values().next().value)
    return this
  }

  delete(value) {
    return this.set.delete(value)
  }

  clear() {
    this.set.clear()
  }

  get size() {
    return this.set.size
  }
}

/** Fixed one-minute window: true (and counted) while below `limit`. */
function takeMinute(state, limit, now = Date.now()) {
  if (now - state.start >= 60000) {
    state.start = now
    state.count = 0
  }
  if (state.count >= limit) return false
  state.count++
  return true
}

/** The rate state of `key` in `map` (created when missing; the map keeps at most 2 × `maxKeys`). */
function rateOf(map, key, maxKeys) {
  let rate = map.get(key)
  if (!rate) {
    rate = { start: 0, count: 0 }
    map.set(key, rate)
    while (map.size > Math.max(1, maxKeys) * 2) map.delete(map.keys().next().value)
  }
  return rate
}

/** Resolves once a file write stream has opened its file; rejects with its open error. */
function opened(ws) {
  return new Promise((resolve, reject) => {
    const done = (err) => {
      ws.off('open', onopen)
      ws.off('error', done)
      if (err) reject(err)
      else resolve()
    }
    const onopen = () => done(null)
    ws.on('open', onopen)
    ws.on('error', done)
  })
}

function drained(ws) {
  return new Promise((resolve) => {
    const go = () => {
      ws.off('drain', go)
      ws.off('close', go)
      resolve()
    }
    ws.on('drain', go)
    ws.on('close', go)
  })
}

/**
 * Writes every chunk of `source` (a readable stream or async iterable) to the writable `ws`,
 * with backpressure, and ends it. Resolves once `ws` has finished and closed; rejects (and
 * destroys `ws`) when the source or the write fails.
 */
function writeAll(ws, source) {
  return new Promise((resolve, reject) => {
    let finished = false
    let closed = false
    let failure = null
    ws.on('finish', () => {
      finished = true
    })
    ws.on('error', (err) => {
      failure = failure || err
    })
    ws.on('close', () => {
      closed = true
      if (finished && !failure) resolve()
      else reject(failure || new FilesError('write stream closed early', 'HUGIN_FILES_WRITE'))
    })
    ;(async () => {
      for await (const chunk of source) {
        if (closed || failure) break
        if (!ws.write(chunk)) await drained(ws)
      }
      if (!closed && !failure) ws.end()
    })().catch((err) => {
      failure = failure || err
      if (!closed) ws.destroy(err)
    })
  })
}

/** The chunks of a readable stream (or async iterable) in one buffer. */
async function collect(source) {
  const chunks = []
  for await (const chunk of source) chunks.push(chunk)
  return chunks.length === 1 ? chunks[0] : b4a.concat(chunks)
}

/** Distinct non-empty address strings. */
function ownerList(owners) {
  if (!Array.isArray(owners)) return []
  return [...new Set(owners.filter((a) => typeof a === 'string' && a.length > 0))]
}

function sleep(ms) {
  return new Promise((resolve) => {
    const t = setTimeout(resolve, ms)
    if (t && typeof t.unref === 'function') t.unref()
  })
}

function withTimeout(promise, ms) {
  let timer = null
  const timeout = new Promise((resolve) => {
    timer = setTimeout(resolve, ms)
  })
  return Promise.race([Promise.resolve(promise).catch(noop), timeout]).finally(() => clearTimeout(timer))
}

class Files extends EventEmitter {
  /**
   * @param {object} [opts]
   * @param {object} [opts.host]  host hooks (README "Host hooks and events"), all optional except `paths`:
   *   `paths` ({ storage, downloads } or a function returning it; `storage` is the corestore
   *   root, `downloads` the directory files are saved to), `autoSyncFiles(topic, roomKey, dm,
   *   file) => boolean` (default: DMs only), `knownFile(hash) => boolean` (already stored or
   *   deleted by the user), `storageLimit() => bytes`, `identity() => { address, name }`,
   *   `sign(message) => Promise<string>` (XKR spend-key signature), `verify(message, address,
   *   signature) => Promise<boolean>` (file signatures), `log(level, msg, data)`.
   * @param {object} [opts.paths]  overrides `host.paths`
   * @param {object} [opts.fs]  filesystem module (default `require('#fs')`); uses `fs.promises`
   * @param {boolean} [opts.saveDownloads]  also write every fetched file to `paths.downloads`
   *   (native's behaviour; desktop keeps fetched files in storage until `saveToDownloads`)
   * @param {number} [opts.downloadTimeoutMs]  per block request (default 30 000)
   * @param {number} [opts.pruneIntervalMs]  0 disables the hourly prune
   * @param {number} [opts.pruneMaxAgeMs]  files older than this are pruned and not auto-synced
   * @param {number} [opts.pruneMaxBytes]  prune the oldest unsaved files above this total
   * @param {number} [opts.maxPeerDrives]  peer drives per room (the room releases a peer's
   *   drive when its last connection closes, `removePeer`)
   * @param {number} [opts.maxNotified]  hashes per room remembered as offered (`file:remote`)
   * @param {number} [opts.remotePerMinute]  `file:remote` events per peer drive and minute
   * @param {number} [opts.autoSyncMaxBytes]  larger files are offered, not auto-synced (50 MiB)
   * @param {number} [opts.autoSyncPerMinute]  auto-sync downloads per peer drive and minute (10)
   * @param {number} [opts.verifyPerMinute]  file signature checks per peer drive and minute (120)
   */
  constructor(opts = {}) {
    super()
    this.host = opts.host || {}
    const num = (v, d) => (typeof v === 'number' && Number.isFinite(v) && v >= 0 ? v : d)
    this.options = {
      saveDownloads: !!opts.saveDownloads,
      downloadTimeoutMs: num(opts.downloadTimeoutMs, DEFAULTS.downloadTimeoutMs),
      pruneIntervalMs: num(opts.pruneIntervalMs, DEFAULTS.pruneIntervalMs),
      pruneMaxAgeMs: num(opts.pruneMaxAgeMs, DEFAULTS.pruneMaxAgeMs),
      pruneMaxBytes: num(opts.pruneMaxBytes, DEFAULTS.pruneMaxBytes),
      maxPeerDrives: num(opts.maxPeerDrives, DEFAULTS.maxPeerDrives),
      maxNotified: num(opts.maxNotified, DEFAULTS.maxNotified),
      remotePerMinute: num(opts.remotePerMinute, DEFAULTS.remotePerMinute),
      autoSyncMaxBytes: num(opts.autoSyncMaxBytes, DEFAULTS.autoSyncMaxBytes),
      autoSyncPerMinute: num(opts.autoSyncPerMinute, DEFAULTS.autoSyncPerMinute),
      verifyPerMinute: num(opts.verifyPerMinute, DEFAULTS.verifyPerMinute)
    }
    this._fs = opts.fs || defaultFs
    this._pathSource = opts.paths || this.host.paths || null
    this._logHook = typeof opts.log === 'function' ? opts.log : typeof this.host.log === 'function' ? this.host.log : null

    this._rooms = new Map() // topic -> room
    this._closingRooms = new Map() // topic -> Promise of a closeRoom in progress
    this._downloading = new Set() // hashes being fetched
    this._removed = new Set() // hashes deleted, purged or pruned in this session (no auto re-fetch)
    this._saved = new Set() // hashes written to the downloads directory (kept by prune)
    this._limit = null
    this._pruneTimer = null
    this._pruning = null
    this._closing = null
    this._writeChain = Promise.resolve() // downloads-directory writes, one at a time
  }

  // -------------------------------------------------------------------------------------------
  // limits and hooks

  /** Storage limit in bytes: `setLimit`, else `host.storageLimit()`, else 100 GB. */
  get limit() {
    if (this._limit !== null) return this._limit
    if (typeof this.host.storageLimit === 'function') {
      try {
        const v = this.host.storageLimit()
        if (typeof v === 'number' && Number.isFinite(v) && v >= 0) return v
      } catch {}
    }
    return DEFAULTS.storageLimit
  }

  /** Bytes stored in the own drives of the open rooms. */
  get used() {
    let total = 0
    for (const room of this._rooms.values()) total += room.used
    return total
  }

  /** Sets the storage limit (the host persists it). */
  setLimit(bytes) {
    if (typeof bytes !== 'number' || !Number.isFinite(bytes) || bytes < 0) {
      throw new FilesError('setLimit: bytes must be a non-negative number', 'HUGIN_FILES_INVALID')
    }
    this._limit = Math.floor(bytes)
    return this._limit
  }

  _log(level, msg, data) {
    if (!this._logHook) return
    try {
      this._logHook(level, msg, data)
    } catch {}
  }

  _dir(kind) {
    let paths = this._pathSource
    if (typeof paths === 'function') paths = paths()
    const v = paths ? paths[kind] : null
    if (typeof v !== 'string' || v.length === 0) {
      throw new FilesError(`paths.${kind} is not set`, 'HUGIN_FILES_PATHS')
    }
    return v.replace(/[\\/]+$/, '') || v
  }

  _identity() {
    const id = this.host.identity
    const v = typeof id === 'function' ? id() : id
    return v && typeof v === 'object' ? v : {}
  }

  _autoSync(room, file) {
    const fn = this.host.autoSyncFiles
    if (typeof fn !== 'function') return room.dm
    try {
      return !!fn(room.topic, room.key, room.dm, file)
    } catch {
      return false
    }
  }

  _knownByHost(hash) {
    const fn = this.host.knownFile
    if (typeof fn !== 'function') return false
    try {
      return !!fn(hash)
    } catch {
      return false
    }
  }

  // -------------------------------------------------------------------------------------------
  // rooms

  /**
   * Opens (or returns) the drive of a room or DM swarm. Call it before joining the swarm, as
   * both apps do with `load_drive`. `key` is the room invite or, for a DM, the contact address
   * (carried in events and passed to `autoSyncFiles`). Returns the drive key (64 hex), the value
   * for `joined.driveKey`.
   */
  async openRoom(topic, { key = null, dm = false } = {}) {
    if (this._closing) throw new FilesError('closed', 'HUGIN_FILES_CLOSED')
    topic = topicOf(topic)
    // the same room still closing (leave + quick rejoin): its corestore must be closed before
    // another one opens on the same directory
    let pending
    while ((pending = this._closingRooms.get(topic))) await pending
    if (this._closing) throw new FilesError('closed', 'HUGIN_FILES_CLOSED')
    let room = this._rooms.get(topic)
    if (room) {
      if (key !== null && key !== undefined) room.key = key
      await room.opening
      return room.driveKey
    }
    room = {
      topic,
      key: key === undefined ? null : key,
      dm: !!dm,
      dir: null,
      store: null,
      drive: null,
      driveKey: null,
      peers: new Map(),
      notified: new BoundedSet(this.options.maxNotified),
      // 'driveKey:hash' of files whose signature did not verify or whose bytes did not match contentHash
      refused: new BoundedSet(this.options.maxNotified),
      remoteRates: new Map(), // peer drive key -> { start, count } of file:remote
      autoRates: new Map(), // peer drive key -> { start, count } of auto-sync downloads
      verifyRates: new Map(), // peer drive key -> { start, count } of signature checks
      used: 0,
      opening: null,
      closing: null
    }
    room.opening = this._openRoom(room)
    room.opening.catch(noop)
    this._rooms.set(topic, room)
    try {
      await room.opening
    } catch (err) {
      if (this._rooms.get(topic) === room) this._rooms.delete(topic)
      throw err
    }
    this._startPrune()
    return room.driveKey
  }

  async _openRoom(room) {
    room.dir = this._dir('storage') + '/' + room.topic + '/files'
    await this._fs.promises.mkdir(room.dir, { recursive: true })
    if (room.closing || this._closing) throw new FilesError('closed', 'HUGIN_FILES_CLOSED')
    room.store = new Corestore(room.dir)
    try {
      room.drive = new Hyperdrive(room.store.session())
      await room.drive.ready()
      room.driveKey = b4a.toString(room.drive.key, 'hex')
      let used = 0
      for await (const entry of room.drive.entries()) used += entrySize(entry)
      room.used = used
    } catch (err) {
      await room.store.close().catch(noop)
      throw err
    }
    this._log('info', 'drive opened', { topic: room.topic })
  }

  /** Open room, waiting for it to finish opening; null if unknown, closing or failed. */
  async _room(topic) {
    const t = hexKey(topic)
    const room = t ? this._rooms.get(t) : null
    if (!room || room.closing || this._closing) return null
    try {
      await room.opening
    } catch {
      return null
    }
    return room.closing || this._closing ? null : room
  }

  /** Own drive key of a room (64 hex) or null. */
  driveKey(topic) {
    const t = hexKey(topic)
    const room = t ? this._rooms.get(t) : null
    return room ? room.driveKey : null
  }

  /** Own Hyperdrive of an open room, or null (for host features this class does not cover). */
  drive(topic) {
    const t = hexKey(topic)
    const room = t ? this._rooms.get(t) : null
    return room && !room.closing ? room.drive : null
  }

  /** `[{ topic, key, dm, driveKey }]` of the open rooms. */
  rooms() {
    const out = []
    for (const room of this._rooms.values()) {
      if (!room.closing) out.push({ topic: room.topic, key: room.key, dm: room.dm, driveKey: room.driveKey })
    }
    return out
  }

  /**
   * Replicates the room's corestore over a room connection (a hyperswarm connection, i.e. a
   * NoiseSecretStream). Shares the stream's Protomux (`stream.userData`) with the
   * `hugin-messages` channel, so it can be called before or after that channel is opened.
   * Returns false when the room is not open.
   */
  replicate(socket, topic) {
    if (this._closing || !socket) return false
    const t = hexKey(topic)
    const room = t ? this._rooms.get(t) : null
    if (!room || room.closing) return false
    const attach = () => {
      if (room.closing || this._closing || !room.store || socket.destroyed) return
      try {
        room.store.replicate(socket)
      } catch (err) {
        this._log('warn', 'replication not started', { topic: room.topic, message: err && err.message })
      }
    }
    if (room.store) attach()
    else room.opening.then(attach, noop)
    return true
  }

  /**
   * Releases a peer's drive (the room calls it when the last connection that announced it
   * closed): its watcher is stopped (not awaited: a hyperbee watcher's destroy can wait for a
   * block that never comes) and the drive session closed, so `maxPeerDrives` counts live peers.
   * Returns false for an unknown room or drive. The replicated blocks stay in the corestore.
   */
  removePeer(topic, driveKey) {
    const t = hexKey(topic)
    const room = t ? this._rooms.get(t) : null
    const key = hexKey(driveKey)
    if (!room || !key) return false
    room.remoteRates.delete(key)
    room.autoRates.delete(key)
    room.verifyRates.delete(key)
    const peer = room.peers.get(key)
    if (!peer) return false
    room.peers.delete(key)
    peer.closed = true
    if (peer.watcher) peer.watcher.destroy().catch(noop)
    peer.drive.close().catch(noop)
    this._log('debug', 'peer drive released', { topic: room.topic })
    return true
  }

  /**
   * Opens a peer's drive (from `joined.driveKey`) and watches it: entries already replicated and
   * every new one are offered like an announcement (auto-sync or `file:remote`), attributed to
   * `owners` (the verified addresses of the connections that announced this drive key; see the
   * attribution rule at the top). Calling it again for an open drive replaces its owners.
   * Returns false for a malformed key, our own key, an unknown room or when the room has
   * `maxPeerDrives`.
   * @param {string} topic
   * @param {string} driveKey
   * @param {{ owners?: string[] }} [opts]
   */
  async addPeer(topic, driveKey, { owners } = {}) {
    const room = await this._room(topic)
    if (!room) return false
    const key = hexKey(driveKey)
    if (!key || key === room.driveKey) return false
    const peer = await this._peerDrive(room, key)
    if (!peer) return false
    if (owners !== undefined) peer.owners = ownerList(owners)
    this._watchPeer(room, peer)
    return true
  }

  /**
   * Replaces the owners of an open peer drive (the room calls it when the set of connections
   * that announced the drive changes). Returns false for an unknown room or drive.
   */
  setPeerOwners(topic, driveKey, owners) {
    const t = hexKey(topic)
    const room = t ? this._rooms.get(t) : null
    const key = hexKey(driveKey)
    const peer = room && key ? room.peers.get(key) : null
    if (!peer) return false
    peer.owners = ownerList(owners)
    return true
  }

  async _peerDrive(room, key) {
    let peer = room.peers.get(key)
    if (!peer) {
      if (room.peers.size >= this.options.maxPeerDrives) {
        this._log('warn', 'peer drive limit reached', { topic: room.topic })
        return null
      }
      const drive = new Hyperdrive(room.store.session(), b4a.from(key, 'hex'))
      peer = { key, drive, owners: [], watcher: null, watching: false, closed: false, ready: drive.ready() }
      peer.ready.catch(noop)
      room.peers.set(key, peer)
    }
    try {
      await peer.ready
    } catch (err) {
      if (room.peers.get(key) === peer) room.peers.delete(key)
      peer.drive.close().catch(noop)
      this._log('warn', 'peer drive not opened', { topic: room.topic, message: err && err.message })
      return null
    }
    return room.closing || this._closing || peer.closed ? null : peer
  }

  _watchPeer(room, peer) {
    if (peer.watching || peer.closed) return
    peer.watching = true
    const stopped = () => room.closing || this._closing || peer.closed
    const onEntry = (entry) => this._onPeerEntry(room, peer, entry)

    // entries replicated in an earlier session
    ;(async () => {
      for await (const entry of peer.drive.entries()) {
        if (stopped()) return
        await onEntry(entry)
      }
    })().catch((err) => {
      if (!stopped()) this._log('debug', 'peer drive scan ended', { message: err && err.message })
    })

    // new entries as they replicate
    const watcher = peer.drive.watch('/')
    peer.watcher = watcher
    ;(async () => {
      for await (const [current, previous] of watcher) {
        for await (const change of current.diff(previous.version, '/')) {
          if (stopped()) return
          if (change.left) await onEntry(change.left)
        }
      }
    })().catch((err) => {
      if (!stopped()) this._log('debug', 'peer drive watch ended', { message: err && err.message })
    })
  }

  async _onPeerEntry(room, peer, entry) {
    try {
      const meta = entry && entry.value ? entry.value.metadata : null
      if (!meta || typeof meta !== 'object' || entry.key !== '/' + meta.hash) return
      await this._offer(room, meta, peer.key, {
        owners: peer.owners,
        // drive entries wait for the signature-check budget instead of being skipped
        stopped: () => room.closing || this._closing || peer.closed
      })
    } catch (err) {
      this._log('debug', 'peer entry skipped', { message: err && err.message })
    }
  }

  /**
   * A file a peer announced (`file-shared`, entries of Ping / request-history / send-history
   * `files`): fetched at once when `autoSyncFiles` says so, it is recent and at most
   * `autoSyncMaxBytes`, otherwise offered to the UI with `file:remote` (once per hash and room).
   * `ctx.driveKey` is the sender's drive key from its `joined`, `ctx.address` the sender's
   * verified address (the owner for this file, see the attribution rule at the top; a file
   * without an address is the sender's) and `ctx.name` its name (used for the sender's own
   * files). Returns `{ action: 'download', result }`, `{ action: 'remote', file }` or
   * `{ action: 'ignored', reason }`.
   */
  async handleRemote(topic, file, ctx = {}) {
    const room = await this._room(topic)
    if (!room) return { action: 'ignored', reason: 'room' }
    if (!file || typeof file !== 'object') return { action: 'ignored', reason: 'invalid' }
    const owners = typeof ctx.address === 'string' && ctx.address.length > 0 ? [ctx.address] : []
    try {
      return await this._offer(room, { ...file }, ctx.driveKey || file.driveKey, { owners, ownerName: ctx.name })
    } catch (err) {
      if (room.closing || this._closing) return { action: 'ignored', reason: 'closed' }
      this._log('debug', 'remote file not handled', { message: err && err.message })
      return { action: 'ignored', reason: 'error' }
    }
  }

  async _offer(room, raw, driveKey, { owners = [], ownerName = null, stopped = null } = {}) {
    let f = normalizeFile(raw)
    if (!f) return { action: 'ignored', reason: 'invalid' }
    if (safeFileName(f.fileName) === null) return { action: 'ignored', reason: 'file_name' }
    const key = hexKey(driveKey)
    if (!key) return { action: 'ignored', reason: 'drive_key' }
    if (key === room.driveKey) return { action: 'ignored', reason: 'own' }
    if (this._removed.has(f.hash) || this._knownByHost(f.hash) || (await room.drive.exists('/' + f.hash))) {
      return { action: 'ignored', reason: 'known' }
    }
    // offered once: no further auto-sync attempts (Ping lists repeat every 10 s)
    if (room.notified.has(f.hash)) return { action: 'ignored', reason: 'notified' }
    if (room.closing || this._closing) return { action: 'ignored', reason: 'closed' }

    const attributed = await this._attribute(room, f, key, owners, stopped)
    if (attributed.reason) return { action: 'ignored', reason: attributed.reason }
    f = attributed.file
    if (owners.includes(f.address) && typeof ownerName === 'string' && ownerName.length > 0) f = { ...f, name: ownerName }
    if (room.notified.has(f.hash)) return { action: 'ignored', reason: 'notified' }
    if (room.closing || this._closing) return { action: 'ignored', reason: 'closed' }

    const maxAge = this.options.pruneMaxAgeMs
    const recent = !(maxAge > 0) || Date.now() - f.time <= maxAge
    if (recent && f.size <= this.options.autoSyncMaxBytes && this._autoSync(room, f) && takeMinute(rateOf(room.autoRates, key, this.options.maxPeerDrives), this.options.autoSyncPerMinute)) {
      const result = await this.download(room.topic, { ...f, driveKey: key }, { auto: true })
      if (result.success || result.error === 'known' || result.error === 'busy' || result.error === 'closed' || result.error === 'content') {
        return { action: 'download', result }
      }
      // not fetched (limit, size, timeout, ...): offer it to the UI instead
    }
    // offers to the UI are rate-limited: `remotePerMinute` per peer drive (not remembered
    // as offered, so a later listing can offer it)
    if (!takeMinute(rateOf(room.remoteRates, key, this.options.maxPeerDrives), this.options.remotePerMinute)) return { action: 'ignored', reason: 'rate' }
    room.notified.add(f.hash)
    const remote = {
      fileName: f.fileName,
      address: f.address,
      size: f.size,
      topic: room.topic,
      key: room.dm ? f.address : room.key,
      chat: f.address,
      hash: f.hash,
      contentHash: f.contentHash,
      name: f.name,
      time: f.time,
      signature: f.signature,
      driveKey: key
    }
    this.emit(EVENTS.REMOTE, { key: room.key, topic: room.topic, dm: room.dm, file: remote })
    return { action: 'remote', file: remote }
  }

  /**
   * Attribution of a peer file (see the rule at the top): `{ file }` with its address filled in
   * (a file without one is the only owner's), or `{ reason }` (`address`: not an owner's and not
   * signed, `signature`: its signature does not verify, `rate`: no signature-check budget left,
   * `closed`). With `stopped` (drive entries) the check waits for the budget instead.
   */
  async _attribute(room, f, key, owners, stopped) {
    const memo = key + ':' + f.hash
    if (room.refused.has(memo)) return { reason: 'refused' }
    if (!f.address) {
      if (owners.length !== 1) return { reason: 'address' }
      f = { ...f, address: owners[0] }
    }
    const own = owners.includes(f.address)
    if (!f.signature) return own ? { file: f } : { reason: 'address' }
    const rate = rateOf(room.verifyRates, key, this.options.maxPeerDrives)
    while (!takeMinute(rate, this.options.verifyPerMinute)) {
      if (!stopped) return { reason: 'rate' }
      if (stopped()) return { reason: 'closed' }
      await sleep(Math.min(1000, Math.max(10, rate.start + 60000 - Date.now())))
    }
    if (room.closing || this._closing || (stopped && stopped())) return { reason: 'closed' }
    const ok = await this._verifyFile(room, f)
    if (ok === true) return { file: f }
    if (ok === null && own) return { file: f } // no verifier: the owner's own files only
    if (ok === false) room.refused.add(memo)
    return { reason: ok === false ? 'signature' : 'address' }
  }

  /** `host.verify` of a file signature: true / false, or null without a verifier (or when it fails). */
  async _verifyFile(room, f) {
    const fn = this.host.verify
    if (typeof fn !== 'function') return null
    let payload
    try {
      payload = wire.fileSigningPayload({ ...f, topic: room.topic })
    } catch {
      return false
    }
    try {
      return (await fn(payload, f.address, f.signature)) === true
    } catch (err) {
      this._log('debug', 'file signature check failed', { message: err && err.message })
      return null
    }
  }

  // -------------------------------------------------------------------------------------------
  // share / download

  /**
   * Stores a file in the room's drive and returns the `file-shared` announcement (a
   * `wire.fileShared` object; the room code encodes and sends it). `source` is a file path or the
   * bytes. `meta`: `fileName` (default: the path's base name), `time` (default now), `hash`
   * (64 hex, default random as native does), `address` / `name` (default `host.identity()`),
   * `signature` (default `host.sign(wire.fileSigningPayload(...))` with the room topic). The
   * size is the byte length and `contentHash` the BLAKE2b-256 of the bytes (always computed
   * here; a given `signature` must cover it). Throws FilesError (`HUGIN_FILES_NO_ROOM`, `_NAME`, `_SIGN`,
   * `_EXISTS`, `_LIMIT`) or WireError (a field an old peer would refuse).
   */
  async share(topic, source, meta = {}) {
    const room = await this._room(topic)
    if (!room) throw new FilesError('room is not open', 'HUGIN_FILES_NO_ROOM')
    let bytes
    if (typeof source === 'string') bytes = await this._fs.promises.readFile(source)
    else if (source instanceof Uint8Array) bytes = source
    else throw new FilesError('share: source must be a file path or a Uint8Array', 'HUGIN_FILES_INVALID')

    const fileName = meta.fileName !== undefined ? meta.fileName : typeof source === 'string' ? baseName(source) : undefined
    if (safeFileName(fileName) === null) throw new FilesError('file name is not allowed', 'HUGIN_FILES_NAME')
    const id = this._identity()
    const address = meta.address !== undefined ? meta.address : id.address
    const name = meta.name !== undefined ? meta.name : id.name
    const hash = meta.hash !== undefined ? meta.hash : randomKey()
    const time = meta.time !== undefined ? meta.time : Date.now()
    const size = bytes.byteLength
    const contentHash = blake2b256Hex(bytes)
    let signature = meta.signature
    if (signature === undefined) {
      if (typeof this.host.sign !== 'function') throw new FilesError('no signature and no host.sign', 'HUGIN_FILES_SIGN')
      signature = await this.host.sign(wire.fileSigningPayload({ topic: room.topic, hash, contentHash, size, time, fileName, address }))
    }
    const announcement = wire.fileShared({ fileName, address, name, topic: room.topic, size, time, hash, contentHash, signature })

    if (await room.drive.exists('/' + hash)) throw new FilesError('a file with this hash is stored already', 'HUGIN_FILES_EXISTS')
    if (this.used + size > this.limit) throw new FilesError('storage limit reached', 'HUGIN_FILES_LIMIT')
    await room.drive.put('/' + hash, bytes, {
      metadata: { name, topic: room.topic, time, size, hash, contentHash, fileName, address, signature, info: FILE_SHARED, type: FILE_TYPE }
    })
    room.used += size
    this._removed.delete(hash)
    this.emit(EVENTS.UPLOADED, {
      hash,
      contentHash,
      fileName,
      chat: address,
      address,
      name,
      time,
      size,
      topic: room.topic,
      key: room.key,
      dm: room.dm,
      path: typeof source === 'string' ? source : 'storage'
    })
    return announcement
  }

  _payload(room, f, driveKey, auto) {
    return {
      hash: f.hash,
      contentHash: f.contentHash,
      fileName: f.fileName,
      chat: f.address,
      address: f.address,
      name: f.name,
      time: f.time,
      size: f.size,
      topic: room.topic,
      key: room.key,
      dm: room.dm,
      driveKey,
      auto
    }
  }

  /**
   * Fetches a file from a peer drive into the room's drive (and, with `saveDownloads`, into the
   * downloads directory). `file`: `{ driveKey, hash, contentHash, fileName, size, time,
   * address, name, signature }` (the `file` of `file:remote`, or an announcement plus
   * `driveKey`). Refused without fetching when the hash is known (`knownFile`, or already in
   * our drive), the file name is not safe (see `safeFileName`), or the stored size would pass
   * the storage limit. The fetched bytes are hashed while they arrive; when their BLAKE2b-256
   * differs from `contentHash` the file is not kept (error `content`) and the fetched peer
   * blocks are dropped. `opts.auto` marks an auto-sync (also skips hashes removed in this
   * session). Returns `{ success: true, hash, path }` (`path` = the written file or 'storage')
   * or `{ success: false, error }` with error `room`, `invalid`, `file_name`, `drive_key`,
   * `known`, `busy`, `drive`, `not_found`, `size`, `too_large`, `limit`, `content`, `timeout`,
   * `closed` or `error`; the failures that are not routine also emit `file:error`.
   */
  /**
   * The entry at `path` in a peer drive, waiting up to `timeout` ms for it to replicate. The
   * announcement travels on the room channel and the drive's new length on the hypercore
   * channel, so the announcement can arrive first, even after `update()` has returned with the
   * length we already knew: wait for the peer core to grow and look again until the deadline.
   */
  async _peerEntry(room, peer, path, timeout) {
    const deadline = Date.now() + timeout
    const core = peer.drive.core
    while (!room.closing && !this._closing) {
      const left = deadline - Date.now()
      if (left <= 0) return null
      const entry = await peer.drive.entry(path, { timeout: left }).catch(() => null)
      if (entry) return entry
      if (deadline - Date.now() <= 0) return null
      let onappend = null
      const grown = new Promise((resolve) => {
        onappend = resolve
        core.once('append', onappend)
      })
      await withTimeout(Promise.race([grown, peer.drive.update({ wait: true })]), Math.min(deadline - Date.now(), 1000))
      core.off('append', onappend)
    }
    return null
  }

  async download(topic, file, opts = {}) {
    const auto = !!opts.auto
    const room = await this._room(topic)
    if (!room) return { success: false, error: 'room' }
    const f = normalizeFile(file)
    const key = hexKey(file && file.driveKey)
    const base = f
      ? this._payload(room, f, key, auto)
      : { hash: file && typeof file.hash === 'string' ? file.hash : '', topic: room.topic, key: room.key, dm: room.dm, auto }
    const refuse = (error, message, emit = true) => {
      if (emit) this.emit(EVENTS.ERROR, { ...base, error, message })
      return { success: false, error }
    }
    if (!f) return refuse('invalid', 'malformed file metadata', !auto)
    if (safeFileName(f.fileName) === null) return refuse('file_name', 'file name is not allowed', !auto)
    if (!key || key === room.driveKey) return refuse('drive_key', 'no peer drive key', !auto)
    if (this._downloading.has(f.hash)) return { success: false, error: 'busy' }
    this._downloading.add(f.hash)
    let active = null
    try {
      if ((auto && this._removed.has(f.hash)) || this._knownByHost(f.hash) || (await room.drive.exists('/' + f.hash))) {
        return { success: false, error: 'known' }
      }
      const peer = await this._peerDrive(room, key)
      if (!peer) return room.closing || this._closing ? { success: false, error: 'closed' } : refuse('drive', 'peer drive not available')
      peer.active = (peer.active || 0) + 1
      active = peer
      if (peer.clearing) await peer.clearing
      this.emit(EVENTS.DOWNLOADING, base)

      const path = '/' + f.hash
      const timeout = this.options.downloadTimeoutMs
      const entry = await this._peerEntry(room, peer, path, timeout)
      const blob = entry && entry.value ? entry.value.blob : null
      if (!blob || !Number.isFinite(blob.byteLength)) return refuse('not_found', 'file not in the peer drive')
      if (blob.byteLength !== f.size) return refuse('size', 'the stored size differs from the announced one')
      if (auto && blob.byteLength > this.options.autoSyncMaxBytes) return refuse('too_large', 'larger than the auto-sync limit', false)
      if (this.used + blob.byteLength > this.limit) return refuse('limit', 'storage limit reached')

      // replicate the blob (its blocks are stored in the corestore, not kept in memory), then
      // copy it into our drive as a stream
      let fetched
      try {
        fetched = await this._fetchBlob(peer.drive, blob, base)
      } catch (err) {
        this._clearPeerBlocks(peer, path)
        throw err
      }
      const { blobs } = fetched
      if (room.closing || this._closing) return { success: false, error: 'closed' }
      if (fetched.contentHash !== f.contentHash) {
        this._clearPeerBlocks(peer, path)
        // not offered or fetched again from this drive (Ping lists repeat it)
        room.refused.add(key + ':' + f.hash)
        return refuse('content', 'the file bytes do not match the announced content hash')
      }
      if (this.used + blob.byteLength > this.limit) return refuse('limit', 'storage limit reached')
      const metadata = {
        name: f.name,
        topic: room.topic,
        time: f.time,
        size: f.size,
        hash: f.hash,
        contentHash: f.contentHash,
        fileName: f.fileName,
        address: f.address,
        signature: f.signature,
        info: FILE_SHARED,
        type: FILE_TYPE,
        syncedAt: Date.now()
      }
      await writeAll(room.drive.createWriteStream(path, { metadata }), blobs.createReadStream(blob, { wait: false }))
      room.used += blob.byteLength
      this._removed.delete(f.hash)
      // the copy in our drive is what we keep and serve; drop the cached peer blocks
      this._clearPeerBlocks(peer, path)

      let written = 'storage'
      if (this.options.saveDownloads) {
        try {
          written = await this._writeUnique(this._dir('downloads'), safeFileName(f.fileName), () => room.drive.createReadStream(path, { wait: false }))
          this._saved.add(f.hash)
        } catch (err) {
          this.emit(EVENTS.ERROR, { ...base, error: 'write', message: err && err.message })
        }
      }
      this.emit(EVENTS.PROGRESS, { ...base, progress: 100 })
      this.emit(EVENTS.DOWNLOADED, { ...base, path: written })
      return { success: true, hash: f.hash, path: written }
    } catch (err) {
      if (room.closing || this._closing) return { success: false, error: 'closed' }
      const timedOut = err && err.code === 'REQUEST_TIMEOUT'
      return refuse(timedOut ? 'timeout' : 'error', (err && err.message) || String(err))
    } finally {
      this._downloading.delete(f.hash)
      if (active) {
        active.active--
        if (active.active === 0) this._flushPeerClears(active)
      }
    }
  }

  /**
   * Replicates the blocks of a peer blob into the corestore (reading it through, `got` bytes
   * counted and hashed, nothing kept in memory), with `file:progress` every 10 %. Returns
   * `{ blobs, contentHash }`: the peer drive's blob store and the BLAKE2b-256 (hex) of the
   * bytes read. Throws when the peer sends more or less than the blob holds, or on a timeout.
   */
  /**
   * Waits up to `timeout` ms until the peer's blob core is known to hold `end` blocks. The
   * entry and its blobs live in two cores whose new lengths can arrive separately, so a blob
   * listed in a just-replicated entry can lie past the blob core length known so far.
   */
  async _blobsReach(core, end, timeout) {
    if (!core || !Number.isFinite(end) || core.length >= end) return
    const deadline = Date.now() + timeout
    while (core.length < end && !core.closing && !this._closing) {
      const left = deadline - Date.now()
      if (left <= 0) return
      let onappend = null
      const grown = new Promise((resolve) => {
        onappend = resolve
        core.once('append', onappend)
      })
      await withTimeout(Promise.race([grown, core.update({ wait: true })]), Math.min(left, 1000))
      core.off('append', onappend)
    }
  }

  /**
   * Drops the cached peer blocks of `path` once no download from that peer drive is running;
   * a download from that drive starts only after a running clear has finished.
   */
  _clearPeerBlocks(peer, path) {
    if (!peer.clears) peer.clears = new Set()
    peer.clears.add(path)
    if (!peer.active) this._flushPeerClears(peer)
  }

  _flushPeerClears(peer) {
    if (!peer.clears || peer.clears.size === 0) return
    const paths = [...peer.clears]
    peer.clears.clear()
    const run = (peer.clearing || Promise.resolve()).then(() => Promise.all(paths.map((p) => peer.drive.clear(p).catch(noop))))
    peer.clearing = run
    run.then(() => {
      if (peer.clearing === run) peer.clearing = null
    }, noop)
  }

  async _fetchBlob(drive, blob, base) {
    const blobs = await drive.getBlobs()
    if (!blobs) throw new FilesError('peer drive has no blob store', 'HUGIN_FILES_NOT_FOUND')
    await this._blobsReach(blobs.core, blob.blockOffset + blob.blockLength, this.options.downloadTimeoutMs)
    const total = blob.byteLength
    const hasher = blake2b256Hasher()
    let got = 0
    let step = 0
    for await (const chunk of blobs.createReadStream(blob, { timeout: this.options.downloadTimeoutMs })) {
      got += chunk.byteLength
      if (got > total) throw new FilesError('peer sent more data than the entry holds', 'HUGIN_FILES_SIZE')
      hasher.update(chunk)
      const pct = total > 0 ? Math.floor((got * 100) / total) : 100
      if (pct < 100 && pct >= step + 10) {
        step = pct - (pct % 10)
        this.emit(EVENTS.PROGRESS, { ...base, progress: step })
      }
    }
    if (got !== total) throw new FilesError('incomplete file', 'HUGIN_FILES_SIZE')
    return { blobs, contentHash: hasher.digest() }
  }

  /**
   * Writes `data` as `dir/name`, or `dir/name (n).ext` when that exists, and never overwrites.
   * `name` must come from `safeFileName`. `data` is the bytes, or a function returning a
   * readable stream (or async iterable) of them, which is written as a stream (opened again for
   * every name tried).
   *
   * Where the fs module defines `constants.O_EXCL` (Node), the write is an exclusive create
   * (`wx`), which also refuses a symlink at the target path. bare-fs 4.5.3 does not define
   * `O_EXCL`, so its `wx` acts like `w` (truncate and overwrite); there the name is
   * checked with `lstat` first (an existing file or symlink counts as taken). Writes of one
   * Files instance run one at a time, so its own writes cannot race each other.
   */
  _writeUnique(dir, name, data) {
    const run = this._writeChain.then(() => this._writeUniqueNow(dir, name, data))
    this._writeChain = run.catch(noop)
    return run
  }

  async _writeUniqueNow(dir, name, data) {
    if (!name) throw new FilesError('file name is not allowed', 'HUGIN_FILES_NAME')
    const fsp = this._fs.promises
    const exclusive = !!(this._fs.constants && typeof this._fs.constants.O_EXCL === 'number')
    const streamed = typeof data === 'function'
    const canStream = typeof this._fs.createWriteStream === 'function'
    await fsp.mkdir(dir, { recursive: true })
    const dot = name.lastIndexOf('.')
    const stem = dot > 0 ? name.slice(0, dot) : name
    const ext = dot > 0 ? name.slice(dot) : ''
    for (let n = 0; n < 1000; n++) {
      const candidate = n === 0 ? name : `${stem} (${n})${ext}`
      const full = dir + '/' + candidate
      if (!exclusive && (await this._taken(full))) continue
      const flag = exclusive ? 'wx' : 'w'
      try {
        if (streamed && canStream) {
          const ws = this._fs.createWriteStream(full, { flags: flag })
          await opened(ws)
          try {
            await writeAll(ws, data())
          } catch (err) {
            // the file is ours (just created): remove what was written of it
            await fsp.unlink(full).catch(noop)
            throw err
          }
        } else {
          const bytes = streamed ? await collect(data()) : data
          await fsp.writeFile(full, bytes, exclusive ? { flag: 'wx' } : undefined)
        }
        return full
      } catch (err) {
        if (exclusive && err && err.code === 'EEXIST') continue
        throw err
      }
    }
    throw new FilesError('no free file name', 'HUGIN_FILES_EXISTS')
  }

  /** True when something (file, directory or symlink, even a dangling one) exists at `path`. */
  async _taken(path) {
    try {
      await this._fs.promises.lstat(path)
      return true
    } catch (err) {
      if (err && err.code === 'ENOENT') return false
      throw err
    }
  }

  /**
   * Copies a stored file into the downloads directory under a safe, unused name. Returns
   * `{ success: true, filePath }` or `{ success: false, error }` (the shape both apps return
   * today).
   */
  async saveToDownloads(hash, fileName, topic) {
    const room = await this._room(topic)
    if (!room) return { success: false, error: 'Room not found' }
    const name = safeFileName(fileName)
    if (name === null) return { success: false, error: 'File name is not allowed' }
    if (!S.isHex64(hash)) return { success: false, error: 'File not found in storage' }
    try {
      const entry = await room.drive.entry('/' + hash, { wait: false })
      if (!entry || !entry.value || !entry.value.blob) return { success: false, error: 'File not found in storage' }
      const filePath = await this._writeUnique(this._dir('downloads'), name, () => room.drive.createReadStream('/' + hash, { wait: false }))
      this._saved.add(hash)
      return { success: true, filePath }
    } catch (err) {
      this._log('warn', 'save to downloads failed', { message: err && err.message })
      return { success: false, error: (err && err.message) || String(err) }
    }
  }

  // -------------------------------------------------------------------------------------------
  // queries

  /** Metadata of every file in the room's drive (the source of Ping/history `files`). */
  async list(topic) {
    const room = await this._room(topic)
    if (!room) return []
    const out = []
    for await (const entry of room.drive.entries()) {
      const meta = entry.value ? entry.value.metadata : null
      if (meta && meta.hash) out.push(meta)
    }
    return out
  }

  /** The bytes of a stored file, or null. */
  async read(hash, topic) {
    const room = await this._room(topic)
    if (!room || !S.isHex64(hash)) return null
    try {
      return await room.drive.get('/' + hash, { wait: false })
    } catch {
      return null
    }
  }

  /**
   * `{ totalSize, totalFiles, limit, used, rooms: [{ topic, key, dm, size, fileCount,
   * files: [{ hash, fileName, size, time, savedToDisk }] }] }` (desktop's shape plus key/dm/used;
   * files newest first).
   */
  async stats() {
    const rooms = []
    let totalSize = 0
    let totalFiles = 0
    for (const room of [...this._rooms.values()]) {
      if (!(await this._room(room.topic))) continue
      const files = []
      let size = 0
      try {
        for await (const entry of room.drive.entries()) {
          const meta = entry.value ? entry.value.metadata : null
          if (!meta || !meta.hash) continue
          const s = entrySize(entry)
          size += s
          files.push({
            hash: meta.hash,
            fileName: typeof meta.fileName === 'string' ? meta.fileName : 'unknown',
            size: s,
            time: toNumber(meta.time) || toNumber(meta.syncedAt) || 0,
            savedToDisk: this._saved.has(meta.hash)
          })
        }
      } catch (err) {
        this._log('warn', 'stats scan failed', { topic: room.topic, message: err && err.message })
      }
      files.sort((a, b) => b.time - a.time)
      totalSize += size
      totalFiles += files.length
      rooms.push({ topic: room.topic, key: room.key, dm: room.dm, size, fileCount: files.length, files })
    }
    return { totalSize, totalFiles, limit: this.limit, used: this.used, rooms }
  }

  // -------------------------------------------------------------------------------------------
  // removal

  async _remove(room, hashes, reason) {
    const removed = []
    for (const hash of hashes) {
      const path = '/' + hash
      try {
        const entry = await room.drive.entry(path, { wait: false })
        if (!entry) continue
        // clear the blob blocks first: `del` alone only drops the index entry
        await room.drive.clear(path).catch(noop)
        await room.drive.del(path)
        room.used = Math.max(0, room.used - entrySize(entry))
        removed.push(hash)
      } catch (err) {
        this._log('warn', 'file not removed', { topic: room.topic, message: err && err.message })
      }
      this._removed.add(hash)
      this._saved.delete(hash)
    }
    if (removed.length) this.emit(EVENTS.REMOVED, { topic: room.topic, key: room.key, dm: room.dm, hashes: removed, reason })
    return removed
  }

  /**
   * Removes one file from the room's drive (index entry and blob blocks). Returns true when the
   * file is no longer stored (also when it was not), false for an unknown room or a malformed
   * hash. Emits `file:removed` (reason `delete`) when something was removed.
   */
  async deleteFile(hash, topic) {
    const room = await this._room(topic)
    if (!room || !S.isHex64(hash)) return false
    await this._remove(room, [hash], 'delete')
    return !(await room.drive.exists('/' + hash))
  }

  /** Removes every file of a room's drive; returns the number removed (`file:removed`, reason `purge`). */
  async purgeRoom(topic) {
    const room = await this._room(topic)
    if (!room) return 0
    const hashes = []
    for await (const entry of room.drive.entries()) {
      const meta = entry.value ? entry.value.metadata : null
      if (meta && typeof meta.hash === 'string' && entry.key === '/' + meta.hash) hashes.push(meta.hash)
    }
    const removed = await this._remove(room, hashes, 'purge')
    return removed.length
  }

  /**
   * Both apps' hourly clean-up: removes files not saved to the downloads directory that are
   * older than `maxAgeMs` (by `syncedAt`, else `time`), then, while the total is above
   * `maxBytes`, the oldest unsaved ones. Returns the number removed (`file:removed`, reason
   * `prune`).
   */
  async prune({ maxAgeMs = this.options.pruneMaxAgeMs, maxBytes = this.options.pruneMaxBytes, now = Date.now() } = {}) {
    const all = []
    for (const room of [...this._rooms.values()]) {
      if (!(await this._room(room.topic))) continue
      try {
        for await (const entry of room.drive.entries()) {
          const meta = entry.value ? entry.value.metadata : null
          if (!meta || typeof meta.hash !== 'string' || entry.key !== '/' + meta.hash) continue
          const at = toNumber(meta.syncedAt) || toNumber(meta.time) || 0
          all.push({ room, hash: meta.hash, size: entrySize(entry), at })
        }
      } catch (err) {
        this._log('warn', 'prune scan failed', { topic: room.topic, message: err && err.message })
      }
    }
    const doomed = new Set()
    for (const e of all) {
      if (!this._saved.has(e.hash) && maxAgeMs > 0 && now - e.at > maxAgeMs) doomed.add(e)
    }
    const remaining = all.filter((e) => !doomed.has(e))
    const total = remaining.reduce((sum, e) => sum + e.size, 0)
    if (total > maxBytes) {
      const candidates = remaining.filter((e) => !this._saved.has(e.hash)).sort((a, b) => a.at - b.at)
      let freed = 0
      for (const e of candidates) {
        if (freed >= total - maxBytes) break
        doomed.add(e)
        freed += e.size
      }
    }
    let count = 0
    const byRoom = new Map()
    for (const e of doomed) {
      if (!byRoom.has(e.room)) byRoom.set(e.room, [])
      byRoom.get(e.room).push(e.hash)
    }
    for (const [room, hashes] of byRoom) {
      if (room.closing || this._closing) continue
      count += (await this._remove(room, hashes, 'prune')).length
    }
    if (count) this._log('info', 'pruned files', { count })
    return count
  }

  _startPrune() {
    if (this._pruneTimer || !(this.options.pruneIntervalMs > 0) || this._closing) return
    const run = () => {
      if (this._pruning || this._closing) return
      this._pruning = this.prune()
        .catch((err) => this._log('warn', 'prune failed', { message: err && err.message }))
        .finally(() => {
          this._pruning = null
        })
    }
    this._pruneTimer = setInterval(run, this.options.pruneIntervalMs)
    if (typeof this._pruneTimer.unref === 'function') this._pruneTimer.unref()
    run()
  }

  // -------------------------------------------------------------------------------------------
  // lifecycle

  async _closeRoom(room) {
    if (room.closing) return room.closing
    room.closing = (async () => {
      try {
        await room.opening
      } catch {}
      // A peer drive watcher can be in the middle of a diff that waits, without a timeout, for a
      // block from a peer that has gone (it completes when the peer comes back), and its
      // destroy() waits for that diff. Closing the corestore does not end such a read, so do
      // not wait for the watchers: the watch loop checks `closing` before it handles anything.
      for (const peer of room.peers.values()) {
        if (peer.watcher) peer.watcher.destroy().catch(noop)
      }
      for (const peer of room.peers.values()) await peer.drive.close().catch(noop)
      room.peers.clear()
      if (room.drive) await room.drive.close().catch(noop)
      if (room.store) await room.store.close().catch(noop)
    })()
    return room.closing
  }

  /**
   * Closes a room's drives (for leaving a room); the data stays on disk. An `openRoom` of the
   * same topic waits until the corestore is closed.
   */
  async closeRoom(topic) {
    const t = hexKey(topic)
    const room = t ? this._rooms.get(t) : null
    if (!room) return false
    this._rooms.delete(t)
    const closing = this._closeRoom(room)
      .catch(noop)
      .finally(() => {
        if (this._closingRooms.get(t) === closing) this._closingRooms.delete(t)
      })
    this._closingRooms.set(t, closing)
    await closing
    return true
  }

  /** Stops the prune timer and closes every drive and corestore. */
  close() {
    if (this._closing) return this._closing
    this._closing = (async () => {
      if (this._pruneTimer) clearInterval(this._pruneTimer)
      this._pruneTimer = null
      const rooms = [...this._rooms.values()]
      this._rooms.clear()
      await Promise.all(rooms.map((room) => this._closeRoom(room)))
      await Promise.all([...this._closingRooms.values()])
      if (this._pruning) await this._pruning
    })()
    return this._closing
  }
}

module.exports = {
  Files,
  FilesError,
  EVENTS,
  DEFAULTS,
  MAX_FILE_NAME,
  safeFileName,
  normalizeFile
}
