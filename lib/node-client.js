'use strict'

// hugin-network/node: the client side of hugin-node (and of xkrd `--hugin-relay`, same protocol), as
// hugin-desktop (`swarm.cjs` NodeConnection) and hugin-native (`bare/swarm.js` NodeConnection)
// run it today, in one class: the client-only swarm on the public or a private node topic, the
// bare-rpc PACKET channel, the packet router, store-and-forward sync and polling, job requests,
// and posts/registrations paid with proof of work.
//
// Packets are built and parsed by `push.js`, PoW by
// `pow.js` (on hugin-pow, with the host's hashing backend), the framing by `rpc.js`. The two
// apps differ in how they keep the connection; the `preset` option selects either behaviour (see
// PRESETS).
//
// No Node-only APIs: runs under Node and Bare.

const EventEmitter = require('bare-events')
const b4a = require('b4a')
const { createHuginSwarm } = require('./swarm.js')
const keys = require('./keys.js')
const push = require('./push.js')
const pow = require('./pow.js')
const { RpcChannel } = require('./rpc.js')
const { NODE_PACKET_COMMAND, NODE_RPC_REPLY, MAX_NODE_SYNC_MESSAGES } = require('./constants.js')
const { randomKey } = require('./bytes.js')

/**
 * Connection and polling behaviour of each app today.
 *
 * desktop: one connection (`maxPeers` 1, further connections are closed); after a connection
 *   error, refresh discovery every 10 s until connected, forever; a post without a connection
 *   fails at once (and starts the reconnect loop); sync gives up after 2 s; polling every 15 s
 *   (first run after 5 s), `since` moves to now - 1 s after a non-empty answer and back by 30 s
 *   on every new connection.
 * native: up to 3 connections, the extra ones kept as backups and promoted when the active one
 *   fails; reconnect = 4 discovery refreshes 2 s apart (then, only with `fallbackToPublic: true`,
 *   a reset to the public node topic, announced with `node:reset`); a
 *   post waits up to 25 s for a connection; polling every 3 s for at most 10 runs (pushed
 *   messages cover the rest), `since` = now after a non-empty answer.
 *
 * Both: jobs above `powMaxDifficulty` (default 2000) are not mined; after `powMaxTooHardJobs`
 * (3) such jobs in a row during a share search the client moves to another node (see
 * `switchNode`).
 */
const PRESETS = Object.freeze({
  desktop: Object.freeze({
    maxPeers: 1,
    keepBackups: false,
    refreshIntervalMs: 10000,
    maxReconnectTries: Infinity,
    fallbackToPublic: false,
    syncTimeoutMs: 2000,
    jobTimeoutMs: 10000,
    jobWaitMs: 2500,
    postTimeoutMs: 60000,
    waitForConnectionMs: 0,
    sendReconnectWaitMs: 5000,
    maxAttempts: 3,
    maxRecalcRetries: 3,
    powMaxJobTimeMs: pow.POW_MAX_JOB_TIME_MS,
    powRoundMs: 30000,
    powMaxDifficulty: pow.DEFAULT_MAX_DIFFICULTY,
    powMaxTooHardJobs: pow.POW_MAX_TOO_HARD_JOBS,
    poll: Object.freeze({
      intervalMs: 15000,
      initialDelayMs: 5000,
      advanceSkewMs: 1000,
      rewindOnConnectMs: 30000,
      maxRuns: Infinity
    })
  }),
  native: Object.freeze({
    maxPeers: 3,
    keepBackups: true,
    refreshIntervalMs: 2000,
    maxReconnectTries: 4,
    fallbackToPublic: false,
    syncTimeoutMs: 10000,
    jobTimeoutMs: 10000,
    jobWaitMs: 2500,
    postTimeoutMs: 60000,
    waitForConnectionMs: 25000,
    sendReconnectWaitMs: 5000,
    maxAttempts: 3,
    maxRecalcRetries: 3,
    powMaxJobTimeMs: pow.POW_MAX_JOB_TIME_MS,
    powRoundMs: pow.POW_ROUND_MS,
    powMaxDifficulty: pow.DEFAULT_MAX_DIFFICULTY,
    powMaxTooHardJobs: pow.POW_MAX_TOO_HARD_JOBS,
    poll: Object.freeze({
      intervalMs: 3000,
      initialDelayMs: 3000,
      advanceSkewMs: 0,
      rewindOnConnectMs: 0,
      maxRuns: 10
    })
  })
})

const NO_CONNECTION = 'No connection to node'

/** Nodes of the public topic the client keeps away from after `switchNode` (per swarm). */
const MAX_SKIPPED_NODES = 64

const OPTION_KEYS = Object.keys(PRESETS.desktop).filter((k) => k !== 'poll')

function noop() {}

function hex(bytes) {
  return bytes ? b4a.toString(bytes, 'hex') : null
}

/**
 * The hugin-pow backend from the options: `backend` as given, else one built from `findShare`
 * and/or `hash`; null without any of them.
 */
function powBackend({ backend, findShare, hash }) {
  if (backend && typeof backend === 'object' && (typeof backend.findShare === 'function' || typeof backend.hash === 'function')) {
    return backend
  }
  const b = {}
  if (typeof findShare === 'function') b.findShare = findShare
  if (typeof hash === 'function') b.hash = hash
  return b.findShare || b.hash ? b : null
}

function isTimeoutError(err) {
  return !!err && (err.code === 'ETIMEDOUT' || err.message === 'Connection timed out')
}

/** `connect`/`change` arguments: an address string, or `{ address, publicNode | pub, keyPair, maxPeers }`. */
function normalizeTarget(input) {
  const opts = typeof input === 'string' ? { address: input } : input || {}
  const publicNode = !!(opts.publicNode || opts.pub)
  if (!publicNode && (typeof opts.address !== 'string' || opts.address.length === 0)) {
    throw new TypeError('NodeClient: address (a private node invite) or publicNode: true is required')
  }
  return {
    address: publicNode ? null : opts.address,
    publicNode,
    keyPair: opts.keyPair || null,
    maxPeers: opts.maxPeers
  }
}

class NodeClient extends EventEmitter {
  /**
   * @param {object} [opts]
   * @param {'desktop'|'native'} [opts.preset]  connection/polling behaviour (default 'desktop')
   * @param {{ findShare?: Function, hash?: Function }} [opts.backend]  hugin-pow hashing backend
   *   for proof of work (`require('hugin-pow/native').createHasher()` on Node.js and Electron)
   * @param {(req: { blobHex, targetHex, startNonce, maxAttempts }) => Promise<object|null>} [opts.findShare]
   *   share search of one slice (kryptokrona-crypto `findPowShare` shape), used when no `backend` is given
   * @param {(blobHex: string) => Promise<string>} [opts.hash]  CN-Turtle-Lite v2, used when no
   *   `backend` is given (checked against hugin-pow's reference vector before the first search)
   * @param {(level: string, msg: string, data?: object) => void} [opts.log]
   * @param {Array<{host, port}>} [opts.bootstrap]  DHT bootstrap (tests: a testnet)
   * @param {Function} [opts.createSwarm]  replaces `createHuginSwarm` (tests)
   * Any key of a preset (`maxPeers`, `keepBackups`, `refreshIntervalMs`, `maxReconnectTries`,
   * `fallbackToPublic`, `syncTimeoutMs`, `powRoundMs`, `powMaxDifficulty`, `powMaxTooHardJobs`, ...)
   * and `poll: { ... }` override the preset.
   */
  constructor(opts = {}) {
    super()
    const presetName = opts.preset || 'desktop'
    const preset = PRESETS[presetName]
    if (!preset) throw new TypeError(`NodeClient: unknown preset '${presetName}'`)

    const options = {}
    for (const k of OPTION_KEYS) options[k] = opts[k] !== undefined ? opts[k] : preset[k]
    options.poll = { ...preset.poll, ...(opts.poll || {}) }
    this.preset = presetName
    this.options = options

    /** hugin-pow backend for proof of work, or null (posts and registrations then throw). */
    this.backend = powBackend(opts)
    this.hooks = {
      log: typeof opts.log === 'function' ? opts.log : null
    }
    this.bootstrap = opts.bootstrap || null
    this._createSwarm = typeof opts.createSwarm === 'function' ? opts.createSwarm : createHuginSwarm

    this.target = null // { address, publicNode, keyPair, maxPeers }
    this.swarm = null
    this.discovery = null
    this.topic = null
    this.keyPair = null

    this.connection = null
    this.rpc = null
    this.remotePublicKey = null
    this.backups = []

    /** The node's XKR address from its hello packet (desktop pays node upgrades to it). */
    this.address = null
    this.version = null

    this.jobs = this._newJobTracker()
    this._lastJobId = null
    this._skipNodes = new Set() // hex DHT keys of public-topic nodes left by switchNode
    this.requests = new Map() // packet id -> entry
    this.activePow = 0
    this._powQueue = Promise.resolve()
    this.suspended = false
    this.destroyed = false

    this._reconnecting = null
    this._generation = 0 // bumped when the swarm is replaced; stale loops stop
    this._timers = new Set()
    this._slots = new Map() // named wake-able delays
    this._jobWaiters = new Set()
    this._activeIds = new Set()
    this._syncs = new Map()
    this._poll = null
  }

  // -------------------------------------------------------------------------------------------
  // state

  get connected() {
    return this.connection !== null
  }

  get state() {
    if (this.destroyed) return 'destroyed'
    if (this.suspended) return 'suspended'
    if (this.connection) return 'connected'
    if (this.swarm) return 'connecting'
    return 'idle'
  }

  /** `since` the poller will use next (after a rewind on connect, for the host to persist). */
  get pollSince() {
    return this._poll ? this._poll.since : null
  }

  // -------------------------------------------------------------------------------------------
  // connect / change / reconnect

  /**
   * Joins the node topic as a client. `target` is a private node invite (the node's address +
   * hex of its DHT public key; only that key is admitted) or `{ publicNode: true }` (any node on
   * the public topic). Calling it again replaces the current node (as `change`).
   * @param {string|{ address?, publicNode?, pub?, keyPair?, maxPeers? }} target
   */
  async connect(target) {
    if (this.destroyed) throw new Error('NodeClient: destroyed')
    const next = normalizeTarget(target)
    if (this.swarm) await this._closeSwarm('change')
    this.target = next
    this._skipNodes.clear()
    this._openSwarm()
  }

  /** Leaves the current node (connection, discovery, swarm) and connects to another. */
  async change(target) {
    if (this.destroyed) throw new Error('NodeClient: destroyed')
    const next = normalizeTarget(target)
    await this._closeSwarm('change')
    this.target = next
    this._skipNodes.clear()
    this._openSwarm()
  }

  /** Resolves true once connected, false after `timeoutMs` (or when suspended/destroyed). */
  waitForConnection(timeoutMs = 30000) {
    if (this.connection) return Promise.resolve(true)
    if (this.destroyed || this.suspended) return Promise.resolve(false)
    return new Promise((resolve) => {
      let timer = null
      const done = (value) => {
        if (timer) clearTimeout(timer)
        this.off('node:connected', onconnected)
        this.off('_stopped', onstopped)
        resolve(value)
      }
      const onconnected = () => done(true)
      const onstopped = () => done(false)
      this.on('node:connected', onconnected)
      this.on('_stopped', onstopped)
      if (Number.isFinite(timeoutMs)) timer = setTimeout(() => done(!!this.connection), Math.max(0, timeoutMs))
    })
  }

  /**
   * Reconnect loop (both apps' `reconnect`): promote a backup connection if there is one, else
   * refresh discovery every `refreshIntervalMs` until connected or `maxReconnectTries` refreshes
   * are done; then, only with `fallbackToPublic` (off by default in both presets), start over on
   * the public node topic and emit `node:reset { from, publicNode: true, reason: 'fallback' }`.
   * One loop at a time; resolves when it ends.
   */
  reconnect() {
    // a loop of a replaced swarm is ending on its own; it does not count as running
    if (this._reconnecting && this._reconnecting.generation === this._generation) return this._reconnecting
    if (this.destroyed || this.suspended || !this.swarm) return Promise.resolve()
    const run = this._reconnectLoop().catch((err) => this._log('warn', 'reconnect failed', { message: err && err.message }))
    const promise = run.then(() => {
      if (this._reconnecting === promise) this._reconnecting = null
    })
    promise.generation = this._generation
    this._reconnecting = promise
    return promise
  }

  async _reconnectLoop() {
    const generation = this._generation
    const max = this.options.maxReconnectTries
    const active = () => !this.connection && !this.destroyed && !this.suspended && this._generation === generation
    let tries = 0
    while (active() && tries < max) {
      if (this._promoteBackup()) return
      if (tries % 20 === 0) this._log('info', 'reconnecting to node', { attempt: tries })
      if (this.discovery && typeof this.discovery.refresh === 'function') {
        try {
          const p = this.discovery.refresh({ client: true, server: false })
          if (p && typeof p.catch === 'function') p.catch(noop)
        } catch {}
      }
      await this._delay(this.options.refreshIntervalMs, 'reconnect')
      tries++
    }
    if (active() && this.options.fallbackToPublic) {
      this._log('warn', 'no node connection after retries, switching to the public node topic (fallbackToPublic)', { tries })
      await this._resetToPublic()
    }
  }

  async _resetToPublic() {
    const from = this.target
    await this._closeSwarm('reset')
    if (this.destroyed) return
    this.jobs = this._newJobTracker()
    this._lastJobId = null
    this._skipNodes.clear()
    this.target = { address: null, publicNode: true, keyPair: null, maxPeers: from ? from.maxPeers : undefined }
    this.emit('node:reset', { from: from ? { address: from.address, publicNode: from.publicNode } : null, publicNode: true, reason: 'fallback' })
    this._openSwarm()
  }

  _openSwarm() {
    const { address, publicNode, keyPair, maxPeers } = this.target
    const rule = { address, pub: publicNode }
    const opts = {
      key: keys.nodeSwarmKey(rule),
      maxPeers: maxPeers !== undefined && maxPeers !== null ? maxPeers : this.options.maxPeers,
      firewall: (remotePublicKey) => {
        const allowed = keys.isAllowedNodePeer(remotePublicKey, rule)
        if (!allowed) this._log('debug', 'firewalled a node that is not the invited one', { remotePublicKey: hex(remotePublicKey) })
        if (allowed && publicNode && this._skipNodes.has(hex(remotePublicKey))) {
          this._log('debug', 'skipped a node left by switchNode', { remotePublicKey: hex(remotePublicKey) })
          return true
        }
        return !allowed
      }
    }
    if (keyPair) opts.keyPair = keyPair
    if (this.bootstrap) opts.bootstrap = this.bootstrap
    const created = this._createSwarm(opts)

    this._generation++
    const generation = this._generation
    this.swarm = created.swarm
    this.topic = created.topic
    this.keyPair = created.keyPair || null
    this.swarm.on('connection', (conn, info) => this._onconnection(generation, conn, info))
    this.discovery = this.swarm.join(this.topic, { server: false, client: true })
    this._log('info', 'joined the node topic', { publicNode })
  }

  /** Closes the connection, backups, discovery and swarm (may emit `node:disconnected`). */
  async _closeSwarm(reason) {
    this._generation++
    this._wake('reconnect')
    const swarm = this.swarm
    const discovery = this.discovery
    const topic = this.topic
    const hadSwarm = !!swarm
    const hadConnection = !!this.connection
    const remotePublicKey = this.remotePublicKey

    this._dropConnection('closed')
    for (const conn of this.backups.splice(0)) destroyConn(conn)

    this.swarm = null
    this.discovery = null
    this.topic = null
    this.address = null
    this.version = null

    // both apps announce "disconnected" on every change; otherwise only a live connection ends here
    if (hadSwarm && (hadConnection || reason === 'change')) this.emit('node:disconnected', { reason, remotePublicKey })

    if (discovery && typeof discovery.destroy === 'function') {
      try {
        await discovery.destroy()
      } catch {}
    }
    if (swarm) {
      try {
        if (topic) await swarm.leave(topic)
      } catch {}
      try {
        await swarm.destroy()
      } catch {}
    }
  }

  // -------------------------------------------------------------------------------------------
  // connections

  _onconnection(generation, conn, info) {
    conn.on('error', (err) => this._onconnerror(conn, err))
    if (generation !== this._generation || this.destroyed || this.suspended) {
      destroyConn(conn)
      return
    }
    // The active connection may be closing already (destroyed, its 'close' not yet emitted);
    // detach it now so the new connection is not refused as a second one.
    if (this.connection && (this.connection.destroyed || this.connection.destroying)) {
      this._detach(this.connection, 'close')
    }
    if (this.connection) {
      const maxBackups = Math.max(0, (this.swarm && this.swarm.maxPeers ? this.swarm.maxPeers : this.options.maxPeers) - 1)
      if (this.options.keepBackups && this.backups.length < maxBackups) {
        this.backups.unshift(conn)
        conn.once('close', () => this._detach(conn, 'close'))
        this._log('debug', 'kept a backup node connection', { remotePublicKey: hex(conn.remotePublicKey), backups: this.backups.length })
        return
      }
      destroyConn(conn)
      return
    }
    this._attach(conn, false)
  }

  _attach(conn, backup) {
    this.connection = conn
    this.remotePublicKey = hex(conn.remotePublicKey)
    this.rpc = new RpcChannel(conn, (req) => this._onrequest(req), {
      onerror: (err) => this._error('node sent a malformed frame', err, 'HUGIN_NODE_PROTOCOL')
    })
    if (!backup) conn.once('close', () => this._detach(conn, 'close'))
    this._wake('reconnect')
    this._log('info', 'connected to a node', { remotePublicKey: this.remotePublicKey, backup })
    this.emit('node:connected', {
      remotePublicKey: this.remotePublicKey,
      backup,
      publicNode: this.target ? this.target.publicNode : null
    })
  }

  _promoteBackup() {
    while (this.backups.length > 0) {
      const conn = this.backups.pop() // the oldest backup, like native
      if (conn.destroyed || conn.destroying) continue
      this._attach(conn, true)
      return true
    }
    return false
  }

  _onconnerror(conn, err) {
    if (isTimeoutError(err)) this._log('info', 'node connection timed out')
    else if (conn === this.connection) this._error('node connection error', err, 'HUGIN_NODE_CONNECTION')
    destroyConn(conn)
    this._detach(conn, 'error')
  }

  _detach(conn, reason) {
    const i = this.backups.indexOf(conn)
    if (i !== -1) {
      this.backups.splice(i, 1)
      return
    }
    if (conn !== this.connection) return
    const remotePublicKey = this.remotePublicKey
    this._dropConnection('connection_lost')
    this.emit('node:disconnected', { reason, remotePublicKey })
    if (this.destroyed || this.suspended || !this.swarm) return
    if (this._promoteBackup()) return
    this.reconnect()
  }

  /** Forgets the active connection (destroying it) and fails the requests waiting on it. */
  _dropConnection(failReason) {
    const conn = this.connection
    const rpc = this.rpc
    this.connection = null
    this.rpc = null
    this.remotePublicKey = null
    if (rpc) rpc.destroy(null)
    if (conn) destroyConn(conn)
    for (const entry of [...this.requests.values()]) entry.fail(failReason)
  }

  // -------------------------------------------------------------------------------------------
  // packets

  _onrequest(req) {
    req.reply(NODE_RPC_REPLY)
    if (req.command !== NODE_PACKET_COMMAND) return
    this._route(push.parseNodePacket(req.data))
  }

  /** Routes a parsed node packet (both apps' `handle_node_packet`). */
  _route(p) {
    switch (p.kind) {
      case 'messages':
        // validated by push.parseNodePacket (push.nodeMessages); nothing to emit when none is valid
        if (p.messages.length > 0) this.emit('node:messages', { messages: p.messages, source: 'push' })
        return
      case 'address':
        this.address = p.address
        this.version = p.version === undefined ? null : p.version
        this.emit('node:address', { address: p.address, version: this.version })
        return
      case 'hello':
        this.version = p.version === undefined ? null : p.version
        return
      case 'job':
        if (p.valid) {
          // false for the current job again or a job hugin-pow refuses
          if (!this.jobs.set(p.job) && this.jobs.lastRefusal === 'job_too_hard') {
            this._log('info', 'job above powMaxDifficulty, not mined', {
              jobId: p.job.job_id,
              difficulty: pow.targetToDifficulty(p.job.target),
              maxDifficulty: this.jobs.maxDifficulty,
              inARow: this.jobs.tooHardJobs
            })
          }
          if (p.job.job_id !== this._lastJobId) {
            // announced once per job id (a retry drops the current job and asks again)
            this._lastJobId = p.job.job_id
            this._log('debug', 'job set', { jobId: p.job.job_id })
            this.emit('node:job', { job: p.job })
          }
          for (const waiter of [...this._jobWaiters]) waiter(p.job)
        } else {
          this._log('warn', 'node sent an invalid job', { reason: p.reason })
        }
        break
      case 'invalid':
        this._log('warn', 'unreadable packet from node', { reason: p.reason })
        return
      case 'ignored':
        return
    }
    if (p.id === undefined || p.id === null) return
    const entry = this.requests.get(p.id)
    if (entry) entry.onpacket(p)
  }

  /** Sends one packet; false without a connection. Throws `PacketError` for an invalid one. */
  _sendPacket(packet) {
    const body = push.encodePacket(packet)
    if (!this.rpc || this.rpc.closed) return false
    this.rpc.request(NODE_PACKET_COMMAND, body).catch(noop)
    return true
  }

  /**
   * Sends `packet` and waits for the answer with the same `id`. `onpacket(p, done)` decides
   * which answers settle it; `onfail(reason)` maps 'write_failed' / 'timeout' /
   * 'connection_lost' / 'closed' / 'destroyed' to the resolved value.
   */
  _request({ id, packet, timeoutMs, onpacket, onfail }) {
    return new Promise((resolve, reject) => {
      let settled = false
      let timer = null
      const entry = {
        done: (value) => {
          if (settled) return
          settled = true
          if (timer) clearTimeout(timer)
          if (this.requests.get(id) === entry) this.requests.delete(id)
          resolve(value)
        },
        fail: (reason) => entry.done(onfail(reason)),
        onpacket: (p) => onpacket(p, entry.done)
      }
      const previous = this.requests.get(id)
      if (previous) previous.fail('replaced')
      this.requests.set(id, entry)
      let sent
      try {
        sent = this._sendPacket(packet)
      } catch (err) {
        settled = true
        this.requests.delete(id)
        reject(err)
        return
      }
      if (!sent) {
        entry.fail('write_failed')
        return
      }
      if (Number.isFinite(timeoutMs) && timeoutMs > 0) timer = setTimeout(() => entry.fail('timeout'), timeoutMs)
    })
  }

  // -------------------------------------------------------------------------------------------
  // sync and polling

  /**
   * Store-and-forward sync: the node's pooled messages newer than `since` (ms). Always sends a
   * numeric timestamp (hugin-node bans a sync without one). Resolves `[]` without a connection,
   * on timeout (`syncTimeoutMs`) or when the connection drops. Only valid messages are kept
   * (`push.nodeMessage`: `{ hash, cipher, timestamp[, viewtag][, kind] }`), at most
   * MAX_NODE_SYNC_MESSAGES (500) per sync, chunked answers included.
   */
  sync({ since = 0, timeoutMs } = {}) {
    if (!this.connection) return Promise.resolve([])
    const packet = push.syncRequest({ since })
    const id = packet.id
    const inflight = this._syncs.get(id)
    if (inflight) return inflight
    const chunks = []
    const promise = this._request({
      id,
      packet,
      timeoutMs: timeoutMs !== undefined ? timeoutMs : this.options.syncTimeoutMs,
      onpacket: (p, done) => {
        if (p.kind === 'response') done(push.syncMessages(p.response))
        else if (p.kind === 'chunk') {
          // at most MAX_NODE_SYNC_MESSAGES in all: the answer ends there
          const left = MAX_NODE_SYNC_MESSAGES - chunks.length
          chunks.push(...push.syncMessages(p.response, left))
          if (chunks.length >= MAX_NODE_SYNC_MESSAGES) done(chunks)
        } else if (p.kind === 'done') done(chunks)
        else if (p.kind === 'result') done([])
      },
      onfail: (reason) => {
        if (reason === 'timeout') this._log('info', 'sync timed out')
        return []
      }
    })
      .catch(() => [])
      .then((messages) => {
        this._syncs.delete(id)
        return messages
      })
    this._syncs.set(id, promise)
    return promise
  }

  /**
   * Polls `sync` and emits `node:messages { messages, source: 'sync', since }` for non-empty
   * answers (the host decrypts and stores them, and may persist `since`).
   * @param {object} [opts]  overrides of the preset's `poll` options, plus:
   * @param {number} [opts.since]  start timestamp (desktop: the persisted `pool.checked`)
   * @param {() => boolean|Promise<boolean>} [opts.shouldSync]  false skips a run (host backlog)
   */
  startPolling(opts = {}) {
    if (this.destroyed) throw new Error('NodeClient: destroyed')
    if (typeof opts === 'number') opts = { intervalMs: opts }
    this.stopPolling()
    const p = {
      ...this.options.poll,
      ...opts,
      since: typeof opts.since === 'number' && Number.isFinite(opts.since) ? opts.since : 0,
      shouldSync: typeof opts.shouldSync === 'function' ? opts.shouldSync : null,
      runs: 0,
      busy: false,
      timer: null
    }
    const onconnected = () => {
      if (p.rewindOnConnectMs > 0 && p.since > 0) p.since = Math.max(0, p.since - p.rewindOnConnectMs)
    }
    this.on('node:connected', onconnected)
    p.stop = () => {
      this.off('node:connected', onconnected)
      if (p.timer) clearTimeout(p.timer)
      p.timer = null
    }
    this._poll = p

    const schedule = (ms) => {
      if (this._poll !== p) return
      p.timer = setTimeout(tick, Math.max(0, ms))
    }
    const tick = async () => {
      p.timer = null
      if (this._poll !== p) return
      if (p.runs >= p.maxRuns) {
        this._log('info', 'polling stopped after its maximum number of runs', { runs: p.runs })
        this.stopPolling()
        return
      }
      p.runs++
      if (!p.busy) {
        p.busy = true
        try {
          const go = p.shouldSync ? await p.shouldSync() : true
          if (go && this._poll === p) {
            const messages = await this.sync({ since: p.since })
            if (messages.length > 0 && this._poll === p) {
              p.since = Date.now() - p.advanceSkewMs
              this.emit('node:messages', { messages, source: 'sync', since: p.since })
            }
          }
        } catch (err) {
          this._log('warn', 'poll failed', { message: err && err.message })
        } finally {
          p.busy = false
        }
      }
      schedule(p.intervalMs)
    }
    schedule(p.initialDelayMs !== undefined && p.initialDelayMs !== null ? p.initialDelayMs : p.intervalMs)
  }

  stopPolling() {
    const p = this._poll
    if (!p) return
    this._poll = null
    p.stop()
  }

  // -------------------------------------------------------------------------------------------
  // jobs and proof of work

  /**
   * Asks the node for a mining job (`job_request`). Resolves the job (also recorded and
   * announced as `node:job`), or null without a connection, on timeout or refusal. When the node
   * answers `job_pending`, waits up to `jobWaitMs` for the job it pushes next.
   */
  async getJob() {
    if (!this.connection) return null
    const id = randomKey()
    const res = await this._request({
      id,
      packet: push.jobRequest(id),
      timeoutMs: this.options.jobTimeoutMs,
      onpacket: (p, done) => {
        if (p.kind === 'job') done({ job: p.valid ? p.job : null })
        else if (p.kind === 'job_pending') done({ pending: true })
        else if (p.kind === 'result') done({ refused: push.nodeResult(p) })
      },
      onfail: (reason) => {
        if (reason === 'timeout') this._log('info', 'job request timed out')
        return null
      }
    })
    if (res && res.job) return res.job
    if (res && res.pending) return this._waitForJob(this.options.jobWaitMs)
    if (res && res.refused) {
      this._log('info', 'job request refused', { reason: res.refused.reason })
      // rate_limit strikes add up to a ban on hugin-node; back off before the caller asks again
      await this._delay(1000)
    }
    return null
  }

  _waitForJob(ms) {
    return new Promise((resolve) => {
      let timer = null
      const waiter = (job) => {
        if (timer) clearTimeout(timer)
        this._jobWaiters.delete(waiter)
        resolve(job)
      }
      this._jobWaiters.add(waiter)
      timer = setTimeout(() => waiter(null), Math.max(0, ms))
    })
  }

  /**
   * One share search (`pow.searchShares` with this connection's jobs and the host's backend).
   * Searches run one at a time: the backend uses every core it is given.
   */
  async computePow() {
    this._needPow()
    this.activePow++
    const run = this._powQueue.then(() => this._searchShares())
    this._powQueue = run.catch(noop)
    try {
      return await run
    } finally {
      this.activePow = Math.max(0, this.activePow - 1)
    }
  }

  _searchShares() {
    if (this.destroyed) return null
    return pow.searchShares({
      requestJob: () => this.getJob(),
      tracker: this.jobs,
      backend: this.backend,
      maxJobTimeMs: this.options.powMaxJobTimeMs,
      roundMs: this.options.powRoundMs,
      maxTooHardJobs: this.options.powMaxTooHardJobs,
      onTooHardJobs: () => this.switchNode('job_too_hard'),
      sleep: (ms) => this._delay(ms),
      isCancelled: () => this.destroyed,
      onEvent: (name, data) => this._log('debug', name, data)
    })
  }

  _newJobTracker() {
    return new pow.JobTracker({ maxDifficulty: this.options.powMaxDifficulty })
  }

  /**
   * Leaves the active node for another one of the same topic. On the public node topic that
   * node is skipped by the firewall for the life of this swarm (until `connect`/`change` or a
   * reset), and a backup connection is promoted or discovery looks for another node
   * (`node:disconnected { reason: 'switch' }`, then `node:connected`). A private node is the
   * only one allowed, so it is kept. Clears the job tracker either way. Resolves true when the
   * connection was left.
   * @param {string} [reason]  for the log (`job_too_hard` from the share search)
   */
  async switchNode(reason = 'switch') {
    const from = this.remotePublicKey
    this.jobs.clear()
    this._lastJobId = null
    if (!from || !this.target || !this.target.publicNode || this.destroyed || this.suspended || !this.swarm) {
      this._log('warn', 'no other node to move to, staying on this one', { reason, publicNode: !!(this.target && this.target.publicNode) })
      return false
    }
    this._skipNodes.add(from)
    while (this._skipNodes.size > MAX_SKIPPED_NODES) this._skipNodes.delete(this._skipNodes.values().next().value)
    this._log('info', 'moving to another node', { reason, from })
    this._dropConnection('connection_lost')
    this.emit('node:disconnected', { reason: 'switch', remotePublicKey: from })
    if (!this._promoteBackup()) this.reconnect()
    return true
  }

  _needPow() {
    if (!this.backend) {
      throw new TypeError('NodeClient: a PoW backend (`backend`, or a `findShare` / `hash` hook) is needed for proof of work')
    }
  }

  /** A packet id (= timestamp) not used by another post/registration in flight. */
  _uniqueTimestamp() {
    let ts = Date.now()
    while (this._activeIds.has(ts) || this.requests.has(ts)) ts++
    this._activeIds.add(ts)
    return ts
  }

  /**
   * Sends a DM (or call/room push) through the node, paid with PoW, retrying per `pow.sendWithPow`.
   * Resolves `{ success, reason?, duplicate?, id }`; local failures use the apps' reasons
   * (`No connection to node`, `PoW required`, `timeout`, `write_failed`). Throws `PacketError`
   * for invalid input before any work is done.
   * @param {{ cipher: string, hash?: string, viewtag?: string, kind?: 'dm'|'call'|'room' }} msg
   */
  async post({ cipher, hash = randomKey(), viewtag, kind = 'dm' } = {}) {
    this._needPow()
    push.postMessage({ cipher, hash, viewtag, kind, timestamp: 0 }) // input check, throws
    const timestamp = this._uniqueTimestamp()
    try {
      return await this._sendWithPow({
        what: 'post',
        hash,
        timestamp,
        context: pow.postAuthContext(kind, cipher),
        buildPacket: (powObj) => push.postPacket({ cipher, hash, viewtag, kind, timestamp, pow: powObj }),
        exceptionReason: 'message_exception'
      })
    } finally {
      this._activeIds.delete(timestamp)
    }
  }

  /** Push registration (`{ register: true, data, ... }`), paid with PoW like a post. */
  async register(data) {
    this._needPow()
    if (typeof data !== 'string') throw new TypeError('NodeClient.register: data must be a string')
    const hash = randomKey()
    const timestamp = this._uniqueTimestamp()
    try {
      return await this._sendWithPow({
        what: 'register',
        hash,
        timestamp,
        context: pow.registerAuthContext(data),
        buildPacket: (powObj) => push.registerPacket({ data, timestamp, hash, pow: powObj }),
        exceptionReason: 'register_exception'
      })
    } finally {
      this._activeIds.delete(timestamp)
    }
  }

  async _sendWithPow({ what, hash, timestamp, context, buildPacket, exceptionReason }) {
    if (this.destroyed) return { success: false, reason: NO_CONNECTION }
    if (!this.connection) {
      this.reconnect()
      if (this.options.waitForConnectionMs > 0) await this.waitForConnection(this.options.waitForConnectionMs)
      if (!this.connection) return { success: false, reason: NO_CONNECTION }
    }
    try {
      return await pow.sendWithPow({
        hash,
        timestamp,
        context,
        computePow: () => this.computePow(),
        buildPacket,
        send: (packet) => this._sendPowPacket(packet, timestamp),
        refreshJob: async () => {
          this.jobs.clear()
          await this.getJob()
        },
        maxAttempts: this.options.maxAttempts,
        maxRecalcRetries: this.options.maxRecalcRetries,
        sleep: (ms) => this._delay(ms),
        isCancelled: () => this.destroyed,
        onEvent: (name, data) => {
          this._log(name === 'error' ? 'warn' : 'debug', `pow_${what}_${name}`, data)
          if (name === 'no_shares') this.emit('node:pow-required', { kind: what, hash, attempt: data && data.attempt })
        }
      })
    } catch (err) {
      this._log('warn', `pow_${what}_error`, { message: err && err.message })
      return { success: false, reason: exceptionReason }
    }
  }

  async _sendPowPacket(packet, id) {
    if (!this.connection) {
      this.reconnect()
      await this.waitForConnection(this.options.sendReconnectWaitMs)
    }
    return this._request({
      id,
      packet,
      timeoutMs: this.options.postTimeoutMs,
      onpacket: (p, done) => {
        if (p.kind === 'result') done(push.nodeResult(p))
      },
      onfail: (reason) => ({ success: false, reason })
    })
  }

  // -------------------------------------------------------------------------------------------
  // lifecycle (mobile host)

  /** Closes the node connections and suspends the swarm (native `idle`). */
  async suspend() {
    if (this.destroyed || this.suspended) return
    this.suspended = true
    this._wake('reconnect')
    this.emit('_stopped')
    const hadConnection = !!this.connection
    const remotePublicKey = this.remotePublicKey
    this._dropConnection('connection_lost')
    for (const conn of this.backups.splice(0)) destroyConn(conn)
    if (hadConnection) this.emit('node:disconnected', { reason: 'suspend', remotePublicKey })
    if (this.swarm && typeof this.swarm.suspend === 'function') {
      try {
        await this.swarm.suspend()
      } catch {}
    }
  }

  /** Resumes the swarm and reconnects (native: `node.resume()` + `reconnect()`). */
  async resume() {
    if (this.destroyed || !this.suspended) return
    this.suspended = false
    if (!this.swarm) return
    if (typeof this.swarm.resume === 'function') {
      try {
        await this.swarm.resume()
      } catch {}
    }
    this.reconnect()
  }

  async destroy() {
    if (this.destroyed) return
    this.destroyed = true
    this.stopPolling()
    this.emit('_stopped')
    await this._closeSwarm('destroy')
    for (const entry of [...this.requests.values()]) entry.fail('destroyed')
    for (const waiter of [...this._jobWaiters]) waiter(null)
    for (const t of [...this._timers]) {
      clearTimeout(t.timer)
      this._timers.delete(t)
      t.resolve()
    }
  }

  // -------------------------------------------------------------------------------------------
  // helpers

  /** Sleep that `destroy()` (and, for a named slot, `_wake(slot)`) ends early. */
  _delay(ms, slot) {
    return new Promise((resolve) => {
      const t = { timer: null, resolve: null }
      t.resolve = () => {
        this._timers.delete(t)
        if (slot && this._slots.get(slot) === t) this._slots.delete(slot)
        resolve()
      }
      if (this.destroyed) return t.resolve()
      t.timer = setTimeout(t.resolve, Math.max(0, ms))
      this._timers.add(t)
      if (slot) this._slots.set(slot, t)
    })
  }

  _wake(slot) {
    const t = this._slots.get(slot)
    if (!t) return
    clearTimeout(t.timer)
    t.resolve()
  }

  _log(level, msg, data) {
    if (!this.hooks.log) return
    try {
      this.hooks.log(level, msg, data)
    } catch {}
  }

  _error(message, err, code) {
    this._log('warn', message, { message: err && err.message, code: err && err.code })
    this.emit('node:error', {
      message,
      code: (err && err.code) || code,
      error: err && err.message ? err.message : undefined
    })
  }
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

module.exports = {
  NodeClient,
  PRESETS,
  NO_CONNECTION
}
