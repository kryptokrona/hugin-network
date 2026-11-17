'use strict'

// A minimal in-process hugin-node for the NodeClient tests: the client-facing half of hugin-node
// 2.0.0 (`network.js` client_connection / rpc_send, `nodes.js` client_message, onrequest,
// job_request, client_post, client_register),
// without a stratum pool or a message database. PoW is checked with a hash function passed in.
//
// Also: FakeSocket (an in-memory duplex pair) and FakeSwarm (a Hyperswarm stand-in that the test
// "dials" by hand), so the client's state machine can be tested without a network.
//
// No Node-only APIs: runs under Node and Bare.

const EventEmitter = require('bare-events')
const b4a = require('b4a')
const pow = require('../../lib/pow.js')
const { RpcChannel } = require('../../lib/rpc.js')
const { createHuginSwarm } = require('../../lib/swarm.js')
const { NODE_PACKET_COMMAND, NODE_RPC_REPLY, MAX_NODE_PACKET_BYTES } = require('../../lib/constants.js')

const NODE_VERSION = '2.0.0'
const MAX_SYNC_MESSAGES = 500

class FakeHuginNode extends EventEmitter {
  /**
   * @param {object} opts
   * @param {string} opts.address  the node's 99-character XKR address (sent in the hello)
   * @param {(blobHex) => Promise<string>} opts.hash  stand-in for CN-Turtle-Lite v2
   * @param {object} [opts.job]  current pool job (none: `job_pending`)
   * @param {Array<object>} [opts.pool]  pooled messages served by `some`
   */
  constructor({ address, hash, job = null, pool = [] } = {}) {
    super()
    this.address = address
    this.hash = hash
    this.job = null
    this.prevIds = []
    this.pool = pool.slice()
    this.clients = []
    this.subscribers = new Set()
    this.received = [] // every packet from clients
    this.accepted = [] // accepted posts and registrations
    this.banned = 0
    /** issued jobs by job_id (the last 8) */
    this.issued = new Map()
    /** Reasons to answer the next posts/registrations with (`{ success: false, reason }`) before checking. */
    this.script = []
    /** false: never answer `some` (to test the client's timeout). */
    this.answerSync = true
    /** Answer a sync with chunks of this size (`chunks`/`done`), 0 = one `response`. */
    this.chunkSize = 0
    this.swarm = null
    if (job) this.setJob(job, { push: false })
  }

  // ---- connections

  /** Serves one client connection (any duplex stream). */
  handle(conn) {
    const client = { conn, rpc: null }
    client.rpc = new RpcChannel(conn, (req) => this._onrequest(client, req))
    this.clients.push(client)
    const remove = () => {
      this.clients = this.clients.filter((c) => c !== client)
      this.subscribers.delete(client)
    }
    conn.on('close', remove)
    conn.on('error', () => {})
    this.send(client, { address: this.address, version: NODE_VERSION })
    this.emit('client', client)
    return client
  }

  send(client, packet) {
    if (!client.rpc || client.rpc.closed) return false
    client.rpc.request(NODE_PACKET_COMMAND, JSON.stringify(packet)).catch(() => {})
    return true
  }

  /** Pushes `{ type: 'new-message', messages }` to every client (hugin-node does it every 5 s). */
  pushMessages(messages) {
    for (const c of this.clients) this.send(c, { type: 'new-message', messages })
  }

  /** New pool job: kept for `job_request`, pushed to subscribed clients. */
  setJob(job, { push = true } = {}) {
    this.job = job
    this.issued.set(job.job_id, job)
    while (this.issued.size > 8) this.issued.delete(this.issued.keys().next().value)
    const prevId = pow.extractPrevIdFromBlob(job.blob)
    if (prevId && this.prevIds[0] !== prevId) {
      this.prevIds.unshift(prevId)
      this.prevIds = this.prevIds.slice(0, 3)
    }
    if (push) for (const c of this.subscribers) this.send(c, { type: 'job', job })
  }

  /**
   * Drops every client connection (the node going away or restarting), including any the swarm
   * holds that were not handed over yet. Returns the number of connections destroyed.
   */
  dropAll() {
    const conns = new Set(this.clients.map((c) => c.conn))
    if (this.swarm && this.swarm.connections) for (const conn of this.swarm.connections) conns.add(conn)
    for (const conn of conns) conn.destroy()
    return conns.size
  }

  _ban(client) {
    this.banned++
    client.conn.destroy()
  }

  // ---- packets (nodes.js client_message)

  async _onrequest(client, req) {
    req.reply(NODE_RPC_REPLY)
    if (req.data && req.data.byteLength > MAX_NODE_PACKET_BYTES) return this._ban(client)
    let data
    try {
      data = JSON.parse(b4a.toString(req.data))
    } catch {
      return this._ban(client)
    }
    if (!data) return this._ban(client)
    this.received.push(data)
    this.emit('packet', data, client)

    if ('request' in data) {
      if (data.type !== 'some' || typeof data.timestamp !== 'number') return this._ban(client)
      if (!this.answerSync) return
      const response = this.pool
        .filter((m) => m && m.timestamp > data.timestamp)
        .sort((a, b) => a.timestamp - b.timestamp)
        .slice(0, MAX_SYNC_MESSAGES)
      if (this.chunkSize > 0) {
        for (let i = 0; i < response.length; i += this.chunkSize) {
          this.send(client, { response: response.slice(i, i + this.chunkSize), id: data.id, chunks: true })
        }
        this.send(client, { id: data.id, done: true })
        return
      }
      this.send(client, { response, id: data.id })
      return
    }

    if ('type' in data) {
      if (data.type === 'job_request') {
        this.subscribers.add(client)
        if (this.job) this.send(client, { type: 'job', job: this.job, id: data.id })
        else this.send(client, { type: 'job_pending', id: data.id })
        return
      }
      if (data.type === 'post') return this._post(client, data)
      if (data.type === 'register') return this._register(client, data)
      this.send(client, { success: false, reason: 'unknown_type', id: data.id })
      return
    }

    if ('register' in data) return this._register(client, data)
  }

  /** true when the `pow` field is well formed, its job recent and its first share valid. */
  async _checkPow(p) {
    if (!p || p.version !== 2 || !pow.isValidPowJob(p.job)) return false
    if (!Array.isArray(p.shares) || p.shares.length === 0 || p.shares.length > pow.MAX_SHARES) return false
    if (!this.prevIds.includes(pow.extractPrevIdFromBlob(p.job.blob))) return false
    const share = p.shares[0]
    if (!(await pow.verifyShare(p.job, share.nonce, share.result, this.hash))) return false
    return true
  }

  _powAnswer(client, checked, id) {
    if (checked !== true) {
      this.send(client, { success: false, reason: 'pow_verify_failed', id })
      return false
    }
    return true
  }

  async _post(client, data) {
    const message = data.message || {}
    const id = message.id
    if (this.script.length) return this.send(client, { success: false, reason: this.script.shift(), id })
    const context = pow.postAuthContext(message.kind, message.cipher)
    const authOk =
      message.pow &&
      pow.verifyPowAuth({ auth: message.pow.auth, hash: message.hash, timestamp: message.timestamp, shares: message.pow.shares, context })
    const checked = authOk ? await this._checkPow(message.pow) : false
    if (!this._powAnswer(client, checked, id)) return
    if (this.pool.some((m) => m.hash === message.hash)) {
      return this.send(client, { success: true, duplicate: true, id })
    }
    const { pow: p, ...rest } = message
    const stored = { ...rest, pow: { ...p, job: undefined } }
    this.pool.push(stored)
    this.accepted.push({ type: 'post', message })
    this.send(client, { success: true, id })
    // other clients get it pushed (hugin-node batches every 5 s; at once here)
    for (const c of this.clients) if (c !== client) this.send(c, { type: 'new-message', messages: [stored] })
  }

  async _register(client, data) {
    const id = typeof data.id === 'number' ? data.id : data.timestamp
    if (this.script.length) return this.send(client, { success: false, reason: this.script.shift(), id })
    const context = pow.registerAuthContext(data.data)
    const authOk = data.pow && pow.verifyPowAuth({ auth: data.pow.auth, hash: data.hash, timestamp: data.timestamp, shares: data.pow.shares, context })
    const checked = authOk ? await this._checkPow(data.pow) : false
    if (!this._powAnswer(client, checked, id)) return
    this.accepted.push({ type: 'register', data })
    this.send(client, { success: true, id })
  }

  // ---- on a DHT (end-to-end tests)

  /**
   * Serves the topic of `key` (the public NETWORK_ADDRESS or the node's address) as a server
   * only, like hugin-node's public/private node swarms.
   */
  async listen({ key, keyPair, bootstrap }) {
    const created = createHuginSwarm({ key, keyPair, bootstrap })
    this.swarm = created.swarm
    this.keyPair = created.keyPair
    this.swarm.on('connection', (conn) => {
      conn.on('error', () => {})
      this.handle(conn)
    })
    await this.swarm.join(created.topic, { server: true, client: false }).flushed()
    return created
  }

  async close() {
    this.dropAll()
    if (this.swarm) await this.swarm.destroy()
  }
}

// ---------------------------------------------------------------------------------------------
// in-memory transport

class FakeSocket extends EventEmitter {
  constructor(remotePublicKey) {
    super()
    this.remotePublicKey = remotePublicKey
    this.peer = null
    this.destroyed = false
    this.destroying = false
    this.written = []
    this._unread = [] // data that arrived before anyone listened (streams buffer it too)
  }

  on(name, fn) {
    super.on(name, fn)
    if (name === 'data' && this._unread.length) {
      const unread = this._unread.splice(0)
      Promise.resolve().then(() => {
        for (const data of unread) this._deliver(data)
      })
    }
    return this
  }

  _deliver(data) {
    if (this.destroyed) return
    if (this.listenerCount('data') === 0) this._unread.push(data)
    else this.emit('data', data)
  }

  write(data) {
    if (this.destroyed) return false
    const copy = b4a.from(data)
    this.written.push(copy)
    const peer = this.peer
    Promise.resolve().then(() => peer._deliver(copy))
    return true
  }

  /** Delivers raw bytes to this socket as if the peer had written them. */
  deliverRaw(data) {
    Promise.resolve().then(() => this._deliver(b4a.from(data)))
  }

  end() {
    this.destroy()
  }

  destroy(err) {
    if (this.destroyed) return
    this.destroyed = true
    this.destroying = true
    Promise.resolve().then(() => {
      if (err) this.emit('error', err)
      this.emit('close')
    })
    if (this.peer && !this.peer.destroyed) this.peer.destroy()
  }
}

/** Two connected FakeSockets: `[a, b]`, `a.remotePublicKey = keyB`, `b.remotePublicKey = keyA`. */
function socketPair(keyA = b4a.alloc(32, 1), keyB = b4a.alloc(32, 2)) {
  const a = new FakeSocket(keyB)
  const b = new FakeSocket(keyA)
  a.peer = b
  b.peer = a
  return [a, b]
}

/** Hyperswarm stand-in: records joins/refreshes; `dial(node, key)` makes a connection through the firewall. */
class FakeSwarm extends EventEmitter {
  constructor(opts) {
    super()
    this.opts = opts
    this.maxPeers = opts.maxPeers
    this.joins = []
    this.refreshes = 0
    this.left = 0
    this.destroyed = false
    this.suspended = false
    this.firewalled = []
  }

  join(topic, opts) {
    this.joins.push({ topic, opts })
    const swarm = this
    return {
      refresh(o) {
        swarm.refreshes++
        swarm.emit('refresh', o)
        return Promise.resolve()
      },
      destroy() {
        return Promise.resolve()
      },
      flushed() {
        return Promise.resolve()
      }
    }
  }

  async leave() {
    this.left++
  }

  async destroy() {
    this.destroyed = true
  }

  async suspend() {
    this.suspended = true
  }

  async resume() {
    this.suspended = false
    this.emit('resumed')
  }

  /** Connects `node` (a FakeHuginNode) with DHT key `remoteKey`, unless the firewall refuses it. */
  dial(node, remoteKey = b4a.alloc(32, 9)) {
    if (this.destroyed || this.suspended) return null
    if (this.opts.firewall && this.opts.firewall(remoteKey, null)) {
      this.firewalled.push(remoteKey)
      return null
    }
    const [local, remote] = socketPair(b4a.alloc(32, 7), remoteKey)
    node.handle(remote)
    this.emit('connection', local, {})
    return { local, remote }
  }
}

/** `createSwarm` option for NodeClient: records every FakeSwarm it makes in `list`. */
function fakeSwarmFactory(list) {
  return (opts) => {
    const swarm = new FakeSwarm(opts)
    list.push(swarm)
    return { swarm, topic: b4a.alloc(32, list.length), keyPair: null }
  }
}

module.exports = {
  FakeHuginNode,
  FakeSocket,
  FakeSwarm,
  socketPair,
  fakeSwarmFactory,
  NODE_VERSION
}
