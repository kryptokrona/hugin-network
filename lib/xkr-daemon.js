'use strict'

// hugin-network/xkr-daemon: a wallet's daemon requests over Hyperswarm, to an xkrd node found on
// the wallets topic (or to a private node of an invite). The answers are what the node's HTTP
// RPC answers, so wallet-backend-js uses it as a `DaemonRequester`:
//
//   const { XkrDaemonRequester } = require('hugin-network/xkr-daemon')
//   const requester = new XkrDaemonRequester({ network: 'mainnet' })
//   const daemon = WB.Daemon.withRequester(requester)
//
// Wire (xkrd `docs/hyper-transport.md`, "Clients topic" and "Wallets topic"): frames of a u32
// little-endian length and that many bytes of JSON (at most 1 MiB). The client sends
// `{v: 1, network, service: "wallet", client}`, the node answers `{v, height, hash, synced,
// services, state_span, state_hash, pruning_seed}` or `{v, error, message}`. Calls are
// `{id, method: "http", params: {method: "GET"|"POST", path, body}}` -> `{id, result: {status,
// body}}` or `{id, error: {code, message}}`; pushes `{method: "tip", params}` are ignored here.
//
// Topics, as xkrd derives them:
//   wallets topic key  = cn_fast_hash(UTF-8("xkr/<network>/wallets/v1"))
//   private clients    = cn_fast_hash(UTF-8("xkr/private/clients/v1") || invite secret)
// each a Hugin topic key (`hugin-network/swarm`): the DHT topic is the Hugin topic of its base
// key, on the testnet with the domain "hugin/testnet/topic".
//
// A node is used when it says it is synchronized and its newest stable state hash equals the
// built-in one for that span (`xkr-state-hashes.json`, the list xkrd ships). CommonJS and no
// Node-only APIs: runs under Node, Electron and Bare.

const EventEmitter = require('bare-events')
const b4a = require('b4a')
const { keccak256 } = require('js-sha3')
const { createHuginSwarm } = require('./swarm.js')
const BUILTIN_STATE_HASHES = require('./xkr-state-hashes.json')

const VERSION = 1
const MAX_FRAME = 1024 * 1024
const INVITE_PREFIX = 'xkr:'
const INVITE_HEX_LEN = 4 * 64
const TESTNET_TOPIC_DOMAIN = 'hugin/testnet/topic'
const REQUEST_TIMEOUT = 30000
const HELLO_TIMEOUT = 15000
const CONNECT_TIMEOUT = 60000

/** `cn_fast_hash` (Keccak-256, original padding) of `bytes`. */
function cnFastHash(bytes) {
  return b4a.from(keccak256(bytes), 'hex')
}

/** The wallets topic key of `network` (`mainnet` or `testnet`). */
function walletsTopicKey(network) {
  return cnFastHash(b4a.from(`xkr/${network}/wallets/v1`))
}

/** The private clients topic key of an invite secret. */
function privateClientsTopicKey(secret) {
  return cnFastHash(b4a.concat([b4a.from('xkr/private/clients/v1'), secret]))
}

/** The DHT topic of a base public key on `network`. */
function topicOn(network, basePublicKey, mainnetTopic) {
  if (network !== 'testnet') return mainnetTopic
  return cnFastHash(b4a.concat([b4a.from(TESTNET_TOPIC_DOMAIN), basePublicKey]))
}

/**
 * A private node's invite `xkr:` + hex of sync key, Hugin key, clients key and secret.
 * @returns {{ syncKey: Uint8Array, huginKey: Uint8Array, clientsKey: Uint8Array, secret: Uint8Array }}
 */
function parseInvite(text) {
  const s = String(text).trim()
  if (!s.startsWith(INVITE_PREFIX)) throw new Error('an invite starts with xkr:')
  const hex = s.slice(INVITE_PREFIX.length)
  if (hex.length !== INVITE_HEX_LEN || !/^[0-9a-fA-F]+$/.test(hex)) {
    throw new Error(`an invite has 256 hex characters after xkr:, not ${hex.length}`)
  }
  const bytes = b4a.from(hex, 'hex')
  const part = (i) => bytes.subarray(i * 32, (i + 1) * 32)
  return { syncKey: part(0), huginKey: part(1), clientsKey: part(2), secret: part(3) }
}

/** Encodes one frame. */
function encodeFrame(value) {
  const body = b4a.from(JSON.stringify(value))
  if (body.length === 0 || body.length > MAX_FRAME) throw new Error('frame too large')
  const n = body.length
  const head = b4a.from([n & 0xff, (n >>> 8) & 0xff, (n >>> 16) & 0xff, (n >>> 24) & 0xff])
  return b4a.concat([head, body])
}

/** Splits a byte stream into frames: `push(chunk)` returns the JSON values completed. */
class FrameReader {
  constructor() {
    this.buf = b4a.alloc(0)
  }

  push(chunk) {
    this.buf = this.buf.length ? b4a.concat([this.buf, chunk]) : chunk
    const out = []
    while (this.buf.length >= 4) {
      const b = this.buf
      const n = (b[0] | (b[1] << 8) | (b[2] << 16) | (b[3] << 24)) >>> 0
      if (n === 0 || n > MAX_FRAME) throw new Error(`bad frame length ${n}`)
      if (this.buf.length < 4 + n) break
      out.push(JSON.parse(b4a.toString(this.buf.subarray(4, 4 + n))))
      this.buf = this.buf.subarray(4 + n)
    }
    return out
  }
}

/**
 * Whether a node's hello makes it usable: synchronized, and its state hash equal to the
 * built-in one of that span (when the list has the span).
 * @returns {string|null} why not, or null
 */
function unusable(reply, stateHashes) {
  if (!reply || reply.v !== VERSION) return 'another protocol version'
  if (!reply.synced) return 'the node is still synchronizing'
  if (reply.state_span !== null && reply.state_span !== undefined && reply.state_hash) {
    const want = stateHashes[reply.state_span]
    if (want && want !== reply.state_hash) return `state hash of span ${reply.state_span} differs`
  }
  return null
}

/** One connection after an accepted hello. */
class Session {
  constructor(conn, reply) {
    this.conn = conn
    this.reply = reply
    this.nextId = 1
    this.pending = new Map()
    this.closed = false
  }

  onframe(frame) {
    if (frame.id === undefined || frame.id === null) return // a push
    const p = this.pending.get(frame.id)
    if (!p) return
    this.pending.delete(frame.id)
    clearTimeout(p.timer)
    if (frame.error) p.reject(new Error(frame.error.message || 'daemon error'))
    else p.resolve(frame.result)
  }

  call(method, params) {
    if (this.closed) return Promise.reject(new Error('the connection is closed'))
    const id = this.nextId++
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id)
        reject(new Error('no answer in time'))
      }, REQUEST_TIMEOUT)
      this.pending.set(id, { resolve, reject, timer })
      this.conn.write(encodeFrame({ id, method, params }))
    })
  }

  close(err) {
    if (this.closed) return
    this.closed = true
    for (const p of this.pending.values()) {
      clearTimeout(p.timer)
      p.reject(err || new Error('the connection is closed'))
    }
    this.pending.clear()
    this.conn.destroy()
  }
}

/**
 * A wallet's daemon over Hyperswarm (a `DaemonRequester` of wallet-backend-js). It joins the
 * wallets topic (or the invite's private clients topic) as a client on the first request,
 * keeps one node, and finds another when that connection ends.
 *
 * Events: `node` ({ publicKey, height }) when a node is taken, `close` when its connection ends.
 */
class XkrDaemonRequester extends EventEmitter {
  /**
   * @param {object} [opts]
   * @param {'mainnet'|'testnet'} [opts.network]
   * @param {string} [opts.invite]  a private node's invite (`xkr:…`): only that node is used
   * @param {Array<{host, port}>} [opts.bootstrap]  DHT bootstrap (tests: a local DHT)
   * @param {Object<number, string>} [opts.stateHashes]  span -> state hash (default: built-in)
   * @param {string} [opts.client]  name sent in the hello
   */
  constructor(opts = {}) {
    super()
    this.network = opts.network === 'testnet' ? 'testnet' : 'mainnet'
    this.invite = opts.invite ? parseInvite(opts.invite) : null
    this.bootstrap = opts.bootstrap || null
    this.stateHashes = opts.stateHashes || (this.network === 'mainnet' ? BUILTIN_STATE_HASHES : {})
    this.client = opts.client || 'hugin-network'
    this.label = this.invite ? 'hyperswarm (private node)' : 'hyperswarm'
    this.session = null
    this.waiters = []
    this.swarm = null
    this.closed = false
  }

  /** `DaemonRequester.request`: one daemon HTTP request. */
  async request(method, path, body) {
    const session = await this._session()
    const params = { method: method === 'post' ? 'POST' : 'GET', path, body: body === undefined ? null : body }
    const result = await session.call('http', params)
    return { status: result.status, body: result.body }
  }

  /** The hello of the node in use, or null. */
  node() {
    return this.session && !this.session.closed ? this.session.reply : null
  }

  async close() {
    this.closed = true
    if (this.session) this.session.close()
    this._fail(new Error('closed'))
    if (this.swarm) await this.swarm.destroy()
    this.swarm = null
  }

  _session() {
    if (this.closed) return Promise.reject(new Error('closed'))
    if (this.session && !this.session.closed) return Promise.resolve(this.session)
    this._start()
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.waiters = this.waiters.filter((w) => w.resolve !== resolve)
        reject(new Error('no xkrd node over Hyperswarm yet'))
      }, CONNECT_TIMEOUT)
      this.waiters.push({ resolve, reject, timer })
    })
  }

  _settle(session) {
    for (const w of this.waiters.splice(0)) {
      clearTimeout(w.timer)
      w.resolve(session)
    }
  }

  _fail(err) {
    for (const w of this.waiters.splice(0)) {
      clearTimeout(w.timer)
      w.reject(err)
    }
  }

  _start() {
    if (this.swarm) return
    const key = this.invite ? privateClientsTopicKey(this.invite.secret) : walletsTopicKey(this.network)
    const opts = { key, maxPeers: 4 }
    if (this.bootstrap) opts.bootstrap = this.bootstrap
    if (this.invite) {
      const allowed = this.invite.clientsKey
      opts.firewall = (remotePublicKey) => !b4a.equals(remotePublicKey, allowed)
    }
    const created = createHuginSwarm(opts)
    this.swarm = created.swarm
    const topic = topicOn(this.network, created.basePublicKey, created.topic)
    this.swarm.on('connection', (conn, info) => this._onconnection(conn, info))
    this.swarm.join(topic, { server: false, client: true })
  }

  _onconnection(conn, info) {
    conn.on('error', () => {})
    if (this.closed || (this.session && !this.session.closed)) {
      conn.destroy()
      return
    }
    const reader = new FrameReader()
    let session = null
    const helloTimer = setTimeout(() => conn.destroy(), HELLO_TIMEOUT)
    conn.on('data', (chunk) => {
      let frames
      try {
        frames = reader.push(chunk)
      } catch (err) {
        conn.destroy()
        return
      }
      for (const frame of frames) {
        if (session) {
          session.onframe(frame)
          continue
        }
        clearTimeout(helloTimer)
        const why = frame.error ? `refused: ${frame.error}` : unusable(frame, this.stateHashes)
        if (why || (this.session && !this.session.closed)) {
          conn.destroy()
          return
        }
        session = new Session(conn, frame)
        this.session = session
        this.emit('node', { publicKey: info && info.publicKey, height: frame.height })
        this._settle(session)
      }
    })
    conn.on('close', () => {
      clearTimeout(helloTimer)
      if (session) {
        session.close()
        if (this.session === session) this.session = null
        this.emit('close')
      }
    })
    conn.write(encodeFrame({ v: VERSION, network: this.network, service: 'wallet', client: this.client }))
  }
}

module.exports = {
  XkrDaemonRequester,
  parseInvite,
  walletsTopicKey,
  privateClientsTopicKey,
  encodeFrame,
  FrameReader,
  unusable,
  cnFastHash,
  BUILTIN_STATE_HASHES
}
