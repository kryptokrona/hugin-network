'use strict'

// The public feed: signed posts that travel over every room connection (not DM swarms).
//
// Extracted from hugin-desktop (`src/backend/swarm.cjs` check_feed_message, send_feed_history,
// save_feed_history, send_feed_message, forward_feed_message) and hugin-native (`bare/swarm.js`
// feed_request_process, request_feed, send_feed_history, save_feed_history, send_feed_message,
// the feed branch of check_data_message). What changed:
//   * every received feed message is verified through `host.verify`, live and history alike;
//   * dedupe through `host.feedMessageExists` plus an in-memory LRU of recently seen hashes, so a
//     gossip loop ends even before the host has stored a message;
//   * a new verified live message is gossiped to every room peer except the one it came from,
//     when gossip is on (desktop: always; native: only while in the foreground). History is
//     never gossiped;
//   * feed history is requested through native's queue (one peer at a time, spaced, with a
//     timeout) instead of desktop's request to every joined peer at once;
//   * answers to `request-feed` carry at most `maxHistory` messages (desktop's page of 50);
//   * `send-feed-history` is taken only from the connection whose request is in flight, once;
//   * a live message whose signature does not verify (or that has none) makes `handle` return
//     UNVERIFIED, and the room bans its direct sender (lib/room.js) — every hugin/3 client
//     verifies before it forwards;
//   * the signature covers every field (`wire.feedSigningPayload`) and the hash is derived from
//     the content (`wire.feedMessageHash`); a message whose hash is not the derived one counts as
//     not verified, and one timestamped later than now + `clockSkewMs` is dropped (the
//     timestamp is signed, so it is not clamped).
//
// The library stores nothing: a new verified message leaves as `feed:message` and the host saves
// it. Nothing here logs message contents. No Node-only APIs: runs under Node and Bare.

const wire = require('./wire.js')
const S = require('./sanitize.js')

const DEFAULTS = Object.freeze({
  /** Wait for a `send-feed-history` answer this long before asking the next peer (native: 5 s). */
  requestTimeoutMs: 5000,
  /** Gap between the end of one feed history request and the start of the next. */
  requestSpacingMs: 500,
  /** Ask the same address again only after this long (it may be in several rooms). */
  requestCooldownMs: 10 * 60 * 1000,
  /** Answer `request-feed` on one connection at most this often. */
  answerIntervalMs: 10 * 1000,
  /** Messages in a history answer, and history entries processed per received answer. */
  maxHistory: 50,
  /** Recently seen feed hashes kept in memory. */
  seenMax: 2000,
  /** Addresses remembered for `requestCooldownMs`. */
  requestedMax: 1000,
  /** Messages timestamped later than now + this are dropped. */
  clockSkewMs: 60 * 1000
})

/** Result of `handle` for one message. */
const RESULT = Object.freeze({
  NEW: 'new', // verified, emitted (and gossiped if live and gossip is on)
  DUPLICATE: 'duplicate', // already seen or stored
  INVALID: 'invalid', // fails the feed validator or has an unusable hash
  UNVERIFIED: 'unverified', // signature missing or wrong (the sender's fault)
  ERROR: 'error' // a host hook failed or is missing
})

function noop() {}

/**
 * A feed hash the host may be asked about: exactly 64 hex characters, either case (hugin-network 3.0
 * derives it, `wire.feedMessageHash`). Narrower than `sanitize.feedMessage`, which
 * accepts any string of at most 64 characters. Live messages, history entries and history
 * answers with any other hash are refused before a host hook is called, because hosts build
 * storage lookups from it.
 */
function isFeedHash(hash) {
  return S.isHex64(hash)
}

/** Accepts a `wire.decode` result (`{ type, value }`) as well as its `value`. */
function unwrap(msg) {
  if (msg && typeof msg === 'object' && typeof msg.type === 'string' && msg.value && typeof msg.value === 'object' && !('message' in msg) && !('messages' in msg)) {
    return msg.value
  }
  return msg
}

/** Insertion-ordered set with a size bound (oldest entry evicted first). */
class Lru {
  constructor(max) {
    this.max = max
    this.map = new Map()
  }

  has(key) {
    return this.map.has(key)
  }

  get(key) {
    return this.map.get(key)
  }

  set(key, value = true) {
    if (this.map.has(key)) this.map.delete(key)
    this.map.set(key, value)
    while (this.map.size > this.max) this.map.delete(this.map.keys().next().value)
  }

  delete(key) {
    this.map.delete(key)
  }

  clear() {
    this.map.clear()
  }

  get size() {
    return this.map.size
  }
}

/** The fields of a feed message as they go on the wire (live and in history answers). */
function wireFields(v) {
  return {
    message: v.message,
    nickname: v.nickname,
    address: v.address,
    reply: v.reply,
    tip: v.tip,
    hash: v.hash,
    timestamp: v.timestamp,
    signature: v.signature
  }
}

class Feed {
  /**
   * @param {object} opts
   * @param {object} opts.host hooks (README "Host hooks and events"): `sign`, `verify`, `feedMessageExists`,
   *   `getFeedHistory`, `identity`, optionally `isBlocked`
   * @param {(level: string, msg: string, data?: object) => void} [opts.log]
   * @param {(name: string, payload: object) => void} [opts.emit] the only way events leave
   * @param {() => object[]} [opts.peers] joined peers of all non-DM rooms
   *   (`{ address, name, joined, room: { key, topic, dm }, send(string) -> boolean }`)
   * @param {boolean | (() => boolean)} [opts.gossip] forward new verified live messages
   *   (desktop: true; native: `() => foreground`). Default true.
   * @param {number} [opts.requestTimeoutMs]
   * @param {number} [opts.requestSpacingMs]
   * @param {number} [opts.requestCooldownMs]
   * @param {number} [opts.answerIntervalMs]
   * @param {number} [opts.maxHistory]
   * @param {number} [opts.seenMax]
   * @param {number} [opts.clockSkewMs]
   */
  constructor(opts = {}) {
    const num = (v, d) => (typeof v === 'number' && Number.isFinite(v) && v >= 0 ? v : d)
    this.host = opts.host || {}
    this._logHook = typeof opts.log === 'function' ? opts.log : null
    this._emitHook = typeof opts.emit === 'function' ? opts.emit : noop
    this._peersHook = typeof opts.peers === 'function' ? opts.peers : () => []
    this._gossip = opts.gossip === undefined ? true : opts.gossip
    this.options = {
      requestTimeoutMs: num(opts.requestTimeoutMs, DEFAULTS.requestTimeoutMs),
      requestSpacingMs: num(opts.requestSpacingMs, DEFAULTS.requestSpacingMs),
      requestCooldownMs: num(opts.requestCooldownMs, DEFAULTS.requestCooldownMs),
      answerIntervalMs: num(opts.answerIntervalMs, DEFAULTS.answerIntervalMs),
      maxHistory: Math.floor(num(opts.maxHistory, DEFAULTS.maxHistory)),
      seenMax: Math.max(1, Math.floor(num(opts.seenMax, DEFAULTS.seenMax))),
      clockSkewMs: num(opts.clockSkewMs, DEFAULTS.clockSkewMs)
    }

    this._seen = new Lru(this.options.seenMax) // hash -> true (stored or emitted)
    this._pending = new Map() // hash -> Promise<boolean> (verification in progress)
    this._requested = new Lru(DEFAULTS.requestedMax) // address -> time of the last request
    this._answered = new WeakMap() // peer -> time of the last history answer
    this._answering = new WeakSet() // peers whose answer is being built

    this._queue = [] // [{ peer, address }]
    this._current = null // { peer, address, timer }
    this._pumpTimer = null
    this._lastDoneAt = -Infinity
    this._destroyed = false
  }

  // -------------------------------------------------------------------------------------------
  // receive

  /**
   * A live `feed` message from a joined room peer. Never throws. UNVERIFIED means the peer sent
   * a message whose signature is missing or does not verify (the room bans it for that).
   * @param {object} peer
   * @param {object} msg the decoded message (`wire.decode(...).value`)
   * @returns {Promise<string>} one of RESULT
   */
  async handle(peer, msg) {
    try {
      return await this._accept(peer, unwrap(msg), true)
    } catch (err) {
      this._log('warn', 'feed message failed', { message: err && err.message })
      return RESULT.ERROR
    }
  }

  /**
   * `request-feed`: answers with `send-feed-history` built from `host.getFeedHistory()`, at most
   * `maxHistory` messages. Never throws.
   */
  async handleRequest(peer, msg) {
    try {
      if (this._destroyed || !peer || typeof peer.send !== 'function') return
      if (this._answering.has(peer)) return
      const last = this._answered.get(peer)
      const now = Date.now()
      if (last !== undefined && now - last < this.options.answerIntervalMs) {
        this._log('debug', 'feed history request ignored (asked again too soon)', { address: peer.address })
        return
      }
      this._answered.set(peer, now)
      this._answering.add(peer)
      let rows
      try {
        if (await this._blocked(peer)) return
        rows = typeof this.host.getFeedHistory === 'function' ? await this.host.getFeedHistory() : []
      } finally {
        this._answering.delete(peer)
      }
      if (this._destroyed) return
      const messages = []
      for (const row of Array.isArray(rows) ? rows : []) {
        if (messages.length >= this.options.maxHistory) break
        const r = S.feedMessage(row)
        if (!r.ok || !isFeedHash(r.value.hash)) continue
        messages.push(wireFields(r.value))
      }
      const sent = this._send(peer, wire.encode(wire.sendFeedHistory(messages)))
      this._log('debug', 'sent feed history', { address: peer.address, count: messages.length, sent })
    } catch (err) {
      this._log('warn', 'feed history request failed', { message: err && err.message })
    }
  }

  /**
   * `send-feed-history`: taken only from the connection whose `request-feed` is in flight (an
   * answer nobody asked for, or a second one, is ignored). Every entry is verified and deduped
   * like a live message, new ones are emitted, none is gossiped. At most `maxHistory` entries
   * are looked at. Never throws.
   */
  async handleHistory(peer, msg) {
    try {
      const current = this._current
      if (!peer || !current || current.peer !== peer) {
        this._log('debug', 'feed history nobody asked for ignored', { address: peer && peer.address })
        return
      }
      this._finishRequest('answered')
      if (this._destroyed || (await this._blocked(peer))) return
      const m = unwrap(msg)
      const list = m && Array.isArray(m.messages) ? m.messages : []
      const counts = { new: 0, duplicate: 0, invalid: 0, unverified: 0, error: 0 }
      const n = Math.min(list.length, this.options.maxHistory)
      for (let i = 0; i < n; i++) {
        if (this._destroyed) return
        let result
        try {
          result = await this._accept(peer, list[i], false)
        } catch (err) {
          this._log('warn', 'feed history entry failed', { message: err && err.message })
          result = RESULT.ERROR
        }
        counts[result]++
      }
      this._log('debug', 'feed history received', { address: peer && peer.address, entries: list.length, ...counts })
    } catch (err) {
      this._log('warn', 'feed history failed', { message: err && err.message })
    }
  }

  // -------------------------------------------------------------------------------------------
  // history request queue (native's feed_request_process)

  /** Queues a feed history request to a peer that just joined a room. Never throws. */
  onPeerJoined(peer) {
    try {
      if (this._destroyed || !peer || typeof peer.send !== 'function') return
      if (peer.room && peer.room.dm) return
      const address = peer.address
      if (typeof address !== 'string' || address.length === 0) return
      if (this._current && this._current.address === address) return
      if (this._queue.some((e) => e.address === address)) return
      const last = this._requested.get(address)
      if (last !== undefined && Date.now() - last < this.options.requestCooldownMs) return
      this._queue.push({ peer, address })
      this._pump()
    } catch (err) {
      this._log('warn', 'feed history queue failed', { message: err && err.message })
    }
  }

  /**
   * Drops queued work for a peer that left. A queued request moves to another joined connection
   * of the same address if there is one. Never throws.
   */
  onPeerLeft(peer) {
    try {
      if (!peer) return
      const others = () => this._peers().filter((p) => p !== peer && p && p.address === peer.address && typeof p.send === 'function')
      for (let i = this._queue.length - 1; i >= 0; i--) {
        const entry = this._queue[i]
        if (entry.peer !== peer) continue
        const other = others()[0]
        if (other) entry.peer = other
        else this._queue.splice(i, 1)
      }
      if (this._current && this._current.peer === peer) this._finishRequest('left')
    } catch (err) {
      this._log('warn', 'feed history queue failed', { message: err && err.message })
    }
  }

  /** Number of queued requests plus the one in flight (for tests and diagnostics). */
  get queued() {
    return this._queue.length + (this._current ? 1 : 0)
  }

  _pump() {
    if (this._destroyed || this._current || this._pumpTimer || this._queue.length === 0) return
    const wait = this._lastDoneAt + this.options.requestSpacingMs - Date.now()
    if (wait > 0) {
      this._pumpTimer = setTimeout(() => {
        this._pumpTimer = null
        this._pump()
      }, wait)
      return
    }
    const entry = this._queue.shift()
    this._current = { peer: entry.peer, address: entry.address, timer: null }
    let sent = false
    try {
      sent = this._send(entry.peer, wire.encode(wire.requestFeed()))
    } catch (err) {
      this._log('warn', 'feed history request not sent', { message: err && err.message })
    }
    if (!sent) {
      this._finishRequest('not sent')
      return
    }
    this._requested.set(entry.address, Date.now())
    this._log('debug', 'requested feed history', { address: entry.address, queued: this._queue.length })
    const current = this._current
    current.timer = setTimeout(() => {
      if (this._current !== current) return
      current.timer = null
      this._finishRequest('timeout')
    }, this.options.requestTimeoutMs)
  }

  _finishRequest(reason) {
    const current = this._current
    if (!current) return
    if (current.timer) clearTimeout(current.timer)
    this._current = null
    this._lastDoneAt = Date.now()
    if (reason !== 'answered') this._log('debug', 'feed history request ended', { address: current.address, reason })
    this._pump()
  }

  // -------------------------------------------------------------------------------------------
  // send

  /**
   * Builds, signs (`host.sign`) and broadcasts a feed message to every room peer. Rejects with a
   * WireError when the message would be refused by an old peer (too long, no identity).
   * @param {{ message: string, reply?: string, tip?: false | { amount: number, receiver: string } }} o
   * @returns {Promise<object>} the wire object that was sent
   */
  async send({ message, reply, tip } = {}) {
    if (this._destroyed) throw new Error('feed destroyed')
    if (typeof this.host.sign !== 'function') throw new Error('host.sign is required to send feed messages')
    const id = (typeof this.host.identity === 'function' ? this.host.identity() : null) || {}
    const fields = {
      message,
      nickname: S.clampText(id.name, S.SEND.feed.nickname),
      address: id.address,
      reply: reply === undefined || reply === null ? '' : reply,
      tip,
      timestamp: Date.now()
    }
    // checks every field before anything is signed (the hash and signature are placeholders)
    const checked = wire.feed({ ...fields, hash: '0'.repeat(64), signature: 'x' })
    const hash = wire.feedMessageHash(checked)
    const draft = { ...checked, hash }
    const signature = await this.host.sign(wire.feedSigningPayload(draft))
    const out = wire.feed({ ...draft, signature })
    const str = wire.encode(out)
    this._seen.set(hash)
    let count = 0
    for (const peer of this._peers()) {
      if (this._send(peer, str)) count++
    }
    this._log('debug', 'sent feed message', { hash, peers: count })
    return out
  }

  // -------------------------------------------------------------------------------------------
  // lifecycle

  /** Stops the request queue and its timers. Messages still being verified are not emitted. */
  destroy() {
    this._destroyed = true
    if (this._pumpTimer) clearTimeout(this._pumpTimer)
    this._pumpTimer = null
    if (this._current && this._current.timer) clearTimeout(this._current.timer)
    this._current = null
    this._queue = []
    this._seen.clear()
    this._requested.clear()
  }

  // -------------------------------------------------------------------------------------------
  // internals

  /**
   * Validates, dedupes and verifies one feed message; emits it when new, gossips it when `live`.
   * @returns {Promise<string>} one of RESULT
   */
  async _accept(peer, raw, live) {
    if (this._destroyed) return RESULT.ERROR
    const r = S.feedMessage(raw)
    if (!r.ok) {
      this._log('debug', 'invalid feed message', { reason: r.reason, address: peer && peer.address })
      return RESULT.INVALID
    }
    if (!isFeedHash(r.value.hash)) return RESULT.INVALID
    // the hash in lower case (it is derived and signed that way), also for the host lookups
    const v = { ...r.value, hash: r.value.hash.toLowerCase() }
    const hash = v.hash
    if (v.timestamp > Date.now() + this.options.clockSkewMs) {
      this._log('debug', 'feed message from the future dropped', { hash })
      return RESULT.INVALID
    }

    // The same message from several peers at once: wait for the verification already running.
    // If it failed (a copy that does not verify), this copy gets its own chance.
    while (this._pending.has(hash)) {
      let ok = false
      try {
        ok = await this._pending.get(hash)
      } catch {}
      if (ok) return RESULT.DUPLICATE
    }
    if (this._seen.has(hash)) return RESULT.DUPLICATE

    let settle
    const done = new Promise((resolve) => {
      settle = resolve
    })
    this._pending.set(hash, done)
    let accepted = false
    try {
      let exists = false
      if (typeof this.host.feedMessageExists === 'function') {
        try {
          exists = (await this.host.feedMessageExists(hash)) === true
        } catch (err) {
          this._log('warn', 'feedMessageExists failed', { message: err && err.message })
          return RESULT.ERROR
        }
      }
      if (exists) {
        this._seen.set(hash)
        accepted = true // a stored message counts as verified for anyone waiting on it
        return RESULT.DUPLICATE
      }

      if (typeof this.host.verify !== 'function') {
        this._log('warn', 'feed message dropped: no host.verify')
        return RESULT.ERROR
      }
      if (!v.signature) {
        this._log('debug', 'unsigned feed message dropped', { hash, address: peer && peer.address })
        return RESULT.UNVERIFIED
      }
      if (!wire.isFeedMessageHash(v)) {
        this._log('debug', 'feed message whose hash is not derived from it dropped', { hash, address: peer && peer.address })
        return RESULT.UNVERIFIED
      }
      let payload
      try {
        payload = wire.feedSigningPayload(v)
      } catch {
        return RESULT.INVALID
      }
      let valid = false
      try {
        valid = (await this.host.verify(payload, v.address, v.signature)) === true
      } catch (err) {
        this._log('warn', 'feed signature check failed', { message: err && err.message })
        return RESULT.ERROR
      }
      if (!valid) {
        this._log('info', 'feed message with a bad signature dropped', { hash, address: peer && peer.address })
        return RESULT.UNVERIFIED
      }

      this._seen.set(hash)
      accepted = true
      if (this._destroyed) return RESULT.NEW
      this._emit('feed:message', { message: { ...v, tip: v.tip ? { ...v.tip } : false }, live: !!live })
      if (live && this._gossipOn()) this._forward(peer, v)
      return RESULT.NEW
    } finally {
      this._pending.delete(hash)
      settle(accepted)
    }
  }

  /** Sends a verified live message, exactly as it was signed, to every room peer but `from`. */
  _forward(from, v) {
    let str
    try {
      str = wire.encode(wire.feed(wireFields(v)))
    } catch (err) {
      // Accepted from an old peer but outside what every old peer accepts (e.g. a non-hex hash).
      this._log('debug', 'feed message not forwarded', { hash: v.hash, reason: err && err.field })
      return
    }
    let count = 0
    for (const peer of this._peers()) {
      if (peer === from) continue
      if (this._send(peer, str)) count++
    }
    this._log('debug', 'forwarded feed message', { hash: v.hash, peers: count })
  }

  _gossipOn() {
    try {
      return typeof this._gossip === 'function' ? this._gossip() === true : this._gossip === true
    } catch {
      return false
    }
  }

  /** `host.isBlocked` (sync or async, as Rooms reads it); a failing hook counts as not blocked. */
  async _blocked(peer) {
    if (!peer || typeof this.host.isBlocked !== 'function') return false
    try {
      return !!(await this.host.isBlocked(peer.address))
    } catch {
      return false
    }
  }

  _peers() {
    let list
    try {
      list = this._peersHook()
    } catch (err) {
      this._log('warn', 'peers() failed', { message: err && err.message })
      return []
    }
    if (!Array.isArray(list)) return []
    return list.filter((p) => p && typeof p.send === 'function' && !(p.room && p.room.dm))
  }

  _send(peer, str) {
    try {
      return peer.send(str) !== false
    } catch (err) {
      this._log('debug', 'write to peer failed', { message: err && err.message })
      return false
    }
  }

  _emit(name, payload) {
    try {
      this._emitHook(name, payload)
    } catch (err) {
      this._log('warn', 'event handler failed', { event: name, message: err && err.message })
    }
  }

  _log(level, msg, data) {
    if (!this._logHook) return
    try {
      this._logHook(level, msg, data)
    } catch {}
  }
}

module.exports = {
  Feed,
  FEED_DEFAULTS: DEFAULTS,
  FEED_RESULT: RESULT,
  isFeedHash
}
