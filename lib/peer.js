'use strict'

// One connection in a room or DM swarm (the apps' `connEntry`, desktop swarm.cjs / native
// swarm.js `new_connection`): the `hugin/3/messages` channel, the identity the peer announced in
// its `joined` once it was verified, its voice state and the sync bookkeeping of the room.
//
// A Peer is created by its Room for every connection; until `joined` is true nothing the peer
// sends except `joined` is acted on, and nothing but our own `joined` is sent to it by the room.
// The room handles the frames of one peer one at a time, in order (`_chain`).

const b4a = require('b4a')
const wire = require('./wire.js')

function noop() {}

/** Window of the per-peer rate limits (`rate`). */
const RATE_WINDOW_MS = 60 * 1000

/**
 * Fixed-window counter. Returns true (and counts the event) while fewer than `limit` events
 * happened in the current window of `windowMs`; a limit of 0 allows nothing.
 * @param {{ start: number, count: number }} state
 */
function takeRate(state, limit, windowMs = RATE_WINDOW_MS, now = Date.now()) {
  if (now - state.start >= windowMs) {
    state.start = now
    state.count = 0
  }
  if (state.count >= limit) return false
  state.count++
  return true
}

/** True when `takeRate` would allow one more event now (nothing is counted). */
function canTakeRate(state, limit, windowMs = RATE_WINDOW_MS, now = Date.now()) {
  if (now - state.start >= windowMs) return limit > 0
  return state.count < limit
}

function newRateState() {
  return { start: 0, count: 0 }
}

class Peer {
  /**
   * @param {object} opts
   * @param {import('./room.js').Room} opts.room
   * @param {object} opts.connection  the Hyperswarm connection (NoiseSecretStream)
   * @param {object} [opts.info]  Hyperswarm PeerInfo (`ban(bool)`), when there is one
   */
  constructor({ room, connection, info = null }) {
    this.room = room
    this.connection = connection
    this.peerInfo = info
    /** hex of the connection's remote (DHT) public key */
    this.remotePublicKey = connection && connection.remotePublicKey ? b4a.toString(connection.remotePublicKey, 'hex') : ''

    /** Set from a verified `joined` (stays true after the connection closed). */
    this.joined = false
    this.address = null
    this.name = ''
    this.avatar = ''
    this.admin = false
    /** when the peer started its swarm (ms), from `joined.time` */
    this.time = null
    /** the peer's drive key (64 hex) from `joined.driveKey`, or null */
    this.driveKey = null

    this.voice = false
    this.video = false
    this.audioMute = false
    this.videoMute = false
    this.screenshare = false

    /** Room sync state: the latest hashes of the peer's Ping (native `con.knownHashes`). */
    this.knownHashes = []
    /** Hashes (lower-case) we asked this peer for with `request-messages`, not answered yet. */
    this.requested = new Set()

    this.closed = false
    this.closeReason = null
    this.channel = null
    /** Promise of the `joined` check in progress (resolves true when the peer was admitted). */
    this._joining = null
    this._joinTimer = null
    this._onclose = noop

    // inbound frames: handled one at a time, in order (lib/room.js)
    this._chain = Promise.resolve()
    this._queued = 0
    this._preJoin = 0
    /** a `joined` frame arrived (it may still be queued or being checked) */
    this._joinSeen = false
    /** closed for misbehaving: frames still queued from it are dropped */
    this._discard = false
    /** we sent `request-history` and wait for `send-history` */
    this._historyRequested = false
    /** we answered its `request-history` (once per connection) */
    this._historyAnswered = false
    /** history entries it relayed whose signature did not verify (lib/room.js maxBadHistory) */
    this._badHistory = 0
    this._rates = new Map()
  }

  /**
   * True while it fits the per-minute limit `limit` of the counter `name` (and counts it).
   * Used by the room to rate-limit what a peer can make us do.
   */
  rate(name, limit, windowMs = RATE_WINDOW_MS) {
    let state = this._rates.get(name)
    if (!state) {
      state = newRateState()
      this._rates.set(name, state)
    }
    return takeRate(state, limit, windowMs)
  }

  /** True when `rate(name, limit)` would allow one more now (nothing is counted). */
  canRate(name, limit, windowMs = RATE_WINDOW_MS) {
    const state = this._rates.get(name)
    return state ? canTakeRate(state, limit, windowMs) : limit > 0
  }

  /** True while frames can be written. */
  get writable() {
    const conn = this.connection
    if (this.closed || !this.channel || this.channel.closed) return false
    if (!conn || conn.destroyed || conn.destroying || conn.writable === false) return false
    return true
  }

  /** Room sync state (native `con.request`): true while we wait for `missing-messages`. */
  get request() {
    return this.requested.size > 0
  }

  /**
   * Writes one string on the `hugin/3/messages` channel. Returns false when the peer is closed
   * or the stream is not writable.
   */
  send(str) {
    if (typeof str !== 'string' || !this.writable) return false
    return this.channel.send(str)
  }

  /** Encodes (lib/wire.js `encode`, size-guarded) and sends a message object. */
  write(message) {
    let str
    try {
      str = typeof message === 'string' ? message : wire.encode(message)
    } catch {
      return false
    }
    return this.send(str)
  }

  /** Public state, as carried in `peer:joined`. */
  toInfo() {
    return {
      address: this.address,
      name: this.name,
      avatar: this.avatar,
      voice: this.voice,
      video: this.video,
      audioMute: this.audioMute,
      videoMute: this.videoMute,
      screenshare: this.screenshare,
      admin: this.admin,
      time: this.time
    }
  }

  /**
   * Hyperswarm's per-peer ban (no reconnects to this key from this swarm), where the connection
   * came with a PeerInfo.
   */
  ban() {
    if (this.peerInfo && typeof this.peerInfo.ban === 'function') {
      try {
        this.peerInfo.ban(true)
      } catch {}
    }
  }

  /** Closes the channel and the connection; the room forgets the peer (once). */
  close(reason = 'closed') {
    if (this.closed) return
    this.closed = true
    this.closeReason = reason
    if (this._joinTimer) {
      clearTimeout(this._joinTimer)
      this._joinTimer = null
    }
    if (this.channel) this.channel.close()
    const conn = this.connection
    if (conn && !conn.destroyed) {
      try {
        if (typeof conn.end === 'function') conn.end()
      } catch {}
      try {
        conn.destroy()
      } catch {}
    }
    try {
      this._onclose(reason)
    } catch {}
  }
}

module.exports = {
  Peer,
  RATE_WINDOW_MS,
  takeRate,
  canTakeRate,
  newRateState
}
