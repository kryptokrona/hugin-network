'use strict'

// Room calls: our own voice state (one voice channel at a time, as both apps keep it), the
// voice status messages (not signed since hugin-network 3.0), the SDP relay between peers of a
// room, and the events that tell the UI whom to call and which SDP arrived (desktop swarm.cjs
// `send_voice_channel_status`, `check_sdp`, `get_sdp`; native swarm.js
// `send_voice_channel_status`, `send_sdp`, the `sdp` and `voice` branches of
// `check_data_message`).
//
// The WebRTC side stays in the UI. DM calls do not use this (they are signalled through
// hugin-node).

const wire = require('./wire.js')
const S = require('./sanitize.js')
const { MAX_VOICE_PEERS } = require('./constants.js')
const E = require('./events.js')

const OFFLINE = Object.freeze({
  key: null,
  topic: '',
  voice: false,
  video: false,
  audioMute: false,
  videoMute: false,
  screenshare: false
})

/** Both apps call the peers already in voice 100 ms after joining a voice channel. */
const CALL_DELAY_MS = 100
/** Native waits 2 s before calling a peer that joins the room while both are in voice. */
const JOIN_CALL_DELAY_MS = 2000

function noop() {}

class Voice {
  /**
   * @param {object} [opts]
   * @param {object} [opts.host]  `identity() => { address, name, avatar }`
   * @param {(level, msg, data) => void} [opts.log]
   * @param {(name: string, payload: object) => void} [opts.emit]
   * @param {import('./rooms.js').Rooms} [opts.rooms]  set by Rooms when not given
   * @param {number} [opts.callDelayMs]
   * @param {number} [opts.joinCallDelayMs]
   */
  constructor(opts = {}) {
    this.host = opts.host || {}
    this.rooms = opts.rooms || null
    this._logHook = typeof opts.log === 'function' ? opts.log : null
    this._emitHook = typeof opts.emit === 'function' ? opts.emit : null
    this.callDelayMs = typeof opts.callDelayMs === 'number' ? opts.callDelayMs : CALL_DELAY_MS
    this.joinCallDelayMs = typeof opts.joinCallDelayMs === 'number' ? opts.joinCallDelayMs : JOIN_CALL_DELAY_MS
    this.state = { ...OFFLINE }
    this._timers = new Set()
    this.destroyed = false
  }

  // -------------------------------------------------------------------------------------------
  // local state

  /** The room we are in voice in (`{ key, topic, voice, video, ... }`), or null. */
  get active() {
    return this.state.topic && (this.state.voice || this.state.video) ? { ...this.state } : null
  }

  /**
   * Our voice fields for a room, as `joined` carries them (all false unless we are in voice in
   * that room).
   */
  local(topic) {
    const s = this.state
    if (!topic || s.topic !== topic) {
      return { voice: false, video: false, audioMute: false, videoMute: false, screenshare: false }
    }
    return { voice: s.voice, video: s.video, audioMute: s.audioMute, videoMute: s.videoMute, screenshare: s.screenshare }
  }

  /**
   * Announces our voice status in a room and records it locally
   * (`send_voice_channel_status(joined, status, update)` of both apps). `status.voice` is the
   * "joined the voice channel" flag; `video` implies it (as `joined` sends it). Unless `update`,
   * joining calls every peer of the room that is in voice already (`voice:call`). Returns false
   * for an unknown room, or when the status could not be built: then nothing is sent, the local
   * state stays as it was and nobody is called.
   * @param {string} key  room key or topic
   * @param {{ voice?, video?, audioMute?, videoMute?, screenshare? }} status
   * @param {{ update?: boolean }} [opts]
   */
  async setStatus(key, status = {}, { update = false } = {}) {
    const room = this.rooms ? this.rooms.get(key) : null
    if (!room || room.dm) return false
    const video = status.video === true
    const joined = status.voice === true || video
    const fields = {
      voice: joined,
      video,
      audioMute: status.audioMute === true,
      videoMute: status.videoMute === true,
      screenshare: status.screenshare === true
    }
    let str
    try {
      const id = this._identity()
      str = wire.encode(
        wire.voiceStatus({
          address: id.address,
          avatar: id.avatar,
          topic: room.topic,
          name: S.clampText(id.name, S.SEND.voice.name),
          ...fields
        })
      )
    } catch (err) {
      this._log('warn', 'voice status not sent', { message: err && err.message })
      return false
    }
    if (room.closed || this.destroyed) return false

    this.state = joined ? { key: room.key, topic: room.topic, ...fields } : { ...OFFLINE }
    room.send(str)

    if (update || !joined) return true
    // call those who announced their voice status before us
    for (const peer of room.joinedPeers()) {
      if (!peer.voice || !peer.address) continue
      this._later(this.callDelayMs, () => {
        if (peer.closed || !peer.voice || this.state.topic !== room.topic || !this.state.voice) return
        this._call(room, peer)
      })
    }
    return true
  }

  /**
   * Leaves the voice channel we are in (announces voice off). Returns false when not in one, or
   * when the announcement could not be built; our local state goes offline either way.
   */
  async leave() {
    const s = this.state
    if (!s.topic) return false
    const room = this.rooms ? this.rooms.get(s.topic) : null
    if (!room) {
      this.state = { ...OFFLINE }
      return false
    }
    const ok = await this.setStatus(room.key, { voice: false, video: false, audioMute: false, videoMute: false, screenshare: false })
    if (!ok && this.state.topic === s.topic) this.state = { ...OFFLINE }
    return ok
  }

  /**
   * Sends an SDP from the UI to one peer of a room (desktop `get_sdp`, native `send_sdp`): an
   * answer or a renegotiation is not an offer, `retry: true` asks the peer to expand it. The
   * message carries our own address as the sender. Returns true when it was written.
   * @param {{ topic?: string, key?: string, address: string, data: string|object, type?: string, retry?: boolean }} o
   *   `address` is the peer the SDP is for
   */
  sendSdp(o = {}) {
    const room = this.rooms ? this.rooms.get(o.topic || o.key) : null
    if (!room || room.dm) return false
    const peer = room.peerByAddress(o.address)
    if (!peer) return false
    const { offer, retry } = wire.sdpFlags({ type: o.type, data: o.data, retry: o.retry })
    let str
    try {
      str = wire.encode(wire.sdp({ data: o.data, offer, address: this._identity().address, topic: room.topic, retry }))
    } catch (err) {
      this._log('warn', 'sdp not sent', { message: err && err.message })
      return false
    }
    return peer.send(str)
  }

  // -------------------------------------------------------------------------------------------
  // inbound (called by Room for joined peers of a room)

  /**
   * A voice status from a joined peer. Returns false when it does not carry the peer's own
   * verified address (both apps ban for that); a status for another room is ignored.
   */
  handleStatus(room, peer, status) {
    if (status.address !== peer.address) return false
    if (status.topic !== room.topic) return true
    peer.voice = status.voice
    peer.video = status.video
    peer.audioMute = status.audioMute
    peer.videoMute = status.videoMute
    peer.screenshare = status.screenshare
    this._emit(E.VOICE_STATUS, { ...status, key: room.key, topic: room.topic })
    return true
  }

  /**
   * An SDP from a joined peer. Acted on only when it comes from the peer's own verified
   * address, for this room, while the peer announced voice, we are in voice in this room and the
   * call has fewer than 10 peers in voice.
   */
  handleSdp(room, peer, sdp) {
    if (sdp.address !== peer.address) {
      this._log('debug', 'sdp ignored: not from the sender address')
      return false
    }
    if (sdp.topic !== room.topic) return false
    if (!peer.voice) return false
    if (!this.local(room.topic).voice) return false
    const inVoice = room.joinedPeers().filter((p) => p.voice).length
    if (inVoice >= MAX_VOICE_PEERS) return false
    const payload = { key: room.key, topic: room.topic, address: peer.address, data: sdp }
    if (sdp.offer === true) this._emit(sdp.retry === true ? E.VOICE_RETRY : E.VOICE_OFFER, payload)
    else this._emit(E.VOICE_ANSWER, payload)
    return true
  }

  /**
   * A peer joined a room. When both of us are in voice there and it started its swarm before
   * us, we create the offer (`voice:call`, after a short delay as native).
   */
  onPeerJoined(room, peer) {
    if (room.dm || !peer.voice || !this.local(room.topic).voice) return
    if (!(typeof peer.time === 'number' && room.time > peer.time)) return
    this._later(this.joinCallDelayMs, () => {
      if (peer.closed || !peer.voice || !this.local(room.topic).voice) return
      this._call(room, peer)
    })
  }

  /** We left a room: our voice state there goes offline. */
  onRoomLeft(room) {
    if (this.state.topic === room.topic) this.state = { ...OFFLINE }
  }

  destroy() {
    this.destroyed = true
    for (const t of this._timers) clearTimeout(t)
    this._timers.clear()
    this.state = { ...OFFLINE }
  }

  // -------------------------------------------------------------------------------------------
  // helpers

  _call(room, peer) {
    this._emit(E.VOICE_CALL, {
      key: room.key,
      topic: room.topic,
      address: peer.address,
      name: peer.name,
      video: peer.video,
      audioMute: peer.audioMute,
      videoMute: peer.videoMute,
      screenshare: peer.screenshare
    })
  }

  _later(ms, fn) {
    if (this.destroyed) return
    const t = setTimeout(() => {
      this._timers.delete(t)
      if (this.destroyed) return
      try {
        fn()
      } catch (err) {
        this._log('warn', 'voice task failed', { message: err && err.message })
      }
    }, Math.max(0, ms))
    this._timers.add(t)
  }

  _identity() {
    if (this.rooms && typeof this.rooms.identity === 'function') return this.rooms.identity()
    const id = typeof this.host.identity === 'function' ? this.host.identity() : this.host.identity
    return id && typeof id === 'object' ? id : {}
  }

  _emit(name, payload) {
    const hook = this._emitHook || (this.rooms && this.rooms._eventHook()) || noop
    try {
      hook(name, payload)
    } catch (err) {
      this._log('warn', 'event handler failed', { event: name, message: err && err.message })
    }
  }

  _log(level, msg, data) {
    const hook = this._logHook || (this.rooms && this.rooms._logHook) || null
    if (!hook) return
    try {
      hook(level, msg, data)
    } catch {}
  }
}

module.exports = {
  Voice,
  CALL_DELAY_MS,
  JOIN_CALL_DELAY_MS
}
