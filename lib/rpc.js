'use strict'

// The bare-rpc framing hugin-node and the apps speak over a hugin-node connection, reduced to what that protocol uses: plain requests and responses, no
// streams. Byte-compatible with bare-rpc 1.3.3 (vectors in test/fixtures/hugin-relay.json `rpc`).
//
//   frame    = len u32 LE (bytes after this field) | type uint | id uint | body
//   REQUEST  (1): command uint | stream uint | stream == 0: data (uint length + bytes)
//   RESPONSE (2): error bool | stream uint | error ? message utf8, code utf8, errno zigzag int
//                                          : stream == 0: data
//   STREAM   (3): stream uint | ... (never sent here; received ones are ignored)
//   uint     = compact-encoding uint (< 0xfd: 1 byte, 0xfd + u16, 0xfe + u32, 0xff + u64)
//
// Request ids count from 1 per side; id 0 is an event (no response). Each side answers every
// request of the other with a RESPONSE carrying the same id. hugin-node and both apps answer
// with `{"ok":true,"data":null,"error":null}` and ignore the responses they get.
//
// No Node-only APIs: runs under Node and Bare. The stream only needs `write`, `destroy` and the
// events `data`, `close` and `error` (a Hyperswarm connection, or a fake in tests).

const b4a = require('b4a')
const c = require('compact-encoding')

const TYPE = Object.freeze({ REQUEST: 1, RESPONSE: 2, STREAM: 3 })

/** bare-rpc's default limit on one frame (16 MiB). A `some` answer can be several MB. */
const DEFAULT_MAX_FRAME_BYTES = 16 * 1024 * 1024
/** Requests awaiting a response; above this the oldest is given up (its promise rejects). */
const MAX_PENDING_RESPONSES = 1024

class RpcError extends Error {
  constructor(message, code) {
    super(message)
    this.name = 'RpcError'
    this.code = code || 'HUGIN_RPC_ERROR'
  }
}

function toBytes(data) {
  if (data === null || data === undefined) return b4a.alloc(0)
  if (typeof data === 'string') return b4a.from(data, 'utf8')
  if (data instanceof Uint8Array) return data
  throw new TypeError('rpc: data must be a string or a Uint8Array')
}

/** Frame of a REQUEST (`id` 0 = event). */
function encodeRequest({ id, command, data }) {
  const bytes = toBytes(data)
  const state = c.state()
  c.uint.preencode(state, TYPE.REQUEST)
  c.uint.preencode(state, id)
  c.uint.preencode(state, command)
  c.uint.preencode(state, 0)
  c.uint.preencode(state, bytes.byteLength)
  const head = state.end
  state.end += 4
  state.buffer = b4a.allocUnsafe(state.end + bytes.byteLength)
  c.uint32.encode(state, head + bytes.byteLength)
  c.uint.encode(state, TYPE.REQUEST)
  c.uint.encode(state, id)
  c.uint.encode(state, command)
  c.uint.encode(state, 0)
  c.uint.encode(state, bytes.byteLength)
  state.buffer.set(bytes, state.start)
  return state.buffer
}

/** Frame of a RESPONSE: `data` for a success, `error` ({ message, code, errno }) for a failure. */
function encodeResponse({ id, data, error }) {
  const state = c.state()
  let bytes = null
  c.uint.preencode(state, TYPE.RESPONSE)
  c.uint.preencode(state, id)
  c.bool.preencode(state, !!error)
  c.uint.preencode(state, 0)
  if (error) {
    c.utf8.preencode(state, String(error.message || ''))
    c.utf8.preencode(state, error.code === undefined || error.code === null ? '' : String(error.code))
    c.int.preencode(state, Number(error.errno) || 0)
  } else {
    bytes = toBytes(data)
    c.uint.preencode(state, bytes.byteLength)
  }
  const head = state.end
  const total = head + (bytes ? bytes.byteLength : 0)
  state.end += 4
  state.buffer = b4a.allocUnsafe(state.end + (bytes ? bytes.byteLength : 0))
  c.uint32.encode(state, total)
  c.uint.encode(state, TYPE.RESPONSE)
  c.uint.encode(state, id)
  c.bool.encode(state, !!error)
  c.uint.encode(state, 0)
  if (error) {
    c.utf8.encode(state, String(error.message || ''))
    c.utf8.encode(state, error.code === undefined || error.code === null ? '' : String(error.code))
    c.int.encode(state, Number(error.errno) || 0)
  } else {
    c.uint.encode(state, bytes.byteLength)
    state.buffer.set(bytes, state.start)
  }
  return state.buffer
}

/**
 * Decodes the body of one frame (without the 4 length bytes):
 * `{ type, id, command, stream, data }`, `{ type, id, stream, error, data }` or
 * `{ type: STREAM, id, stream }`. Throws on a malformed body.
 */
function decodeBody(body) {
  const state = c.state(0, body.byteLength, body)
  const type = c.uint.decode(state)
  const id = c.uint.decode(state)
  if (type === TYPE.REQUEST) {
    const command = c.uint.decode(state)
    const stream = c.uint.decode(state)
    const data = stream === 0 ? c.buffer.decode(state) : null
    return { type, id, command, stream, data }
  }
  if (type === TYPE.RESPONSE) {
    const isError = c.bool.decode(state)
    const stream = c.uint.decode(state)
    if (isError) {
      const message = c.utf8.decode(state)
      const code = c.utf8.decode(state)
      const errno = c.int.decode(state)
      return { type, id, stream, error: { message, code, errno }, data: null }
    }
    const data = stream === 0 ? c.buffer.decode(state) : null
    return { type, id, stream, error: null, data }
  }
  if (type === TYPE.STREAM) {
    const stream = c.uint.decode(state)
    return { type, id, stream }
  }
  throw new RpcError(`unknown message type ${type}`, 'HUGIN_RPC_UNKNOWN_MESSAGE')
}

/**
 * Splits a byte stream into frame bodies. `push(chunk)` returns the complete bodies; throws an
 * RpcError when a frame announces more than `maxFrameBytes`.
 */
class FrameDecoder {
  constructor({ maxFrameBytes = DEFAULT_MAX_FRAME_BYTES } = {}) {
    this.maxFrameBytes = maxFrameBytes
    this.chunks = []
    this.buffered = 0
  }

  push(chunk) {
    const out = []
    if (chunk && chunk.byteLength) {
      this.chunks.push(chunk)
      this.buffered += chunk.byteLength
    }
    while (this.buffered >= 4) {
      const buffer = this.chunks.length === 1 ? this.chunks[0] : b4a.concat(this.chunks)
      this.chunks = [buffer]
      const len = c.uint32.decode(c.state(0, 4, buffer))
      if (len > this.maxFrameBytes) {
        throw new RpcError(`frame of ${len} bytes exceeds the limit of ${this.maxFrameBytes}`, 'HUGIN_RPC_FRAME_TOO_LARGE')
      }
      if (this.buffered < 4 + len) break
      out.push(buffer.subarray(4, 4 + len))
      const rest = buffer.subarray(4 + len)
      this.chunks = rest.byteLength ? [rest] : []
      this.buffered = rest.byteLength
    }
    return out
  }
}

/** An incoming request handed to the `onrequest` callback. */
class IncomingRequest {
  constructor(channel, id, command, data) {
    this.channel = channel
    this.id = id
    this.command = command
    this.data = data
    this.sent = false
  }

  get isEvent() {
    return this.id === 0
  }

  /** Answers the request (no-op for an event, or when already answered). */
  reply(data) {
    if (this.sent || this.id === 0) return false
    this.sent = true
    return this.channel._write(encodeResponse({ id: this.id, data }))
  }

  replyError(error) {
    if (this.sent || this.id === 0) return false
    this.sent = true
    return this.channel._write(encodeResponse({ id: this.id, error }))
  }
}

/**
 * Request/response channel over one stream (what `new RPC(conn, onrequest)` gives the apps).
 *
 *   const ch = new RpcChannel(conn, (req) => { ...; req.reply('...') })
 *   ch.request(1, '{"type":"job_request","id":"..."}')   // -> Promise<response data>
 *   ch.event(1, '...')                                    // id 0, no response
 *
 * `onerror(err)` is called once for a protocol failure (the stream is then destroyed). The
 * channel closes with the stream; pending requests reject with code `HUGIN_RPC_CLOSED`.
 */
class RpcChannel {
  constructor(stream, onrequest, { maxFrameBytes = DEFAULT_MAX_FRAME_BYTES, onerror = null } = {}) {
    if (!stream || typeof stream.write !== 'function' || typeof stream.on !== 'function') {
      throw new TypeError('RpcChannel: stream must be a duplex stream')
    }
    this.stream = stream
    this.onrequest = typeof onrequest === 'function' ? onrequest : null
    this.onerror = typeof onerror === 'function' ? onerror : null
    this.decoder = new FrameDecoder({ maxFrameBytes })
    this.nextId = 0
    this.pending = new Map()
    this.closed = false
    this.error = null

    this._ondata = this._ondata.bind(this)
    this._onclose = this._onclose.bind(this)
    this._onerror = this._onerror.bind(this)
    stream.on('data', this._ondata)
    stream.on('close', this._onclose)
    stream.on('error', this._onerror)
  }

  /** Sends a request; the promise resolves with the response data (bytes) or rejects. */
  request(command, data) {
    if (this.closed) return Promise.reject(this._closedError())
    if (this.nextId >= Number.MAX_SAFE_INTEGER) this.nextId = 0
    const id = ++this.nextId
    let entry
    const promise = new Promise((resolve, reject) => {
      entry = { resolve, reject }
    })
    promise.catch(noop)
    this.pending.set(id, entry)
    if (this.pending.size > MAX_PENDING_RESPONSES) {
      const [oldest, old] = this.pending.entries().next().value
      this.pending.delete(oldest)
      old.reject(new RpcError('response never arrived', 'HUGIN_RPC_DROPPED'))
    }
    if (!this._write(encodeRequest({ id, command, data }))) {
      this.pending.delete(id)
      entry.reject(this._closedError())
    }
    return promise
  }

  /** Sends an event (request id 0, never answered). Returns false if the channel is closed. */
  event(command, data) {
    if (this.closed) return false
    return this._write(encodeRequest({ id: 0, command, data }))
  }

  /** Stops using the stream (it is destroyed too unless `{ keepStream: true }`). */
  destroy(err, { keepStream = false } = {}) {
    if (!keepStream && !this.stream.destroyed) {
      try {
        this.stream.destroy()
      } catch {}
    }
    this._teardown(err || null)
  }

  _write(frame) {
    if (this.closed || this.stream.destroyed || this.stream.destroying) return false
    try {
      this.stream.write(frame)
      return true
    } catch (err) {
      this._fail(err)
      return false
    }
  }

  _ondata(chunk) {
    if (this.closed) return
    let bodies
    try {
      bodies = this.decoder.push(chunk)
    } catch (err) {
      return this._fail(err)
    }
    for (const body of bodies) {
      if (this.closed) return
      let message
      try {
        message = decodeBody(body)
      } catch (err) {
        return this._fail(err instanceof RpcError ? err : new RpcError(`malformed message: ${err.message}`, 'HUGIN_RPC_INVALID'))
      }
      if (message.type === TYPE.REQUEST) this._onrequestmessage(message)
      else if (message.type === TYPE.RESPONSE) this._onresponse(message)
      // STREAM frames: this protocol opens no streams, so there is nothing they could refer to.
    }
  }

  _onrequestmessage(message) {
    if (message.stream !== 0) {
      // A stream request cannot be served; refuse it like bare-rpc refuses unknown streams.
      const req = new IncomingRequest(this, message.id, message.command, null)
      req.replyError({ message: 'streams are not supported', code: 'UNSUPPORTED' })
      return
    }
    const req = new IncomingRequest(this, message.id, message.command, message.data)
    if (!this.onrequest) {
      req.reply(null)
      return
    }
    try {
      const res = this.onrequest(req)
      if (res && typeof res.then === 'function') {
        res.then(noop, (err) => {
          if (!req.sent) req.replyError(err || { message: 'error' })
        })
      }
    } catch (err) {
      if (!req.sent) req.replyError(err || { message: 'error' })
    }
  }

  _onresponse(message) {
    const entry = this.pending.get(message.id)
    if (!entry) return
    this.pending.delete(message.id)
    if (message.error) {
      const err = new RpcError(message.error.message, message.error.code || 'HUGIN_RPC_REMOTE')
      err.errno = message.error.errno
      entry.reject(err)
    } else {
      entry.resolve(message.data || b4a.alloc(0))
    }
  }

  _onerror(err) {
    this._teardown(err)
  }

  _onclose() {
    this._teardown(null)
  }

  _fail(err) {
    if (this.closed) return
    if (this.onerror) {
      try {
        this.onerror(err)
      } catch {}
    }
    try {
      this.stream.destroy()
    } catch {}
    this._teardown(err)
  }

  _closedError() {
    const err = new RpcError('channel closed', 'HUGIN_RPC_CLOSED')
    if (this.error) err.cause = this.error
    return err
  }

  _teardown(err) {
    if (this.closed) return
    this.closed = true
    this.error = err
    this.stream.removeListener('data', this._ondata)
    this.stream.removeListener('close', this._onclose)
    // the error listener stays: a stream may still emit 'error' while it is destroyed
    const pending = [...this.pending.values()]
    this.pending.clear()
    const closed = this._closedError()
    for (const entry of pending) entry.reject(closed)
  }
}

function noop() {}

module.exports = {
  TYPE,
  DEFAULT_MAX_FRAME_BYTES,
  MAX_PENDING_RESPONSES,
  RpcError,
  encodeRequest,
  encodeResponse,
  decodeBody,
  FrameDecoder,
  IncomingRequest,
  RpcChannel
}
