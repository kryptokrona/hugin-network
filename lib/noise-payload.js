'use strict'

// Noise handshake payload codec = upstream hyperdht `messages.noisePayload` + the Hugin `mid`.
//
// Wire format (identical to hyperdht-hugin 1.0.3 lib/messages.js):
//
//   flags |= 128, and after every upstream field: mid = fixed64
//
// Depends on hyperdht internals (lib/messages.js), so hyperdht stays at the exact version pinned in package.json.

const messages = require('hyperdht/lib/messages.js')
const c = require('compact-encoding')

const MID_FLAG = 128
const MID_BYTES = 64

const upstream = messages.noisePayload

/**
 * The flags field is a compact-encoding uint; upstream never sets more than bits 0..6 and the
 * largest possible value with `mid` (251) is still a single byte, so OR-ing the bit into the
 * already written byte is exactly what hyperdht-hugin's encoder produces.
 */
const midNoisePayload = {
  preencode(state, m) {
    upstream.preencode(state, m)
    if (m.mid) state.end += MID_BYTES
  },
  encode(state, m) {
    const start = state.start
    upstream.encode(state, m)
    if (!m.mid) return
    // byte 0 = version (uint 1), byte 1 = flags (< 128 from upstream, single byte)
    if (state.buffer[start] !== 1 || state.buffer[start + 1] >= MID_FLAG) {
      throw new Error('unexpected noise payload layout')
    }
    state.buffer[start + 1] |= MID_FLAG
    c.fixed64.encode(state, m.mid)
  },
  decode(state) {
    const start = state.start
    const version = state.buffer[start]
    const flags = state.end - start > 1 ? state.buffer[start + 1] : 0
    const m = upstream.decode(state)
    m.mid = null
    // flags < 0xfd is a single byte; upstream ignores bit 7, so the cursor now sits on `mid`.
    if (version === 1 && flags < 0xfd && (flags & MID_FLAG) !== 0) {
      m.mid = c.fixed64.decode(state)
      // The mid is the last field (hyperdht-hugin writes nothing after it): bytes behind it are
      // malformed, not a future extension.
      if (state.start !== state.end) throw new Error('trailing bytes after the Hugin mid')
    }
    return m
  }
}

module.exports = { MID_FLAG, MID_BYTES, midNoisePayload }
