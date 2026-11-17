'use strict'

// The app channel of a room or DM connection: protomux protocol `hugin-messages` with a single
// message type of compact-encoding `string` (desktop swarm.cjs / native swarm.js
// `new_connection`). `Protomux.from(conn)` reuses the stream's existing mux, so the channel sits
// next to corestore replication (protomux `hypercore/alpha`) on the same connection, in either
// order.
//
// Messages written before the remote side opened its channel are buffered by the remote mux
// until it does, so `send` can be used right after opening.

const Protomux = require('protomux')
const c = require('compact-encoding')
const { PROTOCOL } = require('./constants.js')

function noop() {}

/**
 * Opens the `hugin-messages` channel on a connection.
 * @param {object} conn  a duplex stream (a Hyperswarm connection / NoiseSecretStream)
 * @param {(str: string) => void} onmessage  called with every received string; a throw or a
 *   rejected promise is swallowed (the caller handles its own errors)
 * @param {{ onclose?: () => void }} [opts]  `onclose`: the channel closed (remote close or the
 *   stream ended)
 * @returns {{ send(str: string): boolean, close(): void, readonly closed: boolean } | null}
 *   null when the stream is destroyed or already has an open `hugin-messages` channel
 */
function openHuginChannel(conn, onmessage, opts = {}) {
  if (!conn || conn.destroyed) return null
  const mux = Protomux.from(conn)
  const channel = mux.createChannel({
    protocol: PROTOCOL,
    onclose: () => {
      if (typeof opts.onclose === 'function') {
        try {
          opts.onclose()
        } catch {}
      }
    }
  })
  if (!channel) return null
  const message = channel.addMessage({
    encoding: c.string,
    onmessage: (str) => {
      try {
        const r = onmessage(str)
        if (r && typeof r.catch === 'function') r.catch(noop)
      } catch {}
    }
  })
  channel.open()

  return {
    get closed() {
      return channel.closed || !!conn.destroyed
    },

    /**
     * Writes one string. Returns false when nothing was written: not a string, channel closed,
     * stream destroyed or not writable. True means the frame was handed to the stream (it may
     * be buffered under backpressure).
     */
    send(str) {
      if (typeof str !== 'string') return false
      if (channel.closed || conn.destroyed || conn.writable === false) return false
      try {
        message.send(str)
        return true
      } catch {
        return false
      }
    },

    close() {
      try {
        channel.close()
      } catch {}
    }
  }
}

module.exports = {
  openHuginChannel,
  PROTOCOL
}
