'use strict'

// Canonical event names of hugin-network (README "Host hooks and events") and the shapes of their payloads. Events
// carry data only; the host decides how to store and show it. The host adapters map these names
// to the event names the apps use today (desktop IPC channels, native bare-rpc events).
//
// Text in payloads is what the peer sent, checked for type and length only (lib/sanitize.js);
// hosts apply `sanitizeText` / `sanitizeHtml` where they display it.

/** Rooms, peers, messages (lib/rooms.js, lib/room.js). */
const ROOM_JOINED = 'room:joined'
const ROOM_LEFT = 'room:left'
const PEER_JOINED = 'peer:joined'
const PEER_LEFT = 'peer:left'
const ROOM_MESSAGE = 'room:message'
const ROOM_HISTORY = 'room:history'
const DM_WIRE = 'dm:wire'
const TYPING = 'typing'
const BAN_SELF = 'ban:self'
const BAN_PEER = 'ban:peer'

/** Feed (lib/feed.js). */
const FEED_MESSAGE = 'feed:message'

/** Room calls (lib/voice.js). */
const VOICE_STATUS = 'voice:status'
const VOICE_CALL = 'voice:call'
const VOICE_OFFER = 'voice:offer'
const VOICE_ANSWER = 'voice:answer'
const VOICE_RETRY = 'voice:retry'

/** Files (lib/files.js emits these on its own emitter; same strings as `files.EVENTS`). */
const FILE_REMOTE = 'file:remote'
const FILE_DOWNLOADING = 'file:downloading'
const FILE_PROGRESS = 'file:progress'
const FILE_DOWNLOADED = 'file:downloaded'
const FILE_UPLOADED = 'file:uploaded'
const FILE_REMOVED = 'file:removed'
const FILE_ERROR = 'file:error'

/** hugin-node client (lib/node-client.js emits these on its own emitter). */
const NODE_CONNECTED = 'node:connected'
const NODE_DISCONNECTED = 'node:disconnected'
const NODE_ADDRESS = 'node:address'
const NODE_MESSAGES = 'node:messages'
const NODE_JOB = 'node:job'
const NODE_RESET = 'node:reset'
const NODE_ERROR = 'node:error'

/** Errors meant for the UI. */
const ERROR = 'error'

const EVENTS = Object.freeze({
  ROOM_JOINED,
  ROOM_LEFT,
  PEER_JOINED,
  PEER_LEFT,
  ROOM_MESSAGE,
  ROOM_HISTORY,
  DM_WIRE,
  TYPING,
  BAN_SELF,
  BAN_PEER,
  FEED_MESSAGE,
  VOICE_STATUS,
  VOICE_CALL,
  VOICE_OFFER,
  VOICE_ANSWER,
  VOICE_RETRY,
  FILE_REMOTE,
  FILE_DOWNLOADING,
  FILE_PROGRESS,
  FILE_DOWNLOADED,
  FILE_UPLOADED,
  FILE_REMOVED,
  FILE_ERROR,
  NODE_CONNECTED,
  NODE_DISCONNECTED,
  NODE_ADDRESS,
  NODE_MESSAGES,
  NODE_JOB,
  NODE_RESET,
  NODE_ERROR,
  ERROR
})

/** Every event name, for host adapter table tests. */
const ALL = Object.freeze(Object.values(EVENTS))

// ---------------------------------------------------------------------------------------------
// payloads

/**
 * @typedef {object} PeerInfo  public state of a joined peer (`Peer#toInfo()`)
 * @property {string} address   verified XKR address (the idSig checked out)
 * @property {string} name
 * @property {string} avatar    base64 or ''
 * @property {boolean} voice
 * @property {boolean} video
 * @property {boolean} audioMute
 * @property {boolean} videoMute
 * @property {boolean} screenshare
 * @property {boolean} admin    the room admin's key signed this peer's DHT key
 * @property {number|null} time  when the peer started its swarm (ms)
 */

/**
 * @typedef {object} RoomJoinedEvent  `room:joined`: the swarm is open. Not emitted for a room
 * that was left while it was still joining (its `join` rejects with HUGIN_ROOMS_LEFT).
 * @property {string} key      room invite, or the contact address for a DM
 * @property {string} topic    hex of the topic base public key
 * @property {boolean} dm
 * @property {boolean} admin   we hold the room's admin seed
 * @property {string} [address]  the contact (DM only)
 */

/**
 * @typedef {object} RoomLeftEvent  `room:left`: emitted by `leave` once the swarm and the room's
 * drive are closed, after the `peer:left` of every address that was in it; only for a room
 * whose `room:joined` went out.
 * @property {string} key
 * @property {string} topic
 * @property {boolean} dm
 */

/**
 * @typedef {object} PeerJoinedEvent  `peer:joined`: per address, not per connection. In a room
 * one address may have several connections (a user's phone and desktop); the event comes with
 * the first one that is verified, and later connections of the same address raise no event
 * (their name/avatar are not announced again). In a DM swarm there is one connection to the
 * contact. Host adapters that keep a "users in room" list can use it as is.
 * @property {string} key
 * @property {string} topic
 * @property {boolean} dm
 * @property {PeerInfo} peer
 */

/**
 * @typedef {object} PeerLeftEvent  `peer:left`: the last connection of the address closed (after
 * the frames it sent before closing were handled). Desktop's `close-voice-channel-with-peer`
 * mapping therefore fires when the user has no connection left in the room.
 * @property {string} key
 * @property {string} topic
 * @property {boolean} dm
 * @property {string} address
 */

/**
 * @typedef {object} RoomMessage  a validated room message (lib/sanitize.js `roomMessage`) whose
 * signature verified (`host.verify` over `wire.roomMessageSigningPayload`) for `address`. The
 * host stores every field as it is here, `signature` included, and hands the rows back from
 * `getRoomHistory` / `getRoomMessage` unchanged: peers verify them again, and rows without a
 * signature are not sent.
 * @property {string} message
 * @property {string} address
 * @property {string} signature  128 hex characters (XKR message signature of the author)
 * @property {string} room
 * @property {number} timestamp  integer ms, as signed (not clamped)
 * @property {string} name
 * @property {string} reply
 * @property {string} hash  64 hex characters, `wire.roomMessageHash` of the other fields
 * @property {false|{amount: number, receiver: string}} tip
 */

/**
 * @typedef {object} RoomMessageEvent  `room:message`: a verified message (the host stores it; may
 * be a duplicate)
 * @property {string} key
 * @property {string} topic
 * @property {RoomMessage} message
 * @property {boolean} history  part of a history batch (`joined.messages`, `missing-messages`)
 * @property {boolean} live     sent live, or fetched by the Ping sync while live
 */

/**
 * @typedef {object} RoomHistoryEvent  `room:history`, after a history batch
 * @property {string} key
 * @property {string} topic
 * @property {number} count       messages emitted from the batch
 * @property {RoomMessage[]} missing  those messages (live sync only, as desktop's `missing`)
 */

/**
 * @typedef {object} DmWireEvent  `dm:wire`: a DM payload from the verified contact (never from a
 * contact `host.isBlocked` reports)
 * @property {string} address  the contact
 * @property {string} topic
 * @property {string} wire     hugin-crypto `encodeExtra` hex, decrypted by the host
 */

/**
 * @typedef {object} TypingEvent  `typing`
 * @property {string} key
 * @property {string} topic
 * @property {string} address
 * @property {boolean} typing
 * @property {boolean} dm
 */

/**
 * @typedef {object} BanSelfEvent  `ban:self`: the room admin banned us (we leave the room)
 * @property {string} key
 * @property {string} topic
 */

/**
 * @typedef {object} BanPeerEvent  `ban:peer`: an address is banned in a room (host persists it)
 * @property {string} key
 * @property {string} topic
 * @property {string} address
 * @property {boolean} admin  true when the room admin ordered it (or we are the admin)
 */

/**
 * @typedef {object} FeedMessageEvent  `feed:message` (verified, not yet stored)
 * @property {object} message
 * @property {boolean} live  true for a message received as it was posted, false for history
 */

/**
 * @typedef {object} VoiceStatusEvent  `voice:status`: a peer's voice status (lib/sanitize.js
 * `voiceStatus` fields) plus the room
 * @property {string} key
 * @property {string} topic
 * @property {string} address
 * @property {string} name
 * @property {string} avatar
 * @property {boolean} voice
 * @property {boolean} video
 * @property {boolean} audioMute
 * @property {boolean} videoMute
 * @property {boolean} screenshare
 */

/**
 * @typedef {object} VoiceCallEvent  `voice:call`: the UI should call this peer (create an offer)
 * @property {string} key
 * @property {string} topic
 * @property {string} address
 * @property {string} name
 * @property {boolean} video
 * @property {boolean} audioMute
 * @property {boolean} videoMute
 * @property {boolean} screenshare
 */

/**
 * @typedef {object} VoiceSdpEvent  `voice:offer` / `voice:answer` / `voice:retry`
 * @property {string} key
 * @property {string} topic
 * @property {string} address  the sender (its verified joined address)
 * @property {{ data: string|object, offer: boolean, address: string, topic: string, retry: boolean }} data
 *   the SDP message as received
 */

module.exports = {
  EVENTS,
  ALL,
  ...EVENTS
}
