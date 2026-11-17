'use strict'

// Constants shared by the Hugin apps (hugin-desktop `src/backend/*.cjs`, hugin-native
// `bare/*.js`) and hugin-node. Values are copied from those sources; where they live is noted.

/** Public hugin-node topic key (desktop swarm.cjs NodeConnection.public, native swarm.js). */
const NETWORK_ADDRESS = 'xkr96c0f8a36e951b399681d447922f6c54c28c6ef3cad1c65d3568008151337'

/** Push server sealed-box public key (desktop messages.cjs, native bare/messages.js). */
const PUSH_SERVER_PUBKEY = '6e18d19b3c94f7c2c4da5dc6f17305f8ab6da33f8beb18e63a0f048d2a21c345'

/** Protomux protocol of the app channel (one message type, compact-encoding `string`). */
const PROTOCOL = 'hugin-messages'

/**
 * Domain strings of the topic and mid derivation of hugin-network 3.0 (domain-separated, README
 * "Protocol"); clients using the earlier derivation cannot connect.
 *   topic = keccak256(UTF-8(TOPIC_DOMAIN) || base.publicKey)
 *   mid   = ed25519_sign(UTF-8(MID_DOMAIN) || dhtPublicKey, base.secretKey)
 */
const TOPIC_DOMAIN = 'hugin/topic'
const MID_DOMAIN = 'hugin/mid'

/**
 * Context prefixes of every string the host's XKR key signs (`host.sign`; README "Protocol"). Each
 * signed string is `prefix + JSON.stringify([...fields])`. The prefixes are distinct, end with
 * a newline and contain no other newline. No version numbers in them: a later format gets a
 * new name.
 */
const SIGNING_DOMAINS = Object.freeze({
  ID: 'hugin/id\n', // joined.idSig: [topic, hex(dhtPublicKey)]
  ROOM_MESSAGE: 'hugin/room-message\n', // room message signature
  FEED: 'hugin/feed\n', // feed message signature
  FILE: 'hugin/file\n', // file announcement / drive metadata signature
  DM: 'hugin/dm\n' // DM text signature: [to, timestamp, text, flags, handshake digest]
})

/** Prefixes of the derived (not signed) message hashes, BLAKE2b-256 of prefix + JSON array. */
const HASH_DOMAINS = Object.freeze({
  ROOM_MESSAGE: 'hugin/room-message-hash\n',
  FEED: 'hugin/feed-hash\n'
})

/** `type` values on the hugin-messages channel. */
const TYPES = Object.freeze({
  FEED: 'feed',
  DISCONNECTED: 'disconnected',
  BAN: 'ban',
  PING: 'Ping',
  REQUEST_MESSAGES: 'request-messages',
  MISSING_MESSAGES: 'missing-messages',
  REQUEST_HISTORY: 'request-history',
  SEND_HISTORY: 'send-history',
  REQUEST_FEED: 'request-feed',
  SEND_FEED_HISTORY: 'send-feed-history'
})

/** `info` / `type` of a file announcement. */
const FILE_SHARED = 'file-shared'
const FILE_TYPE = 'file'

const XKR_ADDRESS_LENGTH = 99
const HASH_HEX_LENGTH = 64
const TOPIC_HEX_LENGTH = 64
const INVITE_HEX_LENGTH = 128

const ONE_DAY_MS = 24 * 60 * 60 * 1000
const ONE_WEEK_MS = 7 * ONE_DAY_MS

/** Room state sync: one Ping every 10 s, at most 25 hashes, 100 peers and 10 files. */
const PING_INTERVAL_MS = 10 * 1000
const MAX_PING_HASHES = 25
const MAX_PING_PEERS = 100
const MAX_SHARED_FILES = 10

/** At most 10 peers in a room voice call (both apps stop answering at 10 connections in voice). */
const MAX_VOICE_PEERS = 10

/** hugin-node: a PACKET body above 9000 bytes gets the sender banned. */
const MAX_NODE_PACKET_BYTES = 9000

/** hugin-node: messages in one sync answer (`some`), also the most a client takes from one sync or push. */
const MAX_NODE_SYNC_MESSAGES = 500

/** hugin-node: the only bare-rpc command (`PACKET`), carrying one JSON packet per request. */
const NODE_PACKET_COMMAND = 1

/** What hugin-node and both apps answer every PACKET request with (the answer is ignored). */
const NODE_RPC_REPLY = '{"ok":true,"data":null,"error":null}'

module.exports = {
  NETWORK_ADDRESS,
  PUSH_SERVER_PUBKEY,
  PROTOCOL,
  TOPIC_DOMAIN,
  MID_DOMAIN,
  SIGNING_DOMAINS,
  HASH_DOMAINS,
  TYPES,
  FILE_SHARED,
  FILE_TYPE,
  XKR_ADDRESS_LENGTH,
  HASH_HEX_LENGTH,
  TOPIC_HEX_LENGTH,
  INVITE_HEX_LENGTH,
  ONE_DAY_MS,
  ONE_WEEK_MS,
  PING_INTERVAL_MS,
  MAX_PING_HASHES,
  MAX_PING_PEERS,
  MAX_SHARED_FILES,
  MAX_VOICE_PEERS,
  MAX_NODE_PACKET_BYTES,
  MAX_NODE_SYNC_MESSAGES,
  NODE_PACKET_COMMAND,
  NODE_RPC_REPLY
}
