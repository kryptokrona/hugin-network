'use strict'

// Room / DM / hugin-node swarm keys, room invites, admin signatures and the `idSig` identity
// check, as hugin-desktop and hugin-native derive them. Topic derivation itself is
// `hugin-network/swarm`'s (`huginTopicFromKey`, `getNewPeerKeys`, domain-separated since 3.0).
//
// Naming used here and in the apps:
//   swarm key      the bytes or string passed to `get_new_peer_keys` (rooms and DMs: a 64-byte
//                  SHA-512, hugin-node: an address string)
//   topic          hex(base public key), the string both apps call `topic` and send on the wire
//   discoveryKey   the 32-byte DHT topic, keccak256(UTF-8("hugin/topic") || base public key)

const b4a = require('b4a')
const { fill32, huginTopicFromKey, getNewPeerKeys: swarmGetNewPeerKeys } = require('./swarm.js')
const {
  NETWORK_ADDRESS,
  INVITE_HEX_LENGTH,
  NODE_KEY_INVITE_LENGTH,
  XKR_ADDRESS_LENGTH,
  HASH_HEX_LENGTH,
  SIGNING_DOMAINS
} = require('./constants.js')
const { isHex, hexToUint, toHex, randomKey, sha512 } = require('./bytes.js')
const { keyPairFromSeed, keychainSign, verifyDetached } = require('./ed25519.js')

class KeysError extends Error {
  constructor(message, code = 'HUGIN_KEYS_INVALID') {
    super(message)
    this.name = 'KeysError'
    this.code = code
  }
}

// ---------------------------------------------------------------------------------------------
// swarm keys

/**
 * SHA-512 over the hex bytes of `hex` (desktop `crypto.cjs:naclHash`, native RN
 * `services/bare/crypto.ts:naclHash`). Rooms hash the invite, DMs the key derivation hash.
 * @returns {Uint8Array} 64 bytes
 */
function swarmKey(hex) {
  return sha512(hexToUint(hex))
}

/** Swarm key of a room: SHA-512 of the invite bytes. */
function roomSwarmKey(invite) {
  return swarmKey(invite)
}

/**
 * Swarm key of a DM: SHA-512 of the bytes of `key_derivation_hash`
 * (`cn_fast_hash(generateKeyDerivation(peerViewPub, myViewPriv))`, computed by the host, which
 * holds the private view key: desktop `messages.cjs:key_derivation_hash`, RN `wallet.js`).
 */
function dmSwarmKey(derivationHash) {
  return swarmKey(derivationHash)
}

/**
 * Swarm key of hugin-node: the public network address, or the private node's address/invite.
 * An invite of NODE_KEY_INVITE_LENGTH characters (address, topic key in hex, node key in hex;
 * xkrd --private) gives its topic key as bytes; any other invite is the key as it is.
 */
function nodeSwarmKey({ address, pub } = {}) {
  if (pub) return NETWORK_ADDRESS
  if (typeof address !== 'string' || address.length === 0) {
    throw new TypeError('nodeSwarmKey: address is required for a private node')
  }
  if (address.length === NODE_KEY_INVITE_LENGTH) {
    const topicKey = address.slice(XKR_ADDRESS_LENGTH, XKR_ADDRESS_LENGTH + HASH_HEX_LENGTH)
    if (isHex(topicKey, HASH_HEX_LENGTH)) return hexToUint(topicKey)
  }
  return address
}

/** Native transports the room key as comma-separated bytes ("b0,b1,..."), see `toUintArray`. */
function swarmKeyFromCsv(csv) {
  return Uint8Array.from(String(csv).split(',').map((x) => parseInt(x, 10)))
}

function swarmKeyToCsv(bytes) {
  return Array.from(bytes).join(',')
}

/**
 * Topic data of a swarm key (swarm.js `huginTopicFromKey`): `topic` is the hex base public key
 * the apps use as the room id, `discoveryKey` the 32-byte DHT topic.
 * @returns {{ key, topicKey: Uint8Array, base: {publicKey, secretKey}, topic: string, discoveryKey: Uint8Array }}
 */
function topicFromSwarmKey(key) {
  const t = huginTopicFromKey(key)
  return {
    key,
    topicKey: t.topicKey,
    base: t.base,
    topic: toHex(t.base.publicKey),
    discoveryKey: t.topic
  }
}

function roomTopic(invite) {
  return topicFromSwarmKey(roomSwarmKey(invite))
}

function dmTopic(derivationHash) {
  return topicFromSwarmKey(dmSwarmKey(derivationHash))
}

function nodeTopic(opts) {
  return topicFromSwarmKey(nodeSwarmKey(opts))
}

/**
 * Per-swarm DHT identity (`get_new_peer_keys`): a fresh random DHT key pair (or the given one)
 * and its Hugin `mid`. Returns swarm.js `{ topic, keyPair, sig, base, basePublicKey }`.
 */
function newPeerKeys(key, keyPair) {
  return swarmGetNewPeerKeys(key, keyPair)
}

/**
 * Firewall rule of the apps' hugin-node client: any peer on the public topic, only the key in
 * the last 64 characters of the invite on a private node. Returns true when the peer is allowed.
 */
function isAllowedNodePeer(remotePublicKey, { address, pub } = {}) {
  if (pub) return true
  if (typeof address !== 'string') return false
  return toHex(remotePublicKey) === address.slice(-64)
}

// ---------------------------------------------------------------------------------------------
// invites and admin keys

/** True for a 128-character hex room invite (32 random bytes + admin public key). */
function isRoomInvite(invite) {
  return isHex(invite, INVITE_HEX_LENGTH)
}

/**
 * Admin key pair of a room: `keyPair(Buffer.alloc(32).fill(adminSeed))`. A hex string seed is
 * filled with its UTF-8 bytes (so only its first 32 characters count), as both apps do when they
 * sign (`sign_admin_message`) and desktop does when it creates the invite.
 */
function adminKeyPair(adminSeed) {
  return keyPairFromSeed(fill32(adminSeed))
}

/**
 * New room invite: `rand + hex(adminKeyPair(adminSeed).publicKey)` with a random 64-hex
 * `rand` and a random 64-hex `adminSeed` (desktop `crypto.cjs:create_room_invite`). The invite's
 * public key and later admin signatures both come from the same `adminKeyPair(adminSeed)`.
 * @param {{ adminSeed?: string, rand?: string }} [opts] fixed values (tests)
 * @returns {{ invite: string, adminSeed: string }}
 */
function createRoomInvite(opts = {}) {
  const adminSeed = opts.adminSeed !== undefined ? opts.adminSeed : randomKey()
  const rand = opts.rand !== undefined ? opts.rand : randomKey()
  if (!isHex(adminSeed, 64)) throw new TypeError('createRoomInvite: adminSeed must be 64 hex characters')
  if (!isHex(rand, 64)) throw new TypeError('createRoomInvite: rand must be 64 hex characters')
  const admin = adminKeyPair(adminSeed)
  return { invite: rand + toHex(admin.publicKey), adminSeed }
}

/** The admin public key in the last 64 characters of an invite, or null. */
function adminPublicKeyFromInvite(invite) {
  if (typeof invite !== 'string' || invite.length < 64) return null
  const hex = invite.slice(-64)
  if (!isHex(hex, 64)) return null
  return b4a.from(hex, 'hex')
}

/**
 * Admin signature of a peer's DHT public key (`joined.signature`), byte-identical to the apps'
 * keypear signature. Send it as hex.
 */
function signAdmin(adminSeed, dhtPublicKey) {
  return keychainSign(adminKeyPair(adminSeed), dhtPublicKey)
}

/**
 * Checks `joined.signature` (hex or bytes) against the invite's admin key for the DHT public key
 * of the connection it arrived on (desktop `swarm.cjs` / native `swarm.js` `verify_signature`).
 * An empty, malformed or wrong signature is simply "not admin".
 */
function verifyAdmin(dhtPublicKey, signature, invite) {
  const pub = adminPublicKeyFromInvite(invite)
  if (!pub) return false
  let sig = signature
  if (typeof signature === 'string') {
    if (!isHex(signature, 128)) return false
    sig = b4a.from(signature, 'hex')
  }
  return verifyDetached(sig, dhtPublicKey, pub)
}

// ---------------------------------------------------------------------------------------------
// idSig: the XKR address signs the peer's DHT public key in one swarm

const HEX64_RE = /^[0-9a-f]{64}$/i

/**
 * The string the XKR spend key signs for `joined.idSig` (README "Protocol"):
 *
 *   "hugin/id\n" + JSON.stringify([topic, hex(dhtPublicKey)])
 *
 * `topic` is the swarm's topic (hex of its base public key, lower case), `dhtPublicKey` the DHT
 * key the peer uses in that swarm (`connection.remotePublicKey` on the receiving side). The
 * context prefix keeps it apart from every other signed string, and the topic binds it to one
 * room or DM swarm. Throws a KeysError for a key that is not 32 bytes or a topic that is not 64
 * hex characters.
 */
function idSigMessage(dhtPublicKey, topic) {
  if (!(dhtPublicKey instanceof Uint8Array) || dhtPublicKey.byteLength !== 32) {
    throw new KeysError('idSigMessage: dhtPublicKey must be 32 bytes')
  }
  if (typeof topic !== 'string' || !HEX64_RE.test(topic)) throw new KeysError('idSigMessage: topic must be 64 hex characters')
  return SIGNING_DOMAINS.ID + JSON.stringify([topic.toLowerCase(), toHex(dhtPublicKey)])
}

/**
 * Signs the idSig of our DHT key in the swarm `topic` with the host's XKR message signer
 * (`sign(message) -> Promise<string>`; desktop `crypto.cjs:signMessage` with the spend key,
 * native RPC `sign-message`).
 * @param {{ dhtPublicKey: Uint8Array, topic: string }} o
 */
async function signIdSig({ dhtPublicKey, topic } = {}, sign) {
  if (typeof sign !== 'function') throw new TypeError('signIdSig: sign must be a function')
  const sig = await sign(idSigMessage(dhtPublicKey, topic))
  if (typeof sig !== 'string') throw new TypeError('signIdSig: sign() must return a string')
  return sig
}

/**
 * Verifies a peer's `idSig` for the connection's remote DHT key in the swarm `topic` with the
 * host's XKR verifier (`verify(message, address, signature) -> Promise<boolean>`; desktop
 * `crypto.cjs:verifySignature`, native RPC `verify-signature`). The result is awaited and must
 * be truthy; a throwing or rejecting verifier, or a malformed key or topic, counts as "not
 * verified".
 */
async function verifyIdSig({ dhtPublicKey, topic, address, idSig }, verify) {
  if (typeof verify !== 'function') throw new TypeError('verifyIdSig: verify must be a function')
  if (typeof address !== 'string' || address.length !== XKR_ADDRESS_LENGTH) return false
  if (typeof idSig !== 'string' || idSig.length === 0 || idSig.length > 128) return false
  if (!(dhtPublicKey instanceof Uint8Array) || dhtPublicKey.byteLength !== 32) return false
  if (typeof topic !== 'string' || !HEX64_RE.test(topic)) return false
  try {
    const ok = await verify(idSigMessage(dhtPublicKey, topic), address, idSig)
    return !!ok
  } catch {
    return false
  }
}

module.exports = {
  KeysError,
  hexToUint,
  swarmKey,
  roomSwarmKey,
  dmSwarmKey,
  nodeSwarmKey,
  swarmKeyFromCsv,
  swarmKeyToCsv,
  topicFromSwarmKey,
  roomTopic,
  dmTopic,
  nodeTopic,
  newPeerKeys,
  isAllowedNodePeer,
  isRoomInvite,
  adminKeyPair,
  createRoomInvite,
  adminPublicKeyFromInvite,
  signAdmin,
  verifyAdmin,
  idSigMessage,
  signIdSig,
  verifyIdSig
}
