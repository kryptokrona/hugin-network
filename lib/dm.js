'use strict'

// hugin-network/dm: private messages (DMs) between two XKR addresses, on top of the hugin-crypto
// primitives (ML-KEM-512, XSalsa20-Poly1305, CryptoNote key derivation). What both apps did
// around those primitives lives here: building and opening the DM wire payload, the per-contact
// ML-KEM handshake state, node pool entries, the DM swarm key and the push view tag.
//
// The module holds no keys of the wallet. The host gives it:
//   * a crypto provider: the hugin-crypto module or an object with the same functions (README
//     "hugin-network/dm");
//   * hooks: the wallet's private view key operation (`keyDerivation`), the spend key signature
//     (`sign`), the contact crypto store (`loadContactCrypto` / `saveContactCrypto`), the ML-KEM
//     identity store (`loadKemIdentity` / `saveKemIdentity`), the identity, and time (`now`).
//
// Wire payload: one byte string, hex once. The primitives are
// hugin-crypto's (CryptoNote key derivation, its view tag and box key, XSalsa20-Poly1305
// secretbox, ML-KEM-512); the KEM public key and capsule travel as raw bytes inside the box.
//
//   payload = hex(version 0x01 | t: uint64 BE | txKey: 32 | vt: 1 | box)
//   r       = a fresh scalar per message: 64 bytes from the operating system's random source,
//             reduced mod l; txKey = r*G (CryptoNote secret_key_to_public_key of r)
//   d       = generate_key_derivation(viewPublicKey(recipient), r)
//           = generate_key_derivation(txKey, recipient's private view key)
//   vt      = cn_fast_hash(d)[0];  outerKey = cn_fast_hash("626f78" || d)
//   box     = secretbox(outer, nonceFromTimestamp(t), outerKey)
//   outer   = flags: 1 | from: 99 ASCII | [kem_pub: 800] | [kem_ct: 768] | body or inner
//             (flags 1: kem_pub and the body; 6: kem_ct and the inner box; 4: the inner box)
//   inner   = secretbox(body, txKey[0..24], messageKey)
//   body    = nameLength: 1 | name: UTF-8 | signature: 64 | text: UTF-8 (the rest)
//   signature = the sender's spend key signature of
//             "hugin/dm\n" + JSON.stringify([to, t, text, flags, hs]),
//             hs = hex(SHA-256(kem_pub)) with flags 1, hex(SHA-256(kem_ct)) with flags 6, '' with 4
//
// The scalar r and txKey are made here, not by the crypto provider: with sodium-universal
// (Node.js, Electron, Bare) from randombytes_buf, crypto_core_ed25519_scalar_reduce and
// crypto_scalarmult_ed25519_base_noclamp; on React Native, where this file is bundled without
// sodium, from crypto.getRandomValues and the same arithmetic in JavaScript (BigInt).
//
// Handshake state per contact: without a message key we
// send our ML-KEM public key (`kem_pub`); a contact's `kem_pub` is answered by encapsulating
// against it (our key, sent with its capsule `kem_ct` until the contact uses the key); a capsule
// that opens the message gives the contact's key. Both sides sending a capsule at once settle on
// the smaller of the two keys. Timestamps of the contact's own messages tell a newer handshake
// (the contact lost its state) from a late copy of an older one; a message dated more than a day
// ahead of our clock changes no state.
//
// Pure JavaScript apart from the optional sodium-universal above: no hyperswarm, no Node-only
// APIs, no global Buffer. Loads in React Native (Hermes), Bare and Node.

const b4a = require('b4a')
const { keccak256 } = require('js-sha3')
const { XKR_ADDRESS_LENGTH, ONE_WEEK_MS, SIGNING_DOMAINS, MAX_NODE_PACKET_BYTES } = require('./constants.js')

const KEM_PUB_BYTES = 800
const KEM_SECRET_BYTES = 1632
const KEM_CIPHERTEXT_BYTES = 768
const KEY_BYTES = 32

/** First byte of every DM payload. */
const PAYLOAD_VERSION = 1
/** `flags` bits of the outer plaintext. */
const FLAG_KEM_PUB = 1
const FLAG_KEM_CT = 2
const FLAG_INNER = 4
/** The `flags` values `encrypt` writes, and the only ones `open` takes: initial, reply, established. */
const ACCEPTED_FLAGS = Object.freeze([FLAG_KEM_PUB, FLAG_KEM_CT | FLAG_INNER, FLAG_INNER])

/** Field sizes of the payload layout, in bytes. */
const SIZES = Object.freeze({
  VERSION: 1,
  TIMESTAMP: 8,
  TX_KEY: 32,
  VIEW_TAG: 1,
  HEADER: 42, // version + timestamp + txKey + view tag
  MAC: 16, // secretbox
  FLAGS: 1,
  FROM: XKR_ADDRESS_LENGTH,
  KEM_PUB: KEM_PUB_BYTES,
  KEM_CT: KEM_CIPHERTEXT_BYTES,
  NAME_LENGTH: 1,
  SIGNATURE: 64
})

/** Bytes of a payload with an empty name and text and no KEM field, without inner box. */
const MIN_PAYLOAD_BYTES = SIZES.HEADER + SIZES.MAC + SIZES.FLAGS + SIZES.FROM + SIZES.NAME_LENGTH + SIZES.SIGNATURE

/**
 * Longest payload (hex characters) for a node post: a post packet without its `cipher` is at most
 * about 905 bytes (call kind, 64-character view tag, 32-character job id, 76-byte blob, one
 * share), and hugin-node takes at most 9000 bytes; this leaves about 500 bytes to spare.
 */
const NODE_PAYLOAD_BUDGET = 7600

const DEFAULTS = Object.freeze({
  /** older message keys kept to open late messages */
  maxPreviousKeys: 3,
  /** longest payload `open` takes, in hex characters (DM swarm and push payloads) */
  maxPayloadLength: 65536,
  /** longest node pool entry `openPool` takes, in hex characters (hugin-node's `cipher` limit) */
  maxPoolPayloadLength: MAX_NODE_PACKET_BYTES,
  /** node pool entries this short (hex characters) are not DM payloads (desktop: > 200) */
  minPoolPayloadLength: 201,
  /** node pool hashes remembered so that an entry is opened once */
  maxKnownPoolHashes: 1000,
  /** attempts at a node pool entry whose opening failed in a host hook */
  maxPoolTries: 3,
  /** contact names are cut to this many characters */
  maxNameLength: 50,
  /** a message dated more than this many ms ahead of our clock changes no handshake state (one day) */
  maxFutureMs: 24 * 60 * 60 * 1000
})

/** Result `status` of `open`. */
const STATUS = Object.freeze({
  /** opened and verified: `message` */
  OK: 'ok',
  /** not a DM payload (e.g. another kind of pool entry) */
  NOT_DM: 'not-dm',
  /** a DM payload for another recipient (view tag differs) */
  NOT_FOR_US: 'not-for-us',
  /** for us by its view tag, but it does not open or verify (`reason`) */
  REFUSED: 'refused',
  /** a host hook failed; the same payload may open later (`reason`) */
  ERROR: 'error'
})

/**
 * The crypto provider functions used (hugin-crypto 1.0.0 exports them under these names). The
 * per-message key pair is made by this module (`generateTxKey`), so `ephemeralKeypair` is not one
 * of them.
 */
const CRYPTO_FUNCTIONS = Object.freeze([
  'friendRequestSecretSender',
  'addressToViewPub',
  'viewTag',
  'boxKey',
  'nonceFromTimestamp',
  'secretboxEncrypt',
  'secretboxOpen',
  'generateKemKeypair',
  'encapsulate',
  'decapsulate',
  'messageHash'
])

class DmError extends Error {
  constructor(message, code = 'HUGIN_DM_INVALID') {
    super(message)
    this.name = 'DmError'
    this.code = code
  }
}

function noop() {}

// ---------------------------------------------------------------------------------------------
// bytes

const HEX_RE = /^[0-9a-f]*$/i

function isHex(value, length) {
  if (typeof value !== 'string' || !HEX_RE.test(value)) return false
  if (length === undefined) return value.length % 2 === 0
  return value.length === length
}

function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2)
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16)
  return out
}

const HEX_DIGITS = '0123456789abcdef'

function bytesToHex(bytes) {
  let out = ''
  for (let i = 0; i < bytes.length; i++) out += HEX_DIGITS[bytes[i] >> 4] + HEX_DIGITS[bytes[i] & 15]
  return out
}

function utf8(str) {
  return new Uint8Array(b4a.from(str, 'utf8'))
}

function fromUtf8(bytes) {
  return b4a.toString(b4a.from(bytes.buffer, bytes.byteOffset, bytes.byteLength), 'utf8')
}

/** Lower-case hex of a hex string or a Uint8Array of `bytes` bytes, else ''. */
function hexOf(value, bytes) {
  if (value instanceof Uint8Array) return value.byteLength === bytes ? bytesToHex(value) : ''
  if (isHex(value, bytes * 2)) return value.toLowerCase()
  return ''
}

/** `cn_fast_hash` of hex input: Keccak-256 (original padding) of the bytes, as hex. */
function cnFastHashHex(hex) {
  return keccak256(hexToBytes(hex))
}

function isPlainObject(v) {
  return v !== null && typeof v === 'object' && !Array.isArray(v)
}

function isTimestamp(t) {
  return Number.isSafeInteger(t) && t >= 0
}

const ADDRESS_RE = /^SEKR[\x21-\x7e]+$/

/** An XKR address as the apps use it: 99 printable ASCII characters starting with `SEKR`. */
function isAddress(address) {
  return typeof address === 'string' && address.length === XKR_ADDRESS_LENGTH && ADDRESS_RE.test(address)
}

/** The contact address of a chat id (its first 99 characters). */
function contactOf(address) {
  return typeof address === 'string' ? address.slice(0, XKR_ADDRESS_LENGTH) : ''
}

function clampName(name, max) {
  if (typeof name !== 'string') return ''
  const chars = Array.from(name)
  return chars.length > max ? chars.slice(0, max).join('') : name
}

// ---------------------------------------------------------------------------------------------
// SHA-256 (FIPS 180-4), for the handshake field digest `hs` of the signed string

const SHA256_K = Uint32Array.of(
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
)

function rotr(x, n) {
  return (x >>> n) | (x << (32 - n))
}

/** SHA-256 of `bytes` (Uint8Array) as 64 lower-case hex characters. */
function sha256Hex(bytes) {
  const n = bytes.length
  const total = Math.ceil((n + 9) / 64) * 64
  const msg = new Uint8Array(total)
  msg.set(bytes)
  msg[n] = 0x80
  const view = new DataView(msg.buffer)
  view.setUint32(total - 8, Math.floor(n / 0x20000000))
  view.setUint32(total - 4, (n * 8) >>> 0)
  const H = Uint32Array.of(0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19)
  const W = new Uint32Array(64)
  for (let off = 0; off < total; off += 64) {
    for (let i = 0; i < 16; i++) W[i] = view.getUint32(off + 4 * i)
    for (let i = 16; i < 64; i++) {
      const w15 = W[i - 15]
      const w2 = W[i - 2]
      const s0 = rotr(w15, 7) ^ rotr(w15, 18) ^ (w15 >>> 3)
      const s1 = rotr(w2, 17) ^ rotr(w2, 19) ^ (w2 >>> 10)
      W[i] = (W[i - 16] + s0 + W[i - 7] + s1) >>> 0
    }
    let a = H[0]
    let b = H[1]
    let c = H[2]
    let d = H[3]
    let e = H[4]
    let f = H[5]
    let g = H[6]
    let h = H[7]
    for (let i = 0; i < 64; i++) {
      const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)
      const ch = (e & f) ^ (~e & g)
      const t1 = (h + S1 + ch + SHA256_K[i] + W[i]) >>> 0
      const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)
      const maj = (a & b) ^ (a & c) ^ (b & c)
      const t2 = (S0 + maj) >>> 0
      h = g
      g = f
      f = e
      e = (d + t1) >>> 0
      d = c
      c = b
      b = a
      a = (t1 + t2) >>> 0
    }
    H[0] = (H[0] + a) >>> 0
    H[1] = (H[1] + b) >>> 0
    H[2] = (H[2] + c) >>> 0
    H[3] = (H[3] + d) >>> 0
    H[4] = (H[4] + e) >>> 0
    H[5] = (H[5] + f) >>> 0
    H[6] = (H[6] + g) >>> 0
    H[7] = (H[7] + h) >>> 0
  }
  let out = ''
  for (let i = 0; i < 8; i++) out += H[i].toString(16).padStart(8, '0')
  return out
}

// ---------------------------------------------------------------------------------------------
// per-message key: r (a scalar mod l) and txKey = r*G

const SCALAR_BYTES = 32
const WIDE_SCALAR_BYTES = 64
const SODIUM_MODULE = 'sodium-universal'

/** { sodium } after the first lookup; `sodium` is null where it does not load. */
let sodiumLookup = null

function isReactNative() {
  return typeof navigator === 'object' && navigator !== null && navigator.product === 'ReactNative'
}

/**
 * sodium-universal with the functions used here (Node.js, Electron, Bare), or null (React Native).
 * It is required through a variable so that bundlers (Metro) leave it out of a React Native
 * bundle of this file.
 */
function optionalSodium() {
  if (sodiumLookup === null) {
    let sodium = null
    if (!isReactNative()) {
      try {
        const load = require
        const s = load(SODIUM_MODULE)
        if (
          s &&
          typeof s.randombytes_buf === 'function' &&
          typeof s.crypto_core_ed25519_scalar_reduce === 'function' &&
          typeof s.crypto_scalarmult_ed25519_base_noclamp === 'function'
        ) {
          sodium = s
        }
      } catch {}
    }
    sodiumLookup = { sodium }
  }
  return sodiumLookup.sodium
}

/** `n` bytes from the operating system's random source (sodium's randombytes_buf, else crypto.getRandomValues). */
function osRandomBytes(n, sodium) {
  const out = new Uint8Array(n)
  if (sodium) {
    sodium.randombytes_buf(out)
    return out
  }
  const webcrypto = typeof globalThis === 'object' && globalThis !== null ? globalThis.crypto : undefined
  if (!webcrypto || typeof webcrypto.getRandomValues !== 'function') {
    throw new DmError('no random source: sodium-universal or crypto.getRandomValues is needed', 'HUGIN_DM_CRYPTO')
  }
  webcrypto.getRandomValues(out)
  return out
}

function isZero(bytes) {
  let acc = 0
  for (let i = 0; i < bytes.length; i++) acc |= bytes[i]
  return acc === 0
}

/**
 * The ed25519 arithmetic in JavaScript (BigInt): scalars mod l and r*G in extended twisted Edwards
 * coordinates (a = -1, complete addition), encoded as CryptoNote and libsodium encode a point
 * (y little-endian, the sign of x in the top bit). Made on first use.
 */
let edCurve = null

function ed25519() {
  if (edCurve) return edCurve
  const big = BigInt
  const ZERO = big(0)
  const ONE = big(1)
  const TWO = big(2)
  const P = (ONE << big(255)) - big(19)
  const L = (ONE << big(252)) + big('27742317777372353535851937790883648493')
  const D = big('37095705934669439343138083508754565189542113879843219016388785533085940283555')
  const GX = big('15112221349535400772501151409588531511454012693041857206046113283949847762202')
  const GY = big('46316835694926478169428394003475163141307993866256225615783033603165251855960')
  const MASK = (ONE << big(256)) - ONE
  const D2 = (D * TWO) % P
  const mod = (a) => {
    const r = a % P
    return r < ZERO ? r + P : r
  }
  const pow = (base, exp) => {
    let result = ONE
    let b = mod(base)
    let e = exp
    while (e > ZERO) {
      if (e & ONE) result = (result * b) % P
      b = (b * b) % P
      e >>= ONE
    }
    return result
  }
  const add = (p, q) => {
    const A = mod((p[1] - p[0]) * (q[1] - q[0]))
    const B = mod((p[1] + p[0]) * (q[1] + q[0]))
    const C = mod(p[3] * D2 * q[3])
    const Dd = mod(p[2] * TWO * q[2])
    const E = B - A
    const F = Dd - C
    const G = Dd + C
    const H = B + A
    return [mod(E * F), mod(G * H), mod(F * G), mod(E * H)]
  }
  const cswap = (p, q, mask) => {
    for (let i = 0; i < 4; i++) {
      const t = mask & (p[i] ^ q[i])
      p[i] ^= t
      q[i] ^= t
    }
  }
  const fromLE = (bytes) => {
    let v = ZERO
    for (let i = bytes.length - 1; i >= 0; i--) v = (v << big(8)) | big(bytes[i])
    return v
  }
  const toLE = (v, n) => {
    const out = new Uint8Array(n)
    for (let i = 0; i < n; i++) {
      out[i] = Number(v & big(255))
      v >>= big(8)
    }
    return out
  }
  edCurve = {
    /** 64 (or 32) little-endian bytes reduced mod l, as 32 bytes */
    scalarReduce(bytes) {
      return toLE(fromLE(bytes) % L, SCALAR_BYTES)
    },
    /** the 32-byte encoding of scalar*G (scalar: 32 little-endian bytes) */
    scalarmultBase(scalar) {
      const k = fromLE(scalar)
      let r0 = [ZERO, ONE, ONE, ZERO]
      let r1 = [GX, GY, ONE, mod(GX * GY)]
      for (let i = 255; i >= 0; i--) {
        const mask = (k >> big(i)) & ONE ? MASK : ZERO
        cswap(r0, r1, mask)
        r1 = add(r0, r1)
        r0 = add(r0, r0)
        cswap(r0, r1, mask)
      }
      const zi = pow(r0[2], P - TWO)
      const x = mod(r0[0] * zi)
      const y = mod(r0[1] * zi)
      const out = toLE(y, 32)
      out[31] |= Number(x & ONE) << 7
      return out
    }
  }
  return edCurve
}

/** scalar*G for a 32-byte scalar below l, with sodium when it is there. */
function scalarmultBase(scalar, sodium) {
  if (sodium) {
    const out = new Uint8Array(32)
    sodium.crypto_scalarmult_ed25519_base_noclamp(out, scalar)
    return out
  }
  return ed25519().scalarmultBase(scalar)
}

/**
 * A new per-message key pair: r = 64 bytes from the operating system's random source reduced mod
 * l, txKey = r*G. `{ privateKey, publicKey }` as 64 lower-case hex characters each; `publicKey` is
 * CryptoNote's secret_key_to_public_key(privateKey).
 */
function generateTxKey() {
  const sodium = optionalSodium()
  for (;;) {
    const wide = osRandomBytes(WIDE_SCALAR_BYTES, sodium)
    let scalar
    if (sodium) {
      scalar = new Uint8Array(SCALAR_BYTES)
      sodium.crypto_core_ed25519_scalar_reduce(scalar, wide)
    } else {
      scalar = ed25519().scalarReduce(wide)
    }
    wide.fill(0)
    if (isZero(scalar)) continue
    const publicKey = scalarmultBase(scalar, sodium)
    const out = { privateKey: bytesToHex(scalar), publicKey: bytesToHex(publicKey) }
    scalar.fill(0)
    return out
  }
}

/**
 * CryptoNote's secret_key_to_public_key: `privateKey`*G for a scalar below l (64 hex), as 64 hex.
 * `opts.js`: the JavaScript arithmetic even where sodium is loaded.
 */
function secretKeyToPublicKey(privateKey, opts) {
  if (!isHex(privateKey, 64)) throw new DmError('privateKey must be 64 hex characters')
  const scalar = hexToBytes(privateKey)
  const curve = ed25519()
  if (bytesToHex(curve.scalarReduce(scalar)) !== privateKey.toLowerCase() || isZero(scalar)) {
    throw new DmError('privateKey must be a non-zero scalar below l')
  }
  const sodium = opts && opts.js === true ? null : optionalSodium()
  return bytesToHex(scalarmultBase(scalar, sodium))
}

/** 64 (or 32) little-endian bytes reduced mod l, as 32 bytes; `opts.js` as above. */
function scalarReduce(bytes, opts) {
  const sodium = opts && opts.js === true ? null : optionalSodium()
  if (sodium && bytes.length === WIDE_SCALAR_BYTES) {
    const out = new Uint8Array(SCALAR_BYTES)
    sodium.crypto_core_ed25519_scalar_reduce(out, bytes)
    return out
  }
  return ed25519().scalarReduce(bytes)
}

/** Which arithmetic `generateTxKey` uses here: 'sodium' or 'js'. */
function txKeyBackend() {
  return optionalSodium() ? 'sodium' : 'js'
}

// ---------------------------------------------------------------------------------------------
// signed string

/**
 * The string the sender's spend key signs for a DM: `"hugin/dm\n" + JSON.stringify([to,
 * timestamp, text, flags, hs])` (`to`: the recipient's 99-character address, `timestamp`: the
 * payload's integer `t`, `flags`: the outer `flags` byte (1, 6 or 4), `hs`: `handshakeDigest` of
 * the handshake field). The sender is the address the signature is checked against, so it is not
 * repeated; the name is not signed.
 */
function dmSigningPayload(to, timestamp, text, flags, hs) {
  if (!isAddress(to)) throw new DmError('to must be an XKR address')
  if (!isTimestamp(timestamp)) throw new DmError('timestamp must be a non-negative integer')
  if (typeof text !== 'string') throw new DmError('text must be a string')
  if (!ACCEPTED_FLAGS.includes(flags)) throw new DmError('flags must be 1, 6 or 4')
  if (typeof hs !== 'string' || !(hs === '' ? flags === FLAG_INNER : flags !== FLAG_INNER && isHex(hs, 64))) {
    throw new DmError('hs must be 64 hex characters with flags 1 and 6, and empty with flags 4')
  }
  return SIGNING_DOMAINS.DM + JSON.stringify([to, timestamp, text, flags, hs.toLowerCase()])
}

/**
 * `hs` of the signed string: hex(SHA-256(kem_pub)) when the payload carries kem_pub,
 * hex(SHA-256(kem_ct)) when it carries kem_ct, '' otherwise (Uint8Array fields or null).
 */
function handshakeDigest(kemPub, kemCt) {
  if (kemPub) return sha256Hex(kemPub)
  if (kemCt) return sha256Hex(kemCt)
  return ''
}

// ---------------------------------------------------------------------------------------------
// push view tag

/**
 * DM push view tag of a recipient: `cn_fast_hash(UTF-8(viewPublicKey + week))`, the first 3 hex
 * characters, all 64 with `long` (calls); `week = floor(now / one week)`. Same value as
 * `push.dmViewTag`.
 */
function dmViewTag(viewPublicKey, { now = Date.now(), long = false } = {}) {
  const hash = keccak256(utf8(String(viewPublicKey) + String(Math.floor(now / ONE_WEEK_MS))))
  return long ? hash : hash.substring(0, 3)
}

// ---------------------------------------------------------------------------------------------
// contact state

/**
 * The stored crypto state of a contact, normalised (hex strings in lower case; anything malformed
 * dropped):
 *   messageKey         64 hex or '': the key messages to the contact are encrypted with
 *   pendingKemCapsule  1536 hex or '': our ML-KEM capsule for that key, sent until the contact uses the key
 *   peerKemPub         1600 hex or '': the contact's ML-KEM public key our capsule was made for
 *   keyTime            the contact's timestamp of the last handshake step (a message under the key does not change it)
 *   previousKeys       up to `maxPreviousKeys` older keys, newest first, used only to open late messages
 * Accepts the apps' field forms too (Uint8Array values, `peerKemPubHex`).
 */
function normalizeState(raw, maxPreviousKeys = DEFAULTS.maxPreviousKeys) {
  const s = isPlainObject(raw) ? raw : {}
  const messageKey = hexOf(s.messageKey, KEY_BYTES)
  const out = {
    messageKey,
    pendingKemCapsule: messageKey ? hexOf(s.pendingKemCapsule, KEM_CIPHERTEXT_BYTES) : '',
    peerKemPub: hexOf(s.peerKemPub !== undefined ? s.peerKemPub : s.peerKemPubHex, KEM_PUB_BYTES),
    keyTime: isTimestamp(s.keyTime) ? s.keyTime : 0,
    previousKeys: []
  }
  if (Array.isArray(s.previousKeys)) {
    for (const k of s.previousKeys) {
      const key = hexOf(k, KEY_BYTES)
      if (key && key !== messageKey && !out.previousKeys.includes(key)) out.previousKeys.push(key)
      if (out.previousKeys.length >= maxPreviousKeys) break
    }
  }
  return out
}

function sameState(a, b) {
  return JSON.stringify(a) === JSON.stringify(b)
}

/**
 * The contact state after an authenticated message from the contact. Pure apart from
 * `encapsulate(peerKemPubHex) -> { messageKey, kemCapsule }` (hex), called when a new key of ours
 * is needed. `keyTime` only moves forward; a capsule or `kem_pub` with `t <= keyTime` is a late
 * copy and keeps the current key (a capsule's key is kept for opening only).
 *
 * @param {object} state  normalised state (normalizeState)
 * @param {object} ev
 * @param {number} ev.t  the message's timestamp (the contact's clock)
 * @param {string|null} ev.keyUsed  the key that opened the inner box (null: no inner box)
 * @param {string|null} ev.capsuleKey  the key decapsulated from the message's `kem_ct`, only when it opened the inner box
 * @param {string|null} ev.peerKemPub  the message's `kem_pub`
 * @param {Function} encapsulate
 * @param {number} [maxPreviousKeys]
 */
function nextState(state, ev, encapsulate, maxPreviousKeys = DEFAULTS.maxPreviousKeys) {
  const s = normalizeState(state, maxPreviousKeys)
  const t = ev.t
  const keep = (key) => {
    if (!key) return
    s.previousKeys = [key, ...s.previousKeys.filter((k) => k !== key && k !== s.messageKey)].slice(0, maxPreviousKeys)
  }
  const use = (key, capsule, peerKemPub) => {
    s.messageKey = key
    s.pendingKemCapsule = capsule
    if (peerKemPub) s.peerKemPub = peerKemPub
    s.keyTime = Math.max(s.keyTime, t)
    s.previousKeys = s.previousKeys.filter((k) => k !== key)
  }
  const ours = (peerKemPub) => {
    const { messageKey, kemCapsule } = encapsulate(peerKemPub)
    use(messageKey, kemCapsule, peerKemPub)
  }

  const capsuleKey = ev.capsuleKey || null
  if (capsuleKey) {
    if (!s.messageKey) {
      // the contact answered our kem_pub
      use(capsuleKey, '', '')
    } else if (capsuleKey === s.messageKey) {
      // the capsule of the key in use again: nothing changes
    } else if (s.pendingKemCapsule && t <= s.keyTime) {
      // a capsule not newer than our pending key: a late copy, kept for opening only
      keep(capsuleKey)
    } else if (s.pendingKemCapsule) {
      // both sides answered each other: both keep the smaller key
      if (capsuleKey < s.messageKey) {
        const own = s.messageKey
        use(capsuleKey, '', '')
        keep(own)
      } else {
        keep(capsuleKey)
      }
    } else if (t > s.keyTime) {
      // a capsule newer than anything under our key: the contact started over
      const old = s.messageKey
      use(capsuleKey, '', '')
      keep(old)
    } else {
      keep(capsuleKey)
    }
  } else if (ev.keyUsed && ev.keyUsed === s.messageKey && s.pendingKemCapsule) {
    // the contact uses our key: our capsule arrived
    s.pendingKemCapsule = ''
    s.keyTime = Math.max(s.keyTime, t)
  }
  // any other message under the key in use or a previous key changes nothing (no write per message)

  const peerKemPub = ev.peerKemPub || null
  if (peerKemPub) {
    if (!s.messageKey) {
      ours(peerKemPub)
    } else if (s.pendingKemCapsule && peerKemPub === s.peerKemPub) {
      // the contact has not got our capsule yet; it goes out with every message until it has
    } else if (t > s.keyTime) {
      // the contact has no key any more (a new install or a new ML-KEM key pair)
      const old = s.messageKey
      ours(peerKemPub)
      keep(old)
    }
    // else: older than the current key, a late copy
  }
  return s
}

// ---------------------------------------------------------------------------------------------
// DmCrypto

class DmCrypto {
  /**
   * @param {object} opts
   * @param {object} opts.crypto  crypto provider: the hugin-crypto module or the same functions (CRYPTO_FUNCTIONS)
   * @param {object} opts.host  hooks (README "hugin-network/dm"): identity, sign, verify, keyDerivation,
   *   loadContactCrypto, saveContactCrypto, loadKemIdentity, saveKemIdentity, now, log
   * @param {string[]} [opts.knownPoolHashes]  node pool hashes already handled (oldest first)
   * Limits (`maxPreviousKeys`, `maxPayloadLength`, `maxPoolPayloadLength`, `minPoolPayloadLength`, `maxKnownPoolHashes`,
   * `maxNameLength`): see DEFAULTS.
   */
  constructor(opts = {}) {
    const crypto = opts.crypto
    if (!crypto || (typeof crypto !== 'object' && typeof crypto !== 'function')) {
      throw new DmError('DmCrypto: opts.crypto is required (the hugin-crypto module)')
    }
    const missing = CRYPTO_FUNCTIONS.filter((name) => typeof crypto[name] !== 'function')
    if (missing.length) throw new DmError('DmCrypto: crypto provider lacks ' + missing.join(', '))
    if (!opts.host || typeof opts.host !== 'object') throw new DmError('DmCrypto: opts.host is required')
    this.crypto = crypto
    this.host = opts.host
    const options = {}
    for (const k of Object.keys(DEFAULTS)) {
      const v = opts[k]
      options[k] = Number.isSafeInteger(v) && v >= 0 ? v : DEFAULTS[k]
    }
    this.options = options
    this._locks = new Map()
    this._kem = null
    this._known = new Set()
    /** body signatures (hex) of the messages `openPool` delivered */
    this._seenSignatures = new Set()
    /** pool hash -> failed attempts (a host hook failed) */
    this._tries = new Map()
    if (Array.isArray(opts.knownPoolHashes)) for (const h of opts.knownPoolHashes) this._remember(h)
  }

  // -------------------------------------------------------------------------------------------
  // keys

  /**
   * Our ML-KEM identity `{ publicKey, secretKey }` (Uint8Array): `host.loadKemIdentity()`, or a
   * new key pair saved with `host.saveKemIdentity({ publicKey, secretKey })` (hex) when the host
   * has none. Loaded once. Rejects with a DmError (`HUGIN_DM_HOST`) when the load hook throws.
   */
  kemIdentity() {
    if (!this._kem) {
      this._kem = this._loadKem()
      this._kem.catch(() => {
        this._kem = null
      })
    }
    return this._kem
  }

  async _loadKem() {
    let stored = null
    const load = this.host.loadKemIdentity
    if (typeof load === 'function') {
      try {
        stored = await load.call(this.host)
      } catch (err) {
        throw new DmError('ML-KEM identity not loaded: ' + ((err && err.message) || 'host.loadKemIdentity failed'), 'HUGIN_DM_HOST')
      }
    }
    if (isPlainObject(stored)) {
      const publicKey = hexOf(stored.publicKey, KEM_PUB_BYTES)
      const secretKey = hexOf(stored.secretKey, KEM_SECRET_BYTES)
      if (publicKey && secretKey) return { publicKey: hexToBytes(publicKey), secretKey: hexToBytes(secretKey) }
      if (stored.publicKey || stored.secretKey) this._log('warn', 'stored ML-KEM identity is malformed; a new one is made')
    }
    const kp = this.crypto.generateKemKeypair()
    const publicKey = hexOf(kp && kp.publicKey, KEM_PUB_BYTES)
    const secretKey = hexOf(kp && kp.secretKey, KEM_SECRET_BYTES)
    if (!publicKey || !secretKey) throw new DmError('crypto.generateKemKeypair returned a malformed key pair', 'HUGIN_DM_CRYPTO')
    const save = this.host.saveKemIdentity
    if (typeof save === 'function') {
      try {
        await save.call(this.host, { publicKey, secretKey })
      } catch (err) {
        this._log('warn', 'ML-KEM identity not saved', { message: err && err.message })
      }
    }
    return { publicKey: hexToBytes(publicKey), secretKey: hexToBytes(secretKey) }
  }

  /** The stored, normalised crypto state of a contact (see normalizeState). */
  async contactState(address) {
    const contact = contactOf(address)
    if (!isAddress(contact)) throw new DmError('address must be an XKR address')
    return this._load(contact)
  }

  /**
   * The DM swarm's derivation hash for a contact (`rooms.joinDm({ address, derivationHash })`):
   * `cn_fast_hash(generate_key_derivation(viewPublicKey(address), our private view key))`. Both
   * sides compute the same value.
   */
  async derivationHash(address) {
    const contact = contactOf(address)
    if (!isAddress(contact)) throw new DmError('address must be an XKR address')
    const viewPub = await this.crypto.addressToViewPub(contact)
    const derivation = await this._derive(viewPub)
    return cnFastHashHex(derivation)
  }

  /** The push view tag for a DM (`call`: a call notification, all 64 characters) to `address`. */
  async pushViewTag(address, { call = false, now } = {}) {
    const contact = contactOf(address)
    if (!isAddress(contact)) throw new DmError('address must be an XKR address')
    const viewPub = await this.crypto.addressToViewPub(contact)
    return dmViewTag(viewPub, { now: isTimestamp(now) ? now : this._now(), long: call === true })
  }

  // -------------------------------------------------------------------------------------------
  // send

  /**
   * Builds the DM payload of `message` for `address` (layout at the top of this file). Without a
   * message key for the contact it carries our ML-KEM public key (`handshake: 'initial'`); with
   * our unanswered capsule it carries the capsule and the inner box (`'reply'`); otherwise only
   * the inner box (`'established'`). The contact state is not changed. Rejects with a DmError for
   * bad arguments, a missing identity address, or a host hook that fails (`HUGIN_DM_HOST`).
   *
   * @param {string} address  the contact (a longer chat id is cut to 99 characters)
   * @param {string} message  the text (a call: the JSON the app puts in it)
   * @param {object} [opts]
   * @param {string} [opts.name]  our display name (default `host.identity().name`; cut to `maxNameLength` characters)
   * @param {number} [opts.timestamp]  integer ms (default `host.now()`)
   * @param {boolean} [opts.call]  the push view tag for a call
   * @returns {Promise<{ payload, hash, timestamp, viewTag, kind, handshake, to, fitsNode }>}
   *   `payload`: the wire string (hex) for `rooms.sendDm` and `node.post`; `hash`: its message id
   *   (`messageHash(payload)`); `kind`: `'dm'` or `'call'`; `fitsNode`: the payload is at most
   *   NODE_PAYLOAD_BUDGET characters, so a node post with it stays under the packet limit
   */
  async encrypt(address, message, opts) {
    opts = opts || {}
    const to = contactOf(address)
    if (!isAddress(to)) throw new DmError('address must be an XKR address')
    if (typeof message !== 'string' || message.length === 0) throw new DmError('message must be a non-empty string')
    const id = this._identity()
    const from = id.address
    if (!isAddress(from)) throw new DmError('host.identity() has no XKR address', 'HUGIN_DM_HOST')
    let name = opts.name !== undefined ? opts.name : id.name
    if (name === null || name === undefined) name = ''
    if (typeof name !== 'string') throw new DmError('name must be a string')
    const t = opts.timestamp !== undefined && opts.timestamp !== null ? opts.timestamp : this._now()
    if (!isTimestamp(t)) throw new DmError('timestamp must be a non-negative integer')
    const call = opts.call === true

    return this._withLock(to, async () => {
      const state = await this._load(to)
      const kem = state.messageKey ? null : await this.kemIdentity()
      const c = this.crypto

      // the per-message key pair comes from this module (generateTxKey), not from the provider
      const eph = generateTxKey()
      const derivation = await c.friendRequestSecretSender(eph.privateKey, to)
      const vt = await c.viewTag(derivation)
      if (!isHex(vt, 2)) throw new DmError('crypto.viewTag returned a malformed tag', 'HUGIN_DM_CRYPTO')
      const outerKey = await c.boxKey(derivation)
      const txKey = hexToBytes(eph.publicKey)

      // without a key: kem_pub and the body (1); our unused capsule: kem_ct and the inner box (6);
      // otherwise the inner box (4)
      const kemPub = kem ? kem.publicKey : null
      const kemCt = !kem && state.pendingKemCapsule ? hexToBytes(state.pendingKemCapsule) : null
      const flags = kem ? FLAG_KEM_PUB : kemCt ? FLAG_KEM_CT | FLAG_INNER : FLAG_INNER
      const signature = await this._sign(dmSigningPayload(to, t, message, flags, handshakeDigest(kemPub, kemCt)))
      const body = encodeBody(clampName(name, this.options.maxNameLength), signature, message)
      const parts = [Uint8Array.of(flags), asciiBytes(from)]
      if (kemPub) parts.push(kemPub)
      if (kemCt) parts.push(kemCt)
      parts.push(flags & FLAG_INNER ? c.secretboxEncrypt(body, innerNonce(txKey), hexToBytes(state.messageKey)) : body)
      const box = c.secretboxEncrypt(concatBytes(parts), c.nonceFromTimestamp(t), outerKey)

      const payload = bytesToHex(concatBytes([Uint8Array.of(PAYLOAD_VERSION), uint64Bytes(t), txKey, hexToBytes(vt), box]))
      const viewPub = await c.addressToViewPub(to)
      return {
        payload,
        hash: c.messageHash(payload),
        timestamp: t,
        viewTag: dmViewTag(viewPub, { now: this._now(), long: call }),
        kind: call ? 'call' : 'dm',
        handshake: flags === FLAG_KEM_PUB ? 'initial' : flags === FLAG_INNER ? 'established' : 'reply',
        to,
        fitsNode: payload.length <= NODE_PAYLOAD_BUDGET
      }
    })
  }

  // -------------------------------------------------------------------------------------------
  // receive

  /**
   * Opens a DM payload (from the DM swarm's `dm:wire`, a node pool entry or a push). On success
   * the contact's handshake state is updated and saved before this resolves.
   *
   * @param {string} payload
   * @param {object} [opts]
   * @param {string} [opts.hash]  message id from the node pool (64 hex); default `messageHash(payload)`
   * @param {string} [opts.from]  the verified contact of the DM swarm it came from: refused when another address wrote it
   * @returns {Promise<{ status, message?, reason? }>}  `message`: `{ from, message, name, timestamp, hash, type, established }`,
   *   `type` `'friend-request'` (no message key used) or `'message'`, `established`: we hold a key for the contact now.
   *   A message dated more than `maxFutureMs` (one day) ahead of `host.now()` is returned when it
   *   verifies but changes no handshake state.
   */
  async open(payload, opts) {
    const r = await this._open(payload, opts)
    delete r.signature
    return r
  }

  /** `open`, with the body signature (hex) in `signature` on `ok`. */
  async _open(payload, opts) {
    opts = opts || {}
    if (typeof payload !== 'string' || payload.length === 0 || payload.length > this.options.maxPayloadLength) {
      return { status: STATUS.NOT_DM }
    }
    const wire = decodeWire(payload)
    if (!wire) return { status: STATUS.NOT_DM }

    let derivation
    try {
      derivation = await this._derive(wire.txKey)
    } catch (err) {
      return { status: STATUS.ERROR, reason: (err && err.message) || 'keyDerivation' }
    }
    const c = this.crypto
    let vt
    try {
      vt = await c.viewTag(derivation)
    } catch {
      return { status: STATUS.REFUSED, reason: 'derivation' }
    }
    if (typeof vt !== 'string' || vt.toLowerCase() !== wire.vt) return { status: STATUS.NOT_FOR_US }

    let nonce, outerKey
    try {
      nonce = c.nonceFromTimestamp(wire.t)
      outerKey = await c.boxKey(derivation)
    } catch {
      return refused('derivation')
    }
    const openBox = (bytes, n, key) => {
      try {
        return c.secretboxOpen(bytes, n, key) || null
      } catch {
        return null
      }
    }
    const outerPlain = openBox(wire.box, nonce, outerKey)
    if (!outerPlain) return refused('outer box')
    const outer = decodeOuter(outerPlain)
    if (!outer) return refused('outer')
    if (opts.from !== undefined && opts.from !== null && outer.from !== contactOf(opts.from)) return refused('not the contact')
    const hash = isHex(opts.hash, 64) ? opts.hash.toLowerCase() : messageHashOf(c, payload)
    // the signature names us as the recipient
    const me = this._identity().address
    if (!isAddress(me)) return { status: STATUS.ERROR, reason: 'host.identity() has no XKR address' }

    return this._withLock(outer.from, async () => {
      let state
      try {
        state = await this._load(outer.from)
      } catch (err) {
        return { status: STATUS.ERROR, reason: (err && err.message) || 'loadContactCrypto' }
      }

      let bodyBytes, keyUsed, capsuleKey
      if (outer.inner) {
        const keys = []
        if (outer.kemCt) {
          let kem
          try {
            kem = await this.kemIdentity()
          } catch (err) {
            return { status: STATUS.ERROR, reason: (err && err.message) || 'loadKemIdentity' }
          }
          try {
            capsuleKey = hexOf(c.decapsulate(outer.kemCt, kem.secretKey), KEY_BYTES) || null
          } catch {
            capsuleKey = null
          }
          if (capsuleKey) keys.push(capsuleKey)
        }
        for (const k of [state.messageKey, ...state.previousKeys]) if (k && !keys.includes(k)) keys.push(k)
        if (keys.length === 0) return refused('no message key')
        const n = innerNonce(hexToBytes(wire.txKey))
        for (const k of keys) {
          bodyBytes = openBox(outer.rest, n, hexToBytes(k))
          if (bodyBytes) {
            keyUsed = k
            break
          }
        }
        if (!bodyBytes) return refused('inner box')
      } else {
        bodyBytes = outer.rest
        keyUsed = null
      }
      const body = decodeBody(bodyBytes)
      if (!body) return refused('body')
      const signed = dmSigningPayload(me, wire.t, body.text, outer.flags, handshakeDigest(outer.kemPub, outer.kemCt))
      if (!(await this._verify(signed, outer.from, body.signature))) return refused('signature')

      const peerKemPub = outer.kemPub ? bytesToHex(outer.kemPub) : null
      let next = state
      if (wire.t > this._now() + this.options.maxFutureMs) {
        // dated more than a day ahead of our clock: delivered, the handshake state stays
        this._log('warn', 'DM dated ahead of our clock: handshake state unchanged')
      } else {
        try {
          next = nextState(
            state,
            { t: wire.t, keyUsed: keyUsed || null, capsuleKey: capsuleKey && keyUsed === capsuleKey ? capsuleKey : null, peerKemPub },
            (pub) => this._encapsulate(pub),
            this.options.maxPreviousKeys
          )
        } catch (err) {
          this._log('warn', 'contact handshake not updated', { message: err && err.message })
        }
      }
      if (!sameState(next, state)) {
        try {
          await this._save(outer.from, next)
        } catch (err) {
          this._log('warn', 'contact crypto state not saved', { message: err && err.message })
        }
      }
      return {
        status: STATUS.OK,
        message: {
          from: outer.from,
          message: body.text,
          name: clampName(body.name, this.options.maxNameLength),
          timestamp: wire.t,
          hash,
          type: keyUsed ? 'message' : 'friend-request',
          established: !!next.messageKey
        },
        signature: body.signature
      }
    })
  }

  /**
   * Opens node pool entries (`node:messages`, `{ hash, cipher, timestamp }`). The message id of a
   * DM payload is `messageHash(cipher)`: an entry whose `hash` is another value is skipped. Each id
   * is opened once (remembered, at most `maxKnownPoolHashes`), and a body whose signature was
   * already delivered by `openPool` (the same message in another payload) is skipped too. Entries
   * without a 64-hex hash or a string cipher, and ciphers of at most 200 or more than
   * `maxPoolPayloadLength` (9000) hex characters, are skipped. Entries are opened in order; when a
   * host hook fails, a later batch tries the entry again (at most `maxPoolTries` times in all).
   * @returns {Promise<{ messages, others, skipped, errors }>}  `messages`: opened, by timestamp;
   *   `others`: entries that are not DM payloads (the host may handle them otherwise)
   */
  async openPool(entries) {
    const out = { messages: [], others: [], skipped: 0, errors: 0 }
    if (!Array.isArray(entries)) return out
    for (const entry of entries) {
      if (!isPlainObject(entry) || typeof entry.cipher !== 'string' || !isHex(entry.hash, 64)) {
        out.skipped++
        continue
      }
      const hash = entry.hash.toLowerCase()
      if (this._known.has(hash)) {
        out.skipped++
        continue
      }
      this._remember(hash)
      const len = entry.cipher.length
      if (len < this.options.minPoolPayloadLength || len > this.options.maxPoolPayloadLength) {
        out.skipped++
        continue
      }
      if (!decodeWire(entry.cipher)) {
        out.others.push(entry)
        continue
      }
      // a DM payload is taken only under its own message id
      if (messageHashOf(this.crypto, entry.cipher) !== hash) {
        out.skipped++
        continue
      }
      let r
      try {
        r = await this._open(entry.cipher, { hash })
      } catch (err) {
        r = { status: STATUS.ERROR, reason: err && err.message }
      }
      if (r.status === STATUS.OK) {
        this._tries.delete(hash)
        if (this._seenSignatures.has(r.signature)) {
          out.skipped++
          continue
        }
        this._rememberSignature(r.signature)
        out.messages.push(r.message)
      } else if (r.status === STATUS.NOT_DM) out.others.push(entry)
      else if (r.status === STATUS.ERROR) {
        out.errors++
        const tries = (this._tries.get(hash) || 0) + 1
        this._tries.delete(hash)
        if (tries < this.options.maxPoolTries) {
          this._known.delete(hash)
          this._tries.set(hash, tries)
          while (this._tries.size > this.options.maxKnownPoolHashes) this._tries.delete(this._tries.keys().next().value)
        }
      } else this._tries.delete(hash)
    }
    out.messages.sort((a, b) => a.timestamp - b.timestamp)
    return out
  }

  /** True when the node pool hash was handled by `openPool`. */
  knowsPoolHash(hash) {
    return isHex(hash, 64) && this._known.has(hash.toLowerCase())
  }

  // -------------------------------------------------------------------------------------------
  // internals

  _rememberSignature(signature) {
    if (typeof signature !== 'string') return
    this._seenSignatures.add(signature)
    while (this._seenSignatures.size > this.options.maxKnownPoolHashes) this._seenSignatures.delete(this._seenSignatures.values().next().value)
  }

  _remember(hash) {
    if (!isHex(hash, 64)) return
    const h = hash.toLowerCase()
    this._known.delete(h)
    this._known.add(h)
    while (this._known.size > this.options.maxKnownPoolHashes) this._known.delete(this._known.values().next().value)
  }

  _encapsulate(peerKemPubHex) {
    const r = this.crypto.encapsulate(hexToBytes(peerKemPubHex))
    const messageKey = hexOf(r && r.sharedSecret, KEY_BYTES)
    const kemCapsule = hexOf(r && r.ciphertext, KEM_CIPHERTEXT_BYTES)
    if (!messageKey || !kemCapsule) throw new DmError('crypto.encapsulate returned a malformed result', 'HUGIN_DM_CRYPTO')
    return { messageKey, kemCapsule }
  }

  async _derive(publicKey) {
    const fn = this.host.keyDerivation
    if (typeof fn !== 'function') throw new DmError('host.keyDerivation is required', 'HUGIN_DM_HOST')
    let d
    try {
      d = await fn.call(this.host, publicKey)
    } catch (err) {
      throw new DmError('host.keyDerivation failed: ' + ((err && err.message) || 'error'), 'HUGIN_DM_HOST')
    }
    if (!isHex(d, 64)) throw new DmError('host.keyDerivation must return 64 hex characters', 'HUGIN_DM_HOST')
    return d.toLowerCase()
  }

  async _sign(message) {
    const fn = this.host.sign
    if (typeof fn !== 'function') throw new DmError('host.sign is required', 'HUGIN_DM_HOST')
    let s
    try {
      s = await fn.call(this.host, message)
    } catch (err) {
      throw new DmError('host.sign failed: ' + ((err && err.message) || 'error'), 'HUGIN_DM_HOST')
    }
    if (!isHex(s, 128)) throw new DmError('host.sign must return a 128-hex signature', 'HUGIN_DM_HOST')
    return s.toLowerCase()
  }

  /** `host.verify`, else the provider's `verify`; exactly `true` counts. Never throws. */
  async _verify(message, address, signature) {
    const owner = typeof this.host.verify === 'function' ? this.host : typeof this.crypto.verify === 'function' ? this.crypto : null
    if (!owner) {
      this._log('warn', 'DM dropped: no host.verify')
      return false
    }
    try {
      return (await owner.verify(message, address, signature)) === true
    } catch {
      return false
    }
  }

  async _load(address) {
    const fn = this.host.loadContactCrypto
    if (typeof fn !== 'function') return normalizeState(null, this.options.maxPreviousKeys)
    let raw
    try {
      raw = await fn.call(this.host, address)
    } catch (err) {
      throw new DmError('host.loadContactCrypto failed: ' + ((err && err.message) || 'error'), 'HUGIN_DM_HOST')
    }
    return normalizeState(raw, this.options.maxPreviousKeys)
  }

  async _save(address, state) {
    const fn = this.host.saveContactCrypto
    if (typeof fn !== 'function') throw new DmError('host.saveContactCrypto is required', 'HUGIN_DM_HOST')
    await fn.call(this.host, address, { ...state, previousKeys: [...state.previousKeys] })
  }

  _identity() {
    const fn = this.host.identity
    let id = null
    try {
      id = typeof fn === 'function' ? fn.call(this.host) : fn
    } catch (err) {
      this._log('warn', 'host.identity failed', { message: err && err.message })
    }
    return isPlainObject(id) ? id : {}
  }

  _now() {
    const fn = this.host.now
    if (typeof fn === 'function') {
      try {
        const t = fn.call(this.host)
        if (isTimestamp(t)) return t
      } catch {}
    }
    return Date.now()
  }

  /** Runs `fn` after every earlier call for the same contact (state reads and writes in order). */
  _withLock(address, fn) {
    const prev = this._locks.get(address) || Promise.resolve()
    const run = prev.then(fn, fn)
    const tail = run.then(noop, noop)
    this._locks.set(address, tail)
    tail.then(() => {
      if (this._locks.get(address) === tail) this._locks.delete(address)
    })
    return run
  }

  _log(level, msg, data) {
    const fn = this.host.log
    if (typeof fn !== 'function') return
    try {
      fn.call(this.host, level, msg, data)
    } catch {}
  }
}

/** The provider's message id of a payload, or '' when it fails. */
function messageHashOf(crypto, payload) {
  try {
    const h = crypto.messageHash(payload)
    return typeof h === 'string' ? h : ''
  } catch {
    return ''
  }
}

function refused(reason) {
  return { status: STATUS.REFUSED, reason }
}

// ---------------------------------------------------------------------------------------------
// layout

function concatBytes(parts) {
  let n = 0
  for (const p of parts) n += p.byteLength
  const out = new Uint8Array(n)
  let off = 0
  for (const p of parts) {
    out.set(p, off)
    off += p.byteLength
  }
  return out
}

function asciiBytes(str) {
  const out = new Uint8Array(str.length)
  for (let i = 0; i < str.length; i++) out[i] = str.charCodeAt(i)
  return out
}

function fromAscii(bytes) {
  let out = ''
  for (let i = 0; i < bytes.length; i++) out += String.fromCharCode(bytes[i])
  return out
}

/** An integer of at most 2^53 - 1 as 8 bytes, big-endian. */
function uint64Bytes(value) {
  const out = new Uint8Array(8)
  const hi = Math.floor(value / 0x100000000)
  const lo = value % 0x100000000
  for (let i = 0; i < 4; i++) {
    out[3 - i] = (hi >>> (8 * i)) & 0xff
    out[7 - i] = (lo >>> (8 * i)) & 0xff
  }
  return out
}

/** 8 bytes big-endian at `off`, or -1 above 2^53 - 1. */
function readUint64(bytes, off) {
  const hi = ((bytes[off] << 24) | (bytes[off + 1] << 16) | (bytes[off + 2] << 8) | bytes[off + 3]) >>> 0
  const lo = ((bytes[off + 4] << 24) | (bytes[off + 5] << 16) | (bytes[off + 6] << 8) | bytes[off + 7]) >>> 0
  if (hi >= 0x200000) return -1
  return hi * 0x100000000 + lo
}

/** Nonce of the inner box: the first 24 bytes of `txKey` (new for every message). */
function innerNonce(txKey) {
  return txKey.slice(0, 24)
}

/** UTF-8 text of `bytes`, or null when they are not well-formed UTF-8. */
function strictUtf8(bytes) {
  const text = fromUtf8(bytes)
  const back = utf8(text)
  if (back.length !== bytes.length) return null
  for (let i = 0; i < back.length; i++) if (back[i] !== bytes[i]) return null
  return text
}

/** nameLength | name | signature (64) | text */
function encodeBody(name, signatureHex, text) {
  let nameBytes = utf8(name)
  if (nameBytes.length > 255) {
    const chars = Array.from(name)
    while (nameBytes.length > 255) {
      chars.pop()
      nameBytes = utf8(chars.join(''))
    }
  }
  return concatBytes([Uint8Array.of(nameBytes.length), nameBytes, hexToBytes(signatureHex), utf8(text)])
}

/** `{ name, signature (hex), text }`, or null. */
function decodeBody(bytes) {
  if (!bytes || bytes.length < SIZES.NAME_LENGTH + SIZES.SIGNATURE) return null
  const n = bytes[0]
  const sigAt = 1 + n
  const textAt = sigAt + SIZES.SIGNATURE
  if (textAt > bytes.length) return null
  const name = strictUtf8(bytes.subarray(1, sigAt))
  const text = strictUtf8(bytes.subarray(textAt))
  if (name === null || text === null) return null
  return { name, signature: bytesToHex(bytes.subarray(sigAt, textAt)), text }
}

/**
 * `{ flags, from, kemPub, kemCt, inner, rest }` of the outer plaintext (Uint8Array), or null. Only
 * the `flags` values `encrypt` writes are taken: 1 (kem_pub and the body), 6 (kem_ct and the
 * inner box) and 4 (the inner box).
 */
function decodeOuter(bytes) {
  if (!bytes || bytes.length < SIZES.FLAGS + SIZES.FROM) return null
  const flags = bytes[0]
  if (!ACCEPTED_FLAGS.includes(flags)) return null
  const inner = (flags & FLAG_INNER) !== 0
  const from = fromAscii(bytes.subarray(1, 1 + SIZES.FROM))
  if (!isAddress(from)) return null
  let off = 1 + SIZES.FROM
  let kemPub = null
  let kemCt = null
  if (flags & FLAG_KEM_PUB) {
    kemPub = bytes.slice(off, off + SIZES.KEM_PUB)
    off += SIZES.KEM_PUB
  }
  if (flags & FLAG_KEM_CT) {
    kemCt = bytes.slice(off, off + SIZES.KEM_CT)
    off += SIZES.KEM_CT
  }
  const restMin = (inner ? SIZES.MAC : 0) + SIZES.NAME_LENGTH + SIZES.SIGNATURE
  if (off + restMin > bytes.length) return null
  return { flags, from, kemPub, kemCt, inner, rest: bytes.slice(off) }
}

/**
 * `{ version, t, txKey (hex), vt (hex), box (bytes) }` of a payload, or null when it is not a DM
 * payload (not hex, shorter than the smallest payload, another version, a timestamp above
 * 2^53 - 1).
 */
function decodeWire(payload) {
  if (typeof payload !== 'string' || payload.length < MIN_PAYLOAD_BYTES * 2 || !isHex(payload)) return null
  const bytes = hexToBytes(payload)
  if (bytes[0] !== PAYLOAD_VERSION) return null
  const t = readUint64(bytes, SIZES.VERSION)
  if (t < 0) return null
  const keyAt = SIZES.VERSION + SIZES.TIMESTAMP
  const tagAt = keyAt + SIZES.TX_KEY
  return {
    version: PAYLOAD_VERSION,
    t,
    txKey: bytesToHex(bytes.subarray(keyAt, tagAt)),
    vt: bytesToHex(bytes.subarray(tagAt, SIZES.HEADER)),
    box: bytes.slice(SIZES.HEADER)
  }
}

module.exports = {
  DmCrypto,
  DmError,
  STATUS,
  DEFAULTS,
  CRYPTO_FUNCTIONS,
  KEM_PUB_BYTES,
  KEM_SECRET_BYTES,
  KEM_CIPHERTEXT_BYTES,
  PAYLOAD_VERSION,
  SIZES,
  MIN_PAYLOAD_BYTES,
  NODE_PAYLOAD_BUDGET,
  ACCEPTED_FLAGS,
  normalizeState,
  nextState,
  dmSigningPayload,
  handshakeDigest,
  dmViewTag,
  decodeWire,
  decodeOuter,
  generateTxKey,
  secretKeyToPublicKey,
  scalarReduce,
  txKeyBackend,
  sha256Hex
}
