'use strict'

// Small byte/hex helpers shared by the modules. No Node-only APIs and no global Buffer.

const b4a = require('b4a')
const sodium = require('sodium-universal')

const HEX_RE = /^[0-9a-f]*$/i

function isHex(value, length) {
  if (typeof value !== 'string' || !HEX_RE.test(value)) return false
  if (length === undefined) return value.length % 2 === 0
  return value.length === length
}

/**
 * `hexToUint` exactly as hugin-desktop (`utils.cjs:157`) and hugin-native RN
 * (`src/services/utils`) implement it: split into 2-character chunks, `parseInt(chunk, 16)`,
 * stored in a Uint8Array (NaN becomes 0, an odd trailing character is parsed alone).
 * For well-formed hex this equals a plain hex decode.
 */
function hexToUint(hexString) {
  if (typeof hexString !== 'string') throw new TypeError('hexToUint: expected a string')
  const pairs = hexString.match(/.{1,2}/g) || []
  const out = new Uint8Array(pairs.length)
  for (let i = 0; i < pairs.length; i++) out[i] = parseInt(pairs[i], 16)
  return out
}

function toHex(bytes) {
  return b4a.toString(bytes, 'hex')
}

/** UTF-8 bytes of a string as lowercase hex. */
function utf8ToHex(str) {
  return b4a.toString(b4a.from(String(str), 'utf8'), 'hex')
}

function randomBytes(n) {
  const out = b4a.alloc(n)
  sodium.randombytes_buf(out)
  return out
}

/** 32 random bytes as 64 hex characters (the apps' `randomKey()`). */
function randomKey() {
  return toHex(randomBytes(32))
}

function sha512(bytes) {
  const out = b4a.alloc(64)
  sodium.crypto_hash_sha512(out, bytes)
  return out
}

/**
 * BLAKE2b-256 (libsodium `crypto_generichash`, 32 bytes, no key) as 64 hex characters: of the
 * bytes of a Uint8Array as they are, of anything else the UTF-8 bytes of `String(value)`.
 */
function blake2b256Hex(value) {
  const out = b4a.alloc(32)
  sodium.crypto_generichash(out, value instanceof Uint8Array ? value : b4a.from(String(value), 'utf8'))
  return toHex(out)
}

/**
 * Incremental BLAKE2b-256 for data that arrives in chunks: `update(bytes)` per chunk (returns
 * the hasher), then `digest()` once, which gives what `blake2b256Hex` gives for all chunks
 * concatenated.
 */
function blake2b256Hasher() {
  const state = b4a.alloc(sodium.crypto_generichash_STATEBYTES)
  sodium.crypto_generichash_init(state, null, 32)
  let done = false
  return {
    update(bytes) {
      if (done) throw new Error('blake2b256Hasher: digest() was called already')
      sodium.crypto_generichash_update(state, bytes)
      return this
    },
    digest() {
      if (done) throw new Error('blake2b256Hasher: digest() was called already')
      done = true
      const out = b4a.alloc(32)
      sodium.crypto_generichash_final(state, out)
      return toHex(out)
    }
  }
}

/** A uniformly random integer in [0, n) (n at most 2^32) from the OS CSPRNG (rejection sampling). */
function randomInt(n) {
  const range = 0x100000000
  const m = Math.min(Math.floor(n), range)
  if (!(m > 1)) return 0
  const limit = range - (range % m)
  const buf = b4a.alloc(4)
  for (;;) {
    sodium.randombytes_buf(buf)
    const x = ((buf[0] << 24) >>> 0) + (buf[1] << 16) + (buf[2] << 8) + buf[3]
    if (x < limit) return x % m
  }
}

/** Byte length of a JS string encoded as UTF-8. */
function utf8Length(str) {
  return b4a.byteLength(str, 'utf8')
}

module.exports = {
  isHex,
  hexToUint,
  toHex,
  utf8ToHex,
  randomBytes,
  randomKey,
  sha512,
  blake2b256Hex,
  blake2b256Hasher,
  randomInt,
  utf8Length
}
