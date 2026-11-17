'use strict'

// ed25519 helpers. Signatures are produced the way keypear (hugin-desktop) and the keypear
// shim in hugin-native `bare/utils.js` produce them: the secret key is turned into its scalar
// (`extension_tweak_ed25519_sk_to_scalar`) and signed with
// `extension_tweak_ed25519_sign_detached`. These signatures verify with the standard
// `crypto_sign_verify_detached` and are byte-identical to the apps' signatures (the nonce
// derivation differs from `crypto_sign_detached`, so the bytes would not match otherwise).

const b4a = require('b4a')
const sodium = require('sodium-universal')

function keyPairFromSeed(seed) {
  const publicKey = b4a.alloc(32)
  const secretKey = b4a.alloc(64)
  sodium.crypto_sign_seed_keypair(publicKey, secretKey, seed)
  return { publicKey, secretKey }
}

function randomKeyPair() {
  const publicKey = b4a.alloc(32)
  const secretKey = b4a.alloc(64)
  sodium.crypto_sign_keypair(publicKey, secretKey)
  return { publicKey, secretKey }
}

/** keypear-compatible detached signature of `message` (Uint8Array) with an ed25519 key pair. */
function keychainSign(keyPair, message) {
  if (!keyPair || !(keyPair.secretKey instanceof Uint8Array) || keyPair.secretKey.byteLength !== 64) {
    throw new TypeError('keychainSign: keyPair.secretKey must be 64 bytes')
  }
  const scalar = b4a.alloc(32)
  sodium.extension_tweak_ed25519_sk_to_scalar(scalar, keyPair.secretKey)
  const sig = b4a.alloc(64)
  sodium.extension_tweak_ed25519_sign_detached(sig, message, scalar)
  return sig
}

/** `crypto_sign_verify_detached` that returns false instead of throwing on bad lengths. */
function verifyDetached(signature, message, publicKey) {
  if (!(signature instanceof Uint8Array) || signature.byteLength !== 64) return false
  if (!(publicKey instanceof Uint8Array) || publicKey.byteLength !== 32) return false
  if (!(message instanceof Uint8Array)) return false
  try {
    return sodium.crypto_sign_verify_detached(signature, message, publicKey)
  } catch {
    return false
  }
}

module.exports = {
  keyPairFromSeed,
  randomKeyPair,
  keychainSign,
  verifyDetached
}
