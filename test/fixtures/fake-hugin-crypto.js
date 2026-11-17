'use strict'

// Test-only crypto provider for lib/dm.js with the function names of hugin-crypto 1.0.0, built
// on sodium-universal and js-sha3 so that it runs under Node and Bare without kryptokrona-utils
// or noble. What is the same as hugin-crypto and what stands in:
//
//   same as hugin-crypto     viewTag, boxKey (cn_fast_hash = Keccak-256 of the hex bytes),
//                            nonceFromTimestamp, secretbox (XSalsa20-Poly1305, MAC first, as
//                            libsodium crypto_secretbox_easy and noble xsalsa20poly1305),
//                            messageHash (SHA-256 of the UTF-8 string), encodeExtra, key sizes
//   stand-ins                CryptoNote key derivation -> X25519 (both are Diffie-Hellman: the
//                            sender's derivation from the ephemeral private key and the view
//                            public key equals the receiver's from the ephemeral public key and the
//                            private view key); addresses -> 'SEKR' + hex(view public key) +
//                            filler (99 characters); XKR signatures -> ed25519 over the message,
//                            checked against a registry of test wallets; ML-KEM-512 -> X25519 with
//                            the ML-KEM sizes (public key 800, secret key 1632, ciphertext 768,
//                            shared secret 32 bytes; a wrong secret key gives another secret)
//
// `makeNet()` returns `{ crypto, wallet(name) }`; `crypto.ephemeral` (an array of key pairs) makes
// the next `ephemeralKeypair()` calls deterministic.

const sodium = require('sodium-universal')
const b4a = require('b4a')
const { keccak256 } = require('js-sha3')

const hex = (bytes) => b4a.toString(bytes, 'hex')
const fromHex = (h) => new Uint8Array(b4a.from(h, 'hex'))

function cnFastHash(hexInput) {
  return keccak256(fromHex(hexInput))
}

function x25519Pub(priv) {
  const pub = b4a.alloc(32)
  sodium.crypto_scalarmult_base(pub, priv)
  return pub
}

function x25519(priv, pub) {
  const out = b4a.alloc(32)
  sodium.crypto_scalarmult(out, priv, pub)
  return out
}

function randomBytes(n) {
  const out = b4a.alloc(n)
  sodium.randombytes_buf(out)
  return out
}

function seeded(name, n = 32) {
  const out = b4a.alloc(n)
  sodium.crypto_generichash(out, b4a.from('fake-hugin-crypto:' + name, 'utf8'))
  return out
}

function addressFor(viewPubHex, name) {
  // 'SEKR' + 64 hex + 31 filler characters = 99, unique per wallet name
  const filler = keccak256(name).slice(0, 31)
  return 'SEKR' + viewPubHex + filler
}

function makeNet() {
  /** address -> ed25519 public key */
  const registry = new Map()

  const crypto = {
    ephemeral: [],
    KEM_PUB_BYTES: 800,
    KEM_SECRET_BYTES: 1632,
    KEM_CIPHERTEXT_BYTES: 768,
    KEM_SHARED_BYTES: 32,

    async ephemeralKeypair() {
      if (crypto.ephemeral.length) return crypto.ephemeral.shift()
      const priv = randomBytes(32)
      return { private_key: hex(priv), public_key: hex(x25519Pub(priv)) }
    },

    async addressToViewPub(address) {
      if (typeof address !== 'string' || address.length !== 99) throw new Error('bad address')
      return address.slice(4, 68)
    },

    async friendRequestSecretSender(ephemeralPrivateKey, toAddress) {
      const viewPub = await crypto.addressToViewPub(toAddress)
      return hex(x25519(fromHex(ephemeralPrivateKey), fromHex(viewPub)))
    },

    async friendRequestSecretReceiver(txKey, myViewPrivateKey) {
      return hex(x25519(fromHex(myViewPrivateKey), fromHex(txKey)))
    },

    // hugin-crypto derivation.js
    async viewTag(derivation) {
      return cnFastHash(derivation).substring(0, 2)
    },

    async boxKey(derivation) {
      return fromHex(cnFastHash('626f78' + derivation))
    },

    // hugin-crypto util.js
    nonceFromTimestamp(timestamp) {
      const nonce = crypto.hexToUint(String(timestamp))
      const padded = Array.from(nonce)
      while (padded.length < 24) padded.push(0)
      return Uint8Array.from(padded.slice(0, 24))
    },

    hexToUint(h) {
      return new Uint8Array((h.match(/.{1,2}/g) || []).map((byte) => parseInt(byte, 16)))
    },

    uintToHex(bytes) {
      let out = ''
      for (let i = 0; i < bytes.length; i++) {
        const h = bytes[i].toString(16)
        out += h.length === 1 ? '0' + h : h
      }
      return out
    },

    secretboxEncrypt(plain, nonce, key) {
      if (nonce.length !== 24 || key.length !== 32) throw new Error('secretbox: bad nonce or key')
      const out = b4a.alloc(plain.length + 16)
      sodium.crypto_secretbox_easy(out, b4a.from(plain), b4a.from(nonce), b4a.from(key))
      return new Uint8Array(out)
    },

    secretboxOpen(box, nonce, key) {
      if (box.length < 16 || nonce.length !== 24 || key.length !== 32) return null
      const out = b4a.alloc(box.length - 16)
      const ok = sodium.crypto_secretbox_open_easy(out, b4a.from(box), b4a.from(nonce), b4a.from(key))
      return ok ? new Uint8Array(out) : null
    },

    messageHash(data) {
      const buf = typeof data === 'string' ? b4a.from(data, 'utf8') : b4a.from(data)
      const out = b4a.alloc(32)
      sodium.crypto_hash_sha256(out, buf)
      return hex(out)
    },

    encodeExtra(wire) {
      return hex(b4a.from(JSON.stringify(wire), 'utf8'))
    },

    decodeExtra(extra) {
      try {
        return JSON.parse(b4a.toString(b4a.from(extra, 'hex'), 'utf8'))
      } catch {
        return false
      }
    },

    // ML-KEM-512 stand-in (sizes as ML-KEM-512)
    generateKemKeypair() {
      const sk = randomBytes(32)
      const pk = x25519Pub(sk)
      const publicKey = new Uint8Array(800)
      publicKey.set(pk)
      const secretKey = new Uint8Array(1632)
      secretKey.set(sk)
      secretKey.set(pk, 32)
      return { publicKey, secretKey }
    },

    encapsulate(theirPublicKey) {
      if (theirPublicKey.length !== 800) throw new Error('kem: expected an 800-byte public key')
      const pk = b4a.from(theirPublicKey.subarray(0, 32))
      const eph = randomBytes(32)
      const ephPk = x25519Pub(eph)
      const sharedSecret = kemSecret(x25519(eph, pk), ephPk, pk)
      const ciphertext = new Uint8Array(768)
      ciphertext.set(ephPk)
      return { ciphertext, sharedSecret }
    },

    decapsulate(ciphertext, mySecretKey) {
      if (ciphertext.length !== 768) throw new Error('kem: expected a 768-byte ciphertext')
      if (mySecretKey.length !== 1632) throw new Error('kem: expected a 1632-byte secret key')
      const ephPk = b4a.from(ciphertext.subarray(0, 32))
      const sk = b4a.from(mySecretKey.subarray(0, 32))
      const pk = b4a.from(mySecretKey.subarray(32, 64))
      return kemSecret(x25519(sk, ephPk), ephPk, pk)
    },

    // XKR message signatures (stand-in): ed25519 over the UTF-8 message
    async sign(message, privateSpendKey) {
      const sig = b4a.alloc(64)
      sodium.crypto_sign_detached(sig, b4a.from(message, 'utf8'), b4a.from(privateSpendKey, 'hex'))
      return hex(sig)
    },

    async verify(message, address, signature) {
      try {
        const pk = registry.get(address)
        if (!pk || typeof signature !== 'string' || signature.length !== 128) return false
        return sodium.crypto_sign_verify_detached(b4a.from(signature, 'hex'), b4a.from(message, 'utf8'), pk)
      } catch {
        return false
      }
    }
  }

  /** A test wallet: view key pair (X25519), spend key pair (ed25519), address. */
  function wallet(name) {
    const viewPriv = seeded(name + ':view')
    const viewPub = hex(x25519Pub(viewPriv))
    const signPk = b4a.alloc(32)
    const signSk = b4a.alloc(64)
    sodium.crypto_sign_seed_keypair(signPk, signSk, seeded(name + ':spend'))
    const address = addressFor(viewPub, name)
    registry.set(address, signPk)
    return {
      name,
      address,
      viewPub,
      privateViewKey: hex(viewPriv),
      privateSpendKey: hex(signSk),
      /** `generate_key_derivation(publicKey, privateViewKey)` stand-in */
      keyDerivation: (publicKey) => hex(x25519(viewPriv, fromHex(publicKey))),
      sign: (message) => crypto.sign(message, hex(signSk))
    }
  }

  /** A deterministic ephemeral key pair (for byte-identical payloads). */
  function ephemeralFrom(name) {
    const priv = seeded('eph:' + name)
    return { private_key: hex(priv), public_key: hex(x25519Pub(priv)) }
  }

  return { crypto, wallet, ephemeralFrom }
}

function kemSecret(dh, ephPk, pk) {
  const out = b4a.alloc(32)
  sodium.crypto_generichash(out, b4a.concat([dh, ephPk, pk]))
  return new Uint8Array(out)
}

module.exports = { makeNet, cnFastHash }
