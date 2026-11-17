'use strict'

// Verbatim copies of hugin-native code paths (HEAD cc81895 + local hugin-mid migration), used to
// prove that hugin-network computes the same values. Changes from the originals, and nothing else:
//   * `require('sodium-native')` -> `require('sodium-universal')` (which re-exports sodium-native)
//   * `require('hugin-mid')` -> hugin-network's own copy of it, `lib/swarm.js`
//   * `require('./pow-utils')` -> the copy of bare/pow-utils.js below
//   * randomness is passed in where the original calls `random_key()` / `randomKey()`
//   * the push server key of `seal_to_push_server` is a parameter (default: the original key)
//   * NodeConnection methods (`build_pow_auth`, `should_recalc_share`) as plain functions;
//     `get_new_peer_keys(random_key())` -> a one-time key pair passed in
//   * RN `naclHash` (src/services/bare/crypto.ts) uses Node's `crypto`, loaded lazily
//   * console.log calls removed
// Functions that use the global Buffer or Node's crypto only run on Node.

const sodium = require('sodium-universal')
const b4a = require('b4a')
const { keyPairFromSeed } = require('../../lib/swarm.js')

// ---------------------------------------------------------------------------------------------
// bare/utils.js:10-88 (keypear shim)

class Keychain {
  constructor(key_pair) {
    const kp = normalize_keypair(key_pair);
    this.publicKey = kp.publicKey;
    this.secretKey = kp.secretKey;
    this.scalar = kp.scalar || (kp.secretKey ? secret_key_to_scalar(kp.secretKey) : null);
  }

  get isKeychain() {
    return true;
  }

  get() {
    return create_signer({
      publicKey: this.publicKey,
      secretKey: this.secretKey,
      scalar: this.scalar
    });
  }

  static from(k) {
    return this.isKeychain(k) ? k : new this(k);
  }

  static verify(signable, signature, publicKey) {
    return sodium.crypto_sign_verify_detached(signature, signable, publicKey);
  }

  static isKeychain(k) {
    return !!(k && k.isKeychain);
  }
}

function normalize_keypair(key_pair) {
  if (b4a.isBuffer(key_pair) || key_pair instanceof Uint8Array) {
    const publicKey = b4a.from(key_pair);
    return { publicKey, secretKey: null, scalar: null };
  }

  if (!key_pair || typeof key_pair !== 'object') {
    return { publicKey: null, secretKey: null, scalar: null };
  }

  const publicKey = key_pair.publicKey ? b4a.from(key_pair.publicKey) : null;
  const secretKey = key_pair.secretKey ? b4a.from(key_pair.secretKey) : null;
  const scalar = key_pair.scalar ? b4a.from(key_pair.scalar) : null;

  return { publicKey, secretKey, scalar };
}

function secret_key_to_scalar(secret_key) {
  const scalar = b4a.alloc(32);
  sodium.extension_tweak_ed25519_sk_to_scalar(scalar, secret_key);
  return scalar;
}

function create_signer(kp) {
  const verify = (signable, signature) =>
    sodium.crypto_sign_verify_detached(signature, signable, kp.publicKey);

  const signer = {
    publicKey: kp.publicKey,
    secretKey: kp.secretKey || null,
    scalar: kp.scalar || null,
    writable: !!kp.scalar,
    sign: null,
    verify
  };

  if (!kp.scalar) return signer;

  signer.sign = (signable) => {
    const sig = b4a.alloc(sodium.crypto_sign_BYTES);
    sodium.extension_tweak_ed25519_sign_detached(sig, signable, kp.scalar);
    return sig;
  };

  return signer;
}

// ---------------------------------------------------------------------------------------------
// bare/utils.js:125-181 (keys, invite)

function create_peer_base_keys(buf) {
  const keypair = keyPairFromSeed(buf);
  const keys = Keychain.from(keypair);
  return keys;
}

function create_keys_from_seed(seed) {
  const random = Buffer.alloc(32).fill(seed);
  return create_peer_base_keys(random);
}

// `random_key` passed in: returns the next of the given 32-byte Buffers.
function create_room_invite(random_key) {
  const seed = random_key();
  const rand = random_key();
  const admin = create_keys_from_seed(seed);
  //[invite, admin seed]
  return [
    rand.toString('hex') + admin.get().publicKey.toString('hex'),
    seed.toString('hex'),
  ];
}

// ---------------------------------------------------------------------------------------------
// bare/utils.js:191-232 (hash check, PoW job validation)

function check_hash(hash) {
  if (typeof hash !== 'string' || hash.length !== 64) return false;
  return true;
}

const pow_config = {
  DEBUG: true,
  MAX_BLOB_HEX_BYTES: 1024,
};

function is_hex_string(value) {
  return typeof value === 'string' && /^[0-9a-f]+$/i.test(value);
}

function validate_pow_job(job) {
  if (!job || typeof job !== 'object') return { ok: false, reason: 'invalid_job' };
  if (typeof job.job_id !== 'string' || job.job_id.length > 32) {
    return { ok: false, reason: 'invalid_job_id' };
  }
  if (!is_hex_string(job.blob)) return { ok: false, reason: 'invalid_blob' };
  if (job.blob.length % 2 !== 0) return { ok: false, reason: 'invalid_blob_len' };
  if ((job.blob.length / 2) > pow_config.MAX_BLOB_HEX_BYTES) {
    return { ok: false, reason: 'blob_too_large' };
  }
  if (!is_hex_string(job.target) || job.target.length !== 8) {
    return { ok: false, reason: 'invalid_target' };
  }
  const offset = getNonceOffset(job.blob);
  if (typeof offset !== 'number' || offset < 0) {
    return { ok: false, reason: 'invalid_nonce_offset' };
  }
  if ((offset + 4) * 2 > job.blob.length) {
    return { ok: false, reason: 'nonce_out_of_bounds' };
  }
  return { ok: true };
}

// ---------------------------------------------------------------------------------------------
// bare/utils.js:234-469 (sanitizers)

const sanitize_join_swarm_data = (data) => {
  if (data?.address.length > 99 || data.address === undefined) return false;
  const address = sanitizeHtml(data.address);
  if (data?.message.length > 128 || data.message === undefined) return false;
  const message = sanitizeHtml(data.message);
  if (data?.signature.length > 128 || data.signature === undefined)
    return false;
  const signature = sanitizeHtml(data.signature);
  if (data?.topic.length !== 64 || data.topic === undefined) return false;
  const topic = sanitizeHtml(data.topic);
  if (data?.name.length > 50 || data.name === undefined) return false;
  const name = sanitizeHtml(data.name);
  if (data?.time.length > 50 || data.time === undefined) return false;
  const time = sanitizeHtml(data.time);

  if (data.voice === undefined) return false;
  if (typeof data.voice !== 'boolean') return false;
  const voice = data.voice;
  if (typeof data.joined !== 'boolean') return false;
  const joined = data.joined;
  if (typeof data.video !== 'boolean') return false;
  const video = data.video;

  const idSig = data.idSig;
  if (typeof idSig !== 'string' || idSig.length > 128) return false;
  const audioMute = data?.audioMute;
  if (typeof audioMute !== 'boolean') return false;
  const videoMute = data?.videoMute;
  if (typeof videoMute !== 'boolean') return false;
  const screenshare = data?.screenshare;
  if (typeof screenshare !== 'boolean') return false;

  let messages = data?.messages;
  if (!Array.isArray(data?.messages)) {
      messages = []
  }


  // if (typeof data?.avatar !== 'string') return false;
  let avatar = '';
  if (data.avatar !== undefined && data.avatar?.length > 0) {
    avatar = data.avatar;
    const base64 = /^[A-Za-z0-9+/]+={0,2}$/;
    if (!base64.test(avatar)) {
      return false;
    }
    if (avatar.length > 614400) {
      // 600kb
      return false;
    }
  }
  const channels = [];

  let driveKey = null;
  if (typeof data?.driveKey === 'string' && data.driveKey.length === 64) {
    driveKey = data.driveKey;
  }

  const clean_object = {
    address: address,
    avatar: avatar,
    message: message,
    signature: signature,
    topic: topic,
    name: name,
    voice: voice,
    joined: joined,
    channels: channels,
    video: video,
    time: time,
    idSig,
    audioMute,
    videoMute,
    screenshare,
    messages,
    driveKey,
  };

  return clean_object;
};

const sanitize_group_message = (data) => {
  let timestamp = sanitizeHtml(data.timestamp);
  if (parseInt(timestamp) > Date.now()) timestamp = Date.now();
  if (timestamp?.length > 20 || data.timestamp === undefined) return false;
  let room = sanitizeHtml(data.room);
  if (room?.length > 128 || data.room === undefined) return false;
  let text = sanitizeHtml(data.message);
  if (text?.length > 777 || data.message === undefined) return false;
  let addr = sanitizeHtml(data.address);
  if (addr?.length > 99 || data.address === undefined) return false;
  let reply = sanitizeHtml(data.reply ?? '');
  if (reply?.length > 64) return false;
  let sig = sanitizeHtml(data.signature);
  if (sig?.length > 200) return false;
  let nick = sanitizeHtml(data.name ?? data.nickname);
  if (nick?.length > 50 || nick === undefined) return false;
  let txHash = sanitizeHtml(data.hash);
  if (txHash?.length > 64 || data.hash === undefined) return false;
  let tip = false;
  if (data.tip && data.tip !== 'false') {
    if (typeof data.tip.amount !== 'number') return false;
    if (typeof data.tip.receiver !== 'string') return false;
    tip = {
      amount: data.tip.amount,
      receiver: sanitizeHtml(data.tip.receiver),
    };
  }

  const clean_object = {
    message: text,
    address: addr,
    signature: sig,
    room: room,
    timestamp: timestamp,
    name: nick,
    reply: reply,
    hash: txHash,
    sent: false,
    channel: 'channel',
    hash: txHash,
    tip: tip,
  };

  return clean_object;
};

const sanitize_voice_status_data = (data) => {
  const address = sanitizeHtml(data.address);
  if (address?.length > 99 || data.address === undefined) return false;
  const message = sanitizeHtml(data.message);
  if (message?.length > 64 || data.message === undefined) return false;
  const signature = sanitizeHtml(data.signature);
  if (signature?.length > 128 || data.signature === undefined) return false;
  const topic = sanitizeHtml(data.topic);
  if (topic?.length !== 64 || data.topic === undefined) return false;
  const name = sanitizeHtml(data.name);
  if (name?.length > 50 || data.name === undefined) return false;
  const voice = data.voice;
  if (typeof voice !== 'boolean') return false;
  const video = data.video;
  if (typeof video !== 'boolean') return false;
  const audioMute = data?.audioMute;
  if (typeof audioMute !== 'boolean') return false;
  const videoMute = data?.videoMute;
  if (typeof videoMute !== 'boolean') return false;
  const screenshare = data?.screenshare;
  if (typeof screenshare !== 'boolean') return false;

  const clean_object = {
    address: address,
    message: message,
    signature: signature,
    topic: topic,
    name: name,
    voice: voice,
    video: video,
    audioMute,
    videoMute,
    screenshare,
  };

  return clean_object;
};

const sanitize_file_message = (data) => {
  //Check standard message
  const fileName = sanitizeHtml(data?.fileName);
  if (typeof data?.fileName !== 'string' || fileName.length > 100) return false;

  const address = sanitizeHtml(data?.address);
  if (typeof data?.address !== 'string' || address.length > 99) return false;

  const topic = sanitizeHtml(data?.topic);
  if (typeof data?.topic !== 'string' || topic.length > 64) return false;

  const type = sanitizeHtml(data?.type);
  if (typeof data?.type !== 'string' || type.length > 25) return false;

  const info = sanitizeHtml(data?.info);
  if (typeof data?.info !== 'string' || info.length > 25) return false;

  const size = sanitizeHtml(data?.size);
  if (size?.length > 20) return false;

  const time = sanitizeHtml(data?.time);
  if (time?.length > 25) return false;

  const sig = sanitizeHtml(data?.signature);
  if (sig?.length > 128) return false;

  const name = sanitizeHtml(data?.name);
  if (data?.name !== undefined) {
    if (typeof name !== 'string' || name.length > 100) return false;
  }

  //Check optional
  const key = sanitizeHtml(data?.key);
  if (data?.key !== undefined) {
    if (typeof data?.key !== 'string' || key.length > 128) return false;
  }
  const hash = sanitizeHtml(data?.hash);
  if (data?.hash !== undefined) {
    if (typeof hash !== 'string' || hash.length > 64) return false;
  }

  if (typeof data?.file === 'boolean') return false;

  const object = {
    fileName,
    address,
    topic,
    info,
    type,
    size,
    time,
    hash,
    key: key,
    sig,
  };

  return object;
};

const sanitizeHtml = (data) => {
  //Bare js seems not to be working with sanitize-html package.
  //Sanitze input later and only check relevant types and length for now
  return data;
};

const sanitize_typing_message = (data) => {
  const typing = sanitizeHtml(data?.typing);
  if (typeof data?.typing !== 'boolean')          return [false, false];
  return [typing, true]
}

// ---------------------------------------------------------------------------------------------
// bare/utils.js:502-514 (room key transport, admin signatures)

const toUintArray = (val) => {
  return Uint8Array.from(val.split(',').map((x) => parseInt(x, 10)));
};

const verify_signature = (message, signature, invite) => {
  if (signature.length !== 64) return false;
  return Keychain.verify(message, signature, invite);
};

const sign_admin_message = (dht_keys, admin) => {
  const keys = create_keys_from_seed(admin);
  return keys.get().sign(dht_keys.get().publicKey);
};

// ---------------------------------------------------------------------------------------------
// bare/pow-utils.js:1-82

const DEFAULT_NONCE_OFFSET = 39;

function hexToBytes(hex) {
  if (typeof hex !== 'string') throw new Error('hex_to_bytes_invalid');
  if (hex.length % 2 !== 0) throw new Error('hex_to_bytes_len');
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    const byte = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    if (!Number.isFinite(byte)) throw new Error('hex_to_bytes_parse');
    out[i] = byte;
  }
  return out;
}

function bytesToHex(bytes) {
  let hex = '';
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i].toString(16).padStart(2, '0');
  }
  return hex;
}

function readVarint(buffer, offset) {
  let value = 0;
  let shift = 0;
  let bytes = 0;
  while (offset + bytes < buffer.length) {
    const byte = buffer[offset + bytes];
    value |= (byte & 0x7f) << shift;
    bytes += 1;
    if ((byte & 0x80) === 0) {
      return { value, bytes };
    }
    shift += 7;
    if (shift > 63) return null;
  }
  return null;
}

function getNonceOffsetFromBuffer(blobBuffer) {
  try {
    let offset = 0;
    const major = readVarint(blobBuffer, offset);
    if (!major) return DEFAULT_NONCE_OFFSET;
    offset += major.bytes;
    const minor = readVarint(blobBuffer, offset);
    if (!minor) return DEFAULT_NONCE_OFFSET;
    offset += minor.bytes;
    const timestamp = readVarint(blobBuffer, offset);
    if (!timestamp) return DEFAULT_NONCE_OFFSET;
    offset += timestamp.bytes;
    offset += 32;
    return offset;
  } catch (e) {
    return DEFAULT_NONCE_OFFSET;
  }
}

function getNonceOffset(blobHex) {
  const blobBuffer = hexToBytes(blobHex);
  return getNonceOffsetFromBuffer(blobBuffer);
}

function extractPrevIdFromBlob(blobHex) {
  try {
    const blobBuffer = hexToBytes(blobHex);
    let offset = 0;
    const major = readVarint(blobBuffer, offset);
    if (!major) return null;
    offset += major.bytes;
    const minor = readVarint(blobBuffer, offset);
    if (!minor) return null;
    offset += minor.bytes;
    const timestamp = readVarint(blobBuffer, offset);
    if (!timestamp) return null;
    offset += timestamp.bytes;
    if (offset + 32 > blobBuffer.length) return null;
    return bytesToHex(blobBuffer.subarray(offset, offset + 32));
  } catch (e) {
    return null;
  }
}

// ---------------------------------------------------------------------------------------------
// bare/swarm.js:458-488 (NodeConnection.build_pow_auth, should_recalc_share)

// `oneTimeKeys` given (the original: `const [, oneTimeKeys] = get_new_peer_keys(random_key())`).
function build_pow_auth(oneTimeKeys, message_hash, timestamp, shares, context = '') {
  if (!Array.isArray(shares) || !shares.length) return null;
  const share = shares[0];
  const signer = oneTimeKeys && oneTimeKeys.get ? oneTimeKeys.get() : null;
  if (!signer || !signer.sign || !signer.publicKey) return null;
  const payload = `powsig:v2:${String(message_hash || '')}:${timestamp}:${String(share.job_id || '')}:${String(share.nonce || '').toLowerCase()}:${String(share.result || '').toLowerCase()}:${String(context || '')}`;
  const sig = signer.sign(Buffer.from(payload));
  if (!sig) return null;
  return {
    pub: Buffer.from(signer.publicKey).toString('hex'),
    sig: Buffer.from(sig).toString('hex'),
    nonce: String(share.nonce || '').toLowerCase(),
  };
}

function should_recalc_share(res) {
  if (!res || typeof res !== 'object') return false;
  const reason = typeof res.reason === 'string' ? res.reason.toLowerCase() : '';
  if (reason.includes('pool_reject') || reason.includes('invalid_share') || reason.includes('stale') || reason.includes('job')) {
    return true;
  }
  if (!Array.isArray(res.rejects)) return false;
  return res.rejects.some((entry) => {
    if (!entry) return false;
    const txt = typeof entry === 'string'
      ? entry.toLowerCase()
      : JSON.stringify(entry).toLowerCase();
    return txt.includes('invalid') || txt.includes('stale') || txt.includes('low') || txt.includes('job');
  });
}

// ---------------------------------------------------------------------------------------------
// bare/messages.js:20-114 (push payloads)

const PUSH_SERVER_PUBKEY_HEX =
  '6e18d19b3c94f7c2c4da5dc6f17305f8ab6da33f8beb18e63a0f048d2a21c345';

const FIXED_NONCE_LEN = 24;

function nonceFromTimestamp(tmstmp) {
  const hex = String(tmstmp);
  const bytes = [];
  for (let i = 0; i < hex.length; i += 2) {
    bytes.push(parseInt(hex.slice(i, i + 2), 16));
  }
  while (bytes.length < FIXED_NONCE_LEN) bytes.push(0);
  return Buffer.from(bytes.slice(0, FIXED_NONCE_LEN));
}

function toHexUtf8(str) {
  return Buffer.from(str, 'utf-8').toString('hex');
}

function encrypt_push_registration({ deviceId, viewTag, type }, timestamp = Date.now(), pubHex = PUSH_SERVER_PUBKEY_HEX) {
  const payload = type ? { deviceId, viewTag, type } : { deviceId, viewTag };
  return seal_to_push_server(payload, timestamp, pubHex);
}

function seal_to_push_server(payloadObj, timestamp, pubHex = PUSH_SERVER_PUBKEY_HEX) {
  const payloadBytes = Buffer.from(JSON.stringify(payloadObj), 'utf-8');
  const pub = Buffer.from(pubHex, 'hex');
  const sealed = Buffer.alloc(payloadBytes.length + sodium.crypto_box_SEALBYTES);
  sodium.crypto_box_seal(sealed, payloadBytes, pub);
  const envelope = { box: sealed.toString('hex'), t: timestamp };
  return toHexUtf8(JSON.stringify(envelope));
}

function encrypt_room_push({ roomKey, payload, timestamp, viewTag }, pubHex = PUSH_SERVER_PUBKEY_HEX) {
  const innerKey = Buffer.from(roomKey, 'hex');
  if (innerKey.length !== sodium.crypto_secretbox_KEYBYTES) {
    throw new Error('room key must be 32 bytes (64 hex chars)');
  }
  const innerNonce = nonceFromTimestamp(timestamp);
  const innerPlain = Buffer.from(JSON.stringify(payload), 'utf-8');
  const innerBox = Buffer.alloc(innerPlain.length + sodium.crypto_secretbox_MACBYTES);
  sodium.crypto_secretbox_easy(innerBox, innerPlain, innerNonce, innerKey);
  const innerEnvelope = { box: innerBox.toString('hex'), viewTag };
  return seal_to_push_server(innerEnvelope, timestamp, pubHex);
}

function decrypt_room_push({ cipherHex, timestamp, roomKeys }) {
  const cipher = Buffer.from(cipherHex, 'hex');
  const nonce = nonceFromTimestamp(timestamp);
  if (cipher.length <= sodium.crypto_secretbox_MACBYTES) return false;
  for (const room of roomKeys) {
    const key = Buffer.from(room.key.substring(0, 64), 'hex');
    if (key.length !== sodium.crypto_secretbox_KEYBYTES) continue;
    const plain = Buffer.alloc(cipher.length - sodium.crypto_secretbox_MACBYTES);
    const ok = sodium.crypto_secretbox_open_easy(plain, cipher, nonce, key);
    if (!ok) continue;
    try {
      const parsed = JSON.parse(plain.toString('utf-8'));
      parsed.roomKey = room.key;
      parsed.roomName = room.name;
      return parsed;
    } catch (_) {
      continue;
    }
  }
  return false;
}

// ---------------------------------------------------------------------------------------------
// RN src/services/utils (hexToUint) and src/services/bare/crypto.ts:34 (naclHash)

const rnHexToUint = (hexString) =>
  new Uint8Array(
    hexString.match(/.{1,2}/g)?.map((byte) => parseInt(byte, 16)) ?? [],
  );

function naclHash(val) {
  const { createHash } = require('crypto');
  const buf = createHash('sha512').update(Buffer.from(rnHexToUint(val))).digest();
  return Array.from(buf).join(',');
}

module.exports = {
  Keychain,
  create_peer_base_keys,
  create_keys_from_seed,
  create_room_invite,
  check_hash,
  validate_pow_job,
  sanitize_join_swarm_data,
  sanitize_group_message,
  sanitize_voice_status_data,
  sanitize_file_message,
  sanitize_typing_message,
  toUintArray,
  verify_signature,
  sign_admin_message,
  getNonceOffset,
  extractPrevIdFromBlob,
  build_pow_auth,
  should_recalc_share,
  PUSH_SERVER_PUBKEY_HEX,
  nonceFromTimestamp,
  encrypt_push_registration,
  encrypt_room_push,
  decrypt_room_push,
  rnHexToUint,
  naclHash
};
