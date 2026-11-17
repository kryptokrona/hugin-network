'use strict'

// Verbatim copies of hugin-desktop code paths (src/backend, HEAD 8811d9d5 + local hugin-mid
// migration), used to prove that hugin-network computes the same values. Changes from the
// originals, and nothing else:
//   * `sanitizeHtml` (sanitize-html, Electron only) -> identity. The test inputs contain no HTML,
//     for which sanitize-html returns the input unchanged.
//   * `require('hugin-mid')` -> hugin-network's own copy of it, `lib/swarm.js`
//   * keypear -> the keypear shim of hugin-native (`legacy-native.js`). keypear's signatures are
//     covered separately: the hugin-relay `pow.auth` vectors were produced with keypear itself.
//   * `Buffer.from(avatar, 'base64')` in the sanitizers -> `b4a.from` (so they also run on Bare)
//   * randomness is passed in where the original calls `randomKey()`
//   * `is_room_admin()` / `loadRoomKeys()` (database) -> an `adminkeys` argument
//   * `send_room_message_push`: the push server key and the room view tag are parameters
//     (kryptokrona-utils `cn_fast_hash` is not a dependency here), and it returns the wire hex
//     instead of posting it with `Nodes.message`
//   * NodeConnection methods (`build_pow_auth`, `should_recalc_share`) as plain functions
//   * `naclHash` uses Node's `crypto`, loaded lazily; console.log calls removed
// Functions that use the global Buffer or Node's crypto only run on Node.

const b4a = require('b4a')
const sodium = require('sodium-universal')
const { keyPairFromSeed } = require('../../lib/swarm.js')
const { Keychain: Keychains } = require('./legacy-native.js')
const hu = require('./hugin-utils.js')

// ---------------------------------------------------------------------------------------------
// utils.cjs:157-195

const hexToUint = (hexString) =>
	new Uint8Array(hexString.match(/.{1,2}/g).map((byte) => parseInt(byte, 16)));

function toHex(str, hex) {
	try {
		hex = unescape(encodeURIComponent(str))
			.split('')
			.map(function (v) {
				return v.charCodeAt(0).toString(16);
			})
			.join('');
	} catch (e) {
		hex = str;
	}
	return hex;
}

function nonceFromTimestamp(tmstmp) {
	let nonce = hexToUint(String(tmstmp));

	while (nonce.length < 24) {
		let tmp_nonce = Array.from(nonce);

		tmp_nonce.push(0);

		nonce = Uint8Array.from(tmp_nonce);
	}

	return nonce;
}

function check_hash(hash) {
	if (typeof hash !== 'string' || hash.length !== 64) return false;
	return true;
}

// ---------------------------------------------------------------------------------------------
// utils.cjs:22-62 (PoW job validation; getNonceOffset from hugin-utils)

const pow_config = {
	DEBUG: true,
	HASHES_PER_SECOND: 800,
	TIME_BUDGET_MS: 90000,
	SHARES: 1,
	BOOST_HASHES_PER_SECOND: 600,
	BOOST_TIME_BUDGET_MS: 90000,
	MAX_JOB_TIME_MS: 90000,
	MAX_BLOB_HEX_BYTES: 1024
};

function is_hex_string(value) {
	return typeof value === 'string' && /^[0-9a-f]+$/i.test(value);
}

const getNonceOffset = hu.getNonceOffset;

function validate_pow_job(job) {
	if (!job || typeof job !== 'object') return { ok: false, reason: 'invalid_job' };
	// pool job_id is typically a numeric string; only enforce type/length
	if (typeof job.job_id !== 'string' || job.job_id.length > 32)
		return { ok: false, reason: 'invalid_job_id' };
	if (!is_hex_string(job.blob)) return { ok: false, reason: 'invalid_blob' };
	if (job.blob.length % 2 !== 0) return { ok: false, reason: 'invalid_blob_len' };
	if (job.blob.length / 2 > pow_config.MAX_BLOB_HEX_BYTES)
		return { ok: false, reason: 'blob_too_large' };
	if (!is_hex_string(job.target) || job.target.length !== 8)
		return { ok: false, reason: 'invalid_target' };
	const offset = getNonceOffset(job.blob);
	if (typeof offset !== 'number' || offset < 0)
		return { ok: false, reason: 'invalid_nonce_offset' };
	if ((offset + 4) * 2 > job.blob.length) return { ok: false, reason: 'nonce_out_of_bounds' };
	return { ok: true };
}

// ---------------------------------------------------------------------------------------------
// utils.cjs:256-529 (sanitizers)

const sanitizeHtml = (input) => input;
const Buffer_ = { from: (s, enc) => b4a.from(s, enc) };

const sanitize_join_swarm_data = (data) => {
	if (data?.address.length > 99 || data.address === undefined) return false;
	const address = sanitizeHtml(data.address);
	if (data?.message.length > 128 || data.message === undefined) return false;
	const message = sanitizeHtml(data.message);
	if (data?.signature.length > 128 || data.signature === undefined) return false;
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
		messages = [];
	}

	let avatar = '';
	if (data.avatar !== undefined && data.avatar?.length > 0) {
		avatar = Buffer_.from(data.avatar, 'base64');
		if (avatar.length > 200000) {
			return false;
		}
	}

	const channels = [];

	let driveKey = null;
	if (data.driveKey !== undefined) {
		if (typeof data.driveKey !== 'string' || !/^[0-9a-f]{64}$/i.test(data.driveKey)) return false;
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
		driveKey
	};

	return clean_object;
};

const sanitize_group_message = (data, sent = false) => {
	let timestamp = sanitizeHtml(data.timestamp);
	if (parseInt(timestamp) > Date.now()) timestamp = Date.now();
	if (timestamp?.length > 20 || data.timestamp === undefined) return false;
	let room = sanitizeHtml(data.room);
	if (room?.length > 128 || data.room === undefined) return false;
	let text = sanitizeHtml(data.message);
	if (text?.length > 777 || data.message === undefined) return false;
	let addr = sanitizeHtml(data.address);
	if (addr?.length > 128 || data.address === undefined) return false;
	if (data.reply === undefined) {
		data.reply = '';
	}
	let reply = sanitizeHtml(data.reply);
	if (reply?.length > 64) return false;
	let sig = sanitizeHtml(data.signature);
	if (sig?.length > 200) return false;
	let nick = sanitizeHtml(data.name ?? data.nickname);
	if (nick?.length > 50 || nick === undefined) return false;
	let txHash = sanitizeHtml(data.hash);
	if (txHash?.length > 128 || data.hash === undefined) return false;

	let tip = false;
	if (data.tip && data.tip !== 'false') {
		if (typeof data.tip.amount !== 'number' || data.tip.amount?.length > 100) return false;
		if (typeof data.tip.receiver !== 'string' || data.tip.receiver?.length > 100) return false;
		tip = { amount: data.tip.amount, receiver: sanitizeHtml(data.tip.receiver) };
	}

	const clean_object = {
		message: text,
		address: addr,
		signature: sig,
		room,
		timestamp,
		name: nick,
		reply: reply,
		hash: txHash,
		sent: sent,
		channel: 'channel',
		tip
	};

	return clean_object;
};

const sanitize_voice_status_data = (data) => {
	const address = sanitizeHtml(data?.address);
	if (address?.length > 99 || data?.address === undefined) return false;
	const message = sanitizeHtml(data?.message);
	if (message?.length > 64 || data?.message === undefined) return false;
	const signature = sanitizeHtml(data?.signature);
	if (signature?.length > 128 || data?.signature === undefined) return false;
	const topic = sanitizeHtml(data?.topic);
	if (topic?.length !== 64 || data?.topic === undefined) return false;
	const name = sanitizeHtml(data?.name);
	if (name?.length > 50 || data?.name === undefined) return false;
	const voice = data?.voice;
	if (typeof voice !== 'boolean') return false;
	const video = data?.video;
	if (typeof video !== 'boolean') return false;

	const audioMute = data?.audioMute;
	if (typeof audioMute !== 'boolean') return false;
	const videoMute = data?.videoMute;
	if (typeof videoMute !== 'boolean') return false;
	const screenshare = data?.screenshare;
	if (typeof screenshare !== 'boolean') return false;

	let avatar = '';
	if (data.avatar !== undefined && data.avatar?.length > 0) {
		const base64 = /^[A-Za-z0-9+/]+={0,2}$/;
		if (!base64.test(data.avatar)) {
			return false;
		}
		avatar = Buffer_.from(sanitizeHtml(data.avatar), 'base64');
		if (avatar.length > 200000) {
			return false;
		}
	}

	const clean_object = {
		address,
		avatar,
		message,
		signature,
		topic,
		name,
		voice,
		video,
		videoMute,
		audioMute,
		screenshare
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

	//Check optional
	const key = sanitizeHtml(data?.key);
	if (data?.key !== undefined) {
		if (typeof data?.key !== 'string' || key.length > 128) return false;
	}
	const hash = sanitizeHtml(data?.hash);
	if (data?.hash !== undefined) {
		if (typeof hash !== 'string' || hash.length > 64) return false;
	}

	const name = sanitizeHtml(data?.name);
	if (data?.name !== undefined) {
		if (typeof name !== 'string' || name.length > 100) return false;
	}

	if (typeof data?.file === 'boolean') return false;

	const object = {
		fileName,
		address,
		name,
		topic,
		info,
		type,
		size: parseInt(size),
		time: parseInt(time),
		hash,
		key: key,
		sig
	};

	return object;
};

const sanitize_feed_message = (data) => {
	const address = sanitizeHtml(data?.address);
	if (address?.length > 99 || data?.address === undefined) return false;
	const message = sanitizeHtml(data?.message);
	if (message?.length > 777 || data?.message === undefined) return false;
	const signature = sanitizeHtml(data?.signature);
	if (signature?.length > 128) return false;
	const nickname = sanitizeHtml(data?.nickname);
	if (nickname?.length > 50 || data?.nickname === undefined) return false;
	const hash = sanitizeHtml(data.hash);
	if (typeof data.hash !== 'string' || hash.length > 64) return false;
	const timestamp = sanitizeHtml(data?.timestamp);
	if (timestamp?.length > 25) return false;
	const reply = sanitizeHtml(data.reply);
	if (reply?.length > 64) return false;

	let tip = false;
	if (data.tip && data.tip !== 'false') {
		if (typeof data.tip.amount !== 'number' || data.tip.amount?.length > 100) return false;
		if (typeof data.tip.receiver !== 'string' || data.tip.receiver?.length > 100) return false;
		tip = { amount: data.tip.amount, receiver: sanitizeHtml(data.tip.receiver) };
	}

	const clean = {
		message,
		address,
		nickname,
		signature,
		reply,
		hash,
		timestamp: parseInt(timestamp),
		tip
	};
	return clean;
};

const sanitize_typing_message = (data) => {
	if (typeof data?.typing !== 'boolean') return [false, false];
	return [data?.typing, true];
};

// ---------------------------------------------------------------------------------------------
// crypto.cjs:72-122 (keys, invite, admin signatures; keypear -> Keychains shim)

function create_peer_base_keys(buf) {
	const keypair = keyPairFromSeed(buf);
	const keys = Keychains.from(keypair);
	return keys;
}

function create_keys_from_seed(seed) {
	const random_key = Buffer.alloc(32).fill(seed);
	return create_peer_base_keys(random_key);
}

// `randomKey` passed in: returns the next of the given 64-hex strings.
function create_room_invite(randomKey) {
	const seed = randomKey();
	const rand = randomKey();
	const admin = create_keys_from_seed(seed);
	//[invite, admin seed]
	return [rand + admin.get().publicKey.toString('hex'), seed];
}

// SHA-512 (same digest tweetnacl's nacl.hash produced), now via node crypto.
function naclHash(val) {
	const { createHash } = require('crypto');
	return createHash('sha512').update(Buffer.from(hexToUint(val))).digest();
}

function verify_signature(message, signature, pub) {
	if (signature.length !== 64) return false;
	return Keychains.verify(message, signature, pub);
}

const sign_admin_message = (dht_keys, invite, adminkeys) => {
	const admin = adminkeys.find(a => a.invite === invite);
	const keys = create_keys_from_seed(admin.priv);
	return keys.get().sign(dht_keys.get().publicKey);
};

// ---------------------------------------------------------------------------------------------
// swarm.cjs:508-547 (NodeConnection.build_pow_auth, should_recalc_share)

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
		nonce: String(share.nonce || '').toLowerCase()
	};
}

function should_recalc_share(res) {
	if (!res || typeof res !== 'object') return false;
	const reason = typeof res.reason === 'string' ? res.reason.toLowerCase() : '';
	if (
		reason.includes('pool_reject') ||
		reason.includes('invalid_share') ||
		reason.includes('invalid pow') ||
		reason.includes('stale') ||
		reason.includes('job')
	) {
		return true;
	}
	if (!Array.isArray(res.rejects)) return false;
	return res.rejects.some((entry) => {
		if (!entry) return false;
		const txt =
			typeof entry === 'string' ? entry.toLowerCase() : JSON.stringify(entry).toLowerCase();
		return (
			txt.includes('invalid') ||
			txt.includes('stale') ||
			txt.includes('low') ||
			txt.includes('job')
		);
	});
}

// ---------------------------------------------------------------------------------------------
// messages.cjs:901-961 (send_room_message_push)

function send_room_message_push(message, viewTag, fixedPubHex = '6e18d19b3c94f7c2c4da5dc6f17305f8ab6da33f8beb18e63a0f048d2a21c345') {
	const roomKey = message.room.substring(0, 64);
	// secretbox key = the 32-byte room key itself.
	const key = Buffer.from(hexToUint(roomKey));

	const payload_message = {
		message: message.message,
		reply: message.reply,
		tip: message.tip || '',
		hash: message.hash,
		name: message.name,
		address: message.address
	};
	const payload_bytes = Buffer.from(JSON.stringify(payload_message));

	const timestamp = message.timestamp;
	const nonce = Buffer.from(nonceFromTimestamp(timestamp));

	// inner: libsodium secretbox keyed by the room key
	const inner = Buffer.alloc(payload_bytes.length + sodium.crypto_secretbox_MACBYTES);
	sodium.crypto_secretbox_easy(inner, payload_bytes, nonce, key);

	const payload_json = {
		box: inner.toString('hex'),
		viewTag
	};
	const payload_json_bytes = Buffer.from(JSON.stringify(payload_json));

	const fixedPub = Buffer.from(fixedPubHex, 'hex');
	const sealed = Buffer.alloc(payload_json_bytes.length + sodium.crypto_box_SEALBYTES);
	sodium.crypto_box_seal(sealed, payload_json_bytes, fixedPub);

	//Box object
	let payload_box = {
		box: sealed.toString('hex'),
		t: timestamp
	};
	// Convert json to hex
	let payload_hex = toHex(JSON.stringify(payload_box));
	return { payload_hex, payload_message };
}

module.exports = {
	hexToUint,
	toHex,
	nonceFromTimestamp,
	check_hash,
	validate_pow_job,
	sanitize_join_swarm_data,
	sanitize_group_message,
	sanitize_voice_status_data,
	sanitize_file_message,
	sanitize_feed_message,
	sanitize_typing_message,
	create_peer_base_keys,
	create_keys_from_seed,
	create_room_invite,
	naclHash,
	verify_signature,
	sign_admin_message,
	build_pow_auth,
	should_recalc_share,
	send_room_message_push
};
