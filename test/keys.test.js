'use strict'

const test = require('brittle')
const b4a = require('b4a')
const { keccak256 } = require('js-sha3')
const { getNewPeerKeys, keyPairFromSeed } = require('../lib/swarm.js')
const keys = require('../lib/keys.js')
const { NETWORK_ADDRESS } = require('../lib/constants.js')
const desktop = require('./fixtures/legacy-desktop.js')
const native = require('./fixtures/legacy-native.js')
const { legacyTopicFromKey } = require('./fixtures/legacy-hugin-swarm.js')
const { NODE, hex, ADDRESS, SEED_HEX, RAND_HEX } = require('./helpers.js')

// SHA-512 test vectors (FIPS 180-2 "abc" and the empty message).
const SHA512_ABC =
  'ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f'
const SHA512_EMPTY =
  'cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e'

// LEGACY_TOPIC_VECTORS of test/swarm.test.js, computed with hugin-node's
// code path before hugin-network 3.0. `basePub` (the `topic` string) is unchanged; `discovery` is the
// earlier DHT topic, which the domain-separated derivation of 3.0 no longer produces.
const NODE_TOPIC_VECTORS = [
  {
    name: 'public nodes',
    opts: { pub: true },
    basePub: '5f70ed4fd39ca7305ba72377d815dade9083749f3fd9d18b99c618cf81146112',
    discovery: '3566373065643466643339636137333035626137323337376438313564616465'
  },
  {
    name: 'private node (address)',
    opts: { address: ADDRESS },
    basePub: '4137128773a971b710878df51973b42358b37fb016b6ee3bd837cdd356c42b95',
    discovery: '3431333731323837373361393731623731303837386466353139373362343233'
  }
]

const INVITES = [
  'a0'.repeat(32) + '5f70ed4fd39ca7305ba72377d815dade9083749f3fd9d18b99c618cf81146112',
  '0123456789abcdef'.repeat(8),
  '0123456789ABCDEF'.repeat(8) // upper case parses like lower case in both apps
]

const dhtKeyPair = keyPairFromSeed(b4a.alloc(32, 0x11))
const otherDhtKeyPair = keyPairFromSeed(b4a.alloc(32, 0x22))

test('hexToUint: same bytes as desktop and RN hexToUint', (t) => {
  for (const input of ['00ff10', 'abc', 'ABCDEF', 'zz12', '1731500000000', 'a0'.repeat(64)]) {
    const ours = Array.from(keys.hexToUint(input))
    t.alike(ours, Array.from(desktop.hexToUint(input)), 'desktop ' + input)
    t.alike(ours, Array.from(native.rnHexToUint(input)), 'RN ' + input)
  }
  t.alike(Array.from(keys.hexToUint('')), Array.from(native.rnHexToUint('')), 'empty string like RN')
})

test('swarm key is SHA-512 over the hex bytes', (t) => {
  t.is(hex(keys.swarmKey('616263')), SHA512_ABC, 'sha512("abc")')
  t.is(hex(keys.swarmKey('')), SHA512_EMPTY, 'sha512("")')
  t.is(hex(keys.roomSwarmKey('616263')), SHA512_ABC)
  t.is(hex(keys.dmSwarmKey('616263')), SHA512_ABC)
})

test('room topic: same as desktop naclHash and native toUintArray(naclHash) paths', { skip: !NODE }, (t) => {
  for (const invite of INVITES) {
    const ours = keys.roomTopic(invite)

    // desktop swarm.cjs create_swarm: key = naclHash(invite); get_new_peer_keys(key)
    const desktopKey = desktop.naclHash(invite)
    t.is(hex(ours.key), hex(desktopKey), 'swarm key = desktop naclHash')
    const desktopPeer = getNewPeerKeys(desktopKey)
    t.is(ours.topic, hex(desktopPeer.basePublicKey), 'topic = desktop topicHash')
    t.is(hex(ours.discoveryKey), hex(desktopPeer.topic), 'discovery key = desktop')

    // native: RN naclHash -> "b0,b1,..." -> bare toUintArray -> get_new_peer_keys
    const csv = native.naclHash(invite)
    const nativeKey = native.toUintArray(csv)
    t.is(hex(nativeKey), hex(ours.key), 'swarm key = native toUintArray(naclHash)')
    t.is(keys.swarmKeyToCsv(ours.key), csv, 'csv transport form')
    t.is(hex(keys.swarmKeyFromCsv(csv)), hex(ours.key), 'csv round trip')
    t.is(ours.topic, hex(getNewPeerKeys(nativeKey).basePublicKey), 'topic = native Room.join topic')
    t.unlike(ours.discoveryKey, legacyTopicFromKey(desktopKey).topic, 'discovery key is not the earlier one')

    t.alike(keys.dmTopic(invite), ours, 'a DM derivation hash goes through the same derivation')
  }
})

test('node topics: same topic string as hugin-node, DHT topic no longer the earlier one', (t) => {
  for (const v of NODE_TOPIC_VECTORS) {
    const tp = keys.nodeTopic(v.opts)
    t.is(tp.topic, v.basePub, v.name + ': topic string (hex base key) unchanged')
    t.not(hex(tp.discoveryKey), v.discovery, v.name + ': discovery key differs from the earlier one')
    t.is(hex(legacyTopicFromKey(tp.key).topic), v.discovery, v.name + ': fixture = earlier discovery key')
    // keccak256(UTF-8("hugin/topic") || base public key), computed here without lib/swarm.js
    const expected = keccak256(b4a.concat([b4a.from('hugin/topic', 'utf8'), b4a.from(v.basePub, 'hex')]))
    t.is(hex(tp.discoveryKey), expected, v.name + ': discovery key')
  }
  t.is(keys.nodeSwarmKey({ pub: true }), NETWORK_ADDRESS)
  t.exception.all(() => keys.nodeSwarmKey({}))
})

test('node firewall: public topic allows anyone, private node only the invite key', (t) => {
  const remote = dhtKeyPair.publicKey
  const invite = ADDRESS + hex(remote)
  t.ok(keys.isAllowedNodePeer(remote, { pub: true }))
  t.ok(keys.isAllowedNodePeer(remote, { address: invite }))
  t.absent(keys.isAllowedNodePeer(otherDhtKeyPair.publicKey, { address: invite }))
})

test('createRoomInvite: same invite and seed as desktop create_room_invite', { skip: !NODE }, (t) => {
  const randoms = [SEED_HEX, RAND_HEX]
  const [dInvite, dSeed] = desktop.create_room_invite(() => randoms.shift())
  const ours = keys.createRoomInvite({ adminSeed: SEED_HEX, rand: RAND_HEX })
  t.is(ours.invite, dInvite, 'invite')
  t.is(ours.adminSeed, dSeed, 'admin seed')
  t.ok(keys.isRoomInvite(ours.invite))
  t.is(hex(keys.adminPublicKeyFromInvite(ours.invite)), hex(keys.adminKeyPair(SEED_HEX).publicKey))
})

test('createRoomInvite: random invites are well formed', (t) => {
  const a = keys.createRoomInvite()
  const b = keys.createRoomInvite()
  t.ok(keys.isRoomInvite(a.invite))
  t.is(a.adminSeed.length, 64)
  t.not(a.invite, b.invite)
  t.exception.all(() => keys.createRoomInvite({ adminSeed: 'xyz' }))
})

test('admin signature: byte-identical to both apps, verifies in both apps', { skip: !NODE }, (t) => {
  const { invite, adminSeed } = keys.createRoomInvite({ adminSeed: SEED_HEX, rand: RAND_HEX })
  const ours = keys.signAdmin(adminSeed, dhtKeyPair.publicKey)

  const nativeSig = native.sign_admin_message(native.Keychain.from(dhtKeyPair), adminSeed)
  t.is(hex(ours), hex(nativeSig), 'native sign_admin_message')
  const desktopSig = desktop.sign_admin_message(native.Keychain.from(dhtKeyPair), invite, [{ invite, priv: adminSeed }])
  t.is(hex(ours), hex(desktopSig), 'desktop sign_admin_message')

  const pub = Buffer.from(invite.slice(-64), 'hex')
  t.ok(native.verify_signature(dhtKeyPair.publicKey, Buffer.from(hex(ours), 'hex'), pub), 'native verify')
  t.ok(desktop.verify_signature(dhtKeyPair.publicKey, Buffer.from(hex(ours), 'hex'), pub), 'desktop verify')
  t.ok(keys.verifyAdmin(dhtKeyPair.publicKey, hex(ours), invite), 'verifyAdmin (hex)')
  t.ok(keys.verifyAdmin(dhtKeyPair.publicKey, ours, invite), 'verifyAdmin (bytes)')
})

test('verifyAdmin: same answer as the apps for every case', { skip: !NODE }, (t) => {
  // Invites from the library/desktop path and from native create_room_invite (raw seed bytes).
  const lib = keys.createRoomInvite({ adminSeed: SEED_HEX, rand: RAND_HEX })
  const nativeRandoms = [Buffer.alloc(32, 0x31), Buffer.alloc(32, 0x32)]
  const [nativeInvite, nativeSeed] = native.create_room_invite(() => nativeRandoms.shift())

  const cases = []
  for (const { invite, seed } of [{ invite: lib.invite, seed: lib.adminSeed }, { invite: nativeInvite, seed: nativeSeed }]) {
    const good = hex(keys.signAdmin(seed, dhtKeyPair.publicKey))
    cases.push({ invite, sig: good, key: dhtKeyPair.publicKey })
    cases.push({ invite, sig: good, key: otherDhtKeyPair.publicKey })
    cases.push({ invite, sig: '', key: dhtKeyPair.publicKey })
    cases.push({ invite, sig: '00'.repeat(64), key: dhtKeyPair.publicKey })
    cases.push({ invite, sig: good.slice(0, 126), key: dhtKeyPair.publicKey })
  }
  for (const c of cases) {
    const expected = native.verify_signature(c.key, Buffer.from(c.sig, 'hex'), Buffer.from(c.invite.slice(-64), 'hex'))
    const expectedDesktop = desktop.verify_signature(c.key, Buffer.from(c.sig, 'hex'), Buffer.from(c.invite.slice(-64), 'hex'))
    t.is(expected, expectedDesktop, 'apps agree')
    t.is(keys.verifyAdmin(c.key, c.sig, c.invite), expected, 'verifyAdmin')
  }
})

test('native create_room_invite: invite key from the raw seed bytes, signer from the hex seed', { skip: !NODE }, (t) => {
  // hugin-native bare/utils.js:172 derives the invite's admin key from the 32 raw seed bytes and
  // returns the seed as hex; sign_admin_message (utils.js:511) fills the hex string. The library
  // uses the hex string on both sides, as desktop does.
  const randoms = [Buffer.alloc(32, 0x31), Buffer.alloc(32, 0x32)]
  const [invite, seedHex] = native.create_room_invite(() => randoms.shift())
  const rawKey = keyPairFromSeed(Buffer.alloc(32, 0x31)).publicKey
  t.is(invite.slice(-64), hex(rawKey), 'invite key = keyPair(raw seed)')
  t.not(invite.slice(-64), hex(keys.adminKeyPair(seedHex).publicKey), 'signer key = keyPair(fill32(hex seed))')
  const sig = native.sign_admin_message(native.Keychain.from(dhtKeyPair), seedHex)
  t.absent(native.verify_signature(dhtKeyPair.publicKey, sig, Buffer.from(invite.slice(-64), 'hex')), 'native: no match')
  t.absent(keys.verifyAdmin(dhtKeyPair.publicKey, sig, invite), 'library: same answer')
})

test('verifyAdmin rejects malformed input without throwing', (t) => {
  const { invite, adminSeed } = keys.createRoomInvite({ adminSeed: SEED_HEX, rand: RAND_HEX })
  const sig = hex(keys.signAdmin(adminSeed, dhtKeyPair.publicKey))
  t.absent(keys.verifyAdmin(dhtKeyPair.publicKey, sig, 'short'))
  t.absent(keys.verifyAdmin(dhtKeyPair.publicKey, sig, invite.slice(0, -1) + 'z'))
  t.absent(keys.verifyAdmin(dhtKeyPair.publicKey, 'zz'.repeat(64), invite))
  t.absent(keys.verifyAdmin(b4a.alloc(31), sig, invite))
  t.is(keys.adminPublicKeyFromInvite('x'), null)
})

test('idSig: message is the hugin/id context with the topic and the DHT key; verification awaits the host verifier', async (t) => {
  const pub = dhtKeyPair.publicKey
  const topic = keys.roomTopic(INVITES[0]).topic
  const expected = 'hugin/id\n' + JSON.stringify([topic, hex(pub)])
  t.is(keys.idSigMessage(pub, topic), expected)
  t.is(keys.idSigMessage(pub, topic.toUpperCase()), expected, 'the topic in lower case')
  t.not(keys.idSigMessage(pub, keys.roomTopic(INVITES[1]).topic), expected, 'another topic, another message')
  t.exception(() => keys.idSigMessage(pub, 'xyz'), /topic/)
  t.exception(() => keys.idSigMessage(b4a.alloc(31), topic), /dhtPublicKey/)

  const calls = []
  const sig = await keys.signIdSig({ dhtPublicKey: pub, topic }, async (m) => {
    calls.push(m)
    return 'sig-of-' + m
  })
  t.is(sig, 'sig-of-' + expected)
  t.alike(calls, [expected])

  const seen = []
  const verify = async (message, address, signature) => {
    seen.push([message, address, signature])
    return signature === 'good'
  }
  const ok = (o, fn = verify) => keys.verifyIdSig({ dhtPublicKey: pub, topic, address: ADDRESS, idSig: 'good', ...o }, fn)
  t.is(await ok({}), true)
  t.alike(seen[0], [expected, ADDRESS, 'good'], 'verify(message, address, signature)')
  t.is(await ok({ idSig: 'bad' }), false)
  t.is(await ok({}, async () => { throw new Error('rpc') }), false)
  t.is(await ok({}, () => Promise.resolve(false)), false)
  t.is(await ok({ address: 'short' }), false)
  t.is(await ok({ idSig: '' }), false)
  t.is(await ok({ idSig: 'x'.repeat(129) }), false)
  t.is(await ok({ topic: undefined }), false, 'no topic: not verified')
  t.is(await ok({ topic: 'zz'.repeat(32) }), false, 'malformed topic: not verified')
  await t.exception.all(keys.signIdSig({ dhtPublicKey: pub, topic }, async () => 42))
  await t.exception(keys.signIdSig({ dhtPublicKey: pub }, async (m) => m), /topic/)
})

test('newPeerKeys: per-swarm DHT identity for a swarm key', (t) => {
  const k = keys.newPeerKeys(keys.roomSwarmKey(INVITES[0]), dhtKeyPair)
  t.is(hex(k.basePublicKey), keys.roomTopic(INVITES[0]).topic)
  t.is(hex(k.keyPair.publicKey), hex(dhtKeyPair.publicKey))
  t.is(k.sig.byteLength, 64)
})
