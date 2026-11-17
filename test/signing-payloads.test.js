'use strict'

// The strings the host's XKR key signs (README "Protocol"): one context prefix per kind
// (`hugin/id`, `hugin/room-message`, `hugin/feed`, `hugin/file`, `hugin/dm`), a JSON array after it. Pure
// payload checks, a Feed check, and two runs on a local DHT testnet (rooms with a fixed DHT key
// pair).

const test = require('brittle')
const b4a = require('b4a')
const createTestnet = require('hyperdht/testnet.js')
const keys = require('../lib/keys.js')
const wire = require('../lib/wire.js')
const E = require('../lib/events.js')
const { Rooms } = require('../lib/rooms.js')
const { Feed, FEED_RESULT } = require('../lib/feed.js')
const { createHuginSwarm, keyPairFromSeed } = require('../lib/swarm.js')
const { SIGNING_DOMAINS } = require('../lib/constants.js')
const { dmSigningPayload } = require('../lib/dm.js')
const { sha512, toHex, randomBytes } = require('../lib/bytes.js')
const { ADDRESS, ADDRESS_2, HASH, PAST, hex } = require('./helpers.js')

const ADDRESS_3 = 'SEKRe' + 'c'.repeat(94)
const DHT_WAIT = 90000

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms))

/** Stand-in for the XKR message signature: only the holder of `address` "can" produce it. */
function fakeSign(address, message) {
  return toHex(sha512(b4a.from(address + '|' + message, 'utf8')))
}

/** Polls `fn`; resolves true, or false after `ms` with a failed assertion. Never rejects. */
async function waitFor(t, fn, label, ms = DHT_WAIT) {
  const start = Date.now()
  while (!(await fn())) {
    if (Date.now() - start > ms) {
      t.fail('timed out waiting for ' + label)
      return false
    }
    await sleep(50)
  }
  return true
}

// ---------------------------------------------------------------------------------------------
// payloads

/** Every signed string of each kind for a set of nearby values (empty strings included). */
function signedStrings() {
  const { invite } = keys.createRoomInvite()
  const r = keys.roomTopic(invite)
  const dhtKeys = [r.base.publicKey, keyPairFromSeed(b4a.alloc(32, 1)).publicKey]
  const topics = [r.topic, keys.roomTopic(keys.createRoomInvite().invite).topic]
  const hashes = [HASH, ...dhtKeys.map(hex), ...topics]
  const texts = ['', 'post', HASH, r.topic, JSON.stringify([r.topic, hex(dhtKeys[0])])]
  const out = { id: [], room: [], feed: [], file: [], dm: [] }
  for (const k of dhtKeys) for (const topic of topics) out.id.push(keys.idSigMessage(k, topic))
  for (const hash of hashes) {
    for (const message of texts) {
      out.dm.push(dmSigningPayload(ADDRESS, PAST, message, 4, ''))
      out.dm.push(dmSigningPayload(ADDRESS_2, PAST, hash, 1, hash))
      out.room.push(wire.roomMessageSigningPayload({ room: invite, hash, timestamp: PAST, address: ADDRESS, name: '', message, reply: '', tip: false }))
      out.feed.push(wire.feedSigningPayload({ hash, timestamp: PAST, address: ADDRESS, nickname: '', message, reply: '', tip: false }))
      for (const topic of topics) {
        out.file.push(wire.fileSigningPayload({ topic, hash, contentHash: hash, size: 0, time: PAST, fileName: message, address: ADDRESS }))
      }
    }
  }
  return { out, r, dhtKeys }
}

test('signed strings of different kinds never coincide', (t) => {
  const domains = Object.values(SIGNING_DOMAINS)
  t.alike(domains.slice().sort(), ['hugin/dm\n', 'hugin/feed\n', 'hugin/file\n', 'hugin/id\n', 'hugin/room-message\n'])
  for (const a of domains) {
    t.ok(a.endsWith('\n') && a.indexOf('\n') === a.length - 1, JSON.stringify(a) + ': one newline, at the end')
    for (const b of domains) if (a !== b) t.absent(b.startsWith(a), JSON.stringify(a) + ' is not a prefix of ' + JSON.stringify(b))
  }

  const { out } = signedStrings()
  const prefix = { id: SIGNING_DOMAINS.ID, room: SIGNING_DOMAINS.ROOM_MESSAGE, feed: SIGNING_DOMAINS.FEED, file: SIGNING_DOMAINS.FILE, dm: SIGNING_DOMAINS.DM }
  const seen = new Map()
  for (const [kind, list] of Object.entries(out)) {
    t.ok(list.every((s) => s.startsWith(prefix[kind])), kind + ': every string starts with its context')
    for (const s of list) {
      const before = seen.get(s)
      if (before && before !== kind) t.fail(kind + ' and ' + before + ' share a string')
      seen.set(s, kind)
    }
  }
  t.pass('no string in two kinds')
})

test('the values signed before 3.0 are not signed strings of any kind any more', (t) => {
  const { out, r, dhtKeys } = signedStrings()
  const all = new Set([].concat(...Object.values(out)))
  const d = dhtKeys[0]
  // a voice status signed the room topic; an idSig the bare DHT key; a feed post message + hash
  t.absent(all.has(r.topic), 'the bare topic')
  t.absent(all.has(hex(d)), 'the bare DHT key')
  t.not(keys.idSigMessage(r.base.publicKey, r.topic), r.topic, 'idSig of the base key is not the topic')
  t.not(wire.feedSigningPayload({ hash: hex(d), timestamp: PAST, address: ADDRESS, nickname: '', message: '', reply: '', tip: false }), keys.idSigMessage(d, r.topic))
  t.is(wire.voiceSigningPayload, undefined, 'voice status is not signed')
})

test('a feed post carrying an idSig as its signature is not verified', async (t) => {
  const { r } = signedStrings()
  const dht = keyPairFromSeed(b4a.alloc(32, 2)).publicKey
  const idSig = fakeSign(ADDRESS_2, keys.idSigMessage(dht, r.topic))
  const host = {
    verify: async (message, address, signature) => signature === fakeSign(address, message),
    feedMessageExists: async () => false
  }
  const events = []
  const feed = new Feed({ host, emit: (n, p) => events.push([n, p]), peers: () => [] })
  t.teardown(() => feed.destroy())
  const peer = { address: ADDRESS_3, send: () => true, room: { dm: false } }

  // with the hash derived from the post, and with the DHT key as its hash (the 2.x shape)
  const post = { type: 'feed', message: '', nickname: '', address: ADDRESS_2, reply: '', tip: false, timestamp: PAST }
  const derived = { ...post, hash: wire.feedMessageHash(post), signature: idSig }
  const keyHash = { ...post, hash: hex(dht), signature: idSig }
  t.is(await feed.handle(peer, derived), FEED_RESULT.UNVERIFIED)
  t.is(await feed.handle(peer, keyHash), FEED_RESULT.UNVERIFIED)
  t.is(events.length, 0)
})

// ---------------------------------------------------------------------------------------------
// on a DHT testnet

function makeHost(address, extra = {}) {
  return {
    identity: () => ({ address, name: 'n', avatar: '' }),
    sign: async (message) => fakeSign(address, message),
    verify: async (message, addr, signature) => signature === fakeSign(addr, message),
    ...extra
  }
}

/** Rooms on the testnet; `keyPair` fixes the DHT key pair of its swarms. Records events. */
function makeRooms(t, testnet, host, { keyPair = null } = {}) {
  const registries = []
  const rooms = new Rooms({
    host,
    bootstrap: testnet.bootstrap,
    pingIntervalMs: 0,
    leaveFlushMs: 50,
    createSwarm: (o) => {
      const created = createHuginSwarm(keyPair ? { ...o, keyPair } : o)
      registries.push(created.registry)
      return created
    }
  })
  const events = []
  for (const n of E.ALL) rooms.on(n, (payload) => events.push([n, payload]))
  t.teardown(() => rooms.destroy())
  return { rooms, registries, of: (n) => events.filter(([e]) => e === n).map(([, p]) => p) }
}

test('a joined whose idSig was made for another room is refused', { timeout: 180000 }, async (t) => {
  const testnet = await createTestnet(3, t.teardown)
  const R = keys.createRoomInvite().invite
  const base = keys.roomTopic(R).base

  // V is in room R: its idSig there signs [topic of R, V's DHT key in R]
  const V = makeRooms(t, testnet, makeHost(ADDRESS_2))
  const W = makeRooms(t, testnet, makeHost(ADDRESS))
  await V.rooms.join({ invite: R })
  await W.rooms.join({ invite: R })
  if (!(await waitFor(t, () => W.rooms.isPeerIn(R, ADDRESS_2), 'V joined in R'))) return
  const vKey = W.rooms.get(R).peerByAddress(ADDRESS_2).connection.remotePublicKey
  const fromR = fakeSign(ADDRESS_2, keys.idSigMessage(vKey, keys.roomTopic(R).topic))
  const topicOnly = fakeSign(ADDRESS_2, keys.roomTopic(R).topic) // what a 2.x voice status signed

  // in another room, a peer with R's base key pair presents those signatures as V's idSig
  for (const [what, sig] of [['the idSig of room R', fromR], ['a signature of the topic of R', topicOnly]]) {
    const R2 = keys.createRoomInvite().invite
    const Y = makeRooms(t, testnet, makeHost(ADDRESS))
    const X = makeRooms(t, testnet, makeHost(ADDRESS_2, { sign: async () => sig }), { keyPair: base })
    await Y.rooms.join({ invite: R2 })
    await X.rooms.join({ invite: R2 })
    const room = Y.rooms.get(R2)
    if (!(await waitFor(t, () => room.denied.has(hex(base.publicKey)), what + ': key refused'))) return
    t.absent(Y.rooms.isPeerIn(R2, ADDRESS_2), what + ': not admitted')
    t.absent(Y.of(E.PEER_JOINED).some((e) => e.peer.address === ADDRESS_2), what + ': no peer:joined')
    await X.rooms.destroy()
    await Y.rooms.destroy()
  }
})

test('a peer whose DHT key is the room base key is refused in the handshake', { timeout: 180000 }, async (t) => {
  const testnet = await createTestnet(3, t.teardown)
  const { invite } = keys.createRoomInvite()
  const base = keys.roomTopic(invite).base

  const Y = makeRooms(t, testnet, makeHost(ADDRESS))
  const X = makeRooms(t, testnet, makeHost(ADDRESS_2), { keyPair: base })
  await Y.rooms.join({ invite })
  await X.rooms.join({ invite })
  await Y.rooms.get(invite).flushed()
  await X.rooms.get(invite).flushed()
  const rejected = () => Y.registries.some((reg) => {
    const r = reg.rejections.get(hex(base.publicKey))
    return !!r && r.reason === 'base key'
  })
  if (!(await waitFor(t, rejected, 'handshake refused'))) return
  t.is(Y.rooms.get(invite).peers.size, 0, 'no connection')
  t.is(Y.of(E.PEER_JOINED).length, 0)
  t.ok(Y.rooms.get(invite).firewall(base.publicKey), 'the room firewall refuses the base key too')
  t.absent(Y.rooms.get(invite).firewall(keyPairFromSeed(randomBytes(32)).publicKey), 'other keys pass')
})
