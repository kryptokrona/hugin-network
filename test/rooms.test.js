'use strict'

// hugin-network rooms: lib/rooms.js, lib/room.js, lib/peer.js, lib/voice.js, lib/channel.js and
// lib/events.js. Unit tests run two (or three) Rooms instances with an in-memory host on fake
// swarms whose connections are real NoiseSecretStream pairs (protomux needs a real stream); one
// test runs two peers on a local DHT testnet.

const test = require('brittle')
const b4a = require('b4a')
const EventEmitter = require('bare-events')
const NoiseSecretStream = require('@hyperswarm/secret-stream')
const createTestnet = require('hyperdht/testnet.js')
const { Rooms, RoomsError } = require('../lib/rooms.js')
const { openHuginChannel } = require('../lib/channel.js')
const E = require('../lib/events.js')
const keys = require('../lib/keys.js')
const wire = require('../lib/wire.js')
const S = require('../lib/sanitize.js')
const { keyPairFromSeed } = require('../lib/swarm.js')
const { sha512, randomBytes, randomKey, toHex } = require('../lib/bytes.js')
const { ADDRESS, ADDRESS_2, CONTENT_HASH, hex } = require('./helpers.js')

const ADDRESS_3 = 'SEKRe' + 'c'.repeat(94)
const DERIVATION = 'ab'.repeat(32)

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms))

function noop() {}

/** Stand-in for the XKR message signature: only the holder of `address` "can" produce it. */
function fakeSign(address, message) {
  return toHex(sha512(b4a.from(address + '|' + message, 'utf8')))
}

async function waitFor(fn, what = 'condition', ms = 10000) {
  const start = Date.now()
  while (!(await fn())) {
    if (Date.now() - start > ms) throw new Error('timed out waiting for ' + what)
    await sleep(10)
  }
}

/** In-memory host (README "Host hooks and events") that stores what it is told and records hook arguments. */
function makeHost(address, name, extra = {}) {
  const messages = new Map()
  const host = {
    address,
    messages,
    banned: new Set(),
    blocked: new Set(),
    calls: [],
    identity: () => ({ address, name, avatar: '' }),
    sign: async (message) => fakeSign(address, message),
    verify: async (message, addr, signature) => signature === fakeSign(addr, message),
    roomMessageExists: async (hash) => {
      host.calls.push(['roomMessageExists', hash])
      return messages.has(hash)
    },
    getRoomHistory: async (key) => {
      host.calls.push(['getRoomHistory', key])
      return [...messages.values()].filter((m) => m.room === key)
    },
    getRoomMessage: async (hash) => {
      host.calls.push(['getRoomMessage', hash])
      return messages.get(hash) || null
    },
    getLatestRoomHashes: async (key) => {
      host.calls.push(['getLatestRoomHashes', key])
      return [...messages.values()].filter((m) => m.room === key).map((m) => m.hash).slice(-25)
    },
    isBanned: (addr) => host.banned.has(addr),
    isBlocked: (addr) => host.blocked.has(addr),
    ...extra
  }
  return host
}

/** Hyperswarm stand-in: connections are handed to it by `connect`. */
class FakeSwarm extends EventEmitter {
  constructor(opts) {
    super()
    this.opts = opts
    this.keyPair = keyPairFromSeed(randomBytes(32))
    this.firewall = opts.firewall || (() => false)
    this.topicHex = keys.topicFromSwarmKey(opts.key).topic
    this.dialed = []
    this.refreshes = 0
    this.suspended = false
    this.destroyed = false
  }

  join() {
    return {
      flushed: async () => {},
      refresh: () => {
        this.refreshes++
      },
      destroy: async () => {}
    }
  }

  async leave() {}

  joinPeer(publicKey) {
    this.dialed.push(hex(publicKey))
  }

  async suspend() {
    this.suspended = true
  }

  async resume() {
    this.suspended = false
  }

  async destroy() {
    this.destroyed = true
  }
}

/** A Rooms instance on fake swarms with an in-memory host; records every event. */
function makeRooms(t, { address, name, host: extraHost, ...opts } = {}) {
  const host = makeHost(address, name, extraHost)
  const swarms = []
  const rooms = new Rooms({
    host,
    pingIntervalMs: 0,
    historyPickMs: 0, // history from the first earlier peer at once (rooms-limits.test.js covers the pick)
    leaveFlushMs: 50,
    banLeaveDelayMs: 50,
    createSwarm: (o) => {
      const swarm = new FakeSwarm(o)
      swarms.push(swarm)
      return { swarm, topic: keys.topicFromSwarmKey(o.key).discoveryKey, keyPair: swarm.keyPair }
    },
    ...opts
  })
  const events = []
  for (const n of E.ALL) rooms.on(n, (payload) => events.push([n, payload]))
  // the host stores what it receives (dedupe for the sync)
  rooms.on(E.ROOM_MESSAGE, ({ message }) => host.messages.set(message.hash, message))
  t.teardown(() => rooms.destroy())
  const side = {
    rooms,
    host,
    swarms,
    events,
    address,
    swarm: (topic) => swarms.filter((s) => s.topicHex === topic).pop(),
    of: (n, filter = () => true) => events.filter(([e, p]) => e === n && filter(p)).map(([, p]) => p),
    room: (key) => rooms.get(key)
  }
  return side
}

/** Sends a (signed) room message and stores it on the sender's host, as an app does. */
async function say(side, key, text) {
  const msg = await side.rooms.send(key, { message: text })
  side.host.messages.set(msg.hash, msg)
  return msg
}

/** Two NoiseSecretStreams with the given key pairs, opened. */
async function streams(t, kpA, kpB) {
  const a = new NoiseSecretStream(true, null, { keyPair: kpA })
  const b = new NoiseSecretStream(false, null, { keyPair: kpB })
  a.on('error', noop)
  b.on('error', noop)
  a.rawStream.pipe(b.rawStream).pipe(a.rawStream)
  t.teardown(() => {
    a.destroy()
    b.destroy()
  })
  await Promise.all([a.opened, b.opened])
  return [a, b]
}

function peerInfo() {
  return {
    banned: false,
    ban(v) {
      this.banned = v
    }
  }
}

/** Connects A's and B's swarms of `topic` (unless a firewall refuses); returns null when refused. */
async function connect(t, A, B, topic) {
  const sa = A.swarm(topic)
  const sb = B.swarm(topic)
  const [a, b] = await streams(t, sa.keyPair, sb.keyPair)
  if (sa.firewall(b.publicKey, null) || sb.firewall(a.publicKey, null)) {
    a.destroy()
    b.destroy()
    return null
  }
  const ia = peerInfo()
  const ib = peerInfo()
  sa.emit('connection', a, ia)
  sb.emit('connection', b, ib)
  return { a, b, ia, ib }
}

/**
 * A hand-driven peer on A's swarm of `topic`: a raw `hugin-messages` channel with its own DHT
 * key pair. `joined(address)` builds a joined whose idSig verifies for that address.
 */
async function rawPeer(t, A, topic) {
  const sa = A.swarm(topic)
  const kp = keyPairFromSeed(randomBytes(32))
  const [a, b] = await streams(t, sa.keyPair, kp)
  if (sa.firewall(kp.publicKey, null)) {
    a.destroy()
    b.destroy()
    return null
  }
  const info = peerInfo()
  const received = []
  const ch = openHuginChannel(b, (str) => received.push(str))
  sa.emit('connection', a, info)
  return {
    kp,
    conn: b,
    info,
    received,
    parsed: () => received.map((s) => {
      try {
        return JSON.parse(s)
      } catch {
        return s
      }
    }),
    send: (msg) => ch.send(typeof msg === 'string' ? msg : JSON.stringify(msg)),
    joined: (address, extra = {}) =>
      wire.joined({
        address,
        name: 'raw',
        topic,
        time: Date.now(),
        idSig: fakeSign(address, keys.idSigMessage(kp.publicKey, topic)),
        ...extra
      })
  }
}

/**
 * A room message signed (fake XKR signature) by `signer`, by default its own address. With
 * `fields.signature` the given signature is kept as it is.
 */
function roomMsg(fields = {}, { signer } = {}) {
  const draft = wire.roomMessage({
    hash: '0'.repeat(64),
    address: ADDRESS_2,
    name: 'raw',
    message: 'hi',
    timestamp: Date.now(),
    ...fields,
    signature: fields.signature || '0'.repeat(128)
  })
  // the hash is derived from the message unless the test gives one
  if (fields.hash === undefined) draft.hash = wire.roomMessageHash(draft)
  if (fields.signature) return draft
  return { ...draft, signature: fakeSign(signer || draft.address, wire.roomMessageSigningPayload(draft)) }
}

/** A joined room between A (creator, admin) and B. */
async function joinedPair(t, optsA = {}, optsB = {}) {
  const A = makeRooms(t, { address: ADDRESS, name: 'alice', ...optsA })
  const B = makeRooms(t, { address: ADDRESS_2, name: 'bob', ...optsB })
  const { invite, adminSeed } = keys.createRoomInvite()
  const ra = await A.rooms.join({ invite, adminSeed })
  await sleep(5) // B starts its swarm later than A
  const rb = await B.rooms.join({ invite })
  const conn = await connect(t, A, B, ra.topic)
  await waitFor(() => A.rooms.isPeerIn(invite, ADDRESS_2) && B.rooms.isPeerIn(invite, ADDRESS), 'joined both ways')
  return { A, B, invite, adminSeed, topic: ra.topic, ra, rb, conn }
}

// =============================================================================================
// small modules

test('events: canonical names are unique strings', (t) => {
  t.is(new Set(E.ALL).size, E.ALL.length)
  t.is(E.ROOM_JOINED, 'room:joined')
  t.is(E.DM_WIRE, 'dm:wire')
  t.is(E.VOICE_RETRY, 'voice:retry')
  t.ok(Object.isFrozen(E.EVENTS))
  t.ok(E.ALL.includes('file:remote') && E.ALL.includes('node:messages'))
})

test('channel: strings both ways on one mux, send is false once closed', async (t) => {
  const [a, b] = await streams(t, keyPairFromSeed(randomBytes(32)), keyPairFromSeed(randomBytes(32)))
  const got = []
  const ca = openHuginChannel(a, noop)
  const cb = openHuginChannel(b, (s) => got.push(s))
  t.ok(ca && cb)
  t.is(openHuginChannel(a, noop), null, 'one hugin-messages channel per stream')
  t.ok(ca.send('{"typing":true}'))
  t.absent(ca.send(42), 'only strings')
  await waitFor(() => got.length === 1, 'message')
  t.is(got[0], '{"typing":true}')
  ca.close()
  t.ok(ca.closed)
  t.absent(ca.send('x'), 'not sent on a closed channel')
})

// =============================================================================================
// handshake

test('joined both ways: peer:joined, admin flag only for the invite creator', async (t) => {
  const { A, B, invite, topic, ra, rb } = await joinedPair(t)
  t.is(ra.admin, true, 'creator holds the admin seed')
  t.is(rb.admin, false)
  t.is(ra.topic, rb.topic)
  t.alike(A.of(E.ROOM_JOINED)[0], { key: invite, topic, dm: false, admin: true })

  const atA = A.room(invite).peerByAddress(ADDRESS_2)
  const atB = B.room(invite).peerByAddress(ADDRESS)
  t.is(atA.admin, false, 'B is not admin at A')
  t.is(atB.admin, true, 'A verified as admin at B')
  t.is(atB.name, 'alice')
  t.ok(atB.joined)
  t.is(typeof atB.time, 'number')

  const pj = B.of(E.PEER_JOINED)[0]
  t.is(pj.key, invite)
  t.is(pj.dm, false)
  t.is(pj.peer.address, ADDRESS)
  t.is(pj.peer.admin, true)
  t.alike(A.rooms.list(), [{ key: invite, topic, dm: false, admin: true, peers: 1 }])
  t.is(A.rooms.joinedPeers({ dm: false }).length, 1)
  t.is(A.rooms.joinedPeers({ dm: true }).length, 0)
  t.is(atA.room, A.room(invite), 'peer.room is the Room')
  t.is(atA.remotePublicKey.length, 64)

  // a seed that does not belong to the invite gives no admin rights
  const C = makeRooms(t, { address: ADDRESS_3, name: 'carol' })
  const other = keys.createRoomInvite()
  const rc = await C.rooms.join({ invite, adminSeed: other.adminSeed })
  t.is(rc.admin, false)
  t.alike(await C.rooms.join({ invite }), rc, 'joining again returns the open room')
})

test('a bad idSig closes the connection and bans the remote key', async (t) => {
  const A = makeRooms(t, { address: ADDRESS, name: 'alice' })
  const B = makeRooms(t, { address: ADDRESS_2, name: 'bob', host: { sign: async () => 'ff'.repeat(64) } })
  const { invite } = keys.createRoomInvite()
  const { topic } = await A.rooms.join({ invite })
  await B.rooms.join({ invite })
  const conn = await connect(t, A, B, topic)
  const room = A.room(invite)
  await waitFor(() => room.denied.size === 1, 'remote key denied')
  t.is(room.peers.size, 0, 'connection dropped')
  t.ok(conn.ia.banned, 'hyperswarm peer banned')
  t.is(A.of(E.PEER_JOINED).length, 0, 'never admitted')
  t.ok(room.denied.has(hex(B.swarm(topic).keyPair.publicKey)))
  t.is(await connect(t, A, B, topic), null, 'the firewall refuses the key from now on')
})

test('nothing but joined is accepted before joined; a message right after joined waits for the check', async (t) => {
  const A = makeRooms(t, {
    address: ADDRESS,
    name: 'alice',
    host: {
      verify: async (message, addr, signature) => {
        await sleep(100) // a slow host check
        return signature === fakeSign(addr, message)
      }
    }
  })
  const { invite } = keys.createRoomInvite()
  const { topic } = await A.rooms.join({ invite })
  const raw = await rawPeer(t, A, topic)

  await waitFor(() => raw.parsed().some((m) => m.joined === true), 'our joined')
  const ours = raw.parsed().find((m) => m.joined === true)
  t.is(ours.address, ADDRESS)
  t.is(ours.topic, topic)
  t.ok(S.joined(ours).ok, 'our joined passes the validator')

  raw.send(wire.typing(true))
  raw.send(roomMsg({ room: invite, message: 'too early' }))
  raw.send(wire.ping({ hashes: [] }))
  raw.send(wire.voiceStatus({ address: ADDRESS_2, topic, name: 'raw', signature: 'x', voice: true, video: false, audioMute: false, videoMute: false, screenshare: false }))
  await sleep(150)
  t.is(A.of(E.TYPING).length, 0)
  t.is(A.of(E.ROOM_MESSAGE).length, 0)
  t.is(A.of(E.VOICE_STATUS).length, 0)
  t.is(A.room(invite).peers.size, 1, 'not banned for it either')

  raw.send(raw.joined(ADDRESS_2))
  raw.send(roomMsg({ room: invite, message: 'right after joined' }))
  await waitFor(() => A.of(E.ROOM_MESSAGE).length === 1, 'room message after joined')
  t.is(A.of(E.PEER_JOINED).length, 1)
  t.is(A.of(E.ROOM_MESSAGE)[0].message.message, 'right after joined')
  t.is(A.of(E.TYPING).length, 0, 'the early typing was dropped')
})

// =============================================================================================
// traffic

test('room messages both ways; messages for another room or with another sender are rejected', async (t) => {
  const { A, B, invite } = await joinedPair(t)
  const sent = await say(A, invite, 'hello bob')
  t.is(sent.room, invite)
  t.is(sent.address, ADDRESS)
  t.is(sent.name, 'alice')
  t.ok(S.isHex64(sent.hash))
  await waitFor(() => B.of(E.ROOM_MESSAGE).length === 1, 'message at B')
  const got = B.of(E.ROOM_MESSAGE)[0]
  t.is(got.key, invite)
  t.is(got.message.message, 'hello bob')
  t.is(got.message.address, ADDRESS)
  t.is(got.history, false)
  t.is(got.live, true)

  await say(B, invite, 'hello alice')
  await waitFor(() => A.of(E.ROOM_MESSAGE).length === 1, 'message at A')
  t.is(A.of(E.ROOM_MESSAGE)[0].message.message, 'hello alice')

  const toA = B.room(invite).peerByAddress(ADDRESS)
  const other = keys.createRoomInvite().invite
  toA.send(wire.encode(roomMsg({ room: other, address: ADDRESS_2, message: 'other room' })))
  toA.send(wire.encode(roomMsg({ room: invite, address: ADDRESS_3, message: 'other sender' })))
  await say(B, invite, 'barrier')
  await waitFor(() => A.of(E.ROOM_MESSAGE).length === 2, 'barrier')
  await sleep(50)
  t.alike(A.of(E.ROOM_MESSAGE).map((e) => e.message.message), ['hello alice', 'barrier'])
  t.ok(A.rooms.isPeerIn(invite, ADDRESS_2), 'rejected, not banned')

  await t.exception(A.rooms.send('nope', { message: 'x' }), /not in this room/)
  await t.exception(A.rooms.send(invite, { message: 'x'.repeat(800) }), /message/, 'refused when it does not fit the send limits')
  try {
    await A.rooms.send('nope', { message: 'x' })
    t.fail('should reject')
  } catch (err) {
    t.ok(err instanceof RoomsError)
  }
})

test('Ping -> request-messages -> missing-messages fills a gap', async (t) => {
  const { A, B, invite } = await joinedPair(t)
  // a message A has and B missed (stored after both joined, so not in `joined.messages`)
  const missed = roomMsg({ room: invite, address: ADDRESS, name: 'alice', message: 'while you were away' })
  A.host.messages.set(missed.hash, missed)

  await B.room(invite).ping() // B's tick: B acts on Pings now
  t.is(await A.room(invite).ping(), 1, 'A pinged its one peer')
  await waitFor(() => B.of(E.ROOM_MESSAGE).length === 1, 'missing message at B')
  const got = B.of(E.ROOM_MESSAGE)[0]
  t.is(got.message.hash, missed.hash)
  t.is(got.history, true)
  t.is(got.live, true)
  const h = B.of(E.ROOM_HISTORY).pop()
  t.is(h.count, 1)
  t.is(h.missing.length, 1)
  t.ok(A.host.calls.some(([n, v]) => n === 'getRoomMessage' && v === missed.hash))
  t.is(B.swarm(A.room(invite).topic).dialed.length, 0, 'own key in the Ping peers is not dialed')

  // synced now: another round asks for nothing
  const before = A.host.calls.filter(([n]) => n === 'getRoomMessage').length
  await B.room(invite).ping()
  await A.room(invite).ping()
  await sleep(100)
  t.is(A.host.calls.filter(([n]) => n === 'getRoomMessage').length, before)
})

test('history for a late joiner', async (t) => {
  const A = makeRooms(t, { address: ADDRESS, name: 'alice' })
  const B = makeRooms(t, { address: ADDRESS_2, name: 'bob' })
  const { invite } = keys.createRoomInvite()
  const { topic } = await A.rooms.join({ invite })
  for (const text of ['one', 'two', 'three']) await say(A, invite, text)
  const other = roomMsg({ room: invite, address: ADDRESS_3, name: 'carol', message: 'from carol' })
  A.host.messages.set(other.hash, other)
  await sleep(5)
  await B.rooms.join({ invite })
  await connect(t, A, B, topic)

  await waitFor(() => B.of(E.ROOM_HISTORY).length === 1, 'history at B')
  const hist = B.of(E.ROOM_MESSAGE)
  t.is(hist.length, 4)
  t.ok(hist.every((e) => e.history === true && e.live === false))
  t.alike(hist.map((e) => e.message.message).sort(), ['from carol', 'one', 'three', 'two'])
  t.is(B.of(E.ROOM_HISTORY)[0].count, 4)

  // B started later, so it asks A once for history; A answers with send-history
  t.is(B.room(invite).requests, 1)
  t.is(A.room(invite).requests, 0)
  await waitFor(() => A.host.calls.filter(([n]) => n === 'getRoomHistory').length >= 2, 'A answered request-history')
  t.ok(A.host.calls.filter(([n]) => n === 'getRoomHistory').every(([, k]) => k === invite))
  t.is(A.of(E.ROOM_HISTORY).length, 0, 'nothing for A (B had no history)')
})

test('typing', async (t) => {
  const { A, B, invite, topic } = await joinedPair(t)
  t.is(A.rooms.typing(invite, true), 1)
  await waitFor(() => B.of(E.TYPING).length === 1, 'typing at B')
  t.alike(B.of(E.TYPING)[0], { key: invite, topic, address: ADDRESS, typing: true, dm: false })
  B.rooms.typing(invite, false)
  await waitFor(() => A.of(E.TYPING).length === 1, 'typing at A')
  t.is(A.of(E.TYPING)[0].typing, false)
  t.is(A.rooms.typing('unknown', true), 0)
})

test('voice status and SDP relay; an SDP or status with another address is rejected', async (t) => {
  const { A, B, invite, topic } = await joinedPair(t)

  t.ok(await B.rooms.voice.setStatus(invite, { voice: true }))
  await waitFor(() => A.of(E.VOICE_STATUS).length === 1, 'status at A')
  const st = A.of(E.VOICE_STATUS)[0]
  t.is(st.key, invite)
  t.is(st.topic, topic)
  t.is(st.address, ADDRESS_2)
  t.is(st.voice, true)
  t.ok(A.room(invite).peerByAddress(ADDRESS_2).voice)
  t.alike(B.rooms.voice.local(topic), { voice: true, video: false, audioMute: false, videoMute: false, screenshare: false })

  // A joins the call: B was in voice first, so A calls B
  await A.rooms.voice.setStatus(invite, { voice: true })
  await waitFor(() => A.of(E.VOICE_CALL).length === 1, 'voice:call at A')
  t.is(A.of(E.VOICE_CALL)[0].address, ADDRESS_2)
  t.is(A.of(E.VOICE_CALL)[0].name, 'bob')
  await waitFor(() => B.room(invite).peerByAddress(ADDRESS).voice, 'A in voice at B')

  t.ok(A.rooms.voice.sendSdp({ topic, address: ADDRESS_2, data: { type: 'offer', sdp: 'v=0' }, type: 'offer' }))
  await waitFor(() => B.of(E.VOICE_OFFER).length === 1, 'offer at B')
  const offer = B.of(E.VOICE_OFFER)[0]
  t.is(offer.address, ADDRESS)
  t.is(offer.data.offer, true)
  t.alike(offer.data.data, { type: 'offer', sdp: 'v=0' })

  t.ok(B.rooms.voice.sendSdp({ topic, address: ADDRESS, data: { type: 'answer', sdp: 'v=0' }, type: 'answer' }))
  await waitFor(() => A.of(E.VOICE_ANSWER).length === 1, 'answer at A')
  t.is(A.of(E.VOICE_ANSWER)[0].data.offer, false)

  A.rooms.voice.sendSdp({ topic, address: ADDRESS_2, data: 'expand', type: 'offer', retry: true })
  await waitFor(() => B.of(E.VOICE_RETRY).length === 1, 'retry at B')

  t.absent(A.rooms.voice.sendSdp({ topic, address: ADDRESS_3, data: 'x', type: 'offer' }), 'no such peer')

  // an SDP that claims another sender is not relayed to the UI
  const toA = B.room(invite).peerByAddress(ADDRESS)
  toA.send(wire.encode(wire.sdp({ data: 'other sender', offer: true, address: ADDRESS_3, topic })))
  B.rooms.voice.sendSdp({ topic, address: ADDRESS, data: 'barrier', type: 'offer' })
  await waitFor(() => A.of(E.VOICE_OFFER).length === 1, 'barrier offer at A')
  await sleep(50)
  t.alike(A.of(E.VOICE_OFFER).map((e) => e.data.data), ['barrier'])

  // leaving voice
  t.ok(await A.rooms.voice.leave())
  await waitFor(() => B.of(E.VOICE_STATUS).some((s) => s.address === ADDRESS && s.voice === false), 'voice off at B')
  t.is(A.rooms.voice.active, null)

  // a voice status with another address: banned (both apps)
  toA.send(
    wire.encode(
      wire.voiceStatus({ address: ADDRESS_3, topic, name: 'x', signature: 'x', voice: true, video: false, audioMute: false, videoMute: false, screenshare: false })
    )
  )
  await waitFor(() => A.room(invite).denied.size === 1, 'B banned at A')
  t.absent(A.rooms.isPeerIn(invite, ADDRESS_2))
})

test('admin ban disconnects the target; a ban from a non-admin is ignored', async (t) => {
  const { A, B, invite, topic } = await joinedPair(t)
  const C = makeRooms(t, { address: ADDRESS_3, name: 'carol' })
  await C.rooms.join({ invite })
  await connect(t, A, C, topic)
  await connect(t, B, C, topic)
  await waitFor(() => C.rooms.isPeerIn(invite, ADDRESS) && C.rooms.isPeerIn(invite, ADDRESS_2) && A.rooms.isPeerIn(invite, ADDRESS_3), 'three joined')

  // C is not the admin: A ignores its ban order
  C.room(invite).peerByAddress(ADDRESS).send(wire.encode(wire.ban(ADDRESS_2)))
  C.rooms.typing(invite, true)
  await waitFor(() => A.of(E.TYPING).length === 1, 'barrier')
  await sleep(50)
  t.ok(A.rooms.isPeerIn(invite, ADDRESS_2), 'B still connected at A')
  t.is(A.of(E.BAN_PEER).length, 0)

  // A is the admin
  t.ok(await A.rooms.ban(invite, ADDRESS_2))
  t.alike(A.of(E.BAN_PEER)[0], { key: invite, topic, address: ADDRESS_2, admin: true })
  await waitFor(() => !A.rooms.isPeerIn(invite, ADDRESS_2), 'B disconnected at A')
  // (B may already have left on its own after the broadcast; the address stays banned)
  t.ok(A.room(invite).bannedAddresses.has(ADDRESS_2), 'address banned at A')
  await waitFor(() => C.of(E.BAN_PEER).length === 1, 'C honours the admin ban')
  t.is(C.of(E.BAN_PEER)[0].address, ADDRESS_2)
  await waitFor(() => !C.rooms.isPeerIn(invite, ADDRESS_2), 'B disconnected at C')
  await waitFor(() => B.of(E.BAN_SELF).length === 1, 'B learns it was banned')
  t.alike(B.of(E.BAN_SELF)[0], { key: invite, topic })
  await waitFor(() => B.rooms.list().length === 0, 'B left the room')
  t.ok(A.rooms.isPeerIn(invite, ADDRESS_3), 'C stays')

  // a banned address that comes back is refused at joined
  A.host.banned.add(ADDRESS_3)
  const D = makeRooms(t, { address: ADDRESS_3, name: 'carol again' })
  await D.rooms.join({ invite })
  await connect(t, A, D, topic)
  await waitFor(() => A.of(E.BAN_PEER).length === 2, 'banned address refused')
  t.is(A.of(E.PEER_JOINED).filter((e) => e.peer.name === 'carol again').length, 0)
})

test('leave sends disconnected through the channel', async (t) => {
  const A = makeRooms(t, { address: ADDRESS, name: 'alice' })
  const { invite } = keys.createRoomInvite()
  const { topic } = await A.rooms.join({ invite })
  const raw = await rawPeer(t, A, topic)
  raw.send(raw.joined(ADDRESS_2))
  await waitFor(() => A.rooms.isPeerIn(invite, ADDRESS_2), 'raw peer joined')

  t.ok(await A.rooms.leave(invite))
  t.ok(raw.parsed().some((m) => m && m.type === 'disconnected'), 'disconnected received')
  t.alike(A.of(E.ROOM_LEFT)[0], { key: invite, topic, dm: false })
  t.is(A.of(E.PEER_LEFT).length, 1)
  t.alike(A.rooms.list(), [])
  t.ok(A.swarm(topic).destroyed)
  t.absent(await A.rooms.leave(invite), 'already left')

  // the other direction: a peer's `disconnected` closes it at once
  const B = makeRooms(t, { address: ADDRESS_2, name: 'bob' })
  const C = makeRooms(t, { address: ADDRESS_3, name: 'carol' })
  const r = await B.rooms.join({ invite })
  await C.rooms.join({ invite })
  await connect(t, B, C, r.topic)
  await waitFor(() => B.rooms.isPeerIn(invite, ADDRESS_3), 'C joined at B')
  await C.rooms.leave(invite)
  await waitFor(() => B.of(E.PEER_LEFT).length === 1, 'peer:left at B')
  t.is(B.of(E.PEER_LEFT)[0].address, ADDRESS_3)
})

// =============================================================================================
// DM swarms

test('DM swarm: maxPeers 1, DM payloads both ways, only the contact is admitted', async (t) => {
  const A = makeRooms(t, { address: ADDRESS, name: 'alice', dmJoinTimeoutMs: 300 })
  const B = makeRooms(t, { address: ADDRESS_2, name: 'bob' })
  const C = makeRooms(t, { address: ADDRESS_3, name: 'carol' })
  const da = await A.rooms.joinDm({ address: ADDRESS_2, derivationHash: DERIVATION })
  const db = await B.rooms.joinDm({ address: ADDRESS, derivationHash: DERIVATION })
  // C derives the same topic (for example the user's own other device) and claims a DM with A
  await C.rooms.joinDm({ address: ADDRESS, derivationHash: DERIVATION })
  const topic = da.topic
  t.is(db.topic, topic)
  t.alike(da, { key: ADDRESS_2, topic, dm: true, admin: false, address: ADDRESS_2 })
  t.is(A.swarm(topic).opts.maxPeers, 1, 'one slot')

  await connect(t, A, B, topic)
  await waitFor(() => A.rooms.isPeerIn(ADDRESS_2, ADDRESS_2) && B.rooms.isPeerIn(ADDRESS, ADDRESS), 'contacts joined')
  t.is(A.of(E.PEER_JOINED)[0].dm, true)
  t.is(A.rooms.joinedPeers({ dm: true }).length, 1)

  t.is(B.rooms.sendDm(ADDRESS, '0a1b2c3d'), 1)
  await waitFor(() => A.of(E.DM_WIRE).length === 1, 'dm at A')
  t.alike(A.of(E.DM_WIRE)[0], { address: ADDRESS_2, topic, wire: '0a1b2c3d' })
  t.is(A.rooms.sendDm(ADDRESS_2 + 'f'.repeat(64), 'ffee'), 1, 'a chat id that starts with the address works too')
  await waitFor(() => B.of(E.DM_WIRE).length === 1, 'dm at B')
  t.is(B.of(E.DM_WIRE)[0].wire, 'ffee')

  // JSON room messages are not taken in a DM swarm
  B.room(ADDRESS).peerByAddress(ADDRESS).send(wire.encode(roomMsg({ room: keys.createRoomInvite().invite, address: ADDRESS_2 })))
  B.rooms.typing(ADDRESS, true)
  await waitFor(() => A.of(E.TYPING).length === 1, 'typing in the DM')
  t.alike(A.of(E.TYPING)[0], { key: ADDRESS_2, topic, address: ADDRESS_2, typing: true, dm: true })
  t.is(A.of(E.ROOM_MESSAGE).length, 0)

  // a verified identity that is not the contact: closed and denied by the firewall
  await connect(t, A, C, topic)
  const room = A.room(ADDRESS_2)
  const cKey = hex(C.swarm(topic).keyPair.publicKey)
  await waitFor(() => room.denied.has(cKey), 'C denied')
  t.absent(A.rooms.isPeerIn(ADDRESS_2, ADDRESS_3))
  t.is(A.of(E.PEER_JOINED).length, 1, 'only the contact was admitted')
  t.is(await connect(t, A, C, topic), null, 'refused by the firewall from now on')

  // a connection that never sends joined: no DM payload is taken, closed after the timeout
  const raw = await rawPeer(t, A, topic)
  raw.send('deadbeef')
  await waitFor(() => !room.peers.has(hex(raw.kp.publicKey)), 'closed after the join timeout', 3000)
  t.is(A.of(E.DM_WIRE).length, 1)
  t.absent(room.denied.has(hex(raw.kp.publicKey)), 'a timeout is not a ban')
})

// =============================================================================================
// files and feed hand-off

function fakeFiles(driveKey) {
  const calls = []
  return {
    calls,
    openRoom: async (topic, o) => {
      calls.push(['openRoom', topic, o])
      return driveKey
    },
    replicate: (conn, topic) => {
      calls.push(['replicate', topic])
      return true
    },
    addPeer: async (topic, key, opts) => {
      calls.push(['addPeer', topic, key, opts])
      return true
    },
    setPeerOwners: (topic, key, owners) => {
      calls.push(['setPeerOwners', topic, key, owners])
      return true
    },
    handleRemote: async (topic, file, ctx) => {
      calls.push(['handleRemote', topic, file, ctx])
      return { action: 'remote', file }
    },
    share: async (topic, source, meta) => {
      calls.push(['share', topic, meta])
      return wire.fileShared({ fileName: meta.fileName, address: meta.address, name: meta.name, topic, size: source.byteLength, time: Date.now(), hash: randomKey(), contentHash: CONTENT_HASH, signature: 'sig' })
    },
    list: async () => [{ hash: 'e1'.repeat(32), contentHash: CONTENT_HASH, fileName: 'a.png', size: 3, time: Date.now(), address: ADDRESS, name: 'alice', syncedAt: 1 }],
    closeRoom: async (topic) => {
      calls.push(['closeRoom', topic])
      return true
    }
  }
}

test('files: replication on connect, joined.driveKey -> addPeer, file-shared -> handleRemote, a malformed driveKey is ignored', async (t) => {
  const fa = fakeFiles('aa'.repeat(32))
  const fb = fakeFiles('bb'.repeat(32))
  const { A, B, invite, topic } = await joinedPair(t, { files: fa }, { files: fb })
  t.alike(fa.calls[0], ['openRoom', topic, { key: invite, dm: false }])
  t.ok(fa.calls.some(([n, tp]) => n === 'replicate' && tp === topic))
  await waitFor(() => fa.calls.some(([n]) => n === 'addPeer'), 'addPeer at A')
  t.alike(fa.calls.find(([n]) => n === 'addPeer'), ['addPeer', topic, 'bb'.repeat(32), { owners: [ADDRESS_2] }], 'owned by the address that announced it')
  t.is(A.room(invite).peerByAddress(ADDRESS_2).driveKey, 'bb'.repeat(32))

  const remoteCalls = (hash) => fb.calls.filter(([n, , f]) => n === 'handleRemote' && f.hash === hash)
  const LISTED = 'e1'.repeat(32)

  // B joined later and asked A for history: send-history lists A's recent files
  await waitFor(() => remoteCalls(LISTED).length === 1, 'history file offered at B')
  const listed = remoteCalls(LISTED)[0]
  t.is(listed[1], topic)
  t.alike(listed[3], { driveKey: 'aa'.repeat(32), address: ADDRESS, name: 'alice' })
  t.absent('syncedAt' in listed[2], 'only the list fields go on the wire')

  const ann = wire.fileShared({ fileName: 'photo.png', address: ADDRESS, name: 'alice', topic, size: 10, time: Date.now(), hash: 'cd'.repeat(32), contentHash: CONTENT_HASH, signature: 'sig' })
  t.is(A.rooms.get(invite).send(wire.encode(ann)), 1)
  await waitFor(() => remoteCalls(ann.hash).length === 1, 'announcement handled at B')
  const [, tp, file, ctx] = remoteCalls(ann.hash)[0]
  t.is(tp, topic)
  t.is(file.address, ADDRESS)
  t.is(file.fileName, 'photo.png')
  t.alike(ctx, { driveKey: 'aa'.repeat(32), address: ADDRESS, name: 'alice' })

  // shareFile: stored through Files, announced to the room
  const shared = await A.rooms.shareFile(invite, b4a.from('abc'), { fileName: 'note.txt' })
  t.is(shared.sent, 1)
  t.alike(fa.calls.find(([n]) => n === 'share'), ['share', topic, { address: ADDRESS, name: 'alice', fileName: 'note.txt' }])
  await waitFor(() => remoteCalls(shared.announcement.hash).length === 1, 'shared file announced at B')
  await t.exception(B.rooms.shareFile('unknown', b4a.from('x')), /not in this room/)

  // a Ping lists A's recent files too (first Ping and every tenth)
  await B.room(invite).ping()
  await A.room(invite).ping()
  await waitFor(() => remoteCalls(LISTED).length === 2, 'Ping file offered')

  // joined with a malformed driveKey: admitted, the key ignored
  const raw = await rawPeer(t, A, topic)
  const joined = raw.joined(ADDRESS_3)
  joined.driveKey = 'not a drive key'
  raw.send(joined)
  await waitFor(() => A.rooms.isPeerIn(invite, ADDRESS_3), 'admitted')
  t.is(A.room(invite).peerByAddress(ADDRESS_3).driveKey, null)
  t.is(fa.calls.filter(([n]) => n === 'addPeer').length, 1)

  await A.rooms.leave(invite)
  t.ok(fa.calls.some(([n, tp2]) => n === 'closeRoom' && tp2 === topic))
})

test('feed traffic goes to the feed module (rooms only); a throwing feed does not break the room', async (t) => {
  const calls = []
  const feed = {
    handle: async (peer, msg) => calls.push(['handle', peer.address, msg.hash]),
    handleRequest: async (peer) => calls.push(['handleRequest', peer.address]),
    handleHistory: async (peer, msg) => calls.push(['handleHistory', peer.address, msg.messages.length]),
    onPeerJoined: (peer) => calls.push(['onPeerJoined', peer.address, peer.joined, peer.room.dm]),
    onPeerLeft: (peer) => {
      calls.push(['onPeerLeft', peer.address])
      throw new Error('feed error')
    }
  }
  const { A, B, invite } = await joinedPair(t, { feed })
  t.alike(calls[0], ['onPeerJoined', ADDRESS_2, true, false])

  const toA = B.room(invite).peerByAddress(ADDRESS)
  const fm = wire.feed({ message: 'post', nickname: 'bob', address: ADDRESS_2, hash: 'fe'.repeat(32), timestamp: Date.now(), signature: 'sig' })
  toA.send(wire.encode(fm))
  toA.send(wire.encode(wire.requestFeed()))
  toA.send(wire.encode(wire.sendFeedHistory([fm])))
  await waitFor(() => calls.length === 4, 'feed calls')
  t.alike(calls.slice(1), [
    ['handle', ADDRESS_2, 'fe'.repeat(32)],
    ['handleRequest', ADDRESS_2],
    ['handleHistory', ADDRESS_2, 1]
  ])
  t.alike(A.rooms.joinedPeers({ dm: false }).map((p) => p.address), [ADDRESS_2], 'the feed peers')

  await B.rooms.leave(invite)
  await waitFor(() => calls.some(([n]) => n === 'onPeerLeft'), 'onPeerLeft')
  t.is(A.rooms.list().length, 1, 'room still open')

  // DM swarms have no feed
  const dmCalls = calls.length
  await A.rooms.joinDm({ address: ADDRESS_2, derivationHash: DERIVATION })
  await B.rooms.joinDm({ address: ADDRESS, derivationHash: DERIVATION })
  await connect(t, A, B, A.room(ADDRESS_2).topic)
  await waitFor(() => A.rooms.isPeerIn(ADDRESS_2, ADDRESS_2), 'dm joined')
  B.room(ADDRESS).peerByAddress(ADDRESS).send(wire.encode(fm))
  await sleep(100)
  t.is(calls.length, dmCalls)
})

// =============================================================================================
// host hooks get validated values

test('host hooks only get well-formed hashes', async (t) => {
  const A = makeRooms(t, { address: ADDRESS, name: 'alice' })
  const { invite } = keys.createRoomInvite()
  const { topic } = await A.rooms.join({ invite })
  const raw = await rawPeer(t, A, topic)
  raw.send(raw.joined(ADDRESS_2))
  await waitFor(() => A.rooms.isPeerIn(invite, ADDRESS_2), 'joined')

  const bad = 'z'.repeat(64)
  const good = 'ab'.repeat(32)
  await A.room(invite).ping()
  raw.send({ type: 'Ping', peers: [], files: [], hashes: [bad, good, "' OR 1=1 --".padEnd(64, ' ')] })
  raw.send({ type: 'request-messages', hashes: [bad, good] })
  raw.send({ type: 'missing-messages', messages: [roomMsg({ room: invite, address: ADDRESS_2 }), { ...roomMsg({ room: invite, address: ADDRESS_2 }), hash: bad }] })
  await waitFor(() => A.host.calls.some(([n]) => n === 'getRoomMessage'), 'request handled')
  await sleep(100)
  const hashCalls = A.host.calls.filter(([n]) => n === 'roomMessageExists' || n === 'getRoomMessage')
  t.ok(hashCalls.length >= 2)
  t.ok(hashCalls.every(([, v]) => S.isHex64(v)), 'every hash handed to the host is 64 hex')
  t.ok(A.host.calls.filter(([n]) => n === 'getRoomHistory' || n === 'getLatestRoomHashes').every(([, k]) => k === invite))
  t.ok(raw.parsed().some((m) => m && m.type === 'request-messages' && m.hashes.length === 1 && m.hashes[0] === good), 'only the good hash is requested')
})

// =============================================================================================
// lifecycle

test('suspend / resume and idle', async (t) => {
  const { A, B, invite, topic } = await joinedPair(t, { idleSuspendMs: 50 })
  await A.rooms.suspend()
  t.ok(A.rooms.suspended)
  t.ok(A.swarm(topic).suspended)
  t.is(A.room(invite).peers.size, 0, 'connections closed')
  t.is(A.of(E.PEER_LEFT).length, 1)
  await waitFor(() => !B.rooms.isPeerIn(invite, ADDRESS), 'B sees A go')
  t.is(await connect(t, A, B, topic).then((c) => c && sleep(50)).then(() => A.room(invite).peers.size), 0, 'no connections while suspended')

  const refreshes = A.swarm(topic).refreshes
  await A.rooms.resume()
  t.absent(A.swarm(topic).suspended)
  t.ok(A.swarm(topic).refreshes > refreshes, 'discovery refreshed')
  await connect(t, A, B, topic)
  await waitFor(() => A.rooms.isPeerIn(invite, ADDRESS_2) && B.rooms.isPeerIn(invite, ADDRESS), 'joined again')

  // background: suspended after idleSuspendMs; foreground: resumed
  await A.rooms.idle({ background: true })
  t.ok(A.rooms.idleState)
  await waitFor(() => A.rooms.suspended, 'suspended in the background')
  await A.rooms.idle({ background: false })
  t.absent(A.rooms.suspended)
  t.absent(A.rooms.idleState)

  await A.rooms.idle({ force: true })
  t.ok(A.rooms.suspended)
  await A.rooms.resume()
  t.absent(A.rooms.suspended)
})

// =============================================================================================
// on a DHT testnet

test('testnet: two peers in a room, joined and messages both ways', { timeout: 120000 }, async (t) => {
  const testnet = await createTestnet(3, t.teardown)
  const { invite, adminSeed } = keys.createRoomInvite()

  const make = (address, name) => {
    const host = makeHost(address, name)
    const rooms = new Rooms({ host, bootstrap: testnet.bootstrap, pingIntervalMs: 0, leaveFlushMs: 50 })
    const events = []
    for (const n of E.ALL) rooms.on(n, (payload) => events.push([n, payload]))
    t.teardown(() => rooms.destroy())
    return { rooms, host, events, of: (n) => events.filter(([e]) => e === n).map(([, p]) => p) }
  }
  const A = make(ADDRESS, 'alice')
  const B = make(ADDRESS_2, 'bob')

  const ra = await A.rooms.join({ invite, adminSeed })
  const rb = await B.rooms.join({ invite })
  t.is(ra.topic, rb.topic)
  await A.rooms.get(invite).flushed()
  await B.rooms.get(invite).flushed()

  // the server side emits 'connection' a little after the client side: wait on state
  await waitFor(() => A.rooms.isPeerIn(invite, ADDRESS_2) && B.rooms.isPeerIn(invite, ADDRESS), 'joined over the DHT', 90000)
  t.is(B.rooms.get(invite).peerByAddress(ADDRESS).admin, true, 'admin flag over a real connection')

  await A.rooms.send(invite, { message: 'hello over the DHT' })
  await B.rooms.send(invite, { message: 'hello back' })
  await waitFor(() => A.of(E.ROOM_MESSAGE).length === 1 && B.of(E.ROOM_MESSAGE).length === 1, 'messages both ways', 30000)
  t.is(B.of(E.ROOM_MESSAGE)[0].message.message, 'hello over the DHT')
  t.is(A.of(E.ROOM_MESSAGE)[0].message.message, 'hello back')

  await B.rooms.leave(invite)
  await waitFor(() => A.of(E.PEER_LEFT).length === 1, 'peer:left at A', 30000)
})
