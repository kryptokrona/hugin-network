'use strict'

// Limits and ordering in the room and feed layer (lib/room.js, lib/rooms.js, lib/peer.js,
// lib/voice.js, lib/feed.js, lib/files.js): per-peer limits, ordering of one peer's frames,
// per-address peer events, bounded close, and other 3.0 behaviour. Same setup
// as test/rooms.test.js: Rooms instances with an in-memory host on fake swarms whose connections
// are real NoiseSecretStream pairs, plus hand-driven raw peers. One test uses real Files on a
// temporary directory.

const test = require('brittle')
const b4a = require('b4a')
const tmp = require('test-tmp')
const EventEmitter = require('bare-events')
const NoiseSecretStream = require('@hyperswarm/secret-stream')
const { Rooms, RoomsError } = require('../lib/rooms.js')
const { Feed } = require('../lib/feed.js')
const { Files } = require('../lib/files.js')
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
    sign: async (message) => {
      host.calls.push(['sign', message])
      return fakeSign(address, message)
    },
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

/** Hyperswarm stand-in: connections are handed to it by `connect`; dials are recorded. */
class FakeSwarm extends EventEmitter {
  constructor(opts) {
    super()
    this.opts = opts
    this.keyPair = keyPairFromSeed(randomBytes(32))
    this.firewall = opts.firewall || (() => false)
    this.topicHex = keys.topicFromSwarmKey(opts.key).topic
    this.dialed = []
    this.left = []
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

  leavePeer(publicKey) {
    this.left.push(hex(publicKey))
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
    historyPickMs: 0, // history from the first earlier peer at once (a test below covers the pick)
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
  rooms.on(E.ROOM_MESSAGE, ({ message }) => host.messages.set(message.hash, message))
  t.teardown(() => rooms.destroy())
  return {
    rooms,
    host,
    swarms,
    events,
    address,
    swarm: (topic) => swarms.filter((s) => s.topicHex === topic).pop(),
    of: (n, filter = () => true) => events.filter(([e, p]) => e === n && filter(p)).map(([, p]) => p),
    room: (key) => rooms.get(key)
  }
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

/** Connects A's and B's swarms of `topic`. */
async function connect(t, A, B, topic) {
  const sa = A.swarm(topic)
  const sb = B.swarm(topic)
  const [a, b] = await streams(t, sa.keyPair, sb.keyPair)
  if (sa.firewall(b.publicKey, null) || sb.firewall(a.publicKey, null)) {
    a.destroy()
    b.destroy()
    return null
  }
  sa.emit('connection', a, peerInfo())
  sb.emit('connection', b, peerInfo())
  return { a, b }
}

/**
 * A hand-driven peer on A's swarm of `topic`: a raw `hugin/3/messages` channel with its own (or
 * the given) DHT key pair. `joined(address)` builds a joined whose idSig verifies for that address.
 */
async function rawPeer(t, A, topic, kp = keyPairFromSeed(randomBytes(32))) {
  const sa = A.swarm(topic)
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
    key: hex(kp.publicKey),
    conn: b,
    info,
    received,
    parsed: () =>
      received.map((s) => {
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
  await sleep(5)
  await B.rooms.join({ invite })
  await connect(t, A, B, ra.topic)
  await waitFor(() => A.rooms.isPeerIn(invite, ADDRESS_2) && B.rooms.isPeerIn(invite, ADDRESS), 'joined both ways')
  return { A, B, invite, topic: ra.topic }
}

/** A room of A with one raw peer that joined as `address`. */
async function roomWithRaw(t, opts = {}, address = ADDRESS_2, joinedExtra = {}) {
  const A = makeRooms(t, { address: ADDRESS, name: 'alice', ...opts })
  const { invite } = keys.createRoomInvite()
  const { topic } = await A.rooms.join({ invite })
  const raw = await rawPeer(t, A, topic)
  raw.send(raw.joined(address, joinedExtra))
  await waitFor(() => A.rooms.isPeerIn(invite, address), 'raw peer joined')
  return { A, invite, topic, raw }
}

function fakeFiles(driveKey) {
  const calls = []
  return {
    calls,
    openRoom: async (topic, o) => {
      calls.push(['openRoom', topic, o])
      return driveKey
    },
    replicate: () => true,
    addPeer: async (topic, key) => {
      calls.push(['addPeer', topic, key])
      return true
    },
    removePeer: (topic, key) => {
      calls.push(['removePeer', topic, key])
      return true
    },
    handleRemote: async (topic, file, ctx) => {
      calls.push(['handleRemote', topic, file, ctx])
      return { action: 'remote', file }
    },
    list: async () => [],
    closeRoom: async (topic) => {
      calls.push(['closeRoom', topic])
      return true
    }
  }
}

// =============================================================================================
// identity that does not fit the builders

test('identity: a display name over 50 characters is cut on a code point boundary and the room still joins', async (t) => {
  const long = 'e'.repeat(29) + '\u{1F600}'.repeat(20) // 29 + 40 UTF-16 units
  const { A, B, invite, topic } = await joinedPair(t, { name: long })
  const atB = B.room(invite).peerByAddress(ADDRESS)
  t.is(atB.name, 'e'.repeat(29) + '\u{1F600}'.repeat(10), 'cut to 49 units, no half surrogate pair')
  t.ok(B.room(invite).peerByAddress(ADDRESS).joined)

  const msg = await A.rooms.send(invite, { message: 'hi' })
  t.is(msg.name, atB.name, 'room messages build')
  t.ok(await A.rooms.voice.setStatus(invite, { voice: true }), 'voice status builds')
  await waitFor(() => B.of(E.VOICE_STATUS).length === 1, 'status at B')
  t.ok(A.rooms.voice.local(topic).voice)

  A.rooms.setIdentity({ name: 'x'.repeat(200), avatar: 'not base64 !!' })
  t.alike(A.rooms.identity(), { address: ADDRESS, name: 'x'.repeat(50), avatar: '' })
  // a later connection gets a joined with the normalised identity
  const raw = await rawPeer(t, A, topic)
  await waitFor(() => raw.parsed().some((m) => m && m.joined === true), 'joined at the raw peer')
  const j = raw.parsed().find((m) => m && m.joined === true)
  t.is(j.name, 'x'.repeat(50))
  t.ok(S.joined(j).ok)
})

// =============================================================================================
// dialing the keys a Ping lists

test('Ping dials: a Ping listing 100 keys dials at most the cap; every dial ends with leavePeer', async (t) => {
  const { A, invite, topic, raw } = await roomWithRaw(t, { dialTimeoutMs: 150, maxPendingDials: 50 })
  const swarm = A.swarm(topic)
  const own = hex(swarm.keyPair.publicKey)
  await A.room(invite).ping() // A acts on Pings now
  const listed = [raw.key, own, ...Array.from({ length: 98 }, () => randomKey())]
  raw.send(wire.ping({ peers: listed, hashes: [] }))
  await waitFor(() => swarm.dialed.length > 0, 'dials')
  await sleep(30)
  t.is(swarm.dialed.length, A.rooms.options.dialMaxPerPing, 'at most dialMaxPerPing from one Ping')
  t.absent(swarm.dialed.includes(raw.key), 'a connected key is not dialed')
  t.absent(swarm.dialed.includes(own), 'our own key is not dialed')

  // the same peer again within the minute: its dial budget is used up
  await A.room(invite).ping()
  raw.send(wire.ping({ peers: Array.from({ length: 50 }, () => randomKey()), hashes: [] }))
  await sleep(50)
  t.is(swarm.dialed.length, A.rooms.options.dialMaxPerPeerPerMinute, 'per-peer dial budget')

  await waitFor(() => swarm.left.length === swarm.dialed.length, 'leavePeer after the dial timeout', 3000)
  t.alike(swarm.left.slice().sort(), swarm.dialed.slice().sort(), 'every dialed key is left again')
  t.is(A.room(invite)._dials.size, 0, 'nothing pending')
})

test('Ping dials: dials in progress are capped, and a connection from a dialed key ends its dial', async (t) => {
  const { A, invite, topic, raw } = await roomWithRaw(t, { dialTimeoutMs: 60000 })
  const swarm = A.swarm(topic)
  const target = keyPairFromSeed(randomBytes(32))
  await A.room(invite).ping()
  raw.send(wire.ping({ peers: [hex(target.publicKey), randomKey(), randomKey(), randomKey(), randomKey()], hashes: [] }))
  await waitFor(() => swarm.dialed.length > 0, 'dials')
  await sleep(30)
  t.is(swarm.dialed.length, A.rooms.options.maxPendingDials, 'at most maxPendingDials at a time')
  t.is(swarm.dialed[0], hex(target.publicKey))

  await rawPeer(t, A, topic, target)
  await waitFor(() => swarm.left.includes(hex(target.publicKey)), 'leavePeer once connected')
  t.is(A.room(invite)._dials.size, A.rooms.options.maxPendingDials - 1)

  await A.rooms.leave(invite)
  t.is(swarm.left.length, A.rooms.options.maxPendingDials, 'leaving ends every dial')
})

// =============================================================================================
// one peer's frames in order

test('frame order: a message followed by disconnected (and the stream closing) is still delivered, before peer:left', async (t) => {
  const { A, invite, raw } = await roomWithRaw(t, {
    host: {
      isBlocked: async () => {
        await sleep(100) // a slow host hook
        return false
      }
    }
  })
  const msg = roomMsg({ room: invite, message: 'last words' })
  raw.send(msg)
  raw.send(wire.disconnected())
  await sleep(20)
  raw.conn.destroy()
  await waitFor(() => A.of(E.PEER_LEFT).length === 1, 'peer:left')
  t.alike(A.of(E.ROOM_MESSAGE).map((e) => e.message.message), ['last words'])
  const order = A.events.map(([n]) => n).filter((n) => n === E.ROOM_MESSAGE || n === E.PEER_LEFT)
  t.alike(order, [E.ROOM_MESSAGE, E.PEER_LEFT], 'the message first, then peer:left')
})

test('frame order: a peer with too many frames waiting is closed', async (t) => {
  const { A, invite, raw } = await roomWithRaw(t, {
    maxQueuedFrames: 10,
    host: {
      isBlocked: async () => {
        await sleep(200)
        return false
      }
    }
  })
  const peer = A.room(invite).peerByAddress(ADDRESS_2)
  for (let i = 0; i < 40; i++) raw.send(roomMsg({ room: invite, message: 'frame ' + i }))
  await waitFor(() => peer.closed, 'peer with a full queue closed')
  t.is(peer.closeReason, 'queue_full')
  await sleep(300)
  t.ok(A.of(E.ROOM_MESSAGE).length < 40, 'the queued frames of that peer are dropped')
})

// =============================================================================================
// before and around joined

test('joined: frames behind a slow joined check are capped', async (t) => {
  const A = makeRooms(t, {
    address: ADDRESS,
    name: 'alice',
    maxPreJoinFrames: 5,
    host: {
      verify: async (message, addr, signature) => {
        await sleep(200)
        return signature === fakeSign(addr, message)
      }
    }
  })
  const { invite } = keys.createRoomInvite()
  const { topic } = await A.rooms.join({ invite })
  const raw = await rawPeer(t, A, topic)
  raw.send(raw.joined(ADDRESS_2))
  for (let i = 0; i < 30; i++) raw.send(wire.typing(i % 2 === 0))
  await waitFor(() => A.of(E.PEER_JOINED).length === 1, 'admitted')
  await sleep(100)
  t.is(A.of(E.TYPING).length, 5, 'only maxPreJoinFrames waited for the check')
  t.ok(A.rooms.isPeerIn(invite, ADDRESS_2), 'not closed for it')
})

test('joined: a room connection that never joins is closed after roomJoinTimeoutMs (not banned)', async (t) => {
  const A = makeRooms(t, { address: ADDRESS, name: 'alice', roomJoinTimeoutMs: 200 })
  const { invite } = keys.createRoomInvite()
  const { topic } = await A.rooms.join({ invite })
  const raw = await rawPeer(t, A, topic)
  const room = A.room(invite)
  t.is(room.peers.size, 1)
  await waitFor(() => room.peers.size === 0, 'closed after the join timeout', 3000)
  t.absent(room.denied.has(raw.key), 'a timeout is not a ban')
})

test('joined: DM payloads behind a joined check slower than joinWaitMs wait for it (bounded by the join timeout)', async (t) => {
  const A = makeRooms(t, {
    address: ADDRESS,
    name: 'alice',
    joinWaitMs: 50,
    dmJoinTimeoutMs: 5000,
    host: {
      verify: async (message, addr, signature) => {
        await sleep(300)
        return signature === fakeSign(addr, message)
      }
    }
  })
  const { topic } = await A.rooms.joinDm({ address: ADDRESS_2, derivationHash: DERIVATION })
  const raw = await rawPeer(t, A, topic)
  raw.send(raw.joined(ADDRESS_2))
  raw.send('0a0b')
  raw.send('0c0d')
  await waitFor(() => A.of(E.DM_WIRE).length === 2, 'both DM payloads')
  t.alike(A.of(E.DM_WIRE).map((e) => e.wire), ['0a0b', '0c0d'], 'in order')
})

// =============================================================================================
// history and sync answers

test('history: request-history is answered once per connection', async (t) => {
  const { A, invite, raw } = await roomWithRaw(t)
  const m = roomMsg({ room: invite, address: ADDRESS, name: 'alice' })
  A.host.messages.set(m.hash, m)
  raw.send(wire.requestHistory([]))
  raw.send(wire.requestHistory([]))
  raw.send(wire.requestHistory([]))
  await waitFor(() => raw.parsed().some((x) => x && x.type === 'send-history'), 'history answer')
  await sleep(100)
  const answers = raw.parsed().filter((x) => x && x.type === 'send-history')
  t.is(answers.length, 1)
  t.is(answers[0].messages.length, 1)
  t.alike(Object.keys(answers[0].messages[0]).sort(), ['address', 'hash', 'message', 'name', 'reply', 'room', 'signature', 'timestamp', 'tip'], 'rebuilt rows only')
})

test('history: request-messages is rate-limited per connection; rows of other rooms are not sent', async (t) => {
  const { A, invite, raw } = await roomWithRaw(t, { requestMessagesPerMinute: 2 })
  const mine = roomMsg({ room: invite, address: ADDRESS, name: 'alice' })
  const other = roomMsg({ room: keys.createRoomInvite().invite, address: ADDRESS, name: 'alice' })
  A.host.messages.set(mine.hash, { ...mine, extra: 'db column' })
  A.host.messages.set(other.hash, other)
  for (let i = 0; i < 4; i++) raw.send(wire.requestMessages([mine.hash, other.hash]))
  await waitFor(() => raw.parsed().filter((x) => x && x.type === 'missing-messages').length === 2, 'answers')
  await sleep(100)
  const answers = raw.parsed().filter((x) => x && x.type === 'missing-messages')
  t.is(answers.length, 2, 'two per minute')
  t.alike(answers[0].messages.map((m) => m.hash), [mine.hash], 'only this room')
  t.absent('extra' in answers[0].messages[0], 'no host columns on the wire')
})

test('history: unsolicited missing-messages and send-history are ignored; only requested hashes are taken', async (t) => {
  const files = fakeFiles('aa'.repeat(32))
  const { A, invite, topic, raw } = await roomWithRaw(t, { files }, ADDRESS_2, { driveKey: 'bb'.repeat(32) })
  const listed = { fileName: 'a.png', hash: 'e1'.repeat(32), contentHash: CONTENT_HASH, size: 3, time: Date.now() }

  raw.send(wire.missingMessages([roomMsg({ room: invite, message: 'nobody asked' })]))
  raw.send(wire.sendHistory({ messages: [], files: [listed] }))
  raw.send(wire.typing(true)) // barrier
  await waitFor(() => A.of(E.TYPING).length === 1, 'barrier')
  await sleep(50)
  t.is(A.of(E.ROOM_MESSAGE).length, 0, 'unsolicited missing-messages ignored')
  t.is(files.calls.filter(([n]) => n === 'handleRemote').length, 0, 'unsolicited send-history ignored')

  // a Ping with a hash A does not have: A asks for exactly that hash
  const wanted = roomMsg({ room: invite, message: 'asked for' })
  const extra = roomMsg({ room: invite, message: 'smuggled' })
  await A.room(invite).ping()
  raw.send(wire.ping({ hashes: [wanted.hash] }))
  await waitFor(() => raw.parsed().some((x) => x && x.type === 'request-messages'), 'request-messages')
  t.alike(raw.parsed().find((x) => x && x.type === 'request-messages').hashes, [wanted.hash])
  raw.send(wire.missingMessages([extra, wanted]))
  await waitFor(() => A.of(E.ROOM_HISTORY).length === 1, 'history batch')
  t.alike(A.of(E.ROOM_MESSAGE).map((e) => e.message.message), ['asked for'])
  // the same answer again: nothing is requested any more
  raw.send(wire.missingMessages([wanted]))
  raw.send(wire.typing(false))
  await waitFor(() => A.of(E.TYPING).length === 2, 'barrier')
  await sleep(50)
  t.is(A.of(E.ROOM_MESSAGE).length, 1)

  // a peer that was there before A: A asks it for history and takes one answer
  const early = await rawPeer(t, A, topic)
  early.send(early.joined(ADDRESS_3, { time: A.room(invite).time - 1000, driveKey: 'cc'.repeat(32) }))
  await waitFor(() => early.parsed().some((x) => x && x.type === 'request-history'), 'request-history')
  early.send(wire.sendHistory({ messages: [], files: [listed] }))
  early.send(wire.sendHistory({ messages: [], files: [{ ...listed, hash: 'e2'.repeat(32) }] }))
  await waitFor(() => files.calls.some(([n]) => n === 'handleRemote'), 'files offered')
  await sleep(100)
  const offered = files.calls.filter(([n]) => n === 'handleRemote').map(([, , f]) => f.hash)
  t.alike(offered, [listed.hash], 'only the first answer is taken')
})

test('hash: live messages and history entries need a 64-hex hash', async (t) => {
  const { A, invite, raw } = await roomWithRaw(t, {}, ADDRESS_2)
  raw.send({ ...roomMsg({ room: invite, message: 'not hex' }), hash: 'z'.repeat(64) })
  raw.send({ ...roomMsg({ room: invite, message: '128 hex' }), hash: 'ab'.repeat(64) })
  const upper = roomMsg({ room: invite, message: 'upper-case hex' })
  raw.send({ ...upper, hash: upper.hash.toUpperCase() })
  raw.send(roomMsg({ room: invite, message: 'barrier' }))
  await waitFor(() => A.of(E.ROOM_MESSAGE).some((e) => e.message.message === 'barrier'), 'barrier')
  await sleep(50)
  t.alike(A.of(E.ROOM_MESSAGE).map((e) => e.message.message), ['upper-case hex', 'barrier'])
  t.ok(A.rooms.isPeerIn(invite, ADDRESS_2), 'dropped, not banned')

  // joined.messages: the entry with a bad hash is skipped
  const B = makeRooms(t, { address: ADDRESS, name: 'alice' })
  const r = await B.rooms.join({ invite })
  const raw2 = await rawPeer(t, B, r.topic)
  const valid = roomMsg({ room: invite, address: ADDRESS_3, name: 'carol', message: 'valid' })
  raw2.send(raw2.joined(ADDRESS_2, { messages: [valid, { ...valid, hash: 'q'.repeat(64), message: 'bad hash' }] }))
  await waitFor(() => B.of(E.ROOM_HISTORY).length === 1, 'history batch')
  t.alike(B.of(E.ROOM_MESSAGE).map((e) => e.message.message), ['valid'])
})

test('Ping: every Ping carries the latest hashes, also past the fifth connection', async (t) => {
  const A = makeRooms(t, { address: ADDRESS, name: 'alice' })
  const { invite } = keys.createRoomInvite()
  const { topic } = await A.rooms.join({ invite })
  const m = roomMsg({ room: invite, address: ADDRESS, name: 'alice' })
  A.host.messages.set(m.hash, m)
  const raws = []
  for (let i = 0; i < 7; i++) {
    const raw = await rawPeer(t, A, topic)
    raw.send(raw.joined(ADDRESS_2))
    raws.push(raw)
  }
  await waitFor(() => A.room(invite).joinedPeers().length === 7, 'seven connections')
  t.is(A.of(E.PEER_JOINED).length, 1, 'one address: one peer:joined')
  t.is(await A.room(invite).ping(), 7)
  for (let round = 0; round < 2; round++) {
    await waitFor(() => raws.every((r) => r.parsed().filter((x) => x && x.type === 'Ping').length > round), 'pings')
    if (round === 0) await A.room(invite).ping()
  }
  await waitFor(() => raws.every((r) => r.parsed().filter((x) => x && x.type === 'Ping').length === 2), 'second ping')
  for (const r of raws) {
    for (const p of r.parsed().filter((x) => x && x.type === 'Ping')) t.alike(p.hashes, [m.hash])
  }
  t.is(A.host.calls.filter(([n, msg]) => n === 'sign' && msg === keys.idSigMessage(A.swarm(topic).keyPair.publicKey, topic)).length, 1, 'idSig signed once for the swarm')
})

// =============================================================================================
// room message signatures (hugin-network 3.0)

/** Counts host.verify calls for room message payloads (and the most running at once). */
function countingVerify(delayMs = 0) {
  const stats = { calls: 0, running: 0, max: 0 }
  const verify = async (message, addr, signature) => {
    const room = typeof message === 'string' && message.startsWith(wire.ROOM_MESSAGE_DOMAIN)
    if (room) {
      stats.calls++
      stats.running++
      stats.max = Math.max(stats.max, stats.running)
    }
    try {
      if (delayMs) await sleep(delayMs)
      return signature === fakeSign(addr, message)
    } finally {
      if (room) stats.running--
    }
  }
  return { stats, verify }
}

test('signatures: a live room message that does not verify bans its sender and is not emitted', async (t) => {
  const { A, invite, raw } = await roomWithRaw(t)
  raw.send(roomMsg({ room: invite, message: 'signed' }))
  await waitFor(() => A.of(E.ROOM_MESSAGE).length === 1, 'signed message')
  t.is(A.of(E.ROOM_MESSAGE)[0].message.signature, fakeSign(ADDRESS_2, wire.roomMessageSigningPayload(A.of(E.ROOM_MESSAGE)[0].message)), 'emitted with its signature')

  // unsigned, or a signature of the wrong format: dropped by the validator, not banned
  raw.send({ ...roomMsg({ room: invite, message: 'unsigned' }), signature: '' })
  raw.send({ ...roomMsg({ room: invite, message: 'old native' }), signature: 'sig' })
  // signed, but too far in the future: dropped, not banned (clocks differ)
  raw.send(roomMsg({ room: invite, message: 'from the future', timestamp: Date.now() + 60 * 60 * 1000 }))
  raw.send(roomMsg({ room: invite, message: 'barrier' }))
  await waitFor(() => A.of(E.ROOM_MESSAGE).length === 2, 'barrier')
  await sleep(50)
  t.ok(A.rooms.isPeerIn(invite, ADDRESS_2), 'not banned for those')

  // a well-formed signature by another key: banned, not emitted, nothing stored
  const otherSigner = roomMsg({ room: invite, message: 'other signer' }, { signer: ADDRESS_3 })
  raw.send(otherSigner)
  await waitFor(() => A.room(invite).denied.has(raw.key), 'sender banned')
  t.ok(raw.info.banned, 'hyperswarm peer banned')
  t.alike(A.of(E.ROOM_MESSAGE).map((e) => e.message.message), ['signed', 'barrier'])
  t.absent(A.host.messages.has(otherSigner.hash), 'not stored')
})

test('signatures: a changed message text or timestamp fails verification (live: banned)', async (t) => {
  const A = makeRooms(t, { address: ADDRESS, name: 'alice' })
  const { invite } = keys.createRoomInvite()
  const { topic } = await A.rooms.join({ invite })
  const changedFields = [
    ['message text', (m) => ({ ...m, message: m.message + '!' })],
    ['timestamp', (m) => ({ ...m, timestamp: m.timestamp - 1 })]
  ]
  for (const [what, change] of changedFields) {
    const raw = await rawPeer(t, A, topic)
    raw.send(raw.joined(ADDRESS_2))
    await waitFor(() => A.room(invite).joinedPeers().some((p) => p.remotePublicKey === raw.key), 'raw joined')
    raw.send(change(roomMsg({ room: invite, message: 'original' })))
    await waitFor(() => A.room(invite).denied.has(raw.key), what + ': sender banned')
    t.pass(what + ': banned')
  }
  t.is(A.of(E.ROOM_MESSAGE).length, 0, 'none emitted')

  // every signed field is bound (checked without a connection)
  const m = roomMsg({ room: invite, address: ADDRESS_2, reply: 'ab'.repeat(32), tip: { amount: 5, receiver: ADDRESS_3 } })
  const value = S.roomMessage(m, { hexHash: true }).value
  t.is(await A.rooms._verifyRoomMessage(value), 'ok', 'the original verifies')
  t.is(await A.rooms._verifyRoomMessage({ ...value, hash: value.hash.toUpperCase() }), 'ok', 'the case of the hash does not matter')
  const other = keys.createRoomInvite().invite
  const changes = {
    room: { room: other },
    hash: { hash: randomKey() },
    timestamp: { timestamp: value.timestamp + 1 },
    address: { address: ADDRESS_3 },
    name: { name: 'carol' },
    message: { message: 'changed' },
    reply: { reply: '' },
    'tip amount': { tip: { amount: 6, receiver: ADDRESS_3 } },
    'tip receiver': { tip: { amount: 5, receiver: ADDRESS } },
    'tip removed': { tip: false }
  }
  for (const [field, patch] of Object.entries(changes)) {
    t.is(await A.rooms._verifyRoomMessage({ ...value, ...patch }), 'bad', field + ' is signed')
  }
  t.is(await A.rooms._verifyRoomMessage({ ...value, timestamp: 1.5 }), 'invalid', 'a value no valid message has')
})

test('signatures: history entries that do not verify are dropped; more than maxBadHistory bans the relayer', async (t) => {
  const A = makeRooms(t, { address: ADDRESS, name: 'alice' })
  const { invite } = keys.createRoomInvite()
  const { topic } = await A.rooms.join({ invite })

  // joined.messages: two valid entries (one by a third author) and one signed by the relayer for carol
  const raw = await rawPeer(t, A, topic)
  const valid = roomMsg({ room: invite, address: ADDRESS_3, name: 'carol', message: 'by carol' })
  const own = roomMsg({ room: invite, address: ADDRESS_2, message: 'by the relayer' })
  const wrongSigner = roomMsg({ room: invite, address: ADDRESS_3, name: 'carol', message: 'wrong signer' }, { signer: ADDRESS_2 })
  raw.send(raw.joined(ADDRESS_2, { messages: [valid, wrongSigner, own] }))
  await waitFor(() => A.of(E.ROOM_HISTORY).length === 1, 'history batch')
  t.alike(A.of(E.ROOM_MESSAGE).map((e) => e.message.message).sort(), ['by carol', 'by the relayer'])
  t.is(A.of(E.ROOM_HISTORY)[0].count, 2)
  t.absent(A.host.messages.has(wrongSigner.hash))
  t.ok(A.rooms.isPeerIn(invite, ADDRESS_2), 'one bad entry: not banned')
  t.is(A.room(invite).peerByAddress(ADDRESS_2)._badHistory, 1)

  // missing-messages: a requested hash answered with an entry that does not verify is dropped and counted
  const wanted = roomMsg({ room: invite, address: ADDRESS_3, name: 'carol', message: 'asked for' })
  const fake = { ...wanted, message: 'changed answer' }
  await A.room(invite).ping()
  raw.send(wire.ping({ hashes: [wanted.hash] }))
  await waitFor(() => raw.parsed().some((x) => x && x.type === 'request-messages'), 'request-messages')
  raw.send(wire.missingMessages([fake]))
  await waitFor(() => A.of(E.ROOM_HISTORY).length === 2, 'second batch')
  t.is(A.of(E.ROOM_HISTORY)[1].count, 0)
  t.absent(A.of(E.ROOM_MESSAGE).some((e) => e.message.hash === wanted.hash), 'not emitted')
  t.is(A.room(invite).peerByAddress(ADDRESS_2)._badHistory, 2)
  t.ok(A.rooms.isPeerIn(invite, ADDRESS_2))

  // a relayer with more than maxBadHistory (3) entries that do not verify in its joined is banned
  const relayer = await rawPeer(t, A, topic)
  const badEntries = Array.from({ length: 4 }, (_, i) => roomMsg({ room: invite, address: ADDRESS_3, name: 'carol', message: 'unverified ' + i }, { signer: ADDRESS_2 }))
  relayer.send(relayer.joined(ADDRESS_2, { messages: [...badEntries, roomMsg({ room: invite, address: ADDRESS_3, name: 'carol', message: 'verified' })] }))
  await waitFor(() => A.room(invite).denied.has(relayer.key), 'relayer banned')
  t.ok(A.of(E.ROOM_MESSAGE).some((e) => e.message.message === 'verified'), 'its verified entry is still taken')
  t.absent(A.of(E.ROOM_MESSAGE).some((e) => e.message.message.startsWith('unverified ')))
})

test('signatures: a stored message is not verified again; a history batch is verified verifyConcurrency at a time, emitted in order', async (t) => {
  const { stats, verify } = countingVerify(20)
  const { A, invite, topic, raw } = await roomWithRaw(t, { verifyConcurrency: 3, host: { verify } })

  const stored = roomMsg({ room: invite, message: 'stored already' })
  A.host.messages.set(stored.hash, stored)
  raw.send(stored)
  raw.send(roomMsg({ room: invite, message: 'barrier' }))
  await waitFor(() => A.of(E.ROOM_MESSAGE).length === 1, 'barrier')
  t.is(A.of(E.ROOM_MESSAGE)[0].message.message, 'barrier', 'the stored one is not emitted again')
  t.is(stats.calls, 1, 'only the new one was verified')

  const list = Array.from({ length: 12 }, (_, i) => roomMsg({ room: invite, address: ADDRESS_3, name: 'carol', message: 'h' + i, timestamp: Date.now() - 1000 + i }))
  const late = await rawPeer(t, A, topic)
  // joined.messages is newest first in both apps; the batch is emitted oldest first
  late.send(late.joined(ADDRESS_2, { messages: list.slice().reverse() }))
  await waitFor(() => A.of(E.ROOM_HISTORY).length === 1, 'history batch')
  t.alike(A.of(E.ROOM_MESSAGE, (e) => e.history).map((e) => e.message.message), list.map((m) => m.message), 'in order')
  t.is(stats.calls, 13)
  t.ok(stats.max <= 3, 'at most verifyConcurrency checks at once (' + stats.max + ')')
  t.ok(stats.max > 1, 'checks do run in parallel')
})

test('signatures: send signs through host.sign; a signing failure rejects and sends nothing', async (t) => {
  const { A, invite, raw } = await roomWithRaw(t)
  const msg = await A.rooms.send(invite, { message: 'signed', reply: 'cd'.repeat(32), tip: { amount: 1, receiver: ADDRESS_2 } })
  t.ok(S.isRoomSignature(msg.signature))
  t.is(msg.signature, fakeSign(ADDRESS, wire.roomMessageSigningPayload(msg)))
  t.ok(A.host.calls.some(([n, m]) => n === 'sign' && m === wire.roomMessageSigningPayload(msg)), 'host.sign got the payload')
  await waitFor(() => raw.parsed().some((x) => x && x.hash === msg.hash), 'sent')
  const onWire = raw.parsed().find((x) => x && x.hash === msg.hash)
  t.alike(onWire, msg)

  const before = raw.received.length
  A.host.sign = async () => {
    throw new Error('wallet locked')
  }
  try {
    await A.rooms.send(invite, { message: 'not signed' })
    t.fail('should reject')
  } catch (err) {
    t.ok(err instanceof RoomsError)
    t.is(err.code, 'HUGIN_ROOMS_SIGN')
    t.ok(/wallet locked/.test(err.message))
  }
  A.host.sign = async () => 'sig'
  await t.exception(A.rooms.send(invite, { message: 'bad signature' }), /128 hex/)
  delete A.host.sign
  await t.exception(A.rooms.send(invite, { message: 'no signer' }), /host\.sign/)
  A.rooms.typing(invite, true) // barrier
  await waitFor(() => raw.parsed().some((x) => x && x.typing === true), 'barrier')
  t.is(raw.received.length, before + 1, 'only the barrier was written')
})

test('signatures: stored rows without a signature are not sent in history or sync answers', async (t) => {
  const { A, invite, raw } = await roomWithRaw(t)
  const signed = roomMsg({ room: invite, address: ADDRESS, name: 'alice', message: 'signed row' })
  const unsigned = { ...roomMsg({ room: invite, address: ADDRESS, name: 'alice', message: 'unsigned row' }), signature: '' }
  const placeholder = { ...roomMsg({ room: invite, address: ADDRESS, name: 'alice', message: 'old placeholder row' }), signature: 'sig' }
  for (const m of [signed, unsigned, placeholder]) A.host.messages.set(m.hash, m)

  raw.send(wire.requestHistory([]))
  await waitFor(() => raw.parsed().some((x) => x && x.type === 'send-history'), 'history answer')
  const history = raw.parsed().find((x) => x && x.type === 'send-history')
  t.alike(history.messages.map((m) => m.message), ['signed row'])
  t.is(history.messages[0].signature, signed.signature, 'the stored signature goes out')

  raw.send(wire.requestMessages([signed.hash, unsigned.hash, placeholder.hash]))
  await waitFor(() => raw.parsed().some((x) => x && x.type === 'missing-messages'), 'sync answer')
  t.alike(raw.parsed().find((x) => x && x.type === 'missing-messages').messages.map((m) => m.message), ['signed row'])

  // a new connection's joined carries the signed rows only
  const next = await rawPeer(t, A, A.room(invite).topic)
  await waitFor(() => next.parsed().some((x) => x && x.joined === true), 'joined')
  t.alike(next.parsed().find((x) => x && x.joined === true).messages.map((m) => m.message), ['signed row'])
})

test('room message hash: a message signed under the hash of another message is not taken (live: sender banned); the message with that hash still is', async (t) => {
  const { A, invite, topic, raw } = await roomWithRaw(t)
  const original = roomMsg({ room: invite, address: ADDRESS_3, name: 'carol', message: 'first' })
  const sameHash = roomMsg({ room: invite, message: 'second', hash: original.hash }) // signed by its own author
  t.is(await A.rooms._verifyRoomMessage(S.roomMessage(sameHash, { hexHash: true }).value), 'bad', 'the hash is not derived from it')
  raw.send(sameHash)
  await waitFor(() => A.room(invite).denied.has(raw.key), 'sender banned')
  t.is(A.of(E.ROOM_MESSAGE).length, 0)
  t.absent(A.host.messages.has(original.hash))

  const other = await rawPeer(t, A, topic)
  other.send(other.joined(ADDRESS_3, { messages: [original] }))
  await waitFor(() => A.of(E.ROOM_HISTORY).length === 1, 'history batch')
  t.alike(A.of(E.ROOM_MESSAGE).map((e) => e.message.message), ['first'])
})

test('room message hash: send derives it; a given hash must be that one; stored rows with another hash are not sent', async (t) => {
  const { A, invite, raw } = await roomWithRaw(t)
  const at = Date.now() - 1000
  const msg = await A.rooms.send(invite, { message: 'hello', timestamp: at })
  t.is(msg.hash, wire.roomMessageHash(msg))
  t.ok(/^[0-9a-f]{64}$/.test(msg.hash))
  const again = await A.rooms.send(invite, { message: 'hello', timestamp: at, hash: msg.hash.toUpperCase() })
  t.is(again.hash, msg.hash, 'the derived hash given in either case')
  try {
    await A.rooms.send(invite, { message: 'hello', timestamp: at, hash: 'ab'.repeat(32) })
    t.fail('should reject')
  } catch (err) {
    t.is(err.name, 'WireError')
    t.is(err.field, 'hash')
  }

  const derived = roomMsg({ room: invite, address: ADDRESS, name: 'alice', message: 'derived' })
  const other = roomMsg({ room: invite, address: ADDRESS, name: 'alice', message: 'random hash', hash: randomKey() })
  for (const m of [derived, other]) A.host.messages.set(m.hash, m)
  raw.send(wire.requestHistory([]))
  await waitFor(() => raw.parsed().some((x) => x && x.type === 'send-history'), 'history answer')
  t.alike(raw.parsed().find((x) => x && x.type === 'send-history').messages.map((m) => m.message), ['derived'])
})

test('history is requested from one of the earlier peers still connected when historyPickMs has passed', async (t) => {
  const A = makeRooms(t, { address: ADDRESS, name: 'alice', historyPickMs: 300 })
  const { invite } = keys.createRoomInvite()
  const { topic } = await A.rooms.join({ invite })
  const earlier = A.room(invite).time - 1000
  const peers = []
  for (const address of [ADDRESS_2, ADDRESS_3, 'SEKRe' + 'd'.repeat(94)]) {
    const raw = await rawPeer(t, A, topic)
    raw.send(raw.joined(address, { time: address === ADDRESS_2 ? 0 : earlier }))
    peers.push(raw)
  }
  await waitFor(() => A.room(invite).joinedPeers().length === 3, 'three earlier peers')
  const asked = () => peers.filter((p) => p.parsed().some((x) => x && x.type === 'request-history'))
  t.is(asked().length, 0, 'not at once')
  // two of them leave before the pick (also the one that claims the earliest start)
  peers[0].conn.destroy()
  peers[1].conn.destroy()
  await waitFor(() => A.room(invite).joinedPeers().length === 1, 'two left')
  await waitFor(() => asked().length === 1, 'one request-history')
  await sleep(100)
  t.is(asked().length, 1)
  t.ok(asked()[0] === peers[2], 'the peer still connected was asked')
  t.is(A.room(invite).requests, 1)
})

// =============================================================================================
// several connections per address

test('connections: two connections of one address both stay; peer:left and the drive release follow the last one', async (t) => {
  const files = fakeFiles('aa'.repeat(32))
  const A = makeRooms(t, { address: ADDRESS, name: 'alice', files })
  const { invite } = keys.createRoomInvite()
  const { topic } = await A.rooms.join({ invite })
  const phone = await rawPeer(t, A, topic)
  const desktop = await rawPeer(t, A, topic)
  phone.send(phone.joined(ADDRESS_2, { driveKey: 'bb'.repeat(32) }))
  desktop.send(desktop.joined(ADDRESS_2, { driveKey: 'bb'.repeat(32) }))
  await waitFor(() => A.room(invite).joinedPeers().length === 2, 'both admitted')
  t.is(A.of(E.PEER_JOINED).length, 1, 'peer:joined once per address')

  phone.conn.destroy()
  await waitFor(() => A.room(invite).joinedPeers().length === 1, 'phone gone')
  await sleep(50)
  t.is(A.of(E.PEER_LEFT).length, 0, 'the address is still there')
  t.ok(A.rooms.isPeerIn(invite, ADDRESS_2))
  t.is(files.calls.filter(([n]) => n === 'removePeer').length, 0, 'drive still announced by the desktop')

  desktop.conn.destroy()
  await waitFor(() => A.of(E.PEER_LEFT).length === 1, 'peer:left after the last one')
  t.is(A.of(E.PEER_LEFT)[0].address, ADDRESS_2)
  await waitFor(() => files.calls.some(([n]) => n === 'removePeer'), 'drive released')
  t.alike(files.calls.find(([n]) => n === 'removePeer'), ['removePeer', topic, 'bb'.repeat(32)])
})

test('connections: a DM keeps its healthy connection and closes the new duplicate', async (t) => {
  const A = makeRooms(t, { address: ADDRESS, name: 'alice' })
  const { topic } = await A.rooms.joinDm({ address: ADDRESS_2, derivationHash: DERIVATION })
  const room = A.room(ADDRESS_2)
  const first = await rawPeer(t, A, topic)
  first.send(first.joined(ADDRESS_2))
  await waitFor(() => A.rooms.isPeerIn(ADDRESS_2, ADDRESS_2), 'contact joined')
  const second = await rawPeer(t, A, topic)
  second.send(second.joined(ADDRESS_2))
  await waitFor(() => !room.peers.has(second.key), 'the new duplicate closed')
  t.ok(room.peers.has(first.key), 'the first connection stays')
  t.absent(room.denied.has(second.key), 'a duplicate is not banned')
  t.is(A.of(E.PEER_JOINED).length, 1)
  t.is(A.of(E.PEER_LEFT).length, 0)
  first.send('beef')
  await waitFor(() => A.of(E.DM_WIRE).length === 1, 'DM over the first connection')
})

// =============================================================================================
// leave + quick rejoin with real Files

test('rejoin: leave and an immediate rejoin keep the room drive working', { timeout: 60000 }, async (t) => {
  const dir = await tmp(t)
  const files = new Files({
    host: {
      identity: () => ({ address: ADDRESS, name: 'alice' }),
      sign: async (payload) => 'sig' + payload.length,
      paths: { storage: dir + '/corestorage', downloads: dir + '/downloads' }
    },
    pruneIntervalMs: 0
  })
  const A = makeRooms(t, { address: ADDRESS, name: 'alice', files })
  t.teardown(() => files.close())
  const { invite } = keys.createRoomInvite()
  const { topic } = await A.rooms.join({ invite })
  const driveKey = files.driveKey(topic)
  t.ok(S.isHex64(driveKey))
  const first = await A.rooms.shareFile(invite, b4a.from('first file'), { fileName: 'one.txt' })

  const leaving = A.rooms.leave(invite)
  const again = await A.rooms.join({ invite })
  t.ok(await leaving)
  t.is(again.topic, topic)
  t.is(files.driveKey(topic), driveKey, 'the same drive again')
  t.is(A.room(invite).driveKey, driveKey, 'announced in joined')
  t.alike(b4a.toString(await files.read(first.announcement.hash, topic)), 'first file')
  const second = await A.rooms.shareFile(invite, b4a.from('second file'), { fileName: 'two.txt' })
  t.ok((await files.list(topic)).some((m) => m.hash === second.announcement.hash))
  const order = A.events.map(([n]) => n).filter((n) => n === E.ROOM_JOINED || n === E.ROOM_LEFT)
  t.alike(order, [E.ROOM_JOINED, E.ROOM_LEFT, E.ROOM_JOINED])
})

test('leave: leaving a room while it is still joining: no room:joined, no room:left, join rejects', async (t) => {
  const files = {
    openRoom: async () => {
      await sleep(100)
      return 'aa'.repeat(32)
    },
    closeRoom: async () => true
  }
  const A = makeRooms(t, { address: ADDRESS, name: 'alice', files })
  const { invite } = keys.createRoomInvite()
  const joining = A.rooms.join({ invite })
  await sleep(10)
  t.ok(await A.rooms.leave(invite))
  await t.exception(joining, /closed while opening|left while joining/)
  t.is(A.of(E.ROOM_JOINED).length, 0)
  t.is(A.of(E.ROOM_LEFT).length, 0)
  t.alike(A.rooms.list(), [])
})

// =============================================================================================
// feed

test('feed: a live feed message with a bad signature gets its sender banned; a good one does not', async (t) => {
  const { A, invite, topic, raw } = await roomWithRaw(t)
  const feed = new Feed({ host: A.host, emit: (n, p) => A.rooms.emit(n, p), peers: () => A.rooms.joinedPeers({ dm: false }) })
  t.teardown(() => feed.destroy())
  A.rooms.feed = feed

  const good = await rawPeer(t, A, topic)
  good.send(good.joined(ADDRESS_3))
  await waitFor(() => A.rooms.isPeerIn(invite, ADDRESS_3), 'second peer')
  const post = (message, nickname) => {
    const m = { message, nickname, address: ADDRESS_3, reply: '', tip: false, timestamp: Date.now() }
    return { ...m, hash: wire.feedMessageHash(m) }
  }
  const signed = post('signed', 'carol')
  good.send(wire.feed({ ...signed, signature: fakeSign(ADDRESS_3, wire.feedSigningPayload(signed)) }))
  await waitFor(() => A.of(E.FEED_MESSAGE).length === 1, 'verified feed message')
  t.ok(A.rooms.isPeerIn(invite, ADDRESS_3))

  const other = post('signed by another key', 'x')
  raw.send(wire.feed({ ...other, signature: fakeSign(ADDRESS_2, wire.feedSigningPayload(other)) }))
  await waitFor(() => A.room(invite).denied.has(raw.key), 'sender banned')
  t.ok(raw.info.banned, 'hyperswarm peer banned')
  t.is(A.of(E.FEED_MESSAGE).length, 1)
})

// =============================================================================================
// blocked contacts and voice status

test('blocked contact: DM payloads from a blocked contact are not emitted', async (t) => {
  const A = makeRooms(t, { address: ADDRESS, name: 'alice' })
  const { topic } = await A.rooms.joinDm({ address: ADDRESS_2, derivationHash: DERIVATION })
  const raw = await rawPeer(t, A, topic)
  raw.send(raw.joined(ADDRESS_2))
  await waitFor(() => A.rooms.isPeerIn(ADDRESS_2, ADDRESS_2), 'contact joined')
  A.host.blocked.add(ADDRESS_2)
  raw.send('dead')
  raw.send(wire.typing(true))
  await sleep(100)
  A.host.blocked.delete(ADDRESS_2)
  raw.send('beef')
  await waitFor(() => A.of(E.DM_WIRE).length === 1, 'payload after unblocking')
  t.alike(A.of(E.DM_WIRE).map((e) => e.wire), ['beef'])
  t.is(A.of(E.TYPING).length, 0)
})

test('voice status: setStatus that cannot be built returns false, keeps the state and calls nobody; video implies voice; nothing is signed', async (t) => {
  const { A, B, invite, topic } = await joinedPair(t)
  const signs = () => B.host.calls.filter(([n]) => n === 'sign').length
  const before = signs()
  t.ok(await B.rooms.voice.setStatus(invite, { voice: true }))
  t.is(signs(), before, 'a voice status is not signed')
  await waitFor(() => A.room(invite).peerByAddress(ADDRESS_2).voice, 'B in voice at A')

  A.rooms.setIdentity({ address: 'x'.repeat(100) }) // does not fit the voice status
  t.is(await A.rooms.voice.setStatus(invite, { voice: true }), false)
  t.is(A.rooms.voice.active, null, 'state unchanged')
  t.absent(A.rooms.voice.local(topic).voice)
  await sleep(A.rooms.voice.callDelayMs + 100)
  t.is(A.of(E.VOICE_CALL).length, 0, 'nobody called')
  t.is(B.of(E.VOICE_STATUS).length, 0, 'nothing sent')

  A.rooms.setIdentity({ address: ADDRESS })
  t.ok(await A.rooms.voice.setStatus(invite, { video: true }))
  t.alike(A.rooms.voice.local(topic), { voice: true, video: true, audioMute: false, videoMute: false, screenshare: false })
})

// =============================================================================================
// shutdown and bans

test('shutdown: leave and destroy finish although swarm.destroy never resolves', async (t) => {
  const A = makeRooms(t, { address: ADDRESS, name: 'alice', closeTimeoutMs: 200 })
  const one = keys.createRoomInvite().invite
  const two = keys.createRoomInvite().invite
  const r1 = await A.rooms.join({ invite: one })
  const r2 = await A.rooms.join({ invite: two })
  A.swarm(r1.topic).destroy = () => new Promise(noop)
  A.swarm(r2.topic).destroy = () => new Promise(noop)

  let start = Date.now()
  t.ok(await A.rooms.leave(one))
  t.ok(Date.now() - start < 2000, 'leave bounded')
  t.is(A.of(E.ROOM_LEFT).length, 1)

  start = Date.now()
  await A.rooms.destroy()
  t.ok(Date.now() - start < 2000, 'destroy bounded')
})

test('bans: ban validation, bounded ban list', async (t) => {
  t.absent(S.ban({ type: 'ban', address: '' }).ok, 'an empty address is refused')
  t.ok(S.ban({ type: 'ban', address: ADDRESS }).ok)

  const A = makeRooms(t, { address: ADDRESS, name: 'alice', maxBannedAddresses: 3, adminBanDelayMs: 0 })
  const { invite, adminSeed } = keys.createRoomInvite()
  await A.rooms.join({ invite, adminSeed })
  t.absent(await A.rooms.ban(invite, ''))
  for (let i = 0; i < 5; i++) t.ok(await A.rooms.ban(invite, 'SEKRe' + String(i).repeat(94)))
  const banned = A.room(invite).bannedAddresses
  t.is(banned.size, 3)
  t.ok(banned.has('SEKRe' + '4'.repeat(94)), 'the newest kept')
})
