'use strict'

// hugin-network facade: lib/hugin-p2p.js (`HuginP2P`). No network: rooms run on fake swarms whose
// connections are real NoiseSecretStream pairs (as test/rooms.test.js), the node client on the
// fake hugin-node of test/fixtures/fake-hugin-node.js, files on test-tmp directories.

const test = require('brittle')
const b4a = require('b4a')
const tmp = require('test-tmp')
const sodium = require('sodium-universal')
const EventEmitter = require('bare-events')
const NoiseSecretStream = require('@hyperswarm/secret-stream')
const hugin = require('../index.js')
const { HuginP2P, HuginP2PError, EVENT_SOURCES, NODE_POW_REQUIRED } = require('../lib/hugin-p2p.js')
const { Rooms } = require('../lib/rooms.js')
const { Feed } = require('../lib/feed.js')
const { Voice } = require('../lib/voice.js')
const { NodeClient } = require('../lib/node-client.js')
const E = require('../lib/events.js')
const keys = require('../lib/keys.js')
const { keyPairFromSeed } = require('../lib/swarm.js')
const { sha512, randomBytes, toHex } = require('../lib/bytes.js')
const { FakeHuginNode, fakeSwarmFactory } = require('./fixtures/fake-hugin-node.js')
const { ADDRESS, ADDRESS_2, hex } = require('./helpers.js')
const { REFERENCE_VECTOR } = require('hugin-pow')

const ADDRESS_3 = 'SEKRe' + 'c'.repeat(94)
const DERIVATION = 'ab'.repeat(32)
const RECORDED = [...E.ALL, NODE_POW_REQUIRED]

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms))

function noop() {}

/** Stand-in for the XKR message signature: only the holder of `address` "can" produce it. */
function fakeSign(address, message) {
  return toHex(sha512(b4a.from(address + '|' + message, 'utf8')))
}

/** Stand-in for CN-Turtle-Lite v2 (the fake node checks shares with it; hugin-pow's reference answer included). */
async function stubHash(blobHex) {
  if (blobHex === REFERENCE_VECTOR.blob) return REFERENCE_VECTOR.hash
  const out = b4a.alloc(32)
  sodium.crypto_generichash(out, b4a.from(blobHex, 'hex'))
  return hex(out)
}

/**
 * Polls `fn` until it is true; resolves true, or false after `ms` with a failed assertion.
 * Never rejects (an error thrown out of a brittle test crashes the run).
 */
function waitFor(t, fn, label = 'condition', ms = 10000) {
  let stopped = false
  t.teardown(() => {
    stopped = true
  })
  return (async () => {
    const start = Date.now()
    try {
      while (!(await fn())) {
        if (stopped) return false
        if (Date.now() - start > ms) {
          t.fail('timed out waiting for ' + label)
          return false
        }
        await sleep(10)
      }
      return true
    } catch (err) {
      t.fail(label + ': ' + (err && err.message))
      return false
    }
  })()
}

/** In-memory host (README "Host hooks and events"): stores room and feed messages it is told about. */
function makeHost(address, name, extra = {}) {
  const messages = new Map()
  const feed = new Map()
  const host = {
    address,
    messages,
    feed,
    banned: new Set(),
    blocked: new Set(),
    logs: [],
    identity: () => ({ address, name, avatar: '' }),
    sign: async (message) => fakeSign(address, message),
    verify: async (message, addr, signature) => signature === fakeSign(addr, message),
    roomMessageExists: async (hash) => messages.has(hash),
    getRoomHistory: async (key) => [...messages.values()].filter((m) => m.room === key),
    getRoomMessage: async (hash) => messages.get(hash) || null,
    getLatestRoomHashes: async (key) => [...messages.values()].filter((m) => m.room === key).map((m) => m.hash).slice(-25),
    feedMessageExists: async (hash) => feed.has(hash),
    getFeedHistory: async () => [...feed.values()],
    isBanned: (addr) => host.banned.has(addr),
    isBlocked: (addr) => host.blocked.has(addr),
    log: (level, msg) => host.logs.push([level, msg]),
    ...extra
  }
  return host
}

/** Hyperswarm stand-in for room swarms: connections are handed to it by `connect`. */
class FakeSwarm extends EventEmitter {
  constructor(opts) {
    super()
    this.opts = opts
    this.keyPair = keyPairFromSeed(randomBytes(32))
    this.firewall = opts.firewall || (() => false)
    this.topicHex = keys.topicFromSwarmKey(opts.key).topic
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

  joinPeer() {}

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

/**
 * A HuginP2P on fake room swarms and fake node swarms with an in-memory host; records every
 * event. `storage`: a directory for Files (else `files` is null).
 */
function makeP2P(t, { address, name, storage = null, host: extraHost = {}, rooms = {}, node = {}, ...opts } = {}) {
  const paths = storage ? { paths: { storage: storage + '/store', downloads: storage + '/downloads' }, autoSyncFiles: () => true } : {}
  const host = makeHost(address, name, { ...paths, ...extraHost })
  const swarms = []
  const nodeSwarms = []
  const p2p = new HuginP2P({
    host,
    rooms: {
      pingIntervalMs: 0,
      leaveFlushMs: 50,
      banLeaveDelayMs: 50,
      createSwarm: (o) => {
        const swarm = new FakeSwarm(o)
        swarms.push(swarm)
        return { swarm, topic: keys.topicFromSwarmKey(o.key).discoveryKey, keyPair: swarm.keyPair }
      },
      ...rooms
    },
    node: { createSwarm: fakeSwarmFactory(nodeSwarms), hash: stubHash, ...node },
    files: { pruneIntervalMs: 0 },
    ...opts
  })
  const events = []
  for (const n of RECORDED) p2p.on(n, (payload) => events.push([n, payload]))
  // the host stores what it receives (dedupe and history for the next peer)
  p2p.on(E.ROOM_MESSAGE, (e) => e && e.message && host.messages.set(e.message.hash, e.message))
  p2p.on(E.FEED_MESSAGE, (e) => e && e.message && host.feed.set(e.message.hash, e.message))
  t.teardown(() => p2p.destroy())
  return {
    p2p,
    host,
    swarms,
    nodeSwarms,
    events,
    swarm: (topic) => swarms.filter((s) => s.topicHex === topic).pop(),
    of: (n, filter = () => true) => events.filter(([e, p]) => e === n && filter(p)).map(([, p]) => p)
  }
}

/** Sends a (signed) room message and stores it on the sender's host, as an app does. */
async function say(side, key, text) {
  const msg = await side.p2p.rooms.send(key, { message: text })
  side.host.messages.set(msg.hash, msg)
  return msg
}

/** Two opened NoiseSecretStreams with the given key pairs. */
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

/** Connects A's and B's swarms of `topic` (unless a firewall refuses); null when refused. */
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

/** A room with A (creator, admin) and B joined to each other. */
async function joinedPair(t, optsA = {}, optsB = {}) {
  const A = makeP2P(t, { address: ADDRESS, name: 'alice', ...optsA })
  const B = makeP2P(t, { address: ADDRESS_2, name: 'bob', ...optsB })
  const { invite, adminSeed } = keys.createRoomInvite()
  const ra = await A.p2p.rooms.join({ invite, adminSeed })
  await sleep(5) // B starts its swarm later than A
  await B.p2p.rooms.join({ invite })
  await connect(t, A, B, ra.topic)
  const ok = await waitFor(t, () => A.p2p.rooms.isPeerIn(invite, ADDRESS_2) && B.p2p.rooms.isPeerIn(invite, ADDRESS), 'joined both ways')
  return { A, B, invite, topic: ra.topic, ok }
}

// =============================================================================================
// construction

test('facade: exports, parts and options without file storage', async (t) => {
  for (const k of ['constants', 'keys', 'sanitize', 'wire', 'pow', 'push', 'swarm', 'node', 'NodeClient', 'files', 'Files']) {
    t.ok(k in hugin, 'index still exports ' + k)
  }
  t.is(hugin.HuginP2P, HuginP2P)
  t.is(hugin.HuginP2PError, HuginP2PError)
  t.is(hugin.events, E)
  t.is(hugin.Rooms, Rooms)
  t.is(hugin.Feed, Feed)
  t.is(hugin.Voice, Voice)
  t.is(hugin.NodeClient, NodeClient)

  // own error class (brittle rethrows native error types such as TypeError from t.exception)
  for (const bad of [undefined, {}, { host: null }, { host: 'host' }]) {
    try {
      new HuginP2P(bad) // eslint-disable-line no-new
      t.fail('constructed without a host')
    } catch (err) {
      t.ok(err instanceof HuginP2PError, 'HuginP2PError without a host')
      t.is(err.code, 'HUGIN_P2P_INVALID')
      t.ok(/host/.test(err.message))
    }
  }
  try {
    new HuginP2P({ host: makeHost(ADDRESS, 'alice'), node: { preset: 'nope' } }) // eslint-disable-line no-new
    t.fail('constructed with an unknown node preset')
  } catch (err) {
    t.ok(err instanceof HuginP2PError, 'HuginP2PError for an unknown node preset')
    t.is(err.code, 'HUGIN_P2P_INVALID')
  }

  const host = makeHost(ADDRESS, 'alice')
  const p2p = new HuginP2P({ host })
  t.teardown(() => p2p.destroy())
  t.ok(p2p instanceof EventEmitter)
  t.ok(p2p.rooms instanceof Rooms)
  t.ok(p2p.feed instanceof Feed)
  t.ok(p2p.voice instanceof Voice)
  t.ok(p2p.node instanceof NodeClient, 'node client exists before the first connect')
  t.is(p2p.node.state, 'idle', 'no swarm until connect')
  t.is(p2p.files, null, 'no paths.storage: no Files')
  t.is(p2p.rooms.files, null)
  t.is(p2p.rooms.voice, p2p.voice, 'one voice state')
  t.is(p2p.voice.rooms, p2p.rooms)
  t.is(p2p.rooms.feed, p2p.feed, 'rooms hand feed traffic to the facade feed')
  t.is(p2p.rooms.options.roomMaxPeers, 100, 'desktop default')
  t.ok(p2p.foreground)
  t.ok(p2p.feed._gossipOn(), 'gossip on by default (desktop)')
  await p2p.idle({ background: true })
  t.absent(p2p.feed._gossipOn(), 'default: no gossip while idle in the background')
  await p2p.idle({ background: false })
  t.ok(p2p.feed._gossipOn())

  const other = new HuginP2P({ host, roomMaxPeers: 7, gossip: false, rooms: { joinWaitMs: 1234 }, feed: { maxHistory: 3 }, node: { preset: 'native' } })
  t.teardown(() => other.destroy())
  t.is(other.rooms.options.roomMaxPeers, 7)
  t.is(other.rooms.options.joinWaitMs, 1234, 'rooms options pass through')
  t.is(other.feed.options.maxHistory, 3, 'feed options pass through')
  t.is(other.node.preset, 'native', 'node options pass through')
  t.absent(other.feed._gossipOn(), 'gossip off')

  // the node's PoW backend: node.backend / node.findShare / node.hash, else host.powBackend,
  // else host.findShare (+ host.powHash)
  t.is(p2p.node.backend, null, 'no backend without hooks')
  const findShare = async () => null
  const withPow = new HuginP2P({ host: { ...host, findShare } })
  t.teardown(() => withPow.destroy())
  t.is(typeof withPow.node.backend.findShare, 'function')
  t.absent(withPow.node.backend.hash)
  const withPowHash = new HuginP2P({ host: { ...host, findShare, powHash: stubHash } })
  t.teardown(() => withPowHash.destroy())
  t.is(typeof withPowHash.node.backend.hash, 'function')
  t.is(await withPowHash.node.backend.hash(REFERENCE_VECTOR.blob), REFERENCE_VECTOR.hash, 'host.powHash behind backend.hash')
  const powBackend = { findShare, hash: stubHash }
  const withBackend = new HuginP2P({ host: { ...host, findShare: async () => 1, powBackend } })
  t.teardown(() => withBackend.destroy())
  t.is(withBackend.node.backend, powBackend, 'host.powBackend first')
  const withHash = new HuginP2P({ host: { ...host, findShare }, node: { hash: stubHash } })
  t.teardown(() => withHash.destroy())
  t.absent(withHash.node.backend.findShare)
  t.is(withHash.node.backend.hash, stubHash)
})

test('facade: paths.storage creates Files (also from a paths function); files: false disables it', async (t) => {
  const dir = await tmp(t)
  const { Files } = require('../lib/files.js')

  const A = makeP2P(t, { address: ADDRESS, name: 'alice', storage: dir + '/a' })
  t.ok(A.p2p.files instanceof Files)
  t.is(A.p2p.rooms.files, A.p2p.files)
  const { invite } = keys.createRoomInvite()
  const { topic } = await A.p2p.rooms.join({ invite })
  t.ok(/^[0-9a-f]{64}$/.test(A.p2p.files.driveKey(topic)), 'joining a room opens its drive')

  const fnHost = makeHost(ADDRESS, 'alice', { paths: () => ({ storage: dir + '/b/store', downloads: dir + '/b/downloads' }) })
  const fromFn = new HuginP2P({ host: fnHost, files: { pruneIntervalMs: 0 } })
  t.teardown(() => fromFn.destroy())
  t.ok(fromFn.files instanceof Files, 'paths as a function')

  const off = new HuginP2P({ host: fnHost, files: false })
  t.teardown(() => off.destroy())
  t.is(off.files, null, 'files: false')

  const noStorage = new HuginP2P({ host: makeHost(ADDRESS, 'alice', { paths: { downloads: dir + '/c' } }) })
  t.teardown(() => noStorage.destroy())
  t.is(noStorage.files, null, 'downloads alone is not storage')

  const viaOption = new HuginP2P({ host: makeHost(ADDRESS, 'alice'), files: { paths: { storage: dir + '/d', downloads: dir + '/d/dl' }, pruneIntervalMs: 0 } })
  t.teardown(() => viaOption.destroy())
  t.ok(viaOption.files instanceof Files, 'files.paths overrides host.paths')
})

// =============================================================================================
// events

test('facade: event table - every canonical event has one source part and reaches facade listeners', async (t) => {
  const dir = await tmp(t)
  const A = makeP2P(t, { address: ADDRESS, name: 'alice', storage: dir })

  // every name in lib/events.js is emitted by a part, or derived by the facade (`error`)
  t.alike(Object.keys(EVENT_SOURCES).sort(), [...E.ALL].sort(), 'the table covers events.ALL exactly')
  const parts = new Set(['rooms', 'voice', 'feed', 'files', 'node', 'facade'])
  for (const name of E.ALL) t.ok(parts.has(EVENT_SOURCES[name]), name + ' -> ' + EVENT_SOURCES[name])
  t.alike(E.ALL.filter((n) => EVENT_SOURCES[n] === 'facade'), [E.ERROR], 'only error is the facade own')

  // each part's way out reaches the facade (Rooms/Voice/Feed: the shared emit hook; Files and
  // NodeClient: their own emitters, re-emitted)
  const emitters = {
    rooms: (n, p) => A.p2p.rooms._event(n, p),
    voice: (n, p) => A.p2p.voice._emit(n, p),
    feed: (n, p) => A.p2p.feed._emit(n, p),
    files: (n, p) => A.p2p.files.emit(n, p),
    node: (n, p) => A.p2p.node.emit(n, p)
  }
  for (const name of E.ALL) {
    const source = EVENT_SOURCES[name]
    if (source === 'facade') continue
    const payload = { probe: name, auto: true }
    emitters[source](name, payload)
    t.ok(A.events.some(([n, p]) => n === name && p === payload), name + ' from ' + source + ' reaches the facade')
  }
  const pow = { kind: 'post', hash: 'h', attempt: 1 }
  A.p2p.node.emit(NODE_POW_REQUIRED, pow)
  t.ok(A.events.some(([n, p]) => n === NODE_POW_REQUIRED && p === pow), 'node:pow-required is forwarded too')
})

test('facade: part errors surface as error only with a listener; throwing listeners stay out of the parts', async (t) => {
  const dir = await tmp(t)
  const host = makeHost(ADDRESS, 'alice', { paths: { storage: dir + '/store', downloads: dir + '/dl' } })
  const p2p = new HuginP2P({ host, files: { pruneIntervalMs: 0 }, node: { createSwarm: fakeSwarmFactory([]) } })
  t.teardown(() => p2p.destroy())

  // no error listener: nothing throws
  t.execution(() => p2p.node.emit(E.NODE_ERROR, { message: 'boom', code: 'X' }), 'node:error without listeners')
  t.execution(() => p2p.files.emit(E.FILE_ERROR, { message: 'nope', auto: false }), 'file:error without listeners')
  t.execution(() => p2p.rooms._event(E.ERROR, { message: 'direct' }), 'error through the hook without listeners')

  const errors = []
  const nodeErrors = []
  p2p.on(E.ERROR, (e) => errors.push(e))
  p2p.on(E.NODE_ERROR, (e) => nodeErrors.push(e))
  p2p.node.emit(E.NODE_ERROR, { message: 'boom', code: 'X' })
  t.alike(nodeErrors, [{ message: 'boom', code: 'X' }], 'node:error forwarded as is')
  t.alike(errors, [{ message: 'boom', source: 'node' }], 'and as error { message }')

  p2p.files.emit(E.FILE_ERROR, { message: 'not found', error: 'not_found', auto: true })
  t.is(errors.length, 1, 'an auto-sync failure stays file:error')
  p2p.files.emit(E.FILE_ERROR, { message: 'over the limit', error: 'limit', auto: false })
  t.alike(errors[1], { message: 'over the limit', source: 'files' }, 'a download the UI asked for surfaces')

  // a listener that throws does not reach the part that emitted
  p2p.on(E.TYPING, () => {
    throw new Error('listener error')
  })
  p2p.on(E.NODE_ADDRESS, () => {
    throw new Error('listener error')
  })
  t.execution(() => p2p.rooms._event(E.TYPING, { key: 'k' }))
  t.execution(() => p2p.node.emit(E.NODE_ADDRESS, { address: ADDRESS }))
  t.ok(host.logs.some(([level, msg]) => level === 'warn' && msg === 'event handler failed'), 'logged through host.log')
})

test('facade: canonical events from real code paths, from the right part', async (t) => {
  const dir = await tmp(t)
  const A = makeP2P(t, { address: ADDRESS, name: 'alice', storage: dir + '/a' })
  const B = makeP2P(t, { address: ADDRESS_2, name: 'bob' })
  const C = makeP2P(t, { address: ADDRESS_3, name: 'carol' })
  const { invite, adminSeed } = keys.createRoomInvite()

  // rooms: A creates the room and writes before anyone else is there
  const ra = await A.p2p.rooms.join({ invite, adminSeed })
  const topic = ra.topic
  t.alike(A.of(E.ROOM_JOINED)[0], { key: invite, topic, dm: false, admin: true })
  const early = await say(A, invite, 'before you came')
  await sleep(5)
  await B.p2p.rooms.join({ invite })
  await C.p2p.rooms.join({ invite })
  // A - B - C: A and C are not connected
  await connect(t, A, B, topic)
  await connect(t, B, C, topic)
  const meshed = await waitFor(
    t,
    () => A.p2p.rooms.isPeerIn(invite, ADDRESS_2) && B.p2p.rooms.isPeerIn(invite, ADDRESS) && B.p2p.rooms.isPeerIn(invite, ADDRESS_3) && C.p2p.rooms.isPeerIn(invite, ADDRESS_2),
    'A-B and B-C joined'
  )
  if (!meshed) return
  t.ok(B.of(E.PEER_JOINED).some((e) => e.peer.address === ADDRESS && e.peer.admin === true), 'peer:joined with the admin flag')
  t.absent(A.p2p.rooms.isPeerIn(invite, ADDRESS_3))

  // history: B gets A's early message from joined.messages
  await waitFor(t, () => B.of(E.ROOM_HISTORY).length >= 1, 'room:history at B')
  t.ok(B.of(E.ROOM_MESSAGE).some((e) => e.message.hash === early.hash && e.history === true), 'history message at B')

  // live message and typing
  const live = await say(A, invite, 'live')
  await waitFor(t, () => B.of(E.ROOM_MESSAGE).some((e) => e.message.hash === live.hash && e.live === true), 'live room:message at B')
  B.p2p.rooms.typing(invite, true)
  await waitFor(t, () => A.of(E.TYPING).length === 1 && C.of(E.TYPING).length === 1, 'typing at A and C')

  // feed: A posts; B gets it from A, C only through B's gossip; nobody twice, no echo to A
  const post = await A.p2p.feed.send({ message: 'feed post' })
  await waitFor(t, () => B.of(E.FEED_MESSAGE).length === 1 && C.of(E.FEED_MESSAGE).length === 1, 'feed:message at B and at C via B')
  await sleep(200)
  t.is(B.of(E.FEED_MESSAGE).length, 1)
  t.is(C.of(E.FEED_MESSAGE).length, 1, 'C got it once, through B')
  t.is(A.of(E.FEED_MESSAGE).length, 0, 'no echo to the author')
  t.is(C.of(E.FEED_MESSAGE)[0].message.hash, post.hash)
  t.is(C.of(E.FEED_MESSAGE)[0].message.address, ADDRESS)

  // voice: B is in voice first, A joins and calls B; SDP offer, answer, retry
  t.ok(await B.p2p.voice.setStatus(invite, { voice: true }))
  await waitFor(t, () => A.of(E.VOICE_STATUS).some((s) => s.address === ADDRESS_2 && s.voice), 'voice:status at A')
  t.ok(await A.p2p.voice.setStatus(invite, { voice: true }))
  await waitFor(t, () => A.of(E.VOICE_CALL).length === 1, 'voice:call at A')
  t.is(A.of(E.VOICE_CALL)[0].address, ADDRESS_2)
  await waitFor(t, () => B.of(E.VOICE_STATUS).some((s) => s.address === ADDRESS && s.voice), 'A in voice at B')
  t.ok(A.p2p.voice.sendSdp({ topic, address: ADDRESS_2, data: { type: 'offer', sdp: 'v=0' }, type: 'offer' }))
  await waitFor(t, () => B.of(E.VOICE_OFFER).length === 1, 'voice:offer at B')
  t.ok(B.p2p.voice.sendSdp({ topic, address: ADDRESS, data: { type: 'answer', sdp: 'v=0' }, type: 'answer' }))
  await waitFor(t, () => A.of(E.VOICE_ANSWER).length === 1, 'voice:answer at A')
  t.ok(A.p2p.voice.sendSdp({ topic, address: ADDRESS_2, data: 'expand', type: 'offer', retry: true }))
  await waitFor(t, () => B.of(E.VOICE_RETRY).length === 1, 'voice:retry at B')

  // files (A has storage): share through the room, then delete
  const { announcement, sent } = await A.p2p.rooms.shareFile(invite, b4a.from('hello file'), { fileName: 'note.txt' })
  t.is(sent, 1, 'announced to B')
  t.is(A.of(E.FILE_UPLOADED)[0].hash, announcement.hash)
  t.ok(await A.p2p.files.deleteFile(announcement.hash, topic))
  t.alike(A.of(E.FILE_REMOVED)[0].hashes, [announcement.hash])

  // node: a fake hugin-node on the public topic
  await A.p2p.node.connect({ publicNode: true })
  const fakeNode = new FakeHuginNode({ address: ADDRESS_2, hash: stubHash })
  A.nodeSwarms[0].dial(fakeNode)
  await waitFor(t, () => A.of(E.NODE_CONNECTED).length === 1 && A.of(E.NODE_ADDRESS).length === 1, 'node:connected and node:address')
  t.is(A.of(E.NODE_ADDRESS)[0].address, ADDRESS_2)
  fakeNode.pushMessages([{ hash: 'x', timestamp: 1 }, { cipher: 'abcd', hash: 'ab'.repeat(32), timestamp: 1 }])
  await waitFor(t, () => A.of(E.NODE_MESSAGES).length === 1, 'node:messages')

  // DM
  const da = await A.p2p.rooms.joinDm({ address: ADDRESS_2, derivationHash: DERIVATION })
  await B.p2p.rooms.joinDm({ address: ADDRESS, derivationHash: DERIVATION })
  await connect(t, A, B, da.topic)
  await waitFor(t, () => A.p2p.rooms.isPeerIn(ADDRESS_2, ADDRESS_2), 'DM joined')
  t.is(A.p2p.rooms.sendDm(ADDRESS_2, '0a1b2c'), 1)
  await waitFor(t, () => B.of(E.DM_WIRE).length === 1, 'dm:wire at B')
  t.alike(B.of(E.DM_WIRE)[0], { address: ADDRESS, topic: da.topic, wire: '0a1b2c' })

  // leave: peer:left on the other side
  await C.p2p.rooms.leave(invite)
  t.alike(C.of(E.ROOM_LEFT)[0], { key: invite, topic, dm: false })
  await waitFor(t, () => B.of(E.PEER_LEFT).some((e) => e.address === ADDRESS_3), 'peer:left at B')

  // admin ban
  t.ok(await A.p2p.rooms.ban(invite, ADDRESS_2))
  t.alike(A.of(E.BAN_PEER)[0], { key: invite, topic, address: ADDRESS_2, admin: true })
  await waitFor(t, () => B.of(E.BAN_SELF).length === 1, 'ban:self at B')
  await waitFor(t, () => B.of(E.ROOM_LEFT).some((e) => e.key === invite), 'B left the room')

  const seen = new Set([...A.events, ...B.events, ...C.events].map(([n]) => n))
  const expected = E.ALL.filter((n) => !['file:remote', 'file:downloading', 'file:progress', 'file:downloaded', 'file:error', 'node:disconnected', 'node:job', 'node:reset', 'node:error', 'error'].includes(n))
  for (const name of expected) t.ok(seen.has(name), name + ' seen from ' + EVENT_SOURCES[name])
  t.absent(seen.has(E.ERROR), 'no error on the way')
})

// =============================================================================================
// identity and lifecycle

test('facade: setIdentity reaches rooms, voice, feed, files and later joined messages', async (t) => {
  const dir = await tmp(t)
  const A = makeP2P(t, { address: ADDRESS, name: 'alice', storage: dir })
  const B = makeP2P(t, { address: ADDRESS_2, name: 'bob' })
  t.alike(A.p2p.identity(), { address: ADDRESS, name: 'alice', avatar: '' })

  const id = A.p2p.setIdentity({ name: 'alice two' })
  t.alike(id, { address: ADDRESS, name: 'alice two', avatar: '' })
  t.is(A.p2p.rooms.identity().name, 'alice two')
  t.is(A.p2p.voice._identity().name, 'alice two')
  t.is(A.p2p.feed.host.identity().name, 'alice two', 'feed sees it')
  t.is(A.p2p.files.host.identity().name, 'alice two', 'files see it')
  t.is(A.host.identity().name, 'alice', 'the host hook itself is untouched')
  t.is(A.p2p.feed.host.sign, A.host.sign, 'the other hooks are the host own')
  t.is(A.p2p.files.host.paths, A.host.paths)

  const { invite, adminSeed } = keys.createRoomInvite()
  const ra = await A.p2p.rooms.join({ invite, adminSeed })
  await B.p2p.rooms.join({ invite })
  await connect(t, A, B, ra.topic)
  if (!(await waitFor(t, () => B.p2p.rooms.isPeerIn(invite, ADDRESS), 'joined'))) return
  t.is(B.of(E.PEER_JOINED)[0].peer.name, 'alice two', 'joined carries the new name')

  t.is((await A.p2p.rooms.send(invite, { message: 'x' })).name, 'alice two')
  t.is((await A.p2p.feed.send({ message: 'y' })).nickname, 'alice two')
  const { announcement } = await A.p2p.rooms.shareFile(invite, b4a.from('z'), { fileName: 'z.txt' })
  t.is(announcement.name, 'alice two')
  t.is(announcement.address, ADDRESS)

  A.p2p.setIdentity({ avatar: 'aGk=' })
  t.alike(A.p2p.identity(), { address: ADDRESS, name: 'alice two', avatar: 'aGk=' }, 'fields update one at a time')
})

test('facade: suspend, resume and idle delegate to rooms, node and feed gossip', async (t) => {
  const { A, B, invite, topic, ok } = await joinedPair(t, { rooms: { idleSuspendMs: 50 }, gossip: 'foreground' })
  if (!ok) return
  await A.p2p.node.connect({ publicNode: true })
  const nodeSwarm = A.nodeSwarms[0]
  t.ok(A.p2p.foreground)
  t.ok(A.p2p.feed._gossipOn(), 'gossip in the foreground')

  await A.p2p.suspend()
  t.ok(A.p2p.rooms.suspended)
  t.ok(A.p2p.node.suspended)
  t.ok(A.swarm(topic).suspended, 'room swarm suspended')
  t.ok(nodeSwarm.suspended, 'node swarm suspended')
  t.is(A.p2p.rooms.get(invite).peers.size, 0, 'room connections closed')
  await waitFor(t, () => !B.p2p.rooms.isPeerIn(invite, ADDRESS), 'B sees A go')
  t.absent(A.p2p.foreground)
  t.absent(A.p2p.feed._gossipOn(), 'no gossip while suspended')

  await A.p2p.resume()
  t.absent(A.p2p.rooms.suspended)
  t.absent(A.p2p.node.suspended)
  t.absent(A.swarm(topic).suspended)
  t.absent(nodeSwarm.suspended)
  t.ok(A.p2p.foreground)

  // background: idle at once, suspended after idleSuspendMs
  await A.p2p.idle({ background: true })
  t.ok(A.p2p.rooms.idleState)
  t.absent(A.p2p.foreground)
  t.absent(A.p2p.feed._gossipOn(), 'no gossip in the background (native)')
  await waitFor(t, () => A.p2p.rooms.suspended && A.p2p.node.suspended, 'rooms and node suspended in the background')
  await A.p2p.idle({ background: false })
  t.absent(A.p2p.rooms.idleState)
  t.absent(A.p2p.rooms.suspended)
  t.absent(A.p2p.node.suspended)
  t.ok(A.p2p.feed._gossipOn())

  // force: at once
  await A.p2p.idle({ force: true })
  t.ok(A.p2p.rooms.suspended)
  t.ok(A.p2p.node.suspended)
  await A.p2p.idle({ background: false })
  t.absent(A.p2p.rooms.suspended)
  t.absent(A.p2p.node.suspended)

  // back in the foreground before the delay: nothing is suspended
  await A.p2p.idle({ background: true })
  await A.p2p.idle({ background: false })
  await sleep(150)
  t.absent(A.p2p.rooms.suspended)
  t.absent(A.p2p.node.suspended)
  t.is(A.p2p._idleTimer, null)

  // connections come back after resume
  await connect(t, A, B, topic)
  await waitFor(t, () => A.p2p.rooms.isPeerIn(invite, ADDRESS_2) && B.p2p.rooms.isPeerIn(invite, ADDRESS), 'joined again')
})

test('facade: destroy is idempotent, closes every part and leaves no timers', async (t) => {
  const dir = await tmp(t)
  const { A, invite, topic, ok } = await joinedPair(t, { storage: dir, rooms: { pingIntervalMs: 10000, idleSuspendMs: 60000 } })
  if (!ok) return
  const room = A.p2p.rooms.get(invite)
  t.ok(room._pingTimer, 'ping loop running')
  await A.p2p.node.connect({ publicNode: true })
  A.p2p.node.startPolling({ intervalMs: 60000 })
  await A.p2p.idle({ background: true })
  t.ok(A.p2p._idleTimer, 'facade idle timer running')
  t.ok(A.p2p.rooms._idleTimer, 'rooms idle timer running')

  const first = A.p2p.destroy()
  const second = A.p2p.destroy()
  t.is(first, second, 'one destroy')
  await first
  t.ok(A.p2p.destroyed)
  t.ok(A.p2p.rooms.destroyed)
  t.ok(A.p2p.node.destroyed)
  t.ok(A.p2p.feed._destroyed)
  t.ok(A.p2p.files._closing, 'files closed')

  t.is(A.p2p._idleTimer, null)
  t.is(A.p2p.rooms._idleTimer, null)
  t.is(A.p2p.rooms._timers.size, 0)
  t.is(A.p2p.voice._timers.size, 0)
  t.is(A.p2p.feed._pumpTimer, null)
  t.is(A.p2p.feed._current, null, 'no feed request timer')
  t.is(A.p2p.node._timers.size, 0)
  t.is(A.p2p.node._poll, null, 'polling stopped')
  t.is(A.p2p.files._pruneTimer, null)
  t.ok(room.closed)
  t.is(room._pingTimer, null)
  t.ok(A.swarm(topic).destroyed, 'room swarm destroyed')
  t.ok(A.nodeSwarms[0].destroyed, 'node swarm destroyed')
  t.alike(A.p2p.rooms.list(), [])

  await A.p2p.destroy()
  t.pass('a later destroy resolves')
  await A.p2p.suspend()
  await A.p2p.resume()
  await A.p2p.idle({ background: true })
  t.is(A.p2p._idleTimer, null, 'lifecycle calls after destroy do nothing')
  await t.exception(A.p2p.rooms.join({ invite: keys.createRoomInvite().invite }), /destroyed/)
})
