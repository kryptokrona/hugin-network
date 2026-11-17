'use strict'

// hugin-network end to end: real HuginP2P instances (rooms, voice, feed, files, node client) on a
// local DHT testnet (`hyperdht/testnet.js`), with in-memory hosts and, where files are involved,
// real Files on test-tmp directories. Waits poll state (the server side of a Hyperswarm
// connection emits 'connection' a little after the client side) and never throw: a timeout is a
// failed assertion. Every instance is destroyed in teardown, before the testnet and the
// temporary directories (their teardowns run last).

const test = require('brittle')
const b4a = require('b4a')
const tmp = require('test-tmp')
const createTestnet = require('hyperdht/testnet.js')
const { HuginP2P } = require('../lib/hugin-p2p.js')
const E = require('../lib/events.js')
const keys = require('../lib/keys.js')
const { sha512, toHex } = require('../lib/bytes.js')
const { ADDRESS, ADDRESS_2, hex } = require('./helpers.js')

const ADDRESS_3 = 'SEKRe' + 'c'.repeat(94)
const DERIVATION = 'cd'.repeat(32)
const TIMEOUT = 120000
const DHT_WAIT = 90000

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms))

/** Stand-in for the XKR message signature: only the holder of `address` "can" produce it. */
function fakeSign(address, message) {
  return toHex(sha512(b4a.from(address + '|' + message, 'utf8')))
}

/** Polls `fn`; resolves true, or false after `ms` with a failed assertion. Never rejects. */
function waitFor(t, fn, label = 'condition', ms = 30000) {
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
        await sleep(50)
      }
      return true
    } catch (err) {
      t.fail(label + ': ' + (err && err.message))
      return false
    }
  })()
}

/** In-memory host (README "Host hooks and events") that keeps the room and feed messages it is told about. */
function makeHost(address, name, extra = {}) {
  const messages = new Map()
  const feed = new Map()
  const host = {
    address,
    messages,
    feed,
    banned: new Set(),
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
    isBlocked: () => false,
    ...extra
  }
  return host
}

/**
 * A HuginP2P on the testnet. `storage`: a directory for Files (auto-sync on); `banned`:
 * addresses the host refuses.
 */
function make(t, testnet, address, name, { storage = null, banned = [], ...opts } = {}) {
  const extra = storage ? { paths: { storage: storage + '/store', downloads: storage + '/downloads' }, autoSyncFiles: () => true } : {}
  const host = makeHost(address, name, extra)
  for (const a of banned) host.banned.add(a)
  const p2p = new HuginP2P({
    host,
    bootstrap: testnet.bootstrap,
    rooms: { pingIntervalMs: 0, leaveFlushMs: 50, banLeaveDelayMs: 50 },
    files: { pruneIntervalMs: 0 },
    ...opts
  })
  const events = []
  for (const n of E.ALL) p2p.on(n, (payload) => events.push([n, payload]))
  p2p.on(E.ROOM_MESSAGE, (e) => host.messages.set(e.message.hash, e.message))
  p2p.on(E.FEED_MESSAGE, (e) => host.feed.set(e.message.hash, e.message))
  t.teardown(() => p2p.destroy())
  return {
    p2p,
    host,
    address,
    events,
    of: (n, filter = () => true) => events.filter(([e, p]) => e === n && filter(p)).map(([, p]) => p),
    has: (key, other) => p2p.rooms.isPeerIn(key, other.address)
  }
}

/** Sends a (signed) room message and stores it on the sender's host, as an app does. */
async function say(side, key, text) {
  const msg = await side.p2p.rooms.send(key, { message: text })
  side.host.messages.set(msg.hash, msg)
  return msg
}

async function joinRoom(sides, invite, adminSeed) {
  const out = []
  for (const [i, side] of sides.entries()) {
    out.push(await side.p2p.rooms.join(i === 0 && adminSeed ? { invite, adminSeed } : { invite }))
  }
  for (const side of sides) await side.p2p.rooms.get(invite).flushed()
  return out[0].topic
}

// =============================================================================================

test('integration: three peers - messages both ways, a feed post reaches C through B exactly once, leave', { timeout: TIMEOUT }, async (t) => {
  const testnet = await createTestnet(3, t.teardown)
  const { invite, adminSeed } = keys.createRoomInvite()
  const A = make(t, testnet, ADDRESS, 'alice')
  const B = make(t, testnet, ADDRESS_2, 'bob')
  // C's host refuses A: A and C never exchange anything directly, so A's feed post can only
  // reach C through B's gossip
  const C = make(t, testnet, ADDRESS_3, 'carol', { banned: [ADDRESS] })
  const topic = await joinRoom([A, B, C], invite, adminSeed)

  const linked = await waitFor(t, () => A.has(invite, B) && B.has(invite, A) && B.has(invite, C) && C.has(invite, B), 'A-B and B-C joined over the DHT', DHT_WAIT)
  if (!linked) return

  // C meets A on the DHT and refuses it (soft wait: the meeting is up to the DHT)
  const start = Date.now()
  while (!C.of(E.BAN_PEER).some((e) => e.address === ADDRESS) && Date.now() - start < 20000) await sleep(100)
  if (C.of(E.BAN_PEER).some((e) => e.address === ADDRESS)) t.pass('C met A and refused it')
  else t.comment('A and C did not meet within 20 s; the post still has only one way to C')
  t.absent(C.has(invite, A), 'A is never a joined peer at C')

  // room messages both ways
  const fromA = await say(A, invite, 'hello from A')
  const fromB = await say(B, invite, 'hello from B')
  await waitFor(t, () => B.of(E.ROOM_MESSAGE).some((e) => e.message.hash === fromA.hash), 'A -> B')
  await waitFor(t, () => A.of(E.ROOM_MESSAGE).some((e) => e.message.hash === fromB.hash), 'B -> A')
  await waitFor(t, () => C.of(E.ROOM_MESSAGE).some((e) => e.message.hash === fromB.hash), 'B -> C')
  const atB = B.of(E.ROOM_MESSAGE, (e) => e.message.hash === fromA.hash)[0]
  t.is(atB.message.message, 'hello from A')
  t.is(atB.live, true)
  t.is(atB.key, invite)
  t.is(atB.topic, topic)

  // the feed: delivered once to B and once to C (via B), never back to A
  const post = await A.p2p.feed.send({ message: 'a feed post from A' })
  await waitFor(t, () => B.of(E.FEED_MESSAGE).length >= 1 && C.of(E.FEED_MESSAGE).length >= 1, 'feed post at B and C')
  await sleep(2000)
  t.is(B.of(E.FEED_MESSAGE).length, 1, 'B: once')
  t.is(C.of(E.FEED_MESSAGE).length, 1, 'C: once, deduped')
  t.is(A.of(E.FEED_MESSAGE).length, 0, 'A: no echo')
  const atC = C.of(E.FEED_MESSAGE)[0].message
  t.is(atC.hash, post.hash)
  t.is(atC.address, ADDRESS, 'signed by A')
  t.is(atC.message, 'a feed post from A')
  t.absent(C.has(invite, A), 'C still has no link to A: the post came through B')

  // leave: peer:left on the other side
  t.ok(await C.p2p.rooms.leave(invite))
  t.alike(C.of(E.ROOM_LEFT)[0], { key: invite, topic, dm: false })
  await waitFor(t, () => B.of(E.PEER_LEFT).some((e) => e.address === ADDRESS_3 && e.key === invite), 'peer:left for C at B')
  t.absent(B.has(invite, C))
  t.ok(B.has(invite, A), 'A and B stay')
})

test('integration: a late joiner receives the room history', { timeout: TIMEOUT }, async (t) => {
  const testnet = await createTestnet(3, t.teardown)
  const { invite, adminSeed } = keys.createRoomInvite()
  const A = make(t, testnet, ADDRESS, 'alice')
  const B = make(t, testnet, ADDRESS_2, 'bob')
  await joinRoom([A, B], invite, adminSeed)
  if (!(await waitFor(t, () => A.has(invite, B) && B.has(invite, A), 'A and B joined', DHT_WAIT))) return

  const sent = []
  for (const text of ['one', 'two', 'three']) sent.push(await say(A, invite, text))
  sent.push(await say(B, invite, 'four (from B)'))
  await waitFor(t, () => sent.every((m) => A.host.messages.has(m.hash) && B.host.messages.has(m.hash)), 'both hosts store all four')

  const C = make(t, testnet, ADDRESS_3, 'carol')
  await joinRoom([C], invite)
  if (!(await waitFor(t, () => C.has(invite, A) || C.has(invite, B), 'C joined', DHT_WAIT))) return
  await waitFor(t, () => sent.every((m) => C.of(E.ROOM_MESSAGE).some((e) => e.message.hash === m.hash)), 'history at C', DHT_WAIT)

  const got = C.of(E.ROOM_MESSAGE, (e) => sent.some((m) => m.hash === e.message.hash))
  t.ok(got.every((e) => e.history === true && e.live === false), 'delivered as history')
  t.alike([...new Set(got.map((e) => e.message.message))].sort(), ['four (from B)', 'one', 'three', 'two'])
  t.ok(C.of(E.ROOM_HISTORY).some((h) => h.key === invite && h.count > 0), 'room:history')
  t.ok(sent.every((m) => C.host.messages.has(m.hash)), 'stored by the late joiner')
})

test('integration: a file shared by A auto-syncs to B through the room', { timeout: TIMEOUT }, async (t) => {
  const testnet = await createTestnet(3, t.teardown)
  const dir = await tmp(t)
  const { invite, adminSeed } = keys.createRoomInvite()
  const A = make(t, testnet, ADDRESS, 'alice', { storage: dir + '/a' })
  const B = make(t, testnet, ADDRESS_2, 'bob', { storage: dir + '/b' })
  t.ok(A.p2p.files && B.p2p.files, 'both have file storage')
  const topic = await joinRoom([A, B], invite, adminSeed)
  if (!(await waitFor(t, () => A.has(invite, B) && B.has(invite, A), 'A and B joined', DHT_WAIT))) return

  const photo = b4a.alloc(200 * 1024)
  for (let i = 0; i < photo.length; i++) photo[i] = (i * 31 + 7) & 255
  const { announcement, sent } = await A.p2p.rooms.shareFile(invite, photo, { fileName: 'photo.png' })
  t.is(sent, 1, 'announced to B')
  t.is(announcement.fileName, 'photo.png')
  t.is(announcement.address, ADDRESS)
  t.ok(A.of(E.FILE_UPLOADED).some((e) => e.hash === announcement.hash && e.key === invite), 'file:uploaded at A')

  if (!(await waitFor(t, () => B.of(E.FILE_DOWNLOADED).some((e) => e.hash === announcement.hash), 'file:downloaded at B', DHT_WAIT))) return
  const d = B.of(E.FILE_DOWNLOADED, (e) => e.hash === announcement.hash)[0]
  t.is(d.auto, true, 'auto-synced')
  t.is(d.key, invite)
  t.is(d.topic, topic)
  t.is(d.address, ADDRESS)
  t.alike(b4a.from(await B.p2p.files.read(announcement.hash, topic)), photo, 'same bytes in B storage')
  t.ok((await B.p2p.files.list(topic)).some((m) => m.hash === announcement.hash), 'listed in B drive')
  t.absent(B.of(E.FILE_ERROR).length, 'no file:error')
})

test('integration: DM between two identities, a third identity is refused', { timeout: TIMEOUT }, async (t) => {
  const testnet = await createTestnet(3, t.teardown)
  const A = make(t, testnet, ADDRESS, 'alice')
  const B = make(t, testnet, ADDRESS_2, 'bob')
  // C derives the same topic (as the user's own second device would) and claims a DM with A
  const C = make(t, testnet, ADDRESS_3, 'carol')

  const da = await A.p2p.rooms.joinDm({ address: ADDRESS_2, derivationHash: DERIVATION })
  const dc = await C.p2p.rooms.joinDm({ address: ADDRESS, derivationHash: DERIVATION })
  t.is(dc.topic, da.topic)
  const roomA = A.p2p.rooms.get(ADDRESS_2)
  const roomC = C.p2p.rooms.get(ADDRESS)
  t.is(roomA.swarm.maxPeers, 1, 'one slot')
  await roomA.flushed()
  await roomC.flushed()
  const cKey = hex(roomC.keyPair.publicKey)
  if (!(await waitFor(t, () => roomA.denied.has(cKey), 'A refuses C', DHT_WAIT))) return
  t.absent(A.p2p.rooms.isPeerIn(ADDRESS_2, ADDRESS_3))
  t.is(A.of(E.PEER_JOINED).length, 0, 'C was not admitted')

  const db = await B.p2p.rooms.joinDm({ address: ADDRESS, derivationHash: DERIVATION })
  t.is(db.topic, da.topic)
  await B.p2p.rooms.get(ADDRESS).flushed()
  if (!(await waitFor(t, () => A.p2p.rooms.isPeerIn(ADDRESS_2, ADDRESS_2) && B.p2p.rooms.isPeerIn(ADDRESS, ADDRESS), 'A and B joined in the DM', DHT_WAIT))) return
  t.alike(A.of(E.PEER_JOINED).map((e) => [e.peer.address, e.dm]), [[ADDRESS_2, true]])

  t.is(A.p2p.rooms.sendDm(ADDRESS_2, '0a1b2c3d'), 1)
  await waitFor(t, () => B.of(E.DM_WIRE).length === 1, 'dm:wire at B')
  t.alike(B.of(E.DM_WIRE)[0], { address: ADDRESS, topic: da.topic, wire: '0a1b2c3d' })
  t.is(B.p2p.rooms.sendDm(ADDRESS, 'ffee'), 1)
  await waitFor(t, () => A.of(E.DM_WIRE).length === 1, 'dm:wire at A')
  t.alike(A.of(E.DM_WIRE)[0], { address: ADDRESS_2, topic: da.topic, wire: 'ffee' })

  // C has nobody: A and B refused it
  await waitFor(t, () => C.p2p.rooms.joinedPeers({ dm: true }).length === 0, 'C without a joined peer')
  t.is(C.p2p.rooms.sendDm(ADDRESS, 'beef'), 0, 'C reaches nobody')
  await sleep(500)
  t.is(A.of(E.DM_WIRE).length, 1, 'nothing from C at A')
  t.is(B.of(E.DM_WIRE).length, 1, 'nothing from C at B')
  t.ok(A.of(E.PEER_JOINED).every((e) => e.peer.address === ADDRESS_2), 'only the contact was ever admitted at A')
  t.is(C.of(E.DM_WIRE).length, 0)
})

test('integration: an admin ban removes the peer everywhere', { timeout: TIMEOUT }, async (t) => {
  const testnet = await createTestnet(3, t.teardown)
  const { invite, adminSeed } = keys.createRoomInvite()
  const A = make(t, testnet, ADDRESS, 'alice')
  const B = make(t, testnet, ADDRESS_2, 'bob')
  const C = make(t, testnet, ADDRESS_3, 'carol')
  const topic = await joinRoom([A, B, C], invite, adminSeed)
  const meshed = await waitFor(
    t,
    () => A.has(invite, B) && A.has(invite, C) && B.has(invite, A) && B.has(invite, C) && C.has(invite, A) && C.has(invite, B),
    'three peers joined to each other',
    DHT_WAIT
  )
  if (!meshed) return
  t.ok(B.p2p.rooms.get(invite).peerByAddress(ADDRESS).admin, 'B sees A as the admin')
  t.ok(C.p2p.rooms.get(invite).peerByAddress(ADDRESS).admin, 'C sees A as the admin')

  t.ok(await A.p2p.rooms.ban(invite, ADDRESS_2))
  t.alike(A.of(E.BAN_PEER)[0], { key: invite, topic, address: ADDRESS_2, admin: true })
  await waitFor(t, () => B.of(E.BAN_SELF).length === 1, 'ban:self at B')
  t.alike(B.of(E.BAN_SELF)[0], { key: invite, topic })
  await waitFor(t, () => B.of(E.ROOM_LEFT).some((e) => e.key === invite), 'B left the room')
  await waitFor(t, () => C.of(E.BAN_PEER).some((e) => e.address === ADDRESS_2 && e.admin === true), 'C honours the admin ban')
  await waitFor(t, () => !A.has(invite, B) && !C.has(invite, B), 'B gone at A and C')
  t.ok(A.of(E.PEER_LEFT).some((e) => e.address === ADDRESS_2), 'peer:left for B at A')
  t.ok(A.has(invite, C) && C.has(invite, A), 'A and C stay')
  t.alike(B.p2p.rooms.list(), [], 'B is in no room')
})
