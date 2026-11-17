'use strict'

// One DHT for every room and DM swarm of a process: `SharedMidDHT` and `createHuginSwarm` on it
// (lib/swarm.js), and `sharedDht: true` on HuginP2P / Rooms, on a local DHT testnet
// (`hyperdht/testnet.js`). Waits poll state and never throw: a timeout is a failed assertion.

const test = require('brittle')
const b4a = require('b4a')
const createTestnet = require('hyperdht/testnet.js')
const { SharedMidDHT, MidDHT, createHuginSwarm, isSharedDht } = require('../lib/swarm.js')
const { HuginP2P } = require('../lib/hugin-p2p.js')
const { Rooms } = require('../lib/rooms.js')
const E = require('../lib/events.js')
const keys = require('../lib/keys.js')
const { sha512, toHex } = require('../lib/bytes.js')
const { ADDRESS, ADDRESS_2, hex } = require('./helpers.js')

const DERIVATION = 'ef'.repeat(32)
const TIMEOUT = 180000
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

function makeHost(address, name) {
  const messages = new Map()
  return {
    address,
    messages,
    identity: () => ({ address, name, avatar: '' }),
    sign: async (message) => fakeSign(address, message),
    verify: async (message, addr, signature) => signature === fakeSign(addr, message),
    roomMessageExists: async (hash) => messages.has(hash),
    getRoomHistory: async (key) => [...messages.values()].filter((m) => m.room === key),
    getRoomMessage: async (hash) => messages.get(hash) || null,
    getLatestRoomHashes: async (key) => [...messages.values()].filter((m) => m.room === key).map((m) => m.hash).slice(-25),
    isBanned: () => false,
    isBlocked: () => false
  }
}

function make(t, testnet, address, name, opts = {}) {
  const host = makeHost(address, name)
  const p2p = new HuginP2P({
    host,
    bootstrap: testnet.bootstrap,
    rooms: { pingIntervalMs: 0, leaveFlushMs: 50 },
    files: false,
    ...opts
  })
  const events = []
  for (const n of E.ALL) p2p.on(n, (payload) => events.push([n, payload]))
  p2p.on(E.ROOM_MESSAGE, (e) => host.messages.set(e.message.hash, e.message))
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

async function say(side, key, text) {
  const msg = await side.p2p.rooms.send(key, { message: text })
  side.host.messages.set(msg.hash, msg)
  return msg
}

function listenerCounts(dht) {
  return { change: dht.listenerCount('network-change'), update: dht.listenerCount('network-update') }
}

/** Records 'connection' events and the first line of data on each connection. */
function watch(swarm) {
  const log = { connections: [], data: [], closed: [] }
  swarm.on('connection', (conn) => {
    const remote = hex(conn.remotePublicKey)
    log.connections.push(remote)
    conn.on('data', (d) => log.data.push([remote, b4a.toString(d)]))
    conn.on('close', () => log.closed.push(remote))
    conn.on('error', () => {})
    conn.write(b4a.from('hello'))
  })
  return log
}

// =============================================================================================

test('SharedMidDHT: two swarms on one DHT; destroying one leaves the DHT and the other swarm', { timeout: TIMEOUT }, async (t) => {
  const testnet = await createTestnet(3, t.teardown)
  const { bootstrap } = testnet

  const dht = new SharedMidDHT({ bootstrap })
  t.teardown(() => dht.destroyShared())
  t.ok(dht instanceof MidDHT, 'a MidDHT')
  t.ok(isSharedDht(dht))
  const plainDht = new MidDHT({ bootstrap })
  t.absent(isSharedDht(plainDht), 'a MidDHT is not a shared DHT')
  await plainDht.destroy()
  t.absent(isSharedDht(null))

  const before = listenerCounts(dht)
  const a1 = createHuginSwarm({ key: 'shared topic one', dht })
  const a2 = createHuginSwarm({ key: 'shared topic two', dht })
  t.is(a1.dht, dht)
  t.is(a2.dht, dht)
  t.unlike(a1.keyPair.publicKey, a2.keyPair.publicKey, 'each swarm has its own DHT key pair')
  t.is(dht.midRegistry.get(a1.keyPair.publicKey), a1.identity)
  t.is(dht.midRegistry.get(a2.keyPair.publicKey), a2.identity)
  const withTwo = listenerCounts(dht)
  t.is(withTwo.change, before.change + 2, 'each swarm listens for network changes')

  // the other side: one DHT node per swarm (the default)
  const b1 = createHuginSwarm({ key: 'shared topic one', bootstrap })
  t.teardown(() => b1.swarm.destroy())
  const b2 = createHuginSwarm({ key: 'shared topic two', bootstrap })
  t.teardown(() => b2.swarm.destroy())
  t.not(b1.dht, b2.dht)

  const logA1 = watch(a1.swarm)
  const logA2 = watch(a2.swarm)
  const logB1 = watch(b1.swarm)
  const logB2 = watch(b2.swarm)
  const both = { server: true, client: true }
  await Promise.all([a1, a2, b1, b2].map((s) => s.swarm.join(s.topic, both).flushed()))

  const k = (s) => hex(s.keyPair.publicKey)
  if (!(await waitFor(t, () => logA1.data.length > 0 && logB1.data.length > 0 && logA2.data.length > 0 && logB2.data.length > 0, 'both pairs connected', DHT_WAIT))) return
  t.ok(logA1.connections.every((r) => r === k(b1)), 'a1 only meets b1')
  t.ok(logA2.connections.every((r) => r === k(b2)), 'a2 only meets b2')

  // a1 goes: the DHT and a2 stay
  await a1.swarm.destroy()
  t.is(dht.destroyed, false, 'the shared DHT is not destroyed with a swarm')
  t.is(dht.midRegistry.get(a1.keyPair.publicKey), null, "a1's identity left the registry")
  t.is(dht.midRegistry.get(a2.keyPair.publicKey), a2.identity, "a2's identity stays")
  t.alike(listenerCounts(dht), { change: before.change + 1, update: before.update + 1 }, "a1's DHT listeners are removed")
  await waitFor(t, () => logB1.closed.includes(k(a1)), 'b1 sees a1 close', DHT_WAIT)

  // a2 still works: a new line both ways on its connection
  const conn = [...a2.swarm.connections][0]
  t.ok(conn, 'a2 keeps its connection')
  if (conn) conn.write(b4a.from('still here'))
  await waitFor(t, () => logB2.data.some(([r, d]) => r === k(a2) && d === 'still here'), 'a2 -> b2 after a1 left')

  // the owner destroys the DHT, once
  let closes = 0
  dht.on('close', () => closes++)
  await a2.swarm.destroy()
  t.is(dht.destroyed, false)
  const p1 = dht.destroyShared()
  const p2 = dht.destroyShared()
  t.is(p1, p2, 'destroyShared returns the same promise')
  await p1
  t.is(dht.destroyed, true)
  t.is(closes, 1, 'the DHT closed once')
  await dht.destroy()
  t.is(closes, 1, 'a swarm-side destroy afterwards does nothing')
})

test('Rooms sharedDht: off by default, one DHT for every swarm when on', { timeout: TIMEOUT }, async (t) => {
  const testnet = await createTestnet(3, t.teardown)
  const plain = new Rooms({ host: makeHost(ADDRESS, 'alice'), bootstrap: testnet.bootstrap, pingIntervalMs: 0 })
  t.teardown(() => plain.destroy())
  t.is(plain.sharedDht, false)
  const { invite } = keys.createRoomInvite()
  await plain.join({ invite })
  await plain.joinDm({ address: ADDRESS_2, derivationHash: DERIVATION })
  t.is(plain.dht, null, 'no shared DHT by default')
  t.not(plain.get(invite).swarm.dht, plain.get(ADDRESS_2).swarm.dht, 'one DHT node per swarm')

  const shared = new Rooms({ host: makeHost(ADDRESS, 'alice'), bootstrap: testnet.bootstrap, pingIntervalMs: 0, sharedDht: true })
  t.teardown(() => shared.destroy())
  t.is(shared.sharedDht, true)
  t.is(shared.dht, null, 'created with the first swarm')
  const other = keys.createRoomInvite().invite
  await shared.join({ invite: other })
  await shared.joinDm({ address: ADDRESS_2, derivationHash: '12'.repeat(32) })
  t.ok(shared.dht instanceof SharedMidDHT)
  t.is(shared.get(other).swarm.dht, shared.dht)
  t.is(shared.get(ADDRESS_2).swarm.dht, shared.dht)
  let closes = 0
  shared.dht.on('close', () => closes++)
  await shared.destroy()
  await shared.destroy()
  t.is(shared.dht.destroyed, true, 'destroy closes the shared DHT')
  t.is(closes, 1, 'once')
})

test('HuginP2P sharedDht: two rooms and a DM on one DHT; leaving one room keeps the others; destroy closes the DHT once', { timeout: TIMEOUT }, async (t) => {
  const testnet = await createTestnet(3, t.teardown)
  const A = make(t, testnet, ADDRESS, 'alice', { sharedDht: true })
  // B runs one DHT node per swarm: both kinds meet in the same rooms
  const B = make(t, testnet, ADDRESS_2, 'bob')
  const one = keys.createRoomInvite().invite
  const two = keys.createRoomInvite().invite

  for (const side of [A, B]) {
    await side.p2p.rooms.join({ invite: one })
    await side.p2p.rooms.join({ invite: two })
  }
  await A.p2p.rooms.joinDm({ address: ADDRESS_2, derivationHash: DERIVATION })
  await B.p2p.rooms.joinDm({ address: ADDRESS, derivationHash: DERIVATION })

  const dht = A.p2p.rooms.dht
  t.ok(dht instanceof SharedMidDHT, 'A has a shared DHT')
  t.is(B.p2p.rooms.dht, null, 'B has none')
  const aRooms = [A.p2p.rooms.get(one), A.p2p.rooms.get(two), A.p2p.rooms.get(ADDRESS_2)]
  t.ok(aRooms.every((room) => room.swarm.dht === dht), "all of A's swarms run on it")
  t.is(new Set(aRooms.map((room) => hex(room.keyPair.publicKey))).size, 3, 'with three DHT key pairs')
  for (const side of [A, B]) for (const key of [one, two, ADDRESS_2, ADDRESS]) if (side.p2p.rooms.get(key)) await side.p2p.rooms.get(key).flushed()

  const linked = await waitFor(
    t,
    () => A.has(one, B) && B.has(one, A) && A.has(two, B) && B.has(two, A) && A.p2p.rooms.isPeerIn(ADDRESS_2, ADDRESS_2) && B.p2p.rooms.isPeerIn(ADDRESS, ADDRESS),
    'A and B joined in both rooms and the DM',
    DHT_WAIT
  )
  if (!linked) return

  const m1 = await say(A, one, 'in room one')
  const m2 = await say(B, two, 'in room two')
  t.is(A.p2p.rooms.sendDm(ADDRESS_2, '0a0b0c'), 1)
  await waitFor(t, () => B.of(E.ROOM_MESSAGE).some((e) => e.message.hash === m1.hash), 'room one A -> B')
  await waitFor(t, () => A.of(E.ROOM_MESSAGE).some((e) => e.message.hash === m2.hash), 'room two B -> A')
  await waitFor(t, () => B.of(E.DM_WIRE).some((e) => e.wire === '0a0b0c'), 'DM A -> B')

  // A leaves room one: B sees A go there only; room two and the DM keep working
  const leftKey = A.p2p.rooms.get(one).keyPair.publicKey
  const othersLeft = () => B.of(E.PEER_LEFT).filter((e) => e.key === two || e.dm).length
  const leftBefore = othersLeft()
  t.ok(await A.p2p.rooms.leave(one))
  t.is(dht.destroyed, false, 'the shared DHT stays')
  t.is(dht.midRegistry.get(leftKey), null, "room one's identity is gone from the DHT")
  await waitFor(t, () => B.of(E.PEER_LEFT).some((e) => e.key === one && e.address === ADDRESS), 'peer:left for A in room one at B')
  t.is(othersLeft(), leftBefore, 'nobody left room two or the DM')
  t.ok(A.has(two, B) && B.has(two, A), 'room two still joined')

  const m3 = await say(A, two, 'room two after leaving room one')
  const m4 = await say(B, two, 'and back')
  t.is(B.p2p.rooms.sendDm(ADDRESS, '0d0e0f'), 1)
  await waitFor(t, () => B.of(E.ROOM_MESSAGE).some((e) => e.message.hash === m3.hash), 'room two A -> B')
  await waitFor(t, () => A.of(E.ROOM_MESSAGE).some((e) => e.message.hash === m4.hash), 'room two B -> A')
  await waitFor(t, () => A.of(E.DM_WIRE).some((e) => e.wire === '0d0e0f'), 'DM B -> A')

  // destroy: every swarm, then the DHT once
  let closes = 0
  dht.on('close', () => closes++)
  await Promise.all([A.p2p.destroy(), A.p2p.destroy()])
  await A.p2p.destroy()
  t.is(dht.destroyed, true, 'destroy closes the shared DHT')
  t.is(closes, 1, 'once')
  await waitFor(t, () => B.of(E.PEER_LEFT).some((e) => e.key === two && e.address === ADDRESS), 'B sees A leave room two', DHT_WAIT)
})

test('HuginP2P sharedDht: suspend suspends the DHT after the swarms, resume brings the rooms back', { timeout: TIMEOUT }, async (t) => {
  const testnet = await createTestnet(3, t.teardown)
  const A = make(t, testnet, ADDRESS, 'alice', { sharedDht: true })
  const B = make(t, testnet, ADDRESS_2, 'bob', { sharedDht: true })
  const { invite } = keys.createRoomInvite()
  for (const side of [A, B]) {
    await side.p2p.rooms.join({ invite })
    await side.p2p.rooms.get(invite).flushed()
  }
  if (!(await waitFor(t, () => A.has(invite, B) && B.has(invite, A), 'joined', DHT_WAIT))) return

  const dht = A.p2p.rooms.dht
  await A.p2p.suspend()
  t.is(dht.suspended, true, 'the shared DHT is suspended')
  t.is(A.p2p.rooms.get(invite).swarm.suspended, true, 'and the swarm')
  await waitFor(t, () => !B.has(invite, A), 'B lost A', DHT_WAIT)

  await A.p2p.resume()
  t.is(dht.suspended, false, 'the shared DHT is resumed')
  if (!(await waitFor(t, () => A.has(invite, B) && B.has(invite, A), 'joined again after resume', DHT_WAIT))) return
  const msg = await say(A, invite, 'after resume')
  await waitFor(t, () => B.of(E.ROOM_MESSAGE).some((e) => e.message.hash === msg.hash), 'A -> B after resume')
})
