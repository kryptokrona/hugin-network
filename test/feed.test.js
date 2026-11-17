'use strict'

// lib/feed.js: verify, dedupe, gossip, history answers and the history request queue, with fake
// peers and an in-memory host. No network.

const test = require('brittle')
const { Feed, FEED_RESULT, isFeedHash } = require('../lib/feed.js')
const wire = require('../lib/wire.js')
const S = require('../lib/sanitize.js')
const desktop = require('./fixtures/legacy-desktop.js')
const { ADDRESS, ADDRESS_2, PAST, legacy } = require('./helpers.js')

const ADDRESS_3 = 'SEKRe' + 'c'.repeat(94)
const ADDRESS_4 = 'SEKRe' + 'd'.repeat(94)

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms))

/** Deterministic stand-in for an XKR signature: short, bound to the payload and the address. */
function fakeSig(payload, address) {
  let h = 5381
  const s = payload + '|' + address
  for (let i = 0; i < s.length; i++) h = ((h * 33) ^ s.charCodeAt(i)) >>> 0
  return 'sig' + h.toString(16)
}

let counter = 0

/**
 * A signed feed message as `Feed#send` builds it: the hash derived from the fields
 * (`wire.feedMessageHash`), the signature over `wire.feedSigningPayload`. Every call gets its
 * own timestamp (PAST + n), so two calls never build the same message.
 */
function feedMsg(o = {}) {
  counter++
  const address = o.address || ADDRESS_2
  const m = {
    type: 'feed',
    message: o.message !== undefined ? o.message : 'hello feed',
    nickname: o.nickname !== undefined ? o.nickname : 'Bob',
    address,
    reply: o.reply !== undefined ? o.reply : '',
    tip: o.tip !== undefined ? o.tip : false,
    hash: '',
    timestamp: o.timestamp !== undefined ? o.timestamp : PAST + counter
  }
  m.hash = o.hash || wire.feedMessageHash(m)
  m.signature = o.signature !== undefined ? o.signature : fakeSig(wire.feedSigningPayload(m), address)
  return m
}

/** What the rooms layer passes in: the decoded value. */
function decoded(msg) {
  const d = wire.decode(JSON.stringify(msg))
  return d.value
}

function makePeer(address, { dm = false, key = 'room1' } = {}) {
  return {
    address,
    name: 'peer',
    joined: true,
    room: { key, topic: 'e5'.repeat(32), dm },
    sent: [],
    send(str) {
      this.sent.push(str)
      return true
    }
  }
}

function makeHost(o = {}) {
  const host = {
    stored: new Set(o.stored || []),
    verifyCalls: 0,
    signCalls: [],
    blocked: new Set(o.blocked || []),
    history: o.history || [],
    historyCalls: 0,
    verifyDelayMs: o.verifyDelayMs || 0,
    identity: () => ({ address: ADDRESS, name: 'Alice', avatar: '' }),
    sign: async (payload) => {
      host.signCalls.push(payload)
      return fakeSig(payload, ADDRESS)
    },
    verify: async (payload, address, signature) => {
      host.verifyCalls++
      if (host.verifyDelayMs) await sleep(host.verifyDelayMs)
      return signature === fakeSig(payload, address)
    },
    feedMessageExists: async (hash) => host.stored.has(hash),
    getFeedHistory: async () => {
      host.historyCalls++
      return host.history
    },
    isBlocked: (address) => host.blocked.has(address)
  }
  return host
}

function setup(t, o = {}) {
  const host = o.host || makeHost()
  const peers = o.peers || [makePeer(ADDRESS_2), makePeer(ADDRESS_3), makePeer(ADDRESS_4)]
  const events = []
  const logs = []
  const feed = new Feed({
    host,
    log: (level, msg, data) => logs.push({ level, msg, data }),
    emit: (name, payload) => {
      events.push({ name, payload })
      // the host stores what it is given
      if (name === 'feed:message') host.stored.add(payload.message.hash)
    },
    peers: () => peers.filter((p) => !p.gone),
    gossip: o.gossip === undefined ? true : o.gossip,
    requestSpacingMs: o.requestSpacingMs === undefined ? 30 : o.requestSpacingMs,
    requestTimeoutMs: o.requestTimeoutMs === undefined ? 2000 : o.requestTimeoutMs,
    maxHistory: o.maxHistory
  })
  t.teardown(() => feed.destroy())
  return { feed, host, peers, events, logs }
}

/** Polls `fn` until true or `ms` passed (then a failed assertion, never an exception). */
async function waitFor(t, fn, ms = 3000, label = 'condition') {
  const start = Date.now()
  while (!fn()) {
    if (Date.now() - start > ms) {
      t.fail('timeout waiting for ' + label)
      return false
    }
    await sleep(5)
  }
  return true
}

const kinds = (peer) => peer.sent.map((s) => wire.decode(s).type)

// ---------------------------------------------------------------------------------------------

test('feed: isFeedHash accepts exactly 64 hex characters, either case', (t) => {
  t.ok(isFeedHash('a'.repeat(64)))
  t.ok(isFeedHash('0123456789abcdef'.repeat(4)))
  t.ok(isFeedHash('0123456789ABCDEF'.repeat(4)))
  t.absent(isFeedHash(''))
  t.absent(isFeedHash('x'))
  t.absent(isFeedHash('a'.repeat(63)))
  t.absent(isFeedHash('a'.repeat(65)))
  t.absent(isFeedHash('g'.repeat(64)))
  t.absent(isFeedHash("'".padEnd(64, 'a')))
  t.absent(isFeedHash(5))
  t.absent(isFeedHash(null))
})

test('feed: a verified live message is emitted once and gossiped to everyone but the sender', async (t) => {
  const { feed, host, peers, events } = setup(t)
  const [a, b, c] = peers
  const msg = feedMsg()

  t.is(await feed.handle(a, decoded(msg)), FEED_RESULT.NEW)
  t.is(events.length, 1)
  t.is(events[0].name, 'feed:message')
  t.is(events[0].payload.live, true, 'a live message is marked live')
  const m = events[0].payload.message
  t.is(m.hash, msg.hash)
  t.is(m.message, msg.message)
  t.is(m.signature, msg.signature)
  t.is(m.timestamp, msg.timestamp)
  t.is(m.tip, false)
  t.absent('type' in m, 'the event carries the message fields only')

  t.is(a.sent.length, 0, 'not sent back to the sender')
  t.is(b.sent.length, 1)
  t.is(c.sent.length, 1)
  const fwd = JSON.parse(b.sent[0])
  t.alike(fwd, msg, 'forwarded exactly as signed')
  t.ok(legacy(desktop.sanitize_feed_message, fwd), 'old desktop accepts the forwarded message')

  // The same message again, from another peer: the LRU stops it (before the host is asked).
  host.stored.clear()
  t.is(await feed.handle(b, decoded(msg)), FEED_RESULT.DUPLICATE)
  t.is(events.length, 1)
  t.is(a.sent.length, 0)
  t.is(c.sent.length, 1, 'gossip loop ends')
  t.is(host.verifyCalls, 1)
})

test('feed: the decode result wrapper is accepted too', async (t) => {
  const { feed, events } = setup(t)
  const d = wire.decode(JSON.stringify(feedMsg()))
  t.is(await feed.handle(makePeer(ADDRESS_2), d), FEED_RESULT.NEW)
  t.is(events.length, 1)
})

test('feed: a bad signature is dropped and not gossiped, and does not mark the hash as seen', async (t) => {
  const { feed, peers, events } = setup(t)
  const [a, b, c] = peers
  const good = feedMsg()
  const otherSigner = { ...good, signature: fakeSig(wire.feedSigningPayload(good), ADDRESS_3) }
  const unsigned = { ...good, signature: '' }

  t.is(await feed.handle(a, decoded(otherSigner)), FEED_RESULT.UNVERIFIED)
  t.is(await feed.handle(a, decoded(unsigned)), FEED_RESULT.UNVERIFIED)
  t.is(events.length, 0)
  t.is(b.sent.length + c.sent.length, 0)

  t.is(await feed.handle(b, decoded(good)), FEED_RESULT.NEW, 'the genuine message still gets through')
  t.is(events.length, 1)
  t.is(a.sent.length, 1)
  t.is(b.sent.length, 0)
})

test('feed: an address that did not sign is refused (signature bound to the author)', async (t) => {
  const { feed, events } = setup(t)
  const msg = feedMsg()
  const claimed = { ...msg, address: ADDRESS_4 }
  t.is(await feed.handle(makePeer(ADDRESS_2), decoded(claimed)), FEED_RESULT.UNVERIFIED)
  t.is(events.length, 0)
})

test('feed: a message the host already has is not re-emitted, and verify is skipped', async (t) => {
  const msg = feedMsg()
  const host = makeHost({ stored: [msg.hash] })
  const { feed, peers, events } = setup(t, { host })
  t.is(await feed.handle(peers[0], decoded(msg)), FEED_RESULT.DUPLICATE)
  t.is(events.length, 0)
  t.is(host.verifyCalls, 0)
  t.is(peers[1].sent.length, 0)
})

/** Hashes sanitize accepts (strings of at most 64 characters) that the feed refuses. */
const BAD_HASHES = {
  'empty': '',
  'with a quote': "abc' OR '1'='1",
  '64 with a quote': "'".padEnd(64, 'a'),
  '63 hex': 'a'.repeat(63),
  '64 non-hex': 'g'.repeat(64),
  'short': 'x'
}

/** A message whose signature is valid for `hash`, so only the hash check can refuse it. */
function signedWithHash(hash) {
  const m = feedMsg()
  return { ...m, hash, signature: fakeSig(m.message + hash, m.address) }
}

test('feed: invalid messages and hashes never reach the host', async (t) => {
  const { feed, host, peers, events } = setup(t)
  let asked = 0
  host.feedMessageExists = async () => {
    asked++
    return false
  }
  const peer = makePeer(ADDRESS_2)
  for (const [name, hash] of Object.entries(BAD_HASHES)) {
    t.ok(S.feedMessage(signedWithHash(hash)).ok, name + ': sanitize accepts it')
    t.is(await feed.handle(peer, signedWithHash(hash)), FEED_RESULT.INVALID, name + ': refused')
  }
  t.is(await feed.handle(peer, { ...feedMsg(), hash: 'a'.repeat(65) }), FEED_RESULT.INVALID)
  t.is(await feed.handle(peer, { ...feedMsg(), message: 'm'.repeat(778) }), FEED_RESULT.INVALID)
  t.is(await feed.handle(peer, null), FEED_RESULT.INVALID)

  // The same hashes inside a received history.
  const history = { type: 'send-feed-history', messages: Object.values(BAD_HASHES).map(signedWithHash) }
  await feed.handleHistory(peer, decoded(history))

  t.is(asked, 0, 'feedMessageExists never called')
  t.is(host.verifyCalls, 0, 'verify never called')
  t.is(events.length, 0)
  t.is(peers[0].sent.length + peers[1].sent.length + peers[2].sent.length, 0)
})

test('feed: an upper-case hex hash is accepted (and handled in lower case)', async (t) => {
  const { feed, events } = setup(t)
  const m = feedMsg()
  const msg = { ...m, hash: m.hash.toUpperCase() }
  t.is(await feed.handle(makePeer(ADDRESS_2), decoded(msg)), FEED_RESULT.NEW)
  t.is(events.length, 1)
  t.is(events[0].payload.message.hash, m.hash)
  t.is(await feed.handle(makePeer(ADDRESS_3), decoded(m)), FEED_RESULT.DUPLICATE, 'the lower-case copy is the same message')
})

test('feed: every field is signed; a copy with any field changed is not verified', async (t) => {
  const { feed, events, host } = setup(t)
  const m = feedMsg({ reply: 'ab'.repeat(32), tip: { amount: 5, receiver: ADDRESS_3 } })
  const changes = [
    { tip: { amount: 500, receiver: ADDRESS_4 } },
    { tip: false },
    { reply: 'cd'.repeat(32) },
    { nickname: 'Carol' },
    { timestamp: m.timestamp + 1 },
    { message: 'other text' }
  ]
  for (const change of changes) {
    const changed = { ...m, ...change }
    t.is(await feed.handle(makePeer(ADDRESS_3), decoded(changed)), FEED_RESULT.UNVERIFIED, Object.keys(change)[0] + ' changed')
    // with the hash derived again, the signature is what does not verify
    const rehashed = { ...changed, hash: wire.feedMessageHash(changed) }
    t.is(await feed.handle(makePeer(ADDRESS_3), decoded(rehashed)), FEED_RESULT.UNVERIFIED, Object.keys(change)[0] + ' changed, hash derived again')
  }
  t.is(events.length, 0)
  t.is(await feed.handle(makePeer(ADDRESS_3), decoded(m)), FEED_RESULT.NEW, 'the message as signed')
  t.ok(host.verifyCalls >= 1)
})

test('feed: a message whose hash is not derived from its fields is not verified, even when signed', async (t) => {
  const { feed, events } = setup(t)
  const original = feedMsg({ message: 'first' })
  // another author signs its own message under the hash of the first one
  const other = feedMsg({ message: 'second', address: ADDRESS_3 })
  const sameHash = { ...other, hash: original.hash }
  sameHash.signature = fakeSig(wire.feedSigningPayload(sameHash), ADDRESS_3)
  t.is(await feed.handle(makePeer(ADDRESS_3), decoded(sameHash)), FEED_RESULT.UNVERIFIED)
  t.is(events.length, 0)
  t.is(await feed.handle(makePeer(ADDRESS_2), decoded(original)), FEED_RESULT.NEW, 'the message with that hash still gets through')
  t.is(events[0].payload.message.message, 'first')
})

test('feed: history answers leave out rows whose hash is not 64 hex', async (t) => {
  const good = feedMsg()
  const rows = [good, ...Object.values(BAD_HASHES).map(signedWithHash)]
  const host = makeHost({ history: rows })
  const { feed } = setup(t, { host })
  const peer = makePeer(ADDRESS_2)
  await feed.handleRequest(peer, { type: 'request-feed' })
  const answer = JSON.parse(peer.sent[0])
  t.alike(answer.messages.map((m) => m.hash), [good.hash])
})

test('feed: the same message from two peers at once is emitted once', async (t) => {
  const host = makeHost({ verifyDelayMs: 20 })
  const { feed, peers, events } = setup(t, { host })
  const msg = feedMsg()
  const results = await Promise.all([feed.handle(peers[0], decoded(msg)), feed.handle(peers[1], decoded(msg))])
  t.alike(results.slice().sort(), [FEED_RESULT.DUPLICATE, FEED_RESULT.NEW])
  t.is(events.length, 1)
  t.is(host.verifyCalls, 1)
})

test('feed: host hooks that fail never throw out of handle', async (t) => {
  const { feed, host, events } = setup(t)
  host.verify = async () => {
    throw new Error('rpc down')
  }
  t.is(await feed.handle(makePeer(ADDRESS_2), decoded(feedMsg())), FEED_RESULT.ERROR)
  host.feedMessageExists = async () => {
    throw new Error('db down')
  }
  t.is(await feed.handle(makePeer(ADDRESS_2), decoded(feedMsg())), FEED_RESULT.ERROR)
  t.is(events.length, 0)
})

test('feed: gossip off does not forward; a gossip function is read per message', async (t) => {
  const off = setup(t, { gossip: false })
  t.is(await off.feed.handle(off.peers[0], decoded(feedMsg())), FEED_RESULT.NEW)
  t.is(off.events.length, 1, 'still verified and emitted')
  t.is(off.peers[1].sent.length + off.peers[2].sent.length, 0)

  let foreground = false
  const fg = setup(t, { gossip: () => foreground })
  await fg.feed.handle(fg.peers[0], decoded(feedMsg()))
  t.is(fg.peers[1].sent.length, 0, 'background: no forwarding')
  foreground = true
  await fg.feed.handle(fg.peers[0], decoded(feedMsg()))
  t.is(fg.peers[1].sent.length, 1, 'foreground: forwarded')
  t.is(fg.events.length, 2)
})

test('feed: DM peers never get feed traffic', async (t) => {
  const dm = makePeer(ADDRESS_3, { dm: true })
  const room = makePeer(ADDRESS_4)
  const { feed } = setup(t, { peers: [dm, room] })
  await feed.handle(makePeer(ADDRESS_2), decoded(feedMsg()))
  await feed.send({ message: 'hi' })
  t.is(dm.sent.length, 0)
  t.is(room.sent.length, 2)
  feed.onPeerJoined(dm)
  t.is(dm.sent.length, 0, 'no history request in a DM swarm')
})

test('feed: request-feed is answered from host.getFeedHistory, capped, in a shape old peers accept', async (t) => {
  const rows = []
  for (let i = 0; i < 60; i++) {
    const m = feedMsg({ message: 'row ' + i })
    delete m.type
    // desktop rows carry DB columns, native rows have no signature column
    rows.push(i % 2 ? { ...m, read: 0, tip: undefined } : { ...m, signature: undefined })
  }
  rows.splice(3, 0, { ...feedMsg(), nickname: undefined }, { ...feedMsg(), hash: 'a'.repeat(65) })
  const host = makeHost({ history: rows })
  const { feed } = setup(t, { host })
  const peer = makePeer(ADDRESS_2)

  await feed.handleRequest(peer, { type: 'request-feed' })
  t.is(peer.sent.length, 1)
  const answer = JSON.parse(peer.sent[0])
  t.is(answer.type, 'send-feed-history')
  t.is(answer.messages.length, 50, 'capped at 50 (desktop page size)')
  t.is(answer.messages[0].message, 'row 0', 'host order kept (newest first)')
  t.absent(answer.messages.some((m) => 'read' in m), 'no DB columns on the wire')
  t.ok(answer.messages.every((m) => legacy(desktop.sanitize_feed_message, m)), 'every entry passes old desktop')
  t.ok(answer.messages.every((m) => S.feedMessage(m).ok))
  t.ok(wire.decode(peer.sent[0]).type === 'send-feed-history')

  await feed.handleRequest(peer, { type: 'request-feed' })
  t.is(peer.sent.length, 1, 'asked again right away on the same connection: not answered twice')
  t.is(host.historyCalls, 1)

  const other = makePeer(ADDRESS_3)
  host.blocked.add(ADDRESS_3)
  await feed.handleRequest(other, { type: 'request-feed' })
  t.is(other.sent.length, 0, 'blocked users get no answer (native)')
})

test('feed: maxHistory option caps the answer', async (t) => {
  const host = makeHost({ history: [feedMsg(), feedMsg(), feedMsg()] })
  const { feed } = setup(t, { host, maxHistory: 2 })
  const peer = makePeer(ADDRESS_2)
  await feed.handleRequest(peer, {})
  t.is(JSON.parse(peer.sent[0]).messages.length, 2)
})

test('feed: received history is verified and deduped per entry, emitted, never gossiped', async (t) => {
  const stored = feedMsg({ message: 'already stored' })
  const host = makeHost({ stored: [stored.hash] })
  const { feed, peers, events } = setup(t, { host, requestSpacingMs: 0 })
  const m1 = feedMsg({ message: 'one' })
  const m2 = feedMsg({ message: 'two', address: ADDRESS_3 })
  const otherSigner = { ...feedMsg({ message: 'otherSigner' }), signature: 'sig0' }
  const unsigned = { ...feedMsg({ message: 'unsigned' }), signature: '' }
  const history = decoded({ type: 'send-feed-history', messages: [m1, m2, m1, otherSigner, unsigned, stored] })

  // history is taken only as the answer to our request
  feed.onPeerJoined(peers[0])
  t.alike(kinds(peers[0]), ['request-feed'])
  await feed.handleHistory(peers[0], history)
  t.alike(events.map((e) => e.payload.message.message), ['one', 'two'])
  t.alike(events.map((e) => e.payload.live), [false, false], 'history entries are not live')
  t.is(peers[1].sent.length + peers[2].sent.length + peers[0].sent.length - 1, 0, 'history is never gossiped')

  // Live copy of a history message afterwards: duplicate.
  t.is(await feed.handle(peers[1], decoded(m1)), FEED_RESULT.DUPLICATE)

  // Entries beyond maxHistory are not looked at.
  const many = []
  for (let i = 0; i < 55; i++) many.push(feedMsg({ message: 'h' + i }))
  feed.onPeerJoined(peers[1])
  t.alike(kinds(peers[1]), ['request-feed'])
  await feed.handleHistory(peers[1], { type: 'send-feed-history', messages: many })
  t.is(events.length, 2 + 50)
})

test('feed: send-feed-history is taken only from the connection asked, once', async (t) => {
  const { feed, peers, events } = setup(t, { requestSpacingMs: 0, requestTimeoutMs: 60000 })
  const [a, b] = peers
  const history = () => decoded({ type: 'send-feed-history', messages: [feedMsg()] })

  await feed.handleHistory(a, history())
  t.is(events.length, 0, 'nobody asked: ignored')

  feed.onPeerJoined(a)
  t.alike(kinds(a), ['request-feed'])
  await feed.handleHistory(b, history())
  t.is(events.length, 0, 'another connection than the one asked: ignored')
  t.is(feed.queued, 1, 'the request to a is still in flight')

  await feed.handleHistory(a, history())
  t.is(events.length, 1, 'the answer of the connection asked is taken')
  await feed.handleHistory(a, history())
  t.is(events.length, 1, 'a second answer is ignored')
})

test('feed: a message timestamped too far ahead is dropped (the timestamp is signed); isBlocked may be async', async (t) => {
  const host = makeHost()
  host.isBlocked = async (address) => address === ADDRESS_3
  const { feed, events } = setup(t, { host })
  const ahead = feedMsg({ timestamp: Date.now() + 365 * 24 * 60 * 60 * 1000 })
  t.is(await feed.handle(makePeer(ADDRESS_2), decoded(ahead)), FEED_RESULT.INVALID)
  t.is(events.length, 0)
  const soon = feedMsg({ timestamp: Date.now() + 30 * 1000 })
  t.is(await feed.handle(makePeer(ADDRESS_2), decoded(soon)), FEED_RESULT.NEW, 'within the clock skew')
  t.is(events[0].payload.message.timestamp, soon.timestamp, 'kept as signed')

  const blocked = makePeer(ADDRESS_3)
  await feed.handleRequest(blocked, { type: 'request-feed' })
  t.is(blocked.sent.length, 0, 'an async isBlocked is awaited')
})

test('feed: a long nickname is cut, not refused', async (t) => {
  const host = makeHost()
  host.identity = () => ({ address: ADDRESS, name: 'n'.repeat(80), avatar: '' })
  const { feed } = setup(t, { host })
  const out = await feed.send({ message: 'hi' })
  t.is(out.nickname, 'n'.repeat(50))
})

test('feed: history request queue asks one peer at a time, spaced, and drops peers that left', async (t) => {
  const p1 = makePeer(ADDRESS_2)
  const p2 = makePeer(ADDRESS_3)
  const p3 = makePeer(ADDRESS_4)
  const { feed } = setup(t, { peers: [p1, p2, p3], requestSpacingMs: 40 })

  feed.onPeerJoined(p1)
  feed.onPeerJoined(p2)
  feed.onPeerJoined(p3)
  feed.onPeerJoined(p2) // already queued
  t.alike(kinds(p1), ['request-feed'], 'first peer asked at once')
  t.is(p2.sent.length + p3.sent.length, 0, 'not every peer at once')
  t.is(feed.queued, 3)

  const answeredAt = Date.now()
  await feed.handleHistory(p1, { type: 'send-feed-history', messages: [] })
  await sleep(10)
  t.is(p2.sent.length, 0, 'next request waits for the spacing')
  await waitFor(t, () => p2.sent.length === 1, 2000, 'second request')
  t.ok(Date.now() - answeredAt >= 30, 'spaced after the previous answer')
  t.alike(kinds(p2), ['request-feed'])
  t.is(p3.sent.length, 0, 'still one at a time')

  p3.gone = true
  feed.onPeerLeft(p3)
  t.is(feed.queued, 1, 'only the request in flight is left')
  await feed.handleHistory(p2, { type: 'send-feed-history', messages: [] })
  await sleep(100)
  t.is(p3.sent.length, 0, 'a peer that left is not asked')
  t.is(feed.queued, 0)

  feed.onPeerJoined(p1)
  t.is(p1.sent.length, 1, 'the same address is not asked again soon after (other rooms)')
})

test('feed: an unanswered request times out and the queue moves on', async (t) => {
  const p1 = makePeer(ADDRESS_2)
  const p2 = makePeer(ADDRESS_3)
  const { feed } = setup(t, { peers: [p1, p2], requestTimeoutMs: 50, requestSpacingMs: 0 })
  feed.onPeerJoined(p1)
  feed.onPeerJoined(p2)
  t.is(p2.sent.length, 0)
  await waitFor(t, () => p2.sent.length === 1, 2000, 'request after the timeout')
  t.alike(kinds(p2), ['request-feed'])
})

test('feed: a peer leaving while its request is in flight releases the queue', async (t) => {
  const p1 = makePeer(ADDRESS_2)
  const p2 = makePeer(ADDRESS_3)
  const { feed } = setup(t, { peers: [p1, p2], requestTimeoutMs: 60000, requestSpacingMs: 0 })
  feed.onPeerJoined(p1)
  feed.onPeerJoined(p2)
  p1.gone = true
  feed.onPeerLeft(p1)
  await waitFor(t, () => p2.sent.length === 1, 2000, 'next request')
})

test('feed: a queued request moves to another connection of the same address', async (t) => {
  const p1 = makePeer(ADDRESS_2)
  const p2 = makePeer(ADDRESS_3, { key: 'room1' })
  const p2b = makePeer(ADDRESS_3, { key: 'room2' })
  const { feed } = setup(t, { peers: [p1, p2, p2b], requestSpacingMs: 0 })
  feed.onPeerJoined(p1)
  feed.onPeerJoined(p2)
  feed.onPeerJoined(p2b) // same address: not queued twice
  p2.gone = true
  feed.onPeerLeft(p2)
  await feed.handleHistory(p1, { type: 'send-feed-history', messages: [] })
  await waitFor(t, () => p2b.sent.length === 1, 2000, 'request on the other connection')
  t.is(p2.sent.length, 0)
})

test('feed: send signs via the host, broadcasts, and passes the validators', async (t) => {
  const { feed, host, peers, events } = setup(t)
  const out = await feed.send({ message: 'hello world', reply: '', tip: false })

  t.is(out.type, 'feed')
  t.ok(S.isHex64(out.hash))
  t.is(out.address, ADDRESS)
  t.is(out.nickname, 'Alice')
  t.is(typeof out.timestamp, 'number')
  t.is(out.hash, wire.feedMessageHash(out), 'the hash is derived from the message')
  t.alike(host.signCalls, [wire.feedSigningPayload(out)], 'signs the hugin/feed payload')
  t.ok(host.signCalls[0].startsWith('hugin/feed\n'))
  t.is(out.signature, fakeSig(wire.feedSigningPayload(out), ADDRESS))
  t.is(events.length, 0, 'own messages are not emitted (the host keeps what it sent)')

  for (const p of peers) {
    t.is(p.sent.length, 1)
    t.is(p.sent[0], wire.encode(out))
    const parsed = JSON.parse(p.sent[0])
    const r = S.inspect(parsed)
    t.ok(r.ok && r.kind === 'feed', 'new validator accepts it')
    t.ok(legacy(desktop.sanitize_feed_message, parsed), 'old desktop accepts it')
  }

  // Our own message echoed back by gossip: not emitted again.
  t.is(await feed.handle(peers[0], decoded(out)), FEED_RESULT.DUPLICATE)

  const withTip = await feed.send({ message: 'tip', reply: 'f'.repeat(64), tip: { amount: 5, receiver: ADDRESS_2 } })
  t.alike(withTip.tip, { amount: 5, receiver: ADDRESS_2 })
  t.ok(legacy(desktop.sanitize_feed_message, JSON.parse(peers[0].sent[1])))

  const signs = host.signCalls.length
  await t.exception(feed.send({ message: 'm'.repeat(778) }), /message/)
  await t.exception(feed.send({ message: 'x', reply: 'r'.repeat(65) }), /reply/)
  t.is(host.signCalls.length, signs, 'nothing is signed when the message would be refused')
})

test('feed: destroy clears the queue and its timers', async (t) => {
  const p1 = makePeer(ADDRESS_2)
  const p2 = makePeer(ADDRESS_3)
  const { feed, events } = setup(t, { peers: [p1, p2], requestTimeoutMs: 60000, requestSpacingMs: 60000 })
  feed.onPeerJoined(p1)
  feed.onPeerJoined(p2)
  t.is(feed.queued, 2)
  feed.destroy()
  t.is(feed.queued, 0)
  feed.onPeerJoined(makePeer(ADDRESS_4))
  t.is(feed.queued, 0, 'nothing queued after destroy')
  t.is(await feed.handle(p1, decoded(feedMsg())), FEED_RESULT.ERROR)
  t.is(events.length, 0)
  await t.exception(feed.send({ message: 'late' }), /destroyed/)
  // The test ends without waiting for the 60 s timers: they were cleared.
})
