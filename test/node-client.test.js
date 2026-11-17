'use strict'

// hugin-network/node: the bare-rpc framing (lib/rpc.js), the NodeClient state machine against an
// in-memory fake hugin-node, and end to end on a local DHT testnet.

const test = require('brittle')
const b4a = require('b4a')
const sodium = require('sodium-universal')
const createTestnet = require('hyperdht/testnet.js')
const rpc = require('../lib/rpc.js')
const pow = require('../lib/pow.js')
const { NodeClient, PRESETS, NO_CONNECTION } = require('../lib/node-client.js')
const hugin = require('../index.js')
const { NETWORK_ADDRESS, NODE_RPC_REPLY } = require('../lib/constants.js')
const { keyPairFromSeed } = require('../lib/swarm.js')
const { FakeHuginNode, socketPair, fakeSwarmFactory } = require('./fixtures/fake-hugin-node.js')
const V = require('./fixtures/hugin-relay.json')
const { REFERENCE_VECTOR } = require('hugin-pow')
const { ADDRESS, hex } = require('./helpers.js')

const JOB = V.pow.job // target ffffffff: every hash meets it

/**
 * Stand-in for CN-Turtle-Lite v2 (deterministic, so the fake node can check shares). It gives
 * hugin-pow's reference answer, which every backend with `hash` must give before it mines.
 */
async function stubHash(blobHex) {
  if (blobHex === REFERENCE_VECTOR.blob) return REFERENCE_VECTOR.hash
  const out = b4a.alloc(32)
  sodium.crypto_generichash(out, b4a.from(blobHex, 'hex'))
  return hex(out)
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms))

function noop() {}

/**
 * Polls `fn` until it is true; resolves true, or false after `ms` (recording a failed
 * assertion). Never rejects: brittle treats an error thrown out of a test function as a crash of
 * the whole run, so a timeout must be an assertion, not an exception. Stops when the test ends.
 */
function waitFor(t, fn, ms = 10000, label = 'condition') {
  let stopped = false
  t.teardown(() => {
    stopped = true
  })
  return (async () => {
    const start = Date.now()
    try {
      while (!fn()) {
        if (stopped) return false
        if (Date.now() - start > ms) {
          t.fail('timeout waiting for ' + label)
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

/** Payload a timed-out `once` resolves with: property reads give undefined instead of throwing. */
const TIMED_OUT = Object.freeze({ timedOut: true })

/**
 * Next `name` event of `emitter`. Never rejects (see waitFor): after `ms` it records a failed
 * assertion and resolves `TIMED_OUT`. Listener and timer are removed when the test ends.
 */
function once(t, emitter, name, ms = 20000) {
  let cleanup = noop
  const promise = new Promise((resolve) => {
    const timer = setTimeout(() => {
      cleanup()
      t.fail('timeout waiting for ' + name)
      resolve(TIMED_OUT)
    }, ms)
    const on = (payload) => {
      cleanup()
      resolve(payload)
    }
    cleanup = () => {
      clearTimeout(timer)
      emitter.off(name, on)
    }
    emitter.on(name, on)
  })
  t.teardown(() => cleanup())
  return promise
}

const EVENTS = ['node:connected', 'node:disconnected', 'node:address', 'node:messages', 'node:job', 'node:pow-required', 'node:error', 'node:reset']

function record(client) {
  const events = []
  for (const name of EVENTS) client.on(name, (payload) => events.push([name, payload]))
  events.names = () => events.map((e) => e[0])
  return events
}

/** A NodeClient on fake swarms, connected to a fake node on the public topic. */
async function connectedPair(t, opts = {}, { job = JOB, pool = [] } = {}) {
  const swarms = []
  const client = new NodeClient({ createSwarm: fakeSwarmFactory(swarms), hash: stubHash, ...opts })
  const events = record(client)
  await client.connect({ publicNode: true })
  const node = new FakeHuginNode({ address: ADDRESS, hash: stubHash, job, pool })
  const connected = once(t, client, 'node:connected')
  const link = swarms[0].dial(node, b4a.alloc(32, 9))
  await connected
  return { client, node, swarms, link, events }
}

// =============================================================================================
// framing

test('rpc: frames are byte-identical to bare-rpc 1.3.3 (hugin-relay vectors)', (t) => {
  for (const v of V.rpc) {
    const bytes = b4a.from(v.hex, 'hex')
    const body = bytes.subarray(4)
    if (v.name.startsWith('request') || v.name === 'event') {
      t.is(hex(rpc.encodeRequest({ id: v.id, command: v.command, data: v.data })), v.hex, v.name)
      const m = rpc.decodeBody(body)
      t.is(m.type, rpc.TYPE.REQUEST)
      t.is(m.id, v.id)
      t.is(m.command, v.command)
      t.is(b4a.toString(m.data), v.data, v.name + ' decodes')
    } else if (v.name === 'response_ok') {
      t.is(hex(rpc.encodeResponse({ id: v.id, data: v.data })), v.hex, v.name)
      const m = rpc.decodeBody(body)
      t.is(m.type, rpc.TYPE.RESPONSE)
      t.is(m.error, null)
      t.is(b4a.toString(m.data), v.data)
      const req = rpc.decodeBody(b4a.from(v.request_hex, 'hex').subarray(4))
      t.is(hex(rpc.encodeRequest({ id: req.id, command: req.command, data: req.data })), v.request_hex, 'the sync request of the vector')
      t.is(v.data, NODE_RPC_REPLY, 'the reply both apps and hugin-node send')
    } else if (v.name === 'response_error') {
      t.is(hex(rpc.encodeResponse({ id: v.id, error: { message: v.message, code: v.code, errno: v.errno } })), v.hex, v.name)
      const m = rpc.decodeBody(body)
      t.alike(m.error, { message: v.message, code: v.code, errno: v.errno })
    } else if (v.name === 'two_requests_split') {
      // every split point of the two coalesced frames gives the same two requests
      for (let cut = 0; cut <= bytes.byteLength; cut++) {
        const dec = new rpc.FrameDecoder()
        const bodies = [...dec.push(bytes.subarray(0, cut)), ...dec.push(bytes.subarray(cut))]
        const msgs = bodies.map(rpc.decodeBody)
        t.alike(msgs.map((m) => m.id), v.ids)
        t.alike(msgs.map((m) => b4a.toString(m.data)), v.data)
        t.is(dec.buffered, 0)
      }
    }
  }
})

test('rpc: frame limit, request/response matching by id, events, close and malformed frames', async (t) => {
  const dec = new rpc.FrameDecoder({ maxFrameBytes: 10 })
  t.exception(() => dec.push(b4a.from('0b000000', 'hex')), /exceeds the limit/)
  t.exception(() => rpc.decodeBody(b4a.from('0901', 'hex')), /unknown message type/)

  const [a, b] = socketPair()
  const seen = []
  const held = []
  const server = new rpc.RpcChannel(b, (req) => {
    seen.push([req.id, req.command, b4a.toString(req.data)])
    if (req.isEvent || b4a.toString(req.data) === 'never') return
    held.push(req)
    if (held.length === 2) {
      held[1].reply('second') // out of order
      held[0].reply('first')
    }
  })
  const client = new rpc.RpcChannel(a, null)
  const p1 = client.request(1, 'x')
  const p2 = client.request(1, 'y')
  t.ok(client.event(1, 'e'))
  t.is(b4a.toString(await p1), 'first', 'matched by id')
  t.is(b4a.toString(await p2), 'second')
  t.alike(seen, [
    [1, 1, 'x'],
    [2, 1, 'y'],
    [0, 1, 'e']
  ], 'ids count from 1, an event has id 0')

  // the client answers the server's requests through its own handler (none: an empty reply)
  t.is((await server.request(1, 'ping')).byteLength, 0)

  // a request still waiting when the stream closes is rejected
  const p3 = client.request(1, 'never')
  await waitFor(t, () => seen.length === 4)
  a.destroy()
  await t.exception(() => p3, /channel closed/)
  await waitFor(t, () => server.closed)
  await t.exception(() => client.request(1, 'late'), /channel closed/)
  t.absent(client.event(1, 'late'))

  // a malformed frame fails the channel and destroys the stream
  const [c] = socketPair()
  const errors = []
  const ch = new rpc.RpcChannel(c, null, { onerror: (err) => errors.push(err) })
  c.deliverRaw(b4a.from('030000000901' + '00', 'hex'))
  await waitFor(t, () => c.destroyed)
  t.ok(ch.closed)
  t.is(errors[0]?.code, 'HUGIN_RPC_UNKNOWN_MESSAGE')

  // a remote error answer rejects the request
  const [d, e] = socketPair()
  const thrower = new rpc.RpcChannel(e, () => {
    throw Object.assign(new Error('nope'), { code: 'E_NOPE', errno: -2 })
  })
  const asker = new rpc.RpcChannel(d, null)
  await t.exception(() => asker.request(1, 'x'), /nope/)
  thrower.destroy()
  await waitFor(t, () => asker.closed)
})

// =============================================================================================
// NodeClient on fake swarms

test('exports and presets', (t) => {
  t.is(hugin.NodeClient, NodeClient)
  t.is(hugin.node.NodeClient, NodeClient)
  t.alike(
    [PRESETS.desktop.maxPeers, PRESETS.desktop.keepBackups, PRESETS.desktop.refreshIntervalMs, PRESETS.desktop.maxReconnectTries, PRESETS.desktop.fallbackToPublic, PRESETS.desktop.syncTimeoutMs],
    [1, false, 10000, Infinity, false, 2000]
  )
  t.alike(
    [PRESETS.native.maxPeers, PRESETS.native.keepBackups, PRESETS.native.refreshIntervalMs, PRESETS.native.maxReconnectTries, PRESETS.native.fallbackToPublic],
    [3, true, 2000, 4, false]
  )
  t.alike(PRESETS.desktop.poll, { intervalMs: 15000, initialDelayMs: 5000, advanceSkewMs: 1000, rewindOnConnectMs: 30000, maxRuns: Infinity })
  t.alike(PRESETS.native.poll, { intervalMs: 3000, initialDelayMs: 3000, advanceSkewMs: 0, rewindOnConnectMs: 0, maxRuns: 10 })
  const c = new NodeClient({ preset: 'native', refreshIntervalMs: 5, poll: { maxRuns: 2 } })
  t.is(c.options.refreshIntervalMs, 5)
  t.is(c.options.maxPeers, 3)
  t.is(c.options.poll.maxRuns, 2)
  t.is(c.options.poll.intervalMs, 3000)
  t.is(c.state, 'idle')
  t.exception.all(() => new NodeClient({ preset: 'other' }), /unknown preset/)
})

test('connect: client-only join, presets select maxPeers, private invite firewall, change()', async (t) => {
  const swarms = []
  const client = new NodeClient({ createSwarm: fakeSwarmFactory(swarms), hash: stubHash })
  t.teardown(() => client.destroy())
  const events = record(client)

  await client.connect({ publicNode: true })
  t.is(swarms[0].opts.key, NETWORK_ADDRESS)
  t.is(swarms[0].opts.maxPeers, 1, 'desktop: one node connection')
  t.alike(swarms[0].joins[0].opts, { server: false, client: true })
  t.is(swarms[0].opts.firewall(b4a.alloc(32, 5)), false, 'public topic: any node')
  t.is(client.state, 'connecting')

  const node = new FakeHuginNode({ address: ADDRESS, hash: stubHash, job: JOB })
  const connected = once(t, client, 'node:connected')
  const address = once(t, client, 'node:address')
  swarms[0].dial(node, b4a.alloc(32, 9))
  t.alike(await connected, { remotePublicKey: hex(b4a.alloc(32, 9)), backup: false, publicNode: true })
  t.alike(await address, { address: ADDRESS, version: '2.0.0' })
  t.is(client.address, ADDRESS, 'the node address (desktop pays node upgrades to it)')
  t.is(client.state, 'connected')

  // a private node: only the key in the invite is admitted
  const invited = keyPairFromSeed(b4a.alloc(32, 31)).publicKey
  const invite = ADDRESS + hex(invited)
  await client.change(invite)
  t.ok(swarms[0].destroyed, 'old swarm destroyed')
  t.is(swarms[0].left, 1, 'and its topic left')
  t.alike(events.find((e) => e[0] === 'node:disconnected')?.[1], { reason: 'change', remotePublicKey: hex(b4a.alloc(32, 9)) })
  t.absent(client.connected)
  t.is(client.address, null)
  t.is(swarms[1].opts.key, invite)
  t.is(swarms[1].dial(node, b4a.alloc(32, 8)), null, 'firewall refuses another node')
  t.is(swarms[1].firewalled.length, 1)
  const again = once(t, client, 'node:connected')
  t.ok(swarms[1].dial(node, invited), 'the invited node connects')
  t.is((await again).publicNode, false)

  // native preset: three peers
  const swarms2 = []
  const native = new NodeClient({ preset: 'native', createSwarm: fakeSwarmFactory(swarms2), hash: stubHash })
  t.teardown(() => native.destroy())
  await native.connect({ address: invite })
  t.is(swarms2[0].opts.maxPeers, 3)
  await native.connect({ pub: true }) // connecting again replaces the node, like change()
  t.ok(swarms2[0].destroyed)
  t.is(swarms2[1].opts.key, NETWORK_ADDRESS)

  await t.exception.all(() => client.connect({}), /address/)
  await t.exception.all(() => client.change({ address: '' }), /address/)
})

test('sync: round trip, numeric timestamp, chunks, timeout, no connection, shared in-flight request', async (t) => {
  const pool = [
    { cipher: 'aa', hash: 'a1'.repeat(32), timestamp: 100 },
    { cipher: 'bb', hash: 'b2'.repeat(32), timestamp: 200 },
    { cipher: 'cc', hash: 'c3'.repeat(32), timestamp: 300 }
  ]
  const { client, node } = await connectedPair(t, {}, { pool })
  t.teardown(() => client.destroy())

  t.alike(await client.sync({ since: 150 }), pool.slice(1))
  t.alike(node.received.at(-1), { request: true, type: 'some', timestamp: 150, id: 150 })
  t.alike(await client.sync(), pool)
  t.alike(node.received.at(-1), { request: true, type: 'some', timestamp: 0, id: 0 }, 'never without a timestamp')
  t.is(node.banned, 0)

  node.chunkSize = 2
  t.alike(await client.sync({ since: 0 }), pool, 'chunked answer flattened')
  node.chunkSize = 0

  const p1 = client.sync({ since: 5 })
  t.is(client.sync({ since: 5 }), p1, 'same id in flight: one request')
  await p1

  node.answerSync = false
  const start = Date.now()
  t.alike(await client.sync({ since: 1, timeoutMs: 50 }), [], 'timeout -> []')
  t.ok(Date.now() - start < 1500)
  t.is(client.requests.size, 0, 'the timed-out request is forgotten')

  const idle = new NodeClient({ createSwarm: fakeSwarmFactory([]) })
  t.alike(await idle.sync({ since: 1 }), [], 'no connection -> []')
})

test('sync: only well-formed messages with known fields, at most 500 also when chunked', async (t) => {
  const good = { cipher: 'aa', hash: 'a1'.repeat(32), timestamp: 100 }
  const pool = [
    { ...good, pow: { shares: [] }, id: 100, push: true, viewtag: 'abc', kind: 'dm' },
    { cipher: 'bb', hash: 'b2', timestamp: 200 },
    { cipher: 'xyz', hash: 'c3'.repeat(32), timestamp: 300 },
    { cipher: 'dd', hash: 'd4'.repeat(32), timestamp: '400' },
    { cipher: 'ee'.repeat(4501), hash: 'e5'.repeat(32), timestamp: 500 }
  ]
  const { client, node } = await connectedPair(t, {}, { pool })
  t.teardown(() => client.destroy())
  t.alike(await client.sync({ since: 0 }), [{ ...good, viewtag: 'abc', kind: 'dm' }], 'known fields only; malformed entries dropped')

  // a node that sends more than 500 in chunks: the answer ends at 500
  node.answerSync = false
  const many = Array.from({ length: 300 }, (_, i) => ({ cipher: 'ab', hash: i.toString(16).padStart(64, '0'), timestamp: 1000 + i }))
  const pending = client.sync({ since: 7 })
  await waitFor(t, () => node.received.some((p) => p.request && p.id === 7), 2000, 'sync request')
  const c = node.clients[0]
  node.send(c, { response: many, id: 7, chunks: true })
  node.send(c, { response: many, id: 7, chunks: true })
  node.send(c, { response: many, id: 7, chunks: true })
  const got = await pending
  t.is(got.length, 500, 'capped at 500, without waiting for done')
  t.is(client.requests.size, 0)
})

test('post and register with PoW (stub hash), share recalculation, pushed jobs and messages', async (t) => {
  const { client, node, events } = await connectedPair(t)
  t.teardown(() => client.destroy())

  const res = await client.post({ cipher: 'cd'.repeat(40), viewtag: 'abc', kind: 'dm' })
  t.is(res.success, true)
  t.is(node.accepted.length, 1)
  const m = node.accepted[0].message
  t.is(res.id, m.id)
  t.is(m.cipher, 'cd'.repeat(40))
  t.is(m.kind, 'dm')
  t.is(m.viewtag, 'abc')
  t.is(m.push, true)
  t.is(m.id, m.timestamp)
  t.is(m.hash.length, 64)
  t.is(m.pow.version, 2)
  t.alike(m.pow.job, JOB)
  t.ok(pow.verifyPowAuth({ auth: m.pow.auth, hash: m.hash, timestamp: m.timestamp, shares: m.pow.shares, context: 'dm:' + m.cipher }))
  t.ok(node.received.findIndex((p) => p.type === 'job_request') < node.received.findIndex((p) => p.type === 'post'), 'job requested first')
  t.alike(events.filter((e) => e[0] === 'node:job').map((e) => e[1].job), [JOB], 'node:job once per new job')

  const data = JSON.stringify(['sealed'])
  const reg = await client.register(data)
  t.is(reg.success, true)
  t.is(node.accepted[1].type, 'register')
  t.is(node.accepted[1].data.register, true)
  t.is(node.accepted[1].data.data, data)

  // a refused share is recalculated without using up an attempt
  const posts = node.received.filter((p) => p.type === 'post').length
  node.script.push('stale')
  const res2 = await client.post({ cipher: 'ab'.repeat(10), hash: 'ef'.repeat(32), kind: 'call' })
  t.is(res2.success, true)
  t.is(node.received.filter((p) => p.type === 'post').length, posts + 2)
  t.is(node.accepted.at(-1).message.hash, 'ef'.repeat(32), 'the hash stays the same across retries')

  // a job the node pushes
  const pushedJob = once(t, client, 'node:job')
  node.setJob({ ...JOB, job_id: 'job-2' })
  t.is((await pushedJob).job?.job_id, 'job-2')
  t.is(client.jobs.current.job_id, 'job-2')

  // messages the node pushes: only well-formed ones, known fields only; nothing for none
  const before = events.filter((e) => e[0] === 'node:messages').length
  node.pushMessages([{ hash: 'x', timestamp: 1 }])
  const pushed = once(t, client, 'node:messages')
  const ok = { cipher: 'ab', hash: 'ab'.repeat(32), timestamp: 1 }
  node.pushMessages([{ hash: 'x', timestamp: 1 }, { ...ok, pow: {}, extra: 1 }])
  t.alike(await pushed, { messages: [ok], source: 'push' })
  t.is(events.filter((e) => e[0] === 'node:messages').length, before + 1, 'a batch without valid messages emits nothing')

  // invalid input is refused before any work; a client without a PoW backend refuses posts
  await t.exception(() => client.post({ cipher: 'xyz' }), /cipher/)
  await t.exception(() => client.post({ cipher: 'abcd', kind: 'other' }), /kind/)
  await t.exception.all(() => client.register(5), /data must be a string/)
  const nohash = new NodeClient({ createSwarm: fakeSwarmFactory([]) })
  await t.exception.all(() => nohash.post({ cipher: 'abcd' }), /hash/)
})

test('a findShare backend (kryptokrona-crypto findPowShare shape) mines the job the node handed out', async (t) => {
  const seen = []
  const findShare = async (req) => {
    seen.push(req)
    const share = await pow.findShare({ job: { job_id: 'x', blob: req.blobHex, target: req.targetHex }, hash: stubHash, startNonce: req.startNonce, maxAttempts: 1 })
    return share ? { nonce: share.nonce, result: share.result, hashes_performed: 1, threads: 1 } : null
  }
  const { client, node } = await connectedPair(t, { hash: undefined, findShare })
  t.teardown(() => client.destroy())
  t.is(client.backend.findShare, findShare)
  t.absent(client.backend.hash, 'no hash: shares are checked against the target only')

  const res = await client.post({ cipher: 'cd'.repeat(40), kind: 'dm' })
  t.is(res.success, true)
  t.is(seen.length, 1)
  t.is(seen[0].blobHex, JOB.blob)
  t.is(seen[0].targetHex, JOB.target)
  t.ok(Number.isInteger(seen[0].startNonce) && seen[0].maxAttempts > 0)
  const m = node.accepted[0].message
  t.alike(m.pow.job, { job_id: JOB.job_id, blob: JOB.blob, target: JOB.target })
  t.ok(await pow.verifyShare(m.pow.job, m.pow.shares[0].nonce, m.pow.shares[0].result, stubHash))

  // a backend object is used as it is; posts run their share searches one at a time
  const backend = { findShare }
  const other = await connectedPair(t, { hash: undefined, backend })
  t.teardown(() => other.client.destroy())
  t.is(other.client.backend, backend)
  const both = await Promise.all([other.client.post({ cipher: 'aa', kind: 'dm' }), other.client.post({ cipher: 'bb', kind: 'dm' })])
  t.ok(both.every((r) => r.success === true))
  t.is(other.client.activePow, 0)
})

test('jobs: job_pending then the pushed job; no job at all -> node:pow-required and "PoW required"', async (t) => {
  const { client, node, events } = await connectedPair(t, { jobWaitMs: 2000 }, { job: null })
  t.teardown(() => client.destroy())

  node.once('packet', (p) => {
    if (p.type === 'job_request') setTimeout(() => node.setJob(JOB), 20)
  })
  t.alike(await client.getJob(), JOB, 'waited for the job pushed after job_pending')

  const { client: c2, events: ev2 } = await connectedPair(t, { jobWaitMs: 20, powMaxJobTimeMs: 150 }, { job: null })
  t.teardown(() => c2.destroy())
  const res = await c2.post({ cipher: 'abcd' })
  t.alike(res, { success: false, reason: 'PoW required' })
  const required = ev2.filter((e) => e[0] === 'node:pow-required')
  t.is(required.length, 3, 'one per attempt')
  t.is(required[0]?.[1].kind, 'post')
  t.is(required[0]?.[1].attempt, 1)
  t.absent(events.names().includes('node:pow-required'))
})

test('desktop preset: one connection, refresh every interval until reconnected, no post without a connection', async (t) => {
  const { client, node, swarms, link, events } = await connectedPair(t, { refreshIntervalMs: 30 })
  t.teardown(() => client.destroy())

  const extra = swarms[0].dial(node, b4a.alloc(32, 10))
  t.ok(extra.local.destroyed, 'a second connection is closed')
  t.is(client.backups.length, 0)
  t.is(client.remotePublicKey, hex(b4a.alloc(32, 9)))

  const lost = once(t, client, 'node:disconnected')
  link.remote.destroy()
  t.is((await lost).reason, 'close')
  await waitFor(t, () => swarms[0].refreshes >= 2)
  t.is(client.state, 'connecting')

  t.alike(await client.post({ cipher: 'abcd' }), { success: false, reason: NO_CONNECTION }, 'fails at once (desktop)')
  t.alike(await client.sync({ since: 0 }), [])

  const back = once(t, client, 'node:connected')
  swarms[0].dial(node, b4a.alloc(32, 9))
  t.is((await back).backup, false)
  const n = swarms[0].refreshes
  await sleep(100)
  t.is(swarms[0].refreshes, n, 'the loop stops once connected')
  t.ok(events.names().includes('node:disconnected'))
  t.is((await client.post({ cipher: 'abcd' })).success, true, 'posts again on the new connection')

  // a new connection that arrives while the old one is closing (destroyed, 'close' not yet
  // emitted) replaces it instead of being refused as a second connection
  const old = client.connection
  const replaced = once(t, client, 'node:connected')
  old.destroy()
  const fresh = swarms[0].dial(node, b4a.alloc(32, 11))
  t.is((await replaced).remotePublicKey, hex(b4a.alloc(32, 11)))
  t.absent(fresh.local.destroyed)
  t.is(client.connection, fresh.local)
  await sleep(20) // the old connection's 'close' arrives now and must not detach the new one
  t.is(client.connection, fresh.local)
  t.is(client.state, 'connected')
})

test('native preset: backups promoted on failure; with fallbackToPublic, reset to the public topic after 4 refreshes', async (t) => {
  const swarms = []
  const client = new NodeClient({ preset: 'native', createSwarm: fakeSwarmFactory(swarms), hash: stubHash, refreshIntervalMs: 20, fallbackToPublic: true })
  t.teardown(() => client.destroy())
  const events = record(client)
  await client.connect({ publicNode: true })

  const nodes = [0, 1, 2, 3].map((i) => new FakeHuginNode({ address: ADDRESS, hash: stubHash, job: JOB, pool: [{ cipher: 'aa', hash: ('0' + i).repeat(32), timestamp: 10 + i }] }))
  const first = once(t, client, 'node:connected')
  const links = nodes.map((node, i) => swarms[0].dial(node, b4a.alloc(32, 20 + i)))
  await first
  t.is(client.remotePublicKey, hex(b4a.alloc(32, 20)))
  t.is(client.backups.length, 2, 'two backups (maxPeers 3)')
  t.ok(links[3].local.destroyed, 'a fourth connection is closed')

  const promoted = once(t, client, 'node:connected')
  links[0].remote.destroy()
  const p = await promoted
  t.is(p.backup, true)
  t.is(p.remotePublicKey, hex(b4a.alloc(32, 21)), 'the oldest backup, like native')
  t.alike(await client.sync({ since: 0 }), nodes[1].pool, 'the promoted connection carries requests')
  t.is(swarms[0].refreshes, 0, 'no discovery refresh needed')

  // a private node that goes away: 4 refreshes, then the public topic
  const invited = keyPairFromSeed(b4a.alloc(32, 31)).publicKey
  await client.change(ADDRESS + hex(invited))
  const priv = new FakeHuginNode({ address: ADDRESS, hash: stubHash, job: JOB })
  const up = once(t, client, 'node:connected')
  const link = swarms[1].dial(priv, invited)
  await up
  const reset = once(t, client, 'node:reset', 5000)
  link.remote.destroy()
  t.alike(await reset, { from: { address: ADDRESS + hex(invited), publicNode: false }, publicNode: true, reason: 'fallback' })
  t.is(swarms[1].refreshes, 4)
  t.ok(swarms[1].destroyed)
  t.is(swarms[2].opts.key, NETWORK_ADDRESS)
  t.is(client.target.publicNode, true)
  t.ok(events.names().includes('node:reset'))
})

test('native preset: a private node stays the target after the refreshes (fallbackToPublic off by default)', async (t) => {
  const swarms = []
  const client = new NodeClient({ preset: 'native', createSwarm: fakeSwarmFactory(swarms), hash: stubHash, refreshIntervalMs: 10 })
  t.teardown(() => client.destroy())
  t.is(client.options.fallbackToPublic, false)
  const events = record(client)
  const invited = keyPairFromSeed(b4a.alloc(32, 31)).publicKey
  const invite = ADDRESS + hex(invited)
  await client.connect(invite)
  const priv = new FakeHuginNode({ address: ADDRESS, hash: stubHash, job: JOB })
  const up = once(t, client, 'node:connected')
  const link = swarms[0].dial(priv, invited)
  await up
  link.remote.destroy()
  await waitFor(t, () => swarms[0].refreshes >= 4, 5000, 'four refreshes')
  await sleep(100)
  t.is(swarms[0].refreshes, 4, 'the loop ended')
  t.absent(swarms[0].destroyed, 'the private node swarm is kept')
  t.is(swarms.length, 1, 'no public topic swarm')
  t.is(client.target.address, invite)
  t.absent(events.names().includes('node:reset'))
})

test('jobs above powMaxDifficulty: not mined; after 3 in a row the client moves to another public node', async (t) => {
  const swarms = []
  const client = new NodeClient({ preset: 'native', createSwarm: fakeSwarmFactory(swarms), hash: stubHash, refreshIntervalMs: 20 })
  t.teardown(() => client.destroy())
  t.is(client.options.powMaxDifficulty, 2000)
  t.is(client.options.powMaxTooHardJobs, 3)
  t.is(client.jobs.maxDifficulty, 2000)
  const events = record(client)
  await client.connect({ publicNode: true })

  const HARD = { ...JOB, job_id: 'hard', target: pow.difficultyToTarget(1e6) }
  const hardNode = new FakeHuginNode({ address: ADDRESS, hash: stubHash, job: HARD })
  const easyNode = new FakeHuginNode({ address: ADDRESS, hash: stubHash, job: JOB })
  const hardKey = b4a.alloc(32, 40)
  const first = once(t, client, 'node:connected')
  swarms[0].dial(hardNode, hardKey)
  await first
  swarms[0].dial(easyNode, b4a.alloc(32, 41))
  t.is(client.backups.length, 1)

  const res = await client.post({ cipher: 'cd'.repeat(40), kind: 'dm' })
  t.is(res.success, true, 'posted through the other node')
  t.is(hardNode.accepted.length, 0)
  t.is(easyNode.accepted.length, 1)
  t.is(client.remotePublicKey, hex(b4a.alloc(32, 41)))
  t.ok(hardNode.received.filter((d) => d.type === 'job_request').length >= 3, 'asked the first node for jobs')
  t.alike(events.find((e) => e[0] === 'node:disconnected')?.[1], { reason: 'switch', remotePublicKey: hex(hardKey) })
  t.is(swarms[0].opts.firewall(hardKey), true, 'the node left is skipped on this swarm')
  t.is(swarms[0].opts.firewall(b4a.alloc(32, 42)), false, 'other nodes are not')

  await client.change({ publicNode: true })
  t.is(swarms[1].opts.firewall(hardKey), false, 'a new swarm starts without skipped nodes')
})

test('jobs above powMaxDifficulty: a private node is kept; the limit is configurable', async (t) => {
  const swarms = []
  const client = new NodeClient({ createSwarm: fakeSwarmFactory(swarms), hash: stubHash, powMaxDifficulty: 5000, powMaxTooHardJobs: 2, powMaxJobTimeMs: 1500 })
  t.teardown(() => client.destroy())
  t.is(client.jobs.maxDifficulty, 5000)
  const invited = keyPairFromSeed(b4a.alloc(32, 31)).publicKey
  await client.connect(ADDRESS + hex(invited))
  const node = new FakeHuginNode({ address: ADDRESS, hash: stubHash, job: { ...JOB, job_id: 'hard', target: pow.difficultyToTarget(5001) } })
  const up = once(t, client, 'node:connected')
  swarms[0].dial(node, invited)
  await up

  t.is(await client.computePow(), null, 'nothing mined')
  t.ok(client.connected, 'still connected to the private node')
  t.is(await client.switchNode('job_too_hard'), false)
  t.ok(client.connected)

  t.ok(client.jobs.isTooHard({ ...JOB, target: pow.difficultyToTarget(5001) }))
  t.absent(client.jobs.isTooHard({ ...JOB, target: pow.difficultyToTarget(4000) }))
})

test('suspend and resume (native lifecycle)', async (t) => {
  const { client, node, swarms, link, events } = await connectedPair(t, { preset: 'native', refreshIntervalMs: 20, maxReconnectTries: 1000 })
  t.teardown(() => client.destroy())

  await client.suspend()
  t.is(client.state, 'suspended')
  t.ok(swarms[0].suspended)
  t.ok(link.local.destroyed)
  t.alike(events.filter((e) => e[0] === 'node:disconnected').map((e) => e[1].reason), ['suspend'])
  const before = swarms[0].refreshes
  await sleep(80)
  t.is(swarms[0].refreshes, before, 'no reconnect loop while suspended')
  t.is(swarms[0].dial(node), null)
  t.alike(await client.post({ cipher: 'abcd' }), { success: false, reason: NO_CONNECTION })

  await client.resume()
  t.absent(swarms[0].suspended)
  await waitFor(t, () => swarms[0].refreshes > before)
  const back = once(t, client, 'node:connected')
  swarms[0].dial(node, b4a.alloc(32, 9))
  await back
  t.is(client.state, 'connected')

  await client.destroy()
  t.is(client.state, 'destroyed')
  t.ok(swarms[0].destroyed)
  await t.exception(() => client.connect({ publicNode: true }), /destroyed/)
})

test('polling: since advances, desktop rewind on connect, shouldSync, maxRuns', async (t) => {
  const pool = [{ cipher: 'aa', hash: 'd1'.repeat(32), timestamp: 100 }]
  const { client, node, swarms, link } = await connectedPair(t, { poll: { intervalMs: 20, initialDelayMs: 0 } }, { pool })
  t.teardown(() => client.destroy())
  const syncs = () => node.received.filter((p) => p.request)

  const got = once(t, client, 'node:messages')
  client.startPolling({ since: 50 })
  const ev = await got
  t.alike(ev.messages, pool)
  t.is(ev.source, 'sync')
  t.ok(ev.since <= Date.now() - 1000 && ev.since > Date.now() - 10000, 'since = now - 1 s (desktop)')
  t.is(syncs()[0].timestamp, 50)
  await waitFor(t, () => syncs().length >= 3)
  t.is(syncs().at(-1).timestamp, ev.since, 'next runs ask from the new since')

  // a new connection moves since back by 30 s (desktop)
  const since = client.pollSince
  const lost = once(t, client, 'node:disconnected')
  link.remote.destroy()
  await lost
  const back = once(t, client, 'node:connected')
  swarms[0].dial(node, b4a.alloc(32, 9))
  await back
  t.is(client.pollSince, since - 30000)

  // shouldSync false skips the run (host backlog)
  client.stopPolling()
  await sleep(50)
  const n = syncs().length
  client.startPolling({ since: 0, shouldSync: () => false })
  await sleep(100)
  t.is(syncs().length, n)

  // native: at most maxRuns runs
  client.startPolling({ since: 0, maxRuns: 2, advanceSkewMs: 0 })
  await waitFor(t, () => client.pollSince === null)
  t.is(syncs().length, n + 2)

  client.startPolling(1000)
  t.is(client._poll.intervalMs, 1000)
  client.stopPolling()
  t.is(client.pollSince, null)
})

// =============================================================================================
// end to end on a local testnet

test(
  'end to end: private invite firewall, change(), sync, post with PoW auth, push, reconnect after the node drops',
  { timeout: 180000 },
  async (t) => {
    const testnet = await createTestnet(3, t.teardown)
    const { bootstrap } = testnet

    const nodeKeys = keyPairFromSeed(b4a.alloc(32, 41))
    const node = new FakeHuginNode({
      address: ADDRESS,
      hash: stubHash,
      job: JOB,
      pool: [{ cipher: 'aa', hash: 'a1'.repeat(32), timestamp: Date.now() - 1000 }]
    })
    await node.listen({ key: ADDRESS, keyPair: nodeKeys, bootstrap })
    t.teardown(() => node.close())

    const logs = []
    const client = new NodeClient({ bootstrap, hash: stubHash, refreshIntervalMs: 500, log: (level, msg) => logs.push(msg) })
    t.teardown(() => client.destroy())

    // an invite with another key: the node is found but refused by the firewall
    const wrong = keyPairFromSeed(b4a.alloc(32, 42)).publicKey
    await client.connect(ADDRESS + hex(wrong))
    await waitFor(t, () => logs.includes('firewalled a node that is not the invited one'), 60000)
    await sleep(1000)
    t.absent(client.connected, 'no connection to a node that is not in the invite')
    t.is(node.clients.length, 0)

    // the right invite
    const connected = once(t, client, 'node:connected', 60000)
    const address = once(t, client, 'node:address', 60000)
    await client.change(ADDRESS + hex(nodeKeys.publicKey))
    t.is((await connected).remotePublicKey, hex(nodeKeys.publicKey))
    t.is((await address).address, ADDRESS)

    t.is((await client.sync({ since: 0 })).length, 1, 'sync round trip')

    const res = await client.post({ cipher: 'cd'.repeat(32), viewtag: 'abc' })
    t.is(res.success, true, 'post accepted (auth and share checked by the node)')
    t.is(node.accepted.length, 1)
    t.is((await client.sync({ since: 0 })).length, 2)

    const pushed = once(t, client, 'node:messages')
    node.pushMessages([{ cipher: 'bb', hash: 'b2'.repeat(32), timestamp: Date.now() }])
    t.is((await pushed).source, 'push')

    // the node drops the connection; the client reconnects
    const lost = once(t, client, 'node:disconnected', 30000)
    const again = once(t, client, 'node:connected', 90000)
    node.dropAll()
    t.ok(['close', 'error'].includes((await lost).reason))
    await again
    t.ok(client.connected)
    t.is((await client.sync({ since: 0 })).length, 2, 'requests work on the new connection')
    t.is(node.banned, 0)
  }
)

test('end to end: public topic, native preset keeps a backup that takes over', { timeout: 240000 }, async (t) => {
  const testnet = await createTestnet(3, t.teardown)
  const { bootstrap } = testnet

  // both nodes are announced on the public topic before the client looks for them
  const a = new FakeHuginNode({ address: ADDRESS, hash: stubHash, job: JOB, pool: [{ cipher: 'aa', hash: 'aa'.repeat(32), timestamp: 1 }] })
  const b = new FakeHuginNode({ address: ADDRESS, hash: stubHash, job: JOB, pool: [{ cipher: 'bb', hash: 'bb'.repeat(32), timestamp: 2 }] })
  t.teardown(() => a.close())
  t.teardown(() => b.close())
  const [ka, kb] = await Promise.all([
    a.listen({ key: NETWORK_ADDRESS, keyPair: keyPairFromSeed(b4a.alloc(32, 51)), bootstrap }),
    b.listen({ key: NETWORK_ADDRESS, keyPair: keyPairFromSeed(b4a.alloc(32, 52)), bootstrap })
  ])

  const client = new NodeClient({ preset: 'native', bootstrap, hash: stubHash, refreshIntervalMs: 500, maxReconnectTries: 1000 })
  t.teardown(() => client.destroy())
  const events = record(client)
  await client.connect({ publicNode: true })
  await client.swarm.flush()
  if (!(await waitFor(t, () => client.connected && client.backups.length === 1, 120000, 'one active and one backup connection'))) return

  const byKey = { [hex(ka.keyPair.publicKey)]: a, [hex(kb.keyPair.publicKey)]: b }
  const active = byKey[client.remotePublicKey]
  t.ok(active, 'connected to one of the two nodes')
  if (!active) return
  const other = active === a ? b : a
  const otherKey = other === a ? hex(ka.keyPair.publicKey) : hex(kb.keyPair.publicKey)
  // The client side of a Hyperswarm connection opens a few milliseconds before the server side
  // emits 'connection'; wait until both nodes serve the client before dropping the active one.
  if (!(await waitFor(t, () => a.clients.length > 0 && b.clients.length > 0, 60000, 'both nodes serve the client'))) return
  const from = events.length

  const lost = once(t, client, 'node:disconnected', 60000)
  t.ok(active.dropAll() > 0, 'the active node had the connection to drop')
  t.ok(['close', 'error'].includes((await lost).reason), 'the client saw the drop')

  // the promotion happens in the same tick as the disconnect
  const after = events.slice(from).filter((e) => e[0] === 'node:connected')
  t.ok(after.length > 0 && after[0][1].backup === true, 'the backup was promoted')
  t.is(after.length > 0 ? after[0][1].remotePublicKey : null, otherKey, 'the other node took over')
  t.is(client.remotePublicKey, otherKey)
  t.alike(await client.sync({ since: 0 }), other.pool)
})
