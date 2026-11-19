'use strict'

// hugin-network/xkr-daemon: the wire helpers, the topic keys (the same values as xkrd's
// `topic::xkr_wallets_topic` and the private clients topic), and a request over a local DHT
// testnet to a stand-in node that answers as xkrd's wallet service.

const test = require('brittle')
const b4a = require('b4a')
const createTestnet = require('hyperdht/testnet.js')
const { createHuginSwarm } = require('../lib/swarm.js')
const xd = require('../lib/xkr-daemon.js')

const TIMEOUT = 90000

test('xkr-daemon: frames round trip, also split across chunks', (t) => {
  const frames = [{ v: 1, service: 'wallet' }, { id: 7, result: { status: 200, body: { height: 3 } } }]
  const bytes = b4a.concat(frames.map(xd.encodeFrame))
  const reader = new xd.FrameReader()
  const got = []
  for (let i = 0; i < bytes.length; i += 5) got.push(...reader.push(bytes.subarray(i, i + 5)))
  t.alike(got, frames)
  t.is(bytes[0] + (bytes[1] << 8), JSON.stringify(frames[0]).length, 'little-endian length')
  t.exception(() => new xd.FrameReader().push(b4a.from([0, 0, 0, 0])), 'empty frame refused')
  t.exception(() => new xd.FrameReader().push(b4a.from([0, 0, 0x20, 0])), 'over 1 MiB refused')
})

test('xkr-daemon: topic keys as xkrd derives them', (t) => {
  t.is(
    b4a.toString(xd.walletsTopicKey('mainnet'), 'hex'),
    b4a.toString(xd.cnFastHash(b4a.from('xkr/mainnet/wallets/v1')), 'hex')
  )
  t.not(b4a.toString(xd.walletsTopicKey('mainnet'), 'hex'), b4a.toString(xd.walletsTopicKey('testnet'), 'hex'))
  // the vector xkrd's `wallets_and_private_clients_topic_keys` test checks
  t.is(b4a.toString(xd.walletsTopicKey('mainnet'), 'hex'), WALLETS_MAINNET)
  t.is(b4a.toString(xd.privateClientsTopicKey(b4a.alloc(32, 0x11)), 'hex'), PRIVATE_CLIENTS_11)
})

test('xkr-daemon: invites', (t) => {
  const hex = (b) => b4a.toString(b4a.alloc(32, b), 'hex')
  const invite = `xkr:${hex(1)}${hex(2)}${hex(3)}${hex(4)}`
  const parsed = xd.parseInvite(` ${invite.toUpperCase().replace('XKR:', 'xkr:')} `)
  t.alike(parsed.clientsKey, b4a.alloc(32, 3))
  t.alike(parsed.secret, b4a.alloc(32, 4))
  t.exception(() => xd.parseInvite(`xkrinv2:${hex(1)}`), /starts with xkr:/)
  t.exception(() => xd.parseInvite('xkr:00'), /256 hex/)
})

test('xkr-daemon: which nodes are used', (t) => {
  const [span, hash] = Object.entries(xd.BUILTIN_STATE_HASHES)[0]
  const list = xd.BUILTIN_STATE_HASHES
  t.is(xd.unusable({ v: 1, synced: true, state_span: Number(span), state_hash: hash }, list), null)
  t.is(xd.unusable({ v: 1, synced: true, state_span: null, state_hash: null }, list), null)
  t.ok(xd.unusable({ v: 1, synced: false }, list), 'not synced')
  t.ok(xd.unusable({ v: 1, synced: true, state_span: Number(span), state_hash: '00'.repeat(32) }, list), 'other state hash')
  t.is(xd.unusable({ v: 1, synced: true, state_span: 1e9, state_hash: '00'.repeat(32) }, list), null, 'above the list')
  t.ok(xd.unusable({ v: 2, synced: true }, list), 'other version')
})

test('xkr-daemon: a request over the DHT to a node on the wallets topic', { timeout: TIMEOUT }, async (t) => {
  const testnet = await createTestnet(3, t.teardown)
  const node = createHuginSwarm({ key: xd.walletsTopicKey('mainnet'), bootstrap: testnet.bootstrap })
  t.teardown(() => node.swarm.destroy())
  const seen = []
  node.swarm.on('connection', (conn) => {
    conn.on('error', () => {})
    const reader = new xd.FrameReader()
    conn.on('data', (chunk) => {
      for (const frame of reader.push(chunk)) {
        if (frame.service) {
          seen.push(frame)
          conn.write(xd.encodeFrame({ v: 1, height: 41, hash: 'ab'.repeat(32), synced: true, services: ['wallet'], state_span: null, state_hash: null, pruning_seed: 0 }))
        } else {
          const { method, path, body } = frame.params
          conn.write(xd.encodeFrame({ id: frame.id, result: { status: 200, body: { method, path, body, height: 42 } } }))
        }
      }
    })
  })
  await node.swarm.join(node.topic, { server: true, client: false }).flushed()

  const requester = new xd.XkrDaemonRequester({ network: 'mainnet', bootstrap: testnet.bootstrap, client: 'test/1' })
  t.teardown(() => requester.close())
  const info = await requester.request('get', '/info')
  t.is(info.status, 200)
  t.alike(info.body, { method: 'GET', path: '/info', body: null, height: 42 })
  const sync = await requester.request('post', '/getwalletsyncdata', { startHeight: 5 })
  t.alike(sync.body.body, { startHeight: 5 })
  t.is(sync.body.method, 'POST')
  t.is(seen.length, 1, 'one hello for both requests')
  t.alike(seen[0], { v: 1, network: 'mainnet', service: 'wallet', client: 'test/1' })
  t.is(requester.node().height, 41)
})

const WALLETS_MAINNET = '1e35744b40a383370e2e6a489927834ebe5392570afaa926761308916f48aa39'
const PRIVATE_CLIENTS_11 = 'ba0997cb6b12806ed79dc089ca82acc6c22f1ee39bc6adb508f36cb2718d5034'
