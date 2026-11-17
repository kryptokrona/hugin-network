'use strict'

// hugin-network/pow (lib/pow.js): the hugin-pow helpers it re-exports, checked against the
// apps' own code (fixtures) and the hugin-relay vectors, and the network-side loops
// (searchShares on hugin-pow's JobTracker and mineShare, sendWithPow, the retry policy).

const test = require('brittle')
const b4a = require('b4a')
const pow = require('../lib/pow.js')
const { keyPairFromSeed } = require('../lib/ed25519.js')
const hu = require('./fixtures/hugin-utils.js')
const desktop = require('./fixtures/legacy-desktop.js')
const native = require('./fixtures/legacy-native.js')
const V = require('./fixtures/hugin-relay.json')
const { NODE } = require('./helpers.js')

const SHARE = { job_id: V.pow.job.job_id, nonce: V.pow.nonce, result: V.pow.result }

/** Stand-in for CN-Turtle-Lite v2: the real hash for the vector blob, a high hash otherwise. */
const stubHash = async (blobHex) => (blobHex === V.pow.hashing_blob ? V.pow.result : 'ff'.repeat(32))

test('nonce offset, nonce insertion and prev_id: hugin-relay vectors', (t) => {
  t.is(pow.getNonceOffset(V.pow.job.blob), V.pow.nonce_offset)
  t.is(pow.getNonceOffset(V.pow.short_blob), V.pow.short_nonce_offset)
  t.is(pow.insertNonce(V.pow.job.blob, V.pow.nonce).blobHex, V.pow.hashing_blob)
  t.is(pow.insertNonce(V.pow.job.blob, V.pow.nonce).offset, V.pow.nonce_offset)
  t.is(pow.extractPrevIdFromBlob(V.pow.job.blob), V.pow.prev_id)
  t.is(pow.extractPrevIdFromBlob(V.pow.short_blob), V.pow.short_prev_id)
  t.is(pow.extractPrevIdFromBlob('0500ff'), V.pow.bad_prev_id)
})

test('blob helpers: same as hugin-utils and native pow-utils', (t) => {
  const blobs = [V.pow.job.blob, V.pow.short_blob, '0500ff', '05', 'ffffffffffffffffffffff' + '00'.repeat(40), '']
  for (const blob of blobs) {
    t.is(pow.extractPrevIdFromBlob(blob), hu.extractPrevIdFromBlob(blob), 'prev_id ' + blob.slice(0, 12))
    t.is(pow.extractPrevIdFromBlob(blob), native.extractPrevIdFromBlob(blob))
    if (blob.length) {
      t.is(pow.getNonceOffset(blob), hu.getNonceOffset(blob), 'offset ' + blob.slice(0, 12))
      t.is(pow.getNonceOffset(blob), native.getNonceOffset(blob))
    }
  }
  t.is(pow.insertNonce(V.pow.short_blob, 'deadbeef').blobHex, hu.insertNonce(V.pow.short_blob, 'deadbeef').blobHex)
})

test('meetsTarget: hugin-relay target table', (t) => {
  for (const v of V.pow.meets_target) {
    t.is(pow.meetsTarget(v.hash, v.target), v.meets, v.target + ' ' + v.hash.slice(48))
    t.is(pow.meetsTarget(v.hash, v.target), hu.meetsTarget(v.hash, v.target))
  }
})

test('target and difficulty helpers', (t) => {
  t.is(pow.targetToDifficulty('ffffffff'), 1)
  t.is(pow.difficultyToTarget(1), 'ffffffff')
  t.is(pow.difficultyToTarget(1000), '37894100')
  t.is(pow.targetToDifficulty('37894100'), 1000)
  t.is(pow.targetToDifficulty('00000000'), 0, 'zero target: no work')
  t.is(pow.parseTarget('00000000'), null)
  t.is(pow.nonceToHex(0xd4c3b2a1), 'a1b2c3d4', 'little-endian')
})

test('verifyShare with a given hash function: hugin-relay share', async (t) => {
  t.is(await pow.verifyShare(V.pow.job, V.pow.nonce, V.pow.result, stubHash), V.pow.verify_share)
  t.is(await pow.verifyShare(V.pow.job, 'a1b2c3d5', V.pow.result, stubHash), V.pow.verify_share_wrong_nonce)
  t.is(await pow.verifyShare(V.pow.job, V.pow.nonce, V.pow.result, stubHash), await hu.verifyShare(V.pow.job, V.pow.nonce, V.pow.result, stubHash))
  t.is(await pow.verifyShare(V.pow.job, V.pow.nonce, V.pow.result.toUpperCase(), stubHash), false, 'result must match the hash as returned')
  t.is(await pow.verifyShare({ ...V.pow.job, target: 'zz' }, V.pow.nonce, V.pow.result, stubHash), false)
  await t.exception.all(pow.verifyShare(V.pow.job, V.pow.nonce, V.pow.result))
})

test('findShare with a given hash function', async (t) => {
  const job = { job_id: 'j', blob: V.pow.job.blob, target: '01000000' }
  const winning = 'a1b2c3d4' // nonce 0xd4c3b2a1 little-endian
  const hash = async (blobHex) =>
    blobHex === pow.insertNonce(job.blob, winning).blobHex ? '33'.repeat(24) + '00'.repeat(8) : '33'.repeat(24) + 'ff'.repeat(8)
  const start = 0xd4c3b2a1 - 5
  const share = await pow.findShare({ job, hash, startNonce: start, maxAttempts: 10, timeBudgetMs: 60000 })
  t.alike(share, { job_id: 'j', nonce: winning, result: '33'.repeat(24) + '00'.repeat(8) })
  const theirs = await hu.findShare({ job, startNonce: start, hashFn: hash, hashesPerSecond: 10, timeBudgetMs: 1000 })
  t.alike(share, theirs, 'same share as hugin-utils findShare')
  t.is(await pow.findShare({ job, hash, startNonce: start, maxAttempts: 3, timeBudgetMs: 60000 }), null, 'gives up')
  t.is(await pow.findShare({ job: { job_id: 'j', blob: 'zz', target: '01000000' }, hash, maxAttempts: 3 }), null, 'invalid job')
})

test('validatePowJob: same answers as both apps', (t) => {
  const jobs = [
    V.pow.job,
    null,
    'job',
    { ...V.pow.job, job_id: 5 },
    { ...V.pow.job, job_id: 'j'.repeat(33) },
    { ...V.pow.job, blob: 'xyz' },
    { ...V.pow.job, blob: V.pow.job.blob + 'a' },
    { ...V.pow.job, blob: 'aa'.repeat(1025) },
    { ...V.pow.job, target: 'ffff' },
    { ...V.pow.job, target: 'gggggggg' },
    { ...V.pow.job, blob: V.pow.short_blob.slice(0, 74) }
  ]
  for (const job of jobs) {
    const ours = pow.validatePowJob(job)
    t.alike(ours, desktop.validate_pow_job(job), 'desktop ' + JSON.stringify(ours))
    t.alike(ours, native.validate_pow_job(job), 'native')
  }
})

test('powsig:v2 auth: hugin-relay vectors (keypear signatures)', (t) => {
  const keyPair = keyPairFromSeed(b4a.alloc(32, 7))
  for (const v of V.auth) {
    const payload = pow.powAuthPayload({ hash: v.hash, timestamp: v.timestamp, share: SHARE, context: v.context })
    t.is(payload, v.payload, 'payload')
    const auth = pow.buildPowAuth({ hash: v.hash, timestamp: v.timestamp, shares: [SHARE], context: v.context, keyPair })
    t.is(auth.pub, v.pub, 'pub')
    t.is(auth.sig, v.sig, 'sig (byte-identical to keypear)')
    t.is(auth.nonce, SHARE.nonce)
    t.ok(pow.verifyPowAuth({ auth, hash: v.hash, timestamp: v.timestamp, shares: [SHARE], context: v.context }))
    t.absent(pow.verifyPowAuth({ auth, hash: v.hash, timestamp: v.timestamp + 1, shares: [SHARE], context: v.context }), 'other timestamp')
    t.absent(pow.verifyPowAuth({ auth, hash: v.hash, timestamp: v.timestamp, shares: [SHARE], context: v.context + 'x' }), 'other context')
  }
})

test('buildPowAuth: same as both apps build_pow_auth', { skip: !NODE }, (t) => {
  const keyPair = keyPairFromSeed(b4a.alloc(32, 9))
  const keychain = native.Keychain.from(keyPair)
  const shares = [{ job_id: 'job-1', nonce: 'A1B2C3D4', result: V.pow.result.toUpperCase() }]
  const ctx = pow.postAuthContext('room', 'abcd')
  const ours = pow.buildPowAuth({ hash: 'ab'.repeat(32), timestamp: 1731500000000, shares, context: ctx, keyPair })
  t.alike(ours, native.build_pow_auth(keychain, 'ab'.repeat(32), 1731500000000, shares, ctx), 'native')
  t.alike(ours, desktop.build_pow_auth(keychain, 'ab'.repeat(32), 1731500000000, shares, ctx), 'desktop')
  t.is(pow.buildPowAuth({ hash: 'x', timestamp: 1, shares: [], context: '' }), null)
})

test('auth contexts', (t) => {
  t.is(pow.postAuthContext('dm', 'cafe'), 'dm:cafe')
  t.is(pow.postAuthContext('', 'cafe'), 'cafe')
  t.is(pow.registerAuthContext('[1]'), '[1]')
  t.is(pow.registerAuthContext(undefined), '')
})

test('retry policy: union of both apps plus xkrd reasons', (t) => {
  const answers = [
    null,
    { success: true },
    { success: false },
    { success: false, reason: 'pool_reject' },
    { success: false, reason: 'invalid_share' },
    { success: false, reason: 'Invalid PoW' },
    { success: false, reason: 'stale_job' },
    { success: false, reason: 'timeout' },
    { success: false, reason: 'pool_reject', rejects: ['Low difficulty share'] },
    { success: false, reason: 'x', rejects: [{ error: 'invalid nonce' }] },
    { success: false, reason: 'x', rejects: ['other'] }
  ]
  for (const res of answers) {
    const expected = desktop.should_recalc_share(res) || native.should_recalc_share(res)
    t.is(pow.shouldRecalcShare(res), expected, JSON.stringify(res))
  }
  t.ok(pow.shouldRecalcShare({ success: false, reason: 'share_reused' }), 'xkrd share_reused')
  t.ok(pow.shouldRecalcShare({ success: false, reason: 'stale_job' }), 'relay stale_job')
  t.is(pow.retryDelayMs({ success: false, reason: 'share_reused' }), 25)
  t.ok(pow.shouldRetry(null))
  t.absent(pow.shouldRetry({ success: true }))
  t.ok(pow.shouldRetry({ success: false, reason: 'cooldown' }))
  t.absent(pow.shouldRetry({ success: false }))
  t.is(pow.retryDelayMs({ success: false, reason: 'cooldown' }), 1000)
  t.is(pow.retryDelayMs({ success: false, reason: 'rate_limit' }), 1000)
  t.is(pow.retryDelayMs({ success: false, reason: 'stale' }), 25)
  t.is(pow.retryDelayMs({ success: false, reason: 'timeout' }), 100)
})

test('hugin-pow parts are re-exported unchanged', (t) => {
  const job = require('hugin-pow/job')
  const auth = require('hugin-pow/auth')
  const mine = require('hugin-pow/mine')
  for (const name of ['getNonceOffset', 'insertNonce', 'extractPrevIdFromBlob', 'meetsTarget', 'validatePowJob', 'isValidPowJob', 'verifyShare', 'findShare', 'normalizeShare', 'powField']) {
    t.is(pow[name], job[name], name)
  }
  for (const name of ['postAuthContext', 'registerAuthContext', 'powAuthPayload', 'buildPowAuth', 'verifyPowAuth']) t.is(pow[name], auth[name], name)
  for (const name of ['mineShare', 'JobTracker', 'checkBackend', 'isStaleAnswer', 'StopController']) t.is(pow[name], mine[name], name)
  t.is(pow.verifyPow, require('hugin-pow/verify').verifyPow)
})

test('normalizeShare and powField', (t) => {
  t.alike(pow.normalizeShare({ job_id: 7, nonce: 'AB', result: 'CD' }), { job_id: '7', nonce: 'ab', result: 'cd' })
  t.is(pow.normalizeShare({ nonce: 1 }), null)
  t.alike(pow.powField({ job: 1, shares: 2, auth: 3 }), { version: 2, job: 1, shares: 2, auth: 3 })
})

// ---------------------------------------------------------------------------------------------
// share search and send-with-retries loops

/** A clock and sleep that only advance when the loop sleeps (or a backend says so). */
function fakeClock() {
  const clock = { t: 0, slept: [] }
  clock.now = () => clock.t
  clock.sleep = async (ms) => {
    clock.slept.push(ms)
    clock.t += ms
  }
  return clock
}

const FRESH_JOB = V.pow.job

/** A job of another block than FRESH_JOB (another prev_id). */
function otherBlockJob(id, prevByte) {
  return { job_id: id, blob: '0500e0afd2b906' + prevByte.repeat(32) + '00000000' + '5a'.repeat(32) + '01', target: 'ffffffff' }
}

test('searchShares: mines the tracker job with the backend, normalizes the share, returns { job_id, blob, target }', async (t) => {
  const clock = fakeClock()
  const tracker = new pow.JobTracker({ now: clock.now })
  const calls = []
  const issued = { ...FRESH_JOB, height: 7 }
  const res = await pow.searchShares({
    tracker,
    requestJob: async () => {
      tracker.set(issued)
      return issued
    },
    backend: {
      findShare: async (req) => {
        calls.push(req)
        return { nonce: 'A1B2C3D4', result: V.pow.result.toUpperCase() } // upper case, as a backend may
      }
    },
    now: clock.now,
    sleep: clock.sleep
  })
  t.alike(res.shares, [SHARE])
  t.alike(res.allShares, [SHARE])
  t.alike(res.job, { job_id: FRESH_JOB.job_id, blob: FRESH_JOB.blob, target: FRESH_JOB.target }, 'pow.job: the job as handed out, no extra fields')
  t.is(calls.length, 1)
  t.is(calls[0].blobHex, FRESH_JOB.blob)
  t.is(calls[0].targetHex, FRESH_JOB.target)
  t.ok(Number.isInteger(calls[0].startNonce))
  t.ok(calls[0].maxAttempts > 0 && calls[0].maxAttempts % 840 === 0, 'hugin-pow slice size')
})

test('searchShares: skips stale jobs, waits without a job, gives up after the job time', async (t) => {
  const clock = fakeClock()
  const tracker = new pow.JobTracker({ now: clock.now })
  const stale = otherBlockJob('old', '99') // never handed out through the tracker
  const events = []
  let jobs = 0
  let finds = 0
  const res = await pow.searchShares({
    tracker,
    requestJob: async () => {
      jobs++
      if (jobs === 1) return null
      if (jobs === 2) return stale
      tracker.set(FRESH_JOB)
      return FRESH_JOB
    },
    backend: {
      findShare: async () => {
        finds++
        clock.t += 5000
        return null
      }
    },
    maxJobTimeMs: 90000,
    now: clock.now,
    sleep: clock.sleep,
    onEvent: (name) => events.push(name)
  })
  t.is(res, null, 'no share within 90 s')
  t.is(clock.slept[0], 250, 'no job: wait 250 ms')
  t.is(clock.slept[1], 250, 'stale job: wait 250 ms')
  t.ok(events.includes('pow_stale_local'))
  t.ok(jobs >= 4, 'the relay is asked for a job again after each round')
  t.ok(finds >= 3)

  await t.exception(
    () => pow.searchShares({ tracker, requestJob: async () => FRESH_JOB, backend: { findShare: async () => { throw new Error('boom') } } }),
    /boom/
  )
  await t.exception.all(() => pow.searchShares({ tracker, requestJob: async () => FRESH_JOB }), /backend/)
  await t.exception.all(() => pow.searchShares({ tracker: {}, requestJob: async () => FRESH_JOB, backend: { hash: async () => '' } }), /JobTracker/)
  let cancelled = false
  t.is(
    await pow.searchShares({
      tracker,
      requestJob: async () => {
        cancelled = true
        return FRESH_JOB
      },
      backend: { findShare: async () => null },
      isCancelled: () => cancelled
    }),
    null,
    'cancelled'
  )
})

test('searchShares: jobs above maxDifficulty are not mined; onTooHardJobs after 3 in a row', async (t) => {
  const clock = fakeClock()
  const tracker = new pow.JobTracker({ now: clock.now })
  const hard = { ...FRESH_JOB, job_id: 'hard', target: pow.difficultyToTarget(pow.DEFAULT_MAX_DIFFICULTY + 1) }
  const events = []
  const switches = []
  let switched = false
  let finds = 0
  const res = await pow.searchShares({
    tracker,
    requestJob: async () => {
      const j = switched ? FRESH_JOB : hard
      tracker.set(j)
      return j
    },
    backend: {
      findShare: async (req) => {
        finds++
        t.is(req.blobHex, FRESH_JOB.blob, 'only the job within the limit is mined')
        return { nonce: V.pow.nonce, result: V.pow.result }
      }
    },
    onTooHardJobs: async (info) => {
      switches.push(info)
      switched = true
    },
    now: clock.now,
    sleep: clock.sleep,
    onEvent: (name, data) => events.push([name, data])
  })
  t.ok(res, 'a share from the next node')
  t.is(finds, 1)
  t.alike(switches, [{ jobs: 3 }])
  const tooHard = events.filter((e) => e[0] === 'pow_job_too_hard')
  t.is(tooHard.length, 3)
  t.alike(tooHard[0][1], { jobId: 'hard', difficulty: pow.DEFAULT_MAX_DIFFICULTY + 1, jobs: 1 })
  t.is(pow.POW_MAX_TOO_HARD_JOBS, 3)
})

test('searchShares: a job of a new block stops the search and the new job is mined', async (t) => {
  const clock = fakeClock()
  const tracker = new pow.JobTracker({ now: clock.now })
  const next = otherBlockJob('next', '44')
  const mined = []
  const res = await pow.searchShares({
    tracker,
    requestJob: async () => {
      tracker.set(FRESH_JOB)
      return FRESH_JOB
    },
    backend: {
      findShare: async (req) => {
        mined.push(req.blobHex)
        if (mined.length === 1) {
          tracker.set(next) // the relay pushes a job of a new block while the slice runs
          return { nonce: 'a1b2c3d4', result: V.pow.result } // dropped: found for the replaced block
        }
        return { nonce: '01020304', result: '00'.repeat(32) }
      }
    },
    now: clock.now,
    sleep: clock.sleep
  })
  t.alike(mined, [FRESH_JOB.blob, next.blob])
  t.is(res.job.job_id, 'next')
  t.alike(res.shares, [{ job_id: 'next', nonce: '01020304', result: '00'.repeat(32) }])
})

test('searchShares: a backend with hash is checked against the reference vector first', async (t) => {
  const { REFERENCE_VECTOR } = require('hugin-pow')
  const tracker = new pow.JobTracker()
  tracker.set(FRESH_JOB)
  const good = async (blobHex) => (blobHex === REFERENCE_VECTOR.blob ? REFERENCE_VECTOR.hash : '00'.repeat(32))
  const res = await pow.searchShares({ tracker, requestJob: async () => FRESH_JOB, backend: { hash: good }, sleep: async () => {} })
  t.is(res.shares.length, 1, 'every hash meets target ffffffff')
  await t.exception(
    () => pow.searchShares({ tracker, requestJob: async () => FRESH_JOB, backend: { hash: async () => '00'.repeat(32) }, sleep: async () => {} }),
    /reference/
  )
})

function sendHarness(answers, { shares = [SHARE] } = {}) {
  const h = { sent: [], refreshes: 0, events: [], clock: fakeClock() }
  h.opts = {
    hash: V.auth[0].hash,
    timestamp: V.auth[0].timestamp,
    context: V.auth[0].context,
    computePow: async () => (shares ? { job: V.pow.job, shares } : null),
    buildPacket: (p) => ({ type: 'post', message: { pow: p } }),
    send: async (packet) => {
      h.sent.push(packet)
      return answers.length ? answers.shift() : { success: false, reason: 'timeout' }
    },
    refreshJob: async () => {
      h.refreshes++
    },
    sleep: h.clock.sleep,
    onEvent: (name) => h.events.push(name),
    authKeyPair: keyPairFromSeed(b4a.alloc(32, 7))
  }
  return h
}

test('sendWithPow: success, auth over the share, no retry after success', async (t) => {
  const h = sendHarness([{ success: true, id: 1 }])
  const res = await pow.sendWithPow(h.opts)
  t.alike(res, { success: true, id: 1 })
  t.is(h.sent.length, 1)
  const p = h.sent[0].message.pow
  t.is(p.version, 2)
  t.is(p.auth.sig, V.auth[0].sig, 'the hugin-relay auth vector')
  t.ok(pow.verifyPowAuth({ auth: p.auth, hash: h.opts.hash, timestamp: h.opts.timestamp, shares: p.shares, context: h.opts.context }))
})

test('sendWithPow: recalc answers do not use up attempts, gives up after 3 + 3', async (t) => {
  const h = sendHarness(Array.from({ length: 10 }, () => ({ success: false, reason: 'stale' })))
  const res = await pow.sendWithPow(h.opts)
  t.alike(res, { success: false, reason: 'stale' })
  t.is(h.sent.length, 6, '3 attempts + 3 share recalculations')
  t.is(h.refreshes, 6, 'a new job before every retry')
  t.ok(h.clock.slept.every((ms) => ms === 25), 'recalc retries wait 25 ms')
  t.is(h.events.filter((e) => e === 'recalc').length, 3)
})

test('sendWithPow: 1 s back-off after cooldown / rate_limit, 100 ms otherwise', async (t) => {
  const h = sendHarness([
    { success: false, reason: 'cooldown' },
    { success: false, reason: 'rate_limit' },
    { success: true, id: 2 }
  ])
  t.alike(await pow.sendWithPow(h.opts), { success: true, id: 2 })
  t.alike(h.clock.slept, [1000, 1000])

  const h2 = sendHarness([{ success: false, reason: 'timeout' }, { success: false, reason: 'timeout' }, { success: false, reason: 'timeout' }])
  t.alike(await pow.sendWithPow(h2.opts), { success: false, reason: 'timeout' })
  t.is(h2.sent.length, 3)
  t.alike(h2.clock.slept, [100, 100, 100])
})

test('sendWithPow: answers without a reason are final; no shares -> PoW required; bad packet -> invalid_packet', async (t) => {
  const h = sendHarness([{ success: false }])
  t.alike(await pow.sendWithPow(h.opts), { success: false })
  t.is(h.sent.length, 1)

  const h2 = sendHarness([], { shares: null })
  t.alike(await pow.sendWithPow(h2.opts), { success: false, reason: 'PoW required' })
  t.is(h2.sent.length, 0)
  t.is(h2.events.filter((e) => e === 'no_shares').length, 3)
  t.is(h2.refreshes, 3)

  const h3 = sendHarness([])
  h3.opts.buildPacket = () => {
    const err = new Error('packet: larger than 9000 bytes')
    err.name = 'PacketError'
    err.code = 'HUGIN_PACKET_INVALID'
    throw err
  }
  t.alike(await pow.sendWithPow(h3.opts), { success: false, reason: 'invalid_packet' })

  const h4 = sendHarness([])
  t.alike(await pow.sendWithPow({ ...h4.opts, isCancelled: () => true }), { success: false, reason: 'cancelled' })
  await t.exception.all(() => pow.sendWithPow({ ...h4.opts, send: null }), /must be functions/)
})
