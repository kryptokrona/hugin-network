'use strict'

// hugin-network/pow: proof of work for hugin-node and xkrd `--hugin-relay` posts and
// registrations.
//
// Jobs, nonces, targets, share verification, the `powsig:v2` auth signature, share mining and
// the job tracker come from hugin-pow and are re-exported here unchanged (`hugin-pow/job`,
// `hugin-pow/auth`, `hugin-pow/mine`, `hugin-pow/verify`). This file adds the network side the
// node client runs: the share search loop over a relay connection (`searchShares`), sending a
// post or registration with retries (`sendWithPow`), and the retry policy.
//
// Hashing is a backend the host passes in, as hugin-pow defines it: an object with
// `findShare({ blobHex, targetHex, startNonce, maxAttempts })` (kryptokrona-crypto's
// `findPowShare`, all cores) and/or `hash(blobHex)` (CN-Turtle-Lite v2). On Node.js and
// Electron `require('hugin-pow/native').createHasher()` builds it; the Bare worklet of
// hugin-native passes functions that ask the React Native side.
//
// No Node-only APIs: runs under Node and Bare (hugin-pow/native, which loads kryptokrona-crypto,
// is not required here).

const job = require('hugin-pow/job')
const auth = require('hugin-pow/auth')
const mine = require('hugin-pow/mine')
const { verifyPow } = require('hugin-pow/verify')

const { POW_MAX_JOB_TIME_MS, POW_REQUIRED_SHARES, normalizeShare, powField, targetToDifficulty } = job
const { buildPowAuth } = auth
const { JobTracker } = mine

/** How long one search round mines before the relay is asked for a job again. */
const POW_ROUND_MS = 20000

/** Jobs above the tracker's `maxDifficulty` in a row before `searchShares` calls `onTooHardJobs`. */
const POW_MAX_TOO_HARD_JOBS = 3

// ---------------------------------------------------------------------------------------------
// retry policy (used by the node client)

const RECALC_REASONS = Object.freeze(['pool_reject', 'invalid_share', 'invalid pow', 'stale', 'job', 'share_reused'])
const RECALC_REJECTS = Object.freeze(['invalid', 'stale', 'low', 'job'])

/** Whether a failed post/registration answer is worth another attempt (any reason given). */
function shouldRetry(res) {
  if (!res) return true
  if (res.success === true) return false
  return !!res.reason
}

/**
 * Whether the answer means the share itself was refused, so a new one is needed (union of the
 * apps' lists; `share_reused` is xkrd's answer for a share already spent on another message).
 */
function shouldRecalcShare(res) {
  if (!res || typeof res !== 'object') return false
  const reason = typeof res.reason === 'string' ? res.reason.toLowerCase() : ''
  if (RECALC_REASONS.some((r) => reason.includes(r))) return true
  if (!Array.isArray(res.rejects)) return false
  return res.rejects.some((entry) => {
    if (!entry) return false
    const txt = typeof entry === 'string' ? entry.toLowerCase() : JSON.stringify(entry).toLowerCase()
    return RECALC_REJECTS.some((r) => txt.includes(r))
  })
}

/** Delay before the next attempt: 1 s after `cooldown` / `rate_limit`, 25 ms to recalculate, else 100 ms. */
function retryDelayMs(res) {
  const reason = res && typeof res.reason === 'string' ? res.reason.toLowerCase() : ''
  if (reason.includes('cooldown') || reason.includes('rate_limit')) return 1000
  if (shouldRecalcShare(res)) return 25
  return 100
}

// ---------------------------------------------------------------------------------------------
// share search and send-with-retries loops (used by the node client; all I/O passed in)

function defaultSleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

function noop() {}

function isAborted(signal) {
  return !!signal && signal.aborted === true
}

function sameJob(a, b) {
  return !!a && !!b && a.job_id === b.job_id && a.blob === b.blob
}

/**
 * Searches shares for a post or registration over one relay connection: asks the relay for a
 * job (`requestJob`; the caller records every job the relay sends in `tracker`), skips a job the
 * tracker counts as stale (`pow_stale_local`), and mines the tracker's current job with
 * hugin-pow's `JobTracker#mine` on `backend` for at most `roundMs`, until `requiredShares`
 * distinct shares of one job are found or `maxJobTimeMs` has passed. A job of a new block stops
 * the running search and the new job is mined; a share is only returned while its job may still
 * be handed out (the relay's rule, see hugin-pow's JobTracker).
 *
 * A job above the tracker's `maxDifficulty` is not mined (`pow_job_too_hard`); after
 * `maxTooHardJobs` such jobs in a row (`tracker.tooHardJobs`) `onTooHardJobs` is called (the node
 * client moves to another node there), the tracker is cleared and the search goes on.
 *
 * @param {object} opts
 * @param {() => Promise<object|null>} opts.requestJob  a current job (recorded in `tracker` by the caller)
 * @param {JobTracker} opts.tracker  hugin-pow JobTracker
 * @param {{ findShare?: Function, hash?: Function }} opts.backend  hugin-pow backend
 * @param {number} [opts.maxJobTimeMs]  default 90 s
 * @param {number} [opts.requiredShares]  default 1
 * @param {number} [opts.roundMs]  mining time before the relay is asked again (default 20 s)
 * @param {number} [opts.sliceMs]  hugin-pow `mineShare` slice length (default 250 ms)
 * @param {AbortSignal|object} [opts.signal]  stops the search
 * @param {(ms) => Promise} [opts.sleep]
 * @param {() => number} [opts.now]
 * @param {() => boolean} [opts.isCancelled]
 * @param {(p: object) => void} [opts.onProgress]  hugin-pow progress reports
 * @param {number} [opts.maxTooHardJobs]  default 3
 * @param {(info: { jobs: number }) => Promise|void} [opts.onTooHardJobs]
 * @param {(name, data) => void} [opts.onEvent]  `pow_stale_local`, `pow_job_too_hard`,
 *   `pow_share_found_local`
 * @returns {Promise<{ job, shares, allShares } | null>}
 */
async function searchShares({
  requestJob,
  tracker,
  backend,
  maxJobTimeMs = POW_MAX_JOB_TIME_MS,
  requiredShares = POW_REQUIRED_SHARES,
  roundMs = POW_ROUND_MS,
  sliceMs,
  signal,
  sleep = defaultSleep,
  now = Date.now,
  isCancelled = () => false,
  onProgress,
  maxTooHardJobs = POW_MAX_TOO_HARD_JOBS,
  onTooHardJobs,
  onEvent = noop
}) {
  if (typeof requestJob !== 'function') throw new TypeError('searchShares: requestJob must be a function')
  if (!tracker || typeof tracker.mine !== 'function' || typeof tracker.isUsable !== 'function') {
    throw new TypeError('searchShares: tracker must be a hugin-pow JobTracker')
  }
  if (!backend || (typeof backend.findShare !== 'function' && typeof backend.hash !== 'function')) {
    throw new TypeError('searchShares: backend must have findShare and/or hash')
  }
  const start = now()
  let job = null
  let shares = []
  const allShares = []
  const seen = new Set()
  const stopped = () => isCancelled() || isAborted(signal)

  while (now() - start < maxJobTimeMs && shares.length < requiredShares && !stopped()) {
    const issued = await requestJob()
    if (stopped()) break
    if (issued && typeof tracker.isTooHard === 'function' && tracker.isTooHard(issued)) {
      const jobs = Number.isFinite(tracker.tooHardJobs) ? tracker.tooHardJobs : 1
      onEvent('pow_job_too_hard', { jobId: issued.job_id, difficulty: targetToDifficulty(issued.target), jobs })
      if (jobs >= Math.max(1, maxTooHardJobs) && typeof onTooHardJobs === 'function') {
        await onTooHardJobs({ jobs })
        tracker.clear()
        if (stopped()) break
      }
      await sleep(250)
      continue
    }
    if (issued && !tracker.isUsable(issued)) {
      onEvent('pow_stale_local', { jobId: issued.job_id })
      await sleep(250)
      continue
    }
    if (!tracker.current) {
      await sleep(250)
      continue
    }

    const remaining = Math.max(1, maxJobTimeMs - (now() - start))
    const timeBudgetMs = Math.max(1, Math.min(roundMs !== undefined && roundMs !== null ? roundMs : remaining, remaining))
    const opts = { backend, signal, timeBudgetMs }
    if (sliceMs !== undefined && sliceMs !== null) opts.sliceMs = sliceMs
    if (typeof onProgress === 'function') opts.onProgress = onProgress
    const found = await tracker.mine(opts)
    if (stopped()) break

    if (found) {
      // all shares of one post belong to one job
      if (job && !sameJob(job, found.job)) shares = []
      job = found.job
      const share = normalizeShare(found.share)
      if (share && !seen.has(share.nonce)) {
        seen.add(share.nonce)
        allShares.push(share)
        shares.push(share)
        onEvent('pow_share_found_local', { jobId: job.job_id })
      }
      if (shares.length >= requiredShares) return { job: plainJob(job), shares, allShares }
    }
    await sleep(50)
  }
  return null
}

/** `{ job_id, blob, target }`: what a post or registration carries as `pow.job`. */
function plainJob(j) {
  return { job_id: j.job_id, blob: j.blob, target: j.target }
}

/**
 * Sends a post or registration with proof of work, retrying like both apps
 * (`send_pow_packet` / `message` / `register`): up to `maxAttempts` attempts, plus up to
 * `maxRecalcRetries` extra ones when the answer says the share itself was refused; a new job is
 * requested before every retry; the delay before a retry is `retryDelayMs` (1 s after
 * `cooldown` / `rate_limit`). An attempt without a share ends as `{ success: false, reason:
 * 'PoW required' }`.
 *
 * @param {object} opts
 * @param {string} opts.hash            message hash (stable across retries)
 * @param {number} opts.timestamp       packet timestamp / id
 * @param {string} opts.context         auth context (`postAuthContext` / `registerAuthContext`)
 * @param {() => Promise<{ job, shares } | null>} opts.computePow
 * @param {(pow: object) => object} opts.buildPacket   packet for a `powField`
 * @param {(packet: object) => Promise<object>} opts.send  the node's answer `{ success, reason?, ... }`
 * @param {() => Promise} [opts.refreshJob]  drop the current job and ask for a new one
 * @param {number} [opts.maxAttempts]
 * @param {number} [opts.maxRecalcRetries]
 * @param {(ms) => Promise} [opts.sleep]
 * @param {() => boolean} [opts.isCancelled]
 * @param {(name, data) => void} [opts.onEvent]  `no_shares`, `pow_auth_failed`, `retry`, `recalc`, `error`
 * @param {{ publicKey, secretKey }} [opts.authKeyPair]  fixed one-time key (tests only)
 */
async function sendWithPow({
  hash,
  timestamp,
  context = '',
  computePow,
  buildPacket,
  send,
  refreshJob = async () => {},
  maxAttempts = 3,
  maxRecalcRetries = 3,
  sleep = defaultSleep,
  isCancelled = () => false,
  onEvent = noop,
  authKeyPair
}) {
  if (typeof computePow !== 'function' || typeof buildPacket !== 'function' || typeof send !== 'function') {
    throw new TypeError('sendWithPow: computePow, buildPacket and send must be functions')
  }
  let last = { success: false, reason: 'unknown' }
  let recalcRetries = 0
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    if (isCancelled()) return { success: false, reason: 'cancelled' }
    let found = null
    try {
      found = await computePow()
    } catch (err) {
      onEvent('error', { attempt, message: err && err.message })
    }
    if (!found || !Array.isArray(found.shares) || found.shares.length === 0) {
      onEvent('no_shares', { attempt })
      await refreshJob()
      last = { success: false, reason: 'PoW required' }
      continue
    }

    const powAuth = buildPowAuth({ hash, timestamp, shares: found.shares, context, keyPair: authKeyPair })
    if (!powAuth) {
      onEvent('pow_auth_failed', { attempt })
      await sleep(100)
      continue
    }

    let res
    try {
      res = await send(buildPacket(powField({ job: found.job, shares: found.shares, auth: powAuth })))
    } catch (err) {
      // an invalid or oversized packet does not get better by retrying
      const invalid = err && (err.code === 'HUGIN_PACKET_INVALID' || err.name === 'PacketError')
      onEvent('error', { attempt, message: err && err.message })
      return { success: false, reason: invalid ? 'invalid_packet' : 'send_exception' }
    }
    if (res && res.success === true) return res

    last = res || { success: false, reason: 'unknown' }
    if (!shouldRetry(last)) break

    const recalc = shouldRecalcShare(last)
    if (recalc && recalcRetries < maxRecalcRetries) {
      recalcRetries++
      onEvent('recalc', { attempt, recalcRetries, reason: last.reason, jobId: found.job && found.job.job_id })
      attempt-- // share churn does not use up a main attempt
    }
    onEvent('retry', { attempt, reason: last.reason, jobId: found.job && found.job.job_id })
    await refreshJob()
    await sleep(retryDelayMs(last))
  }
  return last
}

module.exports = {
  // hugin-pow: jobs, nonces, targets, shares (hugin-pow/job)
  ...job,
  // hugin-pow: pow.auth (hugin-pow/auth)
  postAuthContext: auth.postAuthContext,
  registerAuthContext: auth.registerAuthContext,
  powAuthPayload: auth.powAuthPayload,
  buildPowAuth: auth.buildPowAuth,
  verifyPowAuth: auth.verifyPowAuth,
  // hugin-pow: mining and the job tracker (hugin-pow/mine), relay-side check (hugin-pow/verify)
  checkBackend: mine.checkBackend,
  mineShare: mine.mineShare,
  JobTracker,
  isStaleAnswer: mine.isStaleAnswer,
  StopController: mine.StopController,
  PREVIOUS_BLOCK_GRACE_MS: mine.PREVIOUS_BLOCK_GRACE_MS,
  verifyPow,
  // network side
  POW_ROUND_MS,
  POW_MAX_TOO_HARD_JOBS,
  shouldRetry,
  shouldRecalcShare,
  retryDelayMs,
  searchShares,
  sendWithPow
}
