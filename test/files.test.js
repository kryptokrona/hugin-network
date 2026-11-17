'use strict'

// hugin-network/files: file names from peers, share/download between two Files instances that
// replicate over an encrypted stream pair (what a hyperswarm connection is), the host hooks
// (autoSyncFiles, knownFile, storageLimit), removal and stats, and replication next to the
// hugin-messages channel on a Hugin swarm connection over a local DHT testnet.
//
// Runs on Node and Bare: temporary directories come from test-tmp (bare-os/bare-fs on Bare),
// files are read and written through the package's `#fs` import.

const test = require('brittle')
const b4a = require('b4a')
const tmp = require('test-tmp')
const NoiseSecretStream = require('@hyperswarm/secret-stream')
const Protomux = require('protomux')
const c = require('compact-encoding')
const createTestnet = require('hyperdht/testnet.js')
const fs = require('#fs')
const { Files, FilesError, EVENTS, DEFAULTS, safeFileName, normalizeFile } = require('../lib/files.js')
const wire = require('../lib/wire.js')
const S = require('../lib/sanitize.js')
const { createHuginSwarm } = require('../lib/swarm.js')
const { sha512, toHex, blake2b256Hex } = require('../lib/bytes.js')
const { ADDRESS, ADDRESS_2, HASH, HASH_2, CONTENT_HASH, TOPIC, hex } = require('./helpers.js')

const ADDRESS_3 = 'SEKRe' + 'c'.repeat(94)

/** Stand-in for the XKR message signature: only the holder of `address` "can" produce it. */
function fakeSign(address, message) {
  return toHex(sha512(b4a.from(address + '|' + message, 'utf8')))
}

const TOPIC_2 = 'f6'.repeat(32)
const DAY = 24 * 60 * 60 * 1000

/** Deterministic bytes of a given length (several hyperblobs blocks for the larger sizes). */
function bytesOf(length, seed = 1) {
  const out = b4a.alloc(length)
  for (let i = 0; i < length; i++) out[i] = (i * 31 + seed) & 0xff
  return out
}

const PHOTO = bytesOf(200 * 1024, 7)

function noop() {}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms))

/** Polls `fn` until it is true; throws after `ms`. */
async function waitUntil(fn, ms = 20000) {
  const start = Date.now()
  while (!fn()) {
    if (Date.now() - start > ms) throw new Error('timed out')
    await sleep(20)
  }
}

/**
 * A Files instance on its own temporary directory. `opts.autoSync`, `opts.saveDownloads`,
 * `opts.address`, `opts.name`, `opts.host` (extra hooks), `opts.files` (extra options).
 */
async function makeFiles(t, opts = {}) {
  const dir = await tmp(t)
  const known = new Set()
  const address = opts.address || ADDRESS
  const host = {
    identity: () => ({ address, name: opts.name || 'alice' }),
    sign: async (payload) => fakeSign(address, payload),
    verify: async (payload, addr, signature) => signature === fakeSign(addr, payload),
    autoSyncFiles: () => (opts.autoSync === undefined ? true : opts.autoSync),
    knownFile: (hash) => known.has(hash),
    paths: { storage: dir + '/corestorage', downloads: dir + '/downloads' },
    ...(opts.host || {})
  }
  const files = new Files({
    host,
    pruneIntervalMs: 0,
    saveDownloads: !!opts.saveDownloads,
    downloadTimeoutMs: 20000,
    ...(opts.files || {})
  })
  t.teardown(() => files.close())
  return { files, dir, known, host }
}

/** Two connected NoiseSecretStreams (a hyperswarm connection without the DHT). */
function streamPair(t) {
  const a = new NoiseSecretStream(true)
  const b = new NoiseSecretStream(false)
  a.on('error', noop)
  b.on('error', noop)
  a.rawStream.pipe(b.rawStream).pipe(a.rawStream)
  t.teardown(() => {
    a.destroy()
    b.destroy()
  })
  return [a, b]
}

/** Resolves with the first `name` event whose payload passes `filter`; rejects after `ms`. */
function once(t, emitter, name, filter = () => true, ms = 60000) {
  let done = false
  let timer = null
  let on = null
  const p = new Promise((resolve, reject) => {
    on = (data) => {
      if (done || !filter(data)) return
      done = true
      clearTimeout(timer)
      emitter.off(name, on)
      resolve(data)
    }
    timer = setTimeout(() => {
      if (done) return
      done = true
      emitter.off(name, on)
      reject(new Error('timed out waiting for ' + name))
    }, ms)
    emitter.on(name, on)
  })
  t.teardown(() => {
    done = true
    clearTimeout(timer)
    emitter.off(name, on)
  })
  return p
}

/** Records every event of `names` on `emitter`. */
function record(emitter, names = Object.values(EVENTS)) {
  const log = []
  for (const name of names) emitter.on(name, (data) => log.push([name, data]))
  return log
}

async function exists(path) {
  try {
    await fs.promises.stat(path)
    return true
  } catch {
    return false
  }
}

/** Two rooms on the same topic, replicating over a stream pair. */
async function connectedPair(t, optsA = {}, optsB = {}) {
  const A = await makeFiles(t, { address: ADDRESS, name: 'alice', ...optsA })
  const B = await makeFiles(t, { address: ADDRESS_2, name: 'bob', ...optsB })
  await A.files.openRoom(TOPIC, { key: 'room-invite' })
  await B.files.openRoom(TOPIC, { key: 'room-invite' })
  const [sa, sb] = streamPair(t)
  t.ok(A.files.replicate(sa, TOPIC))
  t.ok(B.files.replicate(sb, TOPIC))
  return { A, B }
}

// =============================================================================================
// file names from peers

test('safeFileName: separators, .., control characters and length are refused', (t) => {
  for (const name of ['photo.png', 'a b (1).jpg', 'bild-\u00e5\u00e4\u00f6.png', '.hidden', 'x'.repeat(100), 'report.final.pdf']) {
    t.is(safeFileName(name), name, `kept: ${name}`)
  }
  const refused = [
    '',
    '.',
    '..',
    '...',
    '../escape.png',
    '../../escape.png',
    'a/b.png',
    '/etc/passwd',
    'a\\b.png',
    '..\\escape.png',
    'C:\\Windows\\x.dll',
    'file..png',
    'nul\u0000.png',
    'line\nbreak.png',
    'tab\t.png',
    'x'.repeat(101),
    null,
    undefined,
    42,
    {}
  ]
  for (const name of refused) t.is(safeFileName(name), null, `refused: ${JSON.stringify(name)}`)

  t.is(safeFileName('\u00e5'.repeat(100)), '\u00e5'.repeat(100), '100 characters / 200 bytes is fine')
  t.is(safeFileName('\ud83d\ude00'.repeat(50)), '\ud83d\ude00'.repeat(50), '100 UTF-16 units, 200 bytes')

  t.is(safeFileName('a:b.png'), 'a_b.png', 'Windows-reserved characters become _')
  t.is(safeFileName('what?<>|*".png'), 'what______.png')
  t.is(safeFileName('gpj.\u202eexe'), 'gpj._exe', 'bidirectional override replaced')
  t.is(safeFileName('name. . '), 'name', 'trailing dots and spaces removed')
  t.is(safeFileName('CON'), '_CON', 'device name prefixed')
  t.is(safeFileName('nul.txt'), '_nul.txt')
  t.is(safeFileName('com1.log'), '_com1.log')
  t.is(safeFileName('console.log'), 'console.log', 'only exact device names')
  let nfc = false
  try {
    nfc = 'e\u0301'.normalize('NFC') === '\u00e9'
  } catch {}
  if (nfc) t.is(safeFileName('e\u0301.png'), '\u00e9.png', 'NFC')
  else t.comment('String.prototype.normalize without NFC support in this runtime: NFC case skipped')
})

test('normalizeFile: announcement, UI remote file and drive metadata shapes', (t) => {
  const ann = wire.fileShared({
    fileName: 'a.png',
    address: ADDRESS,
    name: 'alice',
    topic: TOPIC,
    size: 10,
    time: 1731500000000,
    hash: HASH,
    contentHash: CONTENT_HASH,
    signature: 'sig'
  })
  t.alike(normalizeFile(ann), { hash: HASH, contentHash: CONTENT_HASH, fileName: 'a.png', size: 10, time: 1731500000000, address: ADDRESS, name: 'alice', signature: 'sig' })
  t.alike(normalizeFile({ hash: HASH, contentHash: CONTENT_HASH, fileName: 'a.png', size: '10', time: '1731500000000' }), {
    hash: HASH,
    contentHash: CONTENT_HASH,
    fileName: 'a.png',
    size: 10,
    time: 1731500000000,
    address: '',
    name: '',
    signature: ''
  }, 'numeric strings (desktop history rows) and missing optional fields')
  t.is(normalizeFile({ ...ann, hash: 'zz' }), null)
  t.is(normalizeFile({ ...ann, contentHash: undefined }), null, 'contentHash is required')
  t.is(normalizeFile({ ...ann, contentHash: 'ab'.repeat(31) }), null)
  t.is(normalizeFile({ ...ann, contentHash: CONTENT_HASH.toUpperCase() }).contentHash, CONTENT_HASH, 'lower case')
  t.is(normalizeFile({ ...ann, size: -1 }), null)
  t.is(normalizeFile({ ...ann, size: 'big' }), null)
  t.is(normalizeFile({ ...ann, time: undefined }), null)
  t.is(normalizeFile({ ...ann, address: 'x'.repeat(100) }), null)
  t.is(normalizeFile({ ...ann, fileName: 'x'.repeat(101) }), null)
  t.is(normalizeFile(null), null)
})

// =============================================================================================
// rooms

test('openRoom: storage layout, stable drive key, validation', async (t) => {
  const { files, dir, host } = await makeFiles(t)
  const key = await files.openRoom(TOPIC.toUpperCase(), { key: 'invite' })
  t.ok(/^[0-9a-f]{64}$/.test(key), 'drive key is 64 hex')
  t.is(files.driveKey(TOPIC), key)
  t.is(await files.openRoom(TOPIC), key, 'opening twice returns the same drive')
  t.ok(await exists(dir + '/corestorage/' + TOPIC + '/files'), '<storage>/<topic>/files')
  t.alike(files.rooms(), [{ topic: TOPIC, key: 'invite', dm: false, driveKey: key }])
  t.ok(files.drive(TOPIC))

  await t.exception(() => files.openRoom('not a topic'), /64 hex/)
  t.is(files.replicate({}, 'xyz'), false)
  t.is(files.replicate({}, TOPIC_2), false, 'room not open')
  t.is(await files.addPeer(TOPIC, 'zz'), false)
  t.is(await files.addPeer(TOPIC, key), false, 'own drive key')
  t.is(files.driveKey(TOPIC_2), null)

  // the same directory gives the same drive key after a restart
  t.ok(await files.closeRoom(TOPIC))
  t.is(files.driveKey(TOPIC), null)
  const again = new Files({ host, pruneIntervalMs: 0 })
  t.teardown(() => again.close())
  t.is(await again.openRoom(TOPIC), key, 'drive key survives a restart')

  const nopaths = new Files({ host: {} })
  t.teardown(() => nopaths.close())
  try {
    await nopaths.openRoom(TOPIC)
    t.fail('no storage path')
  } catch (err) {
    t.ok(err instanceof FilesError)
    t.is(err.code, 'HUGIN_FILES_PATHS')
  }
  t.alike(nopaths.rooms(), [])

  await files.close()
  await t.exception(files.openRoom(TOPIC), /closed/)
})

// =============================================================================================
// share

test('share: stores the file and returns an announcement every old peer accepts', async (t) => {
  const { files, dir } = await makeFiles(t)
  await files.openRoom(TOPIC, { key: 'invite' })
  const events = record(files)

  const ann = await files.share(TOPIC, PHOTO, { fileName: 'photo.png', time: 1731500000000 })
  t.is(ann.info, 'file-shared')
  t.is(ann.type, 'file')
  t.is(ann.topic, TOPIC)
  t.is(ann.address, ADDRESS)
  t.is(ann.name, 'alice')
  t.is(ann.size, PHOTO.byteLength)
  t.ok(/^[0-9a-f]{64}$/.test(ann.hash), 'random 64-hex hash')
  t.is(ann.contentHash, blake2b256Hex(PHOTO), 'contentHash = BLAKE2b-256 of the bytes')
  t.is(ann.signature, fakeSign(ADDRESS, wire.fileSigningPayload(ann)), 'signed by host.sign over the hugin/file payload')
  t.is(wire.fileSigningPayload(ann), 'hugin/file\n' + JSON.stringify([TOPIC, ann.hash, blake2b256Hex(PHOTO), PHOTO.byteLength, 1731500000000, 'photo.png', ADDRESS]))
  t.absent('driveKey' in ann, 'no driveKey (receivers use the one from joined)')
  t.ok(S.fileMessage(JSON.parse(wire.encode(ann))).ok, 'accepted by the receive validator')
  t.alike(b4a.from(await files.read(ann.hash, TOPIC)), b4a.from(PHOTO))
  t.is(files.used, PHOTO.byteLength)

  const uploaded = events.find(([name]) => name === EVENTS.UPLOADED)[1]
  t.alike(uploaded, {
    hash: ann.hash,
    contentHash: ann.contentHash,
    fileName: 'photo.png',
    chat: ADDRESS,
    address: ADDRESS,
    name: 'alice',
    time: 1731500000000,
    size: PHOTO.byteLength,
    topic: TOPIC,
    key: 'invite',
    dm: false,
    path: 'storage'
  })

  // from a path, with the UI's hash (desktop)
  const src = dir + '/clip.mp4'
  await fs.promises.writeFile(src, bytesOf(3000, 3))
  const ann2 = await files.share(TOPIC, src, { hash: HASH, signature: 'given' })
  t.is(ann2.fileName, 'clip.mp4', 'base name of the path')
  t.is(ann2.hash, HASH)
  t.is(ann2.size, 3000)
  t.is(ann2.contentHash, blake2b256Hex(bytesOf(3000, 3)), 'contentHash of the file read from the path')
  t.is(ann2.signature, 'given')

  const list = await files.list(TOPIC)
  t.is(list.length, 2)
  const meta = list.find((m) => m.hash === HASH)
  t.alike(meta, {
    name: 'alice',
    topic: TOPIC,
    time: ann2.time,
    size: 3000,
    hash: HASH,
    contentHash: ann2.contentHash,
    fileName: 'clip.mp4',
    address: ADDRESS,
    signature: 'given',
    info: 'file-shared',
    type: 'file'
  }, 'drive metadata as both apps store it')

  const code = async (p) => {
    try {
      await p
      return 'resolved'
    } catch (err) {
      return err.code || err.name
    }
  }
  t.is(await code(files.share(TOPIC, PHOTO, { fileName: '../x.png' })), 'HUGIN_FILES_NAME')
  t.is(await code(files.share(TOPIC, PHOTO, { fileName: 'a/b.png' })), 'HUGIN_FILES_NAME')
  t.is(await code(files.share(TOPIC, PHOTO)), 'HUGIN_FILES_NAME', 'bytes need a fileName')
  t.is(await code(files.share(TOPIC, PHOTO, { fileName: 'x.png', hash: 'zz' })), 'HUGIN_WIRE_INVALID')
  t.is(await code(files.share(TOPIC, PHOTO, { fileName: 'x.png', hash: HASH })), 'HUGIN_FILES_EXISTS')
  t.is(await code(files.share(TOPIC, 42, { fileName: 'x.png' })), 'HUGIN_FILES_INVALID')
  t.is(await code(files.share(TOPIC_2, PHOTO, { fileName: 'x.png' })), 'HUGIN_FILES_NO_ROOM')
  t.is(await code(files.share(TOPIC, dir + '/missing.png')), 'ENOENT')

  const unsigned = new Files({ host: { paths: { storage: dir + '/other' } }, pruneIntervalMs: 0 })
  t.teardown(() => unsigned.close())
  await unsigned.openRoom(TOPIC)
  t.is(await code(unsigned.share(TOPIC, PHOTO, { fileName: 'x.png', address: ADDRESS, name: 'n' })), 'HUGIN_FILES_SIGN')
})

// =============================================================================================
// share -> download

test('round trip: a peer drive is watched and an auto-synced file lands in storage and downloads', async (t) => {
  const { A, B } = await connectedPair(t, {}, { saveDownloads: true })
  const events = record(B.files)
  t.ok(await B.files.addPeer(TOPIC, A.files.driveKey(TOPIC), { owners: [ADDRESS] }))

  const downloaded = once(t, B.files, EVENTS.DOWNLOADED)
  const ann = await A.files.share(TOPIC, PHOTO, { fileName: 'photo.png' })
  const d = await downloaded

  t.is(d.hash, ann.hash)
  t.is(d.auto, true)
  t.is(d.chat, ADDRESS, 'chat = sender address')
  t.is(d.driveKey, A.files.driveKey(TOPIC))
  t.is(d.key, 'room-invite')
  t.is(d.dm, false)
  t.is(d.path, B.dir + '/downloads/photo.png', 'written to the downloads directory (saveDownloads)')
  t.alike(b4a.from(await fs.promises.readFile(d.path)), b4a.from(PHOTO))
  t.alike(b4a.from(await B.files.read(ann.hash, TOPIC)), b4a.from(PHOTO), 'copied into our own drive')

  const names = events.map(([name]) => name)
  t.ok(names.includes(EVENTS.DOWNLOADING))
  t.ok(events.some(([name, data]) => name === EVENTS.PROGRESS && data.progress === 100))
  t.absent(names.includes(EVENTS.REMOTE), 'auto-synced files are not offered as remote')
  t.absent(names.includes(EVENTS.ERROR))

  const meta = (await B.files.list(TOPIC)).find((m) => m.hash === ann.hash)
  t.is(meta.address, ADDRESS, 'sender kept in the metadata')
  t.is(meta.signature, ann.signature)
  t.ok(meta.syncedAt > 0)

  // re-offered (Ping list, history): already stored
  t.alike(await B.files.handleRemote(TOPIC, ann, { driveKey: A.files.driveKey(TOPIC) }), { action: 'ignored', reason: 'known' })

  // a second file through the live watch, same name: a free name in downloads
  const second = once(t, B.files, EVENTS.DOWNLOADED, (e) => e.fileName === 'photo.png' && e.hash !== ann.hash)
  await A.files.share(TOPIC, bytesOf(1000, 9), { fileName: 'photo.png' })
  t.is((await second).path, B.dir + '/downloads/photo (1).png')
})

test('manual download: autoSyncFiles false offers file:remote, download() fetches on request', async (t) => {
  const { A, B } = await connectedPair(t, {}, { autoSync: false })
  const driveKey = A.files.driveKey(TOPIC)

  // the announcement path (no addPeer, no watch): the file arrives before or after the drive length
  const ann = await A.files.share(TOPIC, PHOTO, { fileName: 'photo.png' })
  const received = S.fileMessage(JSON.parse(wire.encode(ann))).value
  const remoteEvent = once(t, B.files, EVENTS.REMOTE)
  const res = await B.files.handleRemote(TOPIC, received, { driveKey })
  t.is(res.action, 'remote')
  const ev = await remoteEvent
  t.alike(ev, {
    key: 'room-invite',
    topic: TOPIC,
    dm: false,
    file: {
      fileName: 'photo.png',
      address: ADDRESS,
      size: PHOTO.byteLength,
      topic: TOPIC,
      key: 'room-invite',
      chat: ADDRESS,
      hash: ann.hash,
      contentHash: ann.contentHash,
      name: 'alice',
      time: ann.time,
      signature: ann.signature,
      driveKey
    }
  })
  t.alike(await B.files.handleRemote(TOPIC, received, { driveKey }), { action: 'ignored', reason: 'notified' }, 'offered once')
  t.alike(await B.files.handleRemote(TOPIC, received, {}), { action: 'ignored', reason: 'drive_key' })
  t.is(await B.files.read(ann.hash, TOPIC), null, 'nothing fetched yet')

  const got = await B.files.download(TOPIC, ev.file)
  t.alike(got, { success: true, hash: ann.hash, path: 'storage' }, 'kept in storage (desktop behaviour)')
  t.alike(b4a.from(await B.files.read(ann.hash, TOPIC)), b4a.from(PHOTO))
  t.alike(await B.files.download(TOPIC, ev.file), { success: false, error: 'known' })

  // save to downloads (desktop's button): never overwrites, refuses unsafe names
  const s1 = await B.files.saveToDownloads(ann.hash, 'photo.png', TOPIC)
  t.alike(s1, { success: true, filePath: B.dir + '/downloads/photo.png' })
  const s2 = await B.files.saveToDownloads(ann.hash, 'photo.png', TOPIC)
  t.alike(s2, { success: true, filePath: B.dir + '/downloads/photo (1).png' })
  t.alike(b4a.from(await fs.promises.readFile(s2.filePath)), b4a.from(PHOTO))

  // an existing file and a dangling symlink at the name are skipped, never overwritten or followed
  await fs.promises.writeFile(B.dir + '/downloads/mine.png', b4a.from('keep me'))
  const s3 = await B.files.saveToDownloads(ann.hash, 'mine.png', TOPIC)
  t.is(s3.filePath, B.dir + '/downloads/mine (1).png')
  t.is(b4a.toString(await fs.promises.readFile(B.dir + '/downloads/mine.png')), 'keep me', 'existing file kept')
  await fs.promises.symlink(B.dir + '/link-target.png', B.dir + '/downloads/link.png')
  const s4 = await B.files.saveToDownloads(ann.hash, 'link.png', TOPIC)
  t.is(s4.filePath, B.dir + '/downloads/link (1).png')
  t.absent(await exists(B.dir + '/link-target.png'), 'symlink not followed')
  t.is((await B.files.saveToDownloads(ann.hash, '../photo.png', TOPIC)).success, false)
  t.is((await B.files.saveToDownloads(ann.hash, '/tmp/photo.png', TOPIC)).success, false)
  t.alike(await B.files.saveToDownloads(HASH_2, 'x.png', TOPIC), { success: false, error: 'File not found in storage' })
  t.alike(await B.files.saveToDownloads(ann.hash, 'x.png', TOPIC_2), { success: false, error: 'Room not found' })
  t.absent(await exists(B.dir + '/photo.png'))

  const stats = await B.files.stats()
  t.is(stats.rooms[0].files[0].savedToDisk, true)

  // missing pieces
  t.alike(await B.files.download(TOPIC_2, ev.file), { success: false, error: 'room' })
  t.alike(await B.files.download(TOPIC, { ...ev.file, hash: 'zz' }), { success: false, error: 'invalid' })
  t.alike(await B.files.download(TOPIC, { ...ev.file, hash: HASH_2, driveKey: undefined }), { success: false, error: 'drive_key' })
})

test('knownFile and autoSyncFiles: known hashes are not fetched, DMs default to auto-sync', async (t) => {
  const { A, B } = await connectedPair(t, {}, { saveDownloads: true })
  const known = 'ab'.repeat(32)
  B.known.add(known)
  t.ok(await B.files.addPeer(TOPIC, A.files.driveKey(TOPIC)))
  const events = record(B.files)

  const sentinel = once(t, B.files, EVENTS.DOWNLOADED, (e) => e.hash === 'cd'.repeat(32))
  await A.files.share(TOPIC, bytesOf(500, 1), { fileName: 'known.png', hash: known })
  await A.files.share(TOPIC, bytesOf(500, 2), { fileName: 'new.png', hash: 'cd'.repeat(32) })
  await sentinel

  t.is(await B.files.read(known, TOPIC), null, 'known hash not fetched')
  t.absent(events.some(([, e]) => e.hash === known), 'and not offered')
  t.absent(await exists(B.dir + '/downloads/known.png'))
  t.alike(await B.files.download(TOPIC, { hash: known, contentHash: CONTENT_HASH, fileName: 'known.png', size: 500, time: Date.now(), driveKey: A.files.driveKey(TOPIC) }), {
    success: false,
    error: 'known'
  }, 'manual download honours knownFile too')

  // hook arguments; default policy without the hook
  const calls = []
  const H = await makeFiles(t, { host: { autoSyncFiles: (...args) => calls.push(args) && false } })
  await H.files.openRoom(TOPIC_2, { key: ADDRESS_2, dm: true })
  const r = await H.files.handleRemote(TOPIC_2, { hash: HASH, contentHash: CONTENT_HASH, fileName: 'a.png', size: 1, time: Date.now(), address: ADDRESS_2 }, { driveKey: TOPIC, address: ADDRESS_2 })
  t.is(r.action, 'remote')
  t.is(r.file.key, ADDRESS_2, 'a DM remote file is keyed by the sender address')
  t.alike(calls[0].slice(0, 3), [TOPIC_2, ADDRESS_2, true], 'autoSyncFiles(topic, roomKey, dm, file)')
  t.is(calls[0][3].hash, HASH)

  const D = await makeFiles(t, { host: { autoSyncFiles: undefined } })
  await D.files.openRoom(TOPIC, { key: 'room' })
  const old = { hash: HASH, contentHash: CONTENT_HASH, fileName: 'a.png', size: 1, time: Date.now(), address: ADDRESS }
  t.is((await D.files.handleRemote(TOPIC, old, { driveKey: TOPIC_2, address: ADDRESS })).action, 'remote', 'rooms: no auto-sync without the hook')

  // files older than the prune age are offered, not fetched
  const O = await makeFiles(t)
  await O.files.openRoom(TOPIC, { key: 'room' })
  const stale = { ...old, time: Date.now() - DEFAULTS.pruneMaxAgeMs - DAY }
  t.is((await O.files.handleRemote(TOPIC, stale, { driveKey: TOPIC_2, address: ADDRESS })).action, 'remote')
})

test('storage limit: downloads and shares above the limit are refused', async (t) => {
  const { A, B } = await connectedPair(t)
  t.is(B.files.limit, DEFAULTS.storageLimit, '100 GB by default')
  B.files.setLimit(1000)
  t.is(B.files.limit, 1000)
  t.ok(await B.files.addPeer(TOPIC, A.files.driveKey(TOPIC)))

  const failed = once(t, B.files, EVENTS.ERROR)
  const offered = once(t, B.files, EVENTS.REMOTE)
  const ann = await A.files.share(TOPIC, PHOTO, { fileName: 'big.png' })
  const err = await failed
  t.is(err.error, 'limit')
  t.is(err.hash, ann.hash)
  t.is(err.auto, true)
  const remote = await offered
  t.is(remote.file.hash, ann.hash, 'offered for a manual download instead')
  t.is(await B.files.read(ann.hash, TOPIC), null)
  t.is((await B.files.stats()).limit, 1000)

  t.alike(await B.files.download(TOPIC, remote.file), { success: false, error: 'limit' })
  B.files.setLimit(10 * 1024 * 1024)
  t.is((await B.files.download(TOPIC, remote.file)).success, true)
  t.is(B.files.used, PHOTO.byteLength)

  A.files.setLimit(PHOTO.byteLength + 10)
  try {
    await A.files.share(TOPIC, bytesOf(11), { fileName: 'one-too-many.png' })
    t.fail('over the limit')
  } catch (e) {
    t.is(e.code, 'HUGIN_FILES_LIMIT')
  }
  await t.exception(async () => B.files.setLimit(-1), /non-negative/)
  await t.exception(async () => B.files.setLimit('5'), /non-negative/)

  const H = await makeFiles(t, { host: { storageLimit: () => 123 } })
  t.is(H.files.limit, 123, 'host.storageLimit')
  H.files.setLimit(456)
  t.is(H.files.limit, 456, 'setLimit overrides the hook')
})

test('path safety: a peer entry with an unsafe file name is never fetched or written', async (t) => {
  const { A, B } = await connectedPair(t, {}, { saveDownloads: true })
  const driveA = A.files.drive(TOPIC)
  const badNames = ['../../escape.png', '..\\..\\escape.png', 'sub/escape.png', '/tmp/escape.png', '..']
  const hashes = []
  for (let i = 0; i < badNames.length; i++) {
    const hash = (10 + i).toString(16).repeat(64)
    hashes.push(hash)
    // written straight into the drive: share() refuses these names
    await driveA.put('/' + hash, bytesOf(100, i), {
      metadata: { name: 'carol', topic: TOPIC, time: Date.now(), size: 100, hash, contentHash: blake2b256Hex(bytesOf(100, i)), fileName: badNames[i], address: ADDRESS, signature: '', info: 'file-shared', type: 'file' }
    })
  }
  const events = record(B.files)
  const sentinel = once(t, B.files, EVENTS.DOWNLOADED, (e) => e.fileName === 'ok.png')
  t.ok(await B.files.addPeer(TOPIC, A.files.driveKey(TOPIC), { owners: [ADDRESS] }))
  await A.files.share(TOPIC, bytesOf(100, 99), { fileName: 'ok.png' })
  await sentinel

  for (const hash of hashes) t.is(await B.files.read(hash, TOPIC), null, 'not fetched')
  t.absent(events.some(([, e]) => hashes.includes(e.hash) || (e.file && hashes.includes(e.file.hash))), 'not offered either')
  t.alike(await fs.promises.readdir(B.dir + '/downloads'), ['ok.png'], 'only the safe file in downloads')
  t.absent(await exists(B.dir + '/escape.png'))
  t.absent(await exists(B.dir + '/corestorage/escape.png'))

  for (let i = 0; i < badNames.length; i++) {
    const res = await B.files.download(TOPIC, { hash: hashes[i], contentHash: blake2b256Hex(bytesOf(100, i)), fileName: badNames[i], size: 100, time: Date.now(), driveKey: A.files.driveKey(TOPIC) })
    t.alike(res, { success: false, error: 'file_name' }, `manual download refused: ${badNames[i]}`)
  }
  t.ok(events.some(([name, e]) => name === EVENTS.ERROR && e.error === 'file_name'), 'manual refusals emit file:error')
})

// =============================================================================================
// removal and stats

test('deleteFile, purgeRoom, prune and stats', async (t) => {
  const { files } = await makeFiles(t)
  await files.openRoom(TOPIC, { key: 'invite' })
  await files.openRoom(TOPIC_2, { key: ADDRESS_2, dm: true })
  const removed = record(files, [EVENTS.REMOVED])
  const now = Date.now()

  const a = await files.share(TOPIC, bytesOf(1000), { fileName: 'a.png', time: now - 3000 })
  const b = await files.share(TOPIC, bytesOf(2000), { fileName: 'b.png', time: now - 2000 })
  const cc = await files.share(TOPIC, bytesOf(3000), { fileName: 'c.png', time: now - 1000 })
  const d = await files.share(TOPIC_2, bytesOf(4000), { fileName: 'd.png', time: now })

  let stats = await files.stats()
  t.is(stats.totalFiles, 4)
  t.is(stats.totalSize, 10000)
  t.is(stats.used, 10000)
  t.is(stats.limit, DEFAULTS.storageLimit)
  const room = stats.rooms.find((r) => r.topic === TOPIC)
  t.alike({ key: room.key, dm: room.dm, size: room.size, fileCount: room.fileCount }, { key: 'invite', dm: false, size: 6000, fileCount: 3 })
  t.alike(room.files.map((f) => f.fileName), ['c.png', 'b.png', 'a.png'], 'newest first')
  t.alike(room.files[0], { hash: cc.hash, fileName: 'c.png', size: 3000, time: now - 1000, savedToDisk: false })
  t.is(stats.rooms.find((r) => r.topic === TOPIC_2).dm, true)

  t.is(await files.deleteFile(a.hash, TOPIC), true)
  t.is(await files.read(a.hash, TOPIC), null)
  t.alike(removed.pop()[1], { topic: TOPIC, key: 'invite', dm: false, hashes: [a.hash], reason: 'delete' })
  t.is(await files.deleteFile(a.hash, TOPIC), true, 'already gone')
  t.is(removed.length, 0, 'nothing to report the second time')
  t.is(await files.deleteFile('zz', TOPIC), false)
  t.is(await files.deleteFile(b.hash, TOPIC_2), true, 'not in that room')
  t.is(await files.deleteFile(b.hash, 'nope'), false)
  t.is(files.used, 9000)

  t.is(await files.purgeRoom(TOPIC), 2)
  const purge = removed.pop()[1]
  t.is(purge.reason, 'purge')
  t.alike(purge.hashes.sort(), [b.hash, cc.hash].sort())
  t.alike(await files.list(TOPIC), [])
  t.is(await files.purgeRoom(TOPIC), 0)
  t.is(await files.purgeRoom('nope'), 0)
  stats = await files.stats()
  t.is(stats.totalFiles, 1)
  t.is(stats.totalSize, 4000)
  t.is(files.used, 4000)

  // prune: older than a week and not saved; then the size cap, oldest first
  const old = await files.share(TOPIC_2, bytesOf(100), { fileName: 'old.png', time: now - 8 * DAY })
  const keep = await files.share(TOPIC_2, bytesOf(100), { fileName: 'saved.png', time: now - 9 * DAY })
  t.is((await files.saveToDownloads(keep.hash, 'saved.png', TOPIC_2)).success, true)
  t.is(await files.prune(), 1)
  t.is(await files.read(old.hash, TOPIC_2), null, 'old unsaved file pruned')
  t.ok(await files.read(keep.hash, TOPIC_2), 'saved file kept')
  t.ok(await files.read(d.hash, TOPIC_2))
  t.alike(removed.pop()[1], { topic: TOPIC_2, key: ADDRESS_2, dm: true, hashes: [old.hash], reason: 'prune' })

  const e = await files.share(TOPIC_2, bytesOf(1000), { fileName: 'e.png', time: now + 1000 })
  t.is(await files.prune({ maxBytes: 4500 }), 1, 'size cap: the oldest unsaved file goes')
  t.is(await files.read(d.hash, TOPIC_2), null)
  t.ok(await files.read(e.hash, TOPIC_2))
  t.ok(await files.read(keep.hash, TOPIC_2))
})

// =============================================================================================
// on a Hugin swarm connection

test('testnet: drive replication next to the hugin-messages channel on a Hugin swarm connection', { timeout: 180000 }, async (t) => {
  const testnet = await createTestnet(3, t.teardown)
  const { bootstrap } = testnet
  const roomKey = 'hugin-network files test room'

  const peers = []
  for (const [address, name] of [[ADDRESS, 'alice'], [ADDRESS_2, 'bob']]) {
    const s = createHuginSwarm({ key: roomKey, bootstrap })
    t.teardown(() => s.swarm.destroy())
    const { files } = await makeFiles(t, { address, name })
    const topic = hex(s.basePublicKey)
    const driveKey = await files.openRoom(topic, { key: roomKey })
    const peer = { s, files, topic, driveKey, channels: [], messages: [] }
    s.swarm.on('connection', (conn) => {
      conn.on('error', noop)
      // as the apps do: the hugin-messages channel and the corestore on the same stream
      const mux = Protomux.from(conn)
      const channel = mux.createChannel({ protocol: 'hugin-messages' })
      const message = channel.addMessage({
        encoding: c.string,
        onmessage: (str) => {
          const msg = JSON.parse(str)
          peer.messages.push(msg)
          if (msg.joined && msg.driveKey) files.addPeer(topic, msg.driveKey)
        }
      })
      channel.open()
      files.replicate(conn, topic)
      message.send(JSON.stringify({ joined: true, driveKey }))
      peer.channels.push(message)
    })
    peers.push(peer)
  }
  const [alice, bob] = peers
  t.is(alice.topic, bob.topic, 'same room, same topic')

  const downloaded = once(t, bob.files, EVENTS.DOWNLOADED, () => true, 150000)
  await alice.s.swarm.join(alice.s.topic, { server: true, client: true }).flushed()
  await bob.s.swarm.join(bob.s.topic, { server: true, client: true }).flushed()
  while (alice.channels.length === 0 || !bob.messages.some((m) => m.joined)) {
    await new Promise((resolve) => setTimeout(resolve, 100))
  }

  const ann = await alice.files.share(alice.topic, PHOTO, { fileName: 'photo.png' })
  for (const ch of alice.channels) ch.send(wire.encode(ann))

  const d = await downloaded
  t.is(d.hash, ann.hash)
  t.alike(b4a.from(await bob.files.read(ann.hash, bob.topic)), b4a.from(PHOTO), 'bytes replicated over the swarm connection')
  while (!bob.messages.some((m) => m.info === 'file-shared')) {
    await new Promise((resolve) => setTimeout(resolve, 100))
  }
  const received = bob.messages.find((m) => m.info === 'file-shared')
  t.ok(S.fileMessage(received).ok, 'the announcement went over the same connection')
  t.alike(await bob.files.handleRemote(bob.topic, received, { driveKey: alice.driveKey }), { action: 'ignored', reason: 'known' })
})

// =============================================================================================
// quick close + reopen, releasing peer drives, file:remote limits

test('closeRoom then openRoom at once: the reopen waits for the close and the drive works', async (t) => {
  const { files } = await makeFiles(t)
  const key = await files.openRoom(TOPIC, { key: 'room-invite' })
  const first = await files.share(TOPIC, bytesOf(100, 3), { fileName: 'a.png' })
  const closing = files.closeRoom(TOPIC)
  const reopened = await files.openRoom(TOPIC, { key: 'room-invite' })
  t.ok(await closing)
  t.is(reopened, key, 'the same drive')
  t.alike(b4a.from(await files.read(first.hash, TOPIC)), b4a.from(bytesOf(100, 3)))
  const second = await files.share(TOPIC, bytesOf(50, 4), { fileName: 'b.png' })
  t.ok((await files.list(TOPIC)).some((m) => m.hash === second.hash))
})

test('removePeer releases a peer drive, so maxPeerDrives counts live peers', async (t) => {
  const { files } = await makeFiles(t, { files: { maxPeerDrives: 1 } })
  const A = await makeFiles(t, { address: ADDRESS_2 })
  const C = await makeFiles(t, { address: ADDRESS_2 })
  await files.openRoom(TOPIC)
  await A.files.openRoom(TOPIC)
  await C.files.openRoom(TOPIC)
  const keyA = A.files.driveKey(TOPIC)
  const keyC = C.files.driveKey(TOPIC)
  t.ok(await files.addPeer(TOPIC, keyA))
  t.absent(await files.addPeer(TOPIC, keyC), 'limit reached')
  t.ok(files.removePeer(TOPIC, keyA))
  t.absent(files.removePeer(TOPIC, keyA), 'already released')
  t.absent(files.removePeer(TOPIC_2, keyC), 'unknown room')
  t.ok(await files.addPeer(TOPIC, keyC), 'a slot is free again')
})

test('file:remote is rate-limited per peer drive; offered hashes are kept in a bounded list', async (t) => {
  const { files } = await makeFiles(t, { autoSync: false, files: { remotePerMinute: 3, maxNotified: 2 } })
  const other = await makeFiles(t, { address: ADDRESS_2 })
  await files.openRoom(TOPIC, { key: 'room-invite' })
  await other.files.openRoom(TOPIC)
  const driveKey = other.files.driveKey(TOPIC)
  const file = (i) => ({ fileName: 'f' + i + '.png', hash: (i + 1).toString(16).padStart(64, '0'), contentHash: CONTENT_HASH, size: 10, time: Date.now(), address: ADDRESS_2, name: 'bob' })
  const ctx = { driveKey, address: ADDRESS_2 }
  for (let i = 0; i < 3; i++) t.is((await files.handleRemote(TOPIC, file(i), ctx)).action, 'remote')
  t.alike(await files.handleRemote(TOPIC, file(2), ctx), { action: 'ignored', reason: 'notified' })
  t.alike(await files.handleRemote(TOPIC, file(3), ctx), { action: 'ignored', reason: 'rate' })
  t.is(files._rooms.get(TOPIC).notified.size, 2, 'bounded')
})

// =============================================================================================
// attribution, signed files, auto-sync limits, streaming

/** File metadata signed by `signer` (the hugin/file payload of `topic`). */
function signedFile(fields, { signer = fields.address, topic = TOPIC } = {}) {
  return { ...fields, signature: fakeSign(signer, wire.fileSigningPayload({ ...fields, topic })) }
}

test('attribution: a listed file is the announcing peer\'s, or its signature must verify for its address', async (t) => {
  const { files } = await makeFiles(t, { autoSync: false })
  await files.openRoom(TOPIC, { key: 'room-invite' })
  const remote = record(files, [EVENTS.REMOTE])
  const driveKey = 'bb'.repeat(32)
  const ctx = { driveKey, address: ADDRESS_2, name: 'bob' } // the announcing peer
  const base = (i) => ({ fileName: 'f' + i + '.png', hash: (i + 1).toString(16).padStart(64, '0'), contentHash: CONTENT_HASH, size: 10, time: Date.now() })

  // another address, not signed: dropped
  t.alike(await files.handleRemote(TOPIC, { ...base(0), address: ADDRESS }, ctx), { action: 'ignored', reason: 'address' })
  // another address, signed by another key: dropped (and not checked again)
  const wrongKey = signedFile({ ...base(1), address: ADDRESS }, { signer: ADDRESS_2 })
  t.alike(await files.handleRemote(TOPIC, wrongKey, ctx), { action: 'ignored', reason: 'signature' })
  t.alike(await files.handleRemote(TOPIC, wrongKey, ctx), { action: 'ignored', reason: 'refused' })
  // another address, signed for another room: dropped
  const otherRoom = signedFile({ ...base(2), address: ADDRESS }, { topic: TOPIC_2 })
  t.alike(await files.handleRemote(TOPIC, otherRoom, ctx), { action: 'ignored', reason: 'signature' })
  // another address, signed by that address for this room: a copy of its file, kept as its
  const relayed = signedFile({ ...base(3), address: ADDRESS, name: 'alice' })
  const r = await files.handleRemote(TOPIC, relayed, ctx)
  t.is(r.action, 'remote')
  t.is(r.file.address, ADDRESS)
  t.is(r.file.name, 'alice')
  t.is(r.file.signature, relayed.signature)
  // the peer's own file, unsigned: its address and name
  const own = await files.handleRemote(TOPIC, { ...base(4), address: ADDRESS_2, name: 'someone else' }, ctx)
  t.is(own.action, 'remote')
  t.is(own.file.name, 'bob', 'the name of the announcing peer')
  // no address: the announcing peer's
  const none = await files.handleRemote(TOPIC, base(5), ctx)
  t.is(none.file.address, ADDRESS_2)
  // its own address, but a signature that does not verify: dropped
  t.alike(await files.handleRemote(TOPIC, { ...base(6), address: ADDRESS_2, signature: 'ab'.repeat(64) }, ctx), { action: 'ignored', reason: 'signature' })
  // its own address, signed: kept
  t.is((await files.handleRemote(TOPIC, signedFile({ ...base(7), address: ADDRESS_2 }), ctx)).action, 'remote')
  // without an announcing peer, only a verified signature attributes a file
  t.alike(await files.handleRemote(TOPIC, { ...base(8), address: ADDRESS_2 }, { driveKey }), { action: 'ignored', reason: 'address' })

  t.alike(remote.map(([, e]) => e.file.hash), [base(3).hash, base(4).hash, base(5).hash, base(7).hash], 'file:remote only for attributed files')

  // without host.verify only the announcing peer's own files are taken
  const { files: noVerify } = await makeFiles(t, { autoSync: false, host: { verify: undefined } })
  await noVerify.openRoom(TOPIC)
  t.alike(await noVerify.handleRemote(TOPIC, relayed, ctx), { action: 'ignored', reason: 'address' })
  t.is((await noVerify.handleRemote(TOPIC, signedFile({ ...base(9), address: ADDRESS_2 }), ctx)).action, 'remote')
})

test('attribution: entries of a peer drive are offered for its owners; others need a verifying signature', async (t) => {
  const { A, B } = await connectedPair(t, {}, { autoSync: false })
  const driveA = A.files.drive(TOPIC)
  const content = blake2b256Hex(bytesOf(10, 1))
  const put = (hash, meta) => driveA.put('/' + hash, bytesOf(10, 1), { metadata: { topic: TOPIC, time: Date.now(), size: 10, hash, contentHash: content, info: 'file-shared', type: 'file', ...meta } })
  const H = (i) => (i + 1).toString(16).padStart(64, 'e')
  await put(H(0), { fileName: 'claimed.png', address: ADDRESS_3, name: 'carol', signature: '' })
  await put(H(1), signedFile({ fileName: 'copy.png', address: ADDRESS_3, name: 'carol', hash: H(1), contentHash: content, size: 10, time: Date.now() }))
  await put(H(2), { fileName: 'mine.png', address: ADDRESS, name: 'alice', signature: '' })
  const remote = record(B.files, [EVENTS.REMOTE])
  t.ok(await B.files.addPeer(TOPIC, A.files.driveKey(TOPIC), { owners: [ADDRESS] }))
  await waitUntil(() => remote.length >= 2)
  await sleep(200)
  const got = remote.map(([, e]) => [e.file.hash, e.file.address])
  t.alike(got.sort(), [[H(1), ADDRESS_3], [H(2), ADDRESS]].sort(), 'the owner\'s file and the signed copy; the unsigned claim is dropped')
  t.ok(B.files.setPeerOwners(TOPIC, A.files.driveKey(TOPIC), [ADDRESS, ADDRESS_2]))
  t.absent(B.files.setPeerOwners(TOPIC, 'cc'.repeat(32), [ADDRESS]), 'unknown drive')
})

test('auto-sync: files above autoSyncMaxBytes and past autoSyncPerMinute are offered instead; a size that differs from the entry is refused', async (t) => {
  const { A, B } = await connectedPair(t, {}, { files: { autoSyncMaxBytes: 1000, autoSyncPerMinute: 2 } })
  t.is(DEFAULTS.autoSyncMaxBytes, 50 * 1024 * 1024)
  const driveKey = A.files.driveKey(TOPIC)
  const ctx = { driveKey, address: ADDRESS }
  const events = record(B.files)

  const big = await A.files.share(TOPIC, bytesOf(2000, 1), { fileName: 'big.bin' })
  const r1 = await B.files.handleRemote(TOPIC, big, ctx)
  t.is(r1.action, 'remote', 'above the cap: offered')
  t.is(await B.files.read(big.hash, TOPIC), null)

  const small = []
  for (let i = 0; i < 3; i++) small.push(await A.files.share(TOPIC, bytesOf(100, 10 + i), { fileName: 's' + i + '.bin' }))
  const results = []
  for (const f of small) results.push(await B.files.handleRemote(TOPIC, f, ctx))
  t.alike(results.map((r) => r.action), ['download', 'download', 'remote'], 'two per minute per peer drive')
  t.ok(results[0].result.success && results[1].result.success)

  // an entry whose blob is larger than its announced size
  const hash = 'ef'.repeat(32)
  const content = blake2b256Hex(bytesOf(500, 3))
  await A.files.drive(TOPIC).put('/' + hash, bytesOf(500, 3), { metadata: { hash, contentHash: content, fileName: 'x.bin', size: 5, time: Date.now(), address: ADDRESS } })
  const res = await B.files.download(TOPIC, { hash, contentHash: content, fileName: 'x.bin', size: 5, time: Date.now(), address: ADDRESS, driveKey })
  t.alike(res, { success: false, error: 'size' })
  t.ok(events.some(([n, e]) => n === EVENTS.ERROR && e.error === 'size'))
  t.is(await B.files.read(hash, TOPIC), null)
  // a manual download of the large file works (the cap is for auto-sync only)
  t.is((await B.files.download(TOPIC, r1.file)).success, true)
})

test('signature checks of listed files are rate-limited per peer drive', async (t) => {
  const { files } = await makeFiles(t, { autoSync: false, files: { verifyPerMinute: 2 } })
  await files.openRoom(TOPIC)
  const ctx = { driveKey: 'bb'.repeat(32), address: ADDRESS_2 }
  const f = (i) => signedFile({ fileName: 'r' + i + '.png', hash: (i + 1).toString(16).padStart(64, 'a'), contentHash: CONTENT_HASH, size: 1, time: Date.now(), address: ADDRESS })
  t.is((await files.handleRemote(TOPIC, f(0), ctx)).action, 'remote')
  t.is((await files.handleRemote(TOPIC, f(1), ctx)).action, 'remote')
  t.alike(await files.handleRemote(TOPIC, f(2), ctx), { action: 'ignored', reason: 'rate' })
  t.is((await files.handleRemote(TOPIC, f(3), { ...ctx, driveKey: 'cc'.repeat(32) })).action, 'remote', 'per peer drive')
})

test('content hash: bytes that differ from contentHash are not kept and the fetched peer blocks are dropped', async (t) => {
  const { A, B } = await connectedPair(t)
  const driveKey = A.files.driveKey(TOPIC)
  const events = record(B.files)
  const bytes = bytesOf(5000, 4)
  const right = blake2b256Hex(bytes)
  const wrong = blake2b256Hex(bytesOf(5000, 5))
  t.not(right, wrong)

  // an entry whose metadata names the content hash of other bytes (share() always hashes the bytes)
  const hash = 'da'.repeat(32)
  const fields = { hash, contentHash: wrong, fileName: 'x.bin', size: 5000, time: Date.now(), address: ADDRESS }
  await A.files.drive(TOPIC).put('/' + hash, bytes, { metadata: fields })

  t.alike(await B.files.download(TOPIC, { ...fields, driveKey }), { success: false, error: 'content' }, 'manual download refused')
  t.ok(events.some(([n, e]) => n === EVENTS.ERROR && e.error === 'content' && e.hash === hash), 'file:error with error content')
  t.absent(events.some(([n]) => n === EVENTS.DOWNLOADED))
  t.is(await B.files.read(hash, TOPIC), null, 'not in our drive')
  t.is(B.files.used, 0)

  const peer = B.files._rooms.get(TOPIC).peers.get(driveKey)
  const entry = await peer.drive.entry('/' + hash, { wait: false })
  const blobs = await peer.drive.getBlobs()
  const start = Date.now()
  while (await blobs.core.has(entry.value.blob.blockOffset)) {
    if (Date.now() - start > 20000) throw new Error('peer blocks still cached')
    await sleep(20)
  }
  t.pass('the fetched peer blocks are dropped')

  // the same bytes with the right content hash are kept
  t.alike(await B.files.download(TOPIC, { ...fields, contentHash: right, driveKey }), { success: true, hash, path: 'storage' })
  t.alike(b4a.from(await B.files.read(hash, TOPIC)), b4a.from(bytes))
  t.is((await B.files.list(TOPIC)).find((m) => m.hash === hash).contentHash, right, 'kept with its content hash')

  // auto-sync: a signed announcement with a wrong content hash is fetched once, then refused
  const hash2 = 'db'.repeat(32)
  const fields2 = { ...fields, hash: hash2, name: 'alice' }
  await A.files.drive(TOPIC).put('/' + hash2, bytes, { metadata: fields2 })
  const signed = signedFile(fields2)
  const ctx = { driveKey, address: ADDRESS, name: 'alice' }
  const first = await B.files.handleRemote(TOPIC, signed, ctx)
  t.is(first.action, 'download')
  t.alike(first.result, { success: false, error: 'content' })
  t.alike(await B.files.handleRemote(TOPIC, signed, ctx), { action: 'ignored', reason: 'refused' }, 'not fetched or offered again')
  t.absent(events.some(([n, e]) => n === EVENTS.REMOTE && e.file.hash === hash2), 'not offered to the UI')
  t.is(await B.files.read(hash2, TOPIC), null)
})

test('streamed copies: a multi-block file arrives intact in storage and downloads; a failed write leaves no file', async (t) => {
  const { A, B } = await connectedPair(t, {}, { saveDownloads: true, autoSync: false })
  const large = bytesOf(3 * 1024 * 1024 + 123, 5)
  const ann = await A.files.share(TOPIC, large, { fileName: 'large.bin' })
  const r = await B.files.handleRemote(TOPIC, ann, { driveKey: A.files.driveKey(TOPIC), address: ADDRESS })
  const progress = record(B.files, [EVENTS.PROGRESS])
  const got = await B.files.download(TOPIC, r.file)
  t.is(got.success, true)
  t.is(got.path, B.dir + '/downloads/large.bin')
  t.alike(b4a.from(await fs.promises.readFile(got.path)), b4a.from(large), 'downloads copy')
  t.alike(b4a.from(await B.files.read(ann.hash, TOPIC)), b4a.from(large), 'storage copy')
  t.is(B.files.used, large.byteLength)
  t.ok(progress.some(([, e]) => e.progress > 0 && e.progress < 100), 'progress while fetching')
  const s = await B.files.saveToDownloads(ann.hash, 'again.bin', TOPIC)
  t.alike(b4a.from(await fs.promises.readFile(s.filePath)), b4a.from(large), 'saveToDownloads streams too')

  async function * failing() {
    yield b4a.alloc(10, 1)
    throw new FilesError('source failed', 'TEST')
  }
  try {
    await B.files._writeUnique(B.dir + '/downloads', 'broken.bin', () => failing())
    t.fail('should reject')
  } catch (err) {
    t.is(err.message, 'source failed')
  }
  t.absent(await exists(B.dir + '/downloads/broken.bin'), 'the partial file is removed')
})
