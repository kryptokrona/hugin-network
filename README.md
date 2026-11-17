# hugin-network

The peer-to-peer layer of the Hugin apps ([hugin-desktop](https://github.com/kryptokrona/hugin-desktop)
and hugin-native). It joins Hugin rooms and DM swarms on Hyperswarm, builds and checks every
message on the `hugin-messages` channel, signs and verifies messages through the app's XKR keys,
shares files over Hyperdrive, talks to Hugin nodes (hugin-node and compatible relays) with proof
of work from [hugin-pow](https://github.com/kryptokrona/hugin-pow), and builds and opens DM
payloads with their ML-KEM handshake.

## Install

```bash
npm install hugin-network
```

Proof of work for node posts needs a hashing backend, usually
`require('hugin-pow/native').createHasher()`, which needs `kryptokrona-crypto` installed.
`hugin-network/dm` takes a crypto provider such as the `hugin-crypto` module.

## Platforms

- Node.js and Electron (main process): every module.
- Bare (react-native-bare-kit): every module.
- React Native (Hermes): `hugin-network/dm` only. It loads no native code and needs
  `crypto.getRandomValues`.

## Usage

### `HuginP2P`

The one object an app creates. It ties rooms, feed, voice, files and the node client together
and sends every event out of one emitter.

```js
const { HuginP2P } = require('hugin-network')

const p2p = new HuginP2P({
  host,                              // hooks, see below
  node: { preset: 'desktop' },       // or 'native'
  sharedDht: false                   // true: one DHT for every room and DM swarm
})
p2p.setIdentity({ address, name, avatar })

const room = await p2p.rooms.join({ invite })
p2p.on('room:message', ({ key, message }) => store(message))
await p2p.rooms.send(room.key, { message: 'hello' })

await p2p.node.connect({ publicNode: true })

await p2p.suspend(); await p2p.resume()   // mobile lifecycle
await p2p.destroy()
```

`p2p.rooms` (join, joinDm, leave, send, sendDm, typing, shareFile, ban), `p2p.feed` (send),
`p2p.voice` (setStatus, leave, sendSdp), `p2p.files` (null without `host.paths.storage`) and
`p2p.node` (`NodeClient`) are the parts.

### Host hooks and events

Every hook may be sync or async.

| hook | use |
|---|---|
| `identity()` | `{ address, name, avatar }` of the user |
| `sign(message)` | XKR spend key signature of the string (128 hex); needed to send |
| `verify(message, address, signature)` | `true` only for a valid signature; needed to receive |
| `roomMessageExists(hash)`, `getRoomHistory(roomKey)`, `getRoomMessage(hash)`, `getLatestRoomHashes(roomKey)` | stored room messages, returned with every field (including `signature`) |
| `feedMessageExists(hash)`, `getFeedHistory()` | stored feed messages |
| `isBanned(address, topic)`, `isBlocked(address)` | policy |
| `paths` | `{ storage, downloads }` for files |
| `autoSyncFiles(topic, roomKey, dm, file)`, `knownFile(hash)`, `storageLimit()` | file sync policy |
| `powBackend` | a hugin-pow backend for node posts |
| `log(level, msg, data)` | logging; never gets message or file contents |

Event names are in `hugin-network/events` (`events.ALL`) and their payloads are described in
`lib/events.js`: `room:*`, `peer:*`, `dm:wire`, `typing`, `ban:*`, `feed:message`, `voice:*`,
`file:*`, `node:*` and `error`.

### `hugin-network/node`

The client for Hugin nodes. `HuginP2P` creates one as `p2p.node`; it can also be used alone.

```js
const { NodeClient } = require('hugin-network/node')
const { createHasher } = require('hugin-pow/native')

const node = new NodeClient({ preset: 'desktop', backend: await createHasher() })
await node.connect({ publicNode: true })          // or connect(privateNodeInvite)
const messages = await node.sync({ since })
const res = await node.post({ cipher, hash, viewtag, kind })   // { success, reason?, id }
node.startPolling({ since })                      // emits node:messages
await node.destroy()
```

### `hugin-network/dm`

```js
const { DmCrypto, STATUS } = require('hugin-network/dm')
const dm = new DmCrypto({ crypto: require('hugin-crypto'), host })

const out = await dm.encrypt(address, text, { name })
if (p2p.rooms.sendDm(address, out.payload) === 0) {
  await p2p.node.post({ cipher: out.payload, hash: out.hash, viewtag: out.viewTag, kind: out.kind })
}

p2p.on('dm:wire', async ({ address, wire }) => {
  const r = await dm.open(wire, { from: address })
  if (r.status === STATUS.OK) store(r.message)
})
p2p.on('node:messages', async ({ messages }) => {
  for (const m of (await dm.openPool(messages)).messages) store(m)
})
```

The DM host hooks are `identity`, `sign`, `verify` (optional), `keyDerivation`,
`loadContactCrypto` / `saveContactCrypto`, `loadKemIdentity` / `saveKemIdentity`, `now` and
`log` (see the JSDoc in `lib/dm.js`).

### Other modules

- `hugin-network/swarm`: `createHuginSwarm`, `SharedMidDHT` and the topic and `mid` helpers.
- `hugin-network/keys`: swarm keys, room invites (`createRoomInvite`), admin and `idSig` signatures.
- `hugin-network/wire`: message builders, `encode`, `decode`, signed strings and derived hashes.
- `hugin-network/sanitize`: message validators, `sanitizeText`, `sanitizeHtml`.
- `hugin-network/files`: `Files`, file storage and sync on corestore and hyperdrive.
- `hugin-network/push`: hugin-node packets and push payloads.
- `hugin-network/pow`: hugin-pow re-exports and the node client's share search and retries.
- `hugin-network/rooms`, `/feed`, `/voice`, `/events`.

## Protocol

Swarm topic and handshake (`lib/swarm.js`):

```
topicKey = fill32(key)                         Buffer.alloc(32).fill(key)
base     = crypto_sign_seed_keypair(topicKey)
topic    = keccak256(UTF-8("hugin/topic") || base.publicKey)
mid      = ed25519_sign(UTF-8("hugin/mid") || dhtPublicKey, base.secretKey)
```

`keccak256` is CryptoNote's `cn_fast_hash`. The Noise handshake payload carries `flags |= 128`
followed by the 64-byte `mid`; each side checks the other's `mid` against `base.publicKey`. Room
swarm keys are `sha512(hexbytes(invite))`, DM swarm keys `sha512(hexbytes(derivationHash))`.

Messages: one protomux channel `hugin-messages` per connection, one message type
(compact-encoding `string`) holding a JSON object, at most 2 MiB. The first message on a
connection is `joined`. In DM swarms a non-JSON string is a DM payload. Builders and field
limits are in `lib/wire.js` and `lib/sanitize.js`.

Signed strings: a context prefix followed by `JSON.stringify` of the signed fields, signed with
the XKR spend key (kryptokrona-utils `signMessage`):

| what | signed string |
|---|---|
| `joined.idSig` | `"hugin/id\n" + JSON.stringify([topic, hex(dhtPublicKey)])` |
| room message | `"hugin/room-message\n" + JSON.stringify([room, hash, timestamp, address, name, message, reply, tip])` |
| feed message | `"hugin/feed\n" + JSON.stringify([hash, timestamp, address, nickname, message, reply, tip])` |
| file | `"hugin/file\n" + JSON.stringify([topic, hash, contentHash, size, time, fileName, address])` |
| DM | `"hugin/dm\n" + JSON.stringify([to, t, msg, flags, hs])` |

Room and feed message hashes are derived from the content (BLAKE2b-256, 64 lower-case hex):

```
roomHash    = BLAKE2b-256("hugin/room-message-hash\n" + JSON.stringify([room, timestamp, address, name, message, reply, tip]))
feedHash    = BLAKE2b-256("hugin/feed-hash\n" + JSON.stringify([timestamp, address, nickname, message, reply, tip]))
contentHash = BLAKE2b-256(file bytes)
```

The DM payload layout is described at the top of `lib/dm.js`, push payloads in `lib/push.js`
and the node connection framing in `lib/rpc.js`.

## Tests

```bash
npm install
npm test             # Node.js
npm run test:bare    # Bare (needs bare installed)
```

## Publishing

During development `package.json` uses `"hugin-pow": "file:../hugin-pow"`. The registry version
is kept in `releaseDependencies`. Before publishing, run `node scripts/release-deps.js apply`,
reinstall and test; `npm publish` runs `node scripts/release-deps.js check`, which fails while a
`file:` or `link:` dependency is left.

## License

MIT
