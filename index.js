'use strict'

// hugin-network: the P2P layer shared by hugin-desktop and hugin-native.
// `HuginP2P` is the facade a host creates (rooms, voice, feed, files, node in one object, one
// event stream; lib/hugin-p2p.js). The parts and the pure modules stay available on their own:
// `swarm` is the Hugin swarm layer, `node` the hugin-node client
// (`NodeClient`), `files` the file storage and sync (`Files`), `Rooms` / `Feed` / `Voice` the
// room parts, `events` the canonical event names, `dm` the DM payloads and handshake state
// (`DmCrypto`; pure JavaScript, React Native imports `hugin-network/dm` directly), `pow` the
// node client's proof of work on hugin-pow.
//
// `files` and `Files` are loaded on first access: they pull in corestore/hyperdrive and the
// RocksDB addon, which users of the pure modules do not need. `HuginP2P` loads them only for a
// host with `paths.storage`.

const node = require('./lib/node-client.js')
const facade = require('./lib/hugin-p2p.js')

module.exports = {
  constants: require('./lib/constants.js'),
  keys: require('./lib/keys.js'),
  sanitize: require('./lib/sanitize.js'),
  wire: require('./lib/wire.js'),
  pow: require('./lib/pow.js'),
  push: require('./lib/push.js'),
  swarm: require('./lib/swarm.js'),
  events: require('./lib/events.js'),
  node,
  NodeClient: node.NodeClient,
  HuginP2P: facade.HuginP2P,
  HuginP2PError: facade.HuginP2PError,
  Rooms: require('./lib/rooms.js').Rooms,
  Feed: require('./lib/feed.js').Feed,
  Voice: require('./lib/voice.js').Voice,
  dm: require('./lib/dm.js'),
  DmCrypto: require('./lib/dm.js').DmCrypto,
  get files() {
    return require('./lib/files.js')
  },
  get Files() {
    return require('./lib/files.js').Files
  }
}
