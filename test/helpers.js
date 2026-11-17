'use strict'

const b4a = require('b4a')

/**
 * True on Node (global Buffer and Node's `crypto`): the verbatim app fixtures that use them run
 * only there. Everything else runs on Node and Bare.
 */
const NODE = (() => {
  if (typeof Buffer !== 'function') return false
  try {
    return typeof require('crypto').createHash === 'function'
  } catch {
    return false
  }
})()

const hex = (bytes) => b4a.toString(bytes, 'hex')

// A real-looking XKR address (99 characters; the private-node vector of test/swarm.test.js).
const ADDRESS = 'SEKReYU57DLLvUjNzmjVhaK7jqc8SdZZ3cyKJS5f4gWXK4NQQYChzKUUwzCGhgqUPkWQypeR94rqpgMPjXWG9ijnZKNw2LWXnZU'
const ADDRESS_2 = 'SEKRe' + 'b'.repeat(94)

const SEED_HEX = '1f'.repeat(32)
const RAND_HEX = 'a0'.repeat(32)
const HASH = 'c3'.repeat(32)
const HASH_2 = 'd4'.repeat(32)
// A file `contentHash` for metadata whose bytes are never fetched (64 hex characters).
const CONTENT_HASH = 'b6'.repeat(32)
const TOPIC = 'e5'.repeat(32)
const DRIVE_KEY = '7a'.repeat(32)
const PAST = 1731500000000

/** Calls a legacy validator on a deep copy (some of them mutate their input); false if it throws. */
function legacy(fn, data, ...args) {
  try {
    return fn(JSON.parse(JSON.stringify(data)), ...args)
  } catch {
    return false
  }
}

module.exports = {
  NODE,
  hex,
  ADDRESS,
  ADDRESS_2,
  SEED_HEX,
  RAND_HEX,
  HASH,
  HASH_2,
  CONTENT_HASH,
  TOPIC,
  DRIVE_KEY,
  PAST,
  legacy
}
