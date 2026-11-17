'use strict'

// scripts/release-deps.js: local dependency specs are found in every dependency section (Node
// only; not part of test/all.js).

const test = require('brittle')
const { localDeps } = require('../scripts/release-deps.js')
const pkg = require('../package.json')

test('release-deps: finds file:, link:, portal: and workspace: specs', (t) => {
  const found = localDeps({
    dependencies: { a: 'file:../a', b: '1.2.3', c: 'link:../c' },
    optionalDependencies: { d: 'portal:../d' },
    peerDependencies: { e: 'workspace:*', f: '^2.0.0' },
    devDependencies: { g: 'file:../g' }
  })
  t.alike(found.map((d) => d.name), ['a', 'c', 'd', 'e'], 'devDependencies are not published')
  t.alike(localDeps({ dependencies: { a: '^1.0.0' } }), [])
})

test('release-deps: every local dependency of this package has a registry version', (t) => {
  for (const d of localDeps(pkg)) {
    const v = pkg.releaseDependencies && pkg.releaseDependencies[d.name]
    t.ok(typeof v === 'string' && !/^(file|link|portal|workspace):/.test(v), d.name + ' -> ' + v)
  }
  t.is(pkg.releaseDependencies['hugin-pow'], '^1.0.0')
  t.is(pkg.scripts.prepublishOnly, 'node scripts/release-deps.js check')
})
