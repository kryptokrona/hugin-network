#!/usr/bin/env node
'use strict'

// Local and registry dependencies (README, "Publishing").
//
//   node scripts/release-deps.js check [package.json]   exit 1 while a dependency uses a local spec
//   node scripts/release-deps.js apply [package.json]   write `releaseDependencies` into the deps
//
// A local spec is `file:`, `link:`, `portal:` or `workspace:`. `check` runs as `prepublishOnly`.
// `apply` replaces each local spec that has an entry in `releaseDependencies` with that version
// and keeps the file's formatting (two-space JSON or tabs, as it was). Node.js only, no
// dependencies.

const fs = require('fs')
const path = require('path')

const LOCAL = /^(file|link|portal|workspace):/
const SECTIONS = ['dependencies', 'optionalDependencies', 'peerDependencies']

function localDeps(pkg) {
  const out = []
  for (const section of SECTIONS) {
    const deps = pkg[section]
    if (!deps || typeof deps !== 'object') continue
    for (const [name, spec] of Object.entries(deps)) {
      if (typeof spec === 'string' && LOCAL.test(spec.trim())) out.push({ section, name, spec })
    }
  }
  return out
}

function main(argv) {
  const [cmd = 'check', file = 'package.json'] = argv
  const target = path.resolve(file)
  const text = fs.readFileSync(target, 'utf8')
  const pkg = JSON.parse(text)
  const release = pkg.releaseDependencies && typeof pkg.releaseDependencies === 'object' ? pkg.releaseDependencies : {}
  const local = localDeps(pkg)

  if (cmd === 'check') {
    if (local.length === 0) {
      console.log(`${pkg.name || target}: no local dependencies`)
      return 0
    }
    console.error(`${pkg.name || target}: dependencies with a local path cannot be published:`)
    for (const d of local) {
      const hint = release[d.name] ? ` (release version: ${release[d.name]})` : ''
      console.error(`  ${d.section}.${d.name}: ${d.spec}${hint}`)
    }
    console.error('Run `node scripts/release-deps.js apply`, reinstall and test first (README, "Publishing").')
    return 1
  }

  if (cmd === 'apply') {
    const missing = local.filter((d) => typeof release[d.name] !== 'string' || LOCAL.test(release[d.name]))
    if (missing.length > 0) {
      for (const d of missing) console.error(`no registry version for ${d.section}.${d.name} in releaseDependencies`)
      return 1
    }
    for (const d of local) pkg[d.section][d.name] = release[d.name]
    const indent = /^\t/m.test(text) ? '\t' : 2
    fs.writeFileSync(target, JSON.stringify(pkg, null, indent) + '\n')
    for (const d of local) console.log(`${d.section}.${d.name}: ${d.spec} -> ${release[d.name]}`)
    return 0
  }

  console.error('usage: release-deps.js check|apply [package.json]')
  return 2
}

if (require.main === module) process.exitCode = main(process.argv.slice(2))

module.exports = { localDeps, LOCAL }
