import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'

import { parseFailureDetail } from '../src/index.mjs'

/**
 * A parse failure must not reproduce the file it failed on.
 *
 * This tool's whole purpose is that an environment can be reviewed without the
 * review becoming a place secrets leak, and a manifest is exactly the kind of
 * file that is short and nothing but a credential. V8 reports a `JSON.parse`
 * failure two ways: one names a position and says nothing about the content,
 * the other quotes the input back -- `Unexpected token 'A',
 * "AKIAIOSFODNN7EXAMPLE" is not valid JSON`, the whole document when the
 * document is short and a ten-character prefix when it is not. Interpolating
 * that message defeated the redaction on the one path where nothing else looks
 * at the content at all.
 *
 * The canary below is AWS's published documentation placeholder, not a key.
 */

const projectDirectory = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const cli = resolve(projectDirectory, 'bin/env-var-contract-checker.mjs')
const CANARY = 'AKIAIOSFODNN7EXAMPLE'

function run(args) {
  return spawnSync(process.execPath, [cli, ...args], { cwd: projectDirectory, encoding: 'utf8' })
}

/** Every prefix of the canary down to eight characters, longest first. */
function prefixes(value) {
  const found = []
  for (let length = value.length; length >= 8; length -= 1) found.push(value.slice(0, length))
  return found
}

function assertNoCanary(result, label) {
  for (const prefix of prefixes(CANARY)) {
    assert.equal(result.stdout.includes(prefix), false, `${label}: stdout carries ${prefix}`)
    assert.equal(result.stderr.includes(prefix), false, `${label}: stderr carries ${prefix}`)
  }
}

function withFile(contents, body) {
  const directory = mkdtempSync(join(tmpdir(), 'evcc-secrets-'))
  try {
    const path = join(directory, 'unparseable.json')
    writeFileSync(path, contents)
    return body(path)
  } finally {
    rmSync(directory, { recursive: true, force: true })
  }
}

test('a manifest that is only a credential is not echoed by the failure that read it', () => {
  withFile(CANARY, (path) => {
    const result = run(['--contract', 'examples/contract.json', '--env', path])
    assert.equal(result.status, 2)
    assertNoCanary(result, 'manifest')
    assert.match(result.stderr, /Could not read environment manifest: unexpected token 'A' at the start of the document/)
  })
})

test('a contract that is only a credential is not echoed either', () => {
  withFile(CANARY, (path) => {
    const result = run(['--contract', path, '--env', 'examples/production.env.json'])
    assert.equal(result.status, 2)
    assertNoCanary(result, 'contract')
  })
})

test('a longer manifest is not echoed by its ten-character prefix either', () => {
  withFile(`${CANARY} and a great deal of trailing content nobody should read back`, (path) => {
    const result = run(['--contract', 'examples/contract.json', '--env', path])
    assert.equal(result.status, 2)
    assertNoCanary(result, 'long manifest')
  })
})

test('the position, line and column survive, because a parse error that says nothing is a defect', () => {
  withFile('{"schemaVersion": "1", "DATABASE_PASSWORD": "hunter2-correct-horse" "LOG_LEVEL": "info"}', (path) => {
    const result = run(['--contract', 'examples/contract.json', '--env', path])
    assert.equal(result.status, 2)
    assert.match(result.stderr, /at position \d+ \(line \d+ column \d+\)/)
    assert.equal(result.stderr.includes('hunter2'), false)
  })
})

test('a file that is missing rather than malformed still names itself', () => {
  const result = run(['--contract', 'examples/contract.json', '--env', 'examples/nope.json'])

  assert.equal(result.status, 2)
  assert.match(result.stderr, /ENOENT/)
})

test('parseFailureDetail keeps the position and drops the quoted input', () => {
  const cases = [
    [CANARY, "unexpected token 'A' at the start of the document"],
    ['password=hunter2-correct-horse', "unexpected token 'p' at the start of the document"],
    ['', 'Unexpected end of JSON input'],
    ['{"a": 1', "Expected ',' or '}' after property value in JSON at position 7 (line 1 column 8)"],
  ]
  for (const [document, expected] of cases) {
    try {
      JSON.parse(document)
      assert.fail(`${document} parsed`)
    } catch (error) {
      assert.equal(parseFailureDetail(error), expected, JSON.stringify(document))
    }
  }

  // A message this tool has never seen still yields something printable, and an
  // error with no message at all does not throw on its way to stderr.
  assert.equal(parseFailureDetail(new Error('something new from a future V8')), 'the document could not be parsed as JSON')
  assert.equal(parseFailureDetail(undefined), 'the document could not be parsed as JSON')
})
