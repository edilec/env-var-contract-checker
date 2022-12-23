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

/**
 * Ordering pin: the quoting shape must be recognised BEFORE the offset.
 *
 * A helper that searches for `at position` first finds that phrase inside the
 * quoted span whenever the document itself supplies it, and slices the
 * document straight back out. The first case below is the one that bites when
 * the two branches are swapped back, and it takes two assertions to bite:
 * whether the document survives, AND whether the diagnostic does. The closing
 * double-quote guard turns a reverted ordering into the generic sentence
 * rather than a leak, so a test that only looked for the leak would sit green
 * over a helper that had stopped saying anything at all about this document.
 *
 * The last two cases pin that same opposite failure for the shapes V8 writes
 * without a quoted span. A helper that answered every message generically
 * would leak nothing and diagnose nothing.
 */

const ORDERING_SECRET = 'sk-live-9f2c1b7a4d'

/** The detail this tool produces for a document V8 refuses. */
function detailOfParseFailure(text) {
  try {
    JSON.parse(text)
  } catch (error) {
    return parseFailureDetail(error)
  }
  throw new Error(`${JSON.stringify(text)} parsed, so it pins nothing`)
}

/** What V8 actually said, so a case cannot quietly stop having a subject. */
function messageOfParseFailure(text) {
  try {
    JSON.parse(text)
  } catch (error) {
    return error.message
  }
  throw new Error(`${JSON.stringify(text)} parsed, so it pins nothing`)
}

test('a document that merely CONTAINS "at position" is not sliced back out', () => {
  const document = 'at position 1'
  assert.match(
    messageOfParseFailure(document),
    /"at position 1"/,
    'V8 still quotes this document back, so this case still has a subject',
  )

  const detail = detailOfParseFailure(document)
  assert.equal(detail.includes('"'), false, `a double quote survived: ${JSON.stringify(detail)}`)
  assert.equal(detail.includes(document), false, `the document survived: ${JSON.stringify(detail)}`)
  assert.match(
    detail,
    /unexpected token 'a'/,
    'the offending token is still named -- searching for the offset first loses it here',
  )
})

test('a document that is nothing but a credential-shaped token is not echoed', () => {
  const detail = detailOfParseFailure(ORDERING_SECRET)
  assert.equal(detail.includes(ORDERING_SECRET), false, `the token survived: ${JSON.stringify(detail)}`)
  assert.equal(detail.includes('"'), false)
})

test('no four-character prefix of a long sensitive document reaches the detail', () => {
  // Long enough that V8 quotes a ten-character window rather than the whole
  // document: asserting only on the whole string would pass while ten
  // characters of the secret still shipped.
  const detail = detailOfParseFailure(`${ORDERING_SECRET}${'x'.repeat(400)}`)
  for (let length = 4; length <= 10; length += 1) {
    assert.equal(
      detail.includes(ORDERING_SECRET.slice(0, length)),
      false,
      `the first ${length} characters of the document survived: ${JSON.stringify(detail)}`,
    )
  }
  assert.equal(detail.includes('"'), false)
})

test('a quoted span containing a newline is still recognised as a quoted span', () => {
  // Without the `s` flag the quoted-span pattern does not match this message
  // at all and the document falls through to a branch that keeps it.
  const detail = detailOfParseFailure('}x\n')
  assert.match(detail, /unexpected token/)
  assert.equal(detail.includes('"'), false, `a double quote survived: ${JSON.stringify(detail)}`)
})

test('the genuinely safe positional form keeps its position, line and column', () => {
  const detail = detailOfParseFailure('{"a": 1 "b": 2}')
  assert.match(detail, /at position 8/)
  assert.match(detail, /line 1 column 9/)
})

test('"Unexpected end of JSON input" passes through unchanged', () => {
  assert.equal(detailOfParseFailure(''), 'Unexpected end of JSON input')
})
