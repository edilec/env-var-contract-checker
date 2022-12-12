import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { dirname, resolve } from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'

import { checkEnvironment, formatReport, validateContract } from '../src/index.mjs'

const projectDirectory = resolve(dirname(fileURLToPath(import.meta.url)), '..')

async function example(name) {
  return JSON.parse(await readFile(resolve(projectDirectory, 'examples', name), 'utf8'))
}

function contract(variables) {
  return { schemaVersion: '1', variables }
}

function manifest(variables) {
  return { schemaVersion: '1', variables }
}

function rulesFor(report, name) {
  return report.findings.filter((item) => item.name === name).map((item) => item.ruleId)
}

const SECRET = 'hunter2-this-should-never-be-here'

test('the healthy example passes', async () => {
  const report = checkEnvironment(await example('contract.json'), await example('production.env.json'))

  assert.equal(report.status, 'pass')
  assert.deepEqual(report.findings, [])
  assert.equal(report.summary.secretsDeclared, 2)
})

test('a missing required value fails and names its owner', () => {
  const report = checkEnvironment(
    contract({ API_KEY: { type: 'string', required: true, owner: 'platform-team' } }),
    manifest({}),
  )

  assert.equal(report.status, 'fail')
  assert.deepEqual(rulesFor(report, 'API_KEY'), ['required-missing'])
  assert.equal(report.findings[0].owner, 'platform-team')
})

test('a required value with a default is a warning, not a failure', () => {
  const report = checkEnvironment(
    contract({ LOG_LEVEL: { type: 'string', required: true, default: 'info', owner: 'ops' } }),
    manifest({}),
  )

  assert.equal(report.status, 'pass')
  assert.deepEqual(rulesFor(report, 'LOG_LEVEL'), ['required-using-default'])
})

test('an incompatible default fails even when the variable is set correctly here', () => {
  const report = checkEnvironment(
    contract({ MAX_CONNECTIONS: { type: 'integer', default: 'twenty', owner: 'ops' } }),
    manifest({ MAX_CONNECTIONS: { value: '25' } }),
  )

  assert.equal(report.status, 'fail')
  assert.deepEqual(rulesFor(report, 'MAX_CONNECTIONS'), ['default-incompatible'])
})

test('an incompatible default is caught when the variable is absent too', () => {
  const report = checkEnvironment(
    contract({ PORT: { type: 'integer', default: 'eighty', owner: 'ops' } }),
    manifest({}),
  )

  assert.ok(rulesFor(report, 'PORT').includes('default-incompatible'))
})

test('each declared type rejects what it should', () => {
  const cases = [
    [{ type: 'integer', owner: 'o' }, '1.5', /must be an integer/],
    [{ type: 'number', owner: 'o' }, 'NaN', /must be a finite number/],
    [{ type: 'boolean', owner: 'o' }, 'yes', /true, false, 1 or 0/],
    [{ type: 'url', owner: 'o' }, 'example.com', /absolute URL/],
    [{ type: 'url', owner: 'o', allowedSchemes: ['https'] }, 'http://x.test', /URL schemes: https/],
    [{ type: 'enum', owner: 'o', allowedValues: ['a', 'b'] }, 'c', /one of: a, b/],
    [{ type: 'string', owner: 'o', minLength: 8 }, 'short', /at least 8 characters/],
    [{ type: 'string', owner: 'o', pattern: '^v\\d+$' }, 'beta', /must match \^v/],
  ]

  for (const [declared, value, expected] of cases) {
    const report = checkEnvironment(contract({ V: declared }), manifest({ V: { value } }))
    const finding = report.findings.find((item) => item.name === 'V')
    assert.ok(finding, `${declared.type} should have produced a finding for ${value}`)
    assert.match(finding.message, expected)
  }
})

test('each declared type accepts what it should', () => {
  const cases = [
    [{ type: 'integer', owner: 'o' }, '-42'],
    [{ type: 'number', owner: 'o' }, '1.5e3'],
    [{ type: 'boolean', owner: 'o' }, '0'],
    [{ type: 'url', owner: 'o' }, 'https://example.com/path'],
    [{ type: 'enum', owner: 'o', allowedValues: ['a', 'b'] }, 'b'],
    [{ type: 'string', owner: 'o', minLength: 3, pattern: '^[a-z]+$' }, 'abcd'],
  ]

  for (const [declared, value] of cases) {
    const report = checkEnvironment(contract({ V: declared }), manifest({ V: { value } }))
    assert.deepEqual(report.findings, [], `${declared.type} rejected ${value}`)
  }
})

test('a manifest carrying a secret value is reported without echoing it', () => {
  const report = checkEnvironment(
    contract({ SESSION_SIGNING_KEY: { type: 'string', required: true, secret: true, owner: 'security' } }),
    manifest({ SESSION_SIGNING_KEY: { value: SECRET } }),
  )

  assert.equal(report.status, 'fail')
  assert.deepEqual(rulesFor(report, 'SESSION_SIGNING_KEY'), ['secret-value-present'])
  assert.equal(JSON.stringify(report).includes(SECRET), false)
  assert.equal(formatReport(report).includes(SECRET), false)
})

test('no part of a secret leaks: not the value, a prefix, or its length', () => {
  const report = checkEnvironment(
    contract({ TOKEN: { type: 'string', secret: true, required: true, owner: 'security' } }),
    manifest({ TOKEN: { value: SECRET } }),
  )
  const serialized = JSON.stringify(report) + formatReport(report)

  for (let length = 6; length <= SECRET.length; length += 1) {
    assert.equal(serialized.includes(SECRET.slice(0, length)), false, `leaked a ${length}-character prefix`)
  }
  assert.equal(serialized.includes(String(SECRET.length)), false, 'leaked the secret length')
})

test('a secret with an incompatible default does not echo the default either', () => {
  const report = checkEnvironment(
    contract({ TOKEN: { type: 'url', secret: true, default: 'not-a-url', owner: 'security' } }),
    manifest({}),
  )

  assert.deepEqual(rulesFor(report, 'TOKEN'), ['default-incompatible'])
  assert.equal(JSON.stringify(report).includes('not-a-url'), false)
})

test('a secret that is present without its value passes quietly', () => {
  const report = checkEnvironment(
    contract({ TOKEN: { type: 'string', secret: true, required: true, owner: 'security' } }),
    manifest({ TOKEN: { present: true } }),
  )

  assert.equal(report.status, 'pass')
  assert.deepEqual(report.findings, [])
})

test('a non-secret present without a value says its shape was not checked', () => {
  const report = checkEnvironment(
    contract({ REGION: { type: 'string', owner: 'ops' } }),
    manifest({ REGION: { present: true } }),
  )

  assert.equal(report.status, 'pass')
  assert.deepEqual(rulesFor(report, 'REGION'), ['value-not-provided'])
  assert.equal(report.findings[0].severity, 'info')
})

test('an undeclared variable is a warning, not a failure', () => {
  const report = checkEnvironment(
    contract({ A: { type: 'string', owner: 'o' } }),
    manifest({ A: { value: 'x' }, LEGACY: { value: 'y' } }),
  )

  assert.equal(report.status, 'pass')
  assert.deepEqual(rulesFor(report, 'LEGACY'), ['variable-undeclared'])
})

test('a non-string value is rejected by shape, not coerced', () => {
  const report = checkEnvironment(
    contract({ PORT: { type: 'integer', owner: 'o' } }),
    manifest({ PORT: { value: 8080 } }),
  )

  assert.deepEqual(rulesFor(report, 'PORT'), ['value-not-a-string'])
  assert.equal(report.findings[0].shape, 'number')
})

test('a malformed entry is reported without crashing', () => {
  const report = checkEnvironment(
    contract({ A: { type: 'string', owner: 'o' } }),
    manifest({ A: 'just a string' }),
  )

  assert.deepEqual(rulesFor(report, 'A'), ['entry-malformed'])
})

test('findings are deterministically ordered', async () => {
  const first = checkEnvironment(await example('contract.json'), await example('broken.env.json'))
  const second = checkEnvironment(await example('contract.json'), await example('broken.env.json'))

  assert.deepEqual(first.findings, second.findings)
  const names = first.findings.map((item) => item.name)
  assert.deepEqual(names, [...names].sort())
})

test('a malformed contract is a configuration error, never a quiet pass', () => {
  assert.throws(() => validateContract(null), /must be an object/)
  assert.throws(() => validateContract({ schemaVersion: '9', variables: {} }), /Unsupported contract schemaVersion/)
  assert.throws(() => validateContract({ schemaVersion: '1' }), /missing its variables object/)
  assert.throws(() => validateContract(contract({ lowercase: { type: 'string', owner: 'o' } })), /uppercase name/)
  assert.throws(() => validateContract(contract({ A: { type: 'date', owner: 'o' } })), /unsupported type/)
  assert.throws(() => validateContract(contract({ A: { type: 'enum', owner: 'o' } })), /allowedValues/)
  assert.throws(() => validateContract(contract({ A: { type: 'string' } })), /needs an owner/)
  assert.throws(() => validateContract(contract({ A: { type: 'string', owner: 'o', secret: 'yes' } })), /non-boolean secret/)
  assert.throws(() => validateContract(contract({ A: { type: 'string', owner: 'o', default: 7 } })), /default must be a string/)
  assert.throws(() => validateContract(contract({ A: { type: 'string', owner: 'o', pattern: '([' } })), /invalid pattern/)
})

test('a malformed manifest is rejected rather than treated as empty', () => {
  const valid = contract({ A: { type: 'string', owner: 'o' } })

  assert.throws(() => checkEnvironment(valid, null), /must be an object/)
  assert.throws(() => checkEnvironment(valid, { schemaVersion: '1' }), /missing its variables object/)
})

test('the report envelope carries the tool identity and environment label', () => {
  const report = checkEnvironment(
    contract({ A: { type: 'string', owner: 'o' } }),
    { schemaVersion: '1', environment: 'staging', variables: { A: { value: 'x' } } },
  )

  assert.equal(report.schemaVersion, '1')
  assert.equal(report.tool, 'env-var-contract-checker')
  assert.equal(report.summary.environment, 'staging')
})
