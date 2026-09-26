import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { dirname, resolve } from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'

const projectDirectory = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const cli = resolve(projectDirectory, 'bin/env-var-contract-checker.mjs')

function run(args) {
  return spawnSync(process.execPath, [cli, ...args], { cwd: projectDirectory, encoding: 'utf8' })
}

const CONTRACT = ['--contract', 'examples/contract.json']

test('a healthy environment exits zero', () => {
  const result = run([...CONTRACT, '--env', 'examples/production.env.json'])

  assert.equal(result.status, 0)
  assert.match(result.stdout, /status pass/)
})

test('a broken environment exits one and names each problem', () => {
  const result = run([...CONTRACT, '--env', 'examples/broken.env.json'])

  assert.equal(result.status, 1)
  assert.match(result.stdout, /DATABASE_URL/)
  assert.match(result.stdout, /LOG_LEVEL/)
})

test('the CLI never prints a secret value it was handed', () => {
  const result = run([...CONTRACT, '--env', 'examples/broken.env.json', '--json'])
  const combined = result.stdout + result.stderr

  assert.equal(combined.includes('hunter2'), false)
  assert.match(result.stdout, /secret-value-present/)
})

test('--json is parseable and keeps stderr clean', () => {
  const result = run([...CONTRACT, '--env', 'examples/production.env.json', '--json'])

  assert.equal(result.stderr, '')
  assert.equal(JSON.parse(result.stdout).tool, 'env-var-contract-checker')
})

test('repeated runs produce identical JSON', () => {
  const args = [...CONTRACT, '--env', 'examples/broken.env.json', '--json']
  assert.equal(run(args).stdout, run(args).stdout)
})

test('--environment labels the report', () => {
  const result = run([...CONTRACT, '--env', 'examples/production.env.json', '--environment', 'canary', '--json'])

  assert.equal(JSON.parse(result.stdout).summary.environment, 'canary')
})

test('a missing file exits two rather than passing', () => {
  const result = run([...CONTRACT, '--env', 'examples/nope.json'])

  assert.equal(result.status, 2)
  assert.equal(result.stdout, '')
  assert.match(result.stderr, /Could not read environment manifest/)
})

test('a malformed contract exits two', () => {
  const result = run(['--contract', 'examples/production.env.json', '--env', 'examples/production.env.json'])

  assert.equal(result.status, 2)
  assert.match(result.stderr, /unsupported type|variables object|schemaVersion|owner/)
})

test('missing required options are usage errors', () => {
  assert.equal(run([]).status, 2)
  assert.match(run(['--env', 'examples/production.env.json']).stderr, /--contract is required/)
  assert.match(run(CONTRACT).stderr, /--env is required/)
})

test('--help exits zero', () => {
  const result = run(['--help'])

  assert.equal(result.status, 0)
  assert.match(result.stdout, /Usage:/)
})
