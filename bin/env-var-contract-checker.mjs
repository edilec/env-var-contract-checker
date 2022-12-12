#!/usr/bin/env node

import { readFile } from 'node:fs/promises'
import { resolve } from 'node:path'

import { checkEnvironment, formatReport } from '../src/index.mjs'

const HELP = `env-var-contract-checker

Check a redacted environment manifest against a declared variable contract.

Usage:
  env-var-contract-checker --contract FILE --env FILE [--environment NAME] [--json]

Options:
  --contract FILE     Declared variable contract
  --env FILE          Redacted environment manifest to check
  --environment NAME  Label recorded in the report
  --json              Emit the machine-readable report on stdout
  -h, --help          Show this help

Secret values are never read or reported. A manifest that carries one is
reported as a leak in the input, without echoing what leaked.

Exit codes:
  0  the environment satisfied its contract
  1  the environment failed its contract
  2  invalid usage, or a file could not be read or understood
`

function parseArguments(argv) {
  if (argv.includes('-h') || argv.includes('--help')) return { help: true }
  const options = { contract: null, env: null, environment: null, json: false }

  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index]
    const takeValue = (name) => {
      const value = argv[index + 1]
      if (value === undefined || value.startsWith('-')) throw new Error(`${name} requires a value`)
      index += 1
      return value
    }
    if (argument === '--json') options.json = true
    else if (argument === '--contract') options.contract = takeValue('--contract')
    else if (argument === '--env') options.env = takeValue('--env')
    else if (argument === '--environment') options.environment = takeValue('--environment')
    else throw new Error(`Unknown option "${argument}"`)
  }

  if (!options.contract) throw new Error('--contract is required')
  if (!options.env) throw new Error('--env is required')
  return options
}

async function loadJson(path, label) {
  try {
    return JSON.parse(await readFile(resolve(path), 'utf8'))
  } catch (error) {
    throw new Error(`Could not read ${label}: ${error.message}`)
  }
}

async function main(argv) {
  let options
  try {
    options = parseArguments(argv)
  } catch (error) {
    process.stderr.write(`${error.message}\n\n${HELP}`)
    return 2
  }
  if (options.help) {
    process.stdout.write(HELP)
    return 0
  }

  try {
    const contract = await loadJson(options.contract, 'contract')
    const manifest = await loadJson(options.env, 'environment manifest')
    const report = checkEnvironment(contract, manifest, { environment: options.environment ?? undefined })
    process.stdout.write(options.json ? `${JSON.stringify(report, null, 2)}\n` : formatReport(report))
    return report.status === 'fail' ? 1 : 0
  } catch (error) {
    process.stderr.write(`${error.message}\n`)
    return 2
  }
}

process.exitCode = await main(process.argv.slice(2))
