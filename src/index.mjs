export const TOOL_ID = 'env-var-contract-checker'
export const CONTRACT_SCHEMA_VERSION = '1'
export const REPORT_SCHEMA_VERSION = '1'

export const TYPES = Object.freeze(['string', 'integer', 'number', 'boolean', 'url', 'enum'])

/**
 * Redaction is not a formatting concern here, it is the contract.
 *
 * This tool exists so an environment can be reviewed without the review itself
 * becoming a place secrets leak: into a CI log, a report artifact, or a commit.
 * A value belonging to a variable the contract marks `secret` is never echoed,
 * never summarised, and never length-reported. The only facts recorded about it
 * are whether it was present and whether it satisfied its declared shape.
 */
export const REDACTED = '[redacted]'

/**
 * What a `JSON.parse` failure may say about a file this tool did not write.
 *
 * V8 reports a parse failure two ways, and one of them quotes the input back:
 * `Unexpected token 'A', "AKIAIOSFODNN7EXAMPLE" is not valid JSON` -- the whole
 * document when the document is short, a ten-character window when it is not.
 * A manifest is exactly the kind of file that is short and nothing but a
 * credential, so interpolating that message would defeat the redaction this
 * tool exists for, on the one path -- a malformed file -- where nothing else
 * examines the content at all.
 *
 * The quoting shape is recognised FIRST, and that ordering is load-bearing.
 * Searching for the offset first finds `at position 1` INSIDE the quoted span
 * whenever the manifest itself contains that text, and then slices the
 * manifest straight back out: a manifest reading `at position 1` came back as
 * `Unexpected token 'a', "at position 1`.
 *
 * The position is the useful half and carries no content, so it is kept
 * whenever V8 offers one on its own. The quoted half never leaves this
 * function. The closing guard is deliberate belt and braces: every parse
 * message V8 emits without a quoted snippet spells JSON punctuation with
 * apostrophes and carries no double quote at all, so a double quote surviving
 * to the end means a snippet survived with it, whatever the branches above
 * concluded, and the generic sentence is returned instead.
 */
export function parseFailureDetail(error) {
  const message = String(error?.message ?? '')
  const detail = describeParseFailure(message)
  return detail.includes('"') ? UNPARSEABLE : detail
}

const UNPARSEABLE = 'the document could not be parsed as JSON'

/** Where V8 puts the offending offset. Safe: an offset says nothing about content. */
const POSITION = /at position \d+(?: \(line \d+ column \d+\))?/

/**
 * The shape that quotes the input. A leading `...` means the quoted run was
 * taken from the middle of the document rather than its start, which is the
 * only thing about the position this shape reveals. The `s` flag matters too:
 * the quoted span can contain a newline.
 */
const QUOTES_THE_INPUT = /^Unexpected token (.+?), (\.\.\.)?".*"(?:\.\.\.)? is not valid JSON$/s

function describeParseFailure(message) {
  const quoting = QUOTES_THE_INPUT.exec(message)
  if (quoting !== null) {
    const where = quoting[2] === undefined ? 'at the start of the document' : 'inside the document'
    return `unexpected token ${quoting[1]} ${where}`
  }
  const position = POSITION.exec(message)
  if (position !== null) return message.slice(0, position.index + position[0].length)
  if (message === 'Unexpected end of JSON input') return message
  return UNPARSEABLE
}

function byCodeUnit(left, right) {
  if (left === right) return 0
  return left < right ? -1 : 1
}

function finding(ruleId, severity, message, name, extra = {}) {
  return { ruleId, severity, message, location: { pointer: `/${name}` }, name, ...extra }
}

function isRecord(value) {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value)
}

/** Describe a value without revealing it. Safe for any variable, secret or not. */
function shapeOf(value) {
  if (value === null) return 'null'
  if (Array.isArray(value)) return 'array'
  return typeof value
}

function checkType(raw, declared) {
  const { type } = declared

  if (type === 'boolean') {
    return ['true', 'false', '1', '0'].includes(raw)
      ? null
      : 'must be one of true, false, 1 or 0'
  }
  if (type === 'integer') {
    return /^-?\d+$/.test(raw) ? null : 'must be an integer'
  }
  if (type === 'number') {
    return /^-?(?:\d+\.?\d*|\.\d+)(?:[eE][-+]?\d+)?$/.test(raw) && Number.isFinite(Number(raw))
      ? null
      : 'must be a finite number'
  }
  if (type === 'url') {
    let parsed
    try {
      parsed = new URL(raw)
    } catch {
      return 'must be an absolute URL'
    }
    const schemes = declared.allowedSchemes ?? ['http', 'https']
    return schemes.includes(parsed.protocol.slice(0, -1))
      ? null
      : `must use one of these URL schemes: ${schemes.join(', ')}`
  }
  if (type === 'enum') {
    return declared.allowedValues.includes(raw)
      ? null
      : `must be one of: ${declared.allowedValues.join(', ')}`
  }

  if (declared.pattern !== undefined && !new RegExp(declared.pattern).test(raw)) {
    return `must match ${declared.pattern}`
  }
  if (declared.minLength !== undefined && raw.length < declared.minLength) {
    return `must be at least ${declared.minLength} characters long`
  }
  return null
}

/**
 * Validate the contract document itself.
 *
 * A malformed contract is a configuration error, not a finding about the
 * environment: reporting "everything passed" against rules that could not be
 * read would be worse than saying nothing.
 */
export function validateContract(contract) {
  if (!isRecord(contract)) throw new TypeError('Contract must be an object')
  if (contract.schemaVersion !== CONTRACT_SCHEMA_VERSION) {
    throw new TypeError(`Unsupported contract schemaVersion: ${contract.schemaVersion ?? 'missing'}`)
  }
  if (!isRecord(contract.variables)) throw new TypeError('Contract is missing its variables object')

  for (const [name, declared] of Object.entries(contract.variables)) {
    if (!/^[A-Z][A-Z0-9_]*$/.test(name)) {
      throw new TypeError(`Variable "${name}" must be an uppercase name such as DATABASE_URL`)
    }
    if (!isRecord(declared)) throw new TypeError(`Variable "${name}" must be an object`)
    if (!TYPES.includes(declared.type)) {
      throw new TypeError(`Variable "${name}" has unsupported type "${declared.type ?? 'missing'}"`)
    }
    if (declared.type === 'enum' && (!Array.isArray(declared.allowedValues) || declared.allowedValues.length === 0)) {
      throw new TypeError(`Variable "${name}" is an enum and needs a non-empty allowedValues array`)
    }
    if (typeof declared.owner !== 'string' || declared.owner.trim() === '') {
      throw new TypeError(`Variable "${name}" needs an owner`)
    }
    if (declared.secret !== undefined && typeof declared.secret !== 'boolean') {
      throw new TypeError(`Variable "${name}" has a non-boolean secret flag`)
    }
    if (declared.default !== undefined && typeof declared.default !== 'string') {
      throw new TypeError(`Variable "${name}" default must be a string, matching how environments carry values`)
    }
    if (declared.pattern !== undefined) {
      try {
        new RegExp(declared.pattern)
      } catch {
        throw new TypeError(`Variable "${name}" has an invalid pattern`)
      }
    }
  }
  return contract
}

/**
 * Check an environment manifest against a contract.
 *
 * The manifest declares which names are present. A non-secret variable may
 * carry its value for shape checking; a secret variable must not, and doing so
 * is reported as a leak in the input without echoing what leaked.
 */
export function checkEnvironment(contract, manifest, options = {}) {
  validateContract(contract)
  if (!isRecord(manifest)) throw new TypeError('Environment manifest must be an object')
  if (!isRecord(manifest.variables)) throw new TypeError('Environment manifest is missing its variables object')

  const environment = options.environment ?? manifest.environment ?? null
  const findings = []
  const declaredNames = new Set(Object.keys(contract.variables))

  for (const [name, declared] of Object.entries(contract.variables)) {
    const secret = declared.secret === true
    const entry = manifest.variables[name]
    const present = entry !== undefined && entry !== null

    // Default validity is a property of the contract, not of this environment,
    // so it is checked whether or not the variable is set here.
    if (declared.default !== undefined) {
      const problem = checkType(declared.default, declared)
      if (problem) {
        findings.push(finding(
          'default-incompatible',
          'error',
          `Declared default for ${name} ${problem}.`,
          name,
          secret ? {} : { evidence: String(declared.default).slice(0, 80) },
        ))
      }
    }

    if (!present) {
      if (declared.required === true && declared.default === undefined) {
        findings.push(finding('required-missing', 'error', `Required variable ${name} is not set.`, name, { owner: declared.owner }))
      } else if (declared.required === true) {
        findings.push(finding(
          'required-using-default',
          'warning',
          `Required variable ${name} is not set and will fall back to its declared default.`,
          name,
          { owner: declared.owner },
        ))
      }
      continue
    }

    if (!isRecord(entry)) {
      findings.push(finding('entry-malformed', 'error', `Entry for ${name} must be an object.`, name, { shape: shapeOf(entry) }))
      continue
    }

    const hasValue = Object.hasOwn(entry, 'value')

    if (secret && hasValue) {
      // Report the leak. Do not quote it, measure it, or hash it.
      findings.push(finding(
        'secret-value-present',
        'error',
        `${name} is declared secret but the manifest carries its value. Re-export this manifest with secret values omitted.`,
        name,
        { owner: declared.owner },
      ))
      continue
    }

    if (!hasValue) {
      if (!secret) {
        findings.push(finding(
          'value-not-provided',
          'info',
          `${name} is present but its value was not included, so its shape was not checked.`,
          name,
        ))
      }
      continue
    }

    if (typeof entry.value !== 'string') {
      findings.push(finding(
        'value-not-a-string',
        'error',
        `Value for ${name} must be a string, matching how environments carry values.`,
        name,
        { shape: shapeOf(entry.value) },
      ))
      continue
    }

    const problem = checkType(entry.value, declared)
    if (problem) {
      findings.push(finding(
        'value-incompatible',
        'error',
        `${name} ${problem}.`,
        name,
        { evidence: entry.value.slice(0, 80) },
      ))
    }
  }

  for (const name of Object.keys(manifest.variables)) {
    if (!declaredNames.has(name)) {
      findings.push(finding(
        'variable-undeclared',
        'warning',
        `${name} is set but the contract does not declare it.`,
        name,
      ))
    }
  }

  findings.sort((left, right) => byCodeUnit(left.name, right.name) || byCodeUnit(left.ruleId, right.ruleId))

  const errors = findings.filter((item) => item.severity === 'error').length
  const warnings = findings.filter((item) => item.severity === 'warning').length

  return {
    schemaVersion: REPORT_SCHEMA_VERSION,
    tool: TOOL_ID,
    status: errors > 0 ? 'fail' : 'pass',
    summary: {
      checked: declaredNames.size,
      errors,
      warnings,
      info: findings.length - errors - warnings,
      environment,
      secretsDeclared: Object.values(contract.variables).filter((declared) => declared.secret === true).length,
    },
    findings,
  }
}

export function formatReport(report) {
  const lines = report.findings.map((item) =>
    `${item.severity.toUpperCase().padEnd(7)} ${item.name} ${item.message}`)
  lines.push('')
  lines.push(
    `${report.summary.checked} declared variable(s)`
    + `${report.summary.environment ? ` in ${report.summary.environment}` : ''}: `
    + `${report.summary.errors} error, ${report.summary.warnings} warning, status ${report.status}.`,
  )
  lines.push(`${report.summary.secretsDeclared} variable(s) declared secret; their values are never read or reported.`)
  return `${lines.join('\n')}\n`
}
