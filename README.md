# Environment Variable Contract Checker

Check a redacted environment manifest against a declared variable contract.

- **Repository:** [edilec/env-var-contract-checker](https://github.com/edilec/env-var-contract-checker)
- **Area:** Cloud & Platform
- **License:** MIT

## Why it exists

Configuration drifts quietly. A variable gets renamed in one environment, a
default stops matching its type, an old name lingers after the code that read it
was deleted — and none of it surfaces until a deploy fails.

The awkward part is that reviewing configuration usually means handling secrets,
so the review itself becomes a place they leak: into a CI log, a report
artifact, or a commit. This tool is built so that cannot happen.

## Requirements

- Node.js 22 or newer
- no runtime dependencies

## Quick start

```sh
node bin/env-var-contract-checker.mjs \
  --contract examples/contract.json \
  --env examples/production.env.json
```

```text
6 declared variable(s) in production: 0 error, 0 warning, status pass.
2 variable(s) declared secret; their values are never read or reported.
```

A broken environment names each problem:

```text
ERROR   API_BASE_URL API_BASE_URL must be an absolute URL.
ERROR   DATABASE_URL Required variable DATABASE_URL is not set.
WARNING LEGACY_TIMEOUT LEGACY_TIMEOUT is set but the contract does not declare it.
ERROR   LOG_LEVEL LOG_LEVEL must be one of: debug, info, warn, error.
ERROR   MAX_CONNECTIONS MAX_CONNECTIONS must be an integer.
ERROR   SESSION_SIGNING_KEY SESSION_SIGNING_KEY is declared secret but the manifest carries its value. Re-export this manifest with secret values omitted.
```

Note the last line: the tool reports that a secret leaked into the manifest
**without repeating what leaked**.

## Secrets

For any variable declared `secret`:

- its value is never echoed, never summarised, and never length-reported;
- an incompatible `default` is reported without quoting the default either;
- a manifest carrying the value is reported as `secret-value-present`, a leak in
  the *input*, and that variable is not inspected further.

The only facts recorded about a secret are whether it was present and whether it
satisfied its declared shape. The test suite asserts this by scanning the whole
serialized report — and every prefix of the secret — rather than trusting the
formatter.

## Values are strings

Values are strings throughout, because that is what a process environment
actually holds. A JSON number like `8080` is rejected rather than coerced, so a
manifest cannot pass a check that its real environment would fail.

## Library usage

```js
import { checkEnvironment } from 'env-var-contract-checker'

const report = checkEnvironment(contract, manifest, { environment: 'production' })
```

The contract format, manifest format and full rule catalog are in
[`docs/contract-format.md`](./docs/contract-format.md).

## Exit codes

| Code | Meaning |
| ---: | --- |
| `0` | the environment satisfied its contract |
| `1` | the environment failed its contract |
| `2` | invalid usage, or a file could not be read or understood |

## Limits and non-goals

- It reads a **manifest**, not a live process environment. It never reads
  `process.env`, a `.env` file, or a secret store, so it cannot leak a value it
  was never given.
- It checks shape and declaration, not correctness. A `DATABASE_URL` that parses
  as a URL may still point at the wrong database.
- `secret` is a declaration, not detection. The tool will not notice that an
  undeclared variable happens to hold a credential.
- A malformed contract throws rather than producing findings, because reporting
  "everything passed" against rules that could not be read would be worse than
  saying nothing.
- Passing this check is not a deployment approval.

## Development

```sh
npm test          # behaviour tests
npm run check     # lint, tests, runnable example, packaging check
```

## License

MIT. See [LICENSE](./LICENSE).
