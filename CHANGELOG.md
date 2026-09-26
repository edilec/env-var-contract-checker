# Changelog

All notable changes to this project are documented in this file.

## Unreleased

### Added

- a versioned environment variable contract covering type, ownership, required
  state, defaults, secret classification and per-type constraints;
- `checkEnvironment`, reporting missing values, incompatible defaults,
  incompatible values, undeclared variables and malformed entries;
- secret handling that never echoes, summarises or length-reports a secret, and
  reports a manifest carrying one as a leak in the input;
- a CLI with `--json` and exit codes 0 / 1 / 2;
- runnable contract, healthy environment and broken environment examples;
- the format reference and rule catalog in `docs/contract-format.md`.

### Fixed

- the diagnostic for a contract or manifest that is not JSON no longer
  reproduces the file. `JSON.parse` reports a failure either by position or by
  quoting the input back — `Unexpected token 'A', "AKIAIOSFODNN7EXAMPLE" is not
  valid JSON`, which is the whole document when the document is short — so a
  manifest that was nothing but a credential was printed in full by the message
  that failed to read it, defeating the redaction this tool exists for. The
  diagnostic is built from the position, line and column alone now.

No release has been published.
