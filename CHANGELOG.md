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

No release has been published.
