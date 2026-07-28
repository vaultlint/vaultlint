# Changelog

All notable changes to VaultLint are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- **`VL002` reports a bare `AccountInfo` parameter at Medium instead of High.** When
  the deserialised account arrives as a helper's `&AccountInfo` argument, whatever the
  caller proved about it is in another function, and VL002 reads one function at a
  time. The finding stays — a helper that trusts its caller is the shape Metaplex has
  historically been exploited through — but the rule no longer fails a default
  `--fail-on high` build on a question it admits it cannot answer. An account the
  handler itself holds and never checks is still High. On the `coral-xyz/anchor`
  measurement corpus this is the difference between exit 1 and exit 0; the finding
  count is unchanged.

## [0.1.0] — 2026-07-28

First public release.

### Added

- **Five security rules for Solana and Anchor programs:**
  - `VL001` — unproven authority on initialization (Medium)
  - `VL002` — missing owner check (High)
  - `VL003` — `overflow-checks` is not enabled (Medium)
  - `VL004` — non-canonical PDA bump (Medium)
  - `VL005` — unchecked CPI to unknown program (Medium)
- **Three output formats** via `--format`: `human` (default), `json`, and `sarif`.
  The SARIF output targets GitHub code scanning, so findings appear as
  annotations on a pull request.
- **`--fail-on <high|medium|low|never>`** to control the exit code, defaulting to
  `high`. This is what makes the tool usable as a CI gate.
- **Inline suppression** with `// vaultlint:allow VL001`, honoured on the finding's
  own line or on a contiguous block of comments and attributes above it. A bare
  `vaultlint:allow` with no rule id is deliberately not honoured — silencing every
  rule at once should have to be explicit.
- **Project detection** — VaultLint locates the workspace manifest Cargo would read
  `[profile.release]` from and reads the Anchor version and the `overflow-checks`
  setting from it, so `VL003` stays quiet on projects that already enable overflow
  checks.
- **A documentation link on every finding**, pointing at the rule's page on
  <https://vaultlint.com/rules/>. In SARIF this becomes `helpUri`, so the "learn
  more" link on a GitHub Security alert resolves.

### Notes

- VaultLint runs entirely offline. There are no network calls and no telemetry, and
  your source never leaves your machine.
- Rules were measured against real production code and narrowed until the false
  positive rate was acceptable; the measurements are recorded in `docs/measurements/`.
- VaultLint complements a manual audit rather than replacing one.

[Unreleased]: https://github.com/vaultlint/vaultlint/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/vaultlint/vaultlint/releases/tag/v0.1.0
