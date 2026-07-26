# vaultlint

Security linter for Solana and Anchor programs. It reads your Rust the way an auditor
reads it — accounts, seeds, CPIs, math — and reports the file, the line, why it is
dangerous, and how to fix it.

No AI, no network calls, no telemetry: five hand-written rules that run offline in
milliseconds.

[![ci](https://github.com/vaultlint/vaultlint/actions/workflows/ci.yml/badge.svg)](https://github.com/vaultlint/vaultlint/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/vaultlint.svg)](https://crates.io/crates/vaultlint)
[![license](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#licence)

## Install

```bash
cargo install vaultlint
```

Prebuilt binaries for macOS and Linux are attached to every [release](https://github.com/vaultlint/vaultlint/releases).

## Use

```bash
vaultlint scan ./programs
```

```
$ vaultlint scan ./examples/vulnerable
→ analyzing 5 Rust files …

✗ HIGH  missing owner check
        ./examples/vulnerable/missing_owner.rs:5
        Account data is deserialised without verifying the account owner. An attacker can pass a look-alike account owned by another program.
        Use `Account<'info, T>`, which checks the owner and discriminator, or add `require_keys_eq!(*account.owner, crate::ID)` before reading.

✗ HIGH  missing signer check
        ./examples/vulnerable/missing_signer.rs:8
        `authority` is not constrained as Signer. Any account can be passed here.
        Declare the field as `Signer<'info>`, or add `constraint = <account>.is_signer`.

⚠ MED  non-canonical PDA bump
        ./examples/vulnerable/pda_bump.rs:7
        `vault` uses `bump = user_bump`, where `user_bump` is an `#[instruction]` argument. An attacker controls this value and can pass a non-canonical bump to address a different account.
        Store the canonical bump (from `init`) in the account data and validate with `bump = <account>.bump`.

⚠ MED  unchecked CPI to unknown program
        ./examples/vulnerable/unchecked_cpi.rs:10
        This cross-program invocation runs without verifying the callee's program id. An attacker who controls that account can point it at their own program.
        Use Anchor's typed CPI helpers, or verify the id first, e.g. `require_keys_eq!(program.key(), expected::ID)`.

⚠ MED  unchecked arithmetic
        ./examples/vulnerable/unchecked_math.rs:4
        Unchecked subtraction writes into account state. Solana programs are built in release mode, where overflow wraps silently.
        Use `checked_add` / `checked_sub` / `checked_mul` and handle the `None` case.

⚠ MED  unchecked arithmetic
        ./examples/vulnerable/unchecked_math.rs:5
        Unchecked addition writes into account state. Solana programs are built in release mode, where overflow wraps silently.
        Use `checked_add` / `checked_sub` / `checked_mul` and handle the `None` case.

6 issues found · 2 high · 4 medium
```

Exit codes make it CI-ready: `0` when nothing exceeds the threshold, `1` when it does,
`2` on a tool error. The threshold defaults to `high` and is set with
`--fail-on high|medium|low|never`.

## Rules

| ID | Severity | What it catches |
|----|----------|-----------------|
| [VL001](https://vaultlint.com/rules/VL001) | High | Authority accounts that are not constrained as `Signer` |
| [VL002](https://vaultlint.com/rules/VL002) | High | Account data deserialised without an owner check |
| [VL003](https://vaultlint.com/rules/VL003) | Medium | Unchecked `+ - *` written into account state |
| [VL004](https://vaultlint.com/rules/VL004) | Medium | PDAs validated with a caller-supplied bump (`bump = <instruction arg>`) |
| [VL005](https://vaultlint.com/rules/VL005) | Medium | `invoke` / `invoke_signed` without program id verification |

Every rule is deliberately narrow. A linter that cries wolf on healthy code gets
uninstalled the same day, so vaultlint prefers a missed finding to a false one.

Silence a specific finding with a comment on its own line, or anywhere in the
block of comments and attributes directly above it:

```rust
// vaultlint:allow VL003 — audited, cannot underflow
vault.balance = vault.balance - fee;
```

The comment does not have to sit immediately above the finding, so it still
works on the fields where Anchor mandates a `/// CHECK:` doc comment or an
`#[account(...)]` attribute in that position:

```rust
// vaultlint:allow VL001 — authority is verified in the handler
/// CHECK: verified in the handler
pub authority: AccountInfo<'info>,
```

## In CI

```yaml
- run: cargo install vaultlint
- run: vaultlint scan ./programs --format sarif > vaultlint.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: vaultlint.sarif
```

GitHub reads SARIF natively, so findings appear in the repository's Security tab.

## What it is not

vaultlint is a linter, not a prover. It finds patterns strongly correlated with
vulnerabilities; it does not prove their absence and does not replace an audit.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Adding a rule means one file in `src/rules/`,
one line in the registry, and a pair of tests — one vulnerable, one clean.

## Licence

MIT OR Apache-2.0, at your option.
