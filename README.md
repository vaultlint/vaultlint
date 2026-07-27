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

⚠ MED  unproven authority on initialization
        ./examples/vulnerable/unproven_authority.rs:27
        `authority` is an unvalidated account whose key is baked into the seeds of `user_account`, initialised by this instruction, and read by the handler. Nothing proves the account authorised this, so anyone can create `user_account` naming an arbitrary `authority`.
        Declare the field as `Signer<'info>` if it must authorise the instruction, or bind it to an account whose authority was already proven (`has_one = ...`, `constraint = ...`). If the permissionless designation is intended, suppress the finding.

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

6 issues found · 1 high · 5 medium
```

Exit codes make it CI-ready: `0` when nothing exceeds the threshold, `1` when it does,
`2` on a tool error. The threshold defaults to `high` and is set with
`--fail-on high|medium|low|never`.

## Rules

| ID | Severity | What it catches |
|----|----------|-----------------|
| [VL001](https://vaultlint.com/rules/VL001) | Medium | An unvalidated authority baked into the seeds of an account this instruction creates, and written into it |
| [VL002](https://vaultlint.com/rules/VL002) | High | Account data deserialised without an owner check |
| [VL003](https://vaultlint.com/rules/VL003) | Medium | Unchecked `+ - *` written into account state |
| [VL004](https://vaultlint.com/rules/VL004) | Medium | PDAs validated with a caller-supplied bump (`bump = <instruction arg>`) |
| [VL005](https://vaultlint.com/rules/VL005) | Medium | `invoke` / `invoke_signed` without program id verification |

Every rule is deliberately narrow. A linter that cries wolf on healthy code gets
uninstalled the same day, so vaultlint prefers a missed finding to a false one.

**VL001 does not detect missing signer checks in general**, and you should not read
a clean run as "authorization is correct". It detects one shape: an unvalidated
authority-named account whose key is baked into the `seeds` of an account the same
instruction creates, and which the handler then writes into that account. Anyone can
call such an instruction naming an arbitrary authority. The generic version of this
rule was tried and abandoned — every signature broad enough to catch the textbook
case also fired on deliberately permissionless cranks, delegate designations and CPI
forwards, at an 88% false positive rate on audited production code.

The narrow rule was calibrated against a real bug: marginfi-v2 commit `95a4c26`,
*"Authority must now sign to init account as PDA"*, whose entire diff is
`pub authority: UncheckedAccount<'info>` → `pub authority: Signer<'info>`. VL001
fires on the line that commit changed and is silent afterwards. Across thirteen
open-source Solana codebases — roughly 2,100 files — it reports four findings.

Its limits, stated plainly: it reads handler bodies only one call deep, so a program
that verifies `is_signer` further away will be flagged; a field forwarded through
`remaining_accounts` is invisible; permissionless-by-design is indistinguishable from
a bug without protocol context, so confirm intent rather than assuming a
vulnerability; and it only considers fields named like authorities.

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
