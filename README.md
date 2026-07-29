# vaultlint

Security linter for Solana and Anchor programs. It reads your Rust the way an auditor
reads it — accounts, seeds, CPIs, math — and reports the file, the line, why it is
dangerous, and how to fix it.

No AI, no telemetry, and no network calls unless you ask for one: five hand-written
rules that run offline in milliseconds.

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
        https://vaultlint.com/rules/VL002/

⚠ MED  non-canonical PDA bump
        ./examples/vulnerable/pda_bump.rs:7
        `vault` uses `bump = user_bump`, where `user_bump` is an `#[instruction]` argument. An attacker controls this value and can pass a non-canonical bump to address a different account.
        Store the canonical bump (from `init`) in the account data and validate with `bump = <account>.bump`.
        https://vaultlint.com/rules/VL004/

⚠ MED  unchecked CPI to unknown program
        ./examples/vulnerable/unchecked_cpi.rs:10
        `*ctx.accounts.target_program.key` supplies the program id for this CPI, and nothing in the handler proves which program it is. An attacker who controls that account can point the invocation at their own program.
        Use Anchor's typed CPI helpers, or verify the id first, e.g. `require_keys_eq!(program.key(), expected::ID)`.
        https://vaultlint.com/rules/VL005/

⚠ MED  unproven authority on initialization
        ./examples/vulnerable/unproven_authority.rs:27
        `authority` is an unvalidated account whose key is baked into the seeds of `user_account`, initialised by this instruction, and read by the handler. Nothing proves the account authorised this, so anyone can create `user_account` naming an arbitrary `authority`.
        Declare the field as `Signer<'info>` if it must authorise the instruction, or bind it to an account whose authority was already proven (`has_one = ...`, `constraint = ...`). If the permissionless designation is intended, suppress the finding.
        https://vaultlint.com/rules/VL001/

⚠ LOW  unchecked arithmetic
        ./examples/vulnerable/unchecked_math.rs:4
        Unchecked subtraction writes into a struct field, and this workspace does not enable `overflow-checks`, so an overflow wraps silently instead of aborting the transaction.
        Enable `overflow-checks` for the release profile, or use `checked_add` / `checked_sub` / `checked_mul` and handle the `None` case.
        https://vaultlint.com/rules/VL003/

⚠ LOW  unchecked arithmetic
        ./examples/vulnerable/unchecked_math.rs:5
        Unchecked addition writes into a struct field, and this workspace does not enable `overflow-checks`, so an overflow wraps silently instead of aborting the transaction.
        Enable `overflow-checks` for the release profile, or use `checked_add` / `checked_sub` / `checked_mul` and handle the `None` case.
        https://vaultlint.com/rules/VL003/

6 issues found · 1 high · 3 medium · 2 low
```

Exit codes make it CI-ready: `0` when nothing exceeds the threshold, `1` when it does,
`2` on a tool error. The threshold defaults to `high` and is set with
`--fail-on high|medium|low|never`.

## On chain

`--mainnet` collects every `declare_id!` in the tree and asks Solana what is actually
deployed at those addresses:

```
$ vaultlint scan . --mainnet
→ analyzing 26 Rust files (Anchor 0.29.0) …

→ on chain · 1 declared program id
  M2mx93ekt1fmXSVkTrUL9xVFHkmME8HTUi5Cyc5aF7K  upgradeable by 9GWPeu3cBfkGSEit6HMaAFKswoirxqgMqykMh7RVH2Bb — last deploy at slot 358179668
```

Six states are distinguished: no account at the address, an account that is not a
program, a program under a non-upgradeable loader, an upgradeable program whose
authority has been revoked, one that is still upgradeable — with the authority and
the slot of the last deploy — and an address the cluster would not answer about.
`--rpc-url <URL>` sends the lookup elsewhere and implies `--mainnet`; in JSON the
section is a `programs` array, present only when the lookup ran.

It reports no findings of its own and cannot change the exit code. Whether an id is
deployed is a fact about your release process, not a defect in your source: a fresh
repository and an abandoned one look identical from the source alone, and on fifteen
unaudited repositories half the undeployed ids were tutorials. So vaultlint prints
what the cluster said and lets you read it.

What it does do is mark the findings that are **in code which is running**:

```
⚠ MED  overflow-checks is not enabled
        Cargo.toml:6
        This workspace does not set `overflow-checks = true` under `[profile.release]`. …
        Add `[profile.release]` with `overflow-checks = true` to the workspace manifest. …
        live on mainnet at M2mx93ekt1fmXSVkTrUL9xVFHkmME8HTUi5Cyc5aF7K
        https://vaultlint.com/rules/VL003/
```

Neither half of that can be said alone. A block explorer sees the program running and
has never read the manifest that built it; a linter reads the manifest and has no idea
whether anything was ever deployed. The conjunction — *this defect is in code that is
executing at this address right now* — is the claim, and it is why the flag exists.

A finding is marked with an address when its crate is **compiled into** the program
deployed there — the path-dependency closure below that program's crate, not the crate
alone. A shared library declares no id of its own and its arithmetic still executes on
chain, so following `path` dependencies is what makes the mark mean anything: on
`mpl-account-compression` it is the difference between marking 1 finding and 5. Both
ways of naming a local crate are followed, an inline `path = "…"` and an inherited
`{ workspace = true }`, and transitively.

A finding reported against a manifest is the exception: it takes the whole workspace's
live ids, because Cargo reads `[profile.release]` from the root and builds every crate
under it with the flag that is missing.

Severity is deliberately unchanged. The exit code has to be a function of your source
alone, or the same commit passes CI today and fails tomorrow because an RPC endpoint
was slow. The mark tells you which findings to open first; it does not decide for you.

Two things are deliberately not followed, and both make the mark conservative rather
than generous. `dev-dependencies` and `build-dependencies` never reach the cluster. An
`optional = true` dependency is skipped, because whether it is compiled in depends on
which features the build turns on and a manifest alone does not say. So read an
unmarked finding as "not shown to be live", never as "not live". Across the fifteen
repositories 21 of 24 findings are marked; the 3 that are not sit behind program ids
with nothing deployed at them.

## Rules

| ID | Severity | What it catches |
|----|----------|-----------------|
| [VL001](https://vaultlint.com/rules/VL001/) | Medium | An unvalidated authority baked into the seeds of an account this instruction creates, and written into it |
| [VL002](https://vaultlint.com/rules/VL002/) | High / Medium | Raw account data deserialised with nothing proving which program owns the account |
| [VL003](https://vaultlint.com/rules/VL003/) | Medium | A workspace that does not enable `overflow-checks`, and the arithmetic that then wraps silently |
| [VL004](https://vaultlint.com/rules/VL004/) | Medium | PDAs validated with a caller-supplied bump (`bump = <instruction arg>`) |
| [VL005](https://vaultlint.com/rules/VL005/) | Medium | A CPI whose program id comes from an account the caller controls |

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

**VL002 accepts an address check as an owner check.** Only the deriving program can
sign for its own PDA, so an account holding data at an address derived from seeds and
this program's id was created by this program and is owned by it — the guarantee VL002
asks for, reached another way. A handler that derives the address and compares it to
the account key is silent, and so is an Anchor field carrying `seeds = [...]` or
`address = ...`, which Anchor verifies before the body runs. The proof has to name the
account being read: deriving a PDA for one account does not excuse a raw read of
another. Order is not required — a check after the read still stops the program acting
on bad data — so a handler that deserialises first and compares later is silent too.

Reading `.owner` is not checking it. `.owner` names two unrelated things in Solana:
the program that owns the account, and the wallet field of a deserialised SPL token
account. VL002 needs `.owner` in a checking position — a comparison, a `require_*!`
macro, or a helper like `assert_owned_by`. It also does not flag the method form
`account.try_deserialize(...)`, which is the *safe* Anchor path.

Helpers taking a bare `&AccountInfo` whose callers validate are still reported, because
a rule that reads one function at a time cannot see the caller — this is the shape
Metaplex has historically been exploited through, so the findings stay. They are
reported at **Medium**, not High: the rule is admitting that the evidence it needs is in
another function, and a question it cannot answer must not fail your build by default.
Everything else VL002 reports — an account the handler itself holds and never checks —
stays High.

**`#[access_control(...)]` is resolved, for VL002 and VL005.** Anchor expands the
attribute so the named function runs — and its error aborts the instruction — before
the handler body, and programs put exactly these checks there. Both rules read that
function's body as part of the handler's evidence, so a check written in a guard
silences the finding it covers. Two limits: the call is resolved by qualified name, so
`CreateCheck::accounts` never matches another struct's method of the same name, and it
is resolved only within the same file — a checker imported from elsewhere is invisible
and the finding stays. VL001 does not follow the attribute; it reaches handler bodies
through the cross-file use-site index, where the merged body that would silence it
would also feed the trigger that fires it.

**VL003 is a question about your build profile, asked once.** With
`[profile.release] overflow-checks = true` an overflow panics: the transaction aborts
and no funds move. Solana programs are built in release mode, so that one line switches
off the whole silent-wrap bug class, and it is the only actionable thing there is to
say. Reporting it per call site was measured and abandoned — 382 findings across twelve
production codebases, not one of them worth acting on. VL003 now asks the question once,
at the manifest Cargo actually reads `[profile.release]` from, and is completely silent
on a workspace that already sets the flag. Where it is missing, the arithmetic sites are
still listed, at Low, as evidence of what would wrap — but the question does not wait for
them. The flag is missing or present regardless of whether a wrapping expression happens
to be written yet, and on fifteen unaudited repositories six are built without it while
only one of the six has arithmetic in the shape VL003 recognises.

Which manifest counts is not a detail. Cargo ignores `[profile.*]` in every manifest that
is not the workspace root, so a member crate setting the flag changes nothing about how
it is built — and a linter that read the nearest manifest would congratulate you for a
line that has no effect. vaultlint resolves the root the way Cargo does: the nearest
ancestor manifest declaring `[workspace]`, honouring an explicit `package.workspace`
pointer and the `workspace.exclude` list. `workspace.members` globs are not matched,
because a manifest declaring `[workspace]` without listing a package below it makes Cargo
itself refuse to build. Two things do keep the question quiet: a workspace with no on-chain
code in it — no `anchor_lang::prelude`, no `solana_program::entrypoint` — and a root
manifest that sits above the directory you asked to scan, which belongs to a tree you did
not ask about.

**VL004 also fires on `create_program_address`, not only on `bump = <arg>`.** The
table above names the Anchor constraint, but the rule has a second trigger: a direct
`Pubkey::create_program_address` call, which unlike `find_program_address` accepts any
bump you hand it. Which bump you hand it is what decides the finding. A bump read out
of account data — `&[check.nonce]`, `&[self.bump]` — is the stored-canonical-bump
idiom the rule recommends, and is silent. A bare identifier — `&[nonce]`, the caller's
`u8` — is reported, and so is a call whose seeds are assembled elsewhere, where the
bump cannot be read at the call site. Only the last seed is examined, because that is
where the bump goes.

**VL005 does not flag every unverified `invoke`.** It flags a CPI whose `Instruction`
was built in that same function body and whose `program_id` came from an account —
the only shape where a developer has something to verify. A CPI built by an SDK
builder that compiles in its own program id is not reported, because there is nothing
actionable to say about it. The exception, and the reason the rule still catches the
textbook case, is the `spl_token` family: those builders take `token_program_id` as
their *first argument*, so passing an unverified account there is exactly the
Sealevel `arbitrary-cpi` bug. Accounts typed `Program<'info, T>` are silent — Anchor
checks that id itself — and so are CPI helpers taking a `CpiContext`, where the
caller, not the helper, owns the check. Across the same corpus this took VL005 from
324 findings to 21.

**Test, bench and fuzz code is not scanned.** A fuzz harness deserialising raw account
data without an owner check is the harness doing its job, not a vulnerability. Four
things are skipped, and each is decided from a declaration rather than from a name in a
path: files under a crate's own `tests/` or `benches/` directory, crates whose
`Cargo.toml` carries `package.metadata.cargo-fuzz`, files declared as
`#[cfg(test)] mod name;`, and findings inside an inline `#[cfg(test)] mod` block. The
name-based shortcut would be wrong: Anchor's own repository keeps real on-chain programs
under a top-level `tests/` directory. The run header tells you how many files were
skipped.

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
