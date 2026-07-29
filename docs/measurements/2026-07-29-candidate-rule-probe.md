# Candidate-rule probe — declarative checks against the unaudited corpus

Exploratory, not pre-registered. The corpus is the same 15 repositories as
`2026-07-29-unaudited-corpus-results.md`. The purpose was to get a hit rate for five candidate
checks **before** implementing any of them, and to kill the ones that do not earn a rule.

Motivation: in the 19 classified findings, every actionable one came from a declarative input
(a manifest, or an attribute inside `#[derive(Accounts)]`) and none came from reasoning about
Rust dataflow. All five candidates below are therefore declarative.

## Result

| Candidate | Repos flagged | Verified actionable | Verdict |
| --- | ---: | ---: | --- |
| C1 `[profile.*]` in a non-root workspace manifest | 1 / 15 | **1 / 15** | keep |
| C2 `declare_id!` vs `Anchor.toml` program id | 3 / 15 | 0 / 15 | reject |
| C3 dependency version skew across members | 2 / 15 | 0 / 15 | reject |
| C4 `init_if_needed` without a reinit guard | 6 / 15 | 0 / 15 | reject |
| C5 `overflow-checks` not in effect at the workspace root | 6 / 15 | **6 / 15** | keep — see below |

## Why the three were rejected

**C2 — `Anchor.toml` mismatch.** Three repositories disagree between source and manifest, but every
disagreement is on the `devnet` or `localnet` cluster, where a separate address is the normal
workflow rather than a defect. Only 2 of the 15 declare a `mainnet` cluster at all
(`cascade-protocol/sati`, `polymerdao/solana-prover-contracts`), and neither mismatches. The check
is sound in principle and has almost no surface to act on in practice.

**C3 — version skew.** Comparing requirement strings is meaningless: `Kamino-Finance/scope` mixes
`>=0.28.0`, `>= 0.28.0` and `0.28.0`, which resolve to one version. Comparing *resolved* versions
from `Cargo.lock` instead, duplication is ubiquitous and benign — `spl-token` resolves to two
majors in 5 of 15 trees through ordinary transitive dependencies. The one real Anchor split,
`0.31.1` alongside `0.32.1` in `cascade-protocol/sati`, comes from `light-sdk` pulling its own
Anchor; the workspace itself pins one version. Nothing to report.

**C4 — `init_if_needed`.** 38 occurrences across 6 repositories; narrowing to non-token account
types leaves 9 across 2. Truth still requires reading the handler and the PDA seeds. Spot-checking
the highest-stakes instance — `gmx-solana` `PreparePosition`, `init_if_needed` on a trading
`Position` — the seeds include `owner.key()` and `owner` is the signing payer, so re-initialisation
can only touch the caller's own position. This is the same cross-function shape that made 8 of the
19 measured findings unresolvable. Volume without decidable truth is what the tool already has too
much of.

## The two that survived, and why C5 matters most

**C1** reproduces the single valuable finding of the whole measurement:
`metaplex-foundation/mpl-account-compression` writes `[profile.release] overflow-checks = true` in a
workspace *member* manifest, where Cargo ignores it. Cargo itself supplies the ground truth, so the
check has no judgement in it at all.

**C5** is the finding that changes the picture. Six of the fifteen repositories build without
overflow checks:

| Repository | State |
| --- | --- |
| `MeteoraAg/damm-v1-sdk` | no `[profile.release]` at root |
| `helium/helium-anchor-gen` | no `[profile.release]` at root |
| `stabbleorg/amm-sdk` | no `[profile.release]` at root |
| `metaplex-foundation/mpl-account-compression` | set to `true`, but in a member manifest |
| `me-foundation/m2` | **explicitly `overflow-checks = false`** |
| `me-foundation/m3` | **explicitly `overflow-checks = false`** |

**vaultlint 0.1.1 reports one of these six.** `src/lib.rs:105-114` only emits the manifest-level
VL003 finding when some file in the same workspace already produced a per-file VL003 arithmetic
finding. The gate is backwards relative to what the measurement showed: the manifest finding was
true and actionable, the per-file arithmetic findings were bounded counters and noise. A repository
with no unchecked arithmetic that VaultLint recognises is exactly a repository whose missing
overflow guard goes unreported.

## An adjacent discovery

`me-foundation/m2` and `m3` both carry, at the workspace root:

```toml
[profile.release]
codegen-unts = 1
```

`codegen-units` is misspelled. Cargo emits `warning: unused manifest key` and builds anyway —
verified against a scratch crate.

That makes three of the fifteen repositories where a build setting is written down, reads as
correct, and has no effect: mpl's ignored member profile, and m2/m3's misspelled key. The failure
mode is not "the developer forgot". It is **the developer wrote the intent and the toolchain
discarded it silently** — no error, no test failure, nothing a reviewer would catch.

## Bearing on the product

Configuration checks hit **6 of 15** repositories with truth that costs nothing to establish. All
four semantic rules together hit **1 of 15**. That is the yield argument, and it is not close.

The counter-argument is that these checks are cheap to replicate — the whole C1/C5 family is under a
hundred lines. They raise the tool's usefulness sharply and are not, by themselves, something a team
would pay a subscription for.
