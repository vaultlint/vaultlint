# Unaudited-corpus measurement — results

Protocol: `2026-07-29-unaudited-corpus-protocol.md`, written before any repository was searched for.
Tool: `vaultlint 0.1.1` installed from crates.io with `cargo install vaultlint --version 0.1.1
--locked`, not a local build.

## Corpus

The frame was GitHub code search `declare_id language:Rust path:programs` (7224 hits), 5 pages,
deduplicated to 448 repositories. Metadata screening of the first 140 in returned order rejected 99
(94 stale, 3 already measured, 2 teaching material) and passed 41. Those 41 were cloned in order
and screened against the remaining criteria until 15 were accepted.

Clone-stage rejections, in order encountered:

| Repository | Criterion |
| --- | --- |
| `lombard-finance/sol-svm-contracts` | `audits/` directory |
| `generatus/monorepo` | program id is the Anchor placeholder |
| `solanabr/solana-vault-standard` | `audits/` directory |
| `pinocchioSolana/pinocchioSolana` | no on-chain program in tree |
| `MetalLegBob/drfraudsworth` | `audits/` directory |
| `metaDAOproject/programs` | `audits/` directory |

The accepted 15, in the order they were evaluated. All are under 500 stars and all were pushed
within the trailing 12 months.

| Repository | Files analyzed | Skipped | Anchor | Findings |
| --- | ---: | ---: | --- | --- |
| `Kamino-Finance/scope` | 90 | 0 | 0.28.0 | 1 medium |
| `solanakite/anchor-escrow-2026` | 10 | 2 test | 0.32.1 | — |
| `helium/helium-anchor-gen` | 17 | 0 | — | — |
| `KOSASIH/SolanaCore` | 6 | 1 parse error | 0.28.0 | — |
| `me-foundation/m3` | 9 | 0 | 0.29.0 | — |
| `metaplex-foundation/mpl-account-compression` | 23 | 1 test | 1.0.0 | 1 medium, 4 low |
| `me-foundation/m2` | 26 | 0 | 0.29.0 | 5 medium |
| `Kamino-Finance/limo` | 26 | 0 | — | — |
| `polymerdao/solana-prover-contracts` | 8 | 0 | 0.31.1 | — |
| `Saiko-Seiko/solana-Anchor-Rust--project` | 7 | 0 | 0.31.1 | — |
| `gmsol-labs/gmx-solana` | 524 | 4 test | — | 6 medium |
| `stabbleorg/amm-sdk` | 23 | 0 | — | — |
| `cascade-protocol/sati` | 18 | 17 test | — | — |
| `jup-ag/jupusd-program` | 28 | 24 test | — | 2 medium |
| `MeteoraAg/damm-v1-sdk` | 62 | 1 test | 0.28.0 | — |

877 files analyzed. **19 findings. Zero High.**

| Rule | High | Medium | Low |
| --- | ---: | ---: | ---: |
| VL002 missing owner check | 0 | 2 | 0 |
| VL003 overflow | 0 | 1 | 4 |
| VL004 non-canonical bump | 0 | 9 | 0 |
| VL005 unchecked CPI | 0 | 3 | 0 |

VL001 fired nowhere.

## Classification

Every one of the 19 was read against its source. The protocol asked for all High plus a sample of
Medium; with no High and only 19 findings, all were classified.

| # | Location | Rule | Verdict | Basis |
| --- | --- | --- | --- | --- |
| 1 | `scope` `jup-perp-itf/src/utils.rs:11` | VL004 | helper | The sole caller, `oracles/jupiter_lp.rs:29`, passes `jup_pool.lp_token_bump` — a bump read from account data, which is what the rule's own help text asks for. |
| 2 | `gmx-solana` `crates/sdk/…/instruction_buffer.rs:78` | VL004 | **false** | Off-chain client crate, not an on-chain program. A host-side address computation has no attacker. |
| 3 | `gmx-solana` `programs/timelock/src/states/executor.rs:89` | VL004 | helper | Callers pass `executor.load()?.wallet_bump`, stored on the executor account. |
| 4–7 | `gmx-solana` `callback/action_callback.rs:18`, `competition/trade_callback.rs:22,87,336` | VL004 | true | `bump = authority_bump` where `authority_bump` is an `#[instruction]` argument. Impact is contained: the account is a `Signer` under `seeds::program = CALLER_PROGRAM_ID`, so a non-canonical address cannot be signed by an attacker. The deviation from the recommended pattern is real; the exploit is not. |
| 8–9 | `m2` `m2_ins/buy.rs:38`, `m2_ins/execute_sale_v2.rs:64` | VL004 | true | `escrow_payment_account` is a `mut UncheckedAccount` addressed by `bump = escrow_payment_bump`, an `#[instruction]` argument. Two instructions supplying different bumps address different escrows for the same wallet. Exploitability unproven; the invariant break is real. |
| 10–12 | `m2` `utils/transfer.rs:78,100,117` | VL005 | helper | The helper takes `token_program: &AccountInfo`; all five call sites type it `Program<'info, Token>`, which Anchor validates. |
| 13–14 | `jupusd` `jup-stable/src/oracle.rs:27,93` | VL002 | helper | `parse_oracles` matches on `account_info.owner` against `PYTH_RECEIVER_PROGRAM_ID` / `doves::ID_CONST` and requires the key to match the configured feed, one frame above the deserialisation. |
| 15 | `mpl-account-compression` `Cargo.toml:1` | VL003 | **true** | See below. |
| 16–19 | `mpl-account-compression` `concurrent_merkle_tree.rs:339,555,558,581` | VL003 | true, noise | Bounded counters — tree index, active index, buffer size. Consequences of #15, not independently actionable. |

**true 6 (+4 low) · helper 8 · false 1.**

## The one finding that earns its place

`metaplex-foundation/mpl-account-compression` writes, in
`programs/account-compression/Cargo.toml:27`:

```toml
[profile.release]
overflow-checks = true
```

That manifest is a workspace *member*. Cargo ignores profiles outside the workspace root and says so:

```
warning: profiles for the non root package will be ignored, specify profiles at the workspace root
```

The maintainers asked for overflow checks, believe they have them, and do not. Nothing in the diff,
the tests or the program's own source reveals it — the setting is present, spelled correctly, and
inert. The fix is moving four lines to the root manifest.

This is the shape of finding the tool exists for: cheap to verify, invisible to review, and wrong in
a way that a reader of the file would not notice.

## What this answers

The question the corpus was built for was not how many findings appear. It was **how many of these
repositories get at least one true finding they would want to act on.**

- **1 of 15** unambiguously: `mpl-account-compression`.
- **2 of 15** arguably: `gmx-solana` and `m2` get real deviations from the canonical-bump pattern
  with no demonstrated exploit. A maintainer might fix them; a maintainer might reasonably not.
- **12 of 15** get nothing.

Zero High across 877 files of unaudited, recently-pushed, plausibly-deployed Solana programs. The
twelve-tree corpus was chosen to be hostile to findings and produced few; this corpus was chosen to
be the opposite population and produced fewer still, proportionally, with none at the top severity.

The honest reading is that the silence is the tool's, not the corpus's. Two of the five rules
(VL001, and VL003 outside the manifest check) contributed nothing an author would act on. The rules
that did fire, fired mostly on shapes the rules themselves already admit they cannot resolve —
8 of 19 were the cross-function helper case.

For the strategy question this measurement was built to settle: a product whose expected yield is
one actionable finding per fifteen repositories cannot be sold as a subscription, because the
median subscriber gets nothing in their first year. That is the same conclusion the twelve-tree
corpus pointed at, now from the population that was supposed to contradict it.
