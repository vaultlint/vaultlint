# Unaudited-corpus measurement — selection protocol

Written **before** any repository was searched for or scanned. The twelve-tree corpus behind
`docs/specs/2026-07-25-vaultlint-oss-cli-design.md` was chosen for maturity: a linter that fires on
audited production code is broken, so the trees were picked to be hostile to findings. That made
the measurement strict and makes it useless for the question "who would these findings help".

This corpus is chosen to be the opposite population: programs that plausibly ship and plausibly
have never been audited.

## Inclusion criteria

A repository enters the corpus if **all** hold:

1. Rust, and contains at least one on-chain Solana program — `anchor_lang::prelude` or
   `solana_program::entrypoint` in tree.
2. Pushed on or after 2025-07-29 (last 12 months).
3. Not archived, not a fork.
4. Not one of the twelve already measured: `coral-xyz/anchor`, `metaplex-program-library`,
   `protocol-v2` (drift), `marginfi-v2`, `mango-v4`, `openbook-v2`, `squads-mpl`,
   `helium-program-library`, `jito`, `liquid-staking`, `program-examples`, `sealevel`,
   `anchor-check`.
5. Carries a `declare_id!` whose program id is **not** the Anchor template placeholder
   (`Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnS` / all-ones). A replaced program id is the
   cheapest available proxy for "this was actually deployed somewhere".

## Exclusion criteria

Excluded if **any** hold:

1. Name, description or topics mark it as teaching material: tutorial, course, bootcamp, workshop,
   example(s), demo, template, boilerplate, starter, learn, playground, "my first".
2. An `audits/` directory, or an audit report linked from the README. This is the corpus of the
   *un*audited; a repo with an audit belongs to the other population.
3. Stars ≥ 500 — a proxy for a protocol large enough to have an in-house security function.

## Sampling rule

The frame is GitHub **code** search, not repository search: repository search for "solana anchor"
returns tooling *about* Solana (fuzzers, scanners, coverage) rather than on-chain programs. The
query is `declare_id language:Rust path:programs` (7224 hits), read in GitHub's returned order over
the first 5 pages, deduplicated to 448 repositories. Candidates are evaluated **in that order** and
the first 15 that pass every criterion form the corpus. No repository is skipped for any reason not
listed above, and no repository is added after its findings are known. Every rejection is recorded
with the criterion that rejected it.

*This section was rewritten on 2026-07-29 after the frame was built but before any repository was
scanned, to state the query actually used. No finding was known at the time of the amendment.*

## What is measured

Per repository: files scanned, files skipped, and findings per rule at their shipped severity, from
`vaultlint 0.1.1` installed from crates.io — the artifact a user would get, not a local build.

Then every High finding, and a sample of Medium, is read against the source by hand and classified:

- **true** — the account really is unproven / the bump really is caller-supplied
- **helper** — the shape VL002 admits it cannot resolve: caller validates, proof is in another
  function
- **false** — the code is correct and the rule is wrong about it

The number that answers the strategy question is not the finding count. It is: **how many of these
repositories get at least one true finding they would want to act on.**
