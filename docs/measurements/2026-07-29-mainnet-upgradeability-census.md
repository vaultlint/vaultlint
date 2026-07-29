# Mainnet upgradeability census — who can replace a program, and how often it happens

Exploratory, and wider than anything measured before in this repository. The earlier probe
(`2026-07-29-onchain-state-probe.md`) asked what mainnet says about the fifteen repositories in the
unaudited corpus. This one drops the corpus entirely and asks the same two questions of the network:

1. **Who can replace the code** running at a given address — a single keypair, a program, or nobody.
2. **How often the code is actually replaced.**

Neither question is a rule and neither produces a finding. The motivation is strategic: the
source-level measurement gave one actionable finding across fifteen trees, and the question is
whether the deployed state carries more signal than the source does.

Snapshot taken 2026-07-29 against `api.mainnet-beta.solana.com` at tip slot 435 941 295. Every
number below is a snapshot and will drift; the script is written so the census can be re-run
unchanged in a later quarter.

Script: `scripts/mainnet-census.py`. Dependency-free, six subcommands, each writing JSON the next
one reads.

## Method

**Population.** `getProgramAccounts` on `BPFLoaderUpgradeab1e11111111111111111111111` filtered to
`dataSize = 36`. A Program account is exactly a 4-byte enum plus the ProgramData address, so the
size filter is an exact predicate for "is an upgradeable program" and keeps the response small
enough for a public endpoint to serve. **65 119 accounts.**

**Authority and last deploy.** The ProgramData address is a PDA of the program id under the loader,
so it is derived locally rather than looked up — no extra round trip. Its first 45 bytes are a
`u32` discriminant, a `u64` slot of the last deploy, and an `Option<Pubkey>` authority; read with
`getMultipleAccounts` and a `dataSlice`, 100 at a time.

**Classifying an authority.** By ed25519 point decompression. A program-derived address is by
construction *not* a curve point — that is what makes it unsignable by a keypair. So an on-curve
authority is one a private key can sign for, and an off-curve authority is one only a program can
authorise. `None` means the authority was revoked and the program is immutable.

**Slot-to-time.** Measured, not assumed: `getBlockTime` at the tip and 50 000 000 slots earlier gives
**0.3976 s/slot**. Every age below divides by that rather than by a nominal 400 ms.

**Redeploy history.** Successful transactions touching the ProgramData account in the trailing 365
days, paged through `getSignaturesForAddress`.

## Two populations

Sampling by existence and sampling by use give different networks, and the difference is the most
important thing in this document.

**All programs.** A random 2000 of the 65 119, seed 20260729. **Only 610 resolved** — the other
1390 have no ProgramData account at all, i.e. roughly **70% of deployed programs are closed or
abandoned.** A census weighting these equally describes a graveyard.

**Invoked programs.** Every program appearing in a top-level or inner instruction across 25 blocks
sampled at 40-slot intervals: **348 distinct programs, 132 563 invocations.** 340 resolved; the 8
that did not are native programs with no ProgramData — ComputeBudget, Vote, System, Associated
Token, Memo (both), Ed25519 and Secp256k1 — which is a check on the method rather than a gap.

A validation worth recording: SPL Token (`Tokenkeg…`) *is* under the upgradeable loader and *does*
resolve, with its authority revoked. It is counted immutable, correctly.

## Who can replace the code

| Population | n | single keypair | program-controlled | immutable |
| --- | ---: | ---: | ---: | ---: |
| Top 25 by invocations | 25 | 13 (52%) | 11 (44%) | 1 |
| Top 50 by invocations | 50 | 28 (56%) | 21 (42%) | 1 |
| **Top 100 by invocations** | 100 | **49 (49%)** | 48 (48%) | 3 |
| All invoked | 340 | 215 (63%) | 114 (33%) | 11 |
| Random sample of the 65 119 | 610 | 538 (88%) | 56 (9%) | 16 |

Immutability is vanishingly rare everywhere: **3% at every cut.** Practically nothing on Solana has
had its upgrade authority revoked, which matches the earlier corpus probe finding zero revoked
authorities in 44 live programs.

The gradient is the result. Abandoned programs are overwhelmingly single-key (88%); the busiest
hundred are split roughly half and half. Hygiene improves sharply with how much a program is used,
and still stops at a coin flip.

## How often the code changes

Ages are days since the last deploy, at the calibrated 0.3976 s/slot.

| Population | median | ≤30 days | ≤90 days |
| --- | ---: | ---: | ---: |
| Top 25 by invocations | 13 d | 19 (76%) | 24 (96%) |
| Top 50 by invocations | 12 d | 35 (70%) | 46 (92%) |
| **Top 100 by invocations** | **13 d** | 60 (60%) | 81 (81%) |
| All invoked | 25 d | 178 (52%) | 254 (74%) |
| Random sample | 353 d | 62 (10%) | 144 (23%) |

Independently, the trailing-year write history of the 60 busiest programs:

| ProgramData writes in 365 d | Programs |
| --- | ---: |
| 0 (untouched) | 3 (5%) |
| 1–3 | 2 (3%) |
| 4–11 | 15 (25%) |
| **12 or more** | **40 (66%)** |

Median 20, mean 56.6, max 468.

Two independent methods — a one-shot age snapshot and a year of transaction history — agree in order
of magnitude: a busy Solana program is replaced roughly every two to three weeks. The code running
the network is not a fixed artifact.

## What this supports

- **A statement about integration risk.** If a program integrates eight external programs, on these
  rates roughly five of them are replaced within a month. "The program you reviewed is not the
  program executing now" is mechanically true, not rhetorical.
- **A statement about custody.** Half of the hundred busiest programs on Solana are not behind an
  on-chain multisig — with the sharp limitation below.
- **The claim VaultLint already makes.** A defect found in source, in a crate compiled into a program
  that is live and replaceable, is a conjunction neither a block explorer nor a linter states alone.

## What this does not support

These are the limits that must survive into anything published.

- **On-curve does not mean one person.** It means "not an on-chain multisig". A key held in MPC or
  threshold custody (Fireblocks, Turnkey and similar) requires several parties to sign and still
  presents as an ordinary keypair. The honest phrasing is *not protected by an on-chain multisig*,
  never *one person can replace this*.
- **Off-curve does not mean multisig.** It means program-controlled. Squads is the common case, but
  the check does not identify which program, and a PDA of a badly-governed program is not safer than
  a well-kept key.
- **25 blocks is about ten seconds of mainnet.** The invoked population is therefore weighted toward
  high-frequency traffic — DEXs, oracles, trading bots — and misses a program used a few times a day.
  The top-100 cut is robust to this; the "all invoked" row is not, and its 63% should not be quoted
  as a network-wide rate.
- **A ProgramData write is an upper bound on redeploys.** `set-upgrade-authority` and
  `extend-program` also write there. The max of 468 is implausible as 468 releases and probably
  reflects chunked writes. The median of 20 is corroborated by the independent age snapshot; the
  mean is not trustworthy.
- **The 25/50/100 cuts were chosen after seeing the data**, unlike the pre-registered protocol used
  for the unaudited corpus. They are descriptive, not a test.
- **One point in time**, one endpoint, no cross-check against a second RPC provider.

## Reproducing

```
cd docs/measurements/scripts
./mainnet-census.py population
./mainnet-census.py active
./mainnet-census.py headers active
./mainnet-census.py headers all 2000
./mainnet-census.py report
./mainnet-census.py churn 60
```

`report` and `headers` were both re-run against a fresh output directory and reproduced this
document's numbers bit for bit.

Re-running in a later quarter produces a comparable series; the seed, block count, stride and
calibration span are all flags with the values used here as defaults.
