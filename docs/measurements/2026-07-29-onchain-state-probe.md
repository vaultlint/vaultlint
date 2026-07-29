# On-chain state probe — what mainnet says about the same 15 repositories

Exploratory. Same corpus as `2026-07-29-unaudited-corpus-results.md`. The source-level measurement
gave one actionable finding across fifteen trees; this probe asks whether the *deployed* state of the
same programs carries more signal than their source does.

Method: every non-placeholder `declare_id!` in each tree (54 ids), queried against
`api.mainnet-beta.solana.com`. For programs owned by the upgradeable loader, the ProgramData account
gives the upgrade authority and the slot of the last deploy. Each authority was then classified by
ed25519 point decompression: a program-derived address is off the curve, an ordinary keypair is on it.

## Deployment

| State | Ids |
| --- | ---: |
| Deployed, upgradeable loader | 44 |
| Not deployed at that address | 8 |
| Address owned by some other program | 2 |
| **Deployed and immutable (authority revoked)** | **0** |

Twelve of the fifteen repositories have at least one program live on mainnet. Deploy slots span
158 871 428 to 435 764 727 — roughly two and a half years of history.

Not one program in the corpus has had its upgrade authority revoked. Every live program can be
replaced by whoever holds its authority.

## Who holds the authority

21 distinct authorities across the 44 live programs.

| Authority kind | Authorities | Programs |
| --- | ---: | ---: |
| Off-curve — program-controlled (multisig vault or similar) | 16 | 37 |
| On-curve — a single ed25519 keypair | 5 | 7 |

Five of the fifteen repositories have at least one mainnet program whose upgrade authority is a
plain keypair: `Kamino-Finance/scope`, `MeteoraAg/damm-v1-sdk`, `cascade-protocol/sati`,
`metaplex-foundation/mpl-account-compression`, `polymerdao/solana-prover-contracts`.

Two of those authorities hold no account on chain at all — zero lamports, never funded. One of them,
`cmpasUdPXSCcjaEUCEaCnRE5wFJGD8nSKDXvvvfiexN`, controls both live Metaplex compression programs.

**Caveat on the proxy.** Off-curve proves the authority cannot be a bare keypair; it is some
program's PDA, which in practice usually means a multisig vault. On-curve proves only that the
address *could* be a single keypair — it rules out an on-chain multisig, but not a hardware wallet or
an off-chain threshold-signature custody service, which present as ordinary ed25519 keys. Read the
on-curve number as "no on-chain multisig", not as "one person can do this".

## Comparison with the source-level yield

| Signal | Repositories reached (of 15) |
| --- | ---: |
| VaultLint 0.1.1 actionable finding | 1 |
| Build configuration defect (probe C1 + C5) | 6 |
| At least one live program with no on-chain multisig | 5 |
| At least one live program that can still be replaced | 12 |

The on-chain state reaches an order of magnitude more of the corpus than the linter does, and it is
the only one of these signals that changes without anyone touching the repository.

## The combination neither half can state alone

`me-foundation/m2` sets `overflow-checks = false` at its workspace root **and** runs
`M2mx93ekt1fmXSVkTrUL9xVFHkmME8HTUi5Cyc5aF7K` live on mainnet. `me-foundation/m3` does the same.
`metaplex-foundation/mpl-account-compression` believes it has overflow checks, does not, and its two
live programs are upgradeable by an unfunded single key.

No existing tool says this. A block explorer reads the chain and has never seen the manifest. A
linter reads the manifest and does not know the program is live. The interesting claim is the
conjunction: *this defect is in code that is running, at this address, right now.*

Every verified finding in this project so far has had the same shape — **what is written down does
not match what actually happens**. The Cargo profile that Cargo ignores, the misspelled key, the
bump taken from instruction data instead of the canonical one, and now the deployed program whose
provenance nobody can check. That is one invariant, not four rules.
