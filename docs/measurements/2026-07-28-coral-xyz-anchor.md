# Corpus measurement — coral-xyz/anchor `tests/`

The release gate for 0.1.0. Every rule's behaviour changed between the
pre-remediation baseline and this run, so the numbers below are the only
evidence of what those changes did to a third-party tree.

**Re-run this before the next release and diff it against this file.** The
"how to reproduce" section at the bottom is the whole procedure.

## Identity

| | |
|---|---|
| Date | 2026-07-28 |
| Corpus | `https://github.com/coral-xyz/anchor`, subtree `tests/` |
| Corpus commit | `474204eebef7a48373eb4fca441f4c54b8e04348` (2026-07-21, *fix(avm): Skip attestation for older releases (#4835)*) |
| Last corpus commit touching `tests/` | `d2b2c0a8151e8ccbc66c9f861d9951a1debc9142` (2026-07-16) |
| vaultlint commit | `b92315c` (`docs(spec): update canary description to reflect R9 staking.rs rewrite`) |
| vaultlint version | 0.1.0, `--release` build |
| Files analysed | 101 Rust files, 5 test files skipped, 0 unparsable |

**On corpus drift.** The exact date the pre-remediation baseline was taken is
not recorded anywhere, so it cannot be pinned to a SHA. What can be said: the
last upstream commit to touch `tests/` at all landed on 2026-07-16, ten days
before the remediation plan was written. Unless the baseline predates that, the
subtree this run saw is byte-identical to the subtree the baseline saw, and the
−150 delta is attributable to the tool rather than to the corpus. The SHA is
recorded here so the *next* comparison does not have to reason about this.

## Counts

Header and footer of the run, verbatim (the 21 findings between them are
enumerated under Triage):

```
→ analyzing 101 Rust files (5 test files skipped) …
21 issues found · 1 high · 20 medium
```

The process exit code was 1 (observed as `exit=1`): with the default
`--fail-on high`, the single VL002 High breaks a build on this corpus.

| Rule | Baseline (pre-remediation) | This run | Δ |
|---|---|---|---|
| VL001 | 27 | 1 | −26 |
| VL002 | 1 | 1 | 0 |
| VL003 | 55 | 0 | −55 |
| VL004 | 66 | 16 | −50 |
| VL005 | 22 | 3 | −19 |
| **total** | **171** | **21** | **−150** |

Per-rule counts as printed:

```
VL001 1
VL002 1
VL004 16
VL005 3
total 21
```

## Triage

All 21 findings were triaged by hand — no sampling. Each was opened at the
reported file and line and judged against what the rule's own message claims.

Labels: **TP** = the code has the weakness the rule describes. **FP** = the
rule fired on code that does not have it. **TP-pattern** = the construct the
rule names really is present, but the file is a framework test fixture rather
than a deployed program, so "vulnerability" is not a meaningful judgement about
it — counted as a true positive because the rule's claim is factually true of
the line, and flagged separately because a corpus of fixtures does not predict
behaviour on production code.

### VL001 — unproven authority on initialization (1 finding)

| # | Location | Verdict |
|---|---|---|
| 1 | `tests/auction-house/programs/auction-house/src/lib.rs:1098` | **TP** |

`CreateAuctionHouse.authority` is declared `authority: AccountInfo<'info>` with
no `#[account(...)]` attribute at all — no `signer`, no `address`, no
`constraint`, no `has_one` from a settled sibling, and the handler carries no
`#[access_control(...)]`. Its key is baked into the seeds of `auction_house`,
which the same struct declares `init`:

```rust
#[account(
    init,
    seeds=[
        PREFIX.as_bytes(),
        authority.key().as_ref(),
        treasury_mint.key().as_ref(),
    ],
    ...
)]
auction_house: Account<'info, AuctionHouse>,
```

and the handler writes it into the account it just created
(`lib.rs:69-70`):

```rust
auction_house.creator = authority.key();
auction_house.authority = authority.key();
```

Every trigger the rule names is present and every silencer is absent. Nothing
proves the named authority agreed, so anyone can create the one auction house
that exists for a given `(authority, treasury_mint)` pair, choosing
`seller_fee_basis_points`, `requires_sign_off`, `can_change_sale_price` and both
withdrawal destinations on the real authority's behalf.

This is the same shape marginfi-v2 treated as a bug and fixed in `95a4c26`
(`pub authority: UncheckedAccount<'info>` → `pub authority: Signer<'info>`),
which is the case VL001 was calibrated against. It is also the finding the
design spec already names as the single confirmed VL001 true positive across the
whole calibration corpus; this run is an independent re-confirmation of it after
R1–R9 rewrote the rule's internals.

**Impact class: squatting and configuration-poisoning, not theft.** The
legitimate authority can still repair the configuration afterwards —
`update_auction_house` requires `authority: Signer<'info>` — and the attacker
pays the rent. That ceiling is what the severity argument below turns on.

### VL002 — missing owner check (1 finding)

| # | Location | Verdict |
|---|---|---|
| 1 | `tests/auction-house/programs/auction-house/src/utils.rs:301` | **FP** (documented interprocedural limit) |

```rust
pub fn pay_creator_fees<'a>(
    remaining_accounts: &mut Iter<AccountInfo<'a>>,
    metadata_info: &AccountInfo<'a>,
    ...
) -> Result<u64> {
    let metadata = mpl_token_metadata::accounts::Metadata::try_deserialize(
        &mut &**metadata_info.data.borrow(),
    )?;
```

`metadata_info` is a bare `&AccountInfo` helper parameter and the helper body
contains no owner check, so the rule fires. The program has exactly one call
site (`lib.rs:767`) and it validates first (`lib.rs:730`):

```rust
assert_derivation(
    &mpl_token_metadata::ID,
    &metadata.to_account_info(),
    &[
        b"metadata",
        mpl_token_metadata::ID.as_ref(),
        token_account_mint.as_ref(),
    ],
)?;
```

`assert_derivation` is already in VL002's `PDA_DERIVATIONS` list; it simply sits
in the caller, and VL002 reads one function at a time. This is the exact
limitation the README states and deliberately keeps ("helpers taking a bare
`&AccountInfo` whose callers validate are reported … this is the shape Metaplex
has historically been exploited through, so the findings stay"). It is a false
positive against the program, an intended report against the function. See
*Concerns* below — it is also the only High in the run.

### VL003 — overflow-checks (0 findings)

Nothing to triage; the interesting question is whether zero is right.

All 57 workspace-declaring `Cargo.toml` files under `tests/` set
`overflow-checks = true` — every one of them, with no exceptions to print:

```
$ grep -rl "^\[workspace\]" tests --include='Cargo.toml' | while read -r m; do
>   grep -q "overflow-checks = true" "$m" || echo "NO_OVC: $m"; done
(no output above = all set)
      57
```

Verified positively rather than assumed — copy one workspace out, delete the
flag from its manifest, re-scan, and the rule speaks:

```
$ vaultlint scan /tmp/vl003-probe
14 issues found · 0 high · 6 medium · 8 low
```
```
VL003 9
VL004 4
VL005 1
```

(one Medium at the manifest plus eight Low arithmetic sites.)

So the 55 → 0 drop is a genuine true-negative win, not a broken visitor. The
pre-remediation rule reported per call site and ignored the build profile; the
rewritten rule asks the question once, at the manifest Cargo actually reads
`[profile.release]` from, and this corpus already answers it correctly
everywhere. This is the single largest component of the −150 delta.

### VL004 — non-canonical PDA bump (16 findings)

Two signals. Both were checked site by site.

**Signal A — `bump = <bare instruction argument>` on an `Accounts` field (11).**

| # | Location | `bump =` | Verdict |
|---|---|---|---|
| 1 | `tests/misc/programs/misc/src/context.rs:91` | `nonce` | TP-pattern |
| 2 | `tests/misc/programs/misc/src/context.rs:526` | `bump` | TP-pattern |
| 3 | `tests/misc/programs/misc/src/context.rs:530` | `second_bump` | TP-pattern |
| 4 | `tests/misc/programs/misc/src/context.rs:736` | `program_id` | TP-pattern |
| 5 | `tests/misc/programs/misc/src/context.rs:742` | `accounts` | TP-pattern |
| 6 | `tests/misc/programs/misc/src/context.rs:748` | `ix_data` | TP-pattern |
| 7 | `tests/misc/programs/misc/src/context.rs:754` | `remaining_accounts` | TP-pattern |
| 8 | `tests/misc/programs/misc-optional/src/context.rs:89` | `nonce` | TP-pattern |
| 9 | `tests/misc/programs/misc-optional/src/context.rs:519` | `bump` | TP-pattern |
| 10 | `tests/misc/programs/misc-optional/src/context.rs:523` | `second_bump` | TP-pattern |
| 11 | `tests/optional/programs/optional/src/context.rs:23` | `pda_bump` | TP-pattern |

Every one really does carry `seeds = [...]`, no `init`, and a `bump =` whose
right-hand side is a bare identifier listed in that struct's
`#[instruction(...)]`. The message is factually true of each line. All eleven,
however, are Anchor's own macro-expansion fixtures — `TestInstructionConstraint`,
`TestProgramIdConstraint`, and a struct whose four fields exist only to prove
that instruction arguments named `program_id` / `accounts` / `ix_data` /
`remaining_accounts` do not collide with Anchor's generated identifiers. Nobody
deploys them.

**The discrimination is real, and this corpus proves it.** There are 78 Anchor
`bump = <expr>` constraint sites under `tests/`; exactly 11 have a bare
identifier on the right, and those are exactly the 11 the rule fires on:

```
$ grep -rho "bump *= *[A-Za-z_][A-Za-z0-9_]*[,)]" tests --include='*.rs' \
    | sed 's/bump *= *//; s/[,)]//' | sort | uniq -c | sort -rn
   2 second_bump
   2 nonce
   2 bump
   1 remaining_accounts
   1 program_id
   1 pda_bump
   1 ix_data
   1 accounts
```

The 67 it stays silent on are the safe stored-canonical-bump form, and the
corpus contains a particularly clean pair in one file — `cashiers-check/src/lib.rs` is flagged at
`:108` for `create_program_address(..., &[nonce])` and is *silent* at `:128` and
`:145`, where the same program writes `bump = check.nonce`, a field access.

**Signal B — `Pubkey::create_program_address` (5).**

| # | Location | Bump source | Verdict |
|---|---|---|---|
| 12 | `tests/cashiers-check/programs/cashiers-check/src/lib.rs:108` | `nonce` (ix arg) | TP |
| 13 | `tests/lockup/programs/lockup/src/lib.rs:230` | `nonce` (ix arg) | TP |
| 14 | `tests/lockup/programs/registry/src/lib.rs:576` | `nonce` (ix arg) | TP |
| 15 | `tests/lockup/programs/registry/src/lib.rs:632` | `nonce` (ix arg) | TP |
| 16 | `tests/lockup/programs/registry/src/lib.rs:923` | `nonce` (ix arg) | TP |

These are the corpus's only five `create_program_address` calls, and all five
are the textbook bump-seed-canonicalisation shape: a caller-supplied `u8` nonce
fed straight into `create_program_address` with nothing asserting it is the
canonical bump. In each case the derived key is immediately compared against a
passed account, which bounds the impact, but the weakness the rule names — "it
accepts any bump, including non-canonical ones" — is present as written.

VL004 totals: **16/16 accurate against the rule's claim, 0 false positives**;
11 of the 16 in framework fixtures.

### VL005 — unchecked CPI to unknown program (3 findings)

| # | Location | Verdict |
|---|---|---|
| 1 | `tests/auction-house/programs/auction-house/src/utils.rs:205` | **FP** (interprocedural, type erased at helper boundary) |
| 2 | `tests/auction-house/programs/auction-house/src/utils.rs:348` | **FP** (same) |
| 3 | `tests/lockup/programs/lockup/src/lib.rs:479` | **FP** (`#[access_control]` not read) |

1 and 2 are `spl_token::instruction::transfer(token_program.key, …)` inside
`utils.rs` helpers whose signature is `token_program: &AccountInfo<'a>`. VL005's
documented silencer — "accounts typed `Program<'info, T>` are silent" — does
apply to the *callers*: every `token_program` field in `lib.rs` is declared
`token_program: Program<'info, Token>` (9 occurrences). The type is erased when
the account is handed to the helper as an `AccountInfo`, and the rule reads one
function at a time. Same root cause as the VL002 finding, in the same crate.

3 is different and worth its own line. `whitelist_relay_cpi` builds an
`Instruction` in-body with `program_id: *transfer.whitelisted_program…key` and
`invoke_signed`s it — VL005's shape exactly. But the function is annotated:

```rust
#[access_control(is_whitelisted(transfer))]
pub fn whitelist_relay_cpi<'info>(
```

and `is_whitelisted` (`lockup/src/lib.rs:483`) checks the program id against a
stored whitelist. vaultlint contains no reference to
`access_control` anywhere in `src/`, so this validation is invisible to it.

## Verdict on VL001

**Keep VL001 at Medium. No change made.**

Two things must be said plainly before the argument, because they change what
this task was.

1. **VL001 is already Medium in the code.** `src/rules/init_authority.rs:460`
   emits `Severity::Medium`, and has since `4c42272` — the R1 rewrite demoted it
   as part of replacing the rule, with the reasoning in that commit message. The
   README table, `docs/rule-pages.md` and the design spec all say Medium and are
   mutually consistent. R10 therefore validates a decision already taken rather
   than taking a new one, and the honest framing of the result is *the empirical
   measurement supports the severity the tool already ships*.
2. **`n = 1`.** VL001 fires once on this corpus. One true positive out of one
   finding is 100% precision and it is worth almost nothing as a precision
   estimate. Any claim built on it has to be an argument about the *shape*, not
   about the count.

The argument for Medium, which does not depend on the count:

**The impact ceiling of the shape is squatting, not loss of funds.** The
auction-house case is the whole class in miniature: an attacker can occupy the
PDA and choose its initial configuration, but cannot sign as the authority
afterwards, and the real authority can repair it. High severity is the default
`--fail-on` threshold — it stops builds. A class whose worst outcome is "someone
else paid rent to create your account with the wrong fee setting" does not
justify that, and a linter that stops builds for it teaches `--fail-on never`.

**The false-positive direction is intent, not code, and a user cannot resolve it
from the finding.** Permissionless-by-design is textually identical to the bug.
The README says so, the finding text says so ("If the permissionless designation
is intended, suppress the finding"), and a rule whose own remediation advice
includes "or decide this is fine" is by construction not a build-breaker. This
is the deciding argument: even at perfect precision *against the pattern*, VL001
reports a construct that requires protocol context to classify. That is exactly
what Medium is for.

**This corpus is not representative, in the direction that matters.** Anchor's
`tests/` is 57 workspaces of deliberately minimal fixtures plus a handful of
vendored real programs. The one VL001 finding came from a vendored real program
(Metaplex auction-house); every fixture was silent. That is reassuring about
noise — the rule did not fire once across the other 100 analysed files, which
is the failure mode the old VL001 died of — but it means the corpus cannot
establish behaviour on production code either. The calibration corpus (thirteen
codebases, ~2,100 files, four findings) is the better evidence there, and it
points the same way: the rule is very quiet, and its findings need a human.

**What would change this verdict.** If a future measurement finds VL001 firing
on a shape whose impact is direct loss of funds — an authority written into an
account that later signs transfers without a second proof — the severity is
worth revisiting. Nothing here is that.

Because the recommendation is "keep", nothing in `tests/examples.rs`,
`README.md` or the design spec needed to change, and nothing was changed.
`examples/` still summarises `7 issues found · 1 high · 4 medium · 2 low`, with
the one High being VL002.

## Notes on the other four rules

Reported, not fixed — a rule change at this stage needs its own task with its own
review.

**A shared interprocedural blind spot, visible three times in one crate.** VL002
finding 1 and VL005 findings 1–2 are the same defect wearing two rule IDs: a
validated account is handed to a helper as a bare `&AccountInfo`, the helper is
analysed on its own, and the caller's proof is invisible. All three are in
`tests/auction-house/programs/auction-house/`. For VL002 this is documented and
deliberate. For VL005 it is *not* documented — the README claims "accounts typed
`Program<'info, T>` are silent", which is true of the declaration and false at
the helper boundary. Three of this run's 21 findings, and its only High, come
from this one shape.

**`#[access_control(...)]` is invisible to the whole tool.** `grep -rn
access_control src/` returns nothing. Anchor's `#[access_control(f(...))]` runs
`f` before the handler body, and it is where several real programs put exactly
the checks vaultlint looks for — `whitelist_relay_cpi` (VL005 finding 3) and
`CreateCheck::accounts` in cashiers-check both do. This is a systematic silencer
gap affecting at least VL005, and by construction VL001 and VL002 as well. It is
the single highest-value follow-up this measurement found.

**VL004 signal B is unconditional.** `DerivationVisitor` flags every
`create_program_address` call regardless of where its bump comes from. All five
sites here take a caller-supplied nonce, so no false positive materialised — but
the *recommended* remediation (store the canonical bump at init, then
`create_program_address(&[…, &[stored.bump]], id)`) would be flagged too. A rule
that fires on its own fix is a latent false-positive class. Not observed on this
corpus; recorded so the next measurement looks for it.

**No rule fired on a construct it does not name.** Every one of the 21 findings
was checked against its own message text and none misdescribed what was on the
line. The two disagreements above are both scope limits, not misfires.

## Documentation found stale

- `.superpowers/sdd/2026-07-26-vaultlint-remediation/task-R10-brief.md`, Global
  Constraints: "VL001 High (re-evaluated empirically in Task R10)". VL001 has
  been Medium since `4c42272` (R1). The plan text is a record of what was asked
  and was left unedited; this line is the correction.
- `README.md`, VL005 paragraph: "Accounts typed `Program<'info, T>` are silent —
  Anchor checks that id itself". True of a CPI in the handler, not true once the
  account crosses into a helper as `&AccountInfo`, which is where two of this
  run's three VL005 findings are. Worth a clause when VL005 is next touched.

Everything else checked out. The README rule table, `docs/rule-pages.md` and the
design spec all say VL001 Medium and agree with the binary. The README's example
transcript still matches `vaultlint scan ./examples` verbatim, including its
`7 issues found · 1 high · 4 medium · 2 low` footer.

## How to reproduce

```bash
git clone https://github.com/coral-xyz/anchor /tmp/anchor-check
git -C /tmp/anchor-check rev-parse HEAD        # record this
cargo build --release
cd /tmp/anchor-check
/path/to/vaultlint/target/release/vaultlint scan ./tests
/path/to/vaultlint/target/release/vaultlint scan ./tests --format json > scan.json
```

Then group `scan.json`'s `findings` by `rule_id` and open every one at
`file`:`line`. Twenty-one findings is one sitting; if a future run is large
enough that it is not, sample per rule and state the sample size next to any
precision figure.
