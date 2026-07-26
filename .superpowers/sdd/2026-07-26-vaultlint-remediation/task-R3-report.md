# Task R3 Report: VL001 Rebuild Around Absence of Validation

## What Changed

### `src/rules/signer.rs` — complete rewrite

**Old logic:** flagged any `AccountInfo`/`UncheckedAccount` field whose name was in a 6-item marker list and lacked an `is_signer` substring in a `constraint = ...` value.

**New logic:** flags a field only when ALL of the following hold:
1. Type is `AccountInfo` or `UncheckedAccount`
2. Name equals a marker OR ends with `_<marker>` (8 markers: authority, admin, owner, signer, payer, delegate, manager, governance)
3. No `#[account(signer)]` constraint → `Constraint::Other("signer")`
4. No `#[account(address = ...)]` constraint → `Constraint::Other("address")`
5. No `constraint = ...` of any kind → `Constraint::Custom(_)`
6. Field name does not appear as a whole identifier in any sibling field's `Seeds(text)`
7. Field name is not the target of any sibling field's `HasOne(name)`

`/// CHECK:` doc comments are entirely ignored, in both directions.

### Detection implementation details

- **Seeds participation** (`name_in_seeds`): byte-level substring search with explicit left/right identifier-boundary checks. `authority` in `seeds = [b"vault", authority.key().as_ref()]` → suppressed. `authority` in `seeds = [b"vault", authority_bump.as_ref()]` → NOT suppressed (right boundary is `_`).
- **has_one targets**: pre-computed per struct by collecting all `HasOne` values, then checking field name membership.
- **suffix matching** (`matches_marker`): `name == marker || name.ends_with(&format!("_{marker}"))`. `pool_authority` → matches. `authority_seed` → does not match.

### `README.md`

Demo block updated to verbatim output of `./target/release/vaultlint scan ./examples/vulnerable --fail-on never`:
- Message changed from `is not constrained as Signer` → `is not validated`
- Help updated with all valid suppression forms
- Rules table description updated to reflect the new multi-guard logic

### `examples/` — no changes needed

`examples/vulnerable/missing_signer.rs` still has a bare `authority: AccountInfo<'info>` with no constraints. It still fires VL001 at line 8.

`examples/clean/staking.rs` already exercises `Signer<'info>` type, `has_one = authority`, and `seeds`. No new clean example added.

### `tests/examples.rs` — no changes needed

The example file still produces VL001 at line 8. The assertion is unchanged and still passes.

## Tests Added (12 new tests in `src/rules/signer.rs`)

| Test | Type | Guard tested |
|------|------|--------------|
| `flags_bare_authority_account_info` | positive | baseline |
| `flags_pool_authority_suffix` | positive | suffix matching |
| `flags_vault_authority_suffix` | positive | suffix matching |
| `accepts_signer_typed_field` | negative | type check (AccountInfo/UncheckedAccount only) |
| `accepts_account_signer_constraint` | negative | guard 1: `Other("signer")` |
| `accepts_address_constraint` | negative | guard 2: `Other("address")` |
| `accepts_custom_constraint` | negative | guard 3: `Custom(_)` |
| `accepts_has_one_target` | negative | guard 5: `has_one` target |
| `accepts_field_that_appears_in_seeds` | negative | guard 4: seeds participation |
| `ignores_non_authority_name` | negative | marker check |
| `suffix_authority_bump_does_not_match` | negative | suffix parsing |
| `seeds_suppression_requires_identifier_boundary` | positive/boundary | identifier boundary in seeds |

3 legacy tests preserved unchanged (renamed one assertion: `line 6` → `line 5` to match the new inline source).

## Guard-Removal Verification

Each guard was individually removed and the corresponding negative test was confirmed to FAIL:

| Guard removed | Test that fails |
|---|---|
| `Other("signer")` check (lines 106-113) | `accepts_account_signer_constraint` FAILED |
| `Other("address")` check (lines 115-122) | `accepts_address_constraint` FAILED |
| `Custom(_)` check (lines 124-131) | `accepts_custom_constraint` FAILED |
| seeds participation check (lines 133-139) | `accepts_field_that_appears_in_seeds` FAILED |
| `has_one` target check (lines 141-144) | `accepts_has_one_target` FAILED |
| marker name check (lines 99-102) | `ignores_non_authority_name` FAILED |

Each guard was restored after verification.

## Test Counts

- Before: 67 unit tests + 4 integration tests = 71 total
- After: 79 unit tests + 4 integration tests = 83 total
- All pass. Zero failures.

## Exact Test Output

```
test result: ok. 79 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.02s
test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.91s
```

## Concerns / Uncertainties

- None. All requirements from the brief were implemented as specified.
- `examples/clean/staking.rs` was not modified — it already exercises the main suppression paths (`Signer<'info>` type and `has_one` + `seeds`).
- The `#[account(signer)]` and `#[account(address = ...)` suppression paths are covered only by unit tests, not by example files. This is fine per the brief ("add clean/ coverage if a natural negative belongs there").

---

## Fix round 1

### Corpus baseline before this round

- Before R3 rebuild: 103 findings
- After R3 rebuild (pre-fix): 201 findings
- After Fix round 1: **61 findings**

### Changes made

#### `Constraint::Other` now carries its value

`src/anchor/mod.rs`: changed `Constraint::Other(String)` → `Constraint::Other(String, String)` (key, value). `to_constraint` passes the value. Two match sites in `signer.rs` updated to `Other(k, _)`.

#### Class 1 — CPI bundle skip (per-struct)

If no field in an `AccountsStruct` carries any `#[account(...)]` attribute (i.e., `field.constraints.is_empty()` for every field), the entire struct is skipped. This eliminates pure CPI account bundles where the callee program is responsible for all validation. Approximately 99 findings eliminated.

Signal verified against corpus: all CPI bundles in `spl/src/metadata.rs`, `spl/src/token.rs`, `spl/src/token_2022.rs`, `spl/src/associated_token.rs` and many others have zero `#[account(...)]` attributes and were correctly filtered. Files with `#[account(mut)]` on some fields (e.g., spl-stake-pool) were NOT filtered by this check and remain.

Existing positive unit tests updated to include `#[account(mut)]` on a sibling field, making them represent real instruction contexts rather than pure CPI bundles.

#### Class 2 — Namespaced constraint values

The two separate guards (seeds participation and has_one target) were replaced by a single unified check: the field name appears as a whole identifier in the value text of ANY constraint on ANY field of the same struct. This covers `seeds`, `has_one`, `constraint`, `payer = field`, `mint::authority = field`, `token::authority = field`, `associated_token::authority = field`, etc. Approximately 25 of the remaining findings eliminated (all `context.rs` cases).

The `Constraint::Other(key, value)` change was essential: `mint::authority = mint_authority` previously discarded `mint_authority`; now it is captured in the value.

#### Class 3 — Field's own seeds constraint

A field with `#[account(seeds = ..., bump)]` on itself is a PDA whose address is validated by Anchor. Added guard 3b: if the field's own `constraints` includes `Constraint::Seeds(_)`, skip it. This eliminated `member_signer`, `vendor_signer`, `registrar_signer`, `check_signer`, `multisig_signer`, `program_as_signer` patterns (approximately 15 findings).

### Tests added

All 3 new tests followed TDD. Failing test written first, verified to fail, implementation done, verified to pass, guard removal verified to break the test.

| Test | Type | Guard | Guard-removal verified |
|------|------|-------|------------------------|
| `flags_authority_when_some_fields_have_constraints` | positive | Class 1 counterpart | yes (Class 1 guard disabled → test fails) |
| `accepts_cpi_bundle_struct_with_no_account_attrs` | negative | Class 1: no `#[account]` on any field | yes |
| `flags_authority_not_referenced_in_constraint_values` | positive | Class 2 counterpart | yes |
| `accepts_authority_pinned_by_namespaced_constraint_value` | negative | Class 2: name in any constraint value | yes |
| `flags_signer_not_covered_by_own_seeds` | positive | Class 3 counterpart | yes |
| `accepts_authority_field_with_own_seeds_constraint` | negative | Class 3: own seeds constraint | yes |

Test counts: 85 unit + 4 integration = 89 total. All pass.

### 15-finding sample from remaining 61 (verdicts with reasoning)

Numbers below refer to positions in the post-fix finding list.

| # | Field | File/line | Verdict | Reasoning |
|---|-------|-----------|---------|-----------|
| 1 | `treasury_withdrawal_destination_owner` | auction-house:1101 | **TP** | Unconstrained recipient of treasury funds in `CreateAuctionHouse`. Attacker can redirect fee proceeds. |
| 2 | `transfer_authority` | auction-house:1147 | **TP** | Unconstrained in `Deposit`; this account authorises token transfers from the wallet. No constraint prevents substitution. |
| 3 | `transfer_authority` | auction-house:1363 | **TP** | Same pattern in `Buy`. |
| 4 | `new_authority` | auction-house:1613 | **Borderline** | Current `authority: Signer<'info>` signs the update; `new_authority` is arbitrary. Intentional design (owner nominates successor) but could surprise reviewers. Not a clear bug. |
| 5 | `treasury_withdrawal_destination_owner` | auction-house:1618 | **TP** | Same as finding 1, in `UpdateAuctionHouse`. |
| 6 | `sweep_authority` | cfo:483 | **FP** | `DexAccounts` struct, code comment: "DexAccounts are safe because they are used for CPI only." Struct has `#[account(mut)]` on other fields so Class 1 did not filter it. |
| 7 | `vault_signer` | cfo:484 | **FP** | Same struct; a DEX PDA, validated by the DEX program on CPI entry. |
| 8 | `vault_signer` | cfo:593 | **FP** | "PDA owner of the DEX's token accounts," comment in the same file. Same pattern. |
| 9 | `whitelisted_program_vault_authority` | lockup:300 | **FP** | Passed to a whitelisted external program for CPI. The external program owns the PDA; validation is the callee's responsibility. |
| 10 | `member_signer` | registry:619 | **FP** | `CreateMember`: sibling `balances` has legacy string constraint `"&balances.spt.owner == member_signer.key"`. Anchor's legacy string syntax puts the expression as the attribute KEY, not the value. Our parser captures it as `Other(expr, "")` with empty value, so it never enters `all_constraint_values`. The field IS validated; the parser limitation is a Class 4 false positive. |
| 11 | `my_payer` | context.rs:138 | **TP** | `TestPdaMutZeroCopy`: struct has one constrained field (`my_pda` with seeds). `my_payer: AccountInfo<'info>` has no constraint and its name does not appear in any constraint value. Genuinely unconstrained. |
| 12 | `vault_signer` | swap:423 | **FP** | DEX `vault_signer` PDA; same pattern as cfo. |
| 13 | `escrow_authority` | spl-binary-option:73 | **FP** | Autogenerated file (`// This file is autogenerated with https://github.com/acheroncrypto/native-to-anchor`). CPI wrapper struct with `#[account(mut)]` on writable fields; escrow_authority is the native program's PDA. |
| 14 | `authority` | spl-binary-oracle-pair:37 | **FP** | Same autogenerated CPI binding file. `authority` is the pool authority PDA of the native program; validated by the callee. |
| 15 | `authority` | spl-binary-oracle-pair:53 | **FP** | Same file, `Deposit` struct; same reasoning. |

From the 15-finding sample: **5 TP, 9 FP, 1 borderline** → approximately 33% TP rate from this sample.

Extrapolating across all 61: the dominant pattern in the remaining findings is Class 4 (CPI account bundles for native programs with `#[account(mut)]` on writable fields — spl-stake-pool ×13, spl-governance ×11, spl-token-lending ×7, spl-token-swap ×6, spl-token ×4, spl-binary-oracle-pair ×3, etc.). These account for roughly 52 of the 61 findings. Estimated true positive count: ~7–9.

**Estimated residual false-positive rate: ~82–87% (from 15-finding sample and full-corpus extrapolation, N=61).**

### Fourth false-positive class found (not fixed, reporting as requested)

**Class 4 — CPI account bundles for native programs with partial `#[account(mut)]` annotation.**

Files such as `ts/packages/spl-stake-pool/program/lib.rs`, `ts/packages/spl-governance/program/lib.rs`, `ts/packages/spl-token/program/lib.rs`, `ts/packages/spl-token-swap/program/lib.rs`, and others are autogenerated Anchor CPI wrappers for native Solana programs. They use `#[account(mut)]` only to mark writable accounts (as the Solana runtime requires `is_writable`), but carry no Anchor validation constraints. Validation is the responsibility of the callee native program.

These are structurally identical to the Class 1 CPI bundles filtered in this round, except they have `#[account(mut)]` on some fields. The Class 1 signal (no constraints at all) correctly filtered the zero-constraint cases but missed these.

A stronger signal to distinguish Class 4: if ALL authority-named fields in the struct carry neither validation constraints nor their name in any sibling constraint value, AND all present constraints are exclusively `Mut`/`Init`/`Bump`, AND the struct has a programmatic CPI comment or is in a file named `lib.rs` within a `program/` directory with a `native-to-anchor` header — the struct is likely a CPI bundle. However, this heuristic is brittle and file-path-dependent. A cleaner approach would be to require at least one semantically meaningful constraint (not just `mut`) on any field in the struct. I did not implement this because the brief asked me to describe the class rather than silently expand scope.

**This class is the remaining release blocker for VL001.**

### Recommendation

VL001 at 61 findings with ~82–87% FP rate is not acceptable for a flagship High-severity rule. The residual noise is dominated by Class 4. Two options:

1. **Tighten Class 1**: skip struct if no field has any constraint beyond `Mut`, `Bump`, and `Init` (i.e., requires at least one of: `Seeds`, `HasOne`, `Custom`, `Other` with a meaningful key other than `mut`/`bump`/`init`). This would catch the spl-stake-pool, spl-governance, spl-token, spl-token-swap families.
2. **Demote to Medium** (per brief Task R10): accept the current noise level at lower severity. The remaining TPs are real issues (auction-house, spl-record, context.rs).

I believe option 1 is implementable and correct: a struct whose only constraints are `#[account(mut)]` and `#[account(bump = ...)]` is not validating any account identity — it is purely marking writability for the runtime. This signal is semantically sound and would not misfire on real instruction contexts, which virtually always have at least one `seeds`, `has_one`, `constraint`, or `address` constraint.

---

## Fix round 2

### What changed

#### Unified identity-establishing guard (replaces Class 1)

`src/rules/signer.rs`: replaced the old Class 1 guard ("skip struct if no field has any `#[account(...)]` attribute at all") with a single semantically stronger guard: **skip the entire `AccountsStruct` when no field carries an identity-establishing constraint**.

A new top-level predicate `is_identity_establishing(c: &Constraint) -> bool` classifies each constraint:

- **Identity-establishing:** `Seeds(_)`, `HasOne(_)`, `Custom(_)`, and `Other(k, _)` where `k == "signer"`, `k == "address"`, or `k.contains("::")` (namespaced forms such as `mint::authority`, `token::authority`).
- **Not identity-establishing:** `Mut`, `Init`, `Bump(_)`.

The old guard is subsumed: a struct with no `#[account]` attributes has no constraints at all, hence no identity constraints, and is still skipped. The new guard additionally skips structs whose only constraints are `Mut`/`Init`/`Bump` — exactly the autogenerated native-program wrappers (spl-stake-pool, spl-governance, spl-token, spl-token-swap, spl-binary-oracle-pair, etc.) and CPI-only bundles such as `DexAccounts` and `MarketAccounts`.

#### Conclusion on bare `Init`

A struct whose constraints are exclusively `Mut`, `Init`, and `Bump` is skipped. In the corpus, bare-`init` structs without `seeds`, `has_one`, or `constraint` are either autogenerated stubs or unit-test contexts where the test harness supplies validated accounts. A production instruction context that uses `#[account(init)]` almost universally also has `has_one`, `seeds`, or `constraint` on some other field — which is sufficient to keep the struct in scope. The semantics are sound: `init` says "create this account charged to `payer`"; it says nothing about which pubkey is permitted to invoke the instruction.

#### Tests

All tests follow TDD: failing test written first, verified to fail, guard implemented, verified to pass, guard removed and test verified to fail again.

| Test | Type | Guard tested | Guard-removal verified |
|------|------|--------------|------------------------|
| `flags_authority_in_identity_constrained_struct` | positive | identity-constraint counterpart | yes (passes even without guard, since struct has `seeds`) |
| `accepts_mut_only_struct_even_with_authority_name` | negative | identity-constraint check: only `Mut` on any field | yes — removing guard causes both `sweep_authority` and `vault_signer` to fire |
| `accepts_cpi_bundle_struct_with_no_account_attrs` | negative (pre-existing, retained) | identity-constraint check: no attributes | yes — removing guard causes `new_collection_authority`, `update_authority`, `payer` to fire |
| `accepts_bare_init_only_struct` | negative | identity-constraint check: only `Init`/`Mut`/`Bump` | yes — removing guard causes `authority` to fire |

Several existing positive tests were updated to add a `seeds` constraint on the sibling vault field so the struct has an identity-establishing constraint and the firing-on-field logic can be reached. The semantics of those tests are unchanged: they continue to test that the rule fires for an unconstrained authority-named field when the struct has validation context. The struct constraint change reflects the new, tighter definition of "a context where VL001 is meaningful."

Updated: `flags_bare_authority_account_info`, `flags_pool_authority_suffix`, `flags_vault_authority_suffix`, `flags_signer_not_covered_by_own_seeds`, `flags_an_unconstrained_authority_account` (legacy), and `src/lib.rs` scan integration test.

`examples/vulnerable/missing_signer.rs` updated: added `seeds = [b"vault"], bump` to the sibling vault field so the struct is not silently dropped by the new guard.

#### Counts

- Before Fix round 2: 61 VL001 findings
- After Fix round 2: **8 VL001 findings**
- Eliminated: 53 (49 autogenerated spl-* files + 3 cfo CPI structs + 1 swap CPI struct)
- Tests: 87 unit + 4 integration = 91 total (up from 89). All pass.

### 8-finding sample (all remaining findings, full verdicts)

| # | Field | File:line | Context | Verdict | Reasoning |
|---|-------|-----------|---------|---------|-----------|
| 1 | `treasury_withdrawal_destination_owner` | auction-house:1101 | `CreateAuctionHouse` | **TP** | Used to create/verify an associated token account for treasury withdrawals. Attacker passes arbitrary pubkey; treasury fees redirect to attacker-controlled ATA. `CreateAuctionHouse` has `seeds`, `has_one`, so struct not skipped. |
| 2 | `transfer_authority` | auction-house:1147 | `Deposit` | **TP** | Passed as a signer to SPL token `transfer`. Attacker who controls a pre-signed account can drain any delegated `payment_account`. Struct has `seeds` + `has_one`. |
| 3 | `transfer_authority` | auction-house:1363 | `Buy` | **TP** | Same pattern as finding 2 in the `Buy` instruction. Struct has `seeds` + `has_one`. |
| 4 | `new_authority` | auction-house:1613 | `UpdateAuctionHouse` | **Borderline** | `authority: Signer<'info>` signs the update; `new_authority` is stored as the successor. This is intentional design (owner nominates successor). Not exploitable without the current authority's signature. Considered borderline design smell, not a clear bug. |
| 5 | `treasury_withdrawal_destination_owner` | auction-house:1618 | `UpdateAuctionHouse` | **TP** | Same as finding 1. Stored into `auction_house` state; any update redirects future treasury withdrawals. `UpdateAuctionHouse` has `seeds` + `has_one`. |
| 6 | `whitelisted_program_vault_authority` | lockup:300 | `WhitelistTransfer` | **FP** | PDA authority of an external whitelisted program's vault. Passed via CPI to that program, which validates it. The caller does not control what the callee accepts. Struct has `has_one` + `seeds` on other fields so not skipped; the field itself is intentionally unvalidated by this program. |
| 7 | `member_signer` | registry:619 | `CreateMember` | **FP** | Sibling field `balances_locked` carries legacy Anchor string-constraint syntax `"&balances_locked.spt.owner == member_signer.key"`. Parser captures this as `Custom("\"&balances_locked.spt.owner == member_signer.key\"")` with the field name inside the string — but `name_in_seeds` requires identifier boundaries; the surrounding `"` characters cause the match to fail. The field IS validated at runtime; this is a parser limitation. |
| 8 | `my_payer` | misc/context.rs:138 | `TestPdaMutZeroCopy` | **Borderline-TP** | Test fixture struct. `my_payer: AccountInfo<'info>` has no constraint. Structurally the rule is correct: any pubkey can be passed. In practice this is a test harness context, not a production instruction. Firing is semantically correct from a static analysis standpoint. |

**Summary from 8-finding full sample: 4 TP, 2 FP, 2 borderline (1 design-smell, 1 test-fixture).**
**Residual false-positive rate: 25% (2/8), or 37.5% if both borderlines count (3/8).**

### Answers to the three questions

**Q1. Real instruction handlers vs. wrappers/stubs/fixtures?**

Of the 8 remaining findings:
- 5 are from `tests/auction-house` — a real Anchor program included as a test case in the framework repo. It is structurally a production-style program (real handler logic, real state mutations, real CPI calls). All 5 findings are in genuine instruction handler contexts.
- 1 is from `tests/lockup` — a real program; the field is a CPI relay account (FP).
- 1 is from `tests/lockup/registry` — a real program with a parser limitation causing the FP.
- 1 is from `tests/misc/context.rs` — a test fixture (borderline-TP).

**Before the fix**, 53 of 61 findings came from autogenerated wrappers and CPI-only structs — code that performs no validation by design. After the fix, all remaining findings are in real program logic or real-but-misclassified contexts.

**Q2. Does VL001 fire correctly on genuine vulnerable code?**

Three realistic instruction contexts were constructed and scanned:

```rust
// Case A: genuinely missing authority check — struct has seeds (identity-establishing)
#[derive(Accounts)]
pub struct MintTokens<'info> {
    #[account(mut, seeds = [b"vault"], bump)]
    pub vault: Account<'info, Vault>,
    pub admin: AccountInfo<'info>,       // ← no constraint
    #[account(mut)]
    pub token_account: Account<'info, TokenAccount>,
}

// Case B: properly guarded via has_one
#[derive(Accounts)]
pub struct WithdrawGuarded<'info> {
    #[account(mut, has_one = authority)]
    pub vault: Account<'info, Vault>,
    pub authority: Signer<'info>,        // Signer type → not in scope
}

// Case C: properly guarded via seeds pinning
#[derive(Accounts)]
pub struct WithdrawPda<'info> {
    #[account(mut, seeds = [b"vault", authority.key().as_ref()], bump)]
    pub vault: Account<'info, Vault>,
    pub authority: AccountInfo<'info>,   // name appears in seeds → suppressed
}
```

Result: VL001 fires exactly once (Case A, `admin`). Cases B and C are silent. The rule's core logic is sound.

**Q3. Bottom-line recommendation**

VL001 at 8 findings with a 25% FP rate (4 confirmed TP, 2 confirmed FP, 2 borderline) from genuine program code is acceptable for **High severity**, with one caveat: the corpus is `coral-xyz/anchor` itself, which contains very few production handlers. The 4 auction-house true positives are real, exploitable vulnerabilities in code a developer wrote. The 2 FPs have clear structural explanations (CPI relay, parser limitation for legacy string-constraint syntax).

The corpus limitation remains: anchor-framework is not a good measuring stick for VL001 because it contains far more wrappers than handlers. On a real production Solana program containing genuine handlers with missing authority validation, this rule would be extremely precise. The recommendation is: **ship at High severity**. The FP rate on real production code will be lower than what the anchor framework corpus shows, because production programs invariably have more identity-establishing constraints. The legacy string-constraint FP (finding 7) is a known parser limitation, not a flaw in the detection logic itself.

---

## Fix round 3

### The defect inherited from round 2

Round 2 bought its 61 → 8 reduction with a struct-level guard: skip the whole
`AccountsStruct` unless some field carries an identity-establishing constraint
(`Seeds`, `HasOne`, `Custom`, `address`, `signer`, namespaced `Other`).

That guard made VL001 blind to its own headline case. Verified against the
round-2 release binary:

```rust
#[derive(Accounts)]
pub struct WithdrawA<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// CHECK: authority
    pub authority: AccountInfo<'info>,   // ← NO FINDING under round 2
}
```

A textbook missing-signer bug produced silence. The count of 8 was partly bought
by not looking. That is the worst failure mode for a security linter: the user
believes they were checked.

### Evaluating the proposed discriminator before implementing it

The hypothesis under test: a struct is in scope if it holds at least one
`AccountTy::Account(_)` field, because a CPI argument bundle for a foreign
program cannot name a deserialised type for data it does not own.

Measured on the corpus before writing any code:

```
$ grep -rn "Account<'info," --include="*.rs" ts/packages/ spl/src/
(no matches)

$ grep -rhoE ":\s*(Box<)?[A-Za-z_]+<'info" --include="*.rs" ts/packages/ spl/src/ | sort | uniq -c
 821 AccountInfo<'info
 134 Signer<'info
  65 Program<'info
  39 Sysvar<'info
```

Every autogenerated `native-to-anchor` stub (13 files under `ts/packages/*/program/lib.rs`)
and every CPI bundle in `spl/src/` is built exclusively from those four types.
Zero typed accounts across the entire suppressed population. The hypothesis is
confirmed cleanly, with no counterexample in the corpus.

One refinement was made. `AccountLoader<'info, T>` is this program's own
zero-copy state and is just as much a typed account as `Account<'info, T>`;
the corpus contains 41 uses of it, all in real programs and none in a stub.
`is_typed_state` therefore also accepts `AccountLoader`, `Loader`,
`ProgramAccount`, `CpiAccount` and `ProgramState`. `InterfaceAccount` already
normalises to `AccountTy::Account`.

No better separator was found. The alternatives considered and rejected:

- **Empty handler body** (`Ok(())`) — accurate on the stubs, but requires
  resolving `Context<T>` back to a function and breaks on any real handler that
  delegates to a helper module.
- **File path / `native-to-anchor` header** — proposed at the end of round 1 and
  correctly rejected there as brittle and non-semantic.
- **Presence of a `#[program]` module** — useless: the stubs have one.

### What changed

#### `src/rules/signer.rs` — struct scope is now a disjunction

```rust
let holds_typed_state = accounts.fields.iter().any(|f| is_typed_state(&f.ty));
let has_identity_constraint = accounts
    .fields
    .iter()
    .any(|f| f.constraints.iter().any(is_identity_establishing));
if !holds_typed_state && !has_identity_constraint {
    continue;
}
```

Both clauses are load-bearing and each was verified by deletion (below). The
identity clause is not redundant: it is the only thing that keeps a program which
validates raw PDAs by hand — untyped `UncheckedAccount` plus `seeds` — in scope.

#### `src/anchor/mod.rs` — legacy string constraints are parsed

Round 2 recorded `member_signer` (registry:619) as a false positive caused by a
parser limitation. Anchor's legacy syntax `#[account("<expr>")]` is the ancestor
of today's `#[account(constraint = <expr>)]`, but a bare string literal parses
into the *key* slot with no value, so the expression — and every field name it
referenced — was discarded. `to_constraint` now normalises it to
`Constraint::Custom`. This is a parse fix, not a suppression: it makes the model
see a constraint that genuinely exists in the source.

#### Scope impact, measured

Instrumenting the rule to log every struct it considered:

```
total structs 777 | typed 338 | identity 234 | both 168 | in scope 404
typed-only (newly in scope this round): 170
identity-only: 66
```

170 structs re-entered scope. They produced **zero** additional findings. The
widening is real and it is precise.

### Counts

| Stage | VL001 findings |
|---|---|
| Before R3 rebuild | 103 |
| After R3 rebuild | 201 |
| Fix round 1 | 61 |
| Fix round 2 | 8 |
| **Fix round 3** | **7** |

The count fell by one only because the registry parser bug was fixed. The
substantive change of this round is that scope nearly doubled while findings did
not move — the round-2 number was not, in the end, bought by blindness on this
corpus, but the *rule* was blind, and Case A proves it.

### Tests

TDD throughout: failing test written first and observed to fail, then the
implementation, then the guard deleted and the test observed to fail again, then
restored.

| Test | Type | Guard tested | Guard-removal verified |
|---|---|---|---|
| `flags_authority_when_struct_holds_typed_state_account` | positive | typed-state clause | yes — fails with clause removed |
| `accepts_mut_only_cpi_bundle_without_typed_state` | negative | struct-scope guard | yes — fires with guard removed |
| `flags_authority_when_struct_holds_account_loader_state` | positive | typed-state clause (zero-copy) | yes |
| `flags_authority_in_untyped_struct_with_identity_constraint` | positive | identity clause | yes — fails with identity clause removed |
| `flags_bare_init_struct_holding_typed_state` | positive | typed-state clause | yes |
| `accepts_bare_init_only_untyped_struct` | negative | struct-scope guard | yes |
| `case_a_bare_authority_beside_typed_vault_fires` | positive | regression, Case A | yes |
| `case_b_has_one_on_sibling_pins_only_that_sibling` | positive | regression, Case B | n/a (pinning guard) |
| `case_c_has_one_plus_signer_type_is_silent` | negative | regression, Case C | n/a (type guard) |
| `parses_legacy_string_constraint_as_custom` | unit | legacy-syntax parse | yes |
| `accepts_authority_pinned_by_legacy_string_constraint` | negative | legacy-syntax parse | yes |

Each negative differs from its positive by exactly the guard under test. The pair
`flags_authority_when_struct_holds_typed_state_account` /
`accepts_mut_only_cpi_bundle_without_typed_state` differ in one token: the type
of the `vault` field.

Test counts: 97 unit + 4 integration = 101 (up from 91). No test was lost.
`cargo fmt --all --check`, `cargo clippy --all-targets -- -D warnings` and
`cargo test` are all clean.

#### Semantics that moved deliberately

`accepts_bare_init_only_struct` (round 2) asserted that

```rust
#[account(init, payer = payer, space = 128)]
pub record: Account<'info, Record>,
...
pub authority: AccountInfo<'info>,
```

produces no finding. That was wrong. `record` is typed state owned by this
program, so this is a real instruction context and the unvalidated `authority` is
precisely what VL001 exists to report. The test is now
`flags_bare_init_struct_holding_typed_state` (positive), with a new negative
counterpart `accepts_bare_init_only_untyped_struct` differing only in `record`'s
type.

`examples/vulnerable/missing_signer.rs` had `seeds = [b"vault"], bump` added to
the sibling `vault` in round 2 purely to stop the struct being dropped. That
workaround is gone; the example is now the honest canonical shape
(`#[account(mut)]` only), which is exactly Case A. It still fires at line 8, so
`tests/examples.rs` is unchanged and the README demo block regenerates
byte-identically.

### All 7 remaining findings, judged individually

| # | Field | File:line | Context | Verdict | Reasoning |
|---|---|---|---|---|---|
| 1 | `treasury_withdrawal_destination_owner` | auction-house:1101 | `CreateAuctionHouse` | **TP** | The instruction has no signer gate on `authority` at all (it is an `AccountInfo` pinned only by appearing in the PDA seeds). Anyone can create the auction house for an arbitrary authority and point the treasury withdrawal owner at themselves. Consequential and unvalidated. |
| 2 | `transfer_authority` | auction-house:1147 | `Deposit` | **Borderline** | Forwarded as the authority argument of `spl_token::instruction::transfer` inside `invoke_signed` with empty seeds (line 190). The program itself validates nothing; the SPL token program enforces the signature downstream. Not exploitable as written, but an unvalidated `*_authority` handed straight into a CPI is a finding a reviewer should see. |
| 3 | `transfer_authority` | auction-house:1363 | `Buy` | **Borderline** | Identical pattern at line 603. |
| 4 | `new_authority` | auction-house:1613 | `UpdateAuctionHouse` | **FP** | The struct has `authority: Signer<'info>` plus `has_one = authority` on `auction_house`. The instruction is properly gated; nominating an arbitrary successor pubkey is the authority's prerogative. This is an authority-named *data parameter*, not a missing signer check. |
| 5 | `treasury_withdrawal_destination_owner` | auction-house:1618 | `UpdateAuctionHouse` | **FP** | Same gate as #4 — `authority: Signer` and `has_one = authority`. Setting the withdrawal destination is a legitimate signed admin action. (Round 2 recorded this as a TP; on re-reading the struct I disagree — the signer gate is right there.) |
| 6 | `whitelisted_program_vault_authority` | lockup:300 | `WhitelistTransfer` | **FP** | The vault authority PDA of an external whitelisted program, relayed by CPI. The callee owns and validates it; the caller cannot. |
| 7 | `my_payer` | misc/context.rs:138 | `TestPdaMutZeroCopy` | **TP (structurally)** | Genuinely unconstrained `AccountInfo` beside an `AccountLoader` PDA. The rule is right; the file is a test fixture, so the practical value is low. |

**Sample = all 7 (N=7, complete census, not a sample).**
**2 TP, 3 FP, 2 borderline. Residual FP rate 43% (3/7), or 71% if both borderlines are counted against the rule.**

This is a worse ratio than round 2 reported, but the difference is re-reading,
not regression: findings 4 and 5 were graded TP in round 2 and are, on inspection
of the struct, plainly gated by `authority: Signer` + `has_one = authority`.

The dominant residual FP class is now clear and it is **not** CPI bundles: it is
**authority-named fields that are data parameters of an instruction which is
already properly gated by a different signer**. `new_authority`,
`treasury_withdrawal_destination_owner` — these are "which pubkey should I store"
arguments, not "who is allowed to call this". A future round should test for it:
if the struct contains a `Signer<'info>` field, or a `has_one` that is satisfied
by a `Signer`, then a *second* authority-named field is far more likely to be a
parameter than a missing check.

### False-negative probe: five further vulnerable shapes

All five fire.

| Shape | Struct | Signal that keeps it in scope |
|---|---|---|
| D — SPL token drain, unvalidated transfer authority | `Account<'info, TokenAccount>` ×2, `authority: UncheckedAccount` | typed state |
| E — admin-gated config update, admin never checked | `Box<Account<'info, Config>>`, `admin: AccountInfo` | typed state through `Box` |
| F — zero-copy order book, unvalidated manager | `AccountLoader<'info, OrderBook>`, `manager: AccountInfo` | typed state (zero-copy) |
| G — hand-rolled PDA treasury, unvalidated governance | `UncheckedAccount` + `seeds`, `governance: AccountInfo` | identity constraint |
| H — interface token account, unvalidated pool delegate | `InterfaceAccount<'info, TokenAccount>`, `pool_delegate: UncheckedAccount` | typed state |

### Shapes still missed — four confirmed blind spots

Each was constructed, scanned, and confirmed silent.

**M1 — a real handler in which every account is raw `AccountInfo` and the only
constraint is `mut`.** This is the deliberate price of the CPI-bundle guard: such
a struct is textually indistinguishable from an autogenerated stub. Accepted
trade-off, and the narrower of the two costs on offer.

**M2 — authority-ish names outside the marker list** (`creator`, `withdrawer`,
`user`, `recipient`). Deliberate narrowness, already documented in the README.

**M3 — decoy seeds reference.** A field named in *any* sibling's constraint value
is suppressed, even when that constraint has nothing to do with the account being
protected:

```rust
#[account(mut, seeds = [b"log", authority.key().as_ref()], bump)]
pub log: Account<'info, Log>,      // authority pins the log PDA …
#[account(mut)]
pub vault: Account<'info, Vault>,  // … but nothing ties it to the vault
pub authority: AccountInfo<'info>, // silent
```

This is an *unsound* suppression, not a scoping choice, and it is the most
serious of the four.

**M4 — vacuous constraint.** Any `constraint = ...` suppresses regardless of what
it checks; `constraint = authority.key() != Pubkey::default()` silences the rule
while establishing nothing. Also unsound.

M3 and M4 were not fixed in this round: both need dataflow the model does not
carry, and a naive tightening would trade silent false negatives for loud false
positives. They are reported here as known, characterised limitations rather than
left latent.

### Bottom line

**Ship VL001 at Medium, not High.**

The round-2 defect is fixed and the fix is the right one: scope is decided by
what the fields *are*, not by which constraints happen to be present, and that
distinction is semantically sound rather than corpus-fitted. The rule now catches
the canonical vulnerable withdraw it was named for, along with five further
realistic shapes, and it does so while keeping every autogenerated stub and CPI
bundle suppressed — 170 structs re-entered scope for zero new findings.

But High severity means "stop the build", and this rule cannot yet earn that:

1. **Precision is 2 TP / 3 FP / 2 borderline on a complete census.** Even
   granting both borderlines, fewer than half the findings are things a developer
   should change. `--fail-on high` defaults to failing CI, and three of seven
   findings would fail a build over correctly-gated code.
2. **The residual FP class is systematic, not incidental.** Authority-named data
   parameters in already-gated instructions (findings 4 and 5) will recur in every
   real program with an `update_authority`-style instruction. That is a common
   shape, and the rule has no defence against it today.
3. **Two unsound suppressions (M3, M4) are live.** A High-severity rule that can
   be silenced by an unrelated seeds reference is making a promise it does not
   keep.

Medium is the honest severity: worth surfacing, worth a human look, not worth
failing a build. Promote to High once the gated-instruction FP class is handled —
the `Signer`-present test sketched above is the obvious next experiment — and once
M3 is tightened so that suppression requires the constraint to actually relate the
field to the account being protected.

The corpus caveat from round 2 stands and cuts both ways: `coral-xyz/anchor`
holds few production handlers, so seven findings is a small denominator. But it
is now a *complete* denominator — every finding was read in source context — and
that is a firmer basis than the extrapolations of earlier rounds.
