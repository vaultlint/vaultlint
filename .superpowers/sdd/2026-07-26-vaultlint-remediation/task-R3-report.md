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
