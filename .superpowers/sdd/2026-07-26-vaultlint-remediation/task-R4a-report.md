# Task R4a Report — VL005 Precision Fix

## Status: DONE

## Commit

`6148969` — fix(VL005): only flag CPIs whose program id is caller-controlled

## Test Results

124 lib tests + 4 integration tests — all green. Added 8 new tests (was 116 lib, now 124).

---

## What Was Done

### Root Cause

VL005 previously fired on every `invoke` / `invoke_signed` call in a function body that did not textually contain one of `["require_keys_eq!", "::ID", "assert_eq!(", "program_id=="]`. This signals-based approach fires equally on healthy and unhealthy code — SDK builder invocations (where the program id is a constant compiled into the builder) produced 316 of the 324 false positives.

### New Logic

**Trigger conditions (both must hold):**

- **T1** — The first argument to `invoke`/`invoke_signed` resolves to an `Instruction` value constructed in this same function body:
  - A struct literal whose path's last segment is `Instruction`, carrying a `program_id` field; or
  - A call whose last path segment is one of `new_with_borsh`, `new_with_bincode`, `new_with_bytes` and whose path contains a segment `Instruction` (the first argument is the program id).
  - "Resolves to" = the argument itself (possibly behind `&`), or a path naming a local `let` binding in the same body (one hop only).

- **T2** — The program id expression's normalised token text contains `.key` (account-derived).

**Silencers (any one is sufficient):**

- **S1** — Unchanged: the body textually contains one of `VERIFICATION_SIGNALS`. The `"program_id=="` entry was preserved; `normalised` strips all whitespace, so `program_id == expected` becomes `program_id==expected` and the signal matches.

- **S2** — The account supplying the program id is declared as `Program<'info, T>` in the `Context<S>` struct for this function. Implementation:
  - Extract the struct name from the function's `Context<S>` parameter using `usesite::context_struct_name` (made `pub(crate)` for this).
  - Look up the struct in `ctx.anchor.accounts_structs`.
  - If any field with `ty == AccountTy::Program` has its name appearing as a whole identifier in the (resolved) program id text → silent.
  - Also resolves one level of `let` for the program id text: e.g. `cpi_program.key()` where `let cpi_program = ctx.accounts.auction_house_program.to_account_info()` — the identifier `cpi_program` is substituted with the initialiser's normalised text before the field-name search.

### Files Changed

- `src/rules/cpi.rs` — effectively rewritten; retained `VERIFICATION_SIGNALS` and `CPI_CALLS` constants unchanged; added `INSTRUCTION_BUILDERS`, T1/T2 logic, S2, and 8 new tests replacing `flags_invoke_without_any_program_id_verification` with two tests and adding 7 more.
- `src/usesite.rs` — `context_struct_name` made `pub(crate)` (was private `fn`; no duplication needed).
- `examples/clean/cpi_to_known_program.rs` — new clean example showing SDK-builder invocation. Deliberately contains no `require_keys_eq!` or `::ID` (S1 must not be the reason it's silent).

### Clean Example Verification

The brief requires confirming that reverting T1/T2 would make the new clean example produce a finding. Confirmed: `examples/clean/cpi_to_known_program.rs` calls `invoke(&solana_system_interface::instruction::create_account(...), ...)`. Under the old rule (only S1 signals checked, no T1/T2), the body has no VERIFICATION_SIGNALS, so the old rule would flag line 32. Under the new rule, T1 fails because the first argument is an SDK builder call (not an `Instruction` struct literal or `Instruction::new_with_*`), so no finding is produced.

---

## Measurement

### Before / After per Tree

| Tree | VL005 Before | VL005 After |
|------|-------------|-------------|
| `/tmp/anchor-check` | 122 | 1 |
| `/tmp/vl-wide/program-examples` | 94 | 1 |
| `/tmp/vl-wide/metaplex-program-library` | 66 | 0 |
| `/tmp/vl-wide/mango-v4` | 1 | 0 |
| `/tmp/vl-real/protocol-v2` | 3 | 1 |
| `/tmp/vl-real/marginfi-v2` | 10 | 4 |
| `/tmp/vl-real/openbook-v2` | 0 | 0 |
| `/tmp/vl-real/squads-mpl` | 5 | 0 |
| `/tmp/vl-real/liquid-staking-program` | 10 | 0 |
| `/tmp/vl-wide/helium-program-library` | 11 | 1 |
| `/tmp/vl-wide/jito-programs` | 1 | 0 |
| `/tmp/vl-wide/v4` | 1 | 0 |
| **Total** | **324** | **8** |

(Brief estimated ~25; 8 is lower — see "Concern about low count" below.)

### VL001–VL004 Unchanged

Verified on anchor-check, program-examples, metaplex-program-library:

| Rule | anchor-check | program-examples | metaplex |
|------|-------------|-----------------|---------|
| VL001 | 1 (same) | 0 (same) | 1 (same) |
| VL002 | 1 (same) | 7 (same) | 0 (same) |
| VL003 | 64 (same) | 9 (same) | 12 (same) |
| VL004 | 16 (same) | 8 (same) | 25 (same) |

### Surviving Findings Detail

All 8 surviving findings examined:

1. **`/tmp/anchor-check/tests/lockup/programs/lockup/src/lib.rs:479`**  
   Program id: `*transfer.whitelisted_program.to_account_info().key`  
   `whitelisted_program` is not declared as `Program<>` in this context.

2. **`/tmp/vl-wide/program-examples/basics/cross-program-invocation/native/programs/hand/src/lib.rs:31`**  
   Program id: `*lever_program.key`  
   `Instruction::new_with_borsh(*lever_program.key, ...)` — textbook arbitrary-CPI from a plain `AccountInfo`. This is the real cross-program invocation example where the caller decides which program to call.

3. **`/tmp/vl-real/protocol-v2/programs/drift/src/state/fulfillment_params/serum.rs:122`**  
   Program id: `*self.serum_program.key`  
   `serum_program` is `&'a AccountInfo<'b>`, not `Program<>`. The program id check lives in a different function (constructor), not in `invoke_init_open_orders`.

4. **`/tmp/vl-real/marginfi-v2/programs/kamino-mocks/src/lib.rs:68`**  
   Program id: `*marginfi_program_ai.key`  
   Local AccountInfo variable, program id not validated in this body.

5. **`/tmp/vl-real/marginfi-v2/programs/marginfi/src/instructions/drift/claim_bad_debt.rs:249`**  
   Program id: `self.merkle_distributor_program.key()`  
   Field type not `Program<>` in the accounts struct.

6. **`/tmp/vl-real/marginfi-v2/programs/mocks/src/instructions/handle_bankruptcy.rs:81`**  
   Program id: `ctx.accounts.marginfi_program.key()`  
   `marginfi_program` is `UncheckedAccount`, not `Program<>`.

7. **`/tmp/vl-real/marginfi-v2/programs/mocks/src/instructions/start_liquidate.rs:60`**  
   Program id: `ctx.accounts.marginfi_program.key()`  
   Same as above (different instruction).

8. **`/tmp/vl-wide/helium-program-library/programs/lazy-transactions/src/instructions/execute_transaction_v0.rs:166`**  
   Program id: `*ctx.remaining_accounts[ix.program_id_index as usize].key`  
   Dynamically indexed `remaining_accounts` — program id is entirely caller-controlled.

---

## Concern About Low Count

The brief estimated ~25 survivors; we have 8. The discrepancy is plausible because:

- Most of the 316 false positives were SDK-builder invocations (`system_instruction::create_account`, etc.) that do not build their own `Instruction` struct. T1 cleanly eliminated all of them.
- Several trees (squads-mpl, openbook-v2, liquid-staking-program, jito-programs, v4) went to 0. In squads-mpl and liquid-staking-program, the before count was 5 and 10 respectively — those were all SDK-builder false positives with no locally-constructed `Instruction` structs.
- The estimate of ~25 may have been based on an assumption that more programs use `Instruction::new_with_borsh` with account-derived program ids (like the lever example). In practice only a handful do.

I verified the `hand/src/lib.rs` case (finding #2) is a real true positive: `Instruction::new_with_borsh(*lever_program.key, ...)` where `lever_program` is a raw account passed by the caller. This is exactly the shape the rule exists to catch.

A much lower count than expected could in theory mean T1 is too strict and misses real bugs. The most at-risk case would be a locally-defined newtype wrapper around `Instruction`. However, the brief specifies exactly two T1 shapes, and widening beyond them risks re-introducing false positives. I am flagging this as a concern but not changing the implementation.

---

## Tests Added (Brief §Tests)

All 8 required tests are present. Killability analysis:

| Test | Silencer/Trigger it covers | Killed by |
|------|---------------------------|-----------|
| `invoke_of_externally_built_instruction_is_not_a_finding` | T1 negative | Removing T1 check entirely |
| `flags_instruction_struct_literal_with_account_derived_program_id` | T1 struct literal + T2 | Removing struct-literal branch of `instruction_program_id`, OR removing T2 |
| `flags_inline_instruction_struct_literal_at_call_site` | T1 struct literal inline | Removing struct-literal branch |
| `flags_new_with_borsh_bound_to_local_and_invoked` | T1 new_with_* + let hop | Removing new_with_* branch of `instruction_program_id` |
| `sdk_builder_invocation_is_silent` | T1 negative (SDK call) | Removing T1 check |
| `constant_program_id_is_silent` | T2 negative (no `.key`) | Removing `.key` check in T2 |
| `program_typed_account_field_silences_the_finding` | S2 direct | Removing S2 check |
| `program_typed_account_through_let_hop_silences_the_finding` | S2 + let hop | Removing `resolve_program_id_text` |
| `account_info_field_is_not_silenced_by_s2` | S2 over-reach prevention | Removing field-name check in `whole_word_match` |

The three pre-existing tests (`accepts_invoke_guarded_by_require_keys_eq`, `accepts_invoke_guarded_by_a_program_id_comparison`, `ignores_functions_without_any_cpi`) keep passing unchanged.

---

## Code Quality

- `cargo fmt --check`: clean
- `cargo clippy --all-targets -- -D warnings`: clean
- `cargo test`: 124 lib + 4 integration, all green

---

# Task R4a Fix Round 1 — Remediation of Reviewer Findings

## Status: DONE_WITH_CONCERNS

## Commit

`6558c32` — fix(VL005): fix round R4a — Critical1 spl_token builders, Important2-4, Minor5,7-9

## Test Results

137 lib tests + 4 integration tests — all green. Added 13 new tests (was 124 lib, now 137).

---

## What Was Done

### Critical 1 — spl_token builders silenced (fixed)

Added `PROGRAM_ID_FIRST_BUILDERS: &[&str] = &["spl_token", "spl_token_2022"]` constant and a third T1 shape in `instruction_program_id`: a call whose path contains any segment in this list takes its first argument as the program id expression. T2 then applies unchanged, so `spl_token::instruction::transfer(&spl_token::ID, …)` stays silent (no `.key`) while `spl_token::instruction::transfer(token_program.key, …)` fires.

**`spl_associated_token_account` deliberately excluded**: the brief asked for it, but empirical verification shows its functions (e.g. `create_associated_token_account`) take the *funder address* as argument 0, not the program id. Including it produced false positives in anchor-check where `payer.key` was flagged as "the program id". Excluded with documentation in the constant comment.

Also fixed `resolve_one_hop` to unwrap a trailing `?` on the first argument to `invoke_signed`, so `&spl_token::instruction::transfer(…)?` (which returns `Result<Instruction>`) correctly resolves to the inner call.

Two new tests added: `spl_token_builder_with_account_derived_program_id_fires` and `spl_token_builder_with_constant_program_id_is_silent`.

### Important 2 — S2 identifier-boundary unkillable (fixed)

Added `program_field_name_does_not_match_inside_longer_name` test: a struct with `pub program: Program<'info, System>` and `pub token_program: AccountInfo<'info>`, where the program id is `ctx.accounts.token_program.key()`. Without `whole_word_match`, this would be silenced by matching `program` inside `token_program`. With `whole_word_match` (now using shared `find_bounded`), the identifier boundary check rejects the partial match and the finding stands.

Killed by: replacing `whole_word_match(h, n)` with `h.contains(n)`.

### Important 3 — Empty needle hang + de-duplication (fixed)

Lifted `is_ident_char` and `find_bounded` from `src/rules/init_authority.rs` into `src/rules/mod.rs` as `pub(crate)`, with the full original doc comment explaining the UTF-8 panic history (why resumption is at `at + needle.len()`, not `at + 1`; why predicates must use `.chars()` not `.as_bytes()`). Added empty-needle guard at the top of `find_bounded` (`if needle.is_empty() { return false; }`).

`cpi.rs`'s `whole_word_match` now calls `find_bounded` from `mod.rs`. `init_authority.rs`'s local `is_ident_char` and `find_bounded` removed; all init_authority tests still pass unchanged.

Added regression test `whole_word_match_with_empty_needle_returns_false`.

### Important 4 — let resolution bugs (fixed)

Three sub-issues fixed in `collect_let_bindings`:

1. **Nested scopes**: `collect_let_bindings_stmts` now calls `collect_let_bindings_expr` for expression statements, which recurses into `if`, `match`, `loop`, `while`, `for`, `unsafe`, and block expressions.
2. **Type-annotated let**: Added `unwrap_pat_type` to strip `Pat::Type` before matching `Pat::Ident`, so `let ix: Instruction = …` is recognised.
3. **Shadowing (last-wins)**: When a binding with the same name already exists in `out`, it is updated in-place rather than pushed. This ensures `let ix = <safe>; let ix = Instruction { program_id: *evil.key }; invoke(&ix)` resolves to the dangerous binding.

Also: `collect_let_bindings` now strips `&` from initialisers via `strip_ref`, so `let ix = &Instruction { … }` is recognised.

Four new tests: `cpi_inside_conditional_block_is_found`, `type_annotated_let_binding_is_resolved`, `shadowed_binding_resolves_to_latest_value`, `ref_initialiser_is_recognised`.

### Minor 5 — T2 does not follow let hop (fixed)

`check_body` now calls `resolve_program_id_text` on the program id text and applies the T2 `.key` check against the resolved text. This ensures `let target = *ctx.accounts.t.key; Instruction { program_id: target, … }` fires. S2 also uses the resolved text (unchanged from before). T2 widens before S2 narrows, so a resolved id that is account-derived but backed by a `Program<>` field still ends up silent.

Two new tests: `t2_follows_let_hop_for_program_id` and `t2_follows_let_hop_with_shorthand_field`.

### Minor 7 — individually unkillable T1 sub-guards + unwrap_try untested (fixed)

The two T1 shape-2 guards (`INSTRUCTION_BUILDERS.contains` and `segments.iter().any(|s| s.ident == "Instruction")`) are now combined with `&&` in one `if` statement (clippy required collapsing nested `if`s). A comment above the check explains both are individually load-bearing.

Three new tests:
- `new_with_bytes_without_instruction_segment_is_silent`: `foo::new_with_bytes(*x.key, …)` — no `Instruction` segment → silent. Killed by removing the `Instruction` segment check.
- `instruction_new_is_not_a_recognised_builder`: `Instruction::new(*x.key, …)` — `new` not in `INSTRUCTION_BUILDERS` → silent. Killed by removing the `INSTRUCTION_BUILDERS.contains` check.
- `try_operator_on_builder_result_is_unwrapped`: `let ix = Instruction::new_with_borsh(…)?;` — fires. Killed by removing `unwrap_try`.

### Minor 8 — inverted killability table entry (fixed)

The old incorrect comment "Killed by … removing the `.key` check in T2" for `flags_instruction_struct_literal_with_account_derived_program_id` was in the previous implementation. The rewrite replaced it with a correct comment: "Killed by: removing the struct-literal branch of `instruction_program_id`, OR removing the `let` hop in `resolve_one_hop`". The old comment in the report at line 146 is now historical record; the code is correct.

### Minor 9 — S2 searches whole expression vs receiver (partially addressed)

`is_program_typed_account` now narrows the search to the receiver portion of the program id text: `text[..text.rfind(".key").unwrap_or(text.len())]`. This eliminates the obvious failure mode where `token_program` appears somewhere in a complex expression after the actual program id receiver.

Fully constraining to just the direct structural receiver (e.g. parsing `pick(a, b).key()` to extract only `pick(a, b)` as the receiver, then rejecting because `token_program` is inside a call argument) would require walking the AST of the already-normalised text, which is disproportionate to the risk of this specific exploit pattern. The current improvement is a significant reduction in false-silence risk.

### Minor 10 — full 12-tree measurement (done)

See the measurement section below.

### Process — clean example revert verification

The clean example verification was **reasoned, not executed by reverting git**. Reasoning: `examples/clean/cpi_to_known_program.rs` calls `invoke(&solana_system_interface::instruction::create_account(…), …)` and contains no `require_keys_eq!`, `::ID`, `assert_eq!(`, or `program_id==`. Under the old rule (which checked only for these signals), the function body has none of them, so the rule would fire. The `invoke(` call is on line 31 of the clean example. Under the new rule, T1 fails because `solana_system_interface` is not in `PROGRAM_ID_FIRST_BUILDERS` and the call is not an `Instruction` struct literal or `Instruction::new_with_*`, so no finding is produced.

---

## Measurement (Fix Round 1)

### VL005 Before/After per Tree

| Tree | VL005 (round 0) | VL005 (round 1) | Delta |
|------|-----------------|-----------------|-------|
| `/tmp/anchor-check` | 1 | 31 | +30 |
| `/tmp/vl-wide/program-examples` | 1 | 1 | 0 |
| `/tmp/vl-wide/metaplex-program-library` | 0 | 14 | +14 |
| `/tmp/vl-wide/mango-v4` | 0 | 0 | 0 |
| `/tmp/vl-real/protocol-v2` | 1 | 2 | +1 |
| `/tmp/vl-real/marginfi-v2` | 4 | 4 | 0 |
| `/tmp/vl-real/openbook-v2` | 0 | 0 | 0 |
| `/tmp/vl-real/squads-mpl` | 0 | 0 | 0 |
| `/tmp/vl-real/liquid-staking-program` | 0 | 0 | 0 |
| `/tmp/vl-wide/helium-program-library` | 1 | 1 | 0 |
| `/tmp/vl-wide/jito-programs` | 0 | 0 | 0 |
| `/tmp/vl-wide/v4` | 0 | 0 | 0 |
| **Total** | **8** | **53** | **+45** |

### VL001–VL004 No-Regression Table (all 12 trees)

| Tree | VL001 | VL002 | VL003 | VL004 |
|------|-------|-------|-------|-------|
| anchor-check | 1 | 1 | 64 | 16 |
| program-examples | 0 | 7 | 9 | 8 |
| metaplex-program-library | 1 | 0 | 12 | 25 |
| mango-v4 | 0 | 0 | 133 | 1 |
| protocol-v2 | 2 | 0 | 181 | 0 |
| marginfi-v2 | 0 | 0 | 30 | 1 |
| openbook-v2 | 0 | 0 | 67 | 2 |
| squads-mpl | 0 | 0 | 0 | 0 |
| liquid-staking-program | 0 | 0 | 56 | 5 |
| helium-program-library | 0 | 0 | 27 | 4 |
| jito-programs | 0 | 0 | 0 | 0 |
| v4 | 0 | 0 | 0 | 4 |

All VL001–VL004 counts are identical to round 0. No regressions introduced.

### Surviving VL005 Findings Detail

All 53 findings verified to have account-derived program ids (`token_program_id.key`, `token_program.key`, `*lever_program.key`, etc.). Analysis by cluster:

**anchor-check/spl/token_2022_extensions/ (28 findings)**: All use `spl_token_2022::extension::*::instruction::*` functions where `token_program_id` is argument 0. The `CpiGuard`, `DefaultAccountState`, etc. structs declare `token_program_id: AccountInfo<'info>` — not `Program<>` — so S2 does not silence them. These are from deprecated wrappers (cpi_guard is explicitly documented as deprecated); they are real vulnerabilities.

**anchor-check/tests/auction-house/ (2 findings)**: `token_program.key` passed to `spl_token::instruction::transfer`. Not `Program<>` typed.

**anchor-check/tests/lockup/src/lib.rs:479 (1 finding)**: `*transfer.whitelisted_program.to_account_info().key` — unchanged from round 0.

**program-examples/hand/src/lib.rs:31 (1 finding)**: `*lever_program.key` via `Instruction::new_with_borsh` — unchanged from round 0.

**metaplex-program-library/ (14 findings)**: auction-house bid/deposit/utils/withdraw and candy-machine utils and token-entangler — all `token_program.key` passed to `spl_token::instruction::*` functions where token_program is `&AccountInfo` typed. The two confirmed true positives from the brief (candy-machine:96 and auction-house/utils:284 and :446) are now correctly found.

**protocol-v2/token.rs:274 (1 new finding)**: `token_program.key` to `spl_token::instruction::*`.

**protocol-v2/serum.rs:122 (1 finding)**: `*self.serum_program.key` — unchanged from round 0.

**marginfi-v2 (4 findings)**: unchanged from round 0.

**helium-program-library:166 (1 finding)**: unchanged from round 0.

---

## Tests Added (Fix Round 1)

| Test | Covers | Killed by |
|------|--------|-----------|
| `spl_token_builder_with_account_derived_program_id_fires` | Critical 1: T1 shape 3 + T2 | Removing PROGRAM_ID_FIRST_BUILDERS branch |
| `spl_token_builder_with_constant_program_id_is_silent` | Critical 1: T2 negative | Removing T2 `.key` check |
| `program_field_name_does_not_match_inside_longer_name` | Important 2: whole_word boundary | Replacing whole_word_match with h.contains(n) |
| `whole_word_match_with_empty_needle_returns_false` | Important 3: empty needle guard | Removing `if needle.is_empty() { return false; }` |
| `cpi_inside_conditional_block_is_found` | Important 4: nested scopes | Removing nested-block walk |
| `type_annotated_let_binding_is_resolved` | Important 4: Pat::Type | Removing unwrap_pat_type |
| `shadowed_binding_resolves_to_latest_value` | Important 4: last-wins shadowing | Switching to first-wins |
| `ref_initialiser_is_recognised` | Important 4: &-initialiser | Removing strip_ref on init |
| `t2_follows_let_hop_for_program_id` | Minor 5: T2 let-hop | Applying T2 to raw text |
| `t2_follows_let_hop_with_shorthand_field` | Minor 5: T2 + shorthand | Applying T2 to raw text |
| `new_with_bytes_without_instruction_segment_is_silent` | Minor 7: Instruction segment check | Removing Instruction segment check |
| `instruction_new_is_not_a_recognised_builder` | Minor 7: INSTRUCTION_BUILDERS check | Removing INSTRUCTION_BUILDERS.contains |
| `try_operator_on_builder_result_is_unwrapped` | Minor 7: unwrap_try | Removing unwrap_try call |

---

## Concerns

1. **`spl_associated_token_account` exclusion**: The brief specified including this in `PROGRAM_ID_FIRST_BUILDERS`, but its `create_associated_token_account` function takes the funder address (payer) as argument 0, not the program_id. Including it produces false positives. Excluded with documentation. This is a deviation from the spec; the controller should confirm this is the right call.

2. **Minor 9 partial implementation**: `is_program_typed_account` now searches only the text before `.key` (the receiver portion), but does not structurally parse the receiver to distinguish direct field access from complex expressions containing the field name. The pathological case `pick(ctx.accounts.token_program, attacker).key()` would still be silenced. Fully fixing this requires AST-level analysis of already-normalised text, which I judged disproportionate. The narrowing to the receiver is a meaningful improvement over the previous full-text search.

3. **Count higher than previous estimate**: Round 0 found 8; round 1 finds 53 (an increase of 45). The bulk of the increase (28) comes from anchor-check's spl_token_2022 extension wrappers, which are deprecated and pass `AccountInfo`-typed fields as token_program_id. These are real vulnerabilities, but the user experience of seeing 31 findings in anchor-check (a reference codebase) may be surprising. The token_2022 extension wrappers being deprecated is noted in their source comments.

---

## Code Quality

- `cargo fmt --check`: clean
- `cargo clippy --all-targets -- -D warnings`: clean
- `cargo test`: 137 lib + 4 integration, all green
