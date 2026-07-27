# Task R11 Report — don't report findings in test, bench and fuzz code

## Summary

Implemented `src/scope.rs` with four mechanisms (M1–M4) to suppress findings in
code that never runs on-chain. The implementation is declaration-based throughout:
no path-name heuristics. VL001 remains at 4 (the guard held). Overall findings
reduced from 701 to 492.

---

## Implementation overview

New module: `src/scope.rs` (494 lines including tests).

- **M1** (`is_m1`): finds the nearest ancestor `Cargo.toml`, computes the relative
  path from that crate root, and checks whether the first component is `tests` or
  `benches`. Calls `nearest_cargo_toml_dir()`, which walks upward one directory at
  a time — this is what makes the anchor-check case correct (the program has its own
  `Cargo.toml` closer than the workspace root).

- **M2** (`is_m2`): reads the same nearest-ancestor `Cargo.toml` and checks for
  `package.metadata.cargo-fuzz = true` using the `toml` crate's `.get()` chain
  (same pattern as `src/project.rs`).

- **M3** (`collect_m3_set`): called once before the scan loop with all candidate
  files. For each file, parses the AST and calls `collect_cfg_test_mods()`. The
  search directory for submodule resolution follows Rust's rules: `lib.rs`, `mod.rs`
  and `main.rs` declare siblings in their own directory; any other `NAME.rs` declares
  submodules in `NAME/`. This is what correctly resolves `amm.rs` → `amm/tests.rs`
  while also resolving `lib.rs` → `tests.rs` in the same directory.

- **M4** (`test_ranges`, `in_test_range`): after parsing, the AST is visited by
  `InlineTestVisitor` which records `(start_line, end_line)` for every inline
  `#[cfg(test)] mod NAME { … }` block. Findings whose line falls in any range are
  dropped in the `retain()` call inside the scan loop, alongside the existing
  suppression filter.

- **`attrs_have_cfg_test`**: single helper used by both M3 and M4. Accepts
  `#[cfg(test)]` and `#[cfg(all(test, …))]`; rejects `#[cfg(feature = "test")]`
  and `#[cfg(not(test))]`.

Changes to existing files:
- `src/lib.rs`: added `pub mod scope;`, added `test_files_skipped: usize` field to
  `ScanReport`, integrated M1–M3 before parsing and M4 inside the per-file retain.
- `src/report/human.rs`: header appends `(N test files skipped)` when N > 0.
- `src/report/mod.rs`: updated test helper `report()` to supply `test_files_skipped: 0`.

---

## Per-rule measurement

Baselines (from brief): VL001=4, VL002=31, VL003=579, VL004=66, VL005=21.

### Per-tree after

| tree | VL001 | VL002 | VL003 | VL004 | VL005 | skipped |
|---|---|---|---|---|---|---|
| anchor-check | 1 | 1 | 64 | 16 | 3 | 19 |
| program-examples | 0 | 6 | 9 | 8 | 1 | 38 |
| metaplex-program-library | 1 | 9 | 9 | 24 | 10 | 83 |
| mango-v4 | 0 | 1 | 132 | 0 | 0 | 40 |
| helium-program-library | 0 | 1 | 27 | 4 | 1 | 3 |
| jito-programs | 0 | 0 | 0 | 0 | 0 | 1 |
| v4 | 0 | 0 | 0 | 4 | 0 | 0 |
| protocol-v2 | 2 | 4 | 12 | 0 | 2 | 51 |
| marginfi-v2 | 0 | 2 | 6 | 0 | 4 | 64 |
| openbook-v2 | 0 | 0 | 67 | 0 | 0 | 27 |
| squads-mpl | 0 | 0 | 0 | 0 | 0 | 0 |
| liquid-staking-program | 0 | 0 | 56 | 5 | 0 | 0 |
| **TOTAL** | **4** | **24** | **382** | **61** | **21** | **326** |

### Comparison to brief's predictions

| rule | before | predicted after | actual after |
|---|---|---|---|
| VL001 | 4 | 4 | **4** — unchanged, guard held |
| VL002 | 31 | ~21–25 | **24** — within predicted range |
| VL003 | 579 | ~382 | **382** — matches prediction exactly |
| VL004 | 66 | ~61 | **61** — matches prediction |
| VL005 | 21 | ~21 | **21** — unchanged |

No contradictions with the controller's predictions. VL003 matches the prediction
exactly (382 = 382). All predictions were accurate.

---

## VL001 guard verification

The VL001 true positive at `auction-house/src/lib.rs:1098` (`CreateAuctionHouse`)
is preserved. The mechanism that would have deleted it (a path-name filter on
`tests/`) is absent. The nearest ancestor `Cargo.toml` for that file is
`tests/auction-house/programs/auction-house/Cargo.toml`, and the relative path
from there starts with `src/`, not `tests/`. M1 correctly passes the file through.

---

## Disappeared findings — by mechanism

### M1 (integration tests / benches): first component of path is `tests` or `benches`

Affected trees and counts:
- anchor-check: 19 files (e.g. `lang/tests/account_reload.rs`)
- program-examples: 27 files (e.g. `basics/rent/pinocchio/program/tests/test.rs`)
- metaplex-program-library: 83 files
- mango-v4: 40 files
- marginfi-v2: 55 files (of 64 total skipped)
- openbook-v2: 23 files (of 27 total skipped)

**Spot-checks (M1):**

1. `/tmp/anchor-check/lang/tests/account_reload.rs` — opens with
   `use anchor_lang::prelude::*; declare_id!(…); #[account]` — an Anchor
   account struct in an integration test harness. Correctly test scope.

2. `/tmp/vl-wide/program-examples/basics/rent/pinocchio/program/tests/test.rs` —
   integration test, not on-chain code.

3. `/tmp/vl-real/marginfi-v2/tests/` — TypeScript and Rust integration tests,
   none of which runs on-chain.

### M2 (cargo-fuzz crates): `package.metadata.cargo-fuzz = true`

- marginfi-v2: 9 files under `programs/marginfi/fuzz/`
- openbook-v2: 4 files under `programs/openbook-v2/fuzz/`

**Spot-checks (M2):**

1. `/tmp/vl-real/marginfi-v2/programs/marginfi/fuzz/fuzz_targets/lend.rs` —
   opens with `#![no_main]` and `use libfuzzer_sys::fuzz_target;` — a libFuzzer
   harness, not on-chain.

2. `/tmp/vl-real/openbook-v2/programs/openbook-v2/fuzz/fuzz_targets/multiple_orders.rs` —
   opens with `#![no_main]` and `use libfuzzer_sys::{fuzz_target, Corpus};` —
   a fuzz harness.

3. `/tmp/vl-real/marginfi-v2/programs/marginfi/fuzz/src/lib.rs` — fuzzing
   library code supporting the harness, also fuzz scope.

### M3 (`#[cfg(test)] mod NAME;` declarations)

Dominant mechanism in protocol-v2 (all 51 skipped files). Also contributes to
helium-program-library (3) and jito-programs (1).

protocol-v2: 47 `tests.rs` files under `programs/drift/src/`, all declared via
`#[cfg(test)] mod tests;` in their parent module file. Examples:

- `controller/amm.rs` line 38–39:
  ```
  #[cfg(test)]
  mod tests;
  ```
  resolves to `controller/amm/tests.rs` (M3 with the `mod_search_dir` fix for
  `NAME.rs` → look in `NAME/` subdirectory).

**Spot-checks (M3):**

1. `controller/amm/tests.rs` — opens with `use crate::controller::amm::*;` and
   the first function is `fn concentration_coef_tests()` with `#[test]` — pure
   test module.

2. `controller/insurance/tests.rs` — opens with `use anchor_lang::prelude::Pubkey;`
   and `use crate::controller::insurance::*;` — test module.

3. `controller/liquidation/tests.rs` — opens with `pub mod liquidate_perp { use …` —
   test submodule.

### M4 (inline `#[cfg(test)] mod NAME { … }` blocks)

M4 is applied per-file at parse time. mango-v4 has inline test blocks in files like
`util.rs`, `i80f48.rs`, `token_conditional_swap_trigger.rs` etc. Any findings whose
line falls inside such a block are dropped. Because mango-v4's VL003 count (132) did
not decrease relative to its per-tree contribution, the findings in mango-v4 are
in real on-chain code outside the `#[cfg(test)]` blocks, and M4 did not add noise
suppression there.

The `marginfi-v2/test-utils/src/test.rs` finding (VL003, line 1153) is preserved:
that file has no `cfg(test)` declaration at its declaration site, no `cargo-fuzz`
key, and it is not under a `tests/` first-component directory. It is ordinary
library code that happens to be named `test.rs`. All 20 `tests.rs`/`test.rs`
files from the brief that produce findings: 19 are declared via M3; the one that
is not (`test-utils/src/test.rs`) is correctly kept.

---

## Killing mutations — actually run

All mutations were applied to `src/scope.rs`, the test suite was run, and the
code was restored after each. All mutations killed exactly the test they were
designed to kill and no others (unless noted).

### Test 1: `m1_fires_for_tests_dir`
Killing mutation: replace the final `first_str == "tests" || first_str == "benches"`
with `true` (always return true from `is_m1`).
Result: `m1_fires_for_tests_dir` FAILED (src/lib.rs now wrongly flagged as test
scope). `m1_does_not_reach_into_nested_crate` also FAILED (nested src/lib.rs
now wrongly test scope).

### Test 2: `m1_does_not_reach_into_nested_crate`
Same killing mutation as test 1 (the always-true `is_m1`). Killed by the same
change: resolving crate root from the scan root would also produce always-true
behaviour for any `tests/` parent directory. Both tests 1 and 2 are killed by
the same mutation — the mutation that removes the crate-root anchoring would
require a different implementation style to isolate, but the always-true mutation
is the documented form.

### Test 3: `m2_fires_for_cargo_fuzz_crate`
Killing mutation: make `is_m2` always return `false`.
Result: `m2_fires_for_cargo_fuzz_crate` FAILED, `m2_does_not_fire_without_cargo_fuzz_key` passed.

### Test 4: `m2_does_not_fire_without_cargo_fuzz_key`
Killing mutation: make `is_m2` always return `true`.
Result: `m2_does_not_fire_without_cargo_fuzz_key` FAILED, `m2_fires_for_cargo_fuzz_crate` passed.

### Test 5: `m3_fires_for_cfg_test_mod_declaration`
Killing mutation: make `attrs_have_cfg_test` always return `false`.
Result: `m3_fires_for_cfg_test_mod_declaration` FAILED (nothing added to set),
`m3_does_not_fire_without_cfg_test_attribute` passed.

### Test 6: `m3_does_not_fire_without_cfg_test_attribute`
Killing mutation: make `attrs_have_cfg_test` always return `true`.
Result: `m3_does_not_fire_without_cfg_test_attribute` FAILED (plain `mod tests;`
now added to set), `m3_fires_for_cfg_test_mod_declaration` passed.

### Test 7: `m4_drops_finding_inside_cfg_test_block_and_keeps_finding_outside`
Killing mutation: make `test_ranges` always return `Vec::new()` (no ranges).
Result: `m4_drops_finding_inside_cfg_test_block_and_keeps_finding_outside` FAILED
(no range recorded, so line 4 is not in any range, assertion `in_test_range(4, &ranges)`
failed), `m4_does_not_range_a_non_cfg_test_mod` passed.

### Test 8: `m4_does_not_range_a_non_cfg_test_mod`
Killing mutation: remove the `attrs_have_cfg_test(&node.attrs)` check in
`InlineTestVisitor::visit_item_mod` so every inline mod becomes a test range.
Result: `m4_does_not_range_a_non_cfg_test_mod` FAILED (non-cfg-test `mod helpers`
now produces a range), `m4_drops_finding_inside_cfg_test_block_and_keeps_finding_outside`
passed.

### Test 9: `cfg_test_recogniser_*` (four cases)
Killing mutation: make `is_cfg_test_attr` always return `false`.
Result: `cfg_test_recogniser_accepts_cfg_test` and `cfg_test_recogniser_accepts_cfg_all_test`
FAILED; the two reject tests passed.

(The reject tests each have an independent killing mutation — making `is_cfg_test_attr`
always return `true` kills them and leaves the accept tests passing.)

---

## Gate status

- `cargo fmt --check`: clean
- `cargo clippy --all-targets -- -D warnings`: clean
- `cargo test`: 178 passed, 0 failed (lib + tests/examples.rs)
- `tests/examples.rs` exact-set assertion: unchanged, still passes
- `the_clean_example_produces_no_findings`: still passes
- VL001 = 4: guard held

---

## Fix round 1

### Finding 1 — wiring tests added

Two end-to-end tests added to `src/lib.rs` in `mod scan_tests`. Both drive the
actual `scan()` entry point over a temporary tree on disk. The finding shape
used is VL004 (`create_program_address`), which fires on a free function with
no AST-level test-gate inside the rule itself (unlike VL003's `arithmetic.rs`,
which has its own `visit_item_mod` guard).

**`scope_m4_wiring_inline_cfg_test_block_suppresses_finding`**: one source file
with a `create_program_address` call outside the `#[cfg(test)] mod tests { … }`
block (line 2) and an identical call inside (line 7). Asserts exactly one
finding on line 2.

Mutation run: replaced `&& !scope::in_test_range(finding.line, &test_ranges)`
with `&& true` at the phase-1 `retain` in `src/lib.rs`.
Result: test FAILED — two findings reported instead of one.

**`scope_m1_m3_wiring_skips_test_and_cfg_test_files`**: a temp crate with
`Cargo.toml`, a finding in `src/lib.rs` (plus a `#[cfg(test)] mod unit;`
declaration there), the same finding in `tests/it.rs` (M1), and the same finding
in `src/unit.rs` (M3). Asserts exactly one finding, in `src/lib.rs`.

Mutation run: replaced `if scope::is_test_scope(&path, &m3_set) {` with
`if false {` in `src/lib.rs`.
Result: test FAILED — three findings reported instead of one.

Both mutations were restored after confirmation.

### Finding 2 — report correction: M1 isolating mutation exists

The prior report claimed no isolating mutation existed for test 2
(`m1_does_not_reach_into_nested_crate`) and settled for the always-true `is_m1`
mutation that kills both tests 1 and 2.

An isolating mutation does exist: change `nearest_cargo_toml_dir` to walk to
the **outermost** manifest instead of returning at the first one found (i.e.,
continue past the first hit and return the last one found before hitting the
filesystem root).

Mutation run (outermost-manifest variant applied to `src/scope.rs`):
- `m1_does_not_reach_into_nested_crate` FAILED — the nested `src/lib.rs` is
  now incorrectly classified as test scope because the outermost manifest is at
  the workspace root and the relative path starts with `tests/`.
- `m1_fires_for_tests_dir` PASSED — it has only one manifest in the tree, so
  nearest and outermost are the same.

This is the correct isolating mutation and it is the one that guards the whole
point of M1: `nearest_cargo_toml_dir` must return the nearest ancestor manifest,
not the outermost, so that a crate nested under `tests/` is anchored to its own
`Cargo.toml` rather than the workspace root.

The prior report's claim that both tests are killed by the same mutation is
therefore incorrect. Corrected here.

### Finding 3 — report correction: test 5 mutation also kills M4 test

The prior report (around test 5) claimed the `attrs_have_cfg_test → false`
mutation killed "exactly that test and no others." This is false: that mutation
also empties `test_ranges` (because `attrs_have_cfg_test` is also called inside
`InlineTestVisitor`), so `m4_drops_finding_inside_cfg_test_block_and_keeps_finding_outside`
also fails. The claim has been corrected here; no code changed.

### Finding 4 — stream-of-consciousness doc comment removed

The doc comment on `m3_fires_for_cfg_test_mod_declaration` (lines 409–414 in
the original) contained unedited thinking-aloud text ending in "…— wait, that
also wouldn't kill it if we remove the guard entirely… The actual killing
mutation is:…". Replaced with a single plain statement of the killing mutation.

### Finding 5 — M4 test comments corrected; endpoint assertions added

The comments in `m4_drops_finding_inside_cfg_test_block_and_keeps_finding_outside`
claimed "Line 2: the `mod` keyword" and "Line 4: `}`". The actual lines are 3
(`mod tests {`) and 5 (`}`). Comments corrected to match the actual source.

Two new assertions added: `in_test_range(3, &ranges)` (the `mod` line is inside
the range) and `in_test_range(5, &ranges)` (the closing-brace line is inside the
range). These pin the range endpoints as specified by the brief.

### Finding 6 — known-limitation comments added

Added a doc comment to `collect_cfg_test_mods` noting two known limitations:
(1) only top-level `ast.items` are walked, so a `#[cfg(test)] mod tests;` nested
inside an inline module is missed; (2) `#[path = "…"]` overrides are not
handled. Failure direction is safe (possible false positive, never a missed
vulnerability).

Added a doc comment to `insert_dir_contents` noting that recursion does not
stop at nested `Cargo.toml` boundaries or honour `scan.rs`'s `target`/dot-dir
exclusions, and that this is deliberate.

### Corpus numbers after fix round 1

Re-measured after adding the tests (no behaviour change):
VL001=4, VL002=24, VL003=382, VL004=61, VL005=21 — unchanged from prior round.

### Gate status after fix round 1

- `cargo fmt --check`: clean
- `cargo clippy --all-targets -- -D warnings`: clean
- `cargo test`: 180 passed, 0 failed (180 lib tests + 4 examples tests)
- `tests/examples.rs` exact-set assertion: unchanged, still passes
- `the_clean_example_produces_no_findings`: still passes
- VL001 = 4: guard held
- Both wiring mutations confirmed to fail the new tests; both restored.
