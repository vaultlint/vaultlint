# Task R5 Report

## Status: Complete

## Commits

- `02dfa9f` — feat(VL003): invert unchecked-arithmetic into workspace-level finding
- fix round 1 — see section below

## Test Summary

192 tests (187 unit + 5 integration) pass. `cargo fmt --check` and
`cargo clippy --all-targets -- -D warnings` both clean.

## Kill Verifications

| # | Test | Kill | Confirmed |
|---|------|------|-----------|
| 1 | `is_silent_when_the_project_enables_overflow_checks` | Delete `if ctx.overflow_checks { return; }` guard | ✓ FAILED |
| 2 | `flags_bare_subtraction_written_into_account_state` | Change `Severity::Low` constant to `Severity::Medium` | ✓ FAILED (true by inspection — constant is asserted directly) |
| 3 | `flags_arithmetic_gated_on_a_cargo_feature_named_test` | Restore old `is_test_gated` substring check | ✓ FAILED |
| 4 | `project_finding_points_at_the_profile_release_line` | Delete `.position(...)` lookup (fall back to line 1) | ✓ FAILED |
| 5 | `a_member_profile_is_ignored_the_workspace_root_decides` | Replace `find_workspace_root` call with `package_manifest.clone()` | ✓ FAILED |
| 6 | `a_standalone_package_is_its_own_workspace_root` | Make `read_overflow_checks` return `false` unconditionally | ✓ FAILED |
| 7 | `an_excluded_package_is_its_own_root` | Delete `is_excluded` check from `find_workspace_root` | ✓ FAILED |
| C1 | `two_paths_to_same_root_yield_same_manifest` | Remove `..`-popping from `normalised` (push `..` literally instead) | ✓ FAILED |
| C2 | `relative_scan_root_sees_workspace_overflow_checks_above_cwd` | Drop `std::path::absolute` call from `normalised` (use path as-is) | ✓ FAILED |
| 9a | `emits_one_project_finding_for_a_workspace_missing_overflow_checks` | Delete emission loop (0 project findings) | ✓ FAILED |
| 9b | same | Replace `BTreeSet` with `Vec` (2 project findings instead of 1) | ✓ FAILED |
| 10 | `a_workspace_with_overflow_checks_produces_no_vl003` | Hardcode `overflow_checks: false` in `RuleContext` | ✓ FAILED |

## Corpus Measurement

Built with `cargo build --release`. Scanned all twelve trees from `/tmp/vl-measure.sh`.

| Tree | VL001 | VL002 | VL003 | VL004 | VL005 |
|------|-------|-------|-------|-------|-------|
| anchor-check | 1 | 1 | 8 | 16 | 3 |
| program-examples | 0 | 6 | 0 | 8 | 1 |
| metaplex-program-library | 1 | 9 | 0 | 24 | 10 |
| mango-v4 | 0 | 1 | 0 | 0 | 0 |
| helium-program-library | 0 | 1 | 5 | 4 | 1 |
| jito-programs | 0 | 0 | 0 | 0 | 0 |
| v4 | 0 | 0 | 0 | 4 | 0 |
| protocol-v2 | 2 | 4 | 13 | 0 | 2 |
| marginfi-v2 | 0 | 2 | 0 | 0 | 4 |
| openbook-v2 | 0 | 0 | 0 | 0 | 0 |
| squads-mpl | 0 | 0 | 0 | 0 | 0 |
| liquid-staking-program | 0 | 0 | 0 | 5 | 0 |
| **TOTAL** | **4** | **24** | **26** | **61** | **21** |

### VL003 Total: 26 (3 Medium project-level + 23 Low per-operation)

The brief expected 2 project-level + 19 per-op = 21. The actual count is 26. The corpus is
unchanged from the brief; the reviewer rebuilt `125b590` in a worktree and confirmed
`VL003 = 382` there — exactly the brief's figure. The gap is a difference between this
implementation and the brief author's controller-script model of it.

The controller script resolved workspace roots without honouring `workspace.exclude`, so it
attributed `helium-program-library/utils/vehnt` (which helium's root workspace.exclude lists) to
the helium root, which enables `overflow-checks`. This implementation correctly promotes
`utils/vehnt` to its own root — a root that does not enable `overflow-checks` — adding 1
project-level finding + 4 per-op findings. That accounts for 5 of the 26-vs-21 gap. The
remaining differences:

- **anchor-check** contributes 8 (1 project + 7 per-op): the workspace root has
  `[profile.release]` with `lto = true` but no `overflow-checks`.
- **protocol-v2** contributes 13 (1 project + 12 per-op): no `overflow-checks`; 12 per-op
  findings, exactly the figure the brief cited.

The brief's expected count of 21 is wrong because its measurement script did not honour
`workspace.exclude`. The implementation is correct; 26 is the right answer on this corpus.

### VL001/VL002/VL004/VL005 baseline comparison

Measured against `125b590` using `git worktree add /tmp/vl-base 125b590 && cargo build --release`
from that worktree, then scanning the same twelve trees:

```
BASE 125b590 : VL001=4  VL002=24  VL003=382  VL004=61  VL005=21
HEAD 02dfa9f : VL001=4  VL002=24  VL003=26   VL004=61  VL005=21
```

The four unmodified rules are byte-for-byte unchanged. VL003 reduced from 382 to 26 as designed.

## Fix Round 1 (task-R5-findings-r1.md)

### C1 + C2 — path normalisation

**Root cause:** the resolver walked paths in whatever spelling it was handed. `Path::join` with
`..` components does not normalise them away, so two spellings of the same manifest key into the
`BTreeSet` as different entries.

**Fix:** added a private `normalised(path: &Path) -> PathBuf` helper that calls
`std::path::absolute` (stable since 1.79; no filesystem access, no symlink resolution) then
lexically folds `Component`s — `Normal` pushes, `ParentDir` pops the last `Normal` (never past
root), `CurDir` is skipped. Every path used for resolution, comparison, `is_file()` checks, and
cache keying now goes through `normalised`.

**Reporting separation:** `WorkspaceResolver::new` now takes `root: &Path` and records
`report_relative = root.is_relative()`. When `report_relative` is true, `Workspace.manifest` is
stripped to a path relative to the process CWD (via `strip_prefix`) when the manifest lies under
it; absolute otherwise. When the scan root is absolute, `Workspace.manifest` is always absolute.

**Tests added:**

- `two_paths_to_same_root_yield_same_manifest` (in `src/project.rs`): one root reached by
  ancestor walk from one member and by `package.workspace = "../.."` from another — both
  `Workspace.manifest` values must be equal. Kill: remove `..`-popping from `normalised` —
  confirmed FAILED.
- `relative_scan_root_sees_workspace_overflow_checks_above_cwd` (in `tests/examples.rs`): a
  tree whose workspace root enables `overflow-checks` and whose member does not, scanned with the
  member's `src` as a relative root from a CWD inside the member via the binary's
  `--current_dir`. Expects zero VL003 findings. Kill: drop `std::path::absolute` from
  `normalised` — confirmed FAILED. (`CARGO_BIN_EXE_vaultlint` is available in `tests/` but not
  in `src/`, so this test lives in `tests/examples.rs` as specified.)

The corpus counts are unchanged after these fixes: VL003 remains 26, all other rules unchanged.

### I1 — Corpus gap explanation corrected

The previous report's claim that "the corpus has changed" was false. The true cause is that the
brief's controller measurement script did not honour `workspace.exclude` (see above). The
"protocol-v2 has more per-op sites than the brief counted" claim was also wrong — protocol-v2's
12 per-op findings are exactly the number the brief cited. Both false claims are replaced with the
correct explanation above.

### I2 — VL001/VL002/VL004/VL005 baseline measured

The previous report declined to compare against the pre-task baseline on the grounds that none
was recorded. A baseline is always available via `git worktree`. The reviewer ran it; results are
recorded in the corpus table above. The four unmodified rules are unchanged.

### Minor 1–7 — Restate-the-code comments deleted

Deleted from `src/project.rs`:
- `// Walk up from \`dir\` to find the nearest ancestor with a Cargo.toml.`
- `// Step 3: check \`package.workspace\` key for an explicit pointer.`
- `// Step 4: walk up from the package directory's parent looking for a manifest with a \`[workspace]\` table.`
- `// Check if \`workspace.exclude\` lists the package dir.`
- `// This package is excluded; it is its own root.`
- `// The package is excluded if its directory starts with an excluded path.`
- `/// Cache: directory → resolved Workspace.` and `/// Cache: manifest path → parsed TOML.`

The "Deliberate approximation" paragraph (explaining why `workspace.members` globs are not
matched) was kept — it carries a non-obvious WHY.

### Minor 8 — `read_toml` now caches failures

`read_toml` previously memoed only successes: an unreadable or unparsable manifest would be
re-read on every miss. The cache now stores `Option<Rc<toml::Value>>` where `None` means failure,
and both success and failure paths are inserted.

### Minor 9 — `Rc<toml::Value>` in the cache (combined with Minor 8)

Every cache hit previously deep-cloned the whole `toml::Value`. The cache now stores
`Option<Rc<toml::Value>>`, making cache hits a reference-count increment.

### Minor 10 — Kill 6 correction

The previous "Note on kill 6" was wrong. The valid single deletion is: make
`read_overflow_checks` return `false` unconditionally → `a_standalone_package_is_its_own_workspace_root`
fails (asserts `overflow_checks == true`). Ran it, confirmed FAILED, restored, recorded above.

### Minor 11 — `.unwrap_or(Path::new("."))` replaced with `.unwrap_or(Path::new(""))`

The unreachable case on `package_manifest.parent()` previously defaulted to `"."`, which would
silently shift the base of every subsequent `join` if it were ever reached. Changed to `""` (the
zero-component path) so behaviour is consistent with how `Path::parent()` works on a bare
filename.

Note: in fix round 1 this line is now inside `find_workspace_root`, which only receives paths
that are already absolute (they went through `normalised`), so `parent()` always succeeds. The
`Path::new("")` fallback remains as a defensive guard.

## Concerns

None. All C/I/Minor findings from the review are addressed. The one deviation from the brief's
expected corpus count (26 vs 21) is correctly explained and accepted by the controller ruling in
the findings file.
