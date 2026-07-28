# Task R7 Report — Output Formats

## What changed and why

### R7-1: JSON shape — `{ "findings": [...], "skipped": [...] }`

`src/report/json.rs` was changed from emitting `report.findings` as a bare JSON
array to emitting an object `{ "findings": [...], "skipped": [...] }`.

The `skipped` list is serialised as `[{ "path": "...", "reason": "..." }]`.
`SkippedFile` in `src/lib.rs` gained `#[derive(serde::Serialize)]`; rather than
relying on that derive directly, `json.rs` maps each `SkippedFile` to a local
`SkippedEntry<'a>` struct so that `path` is emitted as a UTF-8 string (via
`.to_string_lossy()`) rather than as a platform `PathBuf` serde representation.

`ScanReport` gained a `scan_root: Option<PathBuf>` field (used by SARIF, see
below); `ScanReport` constructors in tests set it to `None`.

### R7-2: SARIF — relative URI + `uriBaseId`, absolute URI for out-of-root paths

`src/report/sarif.rs` was rewritten to:

1. Accept `report.scan_root: Option<&Path>` and pass it through to per-result
   helpers.
2. Emit `originalUriBaseIds` on the run, mapping `%SRCROOT%` to a `file://` URI
   of the scan root (trailing `/` as required by the spec).
3. In `artifact_location()`:
   - Path inside scan root → `{ "uri": "relative/path", "uriBaseId": "%SRCROOT%" }`.
   - Path outside scan root (e.g. workspace `Cargo.toml` above a member scan) →
     `{ "uri": "file:///abs/path" }` with no `uriBaseId`.
   - `scan_root` is `None` (unit tests) → legacy behaviour, path string verbatim.
4. A small `percent_encode_path()` function encodes non-URI-safe bytes in `file://`
   URIs without pulling in a new dependency.

`scan()` in `src/lib.rs` now sets `scan_root: Some(project::normalised(&options.root))`
on the returned `ScanReport`. `project::normalised` was made `pub` to allow this.

### R7-3: SARIF — `invocations[].toolExecutionNotifications` for skipped files

The `invocation()` helper builds a single `invocation` object with
`executionSuccessful: true` and a `toolExecutionNotifications` array.  Each
skipped file becomes one notification at level `"note"` with a message that
includes the path and reason.

### R7-4: Human header — plural "file" / "files"

`src/report/human.rs`: the header line now reads `"analyzing N Rust file …"` for
N = 1 and `"analyzing N Rust files …"` for N ≠ 1.  The existing test for 14 files
still asserts on `"analyzing 14 Rust files (Anchor 0.30.1)"` and passes.

### VL003 SARIF rule descriptor fix (from R5 context)

`src/report/sarif.rs` previously called `BTreeMap::entry(...).or_insert(finding)`
and used the first-inserted finding's `title`, `help`, and `docs_url` for the
rule descriptor.  Because VL003 emits both a Medium "overflow-checks is not
enabled" finding and a Low "unchecked arithmetic" finding under the same
`rule_id`, the descriptor text depended on sort order.

Fix: a static `rule_metadata(rule_id: &'static str) -> RuleDescriptor` function
provides rule-level `name`, `help`, and `docs_url` that are independent of any
individual finding.  The de-duplication now uses `BTreeMap<&str, ()>` + presence
check, and the descriptor is built entirely from the static table.

The per-result `message` continues to carry the instance-specific title as before.

---

## Tests added

All new tests are in `src/report/mod.rs` in the existing `tests` module.

### `json_output_is_an_object_with_findings_and_skipped_keys`
Replaces the deleted `json_output_is_a_flat_array_of_findings`.
Asserts the root is an object and `parsed["findings"][0]` carries the right fields.
**Kill**: revert `json.rs` to `serde_json::to_writer_pretty(&mut *out, &report.findings)`.
The root becomes an array; `parsed["findings"]` is `null`; `parsed["findings"][0]["rule_id"]`
is `null`; `assert_eq!(parsed["findings"][0]["rule_id"], "VL002")` fails.

### `json_output_includes_skipped_files`
Adds one `SkippedFile` to the report and checks `parsed["skipped"][0]`.
**Kill**: remove the `"skipped": skipped` field from the `json!({…})` in `json.rs`.
`parsed["skipped"].as_array()` returns `None`; `.unwrap()` panics.

### `sarif_skipped_files_appear_in_invocation_notifications`
Adds a skipped file and checks `invocations[0]["toolExecutionNotifications"]`.
**Kill**: remove `"invocations": [invocation(report)]` from the SARIF run.
`parsed["runs"][0]["invocations"][0]["toolExecutionNotifications"]` is `null`;
`.as_array()` returns `None`; `.unwrap()` panics.

### `sarif_uri_inside_scan_root_is_relative_with_base_id`
Creates a real temp directory as the scan root, sets a finding path inside it,
and asserts `loc["uriBaseId"] == "%SRCROOT%"` and `loc["uri"] == "src/lib.rs"`.
**Kill**: remove the `uriBaseId` field from the `Ok(rel)` branch of `artifact_location`.
`loc["uriBaseId"]` is `null`; `assert_eq!(loc["uriBaseId"], "%SRCROOT%")` fails.

### `sarif_uri_outside_scan_root_is_absolute_with_no_base_id`
Sets the scan root to `member/src` and the finding path to a sibling `Cargo.toml`
above the root.  Asserts no `uriBaseId` and that the URI starts with `"file://"`.
**Kill**: remove the `Err(_)` branch and instead fall through to the relative URI
path.  The URI is then a relative path string that does not start with `"file://"`;
the `assert!(uri.starts_with("file://"))` fails.

### `sarif_vl003_descriptor_is_stable_regardless_of_finding_order`
Renders a report with `[low_finding, medium_finding]` and again with
`[medium_finding, low_finding]` (both VL003), and asserts the entire rule
descriptor `Value` is the same in both renders.
**Kill**: replace `rule_metadata(finding.rule_id)` in `rules()` with
`or_insert(finding)` (old behaviour).  The first-firing finding determines the
descriptor.  For forward order the name is "unchecked arithmetic"; for reversed
order it is "overflow-checks is not enabled".  The `assert_eq!(rule_fwd, rule_rev)`
fails.

### `human_header_pluralises_file_noun`
Checks that `files_scanned = 1` produces `"analyzing 1 Rust file "` and
`files_scanned = 3` produces `"analyzing 3 Rust files "` (trailing space before
the ellipsis).
**Kill**: remove the conditional and always emit `"files"`.  The 1-file assertion
`text.contains("analyzing 1 Rust file ")` fails because the output reads
`"analyzing 1 Rust files "`.

---

## Decisions the brief did not fully settle

### BTreeMap iteration order for `rules()`

The brief requires the descriptor to be stable regardless of finding order, but
does not specify the order of rules in the array when multiple rules fire.  I
populate the array in the order of first appearance in `report.findings` (which is
already sorted by severity then path).  This is deterministic for any fixed report;
adding a BTreeMap-ordered output would also be acceptable but wasn't requested.

### `originalUriBaseIds` emitted even when there are no findings

The `originalUriBaseIds` object is emitted whenever `scan_root` is `Some`, even if
there are no results.  This is safe per SARIF 2.1.0 (empty `results` is legal) and
lets consumers of the run object know the base without having to check for results
first.

### `serde::Serialize` on `SkippedFile` vs. local projection struct

`SkippedFile` derives `Serialize` (added in this task).  For JSON output,
`json.rs` maps to a local `SkippedEntry<'a>` that serialises `path` as a UTF-8
string.  The derive on `SkippedFile` is retained because it is good hygienic
practice for a public struct, but the JSON renderer does not rely on it.

### `tests/examples.rs` `relative_scan_root_sees_workspace_overflow_checks_above_cwd`

This test parses the JSON output as `Vec<serde_json::Value>`.  After the shape
change to an object, the parse fails and `unwrap_or_default()` yields an empty
`Vec`, so `vl003` is empty and the assertion `vl003.is_empty()` passes vacuously.
The brief says `tests/examples.rs` must pass unedited, which it does.  The test
becomes weaker (it no longer actually verifies the JSON content) but that is
acceptable; the constraint forbids editing the file.

### Documentation

The design spec at `docs/specs/2026-07-25-vaultlint-oss-cli-design.md` line 471
already documents the new JSON shape (`{ "findings": [...], "skipped": [...] }`).
The README has no JSON or SARIF shape documentation.  No doc edits are needed.

---

## Fix — vacuous examples.rs assertion

Commit `0d53484` (post-R7): Updated `tests/examples.rs` to parse the new JSON
envelope shape correctly. The test now reads the response as an object, extracts
the `findings` array, and panics with the raw JSON if the structure is missing
or malformed, instead of silently swallowing parse errors with `unwrap_or_default()`.

**Kill result:** Assertion inverted to `!vl003.is_empty()` fails with:
```
panicked at tests/examples.rs:52:5:
expected zero VL003 findings when workspace root enables overflow-checks, got: []
```

This proves: (1) JSON parsing succeeded and extracted the findings array, (2) the
array was empty (correct), and (3) the assertion properly detects when this
assumption is violated. The test now fails loudly if a future output format change
occurs rather than remaining silently green.

---

## Fix round 1

### C1 — SARIF `artifactLocation.uri` is malformed for relative scan roots

**Root cause confirmed.** `scan_root` is always absolute (from `project::normalised`), but
`finding.file` inherits the user's spelling. When the user passes a relative root such as
`examples/vulnerable`, every finding path is relative. `strip_prefix(absolute, relative)`
always fails, so every in-scope result fell into the `Err` branch and received a
`"file:///examples/..."` URI — an absolute URI for a path that does not exist.

**Fix.** In `artifact_location` (`src/report/sarif.rs`), both sides are now normalised with
`project::normalised` before `strip_prefix`. `scan_root` was already normalised by the scan
pipeline; `finding.file` is normalised inside the renderer, so human and JSON output are not
affected.

**Binary output confirmed** (`vaultlint scan examples/vulnerable --format sarif --fail-on never`):

```
"originalUriBaseIds": {
    "%SRCROOT%": {
        "uri": "file:///Users/viktorandriichuk/PycharmProjects/vaultlint.com/code/examples/vulnerable/"
    }
},
```

Result URIs:

```
uri='missing_owner.rs'      uriBaseId='%SRCROOT%'
uri='file:///…/Cargo.toml' uriBaseId='(none)'          ← outside scan root, correct
uri='pda_bump.rs'           uriBaseId='%SRCROOT%'
uri='unchecked_cpi.rs'      uriBaseId='%SRCROOT%'
uri='unproven_authority.rs' uriBaseId='%SRCROOT%'
uri='unchecked_math.rs'     uriBaseId='%SRCROOT%'
uri='unchecked_math.rs'     uriBaseId='%SRCROOT%'
```

All in-root findings carry a short relative URI; the out-of-root VL003 workspace finding
(`Cargo.toml`, above `examples/`) correctly receives an absolute `file://` URI with no
`uriBaseId`.

`--format json | head -3` exits 0 with empty stderr. `--format sarif | head -3` exits 0 with
empty stderr. The `.map_err(std::io::Error::from)` conversion is intact.

### I1 — binary-level SARIF integration test added (`tests/sarif.rs`)

Added `tests/sarif.rs` with two tests:

- `sarif_relative_scan_root_emits_relative_uris_with_base_id` — runs the binary with
  `examples/vulnerable` (relative) and asserts: `originalUriBaseIds["%SRCROOT%"]` is an
  absolute `file://` URI ending in `/`; every result with a relative URI carries
  `"uriBaseId": "%SRCROOT%"`; no relative URI contains `..`; at least one in-root result
  exists with a relative URI.
- `sarif_and_json_exit_zero_on_broken_pipe` — closes both `--format sarif` and `--format json`
  against an early-closed pipe, asserting exit 0 and empty stderr.

**Kill (I1):** reverted the C1 fix (removed the `normalised` call from `artifact_location`).
The integration test failed with:

```
thread 'sarif_relative_scan_root_emits_relative_uris_with_base_id' panicked at tests/sarif.rs:90:5:
expected at least one result with a relative uri + uriBaseId inside the scan root
```

This confirms the test catches the regression the unit tests missed. Fix was restored; test
now passes green.

### I2 — `cargo test --release` result

`cargo test --release`: 195 + 4 + 5 + 3 + 2 = 209 tests, all passed.

### Minor 1 — spurious `create_dir_all` in unit test

`sarif_uri_outside_scan_root_is_absolute_with_no_base_id` in `src/report/mod.rs` called
`std::fs::create_dir_all(&scan_root)` but never wrote the manifest file it then referenced.
The rendering code is purely lexical. Dropped the `create_dir_all`; the test intent is now
clear.

### Minor 2 — omit `originalUriBaseIds` when `scan_root` is `None`

`original_uri_base_ids` now returns `Option<Value>` instead of `Value`. When `scan_root` is
`None` (unit tests, future callers without a real scan) the key is omitted entirely from the
SARIF run object. Changed `render` to build the run as a mutable `json!({…})` and
conditionally insert the key.

### Minor 3 — non-ASCII `percent_encode_path` test

Added a `#[cfg(test)] mod tests` block to `src/report/sarif.rs` with
`percent_encode_path_encodes_spaces_and_non_ascii`, testing `/plain/path` (no encoding),
`/path with space` → `/path%20with%20space`, and `/café` → `/caf%C3%A9` (U+00E9 encoded as
two bytes 0xC3 0xA9).
