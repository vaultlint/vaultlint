//! Binary-level integration tests for the SARIF and JSON output formats.
//!
//! These tests drive the real binary with a relative scan root, which is the
//! common case.  Unit tests in `src/report/mod.rs` build `ScanReport` with
//! absolute paths, so they cannot catch the `strip_prefix` mismatch that
//! C1 describes.

use std::process::Command;

/// Run `vaultlint scan <path> --format sarif --fail-on never` and return the
/// parsed SARIF value.
fn scan_sarif(path: &str) -> serde_json::Value {
    let output = Command::new(env!("CARGO_BIN_EXE_vaultlint"))
        .args(["scan", path, "--format", "sarif", "--fail-on", "never"])
        .output()
        .expect("failed to spawn vaultlint");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.stderr.is_empty(),
        "expected empty stderr, got: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("failed to parse SARIF output: {e}\n{stdout}"))
}

/// Result locations inside the scan root must carry a relative `uri` and
/// `"uriBaseId": "%SRCROOT%"`.  `originalUriBaseIds` must map `%SRCROOT%` to
/// an absolute `file://` URI.
///
/// Kill (C1): revert the C1 fix (remove the `project::normalised` call from
/// `artifact_location`).  When the scan root is relative, `strip_prefix`
/// always fails because the scan-root path used for comparison is absolute
/// while `finding.file` is relative.  Every in-scope result then falls into
/// the `Err(_)` branch and receives an absolute `file:///…` URI with no
/// `uriBaseId`.  The assertion that at least one result has `uriBaseId ==
/// "%SRCROOT%"` then fails.
#[test]
fn sarif_relative_scan_root_emits_relative_uris_with_base_id() {
    let sarif = scan_sarif("examples/vulnerable");

    let run = &sarif["runs"][0];

    // `originalUriBaseIds["%SRCROOT%"]` must be present and absolute.
    let base_uri = run["originalUriBaseIds"]["%SRCROOT%"]["uri"]
        .as_str()
        .expect("originalUriBaseIds[\"%SRCROOT%\"] must be present and have a uri");
    assert!(
        base_uri.starts_with("file://"),
        "base URI must be an absolute file:// URI, got: {base_uri:?}"
    );
    // Must end with '/' per SARIF spec.
    assert!(
        base_uri.ends_with('/'),
        "base URI must end with '/', got: {base_uri:?}"
    );

    let results = run["results"]
        .as_array()
        .expect("runs[0].results must be an array");
    assert!(
        !results.is_empty(),
        "expected at least one result from examples/vulnerable"
    );

    let mut found_in_root = false;
    for result in results {
        let loc = &result["locations"][0]["physicalLocation"]["artifactLocation"];
        let uri = loc["uri"]
            .as_str()
            .unwrap_or_else(|| panic!("result location has no uri: {result}"));

        if !uri.starts_with("file://") {
            // This is a relative URI — must be inside the scan root.
            found_in_root = true;
            // Relative URIs must not escape the scan root via `..`.
            assert!(
                !uri.contains(".."),
                "relative uri must not contain '..', got: {uri:?}"
            );
            // Every result with a relative URI must carry uriBaseId.
            assert_eq!(
                loc["uriBaseId"], "%SRCROOT%",
                "result with relative uri must have uriBaseId == %SRCROOT%, got: {loc}"
            );
        }
    }

    assert!(
        found_in_root,
        "expected at least one result with a relative uri + uriBaseId inside the scan root"
    );
}

/// `--format json` and `--format sarif` must exit 0 with empty stderr when
/// their output is truncated early (piped to `head`).  This confirms the
/// `.map_err(std::io::Error::from)` conversion is intact for both formats.
#[test]
fn sarif_and_json_exit_zero_on_broken_pipe() {
    for format in ["sarif", "json"] {
        let mut child = Command::new(env!("CARGO_BIN_EXE_vaultlint"))
            .args([
                "scan",
                "examples/vulnerable",
                "--format",
                format,
                "--fail-on",
                "never",
            ])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap_or_else(|e| panic!("failed to spawn vaultlint ({format}): {e}"));

        drop(child.stdout.take());

        let output = child
            .wait_with_output()
            .unwrap_or_else(|e| panic!("failed to wait on child ({format}): {e}"));

        let code = output.status.code();
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(
            code,
            Some(0),
            "broken pipe with --format {format} must exit 0, got {code:?}; stderr: {stderr:?}"
        );
        assert!(
            stderr.is_empty(),
            "broken pipe with --format {format} must produce no stderr, got: {stderr:?}"
        );
    }
}

// ── JSON binary-level tests ───────────────────────────────────────────────────

/// Run `vaultlint scan <path> --format json --fail-on never` and return the
/// parsed JSON envelope.
fn scan_json(path: &str) -> serde_json::Value {
    let output = Command::new(env!("CARGO_BIN_EXE_vaultlint"))
        .args(["scan", path, "--format", "json", "--fail-on", "never"])
        .output()
        .expect("failed to spawn vaultlint");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.stderr.is_empty(),
        "expected empty stderr, got: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("failed to parse JSON output: {e}\n{stdout}"))
}

/// `--format json` must produce the envelope object `{ "findings": [...],
/// "skipped": [...] }` with at least one finding when run over the vulnerable
/// examples. The finding must carry the expected fields.
///
/// Kill: revert json.rs to emit a bare array. Then `parsed["findings"]` is null
/// and the `as_array()` unwrap panics.
#[test]
fn json_format_emits_envelope_with_findings_array() {
    let json = scan_json("examples/vulnerable");

    assert!(json.is_object(), "JSON root must be an object, got: {json}");

    let findings = json["findings"]
        .as_array()
        .expect("JSON envelope must have a 'findings' array");
    assert!(
        !findings.is_empty(),
        "expected at least one finding from examples/vulnerable"
    );

    // Spot-check the first finding's required fields.
    let first = &findings[0];
    assert!(
        first["rule_id"].is_string(),
        "finding must have a string rule_id; got: {first}"
    );
    assert!(
        first["severity"].is_string(),
        "finding must have a string severity; got: {first}"
    );
    assert!(
        first["line"].is_number(),
        "finding must have a numeric line; got: {first}"
    );

    // The skipped array must also be present (even if empty).
    assert!(
        json["skipped"].is_array(),
        "JSON envelope must have a 'skipped' array; got: {json}"
    );
}

/// A directory that contains an unparseable `.rs` file must record that file in
/// the `"skipped"` array of the JSON envelope, with a non-empty `"reason"`.
/// Before the envelope was introduced, the skipped file was silently absent from
/// the output, giving CI a false "no findings" signal for code it could not read.
///
/// Kill: remove the `skipped` key from the JSON envelope in json.rs. Then
/// `json["skipped"].as_array()` returns `None` and the assertion panics.
///
/// Kill (reason field): omit the `reason` field from each `SkippedFile`
/// serialisation. Then `skipped[0]["reason"].as_str()` returns `None`.
#[test]
fn json_format_reports_unparseable_file_in_skipped_array() {
    let dir = std::env::temp_dir().join("vaultlint_r9_json_unparseable");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    // A valid file so there is at least one finding (VL004) alongside the skip.
    std::fs::write(
        dir.join("valid.rs"),
        "use solana_program::pubkey::Pubkey;\n\
         pub fn f(s: &[&[u8]], id: &Pubkey) -> Pubkey {\n\
             Pubkey::create_program_address(s, id).unwrap()\n\
         }\n",
    )
    .unwrap();
    // An unparseable file — must appear in skipped[].
    std::fs::write(dir.join("broken.rs"), "fn oops( { not valid rust").unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_vaultlint"))
        .args([
            "scan",
            dir.to_str().unwrap(),
            "--format",
            "json",
            "--fail-on",
            "never",
        ])
        .output()
        .expect("failed to spawn vaultlint");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("failed to parse JSON output: {e}\n{stdout}"));

    let skipped = json["skipped"]
        .as_array()
        .expect("JSON envelope must have a 'skipped' array");
    assert_eq!(
        skipped.len(),
        1,
        "exactly one file must be skipped; got: {skipped:?}"
    );

    let reason = skipped[0]["reason"]
        .as_str()
        .expect("skipped entry must have a 'reason' string");
    assert!(
        !reason.is_empty(),
        "skipped reason must not be empty; got: {skipped:?}"
    );
    // The reason must identify what went wrong (contains parsing error context).
    assert!(
        reason.contains("parsing"),
        "reason must describe the parse failure; got: {reason:?}"
    );

    // The valid file's finding must still appear — the skip must not suppress
    // all output from the same directory.
    let findings = json["findings"]
        .as_array()
        .expect("JSON envelope must have a 'findings' array");
    assert!(
        !findings.is_empty(),
        "findings from the valid file must appear even when another file was skipped"
    );
}
