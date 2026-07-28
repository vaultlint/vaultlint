//! Binary-level integration tests for the SARIF output format.
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
