use std::process::Command;

use vaultlint::{scan, ScanOptions};

/// A relative scan root whose workspace root lives above the process CWD must
/// resolve the workspace root correctly and emit zero VL003 findings when the
/// root enables `overflow-checks`.
///
/// Kill: drop the `std::path::absolute` call from `normalised`, so the walk
/// stops at the CWD and the member manifest decides.
#[test]
fn relative_scan_root_sees_workspace_overflow_checks_above_cwd() {
    let dir = std::env::temp_dir().join("vaultlint_c2_relative_root");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("member/src")).unwrap();
    // Workspace root enables overflow-checks.
    std::fs::write(
        dir.join("Cargo.toml"),
        "[workspace]\nmembers = [\"member\"]\n\n[profile.release]\noverflow-checks = true\n",
    )
    .unwrap();
    // Member has no profile of its own.
    std::fs::write(
        dir.join("member/Cargo.toml"),
        "[package]\nname = \"member\"\n",
    )
    .unwrap();
    // One unchecked write — would trigger VL003 if the member manifest decided.
    std::fs::write(
        dir.join("member/src/lib.rs"),
        "pub fn f(v: &mut V, a: u64) { v.x = v.x - a; }\n",
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_vaultlint"))
        .current_dir(dir.join("member"))
        .args(["scan", "src", "--format", "json", "--fail-on", "never"])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    let response: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|_| panic!("failed to parse JSON output: {}", stdout));
    let findings = response["findings"]
        .as_array()
        .unwrap_or_else(|| panic!("response must have 'findings' array, got: {}", response));
    let vl003: Vec<_> = findings
        .iter()
        .filter(|f| f["rule_id"].as_str() == Some("VL003"))
        .collect();
    assert!(
        vl003.is_empty(),
        "expected zero VL003 findings when workspace root enables overflow-checks, got: {vl003:?}"
    );
}

fn findings_in(directory: &str) -> Vec<(String, String, usize)> {
    let report = scan(&ScanOptions::new(directory));
    let mut found: Vec<(String, String, usize)> = report
        .findings
        .iter()
        .map(|finding| {
            (
                finding.rule_id.to_string(),
                finding.file.to_string_lossy().replace('\\', "/"),
                finding.line,
            )
        })
        .collect();
    found.sort();
    found
}

#[test]
fn the_clean_example_produces_no_findings() {
    let found = findings_in("examples/clean");

    assert!(
        found.is_empty(),
        "a rule fired on correct code — this is a false positive: {found:?}"
    );
}

#[test]
fn every_vulnerable_example_is_detected_at_the_expected_line() {
    let mut expected = vec![
        (
            "VL001".to_string(),
            "examples/vulnerable/unproven_authority.rs".to_string(),
            27,
        ),
        (
            "VL002".to_string(),
            "examples/vulnerable/missing_owner.rs".to_string(),
            5,
        ),
        ("VL003".to_string(), "Cargo.toml".to_string(), 1),
        (
            "VL003".to_string(),
            "examples/vulnerable/unchecked_math.rs".to_string(),
            4,
        ),
        (
            "VL003".to_string(),
            "examples/vulnerable/unchecked_math.rs".to_string(),
            5,
        ),
        (
            "VL004".to_string(),
            "examples/vulnerable/pda_bump.rs".to_string(),
            7,
        ),
        (
            "VL005".to_string(),
            "examples/vulnerable/unchecked_cpi.rs".to_string(),
            10,
        ),
    ];
    expected.sort();

    assert_eq!(findings_in("examples/vulnerable"), expected);
}

#[test]
fn the_binary_fails_the_build_on_high_severity_findings() {
    let status = Command::new(env!("CARGO_BIN_EXE_vaultlint"))
        .args(["scan", "examples/vulnerable"])
        .status()
        .unwrap();

    assert_eq!(status.code(), Some(1));
}

#[test]
fn the_binary_succeeds_on_clean_code() {
    let status = Command::new(env!("CARGO_BIN_EXE_vaultlint"))
        .args(["scan", "examples/clean"])
        .status()
        .unwrap();

    assert_eq!(status.code(), Some(0));
}
