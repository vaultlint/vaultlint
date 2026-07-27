use std::path::PathBuf;
use std::process::Command;

use vaultlint::{scan, ScanOptions};

fn findings_in(directory: &str) -> Vec<(String, String, usize)> {
    let report = scan(&ScanOptions {
        root: PathBuf::from(directory),
    });
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
