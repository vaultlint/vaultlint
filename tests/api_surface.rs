//! Integration tests for the public API surface (task R8).
//!
//! Each test exercises one of the six R8 requirements and carries a kill comment
//! describing the minimal mutation that makes it go red.

use vaultlint::{finding::Severity, scan, ScanOptions};

// ── R8-1: `#[non_exhaustive]` + public constructor ───────────────────────────

/// `ScanOptions` must be constructed via the public constructor.
///
/// Kill: remove `ScanOptions::new`. Then this test does not compile.
#[test]
fn scan_options_can_be_constructed_via_new() {
    let dir = std::env::temp_dir().join("vaultlint_r8_scan_options_new");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("lib.rs"), "pub fn f() {}").unwrap();

    let opts = ScanOptions::new(&dir);
    let report = scan(&opts);
    assert_eq!(report.files_scanned, 1);
}

// ── R8-2: `Debug` on the public structs and anchor types ─────────────────────

/// `ScanOptions`, `ScanReport`, `SkippedFile`, and `Finding` must all implement `Debug`.
/// The anchor types (`AnchorModel`, `AccountsStruct`, `AccountField`) also derive `Debug`
/// but are no longer public; their `Debug` impls are covered by in-crate unit tests.
///
/// Kill (ScanOptions): remove `#[derive(Debug)]` from `ScanOptions`.
/// Kill (ScanReport): remove `#[derive(Debug)]` from `ScanReport`.
/// Kill (SkippedFile): remove `#[derive(Debug)]` from `SkippedFile`.
/// Kill (Finding): remove `#[derive(Debug)]` from `Finding`.
/// One kill per type breaks its assertion.
#[test]
fn public_types_implement_debug() {
    let dir = std::env::temp_dir().join("vaultlint_r8_debug_structs");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    // One unparseable file so SkippedFile is populated.
    std::fs::write(dir.join("ok.rs"), "pub fn f() {}").unwrap();
    std::fs::write(dir.join("bad.rs"), "fn { not rust").unwrap();
    // VL004 finding so Finding is populated.
    std::fs::write(
        dir.join("trigger.rs"),
        "use solana_program::pubkey::Pubkey;\n\
         pub fn f(s: &[&[u8]], id: &Pubkey) -> Pubkey {\n\
             Pubkey::create_program_address(s, id).unwrap()\n\
         }\n",
    )
    .unwrap();

    let opts = ScanOptions::new(&dir);
    // ScanOptions must implement Debug.
    let _ = format!("{opts:?}");

    let report = scan(&opts);
    // ScanReport must implement Debug.
    let _ = format!("{report:?}");

    // SkippedFile is inside the report.
    assert_eq!(
        report.skipped.len(),
        1,
        "expected one skipped file for Debug test"
    );
    let _ = format!("{:?}", report.skipped[0]);

    // Finding is inside the report.
    assert!(
        !report.findings.is_empty(),
        "expected at least one finding for Debug test"
    );
    let _ = format!("{:?}", report.findings[0]);
}

// ── R8-3: `Display` and `FromStr` for `Severity` ────────────────────────────

/// `Severity` implements `Display` and `FromStr` with a round-trip.
///
/// Kill (Display): change `Severity::High` display text to something other than "high".
/// Kill (FromStr): make `from_str` return an error for "high".
#[test]
fn severity_display_and_from_str_round_trip() {
    use std::str::FromStr;

    for (severity, text) in [
        (Severity::Low, "low"),
        (Severity::Medium, "medium"),
        (Severity::High, "high"),
    ] {
        let displayed = severity.to_string();
        assert_eq!(
            displayed, text,
            "Severity::{severity:?} Display must produce {text:?}, got {displayed:?}"
        );

        let parsed: Severity = Severity::from_str(text)
            .unwrap_or_else(|_| panic!("Severity::from_str({text:?}) must succeed"));
        assert_eq!(
            parsed, severity,
            "Severity::from_str({text:?}) must parse to {severity:?}"
        );
    }
}

/// `Severity::from_str` returns an error for unknown strings.
///
/// Kill: make `from_str` return `Ok(Severity::Low)` for unknown input.
#[test]
fn severity_from_str_rejects_unknown_strings() {
    use std::str::FromStr;
    assert!(
        Severity::from_str("CRITICAL").is_err(),
        "from_str must reject unknown severity strings"
    );
    assert!(
        Severity::from_str("").is_err(),
        "from_str must reject the empty string"
    );
}

// ── R8-4: `Deserialize` on `Finding` / `Severity` and round-trip test ────────

/// Serialise a real `ScanReport` to JSON and deserialise it back into vaultlint's
/// own types.
///
/// Kill (Deserialize derive): remove `#[derive(Deserialize)]` from `Finding`.
/// Then `serde_json::from_value::<Vec<Finding>>(…)` does not compile.
///
/// Kill (round-trip correctness): corrupt a field serialisation so the
/// deserialized value differs from the original.
#[test]
fn json_round_trip_of_scan_report() {
    use vaultlint::finding::Finding;
    use vaultlint::report::json;

    // Set up a minimal tree that produces at least one finding.
    let dir = std::env::temp_dir().join("vaultlint_r8_round_trip");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    // VL004: create_program_address without storing the canonical bump.
    std::fs::write(
        dir.join("lib.rs"),
        "use solana_program::pubkey::Pubkey;\n\
         pub fn f(seeds: &[&[u8]], id: &Pubkey) -> Pubkey {\n\
             Pubkey::create_program_address(seeds, id).unwrap()\n\
         }\n",
    )
    .unwrap();

    let opts = ScanOptions::new(&dir);
    let report = scan(&opts);
    assert!(
        !report.findings.is_empty(),
        "fixture must produce at least one finding for a meaningful round-trip"
    );

    // Serialise to JSON using the same renderer the binary uses.
    let mut buf = Vec::new();
    json::render(&report, &mut buf).unwrap();
    let json_str = String::from_utf8(buf).unwrap();

    // The envelope must have a "findings" array.
    let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
    let findings_json = parsed["findings"]
        .as_array()
        .expect("JSON envelope must have a 'findings' array");

    // Deserialise findings back into vaultlint's own type.
    let deserialized: Vec<Finding> =
        serde_json::from_value(serde_json::Value::Array(findings_json.clone()))
            .expect("findings must deserialise into Vec<Finding>");

    assert_eq!(
        deserialized.len(),
        report.findings.len(),
        "round-trip must preserve finding count"
    );
    for (original, restored) in report.findings.iter().zip(deserialized.iter()) {
        assert_eq!(
            original, restored,
            "round-trip must be lossless for every field"
        );
    }
}

/// The `skipped` array is the other half of the JSON envelope, and a consumer
/// that reads it back should not have to declare its own struct for a type
/// vaultlint already exports.
///
/// Kill (Deserialize derive): remove `#[derive(Deserialize)]` from
/// `SkippedFile`. Then `serde_json::from_value::<Vec<SkippedFile>>(…)` does not
/// compile.
#[test]
fn json_round_trip_of_skipped_files() {
    use vaultlint::report::json;
    use vaultlint::SkippedFile;

    let dir = std::env::temp_dir().join("vaultlint_round_trip_skipped");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("Cargo.toml"), "[package]\nname = \"x\"\n").unwrap();
    std::fs::write(dir.join("broken.rs"), "pub fn f( {").unwrap();

    let report = scan(&ScanOptions::new(&dir));
    assert_eq!(
        report.skipped.len(),
        1,
        "fixture must produce exactly one skipped file"
    );

    let mut buf = Vec::new();
    json::render(&report, &mut buf).unwrap();
    let parsed: serde_json::Value = serde_json::from_slice(&buf).unwrap();

    let restored: Vec<SkippedFile> = serde_json::from_value(parsed["skipped"].clone())
        .expect("skipped must deserialise into Vec<SkippedFile>");
    assert_eq!(restored, report.skipped);
}
