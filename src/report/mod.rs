pub mod human;
pub mod json;
pub mod sarif;

use crate::finding::Severity;
use crate::ScanReport;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Human,
    Json,
    Sarif,
}

pub fn render(
    report: &ScanReport,
    format: Format,
    out: &mut dyn std::io::Write,
    colour: bool,
) -> anyhow::Result<()> {
    match format {
        Format::Human => human::render(report, out, colour)?,
        Format::Json => json::render(report, out)?,
        Format::Sarif => sarif::render(report, out)?,
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailOn {
    High,
    Medium,
    Low,
    Never,
}

impl FailOn {
    pub fn threshold(self) -> Option<Severity> {
        match self {
            FailOn::High => Some(Severity::High),
            FailOn::Medium => Some(Severity::Medium),
            FailOn::Low => Some(Severity::Low),
            FailOn::Never => None,
        }
    }
}

pub fn exit_code(report: &ScanReport, fail_on: FailOn) -> i32 {
    let Some(threshold) = fail_on.threshold() else {
        return 0;
    };
    i32::from(
        report
            .findings
            .iter()
            .any(|finding| finding.severity >= threshold),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::{Finding, Severity};
    use crate::{ScanReport, SkippedFile};
    use std::path::PathBuf;

    fn finding(severity: Severity) -> Finding {
        Finding {
            rule_id: "VL002",
            severity,
            title: "missing owner check",
            message: "`vault` is deserialised without an owner check.".to_string(),
            file: PathBuf::from("programs/staking/src/withdraw.rs"),
            line: 42,
            column: 9,
            snippet: "pub authority: AccountInfo<'info>,".to_string(),
            help: "Use `Account<'info, T>`, which checks the owner.",
            docs_url: "https://vaultlint.com/rules/VL002".to_string(),
        }
    }

    fn report(findings: Vec<Finding>) -> ScanReport {
        ScanReport {
            files_scanned: 14,
            test_files_skipped: 0,
            anchor_version: Some("0.30.1".to_string()),
            findings,
            skipped: Vec::<SkippedFile>::new(),
            scan_root: None,
        }
    }

    #[test]
    fn human_output_shows_severity_location_and_summary() {
        let mut out = Vec::new();
        human::render(&report(vec![finding(Severity::High)]), &mut out, false).unwrap();
        let text = String::from_utf8(out).unwrap();

        assert!(text.contains("analyzing 14 Rust files (Anchor 0.30.1)"));
        assert!(text.contains("HIGH  missing owner check"));
        assert!(text.contains("programs/staking/src/withdraw.rs:42"));
        assert!(text.contains("1 issue found · 1 high · 0 medium"));
    }

    #[test]
    fn human_output_is_reassuring_when_clean() {
        let mut out = Vec::new();
        human::render(&report(Vec::new()), &mut out, false).unwrap();
        let text = String::from_utf8(out).unwrap();

        assert!(text.contains("no issues found"));
    }

    #[test]
    fn exit_code_respects_the_threshold() {
        let medium = report(vec![finding(Severity::Medium)]);

        assert_eq!(exit_code(&medium, FailOn::High), 0);
        assert_eq!(exit_code(&medium, FailOn::Medium), 1);
        assert_eq!(exit_code(&medium, FailOn::Never), 0);
        assert_eq!(exit_code(&report(Vec::new()), FailOn::Low), 0);
    }

    // ── JSON ──────────────────────────────────────────────────────────────────

    /// Kill: revert json.rs to emit a bare array.
    /// Then `parsed["findings"]` is null and the assertion fails.
    #[test]
    fn json_output_is_an_object_with_findings_and_skipped_keys() {
        let mut out = Vec::new();
        json::render(&report(vec![finding(Severity::High)]), &mut out).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&out).unwrap();

        assert!(parsed.is_object(), "root must be an object, not an array");
        assert_eq!(parsed["findings"][0]["rule_id"], "VL002");
        assert_eq!(parsed["findings"][0]["severity"], "high");
        assert_eq!(parsed["findings"][0]["line"], 42);
        assert_eq!(
            parsed["findings"][0]["docs_url"],
            "https://vaultlint.com/rules/VL002"
        );
    }

    /// Kill: remove `skipped` from the JSON object.
    /// Then `parsed["skipped"]` is null and the assertion fails.
    #[test]
    fn json_output_includes_skipped_files() {
        let mut r = report(vec![]);
        r.skipped.push(SkippedFile {
            path: PathBuf::from("programs/broken.rs"),
            reason: "unexpected token".to_string(),
        });
        let mut out = Vec::new();
        json::render(&r, &mut out).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&out).unwrap();

        let skipped = parsed["skipped"].as_array().unwrap();
        assert_eq!(skipped.len(), 1);
        assert_eq!(skipped[0]["path"], "programs/broken.rs");
        assert_eq!(skipped[0]["reason"], "unexpected token");
    }

    // ── SARIF ─────────────────────────────────────────────────────────────────

    #[test]
    fn sarif_output_carries_tool_rules_and_locations() {
        let mut out = Vec::new();
        sarif::render(&report(vec![finding(Severity::Medium)]), &mut out).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&out).unwrap();

        assert_eq!(parsed["version"], "2.1.0");
        assert_eq!(parsed["runs"][0]["tool"]["driver"]["name"], "vaultlint");
        let result = &parsed["runs"][0]["results"][0];
        assert_eq!(result["ruleId"], "VL002");
        assert_eq!(result["level"], "warning");
        assert_eq!(
            result["locations"][0]["physicalLocation"]["region"]["startLine"],
            42
        );
    }

    #[test]
    fn sarif_declares_every_rule_that_produced_a_finding_once() {
        let mut out = Vec::new();
        sarif::render(
            &report(vec![finding(Severity::High), finding(Severity::Medium)]),
            &mut out,
        )
        .unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&out).unwrap();

        let rules = parsed["runs"][0]["tool"]["driver"]["rules"]
            .as_array()
            .unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0]["id"], "VL002");
    }

    /// Kill: remove `invocations` from the SARIF run.
    /// Then `parsed["runs"][0]["invocations"]` is null and the len assertion fails.
    #[test]
    fn sarif_skipped_files_appear_in_invocation_notifications() {
        let mut r = report(vec![]);
        r.skipped.push(SkippedFile {
            path: PathBuf::from("programs/broken.rs"),
            reason: "unexpected token".to_string(),
        });
        let mut out = Vec::new();
        sarif::render(&r, &mut out).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&out).unwrap();

        let notifs = parsed["runs"][0]["invocations"][0]["toolExecutionNotifications"]
            .as_array()
            .unwrap();
        assert_eq!(notifs.len(), 1);
        assert_eq!(notifs[0]["level"], "note");
        let msg = notifs[0]["message"]["text"].as_str().unwrap();
        assert!(
            msg.contains("programs/broken.rs"),
            "notification must include the path: {msg:?}"
        );
    }

    /// Kill: remove the `uriBaseId` field from the location.
    /// Then `uriBaseId` is null and the assertion fails.
    #[test]
    fn sarif_uri_inside_scan_root_is_relative_with_base_id() {
        use std::env::temp_dir;
        let scan_root = temp_dir().join("vaultlint_r7_sarif_uri_base");
        std::fs::create_dir_all(&scan_root).unwrap();

        let mut r = ScanReport {
            files_scanned: 1,
            test_files_skipped: 0,
            anchor_version: None,
            findings: vec![Finding {
                rule_id: "VL002",
                severity: Severity::High,
                title: "missing owner check",
                message: "test".to_string(),
                file: scan_root.join("src/lib.rs"),
                line: 1,
                column: 1,
                snippet: String::new(),
                help: "fix it",
                docs_url: "https://vaultlint.com/rules/VL002".to_string(),
            }],
            skipped: vec![],
            scan_root: None,
        };
        r.scan_root = Some(scan_root.clone());
        let mut out = Vec::new();
        sarif::render(&r, &mut out).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&out).unwrap();

        let loc = &parsed["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
            ["artifactLocation"];
        assert_eq!(loc["uriBaseId"], "%SRCROOT%");
        assert_eq!(loc["uri"], "src/lib.rs");
    }

    /// Kill: remove the branch that emits an absolute URI for out-of-root paths.
    /// Then an out-of-root path gets a relative URI and the assertion that the
    /// uri starts with "file://" fails.
    #[test]
    fn sarif_uri_outside_scan_root_is_absolute_with_no_base_id() {
        use std::env::temp_dir;
        let scan_root = temp_dir().join("vaultlint_r7_sarif_uri_abs/member/src");
        std::fs::create_dir_all(&scan_root).unwrap();
        let workspace_manifest = temp_dir().join("vaultlint_r7_sarif_uri_abs/Cargo.toml");

        let mut r = ScanReport {
            files_scanned: 1,
            test_files_skipped: 0,
            anchor_version: None,
            findings: vec![Finding {
                rule_id: "VL003",
                severity: Severity::Medium,
                title: "overflow-checks is not enabled",
                message: "test".to_string(),
                file: workspace_manifest.clone(),
                line: 1,
                column: 1,
                snippet: String::new(),
                help: "fix it",
                docs_url: "https://vaultlint.com/rules/VL003".to_string(),
            }],
            skipped: vec![],
            scan_root: None,
        };
        r.scan_root = Some(scan_root.clone());
        let mut out = Vec::new();
        sarif::render(&r, &mut out).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&out).unwrap();

        let loc = &parsed["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
            ["artifactLocation"];
        // No uriBaseId for out-of-root paths.
        assert!(
            loc.get("uriBaseId").is_none() || loc["uriBaseId"].is_null(),
            "out-of-root paths must not have uriBaseId"
        );
        let uri = loc["uri"].as_str().unwrap();
        assert!(
            uri.starts_with("file://"),
            "out-of-root path must be an absolute file:// URI, got: {uri:?}"
        );
    }

    /// Kill: use `or_insert(finding)` for de-duplication instead of rule-level
    /// metadata.  The descriptor's `name` then depends on insertion order and the
    /// order-reversed assertion will see a different name.
    #[test]
    fn sarif_vl003_descriptor_is_stable_regardless_of_finding_order() {
        let low_finding = Finding {
            rule_id: "VL003",
            severity: Severity::Low,
            title: "unchecked arithmetic",
            message: "op".to_string(),
            file: PathBuf::from("src/lib.rs"),
            line: 3,
            column: 1,
            snippet: String::new(),
            help: "use checked_add",
            docs_url: "https://vaultlint.com/rules/VL003".to_string(),
        };
        let medium_finding = Finding {
            rule_id: "VL003",
            severity: Severity::Medium,
            title: "overflow-checks is not enabled",
            message: "workspace".to_string(),
            file: PathBuf::from("Cargo.toml"),
            line: 1,
            column: 1,
            snippet: String::new(),
            help: "add overflow-checks = true",
            docs_url: "https://vaultlint.com/rules/VL003".to_string(),
        };

        let render_with = |findings: Vec<Finding>| -> serde_json::Value {
            let r = report(findings);
            let mut out = Vec::new();
            sarif::render(&r, &mut out).unwrap();
            serde_json::from_slice::<serde_json::Value>(&out).unwrap()
        };

        let fwd = render_with(vec![low_finding.clone(), medium_finding.clone()]);
        let rev = render_with(vec![medium_finding, low_finding]);

        let rule_fwd = &fwd["runs"][0]["tool"]["driver"]["rules"][0];
        let rule_rev = &rev["runs"][0]["tool"]["driver"]["rules"][0];

        assert_eq!(
            rule_fwd, rule_rev,
            "VL003 rule descriptor must be byte-identical regardless of finding order"
        );
    }

    // ── Human ─────────────────────────────────────────────────────────────────

    /// Kill: remove the plural branch in human.rs so it always says "file".
    /// Then "analyzing 1 Rust file" stays "analyzing 1 Rust files" or vice versa,
    /// and one of the two assertions fails.
    #[test]
    fn human_header_pluralises_file_noun() {
        let mut r = report(vec![]);
        r.files_scanned = 1;
        let mut out = Vec::new();
        human::render(&r, &mut out, false).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(
            text.contains("analyzing 1 Rust file "),
            "singular form must be 'file', got: {text:?}"
        );

        r.files_scanned = 3;
        let mut out2 = Vec::new();
        human::render(&r, &mut out2, false).unwrap();
        let text2 = String::from_utf8(out2).unwrap();
        assert!(
            text2.contains("analyzing 3 Rust files "),
            "plural form must be 'files', got: {text2:?}"
        );
    }
}
