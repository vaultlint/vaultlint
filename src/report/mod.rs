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

    #[test]
    fn json_output_is_a_flat_array_of_findings() {
        let mut out = Vec::new();
        json::render(&report(vec![finding(Severity::High)]), &mut out).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&out).unwrap();

        assert_eq!(parsed[0]["rule_id"], "VL002");
        assert_eq!(parsed[0]["severity"], "high");
        assert_eq!(parsed[0]["line"], 42);
        assert_eq!(parsed[0]["docs_url"], "https://vaultlint.com/rules/VL002");
    }

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
            result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            "programs/staking/src/withdraw.rs"
        );
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
}
