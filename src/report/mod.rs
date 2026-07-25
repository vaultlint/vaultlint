pub mod human;

use crate::finding::Severity;
use crate::ScanReport;

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
            rule_id: "VL001",
            severity,
            title: "missing signer check",
            message: "`authority` is not constrained as Signer.".to_string(),
            file: PathBuf::from("programs/staking/src/withdraw.rs"),
            line: 42,
            column: 9,
            snippet: "pub authority: AccountInfo<'info>,".to_string(),
            help: "Declare the field as `Signer<'info>`.",
            docs_url: "https://vaultlint.com/rules/VL001".to_string(),
        }
    }

    fn report(findings: Vec<Finding>) -> ScanReport {
        ScanReport {
            files_scanned: 14,
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
        assert!(text.contains("HIGH  missing signer check"));
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
}
