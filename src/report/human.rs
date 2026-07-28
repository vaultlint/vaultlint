use std::io::Write;

use owo_colors::OwoColorize;

use crate::finding::{Finding, Severity};
use crate::ScanReport;

pub fn render(report: &ScanReport, out: &mut dyn Write, colour: bool) -> std::io::Result<()> {
    let anchor = report
        .anchor_version
        .as_ref()
        .map(|version| format!(" (Anchor {version})"))
        .unwrap_or_default();
    let test_skip = if report.test_files_skipped > 0 {
        format!(" ({} test files skipped)", report.test_files_skipped)
    } else {
        String::new()
    };
    let file_noun = if report.files_scanned == 1 {
        "file"
    } else {
        "files"
    };
    writeln!(
        out,
        "→ analyzing {} Rust {file_noun}{anchor}{test_skip} …",
        report.files_scanned
    )?;

    for skipped in &report.skipped {
        writeln!(
            out,
            "  skipped {}: {}",
            skipped.path.display(),
            skipped.reason
        )?;
    }

    if report.findings.is_empty() {
        writeln!(out, "\n✓ no issues found")?;
        return Ok(());
    }

    for finding in &report.findings {
        writeln!(out)?;
        writeln!(
            out,
            "{} {}  {}",
            marker(finding.severity, colour),
            label(finding.severity, colour),
            finding.title
        )?;
        writeln!(out, "        {}:{}", finding.file.display(), finding.line)?;
        writeln!(out, "        {}", finding.message)?;
        writeln!(out, "        {}", finding.help)?;
        writeln!(out, "        {}", link(&finding.docs_url, colour))?;
    }

    let high = count(report, Severity::High);
    let medium = count(report, Severity::Medium);
    let low = count(report, Severity::Low);
    let total = report.findings.len();
    let noun = if total == 1 { "issue" } else { "issues" };
    write!(
        out,
        "\n{total} {noun} found · {high} high · {medium} medium"
    )?;
    if low > 0 {
        write!(out, " · {low} low")?;
    }
    writeln!(out)
}

/// The rule's documentation page. It is also the only place the human report
/// spells the rule id, which is what a `// vaultlint:allow VL002` comment
/// needs — the alternative, a column of ids in the heading, would say the same
/// thing twice.
fn link(url: &str, colour: bool) -> String {
    if colour {
        url.dimmed().to_string()
    } else {
        url.to_string()
    }
}

fn count(report: &ScanReport, severity: Severity) -> usize {
    report
        .findings
        .iter()
        .filter(|finding: &&Finding| finding.severity == severity)
        .count()
}

fn marker(severity: Severity, colour: bool) -> String {
    let symbol = match severity {
        Severity::High => "✗",
        Severity::Medium | Severity::Low => "⚠",
    };
    paint(symbol, severity, colour)
}

fn label(severity: Severity, colour: bool) -> String {
    paint(severity.label(), severity, colour)
}

fn paint(text: &str, severity: Severity, colour: bool) -> String {
    if !colour {
        return text.to_string();
    }
    match severity {
        Severity::High => text.red().bold().to_string(),
        Severity::Medium => text.yellow().to_string(),
        Severity::Low => text.blue().to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one_finding_report() -> ScanReport {
        ScanReport {
            files_scanned: 1,
            test_files_skipped: 0,
            anchor_version: None,
            findings: vec![Finding {
                rule_id: "VL002".into(),
                severity: Severity::High,
                title: "missing owner check".into(),
                message: "message".to_string(),
                file: std::path::PathBuf::from("lib.rs"),
                line: 5,
                column: 1,
                snippet: String::new(),
                help: "help".into(),
                docs_url: "https://vaultlint.com/rules/VL002/".to_string(),
            }],
            skipped: Vec::new(),
            scan_root: None,
        }
    }

    fn render_to_string(colour: bool) -> String {
        let mut out = Vec::new();
        render(&one_finding_report(), &mut out, colour).expect("writing to a Vec cannot fail");
        String::from_utf8(out).expect("output is UTF-8")
    }

    /// The URL is the only place the human report names the rule, so a reader
    /// who wants to suppress the finding has nowhere else to read `VL002` from.
    ///
    /// Killing mutation: drop the `docs_url` line from the finding loop.
    #[test]
    fn a_finding_carries_its_documentation_url() {
        assert!(render_to_string(false).contains("https://vaultlint.com/rules/VL002/"));
    }

    /// Piped output must stay free of escape sequences — CI logs and `grep` see
    /// this, and a colour code in the middle of the URL breaks a copy-paste.
    ///
    /// Killing mutation: in `link`, return `url.dimmed().to_string()`
    /// unconditionally.
    #[test]
    fn the_url_is_unstyled_when_colour_is_off() {
        assert!(!render_to_string(false).contains('\u{1b}'));
    }
}
