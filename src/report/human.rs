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
    writeln!(
        out,
        "→ analyzing {} Rust files{anchor}{test_skip} …",
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
