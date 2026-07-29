use std::io::Write;

use owo_colors::OwoColorize;

use crate::finding::{Finding, Severity};
use crate::onchain::State;
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

    render_deployments(report, out, colour)?;

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
        if let Some(live) = live_at(&finding.live_at) {
            writeln!(out, "        {}", emphasise(&live, colour))?;
        }
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

/// What the cluster says about each declared program id.
///
/// Printed above the findings and never as one: this is the state of the
/// deployment, not a defect in the source, and the reader needs it before the
/// findings to know whether any of them are running.
fn render_deployments(
    report: &ScanReport,
    out: &mut dyn Write,
    colour: bool,
) -> std::io::Result<()> {
    if report.deployments.is_empty() {
        return Ok(());
    }
    let noun = if report.deployments.len() == 1 {
        "program id"
    } else {
        "program ids"
    };
    writeln!(
        out,
        "\n→ on chain · {} declared {noun}",
        report.deployments.len()
    )?;
    for deployment in &report.deployments {
        let address = if colour {
            deployment.declared.address.bold().to_string()
        } else {
            deployment.declared.address.clone()
        };
        writeln!(out, "  {address}  {}", describe(&deployment.state))?;
    }
    Ok(())
}

fn describe(state: &State) -> String {
    match state {
        State::Absent => "no account at this address".to_string(),
        State::NotAProgram { owner } => format!("not a program — owned by {owner}"),
        State::Immutable => {
            "deployed, non-upgradeable loader — the code cannot be replaced".to_string()
        }
        State::Frozen { last_deploy_slot } => {
            format!("deployed, upgrade authority revoked — last deploy at slot {last_deploy_slot}")
        }
        State::Upgradeable {
            authority,
            last_deploy_slot,
        } => format!("upgradeable by {authority} — last deploy at slot {last_deploy_slot}"),
        State::Unavailable { reason } => format!("could not be checked: {reason}"),
    }
}

/// The sentence that turns a finding about a repository into a finding about a
/// running program, or `None` when nothing the crate declares is live.
///
/// One address is named because naming it is the whole point — the reader can
/// paste it into an explorer. Beyond two, the list stops being readable and the
/// count carries the claim instead; the on-chain section above has already
/// spelled every address out once, so nothing is lost.
fn live_at(addresses: &[String]) -> Option<String> {
    match addresses {
        [] => None,
        [one] => Some(format!("live on mainnet at {one}")),
        [first, rest @ ..] => Some(format!(
            "live on mainnet at {first} and {} more declared here",
            rest.len()
        )),
    }
}

fn emphasise(text: &str, colour: bool) -> String {
    if colour {
        text.bold().to_string()
    } else {
        text.to_string()
    }
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
                live_at: Vec::new(),
            }],
            skipped: Vec::new(),
            program_ids: Vec::new(),
            deployments: Vec::new(),
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

    /// An offline scan must not gain a section about a cluster it never asked.
    ///
    /// Kill: print the heading unconditionally in `render_deployments`.
    #[test]
    fn an_offline_report_says_nothing_about_a_cluster() {
        assert!(!render_to_string(false).contains("on chain"));
    }

    /// Each state has to read as a different claim. `Absent` in particular must
    /// not be phrased as immutability — eight ids in the measured corpus are
    /// absent and none of the forty-four live ones are frozen.
    ///
    /// Kill: collapse any two arms of `describe` into one string.
    #[test]
    fn every_deployment_state_reads_differently() {
        let lines: Vec<String> = [
            State::Absent,
            State::NotAProgram {
                owner: "Tokenkeg".to_string(),
            },
            State::Immutable,
            State::Frozen {
                last_deploy_slot: 1,
            },
            State::Upgradeable {
                authority: "AUTH".to_string(),
                last_deploy_slot: 2,
            },
            State::Unavailable {
                reason: "timeout".to_string(),
            },
        ]
        .iter()
        .map(describe)
        .collect();

        let unique: std::collections::BTreeSet<&String> = lines.iter().collect();
        assert_eq!(unique.len(), lines.len(), "{lines:?}");
        assert!(lines[4].contains("AUTH") && lines[4].contains('2'));
        assert!(lines[5].contains("timeout"));
    }

    /// A finding in code nobody deployed must not be dressed as one in code that
    /// is running, and the address has to be named — "somewhere on mainnet" is
    /// not something a reader can check.
    ///
    /// Kill: print the line for an empty `live_at`, or drop the address from it.
    #[test]
    fn the_live_line_names_an_address_and_appears_only_when_there_is_one() {
        assert_eq!(live_at(&[]), None);
        assert_eq!(
            live_at(&["M2mx".to_string()]).unwrap(),
            "live on mainnet at M2mx"
        );
        assert_eq!(
            live_at(&["M2mx".to_string(), "GTuv".to_string(), "Time".to_string()]).unwrap(),
            "live on mainnet at M2mx and 2 more declared here"
        );
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
