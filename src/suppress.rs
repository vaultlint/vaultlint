use crate::finding::Finding;

const MARKER: &str = "vaultlint:allow";

/// True when the finding's own line, or the line directly above it, carries
/// `// vaultlint:allow <RULE_ID>`. Bare `vaultlint:allow` without an id is
/// intentionally not honoured: silencing every rule at once should be explicit.
pub fn is_suppressed(source: &str, finding: &Finding) -> bool {
    let lines: Vec<&str> = source.lines().collect();
    let index = finding.line.saturating_sub(1);
    let mut candidates = Vec::new();
    if let Some(line) = lines.get(index) {
        candidates.push(*line);
    }
    if index > 0 {
        if let Some(line) = lines.get(index - 1) {
            candidates.push(*line);
        }
    }
    candidates
        .iter()
        .any(|line| mentions(line, finding.rule_id))
}

fn mentions(line: &str, rule_id: &str) -> bool {
    let Some(position) = line.find(MARKER) else {
        return false;
    };
    line[position + MARKER.len()..].contains(rule_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::{Finding, Severity};
    use std::path::PathBuf;

    fn finding_at(line: usize) -> Finding {
        Finding {
            rule_id: "VL003",
            severity: Severity::Medium,
            title: "unchecked arithmetic",
            message: "unchecked subtraction".to_string(),
            file: PathBuf::from("state.rs"),
            line,
            column: 1,
            snippet: String::new(),
            help: "use checked_sub",
            docs_url: String::new(),
        }
    }

    const SOURCE: &str = "\
fn a() {
    // vaultlint:allow VL003 — audited, cannot underflow
    vault.balance = vault.balance - amount;
}
fn b() {
    vault.balance = vault.balance - amount; // vaultlint:allow VL003
}
fn c() {
    vault.balance = vault.balance - amount;
}
fn d() {
    // vaultlint:allow VL001
    vault.balance = vault.balance - amount;
}
";

    #[test]
    fn suppresses_from_the_line_above() {
        assert!(is_suppressed(SOURCE, &finding_at(3)));
    }

    #[test]
    fn suppresses_from_a_trailing_comment_on_the_same_line() {
        assert!(is_suppressed(SOURCE, &finding_at(6)));
    }

    #[test]
    fn leaves_unmarked_findings_alone() {
        assert!(!is_suppressed(SOURCE, &finding_at(9)));
    }

    #[test]
    fn does_not_suppress_a_different_rule_id() {
        assert!(!is_suppressed(SOURCE, &finding_at(13)));
    }
}
