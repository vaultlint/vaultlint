pub mod anchor;
pub mod finding;
pub mod parse;
pub mod project;
pub mod report;
pub mod rules;
pub mod scan;
pub mod suppress;

use std::path::PathBuf;

use finding::Finding;
use rules::RuleContext;

pub struct ScanOptions {
    pub root: PathBuf,
}

pub struct SkippedFile {
    pub path: PathBuf,
    pub reason: String,
}

pub struct ScanReport {
    pub files_scanned: usize,
    pub anchor_version: Option<String>,
    pub findings: Vec<Finding>,
    pub skipped: Vec<SkippedFile>,
}

pub fn scan(options: &ScanOptions) -> ScanReport {
    let project = project::detect(&options.root);
    let rules = rules::all();
    let mut findings = Vec::new();
    let mut skipped = Vec::new();
    let mut files_scanned = 0;

    for path in scan::rust_files(&options.root) {
        match parse::parse(&path) {
            Ok(file) => {
                files_scanned += 1;
                let anchor = anchor::build(&file.ast);
                let ctx = RuleContext {
                    path: &file.path,
                    source: &file.source,
                    ast: &file.ast,
                    anchor: &anchor,
                    overflow_checks: project.overflow_checks,
                };
                let mut file_findings = Vec::new();
                for rule in &rules {
                    rule.check(&ctx, &mut file_findings);
                }
                file_findings.retain(|finding| !suppress::is_suppressed(&file.source, finding));
                findings.append(&mut file_findings);
            }
            Err(error) => skipped.push(SkippedFile {
                path,
                reason: error.to_string(),
            }),
        }
    }

    // Most severe first, then stable by location — one ordering for every renderer.
    findings.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| a.file.cmp(&b.file))
            .then_with(|| a.line.cmp(&b.line))
    });

    ScanReport {
        files_scanned,
        anchor_version: project.anchor_version,
        findings,
        skipped,
    }
}

pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[cfg(test)]
mod tests {
    #[test]
    fn version_is_reported() {
        assert_eq!(super::version(), "0.1.0");
    }
}

#[cfg(test)]
mod scan_tests {
    use super::*;
    use std::fs;

    #[test]
    fn scans_a_directory_and_skips_unparsable_files() {
        let dir = std::env::temp_dir().join("vaultlint_scan_integration");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("withdraw.rs"),
            "#[derive(Accounts)]\npub struct W<'info> {\n    #[account(mut)]\n    pub vault: Account<'info, Vault>,\n    pub authority: AccountInfo<'info>,\n}\n",
        )
        .unwrap();
        fs::write(dir.join("broken.rs"), "fn ( { not rust").unwrap();

        let report = scan(&ScanOptions { root: dir.clone() });

        assert_eq!(report.files_scanned, 1);
        assert_eq!(report.skipped.len(), 1);
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].rule_id, "VL001");
        assert!(report.findings[0].file.ends_with("withdraw.rs"));
    }

    #[test]
    fn scan_drops_suppressed_findings() {
        let dir = std::env::temp_dir().join("vaultlint_suppress_integration");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("withdraw.rs"),
            "#[derive(Accounts)]\npub struct W<'info> {\n    // vaultlint:allow VL001 — checked elsewhere\n    pub authority: AccountInfo<'info>,\n}\n",
        )
        .unwrap();

        let report = scan(&ScanOptions { root: dir });

        assert!(report.findings.is_empty());
    }
}
