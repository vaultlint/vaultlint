pub mod anchor;
pub mod finding;
pub mod parse;
pub mod project;
pub mod report;
pub mod rules;
pub mod scan;
pub mod scope;
pub mod suppress;
pub mod usesite;

use std::collections::BTreeSet;
use std::path::PathBuf;

use finding::Finding;
use rules::{LinkedContext, RuleContext};
use usesite::UseSiteIndex;

pub struct ScanOptions {
    pub root: PathBuf,
}

pub struct SkippedFile {
    pub path: PathBuf,
    pub reason: String,
}

pub struct ScanReport {
    pub files_scanned: usize,
    pub test_files_skipped: usize,
    pub anchor_version: Option<String>,
    pub findings: Vec<Finding>,
    pub skipped: Vec<SkippedFile>,
}

pub fn scan(options: &ScanOptions) -> ScanReport {
    let project = project::detect(&options.root);
    let workspace_resolver = project::WorkspaceResolver::new(&options.root);
    let rules = rules::all();
    let linked_rules = rules::linked_all();
    let mut findings = Vec::new();
    let mut skipped = Vec::new();
    let mut files_scanned = 0;
    let mut test_files_skipped = 0;
    let mut index = UseSiteIndex::empty();
    let mut linked_files = Vec::new();
    let mut roots_without_overflow_checks: BTreeSet<PathBuf> = BTreeSet::new();

    // Collect all candidate files first so M3 can be resolved across the tree.
    let all_files = scan::rust_files(&options.root);
    let m3_set = scope::collect_m3_set(&all_files);

    // Phase 1: run the file-local rules and record the facts the linked rules
    // will need. The AST is dropped as each file finishes.
    for path in all_files {
        // M1–M3: skip the file entirely before parsing.
        if scope::is_test_scope(&path, &m3_set) {
            test_files_skipped += 1;
            continue;
        }

        match parse::parse(&path) {
            Ok(file) => {
                files_scanned += 1;
                // M4: compute inline #[cfg(test)] mod ranges for this file.
                let test_ranges = scope::test_ranges(&file.ast);

                let workspace = workspace_resolver.resolve(&file.path);
                let anchor = anchor::build(&file.ast);
                let ctx = RuleContext {
                    path: &file.path,
                    source: &file.source,
                    ast: &file.ast,
                    anchor: &anchor,
                    overflow_checks: workspace.overflow_checks,
                };
                let mut file_findings = Vec::new();
                for rule in &rules {
                    rule.check(&ctx, &mut file_findings);
                }
                file_findings.retain(|finding| {
                    !suppress::is_suppressed(&file.source, finding)
                        && !scope::in_test_range(finding.line, &test_ranges)
                });

                if !workspace.overflow_checks {
                    if let Some(manifest) = &workspace.manifest {
                        if file_findings
                            .iter()
                            .any(|finding| finding.rule_id == "VL003")
                        {
                            roots_without_overflow_checks.insert(manifest.clone());
                        }
                    }
                }

                findings.append(&mut file_findings);

                if !anchor.accounts_structs.is_empty() {
                    linked_files.push(file.path.clone());
                }
                index.insert(&file.path, usesite::collect_facts(&file.ast));
            }
            Err(error) => skipped.push(SkippedFile {
                path,
                reason: format!("{error:#}"),
            }),
        }
    }

    for manifest in &roots_without_overflow_checks {
        findings.push(rules::arithmetic::overflow_checks_finding(manifest));
    }

    // Phase 2: only files declaring an `Accounts` struct can produce a linked
    // finding, and that is a small fraction of any repo. A file phase 1 already
    // accepted is never reported as skipped a second time.
    for path in &linked_files {
        let Ok(file) = parse::parse(path) else {
            continue;
        };
        let test_ranges = scope::test_ranges(&file.ast);
        let anchor = anchor::build(&file.ast);
        let ctx = LinkedContext {
            path: &file.path,
            source: &file.source,
            anchor: &anchor,
            index: &index,
        };
        let mut file_findings = Vec::new();
        for rule in &linked_rules {
            rule.check(&ctx, &mut file_findings);
        }
        file_findings.retain(|finding| {
            !suppress::is_suppressed(&file.source, finding)
                && !scope::in_test_range(finding.line, &test_ranges)
        });
        findings.append(&mut file_findings);
    }

    // Most severe first, then by location — one ordering for every renderer.
    // The rule id is the final tiebreak so that two findings on the same line
    // keep their order regardless of which phase produced them.
    findings.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| a.file.cmp(&b.file))
            .then_with(|| a.line.cmp(&b.line))
            .then_with(|| a.rule_id.cmp(b.rule_id))
    });

    ScanReport {
        files_scanned,
        test_files_skipped,
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

    /// A struct declaration and the handler that reads the unproven authority's
    /// key, split across two files so that phase 2 has to link them.
    const DECLARATION: &str = "\
#[derive(Accounts)]
pub struct Create<'info> {
    #[account(init, payer = fee_payer, space = 64, seeds = [authority.key().as_ref()], bump)]
    pub record: Account<'info, Record>,
    /// CHECK: unvalidated
    pub authority: AccountInfo<'info>,
    #[account(mut)]
    pub fee_payer: Signer<'info>,
}
";

    const HANDLER: &str = "\
pub fn create(ctx: Context<Create>) -> Result<()> {
    ctx.accounts.record.owner = ctx.accounts.authority.key();
    Ok(())
}
";

    #[test]
    fn scans_a_directory_and_skips_unparsable_files() {
        let dir = std::env::temp_dir().join("vaultlint_scan_integration");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("create.rs"), DECLARATION).unwrap();
        fs::write(dir.join("handler.rs"), HANDLER).unwrap();
        fs::write(dir.join("broken.rs"), "fn ( { not rust").unwrap();

        let report = scan(&ScanOptions { root: dir.clone() });

        assert_eq!(report.files_scanned, 2);
        assert_eq!(report.skipped.len(), 1);
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].rule_id, "VL001");
        assert!(report.findings[0].file.ends_with("create.rs"));
    }

    #[test]
    fn scan_drops_suppressed_findings() {
        let dir = std::env::temp_dir().join("vaultlint_suppress_integration");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("create.rs"),
            DECLARATION.replace(
                "    /// CHECK: unvalidated",
                "    // vaultlint:allow VL001 — designation is permissionless by design\n    /// CHECK: unvalidated",
            ),
        )
        .unwrap();
        fs::write(dir.join("handler.rs"), HANDLER).unwrap();

        let report = scan(&ScanOptions { root: dir });

        assert!(report.findings.is_empty(), "{:?}", report.findings);
    }

    // ── Scope wiring: end-to-end tests that drive the real scan pipeline ─────
    //
    // These tests are the authoritative check that the scope guards are actually
    // wired into the scan loop.  The unit tests in scope.rs call the primitives
    // directly; only these tests can fail when the guards are removed from lib.rs.
    //
    // The finding shape used is VL004 (`create_program_address`), which fires on
    // a simple free function with no AST-level test-gate inside the rule itself.

    /// A `create_program_address` call that VL004 fires on.
    const CPA: &str = "pub fn f(seeds: &[&[u8]], id: &Pubkey) -> Pubkey {\n    Pubkey::create_program_address(seeds, id).unwrap()\n}\n";

    /// M4 wiring: a finding inside an inline `#[cfg(test)] mod tests { … }` block
    /// is suppressed; an identical finding outside survives.
    ///
    /// Killing mutation: replace `&& !scope::in_test_range(finding.line, &test_ranges)`
    /// with `&& true` at the phase-1 `retain` call in `lib.rs` — two findings are
    /// then reported instead of one.
    #[test]
    fn scope_m4_wiring_inline_cfg_test_block_suppresses_finding() {
        // The source has two identical `create_program_address` calls:
        //   Line 2: outside the cfg(test) mod — this finding survives.
        //   Line 7: inside `#[cfg(test)] mod tests { … }` — this finding is dropped.
        let source = "\
pub fn outside(seeds: &[&[u8]], id: &Pubkey) -> Pubkey {
    Pubkey::create_program_address(seeds, id).unwrap()
}
#[cfg(test)]
mod tests {
    pub fn inside(seeds: &[&[u8]], id: &Pubkey) -> Pubkey {
        Pubkey::create_program_address(seeds, id).unwrap()
    }
}
";
        let dir = std::env::temp_dir().join("vaultlint_scope_m4_wiring");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("lib.rs"), source).unwrap();

        let report = scan(&ScanOptions { root: dir });

        // Exactly one finding: the outside call on line 2.
        assert_eq!(
            report.findings.len(),
            1,
            "expected exactly one finding (inside the cfg(test) block must be suppressed): {:?}",
            report.findings
        );
        assert_eq!(report.findings[0].rule_id, "VL004");
        assert_eq!(
            report.findings[0].line, 2,
            "surviving finding must be the outside call on line 2"
        );
    }

    /// M1 wiring: a `Cargo.toml`-rooted tree; a finding in `tests/it.rs` is
    /// suppressed (M1), while the identical finding in `src/lib.rs` survives.
    ///
    /// Also covers M3: `src/lib.rs` contains `#[cfg(test)] mod unit;` and
    /// `src/unit.rs` carries the same finding — that finding is also suppressed.
    ///
    /// Killing mutation: replace `if scope::is_test_scope(&path, &m3_set) {`
    /// with `if false {` — both the M1 and M3 findings then survive, giving
    /// three findings instead of one.
    #[test]
    fn scope_m1_m3_wiring_skips_test_and_cfg_test_files() {
        let dir = std::env::temp_dir().join("vaultlint_scope_m1_m3_wiring");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("src")).unwrap();
        fs::create_dir_all(dir.join("tests")).unwrap();

        // Minimal Cargo.toml so M1 can find the crate root.
        fs::write(
            dir.join("Cargo.toml"),
            "[package]\nname = \"t\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .unwrap();

        // src/lib.rs: real on-chain code with a finding; also declares cfg(test) mod unit.
        fs::write(
            dir.join("src/lib.rs"),
            format!("{CPA}#[cfg(test)]\nmod unit;\n"),
        )
        .unwrap();

        // tests/it.rs: M1 integration-test file — finding must be suppressed.
        fs::write(dir.join("tests/it.rs"), CPA).unwrap();

        // src/unit.rs: M3 file (declared as #[cfg(test)] mod unit;) — finding must be suppressed.
        fs::write(dir.join("src/unit.rs"), CPA).unwrap();

        let report = scan(&ScanOptions { root: dir });

        // Exactly one finding: the call in src/lib.rs.
        assert_eq!(
            report.findings.len(),
            1,
            "expected exactly one finding (tests/it.rs and src/unit.rs must be suppressed): {:?}",
            report.findings
        );
        assert_eq!(report.findings[0].rule_id, "VL004");
        assert!(
            report.findings[0].file.ends_with("lib.rs"),
            "surviving finding must be in src/lib.rs, got: {:?}",
            report.findings[0].file
        );
    }

    const UNCHECKED_WRITE: &str = "\
pub fn withdraw(vault: &mut Vault, amount: u64) {
    vault.balance = vault.balance - amount;
}
";

    /// Two `.rs` files each with one unchecked write and no `overflow-checks` in
    /// the root manifest → exactly 3 VL003 findings (2 Low per-op + 1 Medium at
    /// the manifest).
    ///
    /// Kills both the emission loop (0 project findings) and the `BTreeSet`
    /// de-duplication (2 project findings).
    #[test]
    fn emits_one_project_finding_for_a_workspace_missing_overflow_checks() {
        let dir = std::env::temp_dir().join("vaultlint_vl003_project_finding");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("Cargo.toml"), "[package]\nname = \"x\"\n").unwrap();
        fs::write(dir.join("a.rs"), UNCHECKED_WRITE).unwrap();
        fs::write(dir.join("b.rs"), UNCHECKED_WRITE).unwrap();

        let report = scan(&ScanOptions { root: dir.clone() });

        let vl003: Vec<_> = report
            .findings
            .iter()
            .filter(|f| f.rule_id == "VL003")
            .collect();
        assert_eq!(vl003.len(), 3, "expected 2 per-op + 1 project: {:?}", vl003);

        let medium: Vec<_> = vl003
            .iter()
            .filter(|f| f.severity == crate::finding::Severity::Medium)
            .collect();
        assert_eq!(medium.len(), 1, "exactly one Medium (project-level)");
        assert!(
            medium[0].file.ends_with("Cargo.toml"),
            "project finding must point at Cargo.toml"
        );

        let low: Vec<_> = vl003
            .iter()
            .filter(|f| f.severity == crate::finding::Severity::Low)
            .collect();
        assert_eq!(low.len(), 2, "exactly two Low (per-op)");
    }

    /// Same tree but with `overflow-checks = true` → zero VL003 findings.
    ///
    /// Kills the per-file threading of `overflow_checks` into `RuleContext`.
    #[test]
    fn a_workspace_with_overflow_checks_produces_no_vl003() {
        let dir = std::env::temp_dir().join("vaultlint_vl003_overflow_checks_on");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("Cargo.toml"),
            "[package]\nname = \"x\"\n\n[profile.release]\noverflow-checks = true\n",
        )
        .unwrap();
        fs::write(dir.join("a.rs"), UNCHECKED_WRITE).unwrap();
        fs::write(dir.join("b.rs"), UNCHECKED_WRITE).unwrap();

        let report = scan(&ScanOptions { root: dir });

        let vl003: Vec<_> = report
            .findings
            .iter()
            .filter(|f| f.rule_id == "VL003")
            .collect();
        assert!(vl003.is_empty(), "expected no VL003 findings: {:?}", vl003);
    }
}
