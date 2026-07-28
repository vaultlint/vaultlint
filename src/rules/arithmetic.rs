use std::path::Path;

use syn::spanned::Spanned;
use syn::visit::{self, Visit};

use crate::finding::{Finding, Severity};
use crate::rules::{Rule, RuleContext};

pub struct UncheckedArithmetic;

impl Rule for UncheckedArithmetic {
    fn check(&self, ctx: &RuleContext<'_>, out: &mut Vec<Finding>) {
        if ctx.overflow_checks {
            return;
        }
        let mut visitor = ArithmeticVisitor { ctx, out };
        visitor.visit_file(ctx.ast);
    }
}

struct ArithmeticVisitor<'a, 'ctx> {
    ctx: &'a RuleContext<'ctx>,
    out: &'a mut Vec<Finding>,
}

impl ArithmeticVisitor<'_, '_> {
    fn report(&mut self, span: proc_macro2::Span, operation: &str) {
        self.out.push(self.ctx.finding(
            "VL003",
            Severity::Low,
            "unchecked arithmetic",
            format!(
                "Unchecked {operation} writes into a struct field, and this workspace does not \
                 enable `overflow-checks`, so an overflow wraps silently instead of aborting \
                 the transaction."
            ),
            "Enable `overflow-checks` for the release profile, or use `checked_add` / \
             `checked_sub` / `checked_mul` and handle the `None` case.",
            span,
        ));
    }
}

impl<'ast> Visit<'ast> for ArithmeticVisitor<'_, '_> {
    fn visit_item_mod(&mut self, node: &'ast syn::ItemMod) {
        if crate::scope::attrs_have_cfg_test(&node.attrs) {
            return;
        }
        visit::visit_item_mod(self, node);
    }

    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        if crate::scope::attrs_have_cfg_test(&node.attrs) {
            return;
        }
        visit::visit_item_fn(self, node);
    }

    fn visit_expr(&mut self, node: &'ast syn::Expr) {
        match node {
            syn::Expr::Assign(assign) if matches!(*assign.left, syn::Expr::Field(_)) => {
                if let syn::Expr::Binary(binary) = &*assign.right {
                    if let Some(operation) = plain_arithmetic(binary.op) {
                        self.report(node.span(), operation);
                    }
                }
            }
            syn::Expr::Binary(binary) if matches!(*binary.left, syn::Expr::Field(_)) => {
                if let Some(operation) = compound_arithmetic(binary.op) {
                    self.report(node.span(), operation);
                }
            }
            _ => {}
        }
        visit::visit_expr(self, node);
    }
}

fn plain_arithmetic(op: syn::BinOp) -> Option<&'static str> {
    match op {
        syn::BinOp::Add(_) => Some("addition"),
        syn::BinOp::Sub(_) => Some("subtraction"),
        syn::BinOp::Mul(_) => Some("multiplication"),
        _ => None,
    }
}

fn compound_arithmetic(op: syn::BinOp) -> Option<&'static str> {
    match op {
        syn::BinOp::AddAssign(_) => Some("addition"),
        syn::BinOp::SubAssign(_) => Some("subtraction"),
        syn::BinOp::MulAssign(_) => Some("multiplication"),
        _ => None,
    }
}

/// The project-level half of VL003: the workspace manifest does not enable
/// `overflow-checks`, so every arithmetic overflow in it wraps instead of aborting.
pub fn overflow_checks_finding(manifest: &Path) -> Finding {
    let text = std::fs::read_to_string(manifest).unwrap_or_default();
    let line = text
        .lines()
        .position(|l| l.trim() == "[profile.release]")
        .map_or(1, |index| index + 1);
    let snippet = text
        .lines()
        .nth(line - 1)
        .unwrap_or_default()
        .trim()
        .to_string();
    Finding {
        rule_id: std::borrow::Cow::Borrowed("VL003"),
        severity: Severity::Medium,
        title: std::borrow::Cow::Borrowed("overflow-checks is not enabled"),
        message: "This workspace does not set `overflow-checks = true` under \
                  `[profile.release]`. Solana programs are built in release mode, so \
                  arithmetic that overflows wraps silently instead of aborting the \
                  transaction."
            .to_string(),
        file: manifest.to_path_buf(),
        line,
        column: 1,
        snippet,
        help: std::borrow::Cow::Borrowed(
            "Add `[profile.release]` with `overflow-checks = true` to the workspace \
             manifest. Overflow then aborts the transaction instead of writing a wrapped \
             value.",
        ),
        docs_url: "https://vaultlint.com/rules/VL003/".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::Severity;
    use crate::rules::{findings_for, findings_with_overflow_checks};

    /// Kill: delete the `if ctx.overflow_checks { return; }` guard.
    #[test]
    fn is_silent_when_the_project_enables_overflow_checks() {
        let findings = findings_with_overflow_checks(
            r#"
            pub fn withdraw(vault: &mut Vault, amount: u64) {
                vault.balance = vault.balance - amount;
            }
        "#,
            &UncheckedArithmetic,
            true,
        );

        assert!(findings.is_empty());
    }

    /// Kill: change the constant `Severity::Low` to `Severity::Medium`.
    #[test]
    fn flags_bare_subtraction_written_into_account_state() {
        let findings = findings_for(
            r#"
            pub fn withdraw(vault: &mut Vault, amount: u64) {
                vault.balance = vault.balance - amount;
            }
        "#,
            &UncheckedArithmetic,
        );

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "VL003");
        assert_eq!(findings[0].severity, Severity::Low);
        assert_eq!(findings[0].line, 3);
    }

    /// Kill (rule_id): change the emitted rule id to a different string.
    /// Kill (severity): change `Severity::Low` to `Severity::Medium` in
    /// `compound_arithmetic`'s report call.
    /// Kill (rule): change `AddAssign` to not match in `compound_arithmetic`.
    #[test]
    fn flags_compound_assignment_into_account_state() {
        let findings = findings_for(
            r#"
            pub fn accrue(vault: &mut Vault, reward: u64) {
                vault.rewards += reward;
            }
        "#,
            &UncheckedArithmetic,
        );

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "VL003");
        assert_eq!(findings[0].severity, Severity::Low);
    }

    #[test]
    fn accepts_checked_arithmetic() {
        let findings = findings_for(
            r#"
            pub fn withdraw(vault: &mut Vault, amount: u64) -> Result<()> {
                vault.balance = vault.balance.checked_sub(amount).ok_or(Err::Math)?;
                Ok(())
            }
        "#,
            &UncheckedArithmetic,
        );

        assert!(findings.is_empty());
    }

    #[test]
    fn ignores_arithmetic_on_local_variables() {
        let findings = findings_for(
            r#"
            pub fn total(a: u64, b: u64) -> u64 {
                let sum = a + b;
                sum
            }
        "#,
            &UncheckedArithmetic,
        );

        assert!(findings.is_empty());
    }

    #[test]
    fn ignores_test_modules() {
        let findings = findings_for(
            r#"
            #[cfg(test)]
            mod tests {
                pub fn setup(vault: &mut Vault) {
                    vault.balance = vault.balance - 1;
                }
            }
        "#,
            &UncheckedArithmetic,
        );

        assert!(findings.is_empty());
    }

    /// A module gated on a Cargo feature named "test" must not be suppressed —
    /// it ships whenever that feature is enabled.
    ///
    /// Kill: restore the old `is_test_gated` substring check which treats any
    /// cfg token text containing "test" as a test gate.
    #[test]
    fn flags_arithmetic_gated_on_a_cargo_feature_named_test() {
        let findings = findings_for(
            r#"
            #[cfg(feature = "test")]
            mod m {
                pub fn do_work(vault: &mut Vault, amount: u64) {
                    vault.balance = vault.balance - amount;
                }
            }
        "#,
            &UncheckedArithmetic,
        );

        assert_eq!(findings.len(), 1);
    }

    /// Kill: delete the `.position(...)` lookup so it falls back to line 1.
    #[test]
    fn project_finding_points_at_the_profile_release_line() {
        use std::io::Write;

        let dir = std::env::temp_dir().join("vaultlint_arithmetic_project_finding");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let manifest = dir.join("Cargo.toml");
        // `[profile.release]` is on line 4
        let mut f = std::fs::File::create(&manifest).unwrap();
        writeln!(f, "[package]").unwrap();
        writeln!(f, "name = \"x\"").unwrap();
        writeln!(f).unwrap();
        writeln!(f, "[profile.release]").unwrap();
        writeln!(f, "overflow-checks = false").unwrap();

        let finding = overflow_checks_finding(&manifest);

        assert_eq!(finding.line, 4);
        assert_eq!(finding.severity, Severity::Medium);
        assert_eq!(finding.title, "overflow-checks is not enabled");
        assert_eq!(finding.snippet, "[profile.release]");
    }
}
