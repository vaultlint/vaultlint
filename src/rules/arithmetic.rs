use syn::spanned::Spanned;
use syn::visit::{self, Visit};

use crate::finding::{Finding, Severity};
use crate::rules::{Rule, RuleContext};

pub struct UncheckedArithmetic;

impl Rule for UncheckedArithmetic {
    fn id(&self) -> &'static str {
        "VL003"
    }

    fn check(&self, ctx: &RuleContext<'_>, out: &mut Vec<Finding>) {
        let severity = if ctx.overflow_checks {
            Severity::Low
        } else {
            Severity::Medium
        };
        let mut visitor = ArithmeticVisitor { ctx, out, severity };
        visitor.visit_file(ctx.ast);
    }
}

struct ArithmeticVisitor<'a, 'ctx> {
    ctx: &'a RuleContext<'ctx>,
    out: &'a mut Vec<Finding>,
    severity: Severity,
}

impl ArithmeticVisitor<'_, '_> {
    fn report(&mut self, span: proc_macro2::Span, operation: &str) {
        self.out.push(self.ctx.finding(
            "VL003",
            self.severity,
            "unchecked arithmetic",
            format!(
                "Unchecked {operation} writes into account state. \
                 Solana programs are built in release mode, where overflow wraps silently."
            ),
            "Use `checked_add` / `checked_sub` / `checked_mul` and handle the `None` case.",
            span,
        ));
    }
}

impl<'ast> Visit<'ast> for ArithmeticVisitor<'_, '_> {
    fn visit_item_mod(&mut self, node: &'ast syn::ItemMod) {
        if is_test_gated(&node.attrs) {
            return;
        }
        visit::visit_item_mod(self, node);
    }

    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        if is_test_gated(&node.attrs) {
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

fn is_test_gated(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|attr| {
        attr.path().is_ident("cfg")
            && matches!(&attr.meta, syn::Meta::List(list)
                if list.tokens.to_string().contains("test"))
    })
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::Severity;
    use crate::rules::{findings_for, findings_with_overflow_checks};

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
        assert_eq!(findings[0].severity, Severity::Medium);
        assert_eq!(findings[0].line, 3);
    }

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

    #[test]
    fn lowers_severity_when_the_project_enables_overflow_checks() {
        let findings = findings_with_overflow_checks(
            r#"
            pub fn withdraw(vault: &mut Vault, amount: u64) {
                vault.balance = vault.balance - amount;
            }
        "#,
            &UncheckedArithmetic,
            true,
        );

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Low);
    }
}
