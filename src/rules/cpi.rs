use syn::spanned::Spanned;
use syn::visit::{self, Visit};

use crate::finding::{Finding, Severity};
use crate::rules::{normalised, Rule, RuleContext};

const CPI_CALLS: &[&str] = &["invoke", "invoke_signed"];

/// Textual signals that the function verifies which program it is calling.
const VERIFICATION_SIGNALS: &[&str] = &["require_keys_eq!", "::ID", "assert_eq!(", "program_id=="];

pub struct UncheckedCpi;

impl Rule for UncheckedCpi {
    fn id(&self) -> &'static str {
        "VL005"
    }

    fn check(&self, ctx: &RuleContext<'_>, out: &mut Vec<Finding>) {
        let mut visitor = FunctionVisitor { ctx, out };
        visitor.visit_file(ctx.ast);
    }
}

struct FunctionVisitor<'a, 'ctx> {
    ctx: &'a RuleContext<'ctx>,
    out: &'a mut Vec<Finding>,
}

impl FunctionVisitor<'_, '_> {
    fn check_body(&mut self, block: &syn::Block) {
        let text = normalised(block);
        if VERIFICATION_SIGNALS
            .iter()
            .any(|signal| text.contains(signal))
        {
            return;
        }
        let mut finder = CpiFinder { spans: Vec::new() };
        finder.visit_block(block);
        for span in finder.spans {
            self.out.push(self.ctx.finding(
                "VL005",
                Severity::Medium,
                "unchecked CPI to unknown program",
                "This cross-program invocation runs without verifying the callee's program id. \
                 An attacker who controls that account can point it at their own program."
                    .to_string(),
                "Use Anchor's typed CPI helpers, or verify the id first, e.g. \
                 `require_keys_eq!(program.key(), expected::ID)`.",
                span,
            ));
        }
    }
}

impl<'ast> Visit<'ast> for FunctionVisitor<'_, '_> {
    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        self.check_body(&node.block);
    }

    fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
        self.check_body(&node.block);
    }
}

struct CpiFinder {
    spans: Vec<proc_macro2::Span>,
}

impl<'ast> Visit<'ast> for CpiFinder {
    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        if let syn::Expr::Path(path) = &*node.func {
            if path
                .path
                .segments
                .last()
                .is_some_and(|segment| CPI_CALLS.contains(&segment.ident.to_string().as_str()))
            {
                self.spans.push(node.span());
            }
        }
        visit::visit_expr_call(self, node);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::findings_for;

    #[test]
    fn flags_invoke_without_any_program_id_verification() {
        let findings = findings_for(
            r#"
            pub fn claim(ctx: Context<Claim>) -> Result<()> {
                let instruction = build_instruction();
                invoke(&instruction, &[a.clone(), b.clone(), target_program.clone()])?;
                Ok(())
            }
        "#,
            &UncheckedCpi,
        );

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "VL005");
        assert_eq!(findings[0].line, 4);
    }

    #[test]
    fn accepts_invoke_guarded_by_require_keys_eq() {
        let findings = findings_for(
            r#"
            pub fn claim(ctx: Context<Claim>) -> Result<()> {
                require_keys_eq!(ctx.accounts.token_program.key(), anchor_spl::token::ID);
                invoke(&instruction, &[a.clone(), b.clone()])?;
                Ok(())
            }
        "#,
            &UncheckedCpi,
        );

        assert!(findings.is_empty());
    }

    #[test]
    fn accepts_invoke_guarded_by_a_program_id_comparison() {
        let findings = findings_for(
            r#"
            pub fn claim(ctx: Context<Claim>) -> Result<()> {
                if ctx.accounts.target.key() != crate::ID {
                    return Err(Error::WrongProgram.into());
                }
                invoke_signed(&instruction, &accounts, signer_seeds)?;
                Ok(())
            }
        "#,
            &UncheckedCpi,
        );

        assert!(findings.is_empty());
    }

    #[test]
    fn ignores_functions_without_any_cpi() {
        let findings = findings_for(
            r#"
            pub fn claim(ctx: Context<Claim>) -> Result<()> {
                ctx.accounts.vault.balance = 0;
                Ok(())
            }
        "#,
            &UncheckedCpi,
        );

        assert!(findings.is_empty());
    }
}
