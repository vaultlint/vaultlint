use syn::spanned::Spanned;
use syn::visit::{self, Visit};

use crate::finding::{Finding, Severity};
use crate::rules::{normalised, Rule, RuleContext};

const DESERIALISERS: &[&str] = &["try_from_slice", "try_deserialize", "deserialize"];

pub struct MissingOwnerCheck;

impl Rule for MissingOwnerCheck {
    fn id(&self) -> &'static str {
        "VL002"
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
        // Any mention of `.owner` in the function is treated as a check.
        // Deliberately generous: a missed finding is cheaper than a false one.
        if normalised(block).contains(".owner") {
            return;
        }
        let mut finder = RawReadFinder { spans: Vec::new() };
        finder.visit_block(block);
        for span in finder.spans {
            self.out.push(
                self.ctx.finding(
                    "VL002",
                    Severity::High,
                    "missing owner check",
                    "Account data is deserialised without verifying the account owner. \
                 An attacker can pass a look-alike account owned by another program."
                        .to_string(),
                    "Use `Account<'info, T>`, which checks the owner and discriminator, \
                 or add `require_keys_eq!(*account.owner, crate::ID)` before reading.",
                    span,
                ),
            );
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

struct RawReadFinder {
    spans: Vec<proc_macro2::Span>,
}

impl<'ast> Visit<'ast> for RawReadFinder {
    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        if is_deserialiser(&node.func) && reads_account_data(&node.args) {
            self.spans.push(node.span());
        }
        visit::visit_expr_call(self, node);
    }
}

fn is_deserialiser(func: &syn::Expr) -> bool {
    let syn::Expr::Path(path) = func else {
        return false;
    };
    path.path
        .segments
        .last()
        .is_some_and(|segment| DESERIALISERS.contains(&segment.ident.to_string().as_str()))
}

fn reads_account_data(args: &syn::punctuated::Punctuated<syn::Expr, syn::Token![,]>) -> bool {
    args.iter()
        .any(|arg| normalised(arg).contains(".data.borrow()"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::findings_for;

    #[test]
    fn flags_manual_deserialisation_without_an_owner_check() {
        let findings = findings_for(
            r#"
            pub fn read_config(ctx: Context<ReadConfig>) -> Result<()> {
                let account = &ctx.accounts.config;
                let config = Config::try_from_slice(&account.data.borrow())?;
                msg!("{}", config.fee);
                Ok(())
            }
        "#,
            &MissingOwnerCheck,
        );

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "VL002");
        assert_eq!(findings[0].line, 4);
    }

    #[test]
    fn accepts_deserialisation_guarded_by_an_owner_check() {
        let findings = findings_for(
            r#"
            pub fn read_config(ctx: Context<ReadConfig>) -> Result<()> {
                let account = &ctx.accounts.config;
                require_keys_eq!(*account.owner, crate::ID);
                let config = Config::try_from_slice(&account.data.borrow())?;
                Ok(())
            }
        "#,
            &MissingOwnerCheck,
        );

        assert!(findings.is_empty());
    }

    #[test]
    fn ignores_typed_anchor_accounts() {
        let findings = findings_for(
            r#"
            pub fn read_config(ctx: Context<ReadConfig>) -> Result<()> {
                let fee = ctx.accounts.config.fee;
                Ok(())
            }
        "#,
            &MissingOwnerCheck,
        );

        assert!(findings.is_empty());
    }

    #[test]
    fn ignores_deserialisation_that_is_not_reading_raw_account_data() {
        let findings = findings_for(
            r#"
            pub fn parse_params(bytes: &[u8]) -> Result<Params> {
                let params = Params::try_from_slice(bytes)?;
                Ok(params)
            }
        "#,
            &MissingOwnerCheck,
        );

        assert!(findings.is_empty());
    }
}
