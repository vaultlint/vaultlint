use syn::spanned::Spanned;
use syn::visit::{self, Visit};

use crate::anchor::Constraint;
use crate::finding::{Finding, Severity};
use crate::rules::{Rule, RuleContext};

pub struct UnvalidatedPdaBump;

impl Rule for UnvalidatedPdaBump {
    fn id(&self) -> &'static str {
        "VL004"
    }

    fn check(&self, ctx: &RuleContext<'_>, out: &mut Vec<Finding>) {
        for accounts in &ctx.anchor.accounts_structs {
            for field in &accounts.fields {
                let seeded = field
                    .constraints
                    .iter()
                    .any(|constraint| matches!(constraint, Constraint::Seeds(_)));
                let bare_bump = field.constraints.contains(&Constraint::Bump(None));
                let initialising = field.constraints.contains(&Constraint::Init);
                if seeded && bare_bump && !initialising {
                    out.push(ctx.finding(
                        "VL004",
                        Severity::Medium,
                        "PDA bump is not validated",
                        format!(
                            "`{}` re-derives its PDA with a bare `bump`. A caller can supply a \
                             non-canonical bump and address a different account.",
                            field.name
                        ),
                        "Validate against the stored canonical bump, e.g. `bump = <account>.bump`.",
                        field.span,
                    ));
                }
            }
        }

        let mut visitor = DerivationVisitor { ctx, out };
        visitor.visit_file(ctx.ast);
    }
}

struct DerivationVisitor<'a, 'ctx> {
    ctx: &'a RuleContext<'ctx>,
    out: &'a mut Vec<Finding>,
}

impl<'ast> Visit<'ast> for DerivationVisitor<'_, '_> {
    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        if let syn::Expr::Path(path) = &*node.func {
            if path
                .path
                .segments
                .last()
                .is_some_and(|segment| segment.ident == "create_program_address")
            {
                self.out.push(
                    self.ctx.finding(
                        "VL004",
                        Severity::Medium,
                        "PDA bump is not validated",
                        "`create_program_address` accepts any bump, including non-canonical ones."
                            .to_string(),
                        "Use `find_program_address`, or compare the result against a stored \
                     canonical bump before trusting it.",
                        node.span(),
                    ),
                );
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
    fn flags_a_bare_bump_on_a_reused_pda() {
        let findings = findings_for(
            r#"
            #[derive(Accounts)]
            pub struct Withdraw<'info> {
                #[account(mut, seeds = [b"vault", user.key().as_ref()], bump)]
                pub vault: Account<'info, Vault>,
            }
        "#,
            &UnvalidatedPdaBump,
        );

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "VL004");
        assert_eq!(findings[0].line, 5);
    }

    #[test]
    fn accepts_a_bump_validated_against_stored_state() {
        let findings = findings_for(
            r#"
            #[derive(Accounts)]
            pub struct Withdraw<'info> {
                #[account(mut, seeds = [b"vault"], bump = vault.bump)]
                pub vault: Account<'info, Vault>,
            }
        "#,
            &UnvalidatedPdaBump,
        );

        assert!(findings.is_empty());
    }

    #[test]
    fn accepts_a_bare_bump_during_initialisation() {
        let findings = findings_for(
            r#"
            #[derive(Accounts)]
            pub struct Initialize<'info> {
                #[account(init, payer = user, space = 8 + 32, seeds = [b"vault"], bump)]
                pub vault: Account<'info, Vault>,
            }
        "#,
            &UnvalidatedPdaBump,
        );

        assert!(findings.is_empty());
    }

    #[test]
    fn flags_raw_create_program_address() {
        let findings = findings_for(
            r#"
            pub fn derive(seeds: &[&[u8]], program_id: &Pubkey) -> Pubkey {
                Pubkey::create_program_address(seeds, program_id).unwrap()
            }
        "#,
            &UnvalidatedPdaBump,
        );

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].line, 3);
    }

    #[test]
    fn accepts_find_program_address() {
        let findings = findings_for(
            r#"
            pub fn derive(seeds: &[&[u8]], program_id: &Pubkey) -> (Pubkey, u8) {
                Pubkey::find_program_address(seeds, program_id)
            }
        "#,
            &UnvalidatedPdaBump,
        );

        assert!(findings.is_empty());
    }
}
