use syn::spanned::Spanned;
use syn::visit::{self, Visit};

use crate::anchor::Constraint;
use crate::finding::{Finding, Severity};
use crate::rules::{Rule, RuleContext};

pub struct UnvalidatedPdaBump;

/// Returns `true` when `expr` is a bare Rust identifier (no `.`, `::`, `(`,
/// `[`, whitespace, etc.).  Used to distinguish `user_bump` (attacker-
/// controlled instruction argument) from `vault.bump` (field access, safe).
fn is_bare_identifier(expr: &str) -> bool {
    !expr.is_empty()
        && expr.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        && expr.chars().next().is_some_and(|c| !c.is_ascii_digit())
}

impl Rule for UnvalidatedPdaBump {
    fn check(&self, ctx: &RuleContext<'_>, out: &mut Vec<Finding>) {
        for accounts in &ctx.anchor.accounts_structs {
            for field in &accounts.fields {
                let seeded = field
                    .constraints
                    .iter()
                    .any(|constraint| matches!(constraint, Constraint::Seeds(_)));
                let initialising = field.constraints.contains(&Constraint::Init);

                // Find `bump = <expr>` on this field, if any.
                let bump_expr = field.constraints.iter().find_map(|c| match c {
                    Constraint::Bump(Some(expr)) => Some(expr.as_str()),
                    _ => None,
                });

                // Flag only when: the field has seeds, is not an init, has
                // `bump = <expr>`, and <expr> is a bare identifier matching one
                // of the #[instruction(...)] argument names.  A field access
                // (`vault.bump`), method call, or literal is not attacker-
                // controlled and must not be flagged.
                if seeded && !initialising {
                    if let Some(expr) = bump_expr {
                        let is_bare_ident = is_bare_identifier(expr);
                        let is_instruction_arg =
                            accounts.instruction_args.iter().any(|a| a == expr);
                        if is_bare_ident && is_instruction_arg {
                            out.push(ctx.finding(
                                "VL004",
                                Severity::Medium,
                                "non-canonical PDA bump",
                                format!(
                                    "`{}` uses `bump = {expr}`, where `{expr}` is an \
                                     `#[instruction]` argument. An attacker controls this value \
                                     and can pass a non-canonical bump to address a different \
                                     account.",
                                    field.name
                                ),
                                "Store the canonical bump (from `init`) in the account data and \
                                 validate with `bump = <account>.bump`.",
                                field.span,
                            ));
                        }
                    }
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
                        "non-canonical PDA bump",
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

    // ── positive: bump = <instruction arg> is flagged ────────────────────────

    #[test]
    fn flags_bump_equal_to_instruction_argument() {
        let findings = findings_for(
            r#"
            #[derive(Accounts)]
            #[instruction(user_bump: u8)]
            pub struct Withdraw<'info> {
                #[account(mut, seeds = [b"vault", user.key().as_ref()], bump = user_bump)]
                pub vault: Account<'info, Vault>,
            }
        "#,
            &UnvalidatedPdaBump,
        );

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "VL004");
        assert_eq!(findings[0].line, 6);
    }

    // ── negative: bare bump is safe (find_program_address) ───────────────────

    #[test]
    fn accepts_bare_bump_on_reused_pda() {
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

        assert!(findings.is_empty());
    }

    // ── negative: bump = <field.bump> is the safe stored-bump idiom ──────────

    #[test]
    fn accepts_bump_validated_against_stored_state() {
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

    // ── negative: bump = <bare ident> not in #[instruction] is not flagged ───

    #[test]
    fn accepts_bump_equal_to_non_instruction_ident() {
        let findings = findings_for(
            r#"
            #[derive(Accounts)]
            pub struct Withdraw<'info> {
                #[account(mut, seeds = [b"vault"], bump = stored_bump)]
                pub vault: Account<'info, Vault>,
            }
        "#,
            &UnvalidatedPdaBump,
        );

        assert!(findings.is_empty());
    }

    // ── negative: init with bare bump is always safe ──────────────────────────

    #[test]
    fn accepts_bare_bump_during_initialisation() {
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

    // ── retained: raw create_program_address call is still flagged ───────────

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
