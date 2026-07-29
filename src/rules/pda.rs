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
        if is_create_program_address(&node.func) {
            let seed = bump_seed(node);
            // A bump read out of account data was put there by the program that
            // owns it, which is the stored-canonical-bump idiom this rule's own
            // help recommends. Reporting it would make VL004 fire on its own fix.
            if !seed.is_some_and(reads_stored_value) {
                let message = match seed {
                    Some(seed) => format!(
                        "`{}` is the bump seed given to `create_program_address` and is not read \
                         from account data, so nothing proves it is the canonical bump. The call \
                         accepts any bump, and a non-canonical one addresses a different account.",
                        crate::rules::normalised(seed)
                    ),
                    None => "`create_program_address` accepts any bump, including non-canonical \
                             ones, and this call's bump seed is not written out here, so nothing \
                             rules one out."
                        .to_string(),
                };
                self.out.push(self.ctx.finding(
                    "VL004",
                    Severity::Medium,
                    "non-canonical PDA bump",
                    message,
                    "Use `find_program_address`, or compare the result against a stored \
                     canonical bump before trusting it.",
                    node.span(),
                ));
            }
        }
        visit::visit_expr_call(self, node);
    }
}

fn is_create_program_address(func: &syn::Expr) -> bool {
    let syn::Expr::Path(path) = func else {
        return false;
    };
    path.path
        .segments
        .last()
        .is_some_and(|segment| segment.ident == "create_program_address")
}

/// The array literal an expression denotes, through any number of references,
/// groups and parentheses. `None` when the seeds arrive as a variable.
fn as_array(expr: &syn::Expr) -> Option<&syn::ExprArray> {
    match expr {
        syn::Expr::Array(array) => Some(array),
        syn::Expr::Reference(reference) => as_array(&reference.expr),
        syn::Expr::Group(group) => as_array(&group.expr),
        syn::Expr::Paren(paren) => as_array(&paren.expr),
        _ => None,
    }
}

/// The bump seed of a `create_program_address` call, when the seeds are written
/// out at the call site: the last seed, if it is a one-element slice. That is
/// where the bump goes by convention — the other seeds are `&[u8]` of whatever
/// length, and the bump is the single byte `&[bump]`.
fn bump_seed(call: &syn::ExprCall) -> Option<&syn::Expr> {
    let seeds = as_array(call.args.first()?)?;
    let last = as_array(seeds.elems.last()?)?;
    if last.elems.len() != 1 {
        return None;
    }
    last.elems.first()
}

/// True if `expr` reads a field of something — `check.nonce`, `self.bump`,
/// `state.bump.to_le_bytes()`. This is the same distinction the declarative
/// half of the rule draws between `bump = user_bump` and `bump = vault.bump`.
fn reads_stored_value(expr: &syn::Expr) -> bool {
    struct FieldFinder(bool);
    impl<'ast> Visit<'ast> for FieldFinder {
        fn visit_expr_field(&mut self, node: &'ast syn::ExprField) {
            self.0 = true;
            visit::visit_expr_field(self, node);
        }
    }
    let mut finder = FieldFinder(false);
    finder.visit_expr(expr);
    finder.0
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

    /// `find_program_address` is not in the rule's match list: it always returns
    /// the canonical (highest) bump, so using it carries no bump-canonicality
    /// risk. The rule only fires on `create_program_address` (whose match is
    /// verified by `flags_raw_create_program_address`). The two calls differ by
    /// exactly the guard being tested.
    ///
    /// Killing mutation: add `"find_program_address"` to the string compared
    /// against `"create_program_address"` in `DerivationVisitor::visit_expr_call`
    /// (or change the comparison to a contains-check on any `_program_address`
    /// suffix). The test then produces one finding instead of zero.
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
        // Companion: create_program_address IS flagged (see flags_raw_create_program_address).
    }

    // ── conditional: the bump seed decides ───────────────────────────────────

    /// The shape the rule's own help recommends — store the canonical bump at
    /// init, then derive with it. Reporting it made VL004 fire on its own fix.
    ///
    /// Killing mutation: in `visit_expr_call`, drop the `reads_stored_value`
    /// guard and report on every `create_program_address`.
    #[test]
    fn accepts_a_bump_seed_read_from_account_data() {
        let findings = findings_for(
            r#"
            pub fn check(ctx: &Context<Cash>) -> Result<()> {
                let signer = Pubkey::create_program_address(
                    &[ctx.accounts.check.key.as_ref(), &[ctx.accounts.check.nonce]],
                    ctx.program_id,
                )?;
                Ok(())
            }
        "#,
            &UnvalidatedPdaBump,
        );

        assert!(findings.is_empty());
    }

    /// The corpus shape: a caller-supplied `u8` fed straight in. This is what
    /// the rule exists for, and the `reads_stored_value` guard must not reach it.
    ///
    /// Killing mutation: in `reads_stored_value`, return `true` unconditionally.
    #[test]
    fn flags_a_bare_identifier_bump_seed() {
        let findings = findings_for(
            r#"
            pub fn check(ctx: &Context<Cash>, nonce: u8) -> Result<()> {
                let signer = Pubkey::create_program_address(
                    &[ctx.accounts.check.key.as_ref(), &[nonce]],
                    ctx.program_id,
                )?;
                Ok(())
            }
        "#,
            &UnvalidatedPdaBump,
        );

        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("`nonce`"));
    }

    /// Only the last seed is the bump. A field access earlier in the list is an
    /// ordinary seed and says nothing about which bump was used.
    ///
    /// Killing mutation: in `bump_seed`, scan the seed array in reverse for the
    /// first one-element slice instead of reading only the last seed.
    #[test]
    fn a_stored_value_in_an_earlier_seed_does_not_silence() {
        let findings = findings_for(
            r#"
            pub fn check(ctx: &Context<Cash>, nonce: u8) -> Result<()> {
                let signer = Pubkey::create_program_address(
                    &[&[ctx.accounts.check.nonce], ctx.accounts.check.key.as_ref(), &[nonce]],
                    ctx.program_id,
                )?;
                Ok(())
            }
        "#,
            &UnvalidatedPdaBump,
        );

        assert_eq!(findings.len(), 1);
    }
}
