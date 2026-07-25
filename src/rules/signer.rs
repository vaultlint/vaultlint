use crate::anchor::{AccountTy, Constraint};
use crate::finding::{Finding, Severity};
use crate::rules::{Rule, RuleContext};

/// Field names that imply the account authorises the instruction.
/// Kept deliberately short: a missed unusual name costs nothing,
/// a false positive costs the user's trust.
const AUTHORITY_NAMES: &[&str] = &["authority", "admin", "owner", "signer", "payer", "delegate"];

pub struct MissingSignerCheck;

impl Rule for MissingSignerCheck {
    fn id(&self) -> &'static str {
        "VL001"
    }

    fn check(&self, ctx: &RuleContext<'_>, out: &mut Vec<Finding>) {
        for accounts in &ctx.anchor.accounts_structs {
            for field in &accounts.fields {
                if !matches!(
                    field.ty,
                    AccountTy::AccountInfo | AccountTy::UncheckedAccount
                ) {
                    continue;
                }
                if !AUTHORITY_NAMES.contains(&field.name.as_str()) {
                    continue;
                }
                if field.constraints.iter().any(|constraint| {
                    matches!(constraint, Constraint::Custom(text) if text.contains("is_signer"))
                }) {
                    continue;
                }
                out.push(ctx.finding(
                    self.id(),
                    Severity::High,
                    "missing signer check",
                    format!(
                        "`{}` is not constrained as Signer. Any account can be passed here.",
                        field.name
                    ),
                    "Declare the field as `Signer<'info>`, or add `constraint = <account>.is_signer`.",
                    field.span,
                ));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::findings_for;

    #[test]
    fn flags_an_unconstrained_authority_account() {
        let findings = findings_for(
            r#"
            #[derive(Accounts)]
            pub struct Withdraw<'info> {
                pub vault: Account<'info, Vault>,
                /// CHECK: not validated
                pub authority: AccountInfo<'info>,
            }
        "#,
            &MissingSignerCheck,
        );

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "VL001");
        assert_eq!(findings[0].line, 6);
        assert!(findings[0].message.contains("authority"));
    }

    #[test]
    fn accepts_a_signer_typed_authority() {
        let findings = findings_for(
            r#"
            #[derive(Accounts)]
            pub struct Withdraw<'info> {
                pub authority: Signer<'info>,
            }
        "#,
            &MissingSignerCheck,
        );

        assert!(findings.is_empty());
    }

    #[test]
    fn accepts_an_account_info_guarded_by_an_is_signer_constraint() {
        let findings = findings_for(
            r#"
            #[derive(Accounts)]
            pub struct Withdraw<'info> {
                #[account(constraint = admin.is_signer)]
                pub admin: AccountInfo<'info>,
            }
        "#,
            &MissingSignerCheck,
        );

        assert!(findings.is_empty());
    }

    #[test]
    fn ignores_account_info_fields_without_an_authority_name() {
        let findings = findings_for(
            r#"
            #[derive(Accounts)]
            pub struct Withdraw<'info> {
                /// CHECK: only read
                pub price_feed: AccountInfo<'info>,
            }
        "#,
            &MissingSignerCheck,
        );

        assert!(findings.is_empty());
    }
}
