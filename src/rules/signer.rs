use crate::anchor::{AccountTy, Constraint};
use crate::finding::{Finding, Severity};
use crate::rules::{Rule, RuleContext};

/// Field names that imply the account authorises the instruction.
/// Kept deliberately short: a missed unusual name costs nothing,
/// a false positive costs the user's trust.
const MARKERS: &[&str] = &[
    "authority",
    "admin",
    "owner",
    "signer",
    "payer",
    "delegate",
    "manager",
    "governance",
];

pub struct MissingSignerCheck;

/// Returns true if `name` equals `marker` exactly or ends with `_<marker>`.
fn matches_marker(name: &str, marker: &str) -> bool {
    name == marker || name.ends_with(&format!("_{marker}"))
}

/// Returns true if `field_name` appears as a whole identifier inside `seeds_text`.
///
/// We check for identifier boundaries so that `authority` is not matched inside
/// `authority_bump` or `pool_authority_seed`.
fn name_in_seeds(field_name: &str, seeds_text: &str) -> bool {
    let bytes = seeds_text.as_bytes();
    let n = field_name.len();
    let text = seeds_text;

    let mut start = 0;
    while let Some(pos) = text[start..].find(field_name) {
        let abs = start + pos;
        // Check left boundary: must be start of string or a non-identifier char.
        let left_ok = abs == 0 || {
            let c = text.as_bytes()[abs - 1] as char;
            !c.is_alphanumeric() && c != '_'
        };
        // Check right boundary: must be end of string or a non-identifier char.
        let right_ok = abs + n >= bytes.len() || {
            let c = bytes[abs + n] as char;
            !c.is_alphanumeric() && c != '_'
        };
        if left_ok && right_ok {
            return true;
        }
        start = abs + 1;
        if start >= text.len() {
            break;
        }
    }
    false
}

impl Rule for MissingSignerCheck {
    fn id(&self) -> &'static str {
        "VL001"
    }

    fn check(&self, ctx: &RuleContext<'_>, out: &mut Vec<Finding>) {
        for accounts in &ctx.anchor.accounts_structs {
            // Pre-compute: collect all seeds texts in this struct.
            let all_seeds: Vec<&str> = accounts
                .fields
                .iter()
                .flat_map(|f| {
                    f.constraints.iter().filter_map(|c| match c {
                        Constraint::Seeds(s) => Some(s.as_str()),
                        _ => None,
                    })
                })
                .collect();

            // Pre-compute: collect all has_one targets in this struct.
            let has_one_targets: Vec<&str> = accounts
                .fields
                .iter()
                .flat_map(|f| {
                    f.constraints.iter().filter_map(|c| match c {
                        Constraint::HasOne(target) => Some(target.as_str()),
                        _ => None,
                    })
                })
                .collect();

            for field in &accounts.fields {
                // Only flag AccountInfo / UncheckedAccount.
                if !matches!(
                    field.ty,
                    AccountTy::AccountInfo | AccountTy::UncheckedAccount
                ) {
                    continue;
                }

                // Name must match a marker exactly or with `_<marker>` suffix.
                if !MARKERS.iter().any(|m| matches_marker(&field.name, m)) {
                    continue;
                }

                // Check all forms of validation — skip if any is present.

                // 1. `#[account(signer)]` → Other("signer")
                if field
                    .constraints
                    .iter()
                    .any(|c| matches!(c, Constraint::Other(k) if k == "signer"))
                {
                    continue;
                }

                // 2. `#[account(address = ...)]` → Other("address")
                if field
                    .constraints
                    .iter()
                    .any(|c| matches!(c, Constraint::Other(k) if k == "address"))
                {
                    continue;
                }

                // 3. Any `constraint = ...` → Custom(_)
                if field
                    .constraints
                    .iter()
                    .any(|c| matches!(c, Constraint::Custom(_)))
                {
                    continue;
                }

                // 4. Field name appears as an identifier inside any sibling Seeds text.
                if all_seeds.iter().any(|s| name_in_seeds(&field.name, s)) {
                    continue;
                }

                // 5. Field is the target of a has_one on a sibling.
                if has_one_targets.contains(&field.name.as_str()) {
                    continue;
                }

                out.push(ctx.finding(
                    self.id(),
                    Severity::High,
                    "missing signer check",
                    format!(
                        "`{}` is not validated. Any account can be passed here.",
                        field.name
                    ),
                    "Declare the field as `Signer<'info>`, add `#[account(signer)]`, \
                     `#[account(address = expected::ID)]`, a `constraint = ...`, \
                     or ensure it is pinned by a PDA's seeds or a `has_one`.",
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

    // ── positive: bare authority-named AccountInfo with no constraints ────────

    #[test]
    fn flags_bare_authority_account_info() {
        let findings = findings_for(
            r#"
            #[derive(Accounts)]
            pub struct Withdraw<'info> {
                pub vault: Account<'info, Vault>,
                pub authority: AccountInfo<'info>,
            }
        "#,
            &MissingSignerCheck,
        );

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "VL001");
        assert!(findings[0].message.contains("authority"));
    }

    // ── positive: suffix matching (`pool_authority`) ─────────────────────────

    #[test]
    fn flags_pool_authority_suffix() {
        let findings = findings_for(
            r#"
            #[derive(Accounts)]
            pub struct Withdraw<'info> {
                pub pool_authority: AccountInfo<'info>,
            }
        "#,
            &MissingSignerCheck,
        );

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "VL001");
        assert!(findings[0].message.contains("pool_authority"));
    }

    // ── positive: `vault_authority` suffix ───────────────────────────────────

    #[test]
    fn flags_vault_authority_suffix() {
        let findings = findings_for(
            r#"
            #[derive(Accounts)]
            pub struct Transfer<'info> {
                pub vault_authority: AccountInfo<'info>,
            }
        "#,
            &MissingSignerCheck,
        );

        assert_eq!(findings.len(), 1);
    }

    // ── negative: `Signer<'info>` type — out of scope entirely ───────────────

    #[test]
    fn accepts_signer_typed_field() {
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

    // ── negative: `#[account(signer)]` constraint ────────────────────────────

    #[test]
    fn accepts_account_signer_constraint() {
        let findings = findings_for(
            r#"
            #[derive(Accounts)]
            pub struct Withdraw<'info> {
                #[account(signer)]
                pub authority: AccountInfo<'info>,
            }
        "#,
            &MissingSignerCheck,
        );

        assert!(findings.is_empty());
    }

    // ── negative: `#[account(address = ...)]` constraint ─────────────────────

    #[test]
    fn accepts_address_constraint() {
        let findings = findings_for(
            r#"
            #[derive(Accounts)]
            pub struct Withdraw<'info> {
                #[account(address = expected::ID)]
                pub authority: AccountInfo<'info>,
            }
        "#,
            &MissingSignerCheck,
        );

        assert!(findings.is_empty());
    }

    // ── negative: `#[account(constraint = ...)]` constraint ──────────────────

    #[test]
    fn accepts_custom_constraint() {
        let findings = findings_for(
            r#"
            #[derive(Accounts)]
            pub struct Withdraw<'info> {
                #[account(constraint = authority.is_signer)]
                pub authority: AccountInfo<'info>,
            }
        "#,
            &MissingSignerCheck,
        );

        assert!(findings.is_empty());
    }

    // ── negative: sibling `has_one = authority` ───────────────────────────────

    #[test]
    fn accepts_has_one_target() {
        let findings = findings_for(
            r#"
            #[derive(Accounts)]
            pub struct Withdraw<'info> {
                #[account(has_one = authority)]
                pub vault: Account<'info, Vault>,
                pub authority: AccountInfo<'info>,
            }
        "#,
            &MissingSignerCheck,
        );

        assert!(findings.is_empty());
    }

    // ── negative: field name appears in sibling seeds ────────────────────────

    #[test]
    fn accepts_field_that_appears_in_seeds() {
        let findings = findings_for(
            r#"
            #[derive(Accounts)]
            pub struct Initialize<'info> {
                #[account(seeds = [b"vault", authority.key().as_ref()], bump)]
                pub vault: Account<'info, Vault>,
                pub authority: AccountInfo<'info>,
            }
        "#,
            &MissingSignerCheck,
        );

        assert!(findings.is_empty());
    }

    // ── negative: non-authority name is ignored ───────────────────────────────

    #[test]
    fn ignores_non_authority_name() {
        let findings = findings_for(
            r#"
            #[derive(Accounts)]
            pub struct Withdraw<'info> {
                pub price_feed: AccountInfo<'info>,
            }
        "#,
            &MissingSignerCheck,
        );

        assert!(findings.is_empty());
    }

    // ── boundary: `authority_bump` must NOT match `_authority` or `authority` ─

    #[test]
    fn suffix_authority_bump_does_not_match() {
        // `authority_bump` ends with `_bump`, not `_authority`, so no match.
        let findings = findings_for(
            r#"
            #[derive(Accounts)]
            pub struct Withdraw<'info> {
                pub authority_bump: AccountInfo<'info>,
            }
        "#,
            &MissingSignerCheck,
        );

        assert!(findings.is_empty());
    }

    // ── seeds identifier boundary: `authority_bump` in seeds must NOT suppress
    //    a bare `authority` field ────────────────────────────────────────────

    #[test]
    fn seeds_suppression_requires_identifier_boundary() {
        // seeds contain `authority_bump`, which includes `authority` as substring
        // but not as a whole identifier. So `authority` must still be flagged.
        let findings = findings_for(
            r#"
            #[derive(Accounts)]
            pub struct Withdraw<'info> {
                #[account(seeds = [b"vault", authority_bump.as_ref()], bump)]
                pub vault: Account<'info, Vault>,
                pub authority: AccountInfo<'info>,
            }
        "#,
            &MissingSignerCheck,
        );

        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("authority"));
    }

    // ── legacy: original test preserved ──────────────────────────────────────

    #[test]
    fn flags_an_unconstrained_authority_account() {
        let findings = findings_for(
            r#"
            #[derive(Accounts)]
            pub struct Withdraw<'info> {
                pub vault: Account<'info, Vault>,
                pub authority: AccountInfo<'info>,
            }
        "#,
            &MissingSignerCheck,
        );

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "VL001");
        assert_eq!(findings[0].line, 5);
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
                pub price_feed: AccountInfo<'info>,
            }
        "#,
            &MissingSignerCheck,
        );

        assert!(findings.is_empty());
    }
}
