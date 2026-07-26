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
            // Class 1: CPI account bundles have no `#[account(...)]` attribute on
            // any field.  In those structs validation is the callee's job; flagging
            // the authority-named fields is meaningless noise.
            let has_any_account_attr = accounts.fields.iter().any(|f| !f.constraints.is_empty());
            if !has_any_account_attr {
                continue;
            }

            // Pre-compute: collect all constraint *values* from every field in
            // this struct.  This covers seeds texts, has_one targets, namespaced
            // constraints such as `mint::authority = mint_authority`, plain
            // `payer = authority`, and custom `constraint = ...` expressions.
            // A field is considered "pinned" if its name appears as a whole
            // identifier in any of these value strings — the same boundary check
            // used for seeds prevents `authority` from matching `authority_bump`.
            let all_constraint_values: Vec<&str> = accounts
                .fields
                .iter()
                .flat_map(|f| {
                    f.constraints.iter().filter_map(|c| match c {
                        Constraint::Seeds(v) | Constraint::HasOne(v) | Constraint::Custom(v) => {
                            Some(v.as_str())
                        }
                        Constraint::Other(_, v) if !v.is_empty() => Some(v.as_str()),
                        Constraint::Bump(Some(v)) => Some(v.as_str()),
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

                // Check all forms of per-field validation — skip if any is present.

                // 1. `#[account(signer)]` → Other("signer", "")
                if field
                    .constraints
                    .iter()
                    .any(|c| matches!(c, Constraint::Other(k, _) if k == "signer"))
                {
                    continue;
                }

                // 2. `#[account(address = ...)]` → Other("address", value)
                if field
                    .constraints
                    .iter()
                    .any(|c| matches!(c, Constraint::Other(k, _) if k == "address"))
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

                // 3b. Field itself has `#[account(seeds = ..., bump)]` → it IS a
                //     PDA and Anchor validates the derivation.  A field name like
                //     `member_signer` that carries its own seeds constraint is not
                //     unvalidated — the runtime confirms the address at call time.
                if field
                    .constraints
                    .iter()
                    .any(|c| matches!(c, Constraint::Seeds(_)))
                {
                    continue;
                }

                // 4. Field name appears as a whole identifier in the value text of
                //    ANY constraint on ANY sibling field (seeds, has_one, payer =,
                //    mint::authority =, token::authority =, etc.).
                if all_constraint_values
                    .iter()
                    .any(|v| name_in_seeds(&field.name, v))
                {
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
                #[account(mut)]
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
                #[account(mut)]
                pub vault: Account<'info, Vault>,
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
                #[account(mut)]
                pub vault: Account<'info, Vault>,
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

    // ── class 1: CPI bundle (no #[account(...)] on any field) ─────────────

    /// Positive: struct with at least one constrained field fires for an
    /// unconstrained authority-named field.
    #[test]
    fn flags_authority_when_some_fields_have_constraints() {
        let findings = findings_for(
            r#"
            #[derive(Accounts)]
            pub struct Ctx<'info> {
                #[account(mut)]
                pub vault: AccountInfo<'info>,
                pub authority: AccountInfo<'info>,
            }
        "#,
            &MissingSignerCheck,
        );
        // vault has a constraint, so the struct is NOT a pure CPI bundle.
        // authority is unconstrained → should fire.
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("authority"));
    }

    /// Negative: CPI-bundle struct — no field carries ANY #[account(...)]
    /// attribute. VL001 must be silent (the callee program validates).
    ///
    /// Guard removed: class-1 CPI-bundle skip. When removed the test fails
    /// because VL001 flags `authority`.
    #[test]
    fn accepts_cpi_bundle_struct_with_no_account_attrs() {
        let findings = findings_for(
            r#"
            #[derive(Accounts)]
            pub struct ApproveCollectionAuthority<'info> {
                pub collection_authority_record: AccountInfo<'info>,
                pub new_collection_authority: AccountInfo<'info>,
                pub update_authority: AccountInfo<'info>,
                pub payer: AccountInfo<'info>,
                pub metadata: AccountInfo<'info>,
                pub mint: AccountInfo<'info>,
            }
        "#,
            &MissingSignerCheck,
        );
        assert!(
            findings.is_empty(),
            "expected no findings, got {findings:?}"
        );
    }

    // ── class 2: namespaced constraint values pin the field ───────────────

    /// Positive: `authority` is NOT pinned by any constraint value →
    /// VL001 fires. Differs from the negative below only by removing the
    /// mint::authority line from the sibling constraint.
    #[test]
    fn flags_authority_not_referenced_in_constraint_values() {
        let findings = findings_for(
            r#"
            #[derive(Accounts)]
            pub struct Ctx<'info> {
                #[account(init, mint::decimals = 6, payer = payer)]
                pub mint: Account<'info, Mint>,
                #[account(mut)]
                pub payer: Signer<'info>,
                pub authority: AccountInfo<'info>,
            }
        "#,
            &MissingSignerCheck,
        );
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("authority"));
    }

    /// Negative: `mint::authority = mint_authority` on a sibling field pins
    /// `mint_authority` — Anchor verifies the mint's authority equals that
    /// account at the program level. VL001 must be silent.
    ///
    /// Guard removed: name-in-any-constraint-value check. When removed the
    /// test fails because VL001 flags both `mint_authority` and
    /// `freeze_authority`.
    #[test]
    fn accepts_authority_pinned_by_namespaced_constraint_value() {
        let findings = findings_for(
            r#"
            #[derive(Accounts)]
            pub struct TestInitMintIfNeeded<'info> {
                #[account(init_if_needed, mint::decimals = 6,
                          mint::authority = mint_authority,
                          mint::freeze_authority = freeze_authority,
                          payer = payer)]
                pub mint: Account<'info, Mint>,
                #[account(mut)]
                pub payer: Signer<'info>,
                pub mint_authority: AccountInfo<'info>,
                pub freeze_authority: AccountInfo<'info>,
            }
        "#,
            &MissingSignerCheck,
        );
        assert!(
            findings.is_empty(),
            "expected no findings, got {findings:?}"
        );
    }

    // ── class 3: field with own seeds constraint is a PDA (validated) ────────

    /// Positive: `member_signer` has seeds on a *sibling* that don't contain
    /// its name → it IS unconstrained → must fire.
    #[test]
    fn flags_signer_not_covered_by_own_seeds() {
        let findings = findings_for(
            r#"
            #[derive(Accounts)]
            pub struct Stake<'info> {
                #[account(mut)]
                pub vault: Account<'info, Vault>,
                pub member_signer: AccountInfo<'info>,
            }
        "#,
            &MissingSignerCheck,
        );
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("member_signer"));
    }

    /// Negative: `member_signer` itself carries `#[account(seeds = [...], bump)]`
    /// — Anchor verifies it equals the PDA, so it IS validated. VL001 silent.
    ///
    /// Guard removed: own-seeds check. When removed the test fails because
    /// VL001 flags `member_signer`.
    #[test]
    fn accepts_authority_field_with_own_seeds_constraint() {
        let findings = findings_for(
            r#"
            #[derive(Accounts)]
            pub struct ExecuteTransaction<'info> {
                pub registrar: Account<'info, Registrar>,
                #[account(
                    seeds = [registrar.to_account_info().key.as_ref(), member.to_account_info().key.as_ref()],
                    bump = member.nonce,
                )]
                pub member_signer: AccountInfo<'info>,
                pub member: Account<'info, Member>,
            }
        "#,
            &MissingSignerCheck,
        );
        assert!(
            findings.is_empty(),
            "expected no findings, got {findings:?}"
        );
    }

    // ── legacy: original test preserved ──────────────────────────────────────

    #[test]
    fn flags_an_unconstrained_authority_account() {
        let findings = findings_for(
            r#"
            #[derive(Accounts)]
            pub struct Withdraw<'info> {
                #[account(mut)]
                pub vault: Account<'info, Vault>,
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
                pub price_feed: AccountInfo<'info>,
            }
        "#,
            &MissingSignerCheck,
        );

        assert!(findings.is_empty());
    }
}
