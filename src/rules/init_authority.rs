//! VL001 — an unproven authority whose key is baked into an account that this
//! instruction creates.
//!
//! The shape, taken from marginfi-v2 `MarginfiAccountInitializePda.authority`
//! (fixed in `95a4c26`, *"Authority must now sign to init account as PDA"*): a
//! raw `AccountInfo` / `UncheckedAccount` with an authority-like name, named in
//! the `seeds` of a sibling being `init`ialised, whose `.key()` the handler
//! writes into that freshly created account.  Nothing in the struct or the
//! handler proves the account agreed to be named, so anyone can create the PDA
//! designating an arbitrary owner.
//!
//! The rule deliberately does **not** detect the general "missing signer check"
//! class, and its finding text must not claim to.  Every discriminator wide
//! enough to reach the textbook case (an unvalidated authority with no `init`
//! and no seeds) also fired on production code that is permissionless on
//! purpose; the previous, broader VL001 measured 26 findings and zero true
//! positives across five audited programs.

use proc_macro2::{Delimiter, TokenStream, TokenTree};
use syn::visit::Visit;

use crate::anchor::{AccountField, AccountTy, AccountsStruct, Constraint};
use crate::finding::{Finding, Severity};
use crate::rules::{normalised, LinkedContext, LinkedRule};
use crate::usesite::FieldAccess;

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

pub struct UnprovenAuthorityOnInit;

/// Returns true if `name` equals `marker` exactly or ends with `_<marker>`.
fn matches_marker(name: &str, marker: &str) -> bool {
    name == marker || name.ends_with(&format!("_{marker}"))
}

fn is_authority_named(name: &str) -> bool {
    MARKERS.iter().any(|marker| matches_marker(name, marker))
}

/// Returns true if `field_name` appears in `constraint_text` as a reference to
/// the field itself — a bare identifier, not part of a longer name, not the
/// member of a field access, and not a segment of a path.
///
/// Boundaries, and why each one is there:
///
/// * alphanumeric / `_` on either side — `authority` must not match inside
///   `authority_bump` or `pool_authority`.
/// * `.` on the **left** — `vault.authority` reads the *vault's* stored pubkey.
///   It says nothing about the `authority` account we were handed, so it must
///   not stand in for a reference to it. (`.` on the **right** is fine and
///   common: `authority.key()` really is a use of our field.)  Anchor expands
///   `#[account(...)]` expressions where the struct's fields are bare locals, so
///   neither `self.authority` nor `ctx.accounts.authority` is valid syntax
///   there — excluding a `.`-prefixed match therefore loses no real reference.
/// * `:` on **either** side — `config::authority::ID` is a module path whose
///   segment happens to share the name; a field can neither be reached through
///   `::` nor have items hung off it.
fn name_in_seeds(field_name: &str, constraint_text: &str) -> bool {
    let bytes = constraint_text.as_bytes();
    let n = field_name.len();
    let text = constraint_text;

    let mut start = 0;
    while let Some(pos) = text[start..].find(field_name) {
        let abs = start + pos;
        // Check left boundary: must be start of string, or a character that can
        // neither continue an identifier (`a-z`, `_`) nor introduce one as a
        // member (`.`) or a path segment (`:`).
        let left_ok = abs == 0 || {
            let c = text.as_bytes()[abs - 1] as char;
            !c.is_alphanumeric() && c != '_' && c != '.' && c != ':'
        };
        // Check right boundary: must be end of string or a non-identifier char.
        // `:` is excluded as well, so `authority::ID` is read as a path.
        let right_ok = abs + n >= bytes.len() || {
            let c = bytes[abs + n] as char;
            !c.is_alphanumeric() && c != '_' && c != ':'
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

fn carries_init(field: &AccountField) -> bool {
    // `Constraint::Init` covers both `init` and `init_if_needed`.
    field.constraints.contains(&Constraint::Init)
}

/// T4 — `name` appears as a whole identifier inside this field's `seeds = [...]`.
fn seeds_name(field: &AccountField, name: &str) -> bool {
    field
        .constraints
        .iter()
        .any(|c| matches!(c, Constraint::Seeds(text) if name_in_seeds(name, text)))
}

/// S1 — the field's own `#[account(...)]` already pins it.
fn own_constraints_validate(field: &AccountField) -> bool {
    field.constraints.iter().any(|c| match c {
        // `seeds` makes the field itself a PDA that Anchor derives and checks;
        // `constraint = ...` is an arbitrary runtime assertion we take at face
        // value.
        Constraint::Seeds(_) | Constraint::Custom(_) => true,
        Constraint::Other(key, _) => key == "signer" || key == "address",
        _ => false,
    })
}

/// S2 — some sibling that is *not* being created here binds `name`.
///
/// The `init` exclusion is the whole point.  A binding to a **pre-existing**
/// account proves the relationship was established by an earlier — and
/// therefore signed — instruction, which makes the unsigned field a subject
/// rather than an actor.  A `has_one` against an account this same handler is
/// initialising proves nothing at all: the value it compares to is whatever
/// this instruction just wrote.
fn bound_by_settled_sibling(accounts: &AccountsStruct, name: &str) -> bool {
    accounts.fields.iter().any(|sibling| {
        sibling.name != name
            && !carries_init(sibling)
            && sibling.constraints.iter().any(|c| match c {
                Constraint::HasOne(target) => name_in_seeds(name, target),
                // Widened deliberately: the proving constraint is often a call
                // with no comparison operator, as in marginfi's
                // `constraint = is_signer_authorized(&a, g.admin, authority.key(), …)`.
                Constraint::Custom(expr) => name_in_seeds(name, expr),
                // `token::authority = x`, `mint::authority = x`, …
                Constraint::Other(key, value) => key.contains("::") && value == name,
                _ => false,
            })
    })
}

/// S3 — an authority-named `Signer` is present *and* proven by a settled
/// sibling.  That party is the one authorising the designation, which is the
/// ordinary "existing owner names a new owner" pattern.
fn has_proven_signer_authority(accounts: &AccountsStruct) -> bool {
    accounts.fields.iter().any(|field| {
        field.ty == AccountTy::Signer
            && is_authority_named(&field.name)
            && bound_by_settled_sibling(accounts, &field.name)
    })
}

/// One handler body in which this struct's fields are addressable, with the
/// prefix they are addressed through.
struct LinkedBody {
    /// `<binding>.accounts` or `self`.
    prefix: String,
    /// The body rendered by `body_text`.
    text: String,
    block: syn::Block,
}

impl LinkedBody {
    fn base(&self, field: &str) -> String {
        format!("{}.{}", self.prefix, field)
    }
}

/// Token text of a body with whitespace removed everywhere it is not needed to
/// keep two words apart, so `if authority . is_signer` renders as
/// `if authority.is_signer`.
///
/// `normalised` cannot be used for a whole body: it strips every space, gluing a
/// keyword to the identifier after it (`ifauthority`) and destroying the very
/// identifier boundaries the searches below rely on.  Rendering from tokens also
/// flattens macro arguments — syn keeps a macro body as an opaque token stream,
/// and `require!(ctx.accounts.authority.is_signer, …)` is the canonical Anchor
/// signer check.
fn body_text(tokens: TokenStream) -> String {
    let mut out = String::new();
    render(tokens, &mut out);
    out
}

fn render(tokens: TokenStream, out: &mut String) {
    for token in tokens {
        match token {
            TokenTree::Group(group) => {
                let (open, close) = match group.delimiter() {
                    Delimiter::Parenthesis => ("(", ")"),
                    Delimiter::Brace => ("{", "}"),
                    Delimiter::Bracket => ("[", "]"),
                    Delimiter::None => ("", ""),
                };
                out.push_str(open);
                render(group.stream(), out);
                out.push_str(close);
            }
            other => {
                let text = other.to_string();
                if is_word(text.chars().next()) && is_word(out.chars().next_back()) {
                    out.push(' ');
                }
                out.push_str(&text);
            }
        }
    }
}

fn is_word(c: Option<char>) -> bool {
    c.is_some_and(|c| c.is_alphanumeric() || c == '_')
}

/// Returns true if `needle` occurs in `haystack` as a complete expression: it
/// may not continue an identifier on either side, hang off a longer receiver
/// (`other.ctx.accounts.x` is not `ctx.accounts.x`) or be a path segment.
fn contains_access(haystack: &str, needle: &str) -> bool {
    let mut start = 0;
    while let Some(offset) = haystack[start..].find(needle) {
        let at = start + offset;
        let left_ok = at == 0 || {
            let c = haystack.as_bytes()[at - 1] as char;
            !c.is_alphanumeric() && c != '_' && c != '.' && c != ':'
        };
        let end = at + needle.len();
        let right_ok = end >= haystack.len() || {
            let c = haystack.as_bytes()[end] as char;
            !c.is_alphanumeric() && c != '_'
        };
        if left_ok && right_ok {
            return true;
        }
        start = at + 1;
        if start >= haystack.len() {
            break;
        }
    }
    false
}

/// True if `text` reads `<base>.<member>`, directly or through
/// `.to_account_info()`.
fn reads(text: &str, base: &str, member: &str) -> bool {
    contains_access(text, &format!("{base}.{member}"))
        || contains_access(text, &format!("{base}.to_account_info().{member}"))
}

/// Every `(callee name, argument position)` at which one of `spellings` is
/// handed to another function.
struct ForwardedTo {
    spellings: Vec<String>,
    hits: Vec<(String, usize)>,
}

impl ForwardedTo {
    fn record<'a>(&mut self, callee: &str, args: impl Iterator<Item = &'a syn::Expr>) {
        for (position, arg) in args.enumerate() {
            if self.spellings.contains(&normalised(arg)) {
                self.hits.push((callee.to_string(), position));
            }
        }
    }
}

impl<'ast> Visit<'ast> for ForwardedTo {
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let syn::Expr::Path(path) = &*call.func {
            if let Some(segment) = path.path.segments.last() {
                self.record(&segment.ident.to_string(), call.args.iter());
            }
        }
        syn::visit::visit_expr_call(self, call);
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        // The receiver is not an argument, and `UseSite::params` skips it too,
        // so positions line up on both sides of the hop.
        self.record(&call.method.to_string(), call.args.iter());
        syn::visit::visit_expr_method_call(self, call);
    }
}

/// The argument positions at which `field` leaves this body, in every spelling
/// that still carries the account: bare, borrowed, and via `.to_account_info()`.
fn forwarded_arguments(body: &LinkedBody, field: &str) -> Vec<(String, usize)> {
    let base = body.base(field);
    let mut visitor = ForwardedTo {
        spellings: vec![
            base.clone(),
            format!("&{base}"),
            format!("{base}.to_account_info()"),
            format!("&{base}.to_account_info()"),
        ],
        hits: Vec::new(),
    };
    visitor.visit_block(&body.block);
    visitor.hits
}

/// S4 — a use site establishes that `field` signed, directly or one call away.
fn establishes_signer(ctx: &LinkedContext<'_>, body: &LinkedBody, field: &str) -> bool {
    if reads(&body.text, &body.base(field), "is_signer") {
        return true;
    }
    // One hop.  metaplex's four `Buy` variants are false positives purely
    // because `get_fee_payer(authority, wallet)` does the `is_signer` test on
    // the caller's behalf; without this the rule reports all four.
    for (callee, position) in forwarded_arguments(body, field) {
        for site in ctx.index.functions_named(ctx.path, &callee) {
            let Some(parameter) = site.params.get(position) else {
                continue;
            };
            // A tuple or wildcard pattern holds its position but has no name to
            // search for.
            if parameter.is_empty() {
                continue;
            }
            if reads(
                &body_text(quote::ToTokens::to_token_stream(&site.block)),
                parameter,
                "is_signer",
            ) {
                return true;
            }
        }
    }
    false
}

impl LinkedRule for UnprovenAuthorityOnInit {
    fn id(&self) -> &'static str {
        "VL001"
    }

    fn check(&self, ctx: &LinkedContext<'_>, out: &mut Vec<Finding>) {
        for accounts in &ctx.anchor.accounts_structs {
            // T3 — something here is being created.
            let init_fields: Vec<&AccountField> =
                accounts.fields.iter().filter(|f| carries_init(f)).collect();
            if init_fields.is_empty() {
                continue;
            }

            // S3 is a property of the struct, not of any one field.
            if has_proven_signer_authority(accounts) {
                continue;
            }

            let mut candidates = Vec::new();
            for field in &accounts.fields {
                // T1 — a raw account; `account_ty` has already unwrapped `Box`.
                if !matches!(
                    field.ty,
                    AccountTy::AccountInfo | AccountTy::UncheckedAccount
                ) {
                    continue;
                }
                // T2
                if !is_authority_named(&field.name) {
                    continue;
                }
                if own_constraints_validate(field) {
                    continue;
                }
                if bound_by_settled_sibling(accounts, &field.name) {
                    continue;
                }
                // T4 — declaration order decides which `init` field is named.
                let Some(init_field) = init_fields
                    .iter()
                    .find(|init| seeds_name(init, &field.name))
                else {
                    continue;
                };
                candidates.push((field, init_field.name.clone()));
            }
            if candidates.is_empty() {
                continue;
            }

            let bodies: Vec<LinkedBody> = ctx
                .index
                .use_sites(ctx.path, &accounts.name)
                .into_iter()
                .filter_map(|site| {
                    let prefix = match &site.access {
                        FieldAccess::Context(binding) => format!("{binding}.accounts"),
                        FieldAccess::SelfImpl => "self".to_string(),
                        // Not produced by `use_sites`; a body reached by passing
                        // a field along has no name for the struct's fields.
                        FieldAccess::Plain => return None,
                    };
                    Some(LinkedBody {
                        prefix,
                        text: body_text(quote::ToTokens::to_token_stream(&site.block)),
                        block: site.block,
                    })
                })
                .collect();

            for (field, init_field) in candidates {
                // T5 — the handler reads the key, which is what turns the field
                // from an account that was merely handed over into the
                // *designated authority* of the new account.  A struct with no
                // linked body therefore never fires: that is what keeps
                // `anchor-spl`'s CPI accounts structs, which have no handler in
                // the crate at all, out of the results.
                if !bodies
                    .iter()
                    .any(|body| reads(&body.text, &body.base(&field.name), "key()"))
                {
                    continue;
                }
                if bodies
                    .iter()
                    .any(|body| establishes_signer(ctx, body, &field.name))
                {
                    continue;
                }

                out.push(ctx.finding(
                    self.id(),
                    Severity::Medium,
                    "unproven authority on initialization",
                    format!(
                        "`{field_name}` is an unvalidated account whose key is baked into the \
                         seeds of `{init_field}`, initialised by this instruction, and read by \
                         the handler. Nothing proves the account authorised this, so anyone can \
                         create `{init_field}` naming an arbitrary `{field_name}`.",
                        field_name = field.name
                    ),
                    "Declare the field as `Signer<'info>` if it must authorise the instruction, \
                     or bind it to an account whose authority was already proven \
                     (`has_one = ...`, `constraint = ...`). If the permissionless designation is \
                     intended, suppress the finding.",
                    field.span,
                ));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::{linked_findings_for, linked_findings_for_files};

    /// The `authority` declaration of the confirmed true positive, verbatim from
    /// marginfi-v2 at `95a4c26^` — `/// CHECK:` comment included, because the
    /// rule must never read one as a signal.
    const UNCHECKED_AUTHORITY: &str = "    /// CHECK: Authority is only used for PDA seed \
                                        derivation, no signing required\n    \
                                        pub authority: UncheckedAccount<'info>,";

    const AUTHORITY_SEED: &str = "authority.key().as_ref(),";

    /// marginfi-v2 `MarginfiAccountInitializePda` at `95a4c26^`, with three
    /// knobs so that each test can change exactly one thing about it.
    fn decl(seed: &str, authority_field: &str, siblings: &str) -> String {
        format!(
            r#"
#[derive(Accounts)]
#[instruction(account_index: u16, third_party_id: Option<u16>)]
pub struct MarginfiAccountInitializePda<'info> {{
    pub marginfi_group: AccountLoader<'info, MarginfiGroup>,
{siblings}
    #[account(
        init,
        payer = fee_payer,
        space = 8 + std::mem::size_of::<MarginfiAccount>(),
        seeds = [
            MARGINFI_ACCOUNT_SEED.as_bytes(),
            marginfi_group.key().as_ref(),
            {seed}
            &account_index.to_le_bytes(),
        ],
        bump
    )]
    pub marginfi_account: AccountLoader<'info, MarginfiAccount>,

{authority_field}

    #[account(mut)]
    pub fee_payer: Signer<'info>,
}}
"#
        )
    }

    /// The pre-fix struct exactly as it shipped.
    fn marginfi() -> String {
        decl(AUTHORITY_SEED, UNCHECKED_AUTHORITY, "")
    }

    /// The handler: an attacker-chosen pubkey is written into the freshly
    /// created account as its owning authority.
    const HANDLER: &str = r#"
pub fn initialize_account_pda(ctx: Context<MarginfiAccountInitializePda>) -> Result<()> {
    ctx.accounts.marginfi_account.initialize(ctx.accounts.authority.key());
    Ok(())
}
"#;

    fn one_file(source: &str) -> Vec<crate::finding::Finding> {
        linked_findings_for(source, &UnprovenAuthorityOnInit)
    }

    fn files(files: &[(&str, &str)]) -> Vec<crate::finding::Finding> {
        linked_findings_for_files(files, &UnprovenAuthorityOnInit)
    }

    fn line_of(source: &str, needle: &str) -> usize {
        source
            .lines()
            .position(|line| line.contains(needle))
            .expect("test source must contain the needle")
            + 1
    }

    fn assert_flags_authority(source: &str, findings: &[crate::finding::Finding]) {
        assert_eq!(findings.len(), 1, "expected 1 finding, got {findings:?}");
        assert_eq!(findings[0].rule_id, "VL001");
        assert_eq!(findings[0].line, line_of(source, "pub authority:"));
        assert!(findings[0].message.contains("authority"));
    }

    // 1 ── the confirmed true positive ───────────────────────────────────────

    #[test]
    fn flags_the_marginfi_authority_fixed_in_95a4c26() {
        let source = format!("{}{}", marginfi(), HANDLER);

        let findings = one_file(&source);

        assert_flags_authority(&source, &findings);
        assert!(findings[0].message.contains("marginfi_account"));
        assert_eq!(findings[0].severity, crate::finding::Severity::Medium);
        assert_eq!(findings[0].title, "unproven authority on initialization");
    }

    // 2 ── the fix silences it ───────────────────────────────────────────────

    /// The `95a4c26` diff is exactly this one line: `UncheckedAccount` →
    /// `Signer`.
    #[test]
    fn the_marginfi_fix_silences_the_finding() {
        let source = format!(
            "{}{}",
            decl(AUTHORITY_SEED, "    pub authority: Signer<'info>,", ""),
            HANDLER
        );

        assert!(one_file(&source).is_empty());
    }

    // 3 ── cross-file ────────────────────────────────────────────────────────

    #[test]
    fn finds_the_handler_in_another_file_of_the_same_crate() {
        let declaration = marginfi();

        let findings = files(&[("state.rs", &declaration), ("handler.rs", HANDLER)]);

        assert_flags_authority(&declaration, &findings);
    }

    // 4 ── `impl S` method ───────────────────────────────────────────────────

    #[test]
    fn an_impl_method_is_a_use_site() {
        let source = format!(
            "{}{}",
            marginfi(),
            "impl<'info> MarginfiAccountInitializePda<'info> {\n\
                 fn run(&self) -> Result<()> { self.authority.key(); Ok(()) }\n\
             }\n"
        );

        assert_flags_authority(&source, &one_file(&source));
    }

    // 5 ── T5 negative: no use site at all ───────────────────────────────────

    /// A struct nothing in the crate handles is a CPI argument bundle — this is
    /// how `anchor-spl`'s `metadata.rs` and `associated_token.rs` stay out of
    /// the results.
    #[test]
    fn a_struct_with_no_linked_body_never_fires() {
        assert!(one_file(&marginfi()).is_empty());
    }

    // 6 ── T5 negative: forwarded, never read ────────────────────────────────

    /// Forwarding the raw account into a CPI accounts list does not call
    /// `.key()`, and those forwards were the single largest source of false
    /// positives in the old rule.
    #[test]
    fn forwarding_the_account_into_a_cpi_without_reading_its_key_does_not_fire() {
        let source = format!(
            "{}{}",
            marginfi(),
            r#"
pub fn initialize_account_pda(ctx: Context<MarginfiAccountInitializePda>) -> Result<()> {
    let cpi = Transfer {
        authority: ctx.accounts.authority.to_account_info(),
        payer: ctx.accounts.fee_payer.to_account_info(),
    };
    Ok(())
}
"#
        );

        assert!(one_file(&source).is_empty(), "{:?}", one_file(&source));
    }

    // 7 ── T4 negative: not named in the seeds ───────────────────────────────

    #[test]
    fn an_authority_absent_from_the_seeds_does_not_fire() {
        let source = format!("{}{}", decl("", UNCHECKED_AUTHORITY, ""), HANDLER);

        assert!(one_file(&source).is_empty(), "{:?}", one_file(&source));
    }

    // 8 ── T4 boundary ───────────────────────────────────────────────────────

    /// `vault.authority` reads the vault's stored pubkey; it is not a reference
    /// to the `authority` account we were handed.
    #[test]
    fn a_field_access_in_the_seeds_does_not_satisfy_t4() {
        let source = format!(
            "{}{}",
            decl("vault.authority.key().as_ref(),", UNCHECKED_AUTHORITY, ""),
            HANDLER
        );

        assert!(one_file(&source).is_empty(), "{:?}", one_file(&source));
    }

    // 9 ── T3 negative ───────────────────────────────────────────────────────

    /// The sealevel-attacks textbook case: an unvalidated authority with no
    /// `init` and no seeds anywhere.  Missing this is deliberate and documented
    /// — every discriminator that reached it also fired on production code that
    /// is permissionless on purpose.
    #[test]
    fn the_textbook_missing_signer_case_is_a_deliberate_documented_miss() {
        let source = r#"
#[derive(Accounts)]
pub struct LogMessage<'info> {
    #[account(mut)]
    pub user: Account<'info, User>,
    /// CHECK: unvalidated
    pub authority: AccountInfo<'info>,
}

pub fn log_message(ctx: Context<LogMessage>) -> Result<()> {
    msg!("{}", ctx.accounts.authority.key());
    Ok(())
}
"#;

        assert!(one_file(source).is_empty());
    }

    // 10 ── S1 ───────────────────────────────────────────────────────────────

    #[test]
    fn an_own_constraint_silences_the_finding() {
        let source = format!(
            "{}{}",
            decl(
                AUTHORITY_SEED,
                "    /// CHECK: checked below\n    \
                 #[account(constraint = something)]\n    \
                 pub authority: UncheckedAccount<'info>,",
                ""
            ),
            HANDLER
        );

        assert!(one_file(&source).is_empty(), "{:?}", one_file(&source));
    }

    // 11 ── S2 ───────────────────────────────────────────────────────────────

    #[test]
    fn a_settled_sibling_binding_the_field_silences_the_finding() {
        let source = format!(
            "{}{}",
            decl(
                AUTHORITY_SEED,
                UNCHECKED_AUTHORITY,
                "    #[account(has_one = authority)]\n    pub state: Account<'info, State>,\n"
            ),
            HANDLER
        );

        assert!(one_file(&source).is_empty(), "{:?}", one_file(&source));
    }

    // 12 ── S2 must not accept an `init` sibling ─────────────────────────────

    /// The inverse of test 11: a `has_one` on an account this same instruction
    /// creates compares against a value this handler just wrote, so it proves
    /// nothing and the finding must stand.
    #[test]
    fn a_binding_on_an_init_sibling_proves_nothing() {
        let source = format!(
            "{}{}",
            decl(
                AUTHORITY_SEED,
                UNCHECKED_AUTHORITY,
                "    #[account(init, payer = fee_payer, space = 64, has_one = authority)]\n    \
                 pub state: Account<'info, State>,\n"
            ),
            HANDLER
        );

        assert_flags_authority(&source, &one_file(&source));
    }

    // 13 ── S2, widened form ─────────────────────────────────────────────────

    /// marginfi `TransferToNewAccountPda.new_authority`: the proving constraint
    /// is a function call with no comparison operator, so only the widened form
    /// of S2 sees it.
    #[test]
    fn a_constraint_call_mentioning_the_field_silences_the_finding() {
        let source = format!(
            "{}{}",
            decl(
                AUTHORITY_SEED,
                UNCHECKED_AUTHORITY,
                "    #[account(constraint = is_signer_authorized(&a, g.admin, authority.key(), \
                 false, false))]\n    pub state: Account<'info, State>,\n"
            ),
            HANDLER
        );

        assert!(one_file(&source).is_empty(), "{:?}", one_file(&source));
    }

    // 14 ── S3 ───────────────────────────────────────────────────────────────

    /// An already-proven authority is present and is the party authorising the
    /// designation — metaplex `DelegateAuctioneer`, marginfi `transfer_account`.
    #[test]
    fn a_proven_signer_authority_in_the_struct_silences_the_finding() {
        let source = format!(
            "{}{}",
            decl(
                AUTHORITY_SEED,
                UNCHECKED_AUTHORITY,
                "    pub admin: Signer<'info>,\n    \
                 #[account(has_one = admin)]\n    pub state: Account<'info, State>,\n"
            ),
            HANDLER
        );

        assert!(one_file(&source).is_empty(), "{:?}", one_file(&source));
    }

    // 15 ── S3 requires the binding ──────────────────────────────────────────

    /// The inverse of test 14: a `Signer` nothing relates to the state being
    /// touched is just a fee payer, not an authorising party.
    #[test]
    fn an_unbound_signer_does_not_stand_in_for_a_proven_authority() {
        let source = format!(
            "{}{}",
            decl(
                AUTHORITY_SEED,
                UNCHECKED_AUTHORITY,
                "    pub admin: Signer<'info>,\n"
            ),
            HANDLER
        );

        assert_flags_authority(&source, &one_file(&source));
    }

    // 16 ── S4 direct ────────────────────────────────────────────────────────

    /// `require!` is a macro, so the check is only visible if macro tokens are
    /// searched too.
    #[test]
    fn an_is_signer_check_in_the_handler_silences_the_finding() {
        let source = format!(
            "{}{}",
            marginfi(),
            r#"
pub fn initialize_account_pda(ctx: Context<MarginfiAccountInitializePda>) -> Result<()> {
    require!(ctx.accounts.authority.is_signer, MarginfiError::Unauthorized);
    ctx.accounts.marginfi_account.initialize(ctx.accounts.authority.key());
    Ok(())
}
"#
        );

        assert!(one_file(&source).is_empty(), "{:?}", one_file(&source));
    }

    // 17 ── S4 one hop ───────────────────────────────────────────────────────

    /// metaplex's `get_fee_payer` — the reason all four `Buy` variants were
    /// false positives.
    const FEE_PAYER_HELPER: &str = r#"
pub fn get_fee_payer(authority: &AccountInfo, wallet: &AccountInfo) -> Result<()> {
    if authority.to_account_info().is_signer {
        Ok(())
    } else {
        err!(ErrorCode::NoPayerPresent)
    }
}
"#;

    #[test]
    fn an_is_signer_check_one_call_away_silences_the_finding() {
        let source = format!(
            "{}{}{}",
            marginfi(),
            r#"
pub fn initialize_account_pda(ctx: Context<MarginfiAccountInitializePda>) -> Result<()> {
    get_fee_payer(&ctx.accounts.authority, &ctx.accounts.fee_payer)?;
    ctx.accounts.marginfi_account.initialize(ctx.accounts.authority.key());
    Ok(())
}
"#,
            FEE_PAYER_HELPER
        );

        assert!(one_file(&source).is_empty(), "{:?}", one_file(&source));
    }

    // 18 ── S4 must not leak across argument positions ───────────────────────

    /// The inverse of test 17: the field is passed where the helper's
    /// `wallet` parameter goes, and `wallet` is never checked.
    #[test]
    fn an_is_signer_check_on_a_different_parameter_does_not_silence_the_finding() {
        let source = format!(
            "{}{}{}",
            marginfi(),
            r#"
pub fn initialize_account_pda(ctx: Context<MarginfiAccountInitializePda>) -> Result<()> {
    get_fee_payer(&ctx.accounts.fee_payer, &ctx.accounts.authority)?;
    ctx.accounts.marginfi_account.initialize(ctx.accounts.authority.key());
    Ok(())
}
"#,
            FEE_PAYER_HELPER
        );

        assert_flags_authority(&source, &one_file(&source));
    }

    // 19 ── crate scoping ────────────────────────────────────────────────────

    /// sealevel-attacks declares `LogMessage` in both an `insecure` and a
    /// `secure` crate; unioning their handlers lets the secure crate's
    /// `is_signer` silence the insecure crate's finding.
    #[test]
    fn a_check_in_another_crate_does_not_silence_this_ones_finding() {
        let insecure = format!("{}{}", marginfi(), HANDLER);
        let secure = format!(
            "{}{}",
            marginfi(),
            r#"
pub fn initialize_account_pda(ctx: Context<MarginfiAccountInitializePda>) -> Result<()> {
    require!(ctx.accounts.authority.is_signer, MarginfiError::Unauthorized);
    ctx.accounts.marginfi_account.initialize(ctx.accounts.authority.key());
    Ok(())
}
"#
        );
        const MANIFEST: &str = "[package]\nname = \"c\"\n";

        let findings = files(&[
            ("insecure/lib.rs", &insecure),
            ("insecure/Cargo.toml", MANIFEST),
            ("secure/lib.rs", &secure),
            ("secure/Cargo.toml", MANIFEST),
        ]);

        assert_flags_authority(&insecure, &findings);
    }

    // ── the marker set ──────────────────────────────────────────────────────

    /// Every entry of `MARKERS` is load-bearing, in both its bare and its
    /// `<prefix>_<marker>` form.  The list is spelled out here rather than read
    /// from `MARKERS`, so that deleting an entry from the rule breaks the test.
    #[test]
    fn every_marker_name_fires_in_the_marginfi_shape() {
        let expected = [
            "authority",
            "admin",
            "owner",
            "signer",
            "payer",
            "delegate",
            "manager",
            "governance",
        ];
        assert_eq!(MARKERS, &expected, "MARKERS changed; update this test");
        for marker in expected {
            for name in [marker.to_string(), format!("pool_{marker}")] {
                let source = format!(
                    r#"
#[derive(Accounts)]
pub struct Create<'info> {{
    #[account(init, payer = fee_payer, space = 64, seeds = [{name}.key().as_ref()], bump)]
    pub record: Account<'info, Record>,
    /// CHECK: unvalidated
    pub {name}: UncheckedAccount<'info>,
    #[account(mut)]
    pub fee_payer: Signer<'info>,
}}

pub fn create(ctx: Context<Create>) -> Result<()> {{
    ctx.accounts.record.owner = ctx.accounts.{name}.key();
    Ok(())
}}
"#
                );
                let findings = one_file(&source);
                assert_eq!(findings.len(), 1, "`{name}` did not fire: {findings:?}");
                assert!(findings[0].message.contains(&name));
            }
        }
    }

    #[test]
    fn a_name_that_is_not_an_authority_marker_does_not_fire() {
        let source = format!(
            "{}{}",
            r#"
#[derive(Accounts)]
pub struct Create<'info> {
    #[account(init, payer = fee_payer, space = 64, seeds = [price_feed.key().as_ref()], bump)]
    pub record: Account<'info, Record>,
    /// CHECK: price oracle, not an authority
    pub price_feed: UncheckedAccount<'info>,
    #[account(mut)]
    pub fee_payer: Signer<'info>,
}
"#,
            r#"
pub fn create(ctx: Context<Create>) -> Result<()> {
    ctx.accounts.record.owner = ctx.accounts.price_feed.key();
    Ok(())
}
"#
        );

        assert!(one_file(&source).is_empty(), "{:?}", one_file(&source));
    }

    // ── body rendering ──────────────────────────────────────────────────────

    /// `normalised` would render this body as `ifauthority.is_signer{}`, which
    /// destroys the left identifier boundary every search here depends on.
    #[test]
    fn body_text_keeps_two_words_apart_but_glues_a_field_access() {
        let block: syn::Block =
            syn::parse_str("{ if authority.to_account_info().is_signer { ok() } }").unwrap();

        let text = body_text(quote::ToTokens::to_token_stream(&block));

        assert_eq!(text, "{if authority.to_account_info().is_signer{ok()}}");
        assert!(reads(&text, "authority", "is_signer"));
    }

    #[test]
    fn a_longer_receiver_is_not_the_account_we_are_tracking() {
        assert!(!contains_access(
            "other.ctx.accounts.authority.key()",
            "ctx.accounts.authority.key()"
        ));
        assert!(contains_access(
            "let k=ctx.accounts.authority.key();",
            "ctx.accounts.authority.key()"
        ));
    }
}
