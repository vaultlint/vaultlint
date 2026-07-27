//! VL002 — account data deserialised without verifying the owning program.
//!
//! Two things decide whether a function is reported:
//!
//! * the **silencer** ([`has_owner_check`]) — does the body verify the owning
//!   program anywhere? A *mention* of `.owner` is not a check: `.owner` names
//!   two unrelated things in Solana code, `AccountInfo::owner` (the program)
//!   and the `owner` field of a deserialised SPL token account (the wallet),
//!   and the second is by far the more common in application code. The check
//!   must therefore appear in a checking *position*: a comparison, an
//!   assertion macro, or a call to an owner-checking helper.
//! * the **raw-read signal** ([`reads_account_data`]) — is a deserialiser being
//!   handed the account's raw bytes, either inline or through one `let` hop?
//!
//! Deliberately out of scope: [`is_deserialiser`] matches only
//! `syn::Expr::Call` with a path callee, so the *method* form
//! `account.try_deserialize(&mut data)` is not seen. That is intentional and
//! must stay that way — `try_deserialize` as a method on an Anchor typed
//! account is the **safe** path, it is what `Account<'info, T>` does
//! internally, after Anchor has already checked the owner. Matching it would
//! flag the correct pattern.

use syn::spanned::Spanned;
use syn::visit::{self, Visit};

use crate::finding::{Finding, Severity};
use crate::rules::{is_ident_char, normalised, Rule, RuleContext};

const DESERIALISERS: &[&str] = &["try_from_slice", "try_deserialize", "deserialize"];

/// Macros whose arguments are an assertion. A `.owner` mentioned inside one of
/// these is being checked, not merely read.
const OWNER_CHECK_MACROS: &[&str] = &[
    "require_keys_eq",
    "require_keys_neq",
    "require_eq",
    "require_neq",
    "require",
    "assert_eq",
    "assert_ne",
];

/// Textual signals that an expression is reading an account's raw bytes.
const RAW_READ_SIGNALS: &[&str] = &[
    ".data.borrow()",
    ".data.borrow_mut()",
    ".try_borrow_data()",
    ".try_borrow_mut_data()",
];

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
        if has_owner_check(block) {
            return;
        }
        let raw_read_locals = collect_raw_read_locals(block);
        let mut finder = RawReadFinder {
            spans: Vec::new(),
            raw_read_locals: &raw_read_locals,
        };
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

// ─── silencer ────────────────────────────────────────────────────────────────

/// True if the body verifies the owning program somewhere.
///
/// Three shapes count, and only these three; a bare read such as
/// `let holder = token_account.owner;` deliberately does not.
///
/// The compared-against side is *not* additionally required to look like a
/// program id (`::ID`, `program_id`). Requiring it would be a second narrowing
/// whose failure direction is false positives on legitimate checks against a
/// pubkey stored in state, which is not a trade this rule should make while it
/// is the tool's only High-severity finding.
fn has_owner_check(block: &syn::Block) -> bool {
    let mut finder = OwnerCheckFinder { found: false };
    finder.visit_block(block);
    finder.found
}

struct OwnerCheckFinder {
    found: bool,
}

impl<'ast> Visit<'ast> for OwnerCheckFinder {
    /// Rule 1 — `*account.owner == crate::ID`, and the `!=` form.
    fn visit_expr_binary(&mut self, node: &'ast syn::ExprBinary) {
        if matches!(node.op, syn::BinOp::Eq(_) | syn::BinOp::Ne(_))
            && (normalised(&node.left).contains(".owner")
                || normalised(&node.right).contains(".owner"))
        {
            self.found = true;
        }
        visit::visit_expr_binary(self, node);
    }

    /// Rule 2 — `require_keys_eq!(*account.owner, crate::ID)`. Macro tokens are
    /// never parsed as expressions, so rule 1 cannot see inside them.
    fn visit_macro(&mut self, node: &'ast syn::Macro) {
        let is_check_macro = node.path.segments.last().is_some_and(|segment| {
            OWNER_CHECK_MACROS.contains(&segment.ident.to_string().as_str())
        });
        if is_check_macro && normalised(&node.tokens).contains(".owner") {
            self.found = true;
        }
        visit::visit_macro(self, node);
    }

    /// Rule 3 — a helper that does the check: metaplex's
    /// `assert_owned_by(account, &crate::ID)?`, `check_account_owner`,
    /// `is_owned_by`. Matched on the final path segment rather than on the
    /// whole expression text, so an *argument* named `owner` does not silence.
    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        if let syn::Expr::Path(path) = &*node.func {
            if path
                .path
                .segments
                .last()
                .is_some_and(|segment| mentions_owner(&segment.ident))
            {
                self.found = true;
            }
        }
        visit::visit_expr_call(self, node);
    }

    /// Rule 3, method form — `account.assert_owner(&crate::ID)?`.
    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        if mentions_owner(&node.method) {
            self.found = true;
        }
        visit::visit_expr_method_call(self, node);
    }
}

fn mentions_owner(ident: &syn::Ident) -> bool {
    let name = ident.to_string().to_lowercase();
    name.contains("owner") || name.contains("owned")
}

// ─── raw-read locals ─────────────────────────────────────────────────────────

/// Names of the body's local `let` bindings whose initialiser reads raw account
/// data, so that the dominant real shape
///
/// ```ignore
/// let data = token_account_info.try_borrow_data()?;
/// let account = SplTokenAccount::try_from_slice(&data)?;
/// ```
///
/// is recognised as one read rather than two unrelated statements.
///
/// This is deliberately **not** shared with `cpi.rs`'s `collect_let_bindings`.
/// That collector keeps whole initialiser expressions and source positions
/// because VL005 has to substitute them and resolve a name as of a call's own
/// position; VL002 needs nothing but a set of names, and no position, because
/// a binding holding raw bytes taints the read wherever the deserialiser sits.
/// Unifying them would give one helper two jobs and force VL002's callers to
/// carry machinery they do not use.
fn collect_raw_read_locals(block: &syn::Block) -> Vec<String> {
    let mut out = Vec::new();
    collect_raw_read_locals_stmts(&block.stmts, &mut out);
    out
}

fn collect_raw_read_locals_stmts(stmts: &[syn::Stmt], out: &mut Vec<String>) {
    for stmt in stmts {
        match stmt {
            syn::Stmt::Local(local) => {
                if let Some(init) = &local.init {
                    if is_raw_read_text(&normalised(&init.expr)) {
                        if let syn::Pat::Ident(pat_ident) = unwrap_pat_type(&local.pat) {
                            out.push(pat_ident.ident.to_string());
                        }
                    }
                    collect_raw_read_locals_expr(&init.expr, out);
                    if let Some((_, diverge)) = &init.diverge {
                        collect_raw_read_locals_expr(diverge, out);
                    }
                }
            }
            syn::Stmt::Expr(expr, _) => collect_raw_read_locals_expr(expr, out),
            _ => {}
        }
    }
}

/// Walks the same block shapes as `RawReadFinder`'s `visit_block`, so that a
/// deserialiser found inside one of them can still resolve its argument.
fn collect_raw_read_locals_expr(expr: &syn::Expr, out: &mut Vec<String>) {
    match expr {
        syn::Expr::Block(b) => collect_raw_read_locals_stmts(&b.block.stmts, out),
        syn::Expr::If(e) => {
            collect_raw_read_locals_stmts(&e.then_branch.stmts, out);
            if let Some((_, else_expr)) = &e.else_branch {
                collect_raw_read_locals_expr(else_expr, out);
            }
        }
        syn::Expr::Match(m) => {
            for arm in &m.arms {
                collect_raw_read_locals_expr(&arm.body, out);
            }
        }
        syn::Expr::Loop(l) => collect_raw_read_locals_stmts(&l.body.stmts, out),
        syn::Expr::While(w) => collect_raw_read_locals_stmts(&w.body.stmts, out),
        syn::Expr::ForLoop(f) => collect_raw_read_locals_stmts(&f.body.stmts, out),
        syn::Expr::Unsafe(u) => collect_raw_read_locals_stmts(&u.block.stmts, out),
        syn::Expr::Closure(c) => collect_raw_read_locals_expr(&c.body, out),
        syn::Expr::Async(a) => collect_raw_read_locals_stmts(&a.block.stmts, out),
        syn::Expr::TryBlock(t) => collect_raw_read_locals_stmts(&t.block.stmts, out),
        _ => {}
    }
}

/// Unwrap `Pat::Type` to get the inner pattern: `let data: Ref<[u8]> = …` has
/// `Pat::Type { pat: Pat::Ident, … }`.
fn unwrap_pat_type(pat: &syn::Pat) -> &syn::Pat {
    if let syn::Pat::Type(pt) = pat {
        &pt.pat
    } else {
        pat
    }
}

// ─── raw-read finder ─────────────────────────────────────────────────────────

struct RawReadFinder<'a> {
    spans: Vec<proc_macro2::Span>,
    raw_read_locals: &'a [String],
}

impl<'ast> Visit<'ast> for RawReadFinder<'_> {
    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        if is_deserialiser(&node.func) && reads_account_data(&node.args, self.raw_read_locals) {
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

/// True if any argument is the account's raw bytes — written inline, or read
/// into a local first and passed by name (`&data`, `&data[8..]`).
fn reads_account_data(
    args: &syn::punctuated::Punctuated<syn::Expr, syn::Token![,]>,
    raw_read_locals: &[String],
) -> bool {
    args.iter().any(|arg| {
        let text = normalised(arg);
        is_raw_read_text(&text) || {
            let head = leading_ident(&text);
            !head.is_empty() && raw_read_locals.iter().any(|name| name == head)
        }
    })
}

fn is_raw_read_text(text: &str) -> bool {
    RAW_READ_SIGNALS.iter().any(|signal| text.contains(signal))
}

/// The identifier at the head of a normalised expression, after stripping the
/// `*`, `&` and `&mut` that an argument is usually wrapped in. `&data[8..]`
/// yields `data`.
///
/// `normalised` has already removed the whitespace, so `&mut data` arrives as
/// `&mutdata` and the `mut` can only be recognised as the borrow's, not the
/// identifier's, by position: it is stripped only directly after a `&`. A
/// local genuinely named `mutable` would therefore be read as `able` and its
/// read missed — a false negative, which is the safe direction, and the shape
/// does not occur in the corpus.
fn leading_ident(text: &str) -> &str {
    let mut rest = text;
    loop {
        if let Some(stripped) = rest.strip_prefix('*') {
            rest = stripped;
        } else if let Some(stripped) = rest.strip_prefix('&') {
            rest = stripped.strip_prefix("mut").unwrap_or(stripped);
        } else {
            break;
        }
    }
    let end = rest.find(|c: char| !is_ident_char(c)).unwrap_or(rest.len());
    &rest[..end]
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

    /// Defect 1. `token_account.owner` is the *wallet* that holds an SPL token
    /// balance, not the program that owns the account. Reading it is not a
    /// check and must not silence the function.
    ///
    /// Killing mutation: replace the body of `has_owner_check` with
    /// `normalised(block).contains(".owner")`.
    #[test]
    fn a_bare_owner_read_does_not_silence_the_rule() {
        let findings = findings_for(
            r#"
            pub fn read_config(ctx: Context<ReadConfig>) -> Result<()> {
                let account = &ctx.accounts.config;
                let holder = token_account.owner;
                let config = Config::try_from_slice(&account.data.borrow())?;
                Ok(())
            }
        "#,
            &MissingOwnerCheck,
        );

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "VL002");
        assert_eq!(findings[0].line, 5);
    }

    /// Silencer rule 1: a binary `==`/`!=` with `.owner` on one side.
    ///
    /// Killing mutation: delete the `visit_expr_binary` arm of
    /// `OwnerCheckFinder`.
    #[test]
    fn a_comparison_against_the_owner_still_silences() {
        let findings = findings_for(
            r#"
            pub fn read_config(ctx: Context<ReadConfig>) -> Result<()> {
                let account = &ctx.accounts.config;
                if *account.owner != crate::ID {
                    return err!(ErrorCode::WrongOwner);
                }
                let config = Config::try_from_slice(&account.data.borrow())?;
                Ok(())
            }
        "#,
            &MissingOwnerCheck,
        );

        assert!(findings.is_empty());
    }

    /// Silencer rule 3: a helper call whose name mentions owner/owned.
    ///
    /// Killing mutation: delete the `visit_expr_call` arm of
    /// `OwnerCheckFinder`.
    #[test]
    fn an_owner_helper_call_still_silences() {
        let findings = findings_for(
            r#"
            pub fn read_config(ctx: Context<ReadConfig>) -> Result<()> {
                let account = &ctx.accounts.config;
                assert_owned_by(account, &crate::ID)?;
                let config = Config::try_from_slice(&account.data.borrow())?;
                Ok(())
            }
        "#,
            &MissingOwnerCheck,
        );

        assert!(findings.is_empty());
    }

    /// Killing mutation: remove `".try_borrow_data()"` from `RAW_READ_SIGNALS`.
    #[test]
    fn flags_an_inline_try_borrow_data_read() {
        let findings = findings_for(
            r#"
            pub fn read_config(ctx: Context<ReadConfig>) -> Result<()> {
                let account = &ctx.accounts.config;
                let config = Config::try_from_slice(&account.try_borrow_data()?)?;
                Ok(())
            }
        "#,
            &MissingOwnerCheck,
        );

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].line, 4);
    }

    /// Killing mutation: remove `".data.borrow_mut()"` from `RAW_READ_SIGNALS`.
    #[test]
    fn flags_an_inline_mutable_borrow_read() {
        let findings = findings_for(
            r#"
            pub fn read_config(ctx: Context<ReadConfig>) -> Result<()> {
                let account = &ctx.accounts.config;
                let config = Config::try_from_slice(&account.data.borrow_mut())?;
                Ok(())
            }
        "#,
            &MissingOwnerCheck,
        );

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].line, 4);
    }

    /// Defect 2, part B: the dominant real shape binds the borrowed slice to a
    /// local first. The finding belongs on the deserialiser, not on the `let`.
    ///
    /// Killing mutation: delete the `raw_read_locals` branch of
    /// `reads_account_data` (the `leading_ident` lookup).
    #[test]
    fn flags_a_read_through_an_intermediate_local() {
        let findings = findings_for(
            r#"
            pub fn read_config(ctx: Context<ReadConfig>) -> Result<()> {
                let acc = &ctx.accounts.config;
                let data = acc.try_borrow_data()?;
                let cfg = Config::try_from_slice(&data)?;
                Ok(())
            }
        "#,
            &MissingOwnerCheck,
        );

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].line, 5);
    }

    /// The `let` hop must look at the initialiser. Without this test, a hop
    /// that records every local regardless of what it holds still passes
    /// `flags_a_read_through_an_intermediate_local`.
    ///
    /// Killing mutation: in `collect_raw_read_locals`, drop the
    /// `is_raw_read_text(&normalised(&init.expr))` condition and record every
    /// binding.
    #[test]
    fn the_let_hop_ignores_locals_that_do_not_hold_account_data() {
        let findings = findings_for(
            r#"
            pub fn read_config(ctx: Context<ReadConfig>) -> Result<()> {
                let data = compute_something();
                let cfg = Config::try_from_slice(&data)?;
                Ok(())
            }
        "#,
            &MissingOwnerCheck,
        );

        assert!(findings.is_empty());
    }

    /// Killing mutation: delete the `syn::Expr::If` arm of
    /// `collect_raw_read_locals_expr`.
    #[test]
    fn flags_an_intermediate_local_inside_a_nested_block() {
        let findings = findings_for(
            r#"
            pub fn read_config(ctx: Context<ReadConfig>) -> Result<()> {
                let acc = &ctx.accounts.config;
                if acc.lamports() > 0 {
                    let data = acc.try_borrow_data()?;
                    let cfg = Config::try_from_slice(&data)?;
                }
                Ok(())
            }
        "#,
            &MissingOwnerCheck,
        );

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].line, 6);
    }
}
