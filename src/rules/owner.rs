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
//! * the **raw-read signal** ([`RawReadFinder`]) — is a deserialiser being
//!   handed the account's raw bytes, either inline or through one `let` hop?
//! * two **per-read silencers**, which need to know *which account* the bytes
//!   came from and so cannot live in [`has_owner_check`]:
//!   [`pda_address_check_covers`] (the body derives the account's address from
//!   this program's own id and compares it) and
//!   [`anchor_address_constraint_covers`] (the `#[derive(Accounts)]` struct
//!   pins the field's address, so Anchor checked it before the body ran).
//!   Both are address checks, and an address check is not weaker than an owner
//!   check: only this program can sign for its own PDA, so data sitting at that
//!   address was put there by this program.
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

use crate::anchor::{AccountsStruct, Constraint};
use crate::finding::{Finding, Severity};
use crate::rules::{is_ident_char, normalised, whole_word_match, Rule, RuleContext};
use crate::usesite::context_struct_name;

const DESERIALISERS: &[&str] = &["try_from_slice", "try_deserialize", "deserialize"];

/// Calls that derive a program address. Their presence is what turns a pubkey
/// comparison into a proof of ownership: only the deriving program can sign for
/// the address it derives.
const PDA_DERIVATIONS: &[&str] = &[
    "find_program_address",
    "create_program_address",
    "assert_derivation",
];

/// How an `Accounts` struct's fields are addressed inside a handler body.
const ACCOUNTS_PATH: &str = ".accounts.";

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
    fn check(&self, ctx: &RuleContext<'_>, out: &mut Vec<Finding>) {
        let mut visitor = FunctionVisitor {
            ctx,
            out,
            impl_self_ty: None,
        };
        visitor.visit_file(ctx.ast);
    }
}

struct FunctionVisitor<'a, 'ctx> {
    ctx: &'a RuleContext<'ctx>,
    out: &'a mut Vec<Finding>,
    /// Final path segment of the enclosing `impl` block's self type, so that a
    /// handler declared `ctx: Context<Self>` can still be resolved to its
    /// `Accounts` struct. Squads-v4 writes every account-closing instruction
    /// that way, and without this the struct lookup would find nothing.
    impl_self_ty: Option<String>,
}

impl FunctionVisitor<'_, '_> {
    fn check_body(&mut self, sig: &syn::Signature, block: &syn::Block) {
        if has_owner_check(block) {
            return;
        }
        let ctx = self.ctx;
        let accounts = context_accounts_struct(ctx, self.impl_self_ty.as_deref(), sig);
        let bindings = collect_let_bindings(block);
        let raw_read_locals = raw_read_locals(&bindings);
        let mut finder = RawReadFinder {
            reads: Vec::new(),
            bindings: &bindings,
            raw_read_locals: &raw_read_locals,
        };
        finder.visit_block(block);
        let evidence = AddressEvidence::of(block);
        for read in finder.reads {
            if pda_address_check_covers(&read, &evidence)
                || anchor_address_constraint_covers(&read, accounts)
            {
                continue;
            }
            self.out.push(
                ctx.finding(
                    "VL002",
                    Severity::High,
                    "missing owner check",
                    "Account data is deserialised without verifying the account owner. \
                 An attacker can pass a look-alike account owned by another program."
                        .to_string(),
                    "Use `Account<'info, T>`, which checks the owner and discriminator, \
                 or add `require_keys_eq!(*account.owner, crate::ID)` before reading.",
                    read.span,
                ),
            );
        }
    }
}

impl<'ast> Visit<'ast> for FunctionVisitor<'_, '_> {
    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        self.check_body(&node.sig, &node.block);
    }

    fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
        self.check_body(&node.sig, &node.block);
    }

    fn visit_item_impl(&mut self, node: &'ast syn::ItemImpl) {
        let outer = self.impl_self_ty.take();
        self.impl_self_ty = type_final_segment(&node.self_ty);
        visit::visit_item_impl(self, node);
        self.impl_self_ty = outer;
    }
}

/// The `Accounts` struct behind this function's `Context<S>` parameter, if the
/// file declares one. `Context<Self>` resolves through the enclosing `impl`.
fn context_accounts_struct<'a>(
    ctx: &'a RuleContext<'_>,
    impl_self_ty: Option<&str>,
    sig: &syn::Signature,
) -> Option<&'a AccountsStruct> {
    let name = sig.inputs.iter().find_map(|arg| {
        let syn::FnArg::Typed(typed) = arg else {
            return None;
        };
        context_struct_name(&typed.ty)
    })?;
    let name = if name == "Self" {
        impl_self_ty?.to_string()
    } else {
        name
    };
    ctx.anchor
        .accounts_structs
        .iter()
        .find(|accounts| accounts.name == name)
}

fn type_final_segment(ty: &syn::Type) -> Option<String> {
    let syn::Type::Path(path) = ty else {
        return None;
    };
    path.path
        .segments
        .last()
        .map(|segment| segment.ident.to_string())
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

// ─── let bindings ────────────────────────────────────────────────────────────

/// One `let` binding of the body, with its initialiser reduced to normalised,
/// deref-stripped text.
struct LetBinding {
    name: String,
    init: String,
}

/// Every local `let` binding of the body, so that the dominant real shape
///
/// ```ignore
/// let data = token_account_info.try_borrow_data()?;
/// let account = SplTokenAccount::try_from_slice(&data)?;
/// ```
///
/// is recognised as one read rather than two unrelated statements, and so that
/// an alias — `let proposal = &mut ctx.accounts.proposal;` — can be resolved
/// back to the struct field it names.
///
/// This is deliberately **not** shared with `cpi.rs`'s `collect_let_bindings`.
/// That collector keeps whole initialiser *expressions* and source positions
/// because VL005 has to substitute them and resolve a name as of a call's own
/// position; VL002 needs text and no position, because a binding holding raw
/// bytes taints the read wherever the deserialiser sits. Unifying them would
/// give one helper two jobs and force VL002's callers to carry machinery they
/// do not use.
fn collect_let_bindings(block: &syn::Block) -> Vec<LetBinding> {
    let mut out = Vec::new();
    collect_let_bindings_stmts(&block.stmts, &mut out);
    out
}

fn collect_let_bindings_stmts(stmts: &[syn::Stmt], out: &mut Vec<LetBinding>) {
    for stmt in stmts {
        match stmt {
            syn::Stmt::Local(local) => {
                if let Some(init) = &local.init {
                    if let syn::Pat::Ident(pat_ident) = unwrap_pat_type(&local.pat) {
                        out.push(LetBinding {
                            name: pat_ident.ident.to_string(),
                            init: strip_derefs(&normalised(&init.expr)).to_string(),
                        });
                    }
                    collect_let_bindings_expr(&init.expr, out);
                    if let Some((_, diverge)) = &init.diverge {
                        collect_let_bindings_expr(diverge, out);
                    }
                }
            }
            syn::Stmt::Expr(expr, _) => collect_let_bindings_expr(expr, out),
            _ => {}
        }
    }
}

/// Walks the same block shapes as `RawReadFinder`'s `visit_block`, so that a
/// deserialiser found inside one of them can still resolve its argument.
fn collect_let_bindings_expr(expr: &syn::Expr, out: &mut Vec<LetBinding>) {
    match expr {
        syn::Expr::Block(b) => collect_let_bindings_stmts(&b.block.stmts, out),
        syn::Expr::If(e) => {
            collect_let_bindings_stmts(&e.then_branch.stmts, out);
            if let Some((_, else_expr)) = &e.else_branch {
                collect_let_bindings_expr(else_expr, out);
            }
        }
        syn::Expr::Match(m) => {
            for arm in &m.arms {
                collect_let_bindings_expr(&arm.body, out);
            }
        }
        syn::Expr::Loop(l) => collect_let_bindings_stmts(&l.body.stmts, out),
        syn::Expr::While(w) => collect_let_bindings_stmts(&w.body.stmts, out),
        syn::Expr::ForLoop(f) => collect_let_bindings_stmts(&f.body.stmts, out),
        syn::Expr::Unsafe(u) => collect_let_bindings_stmts(&u.block.stmts, out),
        syn::Expr::Closure(c) => collect_let_bindings_expr(&c.body, out),
        syn::Expr::Async(a) => collect_let_bindings_stmts(&a.block.stmts, out),
        syn::Expr::TryBlock(t) => collect_let_bindings_stmts(&t.block.stmts, out),
        _ => {}
    }
}

/// Locals holding raw account bytes, each paired with the receivers of the read
/// that filled it. A name bound more than once contributes one entry per
/// binding; the resolution here is textual and carries no source position, so
/// every candidate is kept rather than guessing which one is in scope.
fn raw_read_locals(bindings: &[LetBinding]) -> Vec<(String, Vec<String>)> {
    bindings
        .iter()
        .filter_map(|binding| {
            let prefix = raw_read_prefix(&binding.init)?;
            Some((binding.name.clone(), receivers_of(prefix, bindings)))
        })
        .collect()
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

/// One deserialisation of raw account bytes.
struct RawRead {
    span: proc_macro2::Span,
    /// Every candidate text for the account the bytes came from — the receiver
    /// as written, plus its one-hop alias expansion, plus one entry per
    /// same-named binding. A silencer fires if *any* candidate is proved,
    /// because they all name the same read.
    receivers: Vec<String>,
}

struct RawReadFinder<'a> {
    reads: Vec<RawRead>,
    bindings: &'a [LetBinding],
    raw_read_locals: &'a [(String, Vec<String>)],
}

impl<'ast> Visit<'ast> for RawReadFinder<'_> {
    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        if is_deserialiser(&node.func) {
            let receivers = self.read_receivers(&node.args);
            if !receivers.is_empty() {
                self.reads.push(RawRead {
                    span: node.span(),
                    receivers,
                });
            }
        }
        visit::visit_expr_call(self, node);
    }
}

impl RawReadFinder<'_> {
    /// The accounts whose raw bytes reach this call — empty if none do, which
    /// is what makes this both the raw-read test and the receiver lookup.
    fn read_receivers(
        &self,
        args: &syn::punctuated::Punctuated<syn::Expr, syn::Token![,]>,
    ) -> Vec<String> {
        let mut out = Vec::new();
        for arg in args {
            let text = normalised(arg);
            if let Some(prefix) = raw_read_prefix(&text) {
                out.extend(receivers_of(prefix, self.bindings));
                continue;
            }
            let head = leading_ident(&text);
            for (name, receivers) in self.raw_read_locals {
                if name == head {
                    out.extend(receivers.iter().cloned());
                }
            }
        }
        out
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

/// The text preceding the first raw-read signal, i.e. the expression the bytes
/// were borrowed from. `None` when the text does not read account data at all.
fn raw_read_prefix(text: &str) -> Option<&str> {
    RAW_READ_SIGNALS
        .iter()
        .filter_map(|signal| text.find(signal))
        .min()
        .map(|at| &text[..at])
}

/// Candidate account texts for a raw read whose bytes came from `prefix`: the
/// receiver as written, plus — when its head names a local that is a plain
/// alias — that alias expanded once.
///
/// Both are kept because the two silencers ask different questions of them. S3
/// matches the *identifier* against proofs written in the same body, where the
/// alias name is what appears (`assert_derivation(…, metadata, …)` next to
/// `let metadata = &self.metadata;`). S4 needs the qualified
/// `ctx.accounts.<field>` form that only the expansion produces
/// (`let proposal = &mut ctx.accounts.proposal;`).
fn receivers_of(prefix: &str, bindings: &[LetBinding]) -> Vec<String> {
    let base = strip_derefs(prefix);
    let mut out = vec![base.to_string()];
    let head = ident_prefix(base);
    if head.is_empty() {
        return out;
    }
    let suffix = &base[head.len()..];
    for binding in bindings
        .iter()
        .filter(|binding| binding.name == head && is_alias(&binding.init))
    {
        out.push(format!("{}{suffix}", binding.init));
    }
    out
}

/// True if an initialiser is a plain path or field access, so that substituting
/// it for the binding name yields another account expression. An initialiser
/// containing a call is a *value* — `let metadata = Metadata::deserialize(…)`
/// re-binds the name to the parsed struct, and expanding through it would swap
/// the account for its contents.
fn is_alias(init: &str) -> bool {
    !init.is_empty() && !init.contains('(')
}

/// Strips the `*`, `&` and `&mut` an account expression is usually wrapped in.
///
/// `normalised` has already removed the whitespace, so `&mut data` arrives as
/// `&mutdata` and the `mut` can only be recognised as the borrow's, not the
/// identifier's, by position: it is stripped only directly after a `&`. A
/// local genuinely named `mutable` would therefore be read as `able` and its
/// read missed — a false negative, which is the safe direction, and the shape
/// does not occur in the corpus.
fn strip_derefs(text: &str) -> &str {
    let mut rest = text;
    loop {
        if let Some(stripped) = rest.strip_prefix('*') {
            rest = stripped;
        } else if let Some(stripped) = rest.strip_prefix('&') {
            rest = stripped.strip_prefix("mut").unwrap_or(stripped);
        } else {
            return rest;
        }
    }
}

/// The leading identifier of `text`, which must already be deref-stripped.
fn ident_prefix(text: &str) -> &str {
    let end = text.find(|c: char| !is_ident_char(c)).unwrap_or(text.len());
    &text[..end]
}

/// The identifier at the head of a normalised expression, after stripping the
/// borrow and deref operators. `&data[8..]` yields `data`.
fn leading_ident(text: &str) -> &str {
    ident_prefix(strip_derefs(text))
}

/// The last dot-separated component of `receiver` that is a plain identifier,
/// skipping components that end with a call (i.e. contain `(`).
///
/// This is needed by S3 so that an Anchor receiver such as
/// `ctx.accounts.collection_metadata` is matched by its trailing field name
/// (`collection_metadata`) rather than by its leading identifier (`ctx`).
/// Matching `ctx` would degenerate to "the body contains any comparison
/// mentioning `ctx`", which is almost always true and allows a check of an
/// unrelated account to silence the read.
///
/// Examples (receiver → result):
/// * `ctx.accounts.collection_metadata` → `collection_metadata`
/// * `favorite_account`                 → `favorite_account`
/// * `self.metadata`                    → `metadata`
/// * `source_account.to_account_info()` → `source_account` (call skipped)
fn trailing_ident(receiver: &str) -> &str {
    // Walk dot-separated segments from the right, skipping call components.
    let base = strip_derefs(receiver);
    let mut rest = base;
    loop {
        // Find the last dot.
        match rest.rfind('.') {
            None => {
                // Single segment — return it if it's a plain identifier.
                let ident = ident_prefix(rest);
                return if ident.is_empty() {
                    ident_prefix(base)
                } else {
                    ident
                };
            }
            Some(dot) => {
                let after_dot = &rest[dot + 1..];
                // If the segment after the dot contains `(`, it is a call;
                // skip it and look at the part before the dot.
                if after_dot.contains('(') {
                    rest = &rest[..dot];
                } else {
                    // Plain identifier segment — return it.
                    let ident = ident_prefix(after_dot);
                    return if ident.is_empty() {
                        ident_prefix(base)
                    } else {
                        ident
                    };
                }
            }
        }
    }
}

// ─── S3: an address check derived from this program's id ─────────────────────

/// What a body offers as proof that an account sits at an address this program
/// derived.
#[derive(Default)]
struct AddressEvidence {
    /// A [`PDA_DERIVATIONS`] call appears somewhere in the body.
    derives: bool,
    /// Texts in which an account being *checked* would be named: comparisons,
    /// assertion macros, and the arguments of the derivations themselves.
    proofs: Vec<String>,
}

impl AddressEvidence {
    fn of(block: &syn::Block) -> Self {
        let mut evidence = Self::default();
        evidence.visit_block(block);
        evidence
    }
}

impl<'ast> Visit<'ast> for AddressEvidence {
    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        if let syn::Expr::Path(path) = &*node.func {
            if path.path.segments.last().is_some_and(|segment| {
                PDA_DERIVATIONS.contains(&segment.ident.to_string().as_str())
            }) {
                self.derives = true;
                self.proofs.push(normalised(&node.args));
            }
        }
        visit::visit_expr_call(self, node);
    }

    fn visit_expr_binary(&mut self, node: &'ast syn::ExprBinary) {
        if matches!(node.op, syn::BinOp::Eq(_) | syn::BinOp::Ne(_)) {
            self.proofs.push(normalised(node));
        }
        visit::visit_expr_binary(self, node);
    }

    fn visit_macro(&mut self, node: &'ast syn::Macro) {
        let tokens = normalised(&node.tokens);
        let is_check_macro = node.path.segments.last().is_some_and(|segment| {
            OWNER_CHECK_MACROS.contains(&segment.ident.to_string().as_str())
        });
        // OWNER_CHECK_MACROS arm: `require_keys_eq!(a, b)` contains no `==`
        // and would be lost without this unconditional push.
        if is_check_macro {
            self.proofs.push(tokens.clone());
        }
        // Comparison arm: `assert!(pda == account.key)` is not in
        // OWNER_CHECK_MACROS, but its tokens contain `==` and constitute a
        // proof. Gate on the comparison operator so that a bare logging macro
        // such as `msg!("{}", account.key)` (which names the account but proves
        // nothing) does not become a silencer.
        if !is_check_macro && (tokens.contains("==") || tokens.contains("!=")) {
            self.proofs.push(tokens);
        }
        visit::visit_macro(self, node);
    }
}

/// True when the body both derives a program address **and** names this read's
/// account in a check.
///
/// Both halves are required. Without the second, deriving a PDA for account X
/// would silence a raw read of an unrelated account Y — "verified something,
/// therefore verified everything". Ordering is deliberately not required: a
/// check that follows the read still stops the program acting on bad data, and
/// demanding order would mean carrying source positions into this rule. The
/// accepted cost is that a deserialise-then-check body such as
/// `program-examples/tokens/escrow/native/…/take_offer.rs` goes silent.
fn pda_address_check_covers(read: &RawRead, evidence: &AddressEvidence) -> bool {
    evidence.derives
        && read.receivers.iter().any(|receiver| {
            // Use the trailing path segment so that an Anchor receiver such as
            // `ctx.accounts.collection_metadata` is tied to the account it
            // actually names rather than to the shared `ctx` prefix. If the
            // leading identifier were used, condition 2 would degenerate to
            // "the body contains any comparison mentioning `ctx`", which is
            // almost always true and allowed a check of an unrelated account
            // to silence the read (the class-A false-negative described in
            // fix round 1's §4).
            let account = trailing_ident(receiver);
            evidence
                .proofs
                .iter()
                .any(|proof| whole_word_match(proof, account))
        })
}

// ─── S4: an Anchor address or seeds constraint ───────────────────────────────

/// True when the field this read names carries a constraint that makes Anchor
/// verify its address before the body runs.
///
/// Only the field actually being read may silence: a struct holding *some*
/// address-constrained field says nothing about a different field.
fn anchor_address_constraint_covers(read: &RawRead, accounts: Option<&AccountsStruct>) -> bool {
    let Some(accounts) = accounts else {
        return false;
    };
    read.receivers.iter().any(|receiver| {
        field_after_accounts(receiver).is_some_and(|field| is_address_constrained(accounts, field))
    })
}

/// `ctx.accounts.proposal` -> `proposal`. `None` when the receiver is not of
/// that shape, in which case S4 does not apply and the finding stands.
///
/// The whole path up to `.accounts.` is required, not just the trailing name:
/// matching a bare field name would silence an unrelated same-named account,
/// which is a bug this project has already shipped once.
fn field_after_accounts(receiver: &str) -> Option<&str> {
    let at = receiver.find(ACCOUNTS_PATH)? + ACCOUNTS_PATH.len();
    let field = ident_prefix(&receiver[at..]);
    (!field.is_empty()).then_some(field)
}

fn is_address_constrained(accounts: &AccountsStruct, field: &str) -> bool {
    accounts
        .fields
        .iter()
        .filter(|candidate| candidate.name == field)
        .any(|candidate| candidate.constraints.iter().any(proves_address))
}

fn proves_address(constraint: &Constraint) -> bool {
    match constraint {
        Constraint::Seeds(_) => true,
        Constraint::Other(key, _) => key == "address",
        _ => false,
    }
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

    /// The method-call form `account.try_deserialize(…)` is how Anchor's typed
    /// `Account<'info, T>` works internally, after the framework has already
    /// checked the account owner. `is_deserialiser` matches only `Expr::Call`
    /// with a path callee, so the method form is invisible to it and produces no
    /// finding. The fixture contains raw bytes (`data.borrow()`) which reaches the
    /// method call, so the positive case (path-call form) produces a finding on
    /// the same shape.
    ///
    /// Killing mutation: in `RawReadFinder::visit_expr_call`, also match
    /// `visit_expr_method_call` so that `account.try_deserialize(…)` is treated
    /// as a raw read. The test then produces one finding instead of zero.
    #[test]
    fn ignores_typed_anchor_accounts() {
        let findings = findings_for(
            r#"
            pub fn read_config(ctx: Context<ReadConfig>) -> Result<()> {
                let account = &ctx.accounts.config;
                let mut data = account.data.borrow();
                let config = account.try_deserialize(&mut data.as_ref())?;
                msg!("{}", config.fee);
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
    /// `RawReadFinder::read_receivers` (the `leading_ident` lookup).
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
    /// Killing mutation: in `raw_read_locals`, drop the `raw_read_prefix`
    /// guard and record every binding as holding account data.
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

    // ── S3: a PDA address check is an owner check ────────────────────────────

    /// Class B. Only this program can sign for its own PDA, so an account that
    /// exists at a PDA derived from this program's id and holds data was
    /// created — and is owned — by this program.
    ///
    /// Killing mutation: empty `PDA_DERIVATIONS`, so condition 1 never holds.
    #[test]
    fn a_pda_address_check_silences_the_read_it_proves() {
        let findings = findings_for(
            r#"
            pub fn get_pda(program_id: &Pubkey, favorite_account: &AccountInfo, user: &AccountInfo) -> ProgramResult {
                let (favorite_pda, _bump) =
                    Pubkey::find_program_address(&[b"favorite", user.key.as_ref()], program_id);
                if favorite_account.key != &favorite_pda {
                    return Err(ProgramError::IncorrectProgramId);
                }
                let favorites = Favorites::try_from_slice(&favorite_account.data.borrow())?;
                Ok(())
            }
        "#,
            &MissingOwnerCheck,
        );

        assert!(findings.is_empty());
    }

    /// S3 must not over-reach across accounts: deriving and checking one
    /// account's address proves nothing about a *different* account.
    ///
    /// Killing mutation: drop condition 2 from `pda_address_check_covers`
    /// (the receiver-identifier match), leaving only "a derivation exists".
    #[test]
    fn a_pda_address_check_does_not_silence_a_different_account() {
        let findings = findings_for(
            r#"
            pub fn get_pda(program_id: &Pubkey, favorite_account: &AccountInfo, other_account: &AccountInfo, user: &AccountInfo) -> ProgramResult {
                let (favorite_pda, _bump) =
                    Pubkey::find_program_address(&[b"favorite", user.key.as_ref()], program_id);
                if favorite_account.key != &favorite_pda {
                    return Err(ProgramError::IncorrectProgramId);
                }
                let favorites = Favorites::try_from_slice(&other_account.data.borrow())?;
                Ok(())
            }
        "#,
            &MissingOwnerCheck,
        );

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "VL002");
        assert_eq!(findings[0].line, 8);
    }

    /// A comparison against an arbitrary pubkey is not a PDA proof. Without a
    /// derivation of this program's own address there is nothing that ties the
    /// account to this program.
    ///
    /// Killing mutation: drop condition 1 from `pda_address_check_covers`
    /// (the `evidence.derives &&`).
    #[test]
    fn a_comparison_without_a_derivation_does_not_silence() {
        let findings = findings_for(
            r#"
            pub fn read_config(config_account: &AccountInfo, expected: &Pubkey) -> ProgramResult {
                if config_account.key != expected {
                    return Err(ProgramError::IncorrectProgramId);
                }
                let config = Config::try_from_slice(&config_account.data.borrow())?;
                Ok(())
            }
        "#,
            &MissingOwnerCheck,
        );

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "VL002");
        assert_eq!(findings[0].line, 6);
    }

    // ── S4: an Anchor address/seeds constraint is an owner check ─────────────

    /// Class C. Anchor verifies a `seeds`-constrained address before the
    /// handler body runs; VL002 reads bodies and would never see it.
    ///
    /// Killing mutation: delete the `Constraint::Seeds(_)` arm of
    /// `is_address_constrained`.
    #[test]
    fn an_anchor_seeds_constraint_silences_the_read_of_that_field() {
        let findings = findings_for(
            r#"
            #[derive(Accounts)]
            pub struct Close<'info> {
                #[account(mut, seeds = [b"proposal", multisig.key().as_ref()], bump)]
                pub proposal: UncheckedAccount<'info>,
            }

            pub fn close(ctx: Context<Close>) -> Result<()> {
                let proposal_account =
                    Proposal::try_deserialize(&mut &**ctx.accounts.proposal.data.borrow_mut())?;
                Ok(())
            }
        "#,
            &MissingOwnerCheck,
        );

        assert!(findings.is_empty());
    }

    /// Killing mutation: delete the `Constraint::Other("address", _)` arm of
    /// `is_address_constrained`.
    #[test]
    fn an_anchor_address_constraint_silences_the_read_of_that_field() {
        let findings = findings_for(
            r#"
            #[derive(Accounts)]
            pub struct Close<'info> {
                #[account(address = PYTH_LAZER_STORAGE_ID)]
                pub proposal: UncheckedAccount<'info>,
            }

            pub fn close(ctx: Context<Close>) -> Result<()> {
                let proposal_account =
                    Proposal::try_deserialize(&mut &**ctx.accounts.proposal.data.borrow_mut())?;
                Ok(())
            }
        "#,
            &MissingOwnerCheck,
        );

        assert!(findings.is_empty());
    }

    /// S4 must not over-reach: a struct having *some* address-constrained
    /// field says nothing about the field actually being read.
    ///
    /// Killing mutation: in `is_address_constrained`, match any field of the
    /// struct instead of the one the read names.
    #[test]
    fn an_anchor_constraint_on_another_field_does_not_silence() {
        let findings = findings_for(
            r#"
            #[derive(Accounts)]
            pub struct Close<'info> {
                #[account(address = PYTH_LAZER_STORAGE_ID)]
                pub storage: UncheckedAccount<'info>,
                /// CHECK: not validated
                pub proposal: UncheckedAccount<'info>,
            }

            pub fn close(ctx: Context<Close>) -> Result<()> {
                let proposal_account =
                    Proposal::try_deserialize(&mut &**ctx.accounts.proposal.data.borrow_mut())?;
                Ok(())
            }
        "#,
            &MissingOwnerCheck,
        );

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "VL002");
        assert_eq!(findings[0].line, 12);
    }

    /// Killing mutation: delete the `syn::Expr::If` arm of
    /// `collect_let_bindings_expr`.
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

    // ── Fix round 2 ──────────────────────────────────────────────────────────

    /// S3 defect: matching the *leading* identifier (`ctx`) lets a comparison
    /// against a *different* account silence the read. The check must use the
    /// trailing path segment (`collection_metadata`), which only matches a proof
    /// that actually names that account.
    ///
    /// Verified corpus shape from
    /// `metaplex candy-machine/…/set_collection_during_mint.rs:116`.
    ///
    /// Killing mutation: revert `trailing_ident` back to `ident_prefix` (the
    /// leading identifier) inside `pda_address_check_covers`.
    #[test]
    fn s3_does_not_silence_when_only_a_different_account_is_checked() {
        let findings = findings_for(
            r#"
            pub fn set_collection_during_mint(ctx: Context<SetCollectionDuringMint>) -> Result<()> {
                // check covers ctx.accounts.metadata, not ctx.accounts.collection_metadata
                if ctx.accounts.metadata.data_len() == 0 {
                    return err!(ErrorCode::MetadataEmpty);
                }
                assert_derivation(
                    ctx.program_id,
                    &ctx.accounts.collection_pda.to_account_info(),
                    &[CollectionPDA::PREFIX, ctx.accounts.candy_machine.key().as_ref()],
                )?;
                // raw read of collection_metadata — no proof covers this account
                let data = ctx.accounts.collection_metadata.data.borrow();
                let collection_metadata = Metadata::deserialize(&mut data.as_ref())?;
                Ok(())
            }
        "#,
            &MissingOwnerCheck,
        );

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "VL002");
    }

    /// S3 must remain silent when `assert!` contains `==` comparing the derived
    /// PDA to the account key — the shape in the shank-and-solita survivors.
    ///
    /// Killing mutation: remove the `==`/`!=` macro arm from
    /// `AddressEvidence::visit_macro`.
    #[test]
    fn assert_with_eq_and_find_program_address_silences() {
        let findings = findings_for(
            r#"
            pub fn pick_up_car(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
                let rental_order_account = &accounts[0];
                let user = &accounts[1];
                let (pda, _) =
                    Pubkey::find_program_address(&[b"rental", user.key.as_ref()], program_id);
                assert!(pda == *rental_order_account.key);
                let rental_order =
                    RentalOrder::try_from_slice(&rental_order_account.data.borrow())?;
                Ok(())
            }
        "#,
            &MissingOwnerCheck,
        );

        assert!(findings.is_empty());
    }

    /// A bare `msg!` that names an account does not prove its address, so it
    /// must not silence. This guards the guard: without this test, pushing every
    /// macro's tokens unconditionally would make `msg!` a silencer.
    ///
    /// Killing mutation: in `AddressEvidence::visit_macro`, push tokens for
    /// every macro unconditionally rather than gating on `==`/`!=`.
    #[test]
    fn msg_macro_naming_account_does_not_silence() {
        let findings = findings_for(
            r#"
            pub fn pick_up_car(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
                let favorite_account = &accounts[0];
                let user = &accounts[1];
                let (pda, _) =
                    Pubkey::find_program_address(&[b"favorite", user.key.as_ref()], program_id);
                msg!("{}", favorite_account.key);
                let favorites = Favorites::try_from_slice(&favorite_account.data.borrow())?;
                Ok(())
            }
        "#,
            &MissingOwnerCheck,
        );

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "VL002");
    }
}
