//! VL005 — a CPI whose program id is supplied by an account the caller passed.
//!
//! The rule deliberately does **not** flag every `invoke` / `invoke_signed`.
//! It only fires when:
//!   T1 — the `Instruction` was *built in this same function body* (struct
//!        literal carrying a `program_id` field, or `Instruction::new_with_*`,
//!        or a call to a program-id-first builder in `PROGRAM_ID_FIRST_BUILDERS`),
//!        AND
//!   T2 — the program id expression (resolved through one level of `let`) is
//!        account-derived (the resolved text contains `.key`).
//!
//! When the `Instruction` was built by an SDK builder function that does not
//! take a program id argument (e.g. `system_instruction::create_account`), the
//! program id is a constant compiled into that builder. There is nothing for
//! the developer to verify, and flagging that call is unactionable.
//!
//! However, the `spl_token::instruction::*` family (and similar modules listed
//! in `PROGRAM_ID_FIRST_BUILDERS`) takes `token_program_id: &Pubkey` as
//! **argument 0**. Passing an unverified account there is precisely the
//! textbook Sealevel arbitrary-CPI vulnerability, and T1 must catch it.
//!
//! Note: a use-shortened path such as `instruction::transfer(…)` after
//! `use spl_token::instruction;` has no `spl_token` segment and will not match
//! `PROGRAM_ID_FIRST_BUILDERS`. That is an accepted missed finding — a false
//! negative is safer than a false positive.

use syn::spanned::Spanned;
use syn::visit::{self, Visit};

use crate::anchor::AccountTy;
use crate::finding::{Finding, Severity};
use crate::rules::{find_bounded, is_ident_char, normalised, Rule, RuleContext};
use crate::usesite::context_struct_name;

const CPI_CALLS: &[&str] = &["invoke", "invoke_signed"];

/// Last path segments whose presence, together with a segment named `Instruction`
/// anywhere in the same path, indicate an `Instruction::new_with_*` builder.
const INSTRUCTION_BUILDERS: &[&str] = &["new_with_borsh", "new_with_bincode", "new_with_bytes"];

/// Module path segments that identify SDK builder families whose **first**
/// argument is `token_program_id: &Pubkey`. Passing an unverified account there
/// is the textbook Sealevel arbitrary-CPI vulnerability.
///
/// The segment is matched anywhere in the call path so that both
/// `spl_token::instruction::transfer(token_program.key, …)` and a hypothetical
/// nested alias still match. A use-shortened form such as `instruction::transfer`
/// has no `spl_token` segment and will not match; that is an accepted missed
/// finding rather than a false positive.
///
/// `spl_associated_token_account` is deliberately absent: its functions put
/// the *funder* (payer) as argument 0, not the program id, so including it
/// would flag `payer.key` as an unverified program id — a false positive.
/// It remains an accepted missed finding.
const PROGRAM_ID_FIRST_BUILDERS: &[&str] = &["spl_token", "spl_token_2022"];

/// Textual signals that the function verifies which program it is calling.
const VERIFICATION_SIGNALS: &[&str] = &["require_keys_eq!", "::ID", "assert_eq!(", "program_id=="];

pub struct UncheckedCpi;

impl Rule for UncheckedCpi {
    fn id(&self) -> &'static str {
        "VL005"
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
    fn check_body(&mut self, sig: &syn::Signature, block: &syn::Block) {
        // S1 — fast exit: a verification signal is present anywhere in the body.
        let body_text = normalised(block);
        if VERIFICATION_SIGNALS
            .iter()
            .any(|signal| body_text.contains(signal))
        {
            return;
        }

        // Collect local `let` bindings in this body so T1 can resolve one hop.
        let bindings = collect_let_bindings(block);

        // S2 setup: find which `Program<…>` fields are in the context struct for
        // this function, if it takes a `Context<S>`.
        let program_account_fields = context_program_fields(sig, self.ctx);

        // Find all `invoke` / `invoke_signed` calls in the body.
        let mut finder = CpiFinder {
            spans_and_first_args: Vec::new(),
        };
        finder.visit_block(block);

        for (call_span, first_arg) in finder.spans_and_first_args {
            // Resolve the first argument through one level of `let` if needed.
            let instr_expr = resolve_one_hop(&first_arg, &bindings);

            // T1 — the instruction must have been built in this body.
            let Some(program_id_expr) = instruction_program_id(instr_expr) else {
                continue;
            };

            let program_id_text = normalised(program_id_expr);

            // T2 — the program id must be account-derived.
            // Apply the let-hop to the program id text before checking T2, so
            // that `let target = *ctx.accounts.t.key; Instruction { program_id: target, … }`
            // and the shorthand form `let program_id = …; Instruction { program_id, … }`
            // are both caught. T2 must widen before S2 narrows.
            let program_id_resolved = resolve_program_id_text(&program_id_text, &bindings);
            if !program_id_resolved.contains(".key") {
                continue;
            }

            // S2 — the account is declared as `Program<'info, T>` in the
            // context struct, so Anchor already verified the program id.
            if is_program_typed_account(&program_id_resolved, &program_account_fields) {
                continue;
            }

            self.out.push(self.ctx.finding(
                "VL005",
                Severity::Medium,
                "unchecked CPI to unknown program",
                format!(
                    "`{program_id_text}` supplies the program id for this CPI, and nothing in the \
                     handler proves which program it is. An attacker who controls that account can \
                     point the invocation at their own program."
                ),
                "Use Anchor's typed CPI helpers, or verify the id first, e.g. \
                 `require_keys_eq!(program.key(), expected::ID)`.",
                call_span,
            ));
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
}

// ─── let-binding collection ──────────────────────────────────────────────────

/// A single `let <name> = <init>;` binding from a block.
struct LetBinding {
    name: String,
    /// The initialiser expression.
    init: syn::Expr,
}

/// Collects all `let <ident> = <expr>` bindings, walking nested blocks so that
/// a CPI inside an `if` or `match` arm is not missed.
///
/// Shadowing: later bindings for the same name override earlier ones, because
/// `let x = <safe>; … let x = Instruction { program_id: *evil.key, … }` must
/// resolve to the second binding.
fn collect_let_bindings(block: &syn::Block) -> Vec<LetBinding> {
    let mut out = Vec::new();
    collect_let_bindings_stmts(&block.stmts, &mut out);
    out
}

fn collect_let_bindings_stmts(stmts: &[syn::Stmt], out: &mut Vec<LetBinding>) {
    for stmt in stmts {
        match stmt {
            syn::Stmt::Local(local) => {
                // Unwrap `Pat::Type` (e.g. `let ix: Instruction = …`) to get the
                // inner ident pattern.
                let pat = unwrap_pat_type(&local.pat);
                let syn::Pat::Ident(pat_ident) = pat else {
                    continue;
                };
                let Some(init) = &local.init else {
                    continue;
                };
                // Unwrap a trailing `?` — `let x = foo()?;` binds `foo()` not `foo()?`.
                // Also strip a leading `&` on the initialiser: `let ix = &Instruction { … };`
                let expr = strip_ref(unwrap_try(&init.expr));
                let name = pat_ident.ident.to_string();
                // Prefer the latest binding for the same name (shadowing).
                if let Some(existing) = out.iter_mut().find(|b| b.name == name) {
                    existing.init = expr.clone();
                } else {
                    out.push(LetBinding {
                        name,
                        init: expr.clone(),
                    });
                }
            }
            // Walk nested blocks in expressions (if, match, block, loop, etc.)
            syn::Stmt::Expr(expr, _) => {
                collect_let_bindings_expr(expr, out);
            }
            _ => {}
        }
    }
}

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
        _ => {}
    }
}

/// Unwrap `Pat::Type` to get the inner pattern. `let ix: Instruction = …`
/// has `Pat::Type { pat: Pat::Ident, … }`.
fn unwrap_pat_type(pat: &syn::Pat) -> &syn::Pat {
    if let syn::Pat::Type(pt) = pat {
        &pt.pat
    } else {
        pat
    }
}

/// Strip a wrapping `?` operator: `foo()?` → `foo()`.
fn unwrap_try(expr: &syn::Expr) -> &syn::Expr {
    if let syn::Expr::Try(t) = expr {
        &t.expr
    } else {
        expr
    }
}

// ─── first-argument resolution ────────────────────────────────────────────────

/// Strip a leading `&` from an expression: `&foo` → `foo`.
fn strip_ref(expr: &syn::Expr) -> &syn::Expr {
    if let syn::Expr::Reference(r) = expr {
        &r.expr
    } else {
        expr
    }
}

/// If `expr` is a path naming a local let-binding, return that binding's
/// initialiser (one hop only). Also strips a leading `&` and a trailing `?`
/// on the argument, so `&spl_token::instruction::transfer(…)?` resolves to
/// the inner call.
fn resolve_one_hop<'a>(expr: &'a syn::Expr, bindings: &'a [LetBinding]) -> &'a syn::Expr {
    let inner = unwrap_try(strip_ref(expr));
    if let syn::Expr::Path(path) = inner {
        if let Some(ident) = path.path.get_ident() {
            let name = ident.to_string();
            if let Some(binding) = bindings.iter().find(|b| b.name == name) {
                return &binding.init;
            }
        }
    }
    inner
}

// ─── T1: does this expression describe an Instruction we built here? ──────────

/// Extract the program-id sub-expression from an `Instruction` value, if
/// the expression matches one of the recognised T1 shapes. Returns `None`
/// if the expression is not a locally-built `Instruction`.
///
/// Three shapes are recognised:
///
/// 1. `Instruction { program_id: <expr>, … }` — struct literal.
/// 2. `Instruction::new_with_borsh(<program_id>, …)` — new_with_* builder.
/// 3. `spl_token::instruction::transfer(token_program.key, …)` — a call whose
///    path contains any segment in `PROGRAM_ID_FIRST_BUILDERS`. The program id
///    is the **first argument**.
fn instruction_program_id(expr: &syn::Expr) -> Option<&syn::Expr> {
    match expr {
        // Shape 1: `Instruction { program_id: <expr>, … }`
        syn::Expr::Struct(s) => {
            let last_seg = s.path.segments.last()?;
            if last_seg.ident != "Instruction" {
                return None;
            }
            for field in &s.fields {
                if let syn::Member::Named(ident) = &field.member {
                    if ident == "program_id" {
                        return Some(&field.expr);
                    }
                }
            }
            None
        }

        syn::Expr::Call(call) => {
            let syn::Expr::Path(func) = &*call.func else {
                return None;
            };
            let segments = &func.path.segments;
            let last = segments.last()?;
            let last_str = last.ident.to_string();

            // Shape 2: `Instruction::new_with_borsh(<program_id>, …)`
            // Both guards are individually load-bearing (Minor 7): removing either one
            // alone leaves a test passing. Together they identify the exact shape.
            if INSTRUCTION_BUILDERS.contains(&last_str.as_str())
                && segments.iter().any(|s| s.ident == "Instruction")
            {
                return call.args.first().map(|a| a as &syn::Expr);
            }

            // Shape 3: `spl_token::instruction::transfer(token_program_id, …)`
            // Path contains any segment in PROGRAM_ID_FIRST_BUILDERS.
            if segments
                .iter()
                .any(|s| PROGRAM_ID_FIRST_BUILDERS.contains(&s.ident.to_string().as_str()))
            {
                return call.args.first().map(|a| a as &syn::Expr);
            }

            None
        }

        _ => None,
    }
}

// ─── S2: is the program id supplied by a Program-typed account? ──────────────

/// Returns the names of all `Program<'info, T>` fields in the context struct
/// for `sig`'s `Context<S>` parameter, looked up in `ctx.anchor`.
fn context_program_fields(sig: &syn::Signature, ctx: &RuleContext<'_>) -> Vec<String> {
    context_program_fields_inner(sig, ctx).unwrap_or_default()
}

fn context_program_fields_inner(
    sig: &syn::Signature,
    ctx: &RuleContext<'_>,
) -> Option<Vec<String>> {
    // Find the first `Context<S>` typed parameter in the function signature.
    let struct_name = sig
        .inputs
        .iter()
        .filter_map(|arg| {
            if let syn::FnArg::Typed(t) = arg {
                context_struct_name(&t.ty)
            } else {
                None
            }
        })
        .next()?;

    // Look up the struct in the anchor model.
    let accounts_struct = ctx
        .anchor
        .accounts_structs
        .iter()
        .find(|s| s.name == struct_name)?;

    Some(
        accounts_struct
            .fields
            .iter()
            .filter(|f| f.ty == AccountTy::Program)
            .map(|f| f.name.clone())
            .collect(),
    )
}

/// Resolve the program-id normalised text through one level of local `let`:
/// if the text starts with an identifier that is a local binding name,
/// substitute that binding's normalised initialiser (keeping any trailing
/// method calls so that `.key()` is not lost).
///
/// For example, `cpi_program.key()` with binding `cpi_program =
/// ctx.accounts.auction_house_program.to_account_info()` expands to
/// `ctx.accounts.auction_house_program.to_account_info().key()`.
fn resolve_program_id_text(text: &str, bindings: &[LetBinding]) -> String {
    // Strip leading `*` and `&` deref/borrow operators.
    let bare = text.trim_start_matches('*').trim_start_matches('&');
    // Extract the leading identifier (everything before the first `.` or end).
    let ident_end = bare.find(|c: char| !is_ident_char(c)).unwrap_or(bare.len());
    let leading_ident = &bare[..ident_end];
    let suffix = &bare[ident_end..];
    if let Some(binding) = bindings.iter().find(|b| b.name == leading_ident) {
        format!("{}{}", normalised(&binding.init), suffix)
    } else {
        text.to_string()
    }
}

/// True if any name in `program_fields` appears as a whole identifier inside
/// the leading receiver of `text`. We narrow the match to the receiver (the
/// part before the first method call) to avoid false silencing when a
/// `Program`-typed field name happens to appear elsewhere in a complex expression.
///
/// For example: `pick(ctx.accounts.token_program,ctx.accounts.attacker).key()`
/// should NOT be silenced by `token_program`, but
/// `ctx.accounts.token_program.key()` should.
///
/// "Receiver" is approximated as everything before the last `.key` occurrence
/// in the text. If `.key` is absent the full text is searched (this branch
/// is only reached after T2 confirmed `.key` is present, so this fallback
/// is unreachable in practice).
fn is_program_typed_account(text: &str, program_fields: &[String]) -> bool {
    // Find the receiver: the part of the expression before the `.key` access.
    let receiver = if let Some(pos) = text.rfind(".key") {
        &text[..pos]
    } else {
        text
    };
    program_fields
        .iter()
        .any(|field| whole_word_match(receiver, field))
}

/// True if `needle` appears in `haystack` as a complete identifier (not
/// continued by an identifier character on either side). Returns false
/// immediately for an empty needle (which would loop forever).
fn whole_word_match(haystack: &str, needle: &str) -> bool {
    find_bounded(
        haystack,
        needle,
        |left| !left.chars().next_back().is_some_and(is_ident_char),
        |right| !right.chars().next().is_some_and(is_ident_char),
    )
}

// ─── CPI finder ──────────────────────────────────────────────────────────────

struct CpiFinder {
    /// (span of the invoke call, first argument expression)
    spans_and_first_args: Vec<(proc_macro2::Span, syn::Expr)>,
}

impl<'ast> Visit<'ast> for CpiFinder {
    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        if let syn::Expr::Path(path) = &*node.func {
            if path
                .path
                .segments
                .last()
                .is_some_and(|segment| CPI_CALLS.contains(&segment.ident.to_string().as_str()))
            {
                if let Some(first_arg) = node.args.first() {
                    self.spans_and_first_args
                        .push((node.span(), first_arg.clone()));
                }
            }
        }
        visit::visit_expr_call(self, node);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::findings_for;

    // ── helpers ──────────────────────────────────────────────────────────────

    fn findings(source: &str) -> Vec<crate::finding::Finding> {
        findings_for(source, &UncheckedCpi)
    }

    // ── existing tests that must keep passing unchanged ───────────────────────

    #[test]
    fn accepts_invoke_guarded_by_require_keys_eq() {
        let f = findings(
            r#"
            pub fn claim(ctx: Context<Claim>) -> Result<()> {
                require_keys_eq!(ctx.accounts.token_program.key(), anchor_spl::token::ID);
                invoke(&instruction, &[a.clone(), b.clone()])?;
                Ok(())
            }
        "#,
        );

        assert!(f.is_empty());
    }

    #[test]
    fn accepts_invoke_guarded_by_a_program_id_comparison() {
        let f = findings(
            r#"
            pub fn claim(ctx: Context<Claim>) -> Result<()> {
                if ctx.accounts.target.key() != crate::ID {
                    return Err(Error::WrongProgram.into());
                }
                invoke_signed(&instruction, &accounts, signer_seeds)?;
                Ok(())
            }
        "#,
        );

        assert!(f.is_empty());
    }

    #[test]
    fn ignores_functions_without_any_cpi() {
        let f = findings(
            r#"
            pub fn claim(ctx: Context<Claim>) -> Result<()> {
                ctx.accounts.vault.balance = 0;
                Ok(())
            }
        "#,
        );

        assert!(f.is_empty());
    }

    // ── the old flags_invoke_without_any_program_id_verification is now silent ─

    /// An `invoke` of an instruction this function did not build is not a
    /// finding under T1: without a locally-constructed `Instruction`, we have
    /// no program id expression to inspect.
    #[test]
    fn invoke_of_externally_built_instruction_is_not_a_finding() {
        let f = findings(
            r#"
            pub fn claim(ctx: Context<Claim>) -> Result<()> {
                let instruction = build_instruction();
                invoke(&instruction, &[a.clone(), b.clone(), target_program.clone()])?;
                Ok(())
            }
        "#,
        );

        // T1 not satisfied: `build_instruction()` is not an Instruction literal
        // or an Instruction::new_with_* call.
        assert!(f.is_empty());
    }

    // ── true positive: struct literal ─────────────────────────────────────────

    /// Struct-literal Instruction with a `.key`-derived program id — the real
    /// vulnerable shape from examples/vulnerable/unchecked_cpi.rs.
    #[test]
    fn flags_instruction_struct_literal_with_account_derived_program_id() {
        // Exercises T1 (struct literal) and T2 (.key present).
        // Killed by: removing the struct-literal branch of `instruction_program_id`,
        // OR removing the `let` hop in `resolve_one_hop` (which backs the let-resolved
        // T2 check when the program id is passed through a binding).
        let f = findings(
            r#"
            pub fn claim(ctx: Context<Claim>, data: Vec<u8>) -> Result<()> {
                let instruction = Instruction {
                    program_id: *ctx.accounts.target_program.key,
                    accounts: vec![],
                    data,
                };
                invoke(&instruction, &[ctx.accounts.target_program.clone()])?;
                Ok(())
            }
        "#,
        );

        assert_eq!(f.len(), 1, "expected 1 finding, got {f:?}");
        assert_eq!(f[0].rule_id, "VL005");
        assert_eq!(f[0].line, 8);
        assert!(
            f[0].message.contains("*ctx.accounts.target_program.key"),
            "message should name the program id expression; got: {}",
            f[0].message
        );
    }

    /// The same Instruction struct but written inline at the call site (no `let`).
    /// Exercises: T1 struct-literal inline (no let-hop needed).
    /// Killed by: removing the struct-literal branch of `instruction_program_id`.
    #[test]
    fn flags_inline_instruction_struct_literal_at_call_site() {
        let f = findings(
            r#"
            pub fn exec(ctx: Context<Exec>) -> Result<()> {
                invoke(
                    &Instruction {
                        program_id: *ctx.accounts.prog.key,
                        accounts: vec![],
                        data: vec![],
                    },
                    &[ctx.accounts.prog.clone()],
                )?;
                Ok(())
            }
        "#,
        );

        assert_eq!(f.len(), 1, "expected 1 finding, got {f:?}");
        assert_eq!(f[0].rule_id, "VL005");
        assert!(
            f[0].message.contains(".key"),
            "message should name the program id expression"
        );
    }

    // ── true positive: Instruction::new_with_borsh bound to a local ───────────

    /// `Instruction::new_with_borsh(*lever_program.key, ...)` bound to a local
    /// and then invoked. Real shape from program-examples cross-program-invocation.
    /// Exercises: T1 new_with_* builder + let hop, T2 `.key` present.
    /// Killed by: removing the new_with_* branch of `instruction_program_id`.
    #[test]
    fn flags_new_with_borsh_bound_to_local_and_invoked() {
        let f = findings(
            r#"
            fn pull_lever(
                _program_id: &Pubkey,
                accounts: &[AccountInfo],
                instruction_data: &[u8],
            ) -> ProgramResult {
                let lever_program = next_account_info(accounts_iter)?;
                let ix = Instruction::new_with_borsh(
                    *lever_program.key,
                    &set_power_status_instruction,
                    vec![AccountMeta::new(*power.key, false)],
                );
                invoke(&ix, &[power.clone()])
            }
        "#,
        );

        assert_eq!(f.len(), 1, "expected 1 finding, got {f:?}");
        assert_eq!(f[0].rule_id, "VL005");
        assert!(
            f[0].message.contains(".key"),
            "message should name the program id expression"
        );
    }

    // ── silent: SDK builder (T1 not satisfied) ────────────────────────────────

    /// `invoke(&system_instruction::create_account(...), ...)` — the first
    /// argument is a *call* to an SDK builder, not an `Instruction` literal or
    /// `Instruction::new_with_*`. T1 is not satisfied, so no finding.
    /// Exercises: T1 negative (SDK builder call).
    /// Killed by: removing the T1 check entirely (would then fire on T2 if T2
    /// is also checked, or fire unconditionally).
    #[test]
    fn sdk_builder_invocation_is_silent() {
        let f = findings(
            r#"
            pub fn create(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
                invoke(
                    &solana_system_interface::instruction::create_account(
                        payer.key,
                        address_info_account.key,
                        lamports_required,
                        account_span as u64,
                        program_id,
                    ),
                    &[payer.clone(), address_info_account.clone(), system_program.clone()],
                )
            }
        "#,
        );

        // T1 not satisfied: the first arg is a call to an SDK builder, not an
        // Instruction struct literal or Instruction::new_with_* call.
        assert!(f.is_empty(), "unexpected findings: {f:?}");
    }

    // ── silent: constant program id (T2 not satisfied) ────────────────────────

    /// `Instruction { program_id: TARGET, .. }` where `TARGET` is a local constant.
    /// Note: `crate::ID` is deliberately *not* used here, so that S1's `::ID`
    /// signal does not silence this — the test must exercise T2, not S1.
    /// Exercises: T2 negative (no `.key` in program id).
    /// Killed by: removing the T2 `.key` check.
    #[test]
    fn constant_program_id_is_silent() {
        let f = findings(
            r#"
            pub fn exec(ctx: Context<Exec>) -> Result<()> {
                const TARGET: Pubkey = Pubkey::new_from_array([0u8; 32]);
                let ix = Instruction {
                    program_id: TARGET,
                    accounts: vec![],
                    data: vec![],
                };
                invoke(&ix, &[])?;
                Ok(())
            }
        "#,
        );

        // T2 not satisfied: `TARGET` does not contain `.key`.
        assert!(f.is_empty(), "unexpected findings: {f:?}");
    }

    // ── S2: Program-typed field silences the finding ──────────────────────────

    /// A `Context<Route>` handler where `Route` declares
    /// `pub target_program: Program<'info, System>` and the program id is
    /// `ctx.accounts.target_program.key()` → silent (S2).
    /// Exercises: S2 direct (no let hop).
    /// Killed by: removing the S2 check, or removing the `Program` field filter.
    #[test]
    fn program_typed_account_field_silences_the_finding() {
        let f = findings(
            r#"
            #[derive(Accounts)]
            pub struct Route<'info> {
                pub target_program: Program<'info, System>,
            }

            pub fn exec(ctx: Context<Route>) -> Result<()> {
                let ix = Instruction {
                    program_id: ctx.accounts.target_program.key(),
                    accounts: vec![],
                    data: vec![],
                };
                invoke(&ix, &[ctx.accounts.target_program.to_account_info()])?;
                Ok(())
            }
        "#,
        );

        // S2: `target_program` is Program-typed, so Anchor already verified it.
        assert!(f.is_empty(), "unexpected findings: {f:?}");
    }

    /// S2 through one `let` hop — the metaplex auctioneer shape:
    /// `let cpi_program = ctx.accounts.auction_house_program.to_account_info();`
    /// and then `program_id: cpi_program.key()`, where `auction_house_program`
    /// is declared as `Program<'info, AuctionHouseProgram>`.
    /// Exercises: S2 with let-hop resolution of the program id text.
    /// Killed by: removing the let-hop resolution in `resolve_program_id_text`.
    #[test]
    fn program_typed_account_through_let_hop_silences_the_finding() {
        let f = findings(
            r#"
            #[derive(Accounts)]
            pub struct Cancel<'info> {
                pub auction_house_program: Program<'info, AuctionHouseProgram>,
            }

            pub fn cancel(ctx: Context<Cancel>) -> Result<()> {
                let cpi_program = ctx.accounts.auction_house_program.to_account_info();
                let ix = solana_program::instruction::Instruction {
                    program_id: cpi_program.key(),
                    accounts: vec![],
                    data: vec![],
                };
                invoke_signed(&ix, &[], &[])?;
                Ok(())
            }
        "#,
        );

        // S2: `auction_house_program` is Program-typed; cpi_program is a local
        // alias for it, resolved through the let-hop.
        assert!(f.is_empty(), "unexpected findings: {f:?}");
    }

    /// S2 must not over-reach: same struct, but the program id comes from a
    /// different, `AccountInfo`-typed field → fires.
    /// Exercises: S2 negative (wrong field type).
    /// Killed by: removing the field-name check in `is_program_typed_account`
    /// (an S2 that ignores field names entirely would silently pass).
    #[test]
    fn account_info_field_is_not_silenced_by_s2() {
        let f = findings(
            r#"
            #[derive(Accounts)]
            pub struct Route<'info> {
                pub target_program: Program<'info, System>,
                /// CHECK: not validated
                pub other_program: AccountInfo<'info>,
            }

            pub fn exec(ctx: Context<Route>) -> Result<()> {
                let ix = Instruction {
                    program_id: ctx.accounts.other_program.key(),
                    accounts: vec![],
                    data: vec![],
                };
                invoke(&ix, &[ctx.accounts.other_program.to_account_info()])?;
                Ok(())
            }
        "#,
        );

        // `other_program` is AccountInfo, not Program — S2 does not apply.
        assert_eq!(f.len(), 1, "expected 1 finding, got {f:?}");
        assert_eq!(f[0].rule_id, "VL005");
    }

    // ── Critical 1: spl_token::instruction::* family (PROGRAM_ID_FIRST_BUILDERS) ──

    /// `spl_token::instruction::transfer(token_program.key, …)` — the first
    /// argument is the program id, not a constant. This is the textbook
    /// Sealevel arbitrary-CPI vulnerability.
    /// Exercises: T1 shape 3 (PROGRAM_ID_FIRST_BUILDERS), T2 `.key` present.
    /// Killed by: removing the PROGRAM_ID_FIRST_BUILDERS branch of `instruction_program_id`.
    #[test]
    fn spl_token_builder_with_account_derived_program_id_fires() {
        let f = findings(
            r#"
            pub fn transfer_tokens(token_program: &AccountInfo) -> ProgramResult {
                invoke_signed(
                    &spl_token::instruction::transfer(
                        token_program.key,
                        source.key,
                        destination.key,
                        authority.key,
                        &[],
                        amount,
                    )?,
                    &[source.clone(), destination.clone(), authority.clone(), token_program.clone()],
                    &[],
                )
            }
        "#,
        );

        assert_eq!(f.len(), 1, "expected 1 finding, got {f:?}");
        assert_eq!(f[0].rule_id, "VL005");
        assert!(
            f[0].message.contains(".key"),
            "message should name the program id expression; got: {}",
            f[0].message
        );
    }

    /// `spl_token::instruction::transfer(&spl_token_local_const, …)` — the
    /// first argument is a local constant (no `.key`), so T2 is not satisfied.
    /// Note: we deliberately do NOT use `spl_token::ID` here — that contains
    /// `::ID` which would trip S1. We use a local constant instead.
    /// Exercises: T2 negative (no `.key` in program id, even for PROGRAM_ID_FIRST_BUILDERS).
    /// Killed by: removing the T2 `.key` check.
    #[test]
    fn spl_token_builder_with_constant_program_id_is_silent() {
        let f = findings(
            r#"
            pub fn transfer_tokens() -> ProgramResult {
                const TOKEN_PROG: Pubkey = Pubkey::new_from_array([0u8; 32]);
                invoke_signed(
                    &spl_token::instruction::transfer(
                        &TOKEN_PROG,
                        source.key,
                        destination.key,
                        authority.key,
                        &[],
                        amount,
                    )?,
                    &[source.clone(), destination.clone(), authority.clone()],
                    &[],
                )
            }
        "#,
        );

        // T2 not satisfied: `TOKEN_PROG` does not contain `.key`.
        assert!(f.is_empty(), "unexpected findings: {f:?}");
    }

    // ── Important 2: S2 identifier-boundary guard (whole_word_match killable) ──

    /// A `Route` struct with both a `Program`-typed `program` field AND an
    /// `AccountInfo`-typed `token_program` field. The program id comes from
    /// `token_program.key()` — the `Program` field name `program` must NOT
    /// match inside `token_program`.
    /// Exercises: S2 whole-word boundary guard.
    /// Killed by: replacing `whole_word_match(h, n)` with `h.contains(n)`.
    #[test]
    fn program_field_name_does_not_match_inside_longer_name() {
        let f = findings(
            r#"
            #[derive(Accounts)]
            pub struct Route<'info> {
                pub program: Program<'info, System>,
                /// CHECK: not validated
                pub token_program: AccountInfo<'info>,
            }

            pub fn exec(ctx: Context<Route>) -> Result<()> {
                let ix = Instruction {
                    program_id: ctx.accounts.token_program.key(),
                    accounts: vec![],
                    data: vec![],
                };
                invoke(&ix, &[ctx.accounts.token_program.to_account_info()])?;
                Ok(())
            }
        "#,
        );

        // `token_program` is AccountInfo; `program` is Program but its name does
        // not match `token_program` as a whole identifier — S2 must not silence this.
        assert_eq!(f.len(), 1, "expected 1 finding, got {f:?}");
        assert_eq!(f[0].rule_id, "VL005");
    }

    // ── Important 3: empty-needle regression ──────────────────────────────────

    /// `find_bounded` with an empty needle must return false immediately.
    /// Without the guard, `find("")` returns `Some(0)` every iteration, the
    /// walk never advances past the end, and the function loops forever.
    #[test]
    fn whole_word_match_with_empty_needle_returns_false() {
        assert!(!whole_word_match("anything", ""));
        assert!(!whole_word_match("", ""));
    }

    // ── Important 4: let-binding fixes ───────────────────────────────────────

    /// A CPI inside a nested block (`if` branch) must still be found.
    /// Exercises: nested-scope let resolution.
    /// Killed by: removing the nested-block walk in `collect_let_bindings_stmts`.
    #[test]
    fn cpi_inside_conditional_block_is_found() {
        let f = findings(
            r#"
            pub fn exec(ctx: Context<Exec>, flag: bool) -> Result<()> {
                if flag {
                    let ix = Instruction {
                        program_id: *ctx.accounts.prog.key,
                        accounts: vec![],
                        data: vec![],
                    };
                    invoke(&ix, &[])?;
                }
                Ok(())
            }
        "#,
        );

        assert_eq!(f.len(), 1, "expected 1 finding, got {f:?}");
        assert_eq!(f[0].rule_id, "VL005");
    }

    /// `let ix: Instruction = Instruction { program_id: *prog.key, … }` — the
    /// type-annotated form wraps the pattern in `Pat::Type`.
    /// Exercises: `Pat::Type` unwrapping in `collect_let_bindings`.
    /// Killed by: removing the `unwrap_pat_type` call.
    #[test]
    fn type_annotated_let_binding_is_resolved() {
        let f = findings(
            r#"
            pub fn exec(ctx: Context<Exec>) -> Result<()> {
                let ix: solana_program::instruction::Instruction = Instruction {
                    program_id: *ctx.accounts.prog.key,
                    accounts: vec![],
                    data: vec![],
                };
                invoke(&ix, &[])?;
                Ok(())
            }
        "#,
        );

        assert_eq!(f.len(), 1, "expected 1 finding, got {f:?}");
        assert_eq!(f[0].rule_id, "VL005");
    }

    /// Shadowing: the second (later) `let ix = …` binds the dangerous value.
    /// Without last-wins, resolving `ix` returns the safe first binding and the
    /// invoke after the shadowing is silenced. With last-wins, the dangerous
    /// binding wins and the invoke fires.
    ///
    /// Trade-off: last-wins also makes the invoke *before* the shadowing fire
    /// (it resolves to the same final dangerous binding), which is a false
    /// positive on the first invoke. That is the accepted trade for ensuring the
    /// dangerous invoke never goes silent. This test verifies the critical
    /// direction: the invoke after shadowing must fire.
    ///
    /// Exercises: shadowing resolution (last-wins).
    /// Killed by: switching to first-wins semantics (bindings.iter().find returns
    /// earliest), which would resolve to the safe binding for ALL invokes and
    /// produce 0 findings.
    #[test]
    fn shadowed_binding_resolves_to_latest_value() {
        // Only one invoke, after the shadowing: must fire.
        let f = findings(
            r#"
            pub fn exec(ctx: Context<Exec>) -> Result<()> {
                const SAFE: Pubkey = Pubkey::new_from_array([0u8; 32]);
                let ix = Instruction {
                    program_id: SAFE,
                    accounts: vec![],
                    data: vec![],
                };
                // Shadow ix with the dangerous version.
                let ix = Instruction {
                    program_id: *ctx.accounts.attacker.key,
                    accounts: vec![],
                    data: vec![],
                };
                invoke(&ix, &[])?;
                Ok(())
            }
        "#,
        );

        // With last-wins: `ix` resolves to the dangerous instruction → fires.
        // With first-wins: `ix` would resolve to the safe instruction → silent.
        assert_eq!(f.len(), 1, "expected 1 finding, got {f:?}");
        assert_eq!(f[0].rule_id, "VL005");
    }

    /// `let ix = &Instruction { program_id: *prog.key, … }` — initialiser
    /// behind `&`. The `&` must be stripped before checking T1.
    /// Exercises: `strip_ref` on the initialiser in `collect_let_bindings`.
    /// Killed by: not calling `strip_ref` on the initialiser.
    #[test]
    fn ref_initialiser_is_recognised() {
        let f = findings(
            r#"
            pub fn exec(ctx: Context<Exec>) -> Result<()> {
                let ix = &Instruction {
                    program_id: *ctx.accounts.prog.key,
                    accounts: vec![],
                    data: vec![],
                };
                invoke(ix, &[])?;
                Ok(())
            }
        "#,
        );

        assert_eq!(f.len(), 1, "expected 1 finding, got {f:?}");
        assert_eq!(f[0].rule_id, "VL005");
    }

    // ── Minor 5: T2 follows the let hop ──────────────────────────────────────

    /// `let target = *ctx.accounts.target_program.key; Instruction { program_id: target, … }`
    /// — T2 must resolve `target` through the let binding before checking `.key`.
    /// Exercises: T2 let-hop resolution.
    /// Killed by: applying T2 to the raw program id text instead of the resolved text.
    #[test]
    fn t2_follows_let_hop_for_program_id() {
        let f = findings(
            r#"
            pub fn exec(ctx: Context<Exec>) -> Result<()> {
                let target = *ctx.accounts.target_program.key;
                let ix = Instruction {
                    program_id: target,
                    accounts: vec![],
                    data: vec![],
                };
                invoke(&ix, &[])?;
                Ok(())
            }
        "#,
        );

        assert_eq!(f.len(), 1, "expected 1 finding, got {f:?}");
        assert_eq!(f[0].rule_id, "VL005");
    }

    /// Field-shorthand form: `let program_id = *ctx.accounts.target.key;`
    /// then `Instruction { program_id, … }` — shorthand is already resolved by
    /// the struct-literal branch; combined with T2 let-hop this must still fire.
    /// Exercises: T2 let-hop with field shorthand.
    /// Killed by: applying T2 to the raw program id text instead of the resolved text.
    #[test]
    fn t2_follows_let_hop_with_shorthand_field() {
        let f = findings(
            r#"
            pub fn exec(ctx: Context<Exec>) -> Result<()> {
                let program_id = *ctx.accounts.target.key;
                let ix = Instruction {
                    program_id,
                    accounts: vec![],
                    data: vec![],
                };
                invoke(&ix, &[])?;
                Ok(())
            }
        "#,
        );

        assert_eq!(f.len(), 1, "expected 1 finding, got {f:?}");
        assert_eq!(f[0].rule_id, "VL005");
    }

    // ── Minor 7: individually unkillable T1 sub-guards ───────────────────────

    /// `foo::new_with_bytes(*x.key, …)` — last segment is `new_with_bytes` but
    /// the path has no `Instruction` segment, so T1 shape 2 must not match.
    /// Exercises: the `Instruction` segment check in shape 2.
    /// Killed by: removing the `segments.iter().any(|s| s.ident == "Instruction")` check.
    #[test]
    fn new_with_bytes_without_instruction_segment_is_silent() {
        let f = findings(
            r#"
            pub fn exec(ctx: Context<Exec>) -> Result<()> {
                let ix = foo::new_with_bytes(*ctx.accounts.x.key, data, accounts);
                invoke(&ix, &[])?;
                Ok(())
            }
        "#,
        );

        // T1 shape 2 not satisfied: no `Instruction` segment in the path.
        assert!(f.is_empty(), "unexpected findings: {f:?}");
    }

    /// `Instruction::new(*x.key, …)` — last segment is `new` (not in
    /// `INSTRUCTION_BUILDERS`), so T1 shape 2 must not match.
    /// Exercises: the `INSTRUCTION_BUILDERS.contains` check.
    /// Killed by: removing the `INSTRUCTION_BUILDERS.contains` check.
    #[test]
    fn instruction_new_is_not_a_recognised_builder() {
        let f = findings(
            r#"
            pub fn exec(ctx: Context<Exec>) -> Result<()> {
                let ix = Instruction::new(*ctx.accounts.x.key, data, accounts);
                invoke(&ix, &[])?;
                Ok(())
            }
        "#,
        );

        // T1 shape 2 not satisfied: `new` is not in INSTRUCTION_BUILDERS.
        assert!(f.is_empty(), "unexpected findings: {f:?}");
    }

    /// `let ix = Instruction::new_with_borsh(…)?;` — unwrap_try must strip the
    /// trailing `?` before T1 sees the expression.
    /// Exercises: `unwrap_try` in `collect_let_bindings`.
    /// Killed by: removing the `unwrap_try` call.
    #[test]
    fn try_operator_on_builder_result_is_unwrapped() {
        let f = findings(
            r#"
            pub fn exec(ctx: Context<Exec>) -> Result<()> {
                let ix = Instruction::new_with_borsh(
                    *ctx.accounts.prog.key,
                    &data,
                    vec![],
                )?;
                invoke(&ix, &[])?;
                Ok(())
            }
        "#,
        );

        assert_eq!(f.len(), 1, "expected 1 finding, got {f:?}");
        assert_eq!(f[0].rule_id, "VL005");
    }
}
