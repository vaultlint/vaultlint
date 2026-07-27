//! VL005 — a CPI whose program id is supplied by an account the caller passed.
//!
//! The rule deliberately does **not** flag every `invoke` / `invoke_signed`.
//! It only fires when:
//!   T1 — the `Instruction` was *built in this same function body* (struct
//!        literal carrying a `program_id` field, or `Instruction::new_with_*`),
//!        AND
//!   T2 — the program id expression is account-derived (contains `.key`).
//!
//! When the `Instruction` was built by an SDK builder function (e.g.
//! `system_instruction::create_account`), the program id is a constant compiled
//! into that builder. There is nothing for the developer to verify, and flagging
//! that call is unactionable.

use syn::spanned::Spanned;
use syn::visit::{self, Visit};

use crate::anchor::AccountTy;
use crate::finding::{Finding, Severity};
use crate::rules::{normalised, Rule, RuleContext};
use crate::usesite::context_struct_name;

const CPI_CALLS: &[&str] = &["invoke", "invoke_signed"];

/// Last path segments whose presence, together with a segment named `Instruction`
/// anywhere in the same path, indicate an `Instruction::new_with_*` builder.
const INSTRUCTION_BUILDERS: &[&str] = &["new_with_borsh", "new_with_bincode", "new_with_bytes"];

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
            if !program_id_text.contains(".key") {
                continue;
            }

            // S2 — the account is declared as `Program<'info, T>` in the
            // context struct, so Anchor already verified the program id.
            //
            // We also resolve one level of `let` in the program id expression:
            // if it names a local binding, substitute that binding's text.
            let program_id_resolved = resolve_program_id_text(&program_id_text, &bindings);
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

/// Collects all `let <ident> = <expr>` bindings at the top level of `block`.
/// Only simple identifier patterns are captured; tuple/struct patterns are skipped.
fn collect_let_bindings(block: &syn::Block) -> Vec<LetBinding> {
    let mut out = Vec::new();
    for stmt in &block.stmts {
        let syn::Stmt::Local(local) = stmt else {
            continue;
        };
        let syn::Pat::Ident(pat) = &local.pat else {
            continue;
        };
        let Some(init) = &local.init else {
            continue;
        };
        // Unwrap a trailing `?` — `let x = foo()?;` binds `foo()` not `foo()?`.
        let expr = unwrap_try(&init.expr);
        out.push(LetBinding {
            name: pat.ident.to_string(),
            init: expr.clone(),
        });
    }
    out
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
/// initialiser (one hop only).
fn resolve_one_hop<'a>(expr: &'a syn::Expr, bindings: &'a [LetBinding]) -> &'a syn::Expr {
    let inner = strip_ref(expr);
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
/// the expression matches one of the two recognised T1 shapes. Returns `None`
/// if the expression is not a locally-built `Instruction`.
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

        // Shape 2: `Instruction::new_with_borsh(<program_id>, …)` (or bincode/bytes)
        syn::Expr::Call(call) => {
            let syn::Expr::Path(func) = &*call.func else {
                return None;
            };
            let segments = &func.path.segments;
            let last = segments.last()?;
            if !INSTRUCTION_BUILDERS.contains(&last.ident.to_string().as_str()) {
                return None;
            }
            // The path must also contain a segment named `Instruction`.
            if !segments.iter().any(|s| s.ident == "Instruction") {
                return None;
            }
            // First argument is the program id.
            call.args.first().map(|a| a as &syn::Expr)
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
/// `text`. We use a simple substring search bounded by non-identifier characters.
fn is_program_typed_account(text: &str, program_fields: &[String]) -> bool {
    program_fields
        .iter()
        .any(|field| whole_word_match(text, field))
}

/// True if `needle` appears in `haystack` as a complete identifier (not
/// continued by an identifier character on either side).
fn whole_word_match(haystack: &str, needle: &str) -> bool {
    let mut start = 0;
    while let Some(offset) = haystack[start..].find(needle) {
        let at = start + offset;
        let end = at + needle.len();
        let left_ok = at == 0
            || !haystack[..at]
                .chars()
                .next_back()
                .is_some_and(is_ident_char);
        let right_ok =
            end >= haystack.len() || !haystack[end..].chars().next().is_some_and(is_ident_char);
        if left_ok && right_ok {
            return true;
        }
        start = end;
        if start >= haystack.len() {
            break;
        }
    }
    false
}

fn is_ident_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
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
        // Killed by: removing the `.key` check in T2, or removing the struct-literal
        // branch of `instruction_program_id`.
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
}
