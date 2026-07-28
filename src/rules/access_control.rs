//! Anchor's `#[access_control(...)]`, resolved to the bodies it runs.
//!
//! ```ignore
//! #[access_control(whitelist_auth(self, &ctx))]
//! pub fn whitelist_add(ctx: Context<Auth>) -> Result<()> { … }
//! ```
//!
//! Anchor expands this so that `whitelist_auth(self, &ctx)` runs, and its
//! error short-circuits the instruction, *before* the handler body. Programs
//! use it for exactly the checks VL002 and VL005 look for, so a rule that
//! reads only the handler body sees an unguarded one and reports it.
//!
//! This module answers one question: which blocks in this file does the
//! attribute cause to run? The rules then fold those blocks into whatever
//! silencer they already have — nothing here decides anything about a finding.
//!
//! Resolution is deliberately **qualified**. `#[access_control(CreateCheck::accounts(&ctx, n))]`
//! resolves only to `impl CreateCheck { fn accounts }`, not to every function
//! in the file named `accounts` — and Anchor programs conventionally name all
//! of them `accounts`. Matching on the bare name would let one struct's check
//! silence a finding in a handler that never runs it, which is a false
//! negative invented out of nothing.
//!
//! Only functions declared in the *same file* are found. `syn` gives no
//! cross-file resolution, and a `use`d checker stays invisible — a false
//! positive, which is the safe direction.
//!
//! VL001 is deliberately left out. It is a `LinkedRule` reading bodies through
//! the use-site index, where a merged block would reach its *trigger* as much
//! as its silencer, and the fact it looks for — that an account signed — is one
//! Anchor programs state with `Signer<'info>` or a constraint, not in a guard.

use syn::spanned::Spanned as _;
use syn::visit::{self, Visit};

const ATTRIBUTE: &str = "access_control";

/// A function as an `#[access_control(...)]` argument names it: the final
/// segment, plus the type it is qualified by when there is one.
#[derive(PartialEq, Eq)]
struct QualifiedName {
    self_ty: Option<String>,
    function: String,
}

/// Every function body in `file` reachable from an `#[access_control(...)]`
/// attribute, indexed by the name the attribute would use.
pub(crate) struct AccessControlIndex<'ast> {
    functions: Vec<(QualifiedName, &'ast syn::Block)>,
}

impl<'ast> AccessControlIndex<'ast> {
    pub(crate) fn of(file: &'ast syn::File) -> Self {
        let mut collector = FunctionCollector {
            functions: Vec::new(),
            impl_self_ty: None,
        };
        collector.visit_file(file);
        Self {
            functions: collector.functions,
        }
    }

    /// The blocks that `attrs` cause to run before the annotated body.
    ///
    /// Empty when there is no such attribute, when its argument is not a call,
    /// or when the named function is declared in another file.
    pub(crate) fn blocks_for(&self, attrs: &[syn::Attribute]) -> Vec<&'ast syn::Block> {
        let mut out = Vec::new();
        for name in attrs.iter().flat_map(named_functions) {
            out.extend(
                self.functions
                    .iter()
                    .filter(|(candidate, _)| *candidate == name)
                    .map(|(_, block)| *block),
            );
        }
        out
    }
}

/// The functions one attribute calls. Anchor accepts several, comma-separated.
fn named_functions(attr: &syn::Attribute) -> Vec<QualifiedName> {
    if attr.path().segments.last().map(|s| s.ident.to_string()) != Some(ATTRIBUTE.to_string()) {
        return Vec::new();
    }
    let Ok(args) = attr.parse_args_with(
        syn::punctuated::Punctuated::<syn::Expr, syn::Token![,]>::parse_terminated,
    ) else {
        return Vec::new();
    };
    args.iter().filter_map(called_function).collect()
}

fn called_function(expr: &syn::Expr) -> Option<QualifiedName> {
    let syn::Expr::Call(call) = expr else {
        return None;
    };
    let syn::Expr::Path(path) = call.func.as_ref() else {
        return None;
    };
    let mut segments = path.path.segments.iter().rev();
    let function = segments.next()?.ident.to_string();
    Some(QualifiedName {
        self_ty: segments.next().map(|s| s.ident.to_string()),
        function,
    })
}

struct FunctionCollector<'ast> {
    functions: Vec<(QualifiedName, &'ast syn::Block)>,
    impl_self_ty: Option<String>,
}

impl<'ast> Visit<'ast> for FunctionCollector<'ast> {
    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        self.functions.push((
            QualifiedName {
                self_ty: None,
                function: node.sig.ident.to_string(),
            },
            &node.block,
        ));
        visit::visit_item_fn(self, node);
    }

    fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
        self.functions.push((
            QualifiedName {
                self_ty: self.impl_self_ty.clone(),
                function: node.sig.ident.to_string(),
            },
            &node.block,
        ));
        visit::visit_impl_item_fn(self, node);
    }

    fn visit_item_impl(&mut self, node: &'ast syn::ItemImpl) {
        let outer = self.impl_self_ty.take();
        self.impl_self_ty = final_segment(&node.self_ty);
        visit::visit_item_impl(self, node);
        self.impl_self_ty = outer;
    }
}

fn final_segment(ty: &syn::Type) -> Option<String> {
    let syn::Type::Path(path) = ty else {
        return None;
    };
    path.path
        .segments
        .last()
        .map(|segment| segment.ident.to_string())
}

/// `body` with the guards' statements appended, so a silencer written against
/// one block can be asked about the whole of what runs.
///
/// Feeds silencers only. A rule must keep looking for the *findings* in `body`
/// alone — a raw read inside a guard belongs to the guard, not to the handler
/// that triggers it.
pub(crate) fn merged_with(body: &syn::Block, guards: &[&syn::Block]) -> syn::Block {
    syn::Block {
        brace_token: syn::token::Brace(body.span()),
        stmts: body
            .stmts
            .iter()
            .chain(guards.iter().flat_map(|guard| guard.stmts.iter()))
            .cloned()
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(source: &str) -> syn::File {
        syn::parse_file(source).expect("parses")
    }

    /// The guards' text, as a silencer would see it appended to an empty body.
    fn guard_text(file: &syn::File) -> String {
        let index = AccessControlIndex::of(file);
        let guards = index.blocks_for(&first_annotated(file));
        let empty: syn::Block = syn::parse_quote!({});
        crate::rules::normalised(&merged_with(&empty, &guards))
    }

    /// Attributes of the first function in the file that carries one.
    fn first_annotated(file: &syn::File) -> Vec<syn::Attribute> {
        struct Finder(Vec<syn::Attribute>);
        impl<'ast> Visit<'ast> for Finder {
            fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
                if self.0.is_empty() && !node.attrs.is_empty() {
                    self.0 = node.attrs.clone();
                }
                visit::visit_item_fn(self, node);
            }
            fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
                if self.0.is_empty() && !node.attrs.is_empty() {
                    self.0 = node.attrs.clone();
                }
                visit::visit_impl_item_fn(self, node);
            }
        }
        let mut finder = Finder(Vec::new());
        finder.visit_file(file);
        finder.0
    }

    #[test]
    fn resolves_a_free_function_by_name() {
        let file = parse(
            r#"
            #[access_control(whitelist_auth(&ctx))]
            pub fn whitelist_add(ctx: Context<Auth>) -> Result<()> { Ok(()) }

            fn whitelist_auth(ctx: &Context<Auth>) -> Result<()> {
                require_keys_eq!(ctx.accounts.a.key(), crate::ID);
                Ok(())
            }
        "#,
        );

        assert!(guard_text(&file).contains("require_keys_eq!"));
    }

    /// The whole point of qualifying: Anchor programs name every one of these
    /// `accounts`, and only the struct named in the attribute runs.
    ///
    /// Killing mutation: in `called_function`, drop `self_ty` and match on the
    /// final segment alone.
    #[test]
    fn a_qualified_call_does_not_resolve_to_another_types_method() {
        let file = parse(
            r#"
            #[access_control(CreateCheck::accounts(&ctx))]
            pub fn create_check(ctx: Context<CreateCheck>) -> Result<()> { Ok(()) }

            impl<'info> CreateCheck<'info> {
                pub fn accounts(ctx: &Context<CreateCheck>) -> Result<()> { Ok(()) }
            }

            impl<'info> CashCheck<'info> {
                pub fn accounts(ctx: &Context<CashCheck>) -> Result<()> {
                    require_keys_eq!(ctx.accounts.a.key(), crate::ID);
                    Ok(())
                }
            }
        "#,
        );
        let index = AccessControlIndex::of(&file);

        assert_eq!(index.blocks_for(&first_annotated(&file)).len(), 1);
        assert!(!guard_text(&file).contains("require_keys_eq!"));
    }

    /// Anchor accepts several checks in one attribute; missing the later ones
    /// would silently drop a proof.
    ///
    /// Killing mutation: in `named_functions`, parse a single `syn::Expr`
    /// instead of a comma-punctuated list.
    #[test]
    fn resolves_every_call_in_one_attribute() {
        let file = parse(
            r#"
            #[access_control(first(&ctx), second(&ctx))]
            pub fn handler(ctx: Context<A>) -> Result<()> { Ok(()) }

            fn first(ctx: &Context<A>) -> Result<()> { Ok(()) }
            fn second(ctx: &Context<A>) -> Result<()> { Ok(()) }
        "#,
        );
        let index = AccessControlIndex::of(&file);

        assert_eq!(index.blocks_for(&first_annotated(&file)).len(), 2);
    }

    /// A checker declared in another file cannot be resolved, and the rule must
    /// then behave exactly as it did before — report, not silence.
    #[test]
    fn an_unresolvable_name_yields_no_blocks() {
        let file = parse(
            r#"
            #[access_control(checks::authorised(&ctx))]
            pub fn handler(ctx: Context<A>) -> Result<()> { Ok(()) }
        "#,
        );
        let index = AccessControlIndex::of(&file);

        assert!(index.blocks_for(&first_annotated(&file)).is_empty());
    }

    /// Every other attribute a handler carries must be inert here.
    ///
    /// Killing mutation: in `named_functions`, drop the attribute-name test.
    #[test]
    fn an_unrelated_attribute_is_ignored() {
        let file = parse(
            r#"
            #[instruction(nonce: u8)]
            pub fn handler(ctx: Context<A>) -> Result<()> { Ok(()) }

            fn nonce(ctx: &Context<A>) -> Result<()> { Ok(()) }
        "#,
        );
        let index = AccessControlIndex::of(&file);

        assert!(index.blocks_for(&first_annotated(&file)).is_empty());
    }
}
