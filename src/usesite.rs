//! Links an Anchor `#[derive(Accounts)]` struct to the function bodies in
//! which its fields are addressable.
//!
//! Phase 1 of a scan records only *facts* about each file — no bodies, no ASTs.
//! Phase 2 asks the index for the bodies it needs and the file is re-parsed then,
//! once, and cached.

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

/// Facts collected from one file during phase 1.
pub struct FileFacts {
    /// Every fn and method, in AST order.
    pub functions: Vec<FnFact>,
}

pub struct FnFact {
    pub name: String,
    /// Final path segment of the self type when this fn is a method in an
    /// `impl <Ty>` / `impl <Ty> for ...` block; `None` for a free or module fn.
    pub impl_self_ty: Option<String>,
    /// Present when a parameter's type is `Context<...>`.
    pub context_param: Option<ContextParam>,
    /// Parameter binding names, in declaration order.
    pub params: Vec<String>,
}

pub struct ContextParam {
    /// The parameter's binding name — `ctx`, `_ctx`, `c`, …
    pub binding: String,
    /// The `Accounts` struct name extracted from `Context<...>`.
    pub struct_name: String,
}

pub struct UseSite {
    #[allow(dead_code)]
    pub file: PathBuf,
    pub block: syn::Block,
    pub access: FieldAccess,
    /// Parameter binding names of the function this body belongs to.
    pub params: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldAccess {
    /// Fields are addressed as `<binding>.accounts.<field>`.
    Context(String),
    /// Fields are addressed as `self.<field>`.
    SelfImpl,
    /// Neither — a helper reached by passing a field as an argument.
    Plain,
}

/// Visits every fn and method of a file — including those inside inline
/// `mod` blocks, where `#[program]` handlers live — in a fixed order.
///
/// Phase 1 and phase 2 both go through here, which is what makes a fn's
/// *ordinal* a stable address into a file: the same bytes always yield the same
/// sequence, so phase 2 can find a body without storing spans.
fn walk_fns<F>(items: &[syn::Item], visit: &mut F)
where
    F: FnMut(Option<&syn::Type>, &syn::Signature, &syn::Block),
{
    for item in items {
        match item {
            syn::Item::Mod(module) => {
                if let Some((_, inner)) = &module.content {
                    walk_fns(inner, visit);
                }
            }
            syn::Item::Fn(item) => visit(None, &item.sig, &item.block),
            syn::Item::Impl(block) => {
                for member in &block.items {
                    if let syn::ImplItem::Fn(method) = member {
                        visit(Some(&block.self_ty), &method.sig, &method.block);
                    }
                }
            }
            _ => {}
        }
    }
}

pub fn collect_facts(file: &syn::File) -> FileFacts {
    let mut functions = Vec::new();
    walk_fns(&file.items, &mut |self_ty, sig, _| {
        functions.push(fn_fact(self_ty, sig));
    });
    FileFacts { functions }
}

fn fn_fact(self_ty: Option<&syn::Type>, sig: &syn::Signature) -> FnFact {
    let mut params = Vec::new();
    let mut context_param = None;
    for arg in &sig.inputs {
        // The receiver is skipped so that a parameter's index in `params`
        // matches its argument position at a call site.
        let syn::FnArg::Typed(arg) = arg else {
            continue;
        };
        let binding = match &*arg.pat {
            syn::Pat::Ident(pat) => pat.ident.to_string(),
            // A tuple or wildcard pattern has no name, but it still occupies a
            // position, so record it as empty rather than dropping it.
            _ => String::new(),
        };
        if context_param.is_none() && !binding.is_empty() {
            if let Some(struct_name) = context_struct_name(&arg.ty) {
                context_param = Some(ContextParam {
                    binding: binding.clone(),
                    struct_name,
                });
            }
        }
        params.push(binding);
    }

    FnFact {
        name: sig.ident.to_string(),
        impl_self_ty: self_ty.and_then(final_segment),
        context_param,
        params,
    }
}

/// `Context<'a, 'b, 'info, Deposit<'info>>` -> `"Deposit"`.
///
/// Take the last generic argument, ignoring lifetimes, then its final path
/// segment without generics. `Context` is matched as the *final* segment of the
/// parameter type so `anchor_lang::context::Context<…>` matches too.
pub(crate) fn context_struct_name(ty: &syn::Type) -> Option<String> {
    let syn::Type::Path(path) = ty else {
        return None;
    };
    let segment = path.path.segments.last()?;
    if segment.ident != "Context" {
        return None;
    }
    let syn::PathArguments::AngleBracketed(args) = &segment.arguments else {
        return None;
    };
    let last = args
        .args
        .iter()
        .filter_map(|arg| match arg {
            syn::GenericArgument::Type(ty) => Some(ty),
            _ => None,
        })
        .next_back()?;
    final_segment(last)
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

struct FileEntry {
    path: PathBuf,
    facts: FileFacts,
}

/// One matched function, addressed by the file it lives in and its ordinal
/// within that file. The body is fetched only once the whole hit set is known.
struct Hit {
    file: usize,
    ordinal: usize,
    access: FieldAccess,
}

#[derive(Default)]
pub struct UseSiteIndex {
    files: Vec<FileEntry>,
    by_crate: HashMap<PathBuf, Vec<usize>>,
    crate_of_dir: RefCell<HashMap<PathBuf, PathBuf>>,
    /// Lazily re-parsed files. Holding every AST would cost several times what
    /// the facts do; only the files a rule actually asks about land here.
    parsed: RefCell<HashMap<PathBuf, syn::File>>,
}

impl UseSiteIndex {
    pub fn empty() -> Self {
        Self::default()
    }

    /// Called once per successfully parsed file during phase 1.
    pub fn insert(&mut self, file: &Path, facts: FileFacts) {
        let crate_id = self.crate_id(file);
        let index = self.files.len();
        self.files.push(FileEntry {
            path: file.to_path_buf(),
            facts,
        });
        self.by_crate.entry(crate_id).or_default().push(index);
    }

    /// Every body in which the fields of `struct_name` are addressable, within
    /// the crate that owns `from_file`.
    pub fn use_sites(&self, from_file: &Path, struct_name: &str) -> Vec<UseSite> {
        let files = self.crate_files(from_file);
        let mut hits = Vec::new();
        let mut seen = HashSet::new();

        // 1. Functions taking `Context<struct_name>`.
        //
        // A `#[program]` fn that forwards its whole `ctx` to a helper needs no
        // separate delegation hop: the helper only typechecks if it takes the
        // same `Context<struct_name>`, so this pass already returns it. Do not
        // add a hop that resolves callees by name — in the canonical Anchor
        // layout every instruction module exports `pub fn handler`, and a
        // by-name hop would union unrelated handlers.
        for &file in files {
            for (ordinal, function) in self.files[file].facts.functions.iter().enumerate() {
                if let Some(ctx) = &function.context_param {
                    if ctx.struct_name == struct_name {
                        push_hit(
                            &mut hits,
                            &mut seen,
                            file,
                            ordinal,
                            FieldAccess::Context(ctx.binding.clone()),
                        );
                    }
                }
            }
        }

        // 2. Methods on the struct itself, where fields are `self.<field>`.
        for &file in files {
            for (ordinal, function) in self.files[file].facts.functions.iter().enumerate() {
                if function.impl_self_ty.as_deref() == Some(struct_name) {
                    push_hit(&mut hits, &mut seen, file, ordinal, FieldAccess::SelfImpl);
                }
            }
        }

        self.materialise(hits)
    }

    /// A same-crate free function or method body by name.
    pub fn functions_named(&self, from_file: &Path, name: &str) -> Vec<UseSite> {
        let files = self.crate_files(from_file);
        let mut hits = Vec::new();
        let mut seen = HashSet::new();
        for &file in files {
            for (ordinal, function) in self.files[file].facts.functions.iter().enumerate() {
                if function.name != name {
                    continue;
                }
                let access = match (&function.context_param, &function.impl_self_ty) {
                    (Some(ctx), _) => FieldAccess::Context(ctx.binding.clone()),
                    (None, Some(_)) => FieldAccess::SelfImpl,
                    (None, None) => FieldAccess::Plain,
                };
                push_hit(&mut hits, &mut seen, file, ordinal, access);
            }
        }
        self.materialise(hits)
    }

    fn crate_files(&self, from_file: &Path) -> &[usize] {
        self.by_crate
            .get(&self.crate_id(from_file))
            .map_or(&[], Vec::as_slice)
    }

    /// The nearest ancestor directory holding a `Cargo.toml`.
    ///
    /// Every lookup is scoped by this. A workspace routinely declares the same
    /// `Accounts` struct name in two program crates (`insecure` and `secure` in
    /// sealevel-attacks); a repo-wide name lookup would union their handlers and
    /// let one crate's validation silence a finding in the other.
    fn crate_id(&self, file: &Path) -> PathBuf {
        let dir = file.parent().unwrap_or(file);
        if let Some(cached) = self.crate_of_dir.borrow().get(dir) {
            return cached.clone();
        }
        let mut current = Some(dir);
        let mut found = None;
        while let Some(candidate) = current {
            if candidate.join("Cargo.toml").is_file() {
                found = Some(candidate.to_path_buf());
                break;
            }
            current = candidate.parent();
        }
        let crate_id = found.unwrap_or_else(|| dir.to_path_buf());
        self.crate_of_dir
            .borrow_mut()
            .insert(dir.to_path_buf(), crate_id.clone());
        crate_id
    }

    fn materialise(&self, mut hits: Vec<Hit>) -> Vec<UseSite> {
        // Sorted so that findings derived from these bodies are reproducible.
        hits.sort_by(|a, b| {
            self.files[a.file]
                .path
                .cmp(&self.files[b.file].path)
                .then_with(|| a.ordinal.cmp(&b.ordinal))
        });

        let mut out = Vec::new();
        let mut start = 0;
        while start < hits.len() {
            let file = hits[start].file;
            let mut end = start;
            while end < hits.len() && hits[end].file == file {
                end += 1;
            }
            let wanted: Vec<usize> = hits[start..end].iter().map(|hit| hit.ordinal).collect();
            let entry = &self.files[file];
            if let Some(blocks) = self.bodies(&entry.path, &wanted) {
                for hit in &hits[start..end] {
                    // Reachable only if the file changed between the two phases,
                    // which must not panic — but must not pass unnoticed in a
                    // test either, since a dropped use site is a false negative.
                    debug_assert!(
                        blocks.contains_key(&hit.ordinal),
                        "fn ordinal {} vanished from {}",
                        hit.ordinal,
                        entry.path.display()
                    );
                    let Some(block) = blocks.get(&hit.ordinal) else {
                        continue;
                    };
                    out.push(UseSite {
                        file: entry.path.clone(),
                        block: block.clone(),
                        access: hit.access.clone(),
                        params: entry.facts.functions[hit.ordinal].params.clone(),
                    });
                }
            }
            start = end;
        }
        out
    }

    /// Re-parses `path` if it is not cached yet and returns the requested
    /// bodies. Phase 1 already parsed this file, so failure is not expected —
    /// but a file that changed or vanished mid-scan must not panic.
    fn bodies(&self, path: &Path, wanted: &[usize]) -> Option<HashMap<usize, syn::Block>> {
        let mut cache = self.parsed.borrow_mut();
        if !cache.contains_key(path) {
            let source = std::fs::read_to_string(path).ok()?;
            let parsed = syn::parse_file(&source).ok()?;
            cache.insert(path.to_path_buf(), parsed);
        }
        let ast = cache.get(path)?;

        let mut found = HashMap::new();
        let mut ordinal = 0;
        walk_fns(&ast.items, &mut |_, _, block| {
            if wanted.contains(&ordinal) {
                found.insert(ordinal, block.clone());
            }
            ordinal += 1;
        });
        Some(found)
    }
}

/// De-duplicates by function *and* access mode. A fn that is both a method on
/// `impl S` and takes a `Context<S>` addresses the same fields two ways; keeping
/// only the first would hide one of them from a rule, and a dropped use site in
/// a security linter is a false negative.
fn push_hit(
    hits: &mut Vec<Hit>,
    seen: &mut HashSet<(usize, usize, std::mem::Discriminant<FieldAccess>)>,
    file: usize,
    ordinal: usize,
    access: FieldAccess,
) {
    if seen.insert((file, ordinal, std::mem::discriminant(&access))) {
        hits.push(Hit {
            file,
            ordinal,
            access,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn facts(source: &str) -> FileFacts {
        collect_facts(&syn::parse_file(source).unwrap())
    }

    #[test]
    fn extracts_the_context_struct_name_from_every_shape() {
        let facts = facts(
            r#"
            pub fn a(ctx: Context<A>) {}
            pub fn b(ctx: Context<'a, 'b, 'c, 'info, B<'info>>) {}
            pub fn c(ctx: Context<'info, C<'info>>) {}
            pub fn d(ctx: Context<'a, 'b, 'c, 'info, D>) {}
            pub fn e(ctx: anchor_lang::context::Context<'info, some::path::E<'info>>) {}
        "#,
        );

        let names: Vec<String> = facts
            .functions
            .iter()
            .map(|f| f.context_param.as_ref().unwrap().struct_name.clone())
            .collect();
        assert_eq!(names, ["A", "B", "C", "D", "E"]);
    }

    #[test]
    fn captures_the_binding_name_instead_of_assuming_ctx() {
        let facts = facts("pub fn a(_ctx: Context<A>) {} pub fn b(c: Context<B>) {}");

        assert_eq!(
            facts.functions[0].context_param.as_ref().unwrap().binding,
            "_ctx"
        );
        assert_eq!(
            facts.functions[1].context_param.as_ref().unwrap().binding,
            "c"
        );
    }

    #[test]
    fn a_plain_parameter_is_not_a_context_parameter() {
        // `Vec<Deposit>` is the case that pins the `Context` guard: it is a
        // generic path type whose last type argument is an `Accounts` struct, so
        // without the guard it would be read as `Context<Deposit>`.
        let facts = facts("pub fn a(amount: u64) {} pub fn b(v: Vec<Deposit>) {}");

        assert!(facts.functions[0].context_param.is_none());
        assert_eq!(facts.functions[0].params, ["amount"]);
        assert!(facts.functions[1].context_param.is_none());
    }

    #[test]
    fn collects_functions_nested_in_inline_modules() {
        let facts = facts("pub mod instructions { pub fn handle(ctx: Context<Deposit>) {} }");

        assert_eq!(facts.functions.len(), 1);
        assert_eq!(facts.functions[0].name, "handle");
    }

    #[test]
    fn records_a_method_with_its_impl_self_type_and_skips_the_receiver() {
        let facts = facts("impl<'info> Deposit<'info> { pub fn run(&self, amount: u64) {} }");

        assert_eq!(facts.functions[0].impl_self_ty.as_deref(), Some("Deposit"));
        assert_eq!(facts.functions[0].params, ["amount"]);
    }

    #[test]
    fn a_non_identifier_parameter_holds_its_position_with_an_empty_name() {
        let facts = facts("pub fn a((x, y): (u8, u8), amount: u64) {}");

        assert_eq!(facts.functions[0].params, ["", "amount"]);
    }

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("vaultlint_usesite_{name}"));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn crate_dir(root: &Path, name: &str) -> PathBuf {
        let dir = root.join(name);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("Cargo.toml"), "[package]\nname = \"c\"\n").unwrap();
        dir
    }

    fn index_of(files: &[(PathBuf, &str)]) -> UseSiteIndex {
        let mut index = UseSiteIndex::empty();
        for (path, source) in files {
            fs::write(path, source).unwrap();
            index.insert(path, collect_facts(&syn::parse_file(source).unwrap()));
        }
        index
    }

    fn body_of(site: &UseSite) -> String {
        crate::rules::normalised(&site.block)
    }

    #[test]
    fn finds_a_handler_declared_in_another_file() {
        let dir = temp_dir("cross_file");
        let root = crate_dir(&dir, "program");
        let decl = root.join("state.rs");
        let handler = root.join("handler.rs");
        let index = index_of(&[
            (
                decl.clone(),
                "#[derive(Accounts)] pub struct Deposit<'info> { pub authority: AccountInfo<'info> }",
            ),
            (
                handler.clone(),
                "pub fn deposit(ctx: Context<Deposit>) -> Result<()> { ctx.accounts.authority.key(); Ok(()) }",
            ),
        ]);

        let sites = index.use_sites(&decl, "Deposit");

        assert_eq!(sites.len(), 1);
        assert_eq!(sites[0].file, handler);
        assert_eq!(sites[0].access, FieldAccess::Context("ctx".to_string()));
        assert!(body_of(&sites[0]).contains("ctx.accounts.authority"));
    }

    #[test]
    fn finds_an_impl_method_as_a_self_use_site() {
        let dir = temp_dir("impl_method");
        let root = crate_dir(&dir, "program");
        let decl = root.join("deposit.rs");
        let index = index_of(&[(
            decl.clone(),
            "#[derive(Accounts)] pub struct Deposit {}\n\
             impl<'info> Deposit<'info> { fn validate(&self) -> Result<()> { self.authority.key(); Ok(()) } }",
        )]);

        let sites = index.use_sites(&decl, "Deposit");

        assert_eq!(sites.len(), 1);
        assert_eq!(sites[0].access, FieldAccess::SelfImpl);
        assert!(body_of(&sites[0]).contains("self.authority"));
    }

    #[test]
    fn a_program_wrapper_and_the_handler_it_forwards_to_are_both_found() {
        let dir = temp_dir("delegation");
        let root = crate_dir(&dir, "program");
        let decl = root.join("program.rs");
        let handler = root.join("handler.rs");
        let index = index_of(&[
            (
                decl.clone(),
                "#[derive(Accounts)] pub struct Deposit {}\n\
                 pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> { handle_deposit(ctx, amount) }",
            ),
            (
                handler.clone(),
                "pub fn handle_deposit(c: Context<Deposit>, amount: u64) -> Result<()> { c.accounts.authority.key(); Ok(()) }",
            ),
        ]);

        let sites = index.use_sites(&decl, "Deposit");

        assert_eq!(sites.len(), 2);
        let delegated = sites.iter().find(|s| s.file == handler).unwrap();
        assert_eq!(delegated.access, FieldAccess::Context("c".to_string()));
        assert_eq!(delegated.params, ["c", "amount"]);
    }

    #[test]
    fn a_callee_taking_a_different_accounts_struct_is_not_a_use_site() {
        // The canonical Anchor layout gives every instruction module a
        // `pub fn handler`, so resolving a forwarded callee by name would union
        // unrelated handlers into one struct's use sites.
        let dir = temp_dir("unrelated_callee");
        let root = crate_dir(&dir, "program");
        let decl = root.join("program.rs");
        let index = index_of(&[(
            decl.clone(),
            "#[derive(Accounts)] pub struct Deposit {}\n\
             #[derive(Accounts)] pub struct Withdraw {}\n\
             pub fn deposit(ctx: Context<Deposit>) -> Result<()> { handler(ctx) }\n\
             pub fn handler(ctx: Context<Withdraw>) -> Result<()> { Ok(()) }",
        )]);

        let sites = index.use_sites(&decl, "Deposit");

        assert_eq!(sites.len(), 1);
        assert_eq!(body_of(&sites[0]), "{handler(ctx)}");
    }

    #[test]
    fn a_fn_addressable_two_ways_keeps_both_access_modes() {
        // A method on `impl Deposit` that also takes a `Context<Deposit>` reads
        // fields as `self.x` *and* `ctx.accounts.x`; dropping either entry would
        // hide half of the accesses from a rule.
        let dir = temp_dir("dual_access");
        let root = crate_dir(&dir, "program");
        let decl = root.join("program.rs");
        let index = index_of(&[(
            decl.clone(),
            "#[derive(Accounts)] pub struct Deposit {}\n\
             impl<'info> Deposit<'info> {\n\
                 fn run(&self, ctx: Context<Deposit>) -> Result<()> { Ok(()) }\n\
             }",
        )]);

        let sites = index.use_sites(&decl, "Deposit");

        assert_eq!(sites.len(), 2);
        let modes: Vec<&FieldAccess> = sites.iter().map(|s| &s.access).collect();
        assert!(modes.contains(&&FieldAccess::Context("ctx".to_string())));
        assert!(modes.contains(&&FieldAccess::SelfImpl));
    }

    #[test]
    fn lookups_are_scoped_to_the_querying_files_own_crate() {
        let dir = temp_dir("crate_scope");
        let insecure = crate_dir(&dir, "insecure").join("lib.rs");
        let secure = crate_dir(&dir, "secure").join("lib.rs");
        let index = index_of(&[
            (
                insecure.clone(),
                "#[derive(Accounts)] pub struct LogMessage {}\n\
                 pub fn log_message(ctx: Context<LogMessage>) -> Result<()> { Ok(()) }",
            ),
            (
                secure.clone(),
                "#[derive(Accounts)] pub struct LogMessage {}\n\
                 pub fn log_message(secure_ctx: Context<LogMessage>) -> Result<()> { require!(secure_ctx.accounts.authority.is_signer); Ok(()) }",
            ),
        ]);

        let sites = index.use_sites(&insecure, "LogMessage");

        assert_eq!(sites.len(), 1);
        assert_eq!(sites[0].file, insecure);
        assert_eq!(sites[0].access, FieldAccess::Context("ctx".to_string()));
    }

    #[test]
    fn functions_named_returns_a_same_crate_helper_with_its_parameters() {
        let dir = temp_dir("functions_named");
        let root = crate_dir(&dir, "program");
        let caller = root.join("caller.rs");
        let helper = root.join("helper.rs");
        let other = crate_dir(&dir, "other").join("lib.rs");
        let index = index_of(&[
            (caller.clone(), "pub fn caller() {}"),
            (
                helper.clone(),
                "pub fn verify(authority: &AccountInfo, expected: &Pubkey) -> Result<()> { Ok(()) }",
            ),
            (
                other.clone(),
                "pub fn verify(nothing: u64) -> Result<()> { Ok(()) }",
            ),
        ]);

        let sites = index.functions_named(&caller, "verify");

        assert_eq!(sites.len(), 1);
        assert_eq!(sites[0].file, helper);
        assert_eq!(sites[0].access, FieldAccess::Plain);
        assert_eq!(sites[0].params, ["authority", "expected"]);
    }

    #[test]
    fn a_file_that_can_no_longer_be_read_yields_no_use_sites() {
        let dir = temp_dir("unreadable");
        let root = crate_dir(&dir, "program");
        let decl = root.join("program.rs");
        let index = index_of(&[(
            decl.clone(),
            "#[derive(Accounts)] pub struct Deposit {}\n\
             pub fn deposit(ctx: Context<Deposit>) -> Result<()> { Ok(()) }",
        )]);
        fs::remove_file(&decl).unwrap();

        assert!(index.use_sites(&decl, "Deposit").is_empty());
    }
}
