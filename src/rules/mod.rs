pub mod arithmetic;
pub mod cpi;
pub mod init_authority;
pub mod owner;
pub mod pda;

use std::path::Path;

use proc_macro2::Span;

use crate::anchor::AnchorModel;
use crate::finding::{Finding, Severity};
use crate::usesite::UseSiteIndex;

pub trait Rule {
    fn check(&self, ctx: &RuleContext<'_>, out: &mut Vec<Finding>);
}

/// A rule that needs to see how a struct's fields are *used*, and therefore runs
/// in a second pass, once the use-site index covers the whole tree.
pub trait LinkedRule {
    fn id(&self) -> &'static str;
    fn check(&self, ctx: &LinkedContext<'_>, out: &mut Vec<Finding>);
}

pub struct RuleContext<'a> {
    pub path: &'a Path,
    pub source: &'a str,
    pub ast: &'a syn::File,
    pub anchor: &'a AnchorModel,
    pub overflow_checks: bool,
}

pub struct LinkedContext<'a> {
    pub path: &'a Path,
    pub source: &'a str,
    pub anchor: &'a AnchorModel,
    pub index: &'a UseSiteIndex,
}

impl RuleContext<'_> {
    pub fn finding(
        &self,
        rule_id: &'static str,
        severity: Severity,
        title: &'static str,
        message: String,
        help: &'static str,
        span: Span,
    ) -> Finding {
        finding_at(
            self.path,
            self.source,
            rule_id,
            severity,
            title,
            message,
            help,
            span,
        )
    }
}

impl LinkedContext<'_> {
    pub fn finding(
        &self,
        rule_id: &'static str,
        severity: Severity,
        title: &'static str,
        message: String,
        help: &'static str,
        span: Span,
    ) -> Finding {
        finding_at(
            self.path,
            self.source,
            rule_id,
            severity,
            title,
            message,
            help,
            span,
        )
    }
}

#[allow(clippy::too_many_arguments)]
fn finding_at(
    path: &Path,
    source: &str,
    rule_id: &'static str,
    severity: Severity,
    title: &'static str,
    message: String,
    help: &'static str,
    span: Span,
) -> Finding {
    let start = span.start();
    let line = start.line.max(1);
    let snippet = source
        .lines()
        .nth(line - 1)
        .unwrap_or_default()
        .trim()
        .to_string();
    Finding {
        rule_id: std::borrow::Cow::Borrowed(rule_id),
        severity,
        title: std::borrow::Cow::Borrowed(title),
        message,
        file: path.to_path_buf(),
        line,
        column: start.column + 1,
        snippet,
        help: std::borrow::Cow::Borrowed(help),
        docs_url: format!("https://vaultlint.com/rules/{rule_id}"),
    }
}

/// Token text of an AST node with all whitespace removed, so that
/// `account . data . borrow ()` becomes `account.data.borrow()` and rules can
/// ask simple textual questions about a fragment they do not want to walk.
pub(crate) fn normalised(tokens: &impl quote::ToTokens) -> String {
    quote::ToTokens::to_token_stream(tokens)
        .to_string()
        .replace(char::is_whitespace, "")
}

/// True if `c` can appear inside a Rust identifier (alphanumeric or `_`).
///
/// Used by [`find_bounded`] to check whether a match is continued by an
/// identifier character. Both predicates look at characters, never bytes —
/// `text.as_bytes()[i] as char` would mis-classify the second byte of a
/// multi-byte character and produce wrong boundary decisions on non-ASCII
/// identifiers, which Rust allows.
pub(crate) fn is_ident_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// Scans `text` for occurrences of `needle`, returning true at the first one
/// whose neighbours are accepted by both predicates. `left` receives everything
/// before the match and `right` everything after it, so a predicate that needs
/// more than one character of context can ask for it.
///
/// Returns `false` immediately if `needle` is empty — an empty needle would
/// produce `Some(0)` from every `find` call, making the walk infinite.
///
/// Two points of care for the walk itself:
///
/// * A failed match resumes at `at + needle.len()`, never `at + 1`. Rust
///   identifiers may hold any XID character, so `pub émetteur_authority:
///   UncheckedAccount<'info>` is legal input, and resuming one byte into a
///   multi-byte character panics on the next slice — unacceptable in a linter,
///   which must survive every file it is pointed at. Skipping the whole needle
///   loses nothing: a later match starting *inside* this one has a character of
///   the needle to its left, and every needle used here begins with an
///   identifier character, so such a match would fail `left` anyway.
/// * Both predicates look at characters, never bytes. `text.as_bytes()[i] as
///   char` would read the second byte of `é` as `©` and answer that an
///   identifier does not continue there.
pub(crate) fn find_bounded(
    text: &str,
    needle: &str,
    left: impl Fn(&str) -> bool,
    right: impl Fn(&str) -> bool,
) -> bool {
    if needle.is_empty() {
        return false;
    }
    let mut start = 0;
    while let Some(offset) = text[start..].find(needle) {
        let at = start + offset;
        let end = at + needle.len();
        if left(&text[..at]) && right(&text[end..]) {
            return true;
        }
        start = end;
        if start >= text.len() {
            break;
        }
    }
    false
}

/// True if `needle` appears in `haystack` as a complete identifier (not
/// continued by an identifier character on either side). Returns false
/// immediately for an empty needle (which would loop forever) — see
/// [`find_bounded`].
///
/// A dotted needle works too, because `is_ident_char` is false for `.`:
/// `ctx.accounts.token_program` matches inside
/// `ctx.accounts.token_program.key()` but not inside
/// `ctx.accounts.token_program_2`.
pub(crate) fn whole_word_match(haystack: &str, needle: &str) -> bool {
    find_bounded(
        haystack,
        needle,
        |left| !left.chars().next_back().is_some_and(is_ident_char),
        |right| !right.chars().next().is_some_and(is_ident_char),
    )
}

pub fn all() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(owner::MissingOwnerCheck),
        Box::new(arithmetic::UncheckedArithmetic),
        Box::new(pda::UnvalidatedPdaBump),
        Box::new(cpi::UncheckedCpi),
    ]
}

pub fn linked_all() -> Vec<Box<dyn LinkedRule>> {
    vec![Box::new(init_authority::UnprovenAuthorityOnInit)]
}

#[cfg(test)]
pub(crate) fn findings_for(source: &str, rule: &dyn Rule) -> Vec<Finding> {
    findings_with_overflow_checks(source, rule, false)
}

#[cfg(test)]
pub(crate) fn findings_with_overflow_checks(
    source: &str,
    rule: &dyn Rule,
    overflow_checks: bool,
) -> Vec<Finding> {
    let ast = syn::parse_file(source).expect("test source must parse");
    let anchor = crate::anchor::build(&ast);
    let ctx = RuleContext {
        path: Path::new("test.rs"),
        source,
        ast: &ast,
        anchor: &anchor,
        overflow_checks,
    };
    let mut out = Vec::new();
    rule.check(&ctx, &mut out);
    out
}

/// Runs a `LinkedRule` over one source, against an index containing only that
/// source.
#[cfg(test)]
pub(crate) fn linked_findings_for(source: &str, rule: &dyn LinkedRule) -> Vec<Finding> {
    linked_findings_for_files(&[("test.rs", source)], rule)
}

/// Runs a `LinkedRule` over a small multi-file tree, returning the findings for
/// `files[0]`.
///
/// Every file is written into one uniquely-named temp directory, because the
/// index keys — and crate-scopes — everything by real path. A file whose name
/// does not end in `.rs` is written but not parsed, which is how a test lays
/// down a nested `Cargo.toml` to split the tree into two crates.
///
/// All files are written *before* any of them is indexed: `crate_id` caches its
/// answer per directory, so indexing `a/lib.rs` before `a/Cargo.toml` exists
/// would pin that directory to the outer crate for the rest of the run.
#[cfg(test)]
pub(crate) fn linked_findings_for_files(
    files: &[(&str, &str)],
    rule: &dyn LinkedRule,
) -> Vec<Finding> {
    use std::sync::atomic::{AtomicUsize, Ordering};

    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "vaultlint_linked_{}_{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("test temp dir must be creatable");
    // Pins the crate boundary to this directory instead of letting it fall back
    // to whatever ancestor of the system temp dir happens to hold a Cargo.toml,
    // which would merge every invocation into one crate.
    std::fs::write(
        dir.join("Cargo.toml"),
        "[package]\nname = \"vaultlint-test\"\n",
    )
    .expect("test crate manifest must be writable");

    let paths: Vec<std::path::PathBuf> = files
        .iter()
        .map(|(name, source)| {
            let path = dir.join(name);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).expect("test subdirectory must be creatable");
            }
            std::fs::write(&path, source).expect("test source must be writable");
            path
        })
        .collect();

    let mut index = UseSiteIndex::empty();
    for (path, (_, source)) in paths.iter().zip(files) {
        if path.extension().is_some_and(|ext| ext == "rs") {
            let ast = syn::parse_file(source).expect("test source must parse");
            index.insert(path, crate::usesite::collect_facts(&ast));
        }
    }

    let source = files[0].1;
    let ast = syn::parse_file(source).expect("test source must parse");
    let anchor = crate::anchor::build(&ast);
    let ctx = LinkedContext {
        path: &paths[0],
        source,
        anchor: &anchor,
        index: &index,
    };
    let mut out = Vec::new();
    rule.check(&ctx, &mut out);
    let _ = std::fs::remove_dir_all(&dir);
    out
}
