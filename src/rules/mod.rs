pub mod arithmetic;
pub mod cpi;
pub mod owner;
pub mod pda;
pub mod signer;

use std::path::Path;

use proc_macro2::Span;

use crate::anchor::AnchorModel;
use crate::finding::{Finding, Severity};
use crate::usesite::UseSiteIndex;

pub trait Rule {
    fn id(&self) -> &'static str;
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
        rule_id,
        severity,
        title,
        message,
        file: path.to_path_buf(),
        line,
        column: start.column + 1,
        snippet,
        help,
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

pub fn all() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(owner::MissingOwnerCheck),
        Box::new(arithmetic::UncheckedArithmetic),
        Box::new(pda::UnvalidatedPdaBump),
        Box::new(cpi::UncheckedCpi),
    ]
}

pub fn linked_all() -> Vec<Box<dyn LinkedRule>> {
    vec![Box::new(signer::MissingSignerCheck)]
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
/// source. The source is written to a uniquely-named temp file because the
/// index keys — and crate-scopes — everything by real path.
#[cfg(test)]
pub(crate) fn linked_findings_for(source: &str, rule: &dyn LinkedRule) -> Vec<Finding> {
    use std::sync::atomic::{AtomicUsize, Ordering};

    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "vaultlint_linked_{}_{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).expect("test temp dir must be creatable");
    let path = dir.join("test.rs");
    std::fs::write(&path, source).expect("test source must be writable");

    let ast = syn::parse_file(source).expect("test source must parse");
    let anchor = crate::anchor::build(&ast);
    let mut index = UseSiteIndex::empty();
    index.insert(&path, crate::usesite::collect_facts(&ast));
    let ctx = LinkedContext {
        path: &path,
        source,
        anchor: &anchor,
        index: &index,
    };
    let mut out = Vec::new();
    rule.check(&ctx, &mut out);
    out
}
