pub mod arithmetic;
pub mod owner;
pub mod signer;

use std::path::Path;

use proc_macro2::Span;

use crate::anchor::AnchorModel;
use crate::finding::{Finding, Severity};

pub trait Rule {
    fn id(&self) -> &'static str;
    fn check(&self, ctx: &RuleContext<'_>, out: &mut Vec<Finding>);
}

pub struct RuleContext<'a> {
    pub path: &'a Path,
    pub source: &'a str,
    pub ast: &'a syn::File,
    pub anchor: &'a AnchorModel,
    pub overflow_checks: bool,
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
        let start = span.start();
        let line = start.line.max(1);
        let snippet = self
            .source
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
            file: self.path.to_path_buf(),
            line,
            column: start.column + 1,
            snippet,
            help,
            docs_url: format!("https://vaultlint.com/rules/{rule_id}"),
        }
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
        Box::new(signer::MissingSignerCheck),
        Box::new(owner::MissingOwnerCheck),
        Box::new(arithmetic::UncheckedArithmetic),
    ]
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
