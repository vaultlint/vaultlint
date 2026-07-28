use crate::finding::Finding;

const MARKER: &str = "vaultlint:allow";

/// True when the finding's own line, or a contiguous block of comment, attribute,
/// and blank lines above the finding line, carries `// vaultlint:allow <RULE_ID>`.
///
/// The upward walk stops at the first line that is not:
///   - a comment line (`//` or `///`),
///   - an attribute line starting with `#[`,
///   - a continuation line inside a multi-line attribute (tracked by bracket depth),
///   - or a blank line.
///
/// Bare `vaultlint:allow` without an id is intentionally not honoured: silencing
/// every rule at once should be explicit.
pub fn is_suppressed(source: &str, finding: &Finding) -> bool {
    let lines: Vec<&str> = source.lines().collect();
    let index = finding.line.saturating_sub(1);

    // Always check the finding's own line first (trailing comment).
    if let Some(line) = lines.get(index) {
        if mentions(line, &finding.rule_id) {
            return true;
        }
    }

    // Walk upward through a contiguous block of comment/attribute/blank lines.
    if index == 0 {
        return false;
    }

    // bracket_depth tracks how deep we are inside a multi-line attribute.
    // Only `(` / `)` and `[` / `]` are counted; `{` and `}` are block boundaries
    // in Rust — a `}` stops the walk immediately rather than being treated as an
    // attribute continuation.
    // NOTE: brackets inside string literals are not excluded; a full lexer would
    // be needed for that. This is a known limitation.
    let mut bracket_depth: usize = 0;
    let mut i = index - 1;
    while let Some(line) = lines.get(i) {
        let trimmed = line.trim();

        // A closing brace is a block boundary — stop here; do not absorb it.
        if trimmed.contains('}') && bracket_depth == 0 {
            break;
        }

        // Account for attribute brackets on this line (right-to-left so we know
        // the depth at the *start* of the line before deciding whether the line
        // is a continuation of a multi-line attribute).
        // Going upward: `)` and `]` open depth; `(` and `[` close depth.
        // `{` / `}` are intentionally excluded — they are block boundaries, not
        // attribute delimiters.
        for ch in trimmed.chars().rev() {
            match ch {
                ')' | ']' => bracket_depth += 1,
                '(' | '[' => {
                    bracket_depth = bracket_depth.saturating_sub(1);
                }
                _ => {}
            }
        }

        let is_block_line = if bracket_depth > 0 {
            // Inside a multi-line attribute — always part of the block.
            true
        } else {
            trimmed.is_empty() || trimmed.starts_with("//") || trimmed.starts_with("#[")
        };

        if !is_block_line {
            break;
        }

        if mentions(line, &finding.rule_id) {
            return true;
        }

        if i == 0 {
            break;
        }
        i -= 1;
    }

    false
}

fn mentions(line: &str, rule_id: &str) -> bool {
    let Some(position) = line.find(MARKER) else {
        return false;
    };
    let after = &line[position + MARKER.len()..];
    // The rule id must be bounded by non-alphanumeric/non-underscore chars
    // (or start/end of the remaining text) on both sides, to prevent
    // `VL0011` from suppressing `VL001`.
    let mut start = 0;
    while let Some(offset) = after[start..].find(rule_id) {
        let abs = start + offset;
        let before_ok = abs == 0
            || !after[..abs]
                .chars()
                .next_back()
                .is_some_and(|c| c.is_alphanumeric() || c == '_');
        let end = abs + rule_id.len();
        let after_ok = end >= after.len()
            || !after[end..]
                .chars()
                .next()
                .is_some_and(|c| c.is_alphanumeric() || c == '_');
        if before_ok && after_ok {
            return true;
        }
        start = abs + 1;
        if start >= after.len() {
            break;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::{Finding, Severity};
    use std::path::PathBuf;

    fn finding_at(line: usize) -> Finding {
        finding_with_id("VL003", line)
    }

    fn finding_with_id(rule_id: &'static str, line: usize) -> Finding {
        Finding {
            rule_id: std::borrow::Cow::Borrowed(rule_id),
            severity: Severity::Medium,
            title: std::borrow::Cow::Borrowed("test finding"),
            message: "test".to_string(),
            file: PathBuf::from("state.rs"),
            line,
            column: 1,
            snippet: String::new(),
            help: std::borrow::Cow::Borrowed("test help"),
            docs_url: String::new(),
        }
    }

    const SOURCE: &str = "\
fn a() {
    // vaultlint:allow VL003 — audited, cannot underflow
    vault.balance = vault.balance - amount;
}
fn b() {
    vault.balance = vault.balance - amount; // vaultlint:allow VL003
}
fn c() {
    vault.balance = vault.balance - amount;
}
fn d() {
    // vaultlint:allow VL001
    vault.balance = vault.balance - amount;
}
";

    #[test]
    fn suppresses_from_the_line_above() {
        assert!(is_suppressed(SOURCE, &finding_at(3)));
    }

    #[test]
    fn suppresses_from_a_trailing_comment_on_the_same_line() {
        assert!(is_suppressed(SOURCE, &finding_at(6)));
    }

    #[test]
    fn leaves_unmarked_findings_alone() {
        assert!(!is_suppressed(SOURCE, &finding_at(9)));
    }

    #[test]
    fn does_not_suppress_a_different_rule_id() {
        assert!(!is_suppressed(SOURCE, &finding_at(13)));
    }

    // ── word-boundary tests ──────────────────────────────────────────────────

    /// `VL0011` must NOT suppress `VL001` — longer id shares the prefix.
    #[test]
    fn does_not_suppress_when_rule_id_is_a_prefix_of_a_longer_token() {
        let source = "\
// vaultlint:allow VL0011
vault.balance = vault.balance - amount;
";
        assert!(!is_suppressed(source, &finding_with_id("VL001", 2)));
    }

    /// `XVL001` must NOT suppress `VL001` — longer id shares the suffix.
    #[test]
    fn does_not_suppress_when_rule_id_is_a_suffix_of_a_longer_token() {
        let source = "\
// vaultlint:allow XVL001
vault.balance = vault.balance - amount;
";
        assert!(!is_suppressed(source, &finding_with_id("VL001", 2)));
    }

    /// `VL001X` must NOT suppress `VL001`.
    #[test]
    fn does_not_suppress_when_rule_id_has_trailing_alphanumeric() {
        let source = "\
// vaultlint:allow VL001X
vault.balance = vault.balance - amount;
";
        assert!(!is_suppressed(source, &finding_with_id("VL001", 2)));
    }

    /// Multiple ids on one line: `vaultlint:allow VL001, VL004` suppresses VL001.
    #[test]
    fn suppresses_when_multiple_ids_listed_and_rule_matches() {
        let source = "\
// vaultlint:allow VL001, VL004
vault.balance = vault.balance - amount;
";
        assert!(is_suppressed(source, &finding_with_id("VL001", 2)));
        assert!(is_suppressed(source, &finding_with_id("VL004", 2)));
        assert!(!is_suppressed(source, &finding_with_id("VL003", 2)));
    }

    // ── VL001: suppression through a `/// CHECK:` block ─────────────────────

    /// VL001 fires on an `AccountInfo` field. Anchor requires `/// CHECK: reason`
    /// directly above every such field. A `// vaultlint:allow VL001` comment
    /// above the `/// CHECK:` line must still suppress the finding.
    #[test]
    fn suppresses_vl001_via_comment_above_check_doc_comment() {
        // The finding is on line 5 (`pub authority: AccountInfo<'info>,`).
        // Line 4 is `/// CHECK: not validated`, line 3 is the allow comment.
        let source = "\
#[derive(Accounts)]
pub struct Withdraw<'info> {
    // vaultlint:allow VL001 — reviewed
    /// CHECK: not validated
    pub authority: AccountInfo<'info>,
}
";
        assert!(is_suppressed(source, &finding_with_id("VL001", 5)));
    }

    /// Without the allow comment, the finding must NOT be suppressed.
    #[test]
    fn does_not_suppress_vl001_when_only_check_doc_comment_present() {
        let source = "\
#[derive(Accounts)]
pub struct Withdraw<'info> {
    /// CHECK: not validated
    pub authority: AccountInfo<'info>,
}
";
        assert!(!is_suppressed(source, &finding_with_id("VL001", 4)));
    }

    // ── VL002: suppression works (simple case — comment directly above) ──────

    #[test]
    fn suppresses_vl002_from_comment_above() {
        let source = "\
pub fn read_config(ctx: Context<ReadConfig>) -> Result<()> {
    let account = &ctx.accounts.config;
    // vaultlint:allow VL002 — owner verified at call site
    let config = Config::try_from_slice(&account.data.borrow())?;
    Ok(())
}
";
        assert!(is_suppressed(source, &finding_with_id("VL002", 4)));
    }

    // ── VL004: suppression through an `#[account(...)]` attribute block ──────

    /// VL004 fires on the field line. The `#[account(...)]` attribute sits
    /// directly above the field, and the allow comment must be above that.
    #[test]
    fn suppresses_vl004_via_comment_above_account_attribute() {
        // Finding is on line 7 (`pub vault: Account<'info, Vault>,`).
        // Line 6 is `)]`, line 5 is `  bump = user_bump`, etc — the multi-line
        // attribute. Line 3 is the allow comment.
        let source = "\
#[derive(Accounts)]
#[instruction(user_bump: u8)]
// vaultlint:allow VL004 — bump validated elsewhere
#[account(
  seeds = [b\"vault\"],
  bump = user_bump
)]
pub vault: Account<'info, Vault>,
";
        assert!(is_suppressed(source, &finding_with_id("VL004", 8)));
    }

    /// Without the allow comment, the finding must NOT be suppressed.
    #[test]
    fn does_not_suppress_vl004_without_allow_comment() {
        let source = "\
#[derive(Accounts)]
#[instruction(user_bump: u8)]
#[account(
  seeds = [b\"vault\"],
  bump = user_bump
)]
pub vault: Account<'info, Vault>,
";
        assert!(!is_suppressed(source, &finding_with_id("VL004", 7)));
    }

    // ── VL005: suppression works (simple case — comment directly above) ──────

    #[test]
    fn suppresses_vl005_from_comment_above() {
        let source = "\
pub fn claim(ctx: Context<Claim>) -> Result<()> {
    let instruction = build_instruction();
    // vaultlint:allow VL005 — callee verified at runtime
    invoke(&instruction, &[a.clone(), b.clone(), target_program.clone()])?;
    Ok(())
}
";
        assert!(is_suppressed(source, &finding_with_id("VL005", 4)));
    }

    // ── Block-breaking: an unrelated line stops the walk ────────────────────

    /// If a non-comment, non-attribute, non-blank line appears between the allow
    /// comment and the finding, the block is broken and suppression must NOT apply.
    #[test]
    fn does_not_suppress_when_unrelated_line_breaks_the_block() {
        let source = "\
// vaultlint:allow VL003 — this is too far away
let unrelated = 1;
vault.balance = vault.balance - amount;
";
        assert!(!is_suppressed(source, &finding_with_id("VL003", 3)));
    }

    // ── Closing-brace boundary: the walk must not cross a `}` ───────────────

    /// An allow comment inside a preceding block must NOT suppress a finding
    /// that is outside that block, even if only blank / comment lines separate
    /// the `}` from the finding.
    ///
    /// This is the critical regression test: the old code counted `}` as an
    /// attribute depth opener, which could drive `bracket_depth > 0` and make
    /// the walker absorb arbitrary preceding code.
    #[test]
    fn does_not_cross_a_closing_brace() {
        let source = "\
fn a() {
    // vaultlint:allow VL003
    let y = 2;
}

vault.balance = vault.balance - amount;
";
        assert!(!is_suppressed(source, &finding_with_id("VL003", 6)));
    }

    // ── Right-to-left bracket accounting ────────────────────────────────────

    /// A line that both opens and closes an attribute bracket on the same line
    /// (e.g. `#[account(mut)]`) must leave `bracket_depth` at zero after being
    /// processed. If the per-line scan goes left-to-right instead of
    /// right-to-left the depth could be transiently non-zero at the wrong
    /// moment, allowing lines that should break the block to be absorbed.
    ///
    /// We test with an allow comment directly above a single-line `#[account(mut)]`
    /// attribute — suppression MUST work — and then verify that walking further
    /// up through a closing brace still stops the walk.
    #[test]
    fn bracket_accounting_handles_open_and_close_on_same_line() {
        // Finding on line 3 (`pub authority: Signer<'info>,`).
        // Line 2 is `#[account(mut)]` (brackets open and close on the same line,
        // net depth = 0 after processing right-to-left).
        // Line 1 is the allow comment.
        let source = "\
// vaultlint:allow VL001 — reviewed
#[account(mut)]
pub authority: Signer<'info>,
";
        assert!(is_suppressed(source, &finding_with_id("VL001", 3)));
    }

    /// Companion negative: an allow comment separated from the finding by a
    /// closing brace and a single-line attribute must NOT suppress.
    #[test]
    fn does_not_cross_closing_brace_even_with_single_line_attribute() {
        let source = "\
fn prev() {
    // vaultlint:allow VL001
}

#[account(mut)]
pub authority: Signer<'info>,
";
        // Finding is on line 6.  The walk will hit the `}` on line 3 and stop.
        assert!(!is_suppressed(source, &finding_with_id("VL001", 6)));
    }
}
