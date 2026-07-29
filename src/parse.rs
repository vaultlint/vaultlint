use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};

/// Deepest `(`/`[`/`{` nesting a file may have before it is skipped unparsed.
///
/// `syn` descends recursively, so past a few thousand delimiters it exhausts
/// the stack — an abort the process cannot catch or report. The scan already
/// runs on a 64 MiB stack, which measured out at roughly 3,000 nested blocks in
/// a dev build; this leaves a factor of three under that. Nothing anyone writes
/// or generates comes close: rustc's own default recursion limit is 128.
const MAX_DELIMITER_DEPTH: usize = 1024;

pub struct ParsedFile {
    pub path: PathBuf,
    pub source: String,
    pub ast: syn::File,
}

pub fn parse(path: &Path) -> Result<ParsedFile> {
    let source =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let ast = parse_source(&source).with_context(|| format!("parsing {}", path.display()))?;
    Ok(ParsedFile {
        path: path.to_path_buf(),
        source,
        ast,
    })
}

/// `syn::parse_file`, refusing input nested deeply enough to take the stack
/// with it. Every parse in the crate goes through here — the scan reaches the
/// same file from three directions, and a guard on only one of them is no
/// guard at all.
pub fn parse_source(source: &str) -> Result<syn::File> {
    let depth = max_delimiter_depth(source);
    if depth > MAX_DELIMITER_DEPTH {
        return Err(anyhow!(
            "nests {depth} delimiters deep, past the limit of {MAX_DELIMITER_DEPTH}; \
             parsing it would overflow the stack"
        ));
    }
    Ok(syn::parse_file(source)?)
}

/// The deepest `(`/`[`/`{` nesting in `source`, counting neither comments nor
/// literals — a `{` inside a string opens nothing.
///
/// Iterative by construction: the guard cannot itself be the thing that
/// overflows. It works on bytes, which is safe because every byte it looks for
/// is ASCII and a UTF-8 continuation byte never is.
fn max_delimiter_depth(source: &str) -> usize {
    let bytes = source.as_bytes();
    let mut depth = 0usize;
    let mut deepest = 0usize;
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'/' if bytes.get(i + 1) == Some(&b'/') => i = skip_line_comment(bytes, i),
            b'/' if bytes.get(i + 1) == Some(&b'*') => i = skip_block_comment(bytes, i),
            b'"' => i = skip_quoted(bytes, i + 1, 0),
            b'r' | b'b' if starts_string(bytes, i) => i = skip_string_literal(bytes, i),
            b'\'' => i = skip_char_literal(bytes, i),
            b'(' | b'[' | b'{' => {
                depth += 1;
                deepest = deepest.max(depth);
                i += 1;
            }
            b')' | b']' | b'}' => {
                depth = depth.saturating_sub(1);
                i += 1;
            }
            _ => i += 1,
        }
    }
    deepest
}

fn skip_line_comment(bytes: &[u8], from: usize) -> usize {
    let mut i = from + 2;
    while i < bytes.len() && bytes[i] != b'\n' {
        i += 1;
    }
    i
}

/// Rust block comments nest, so `/* /* */ */` closes once, not twice.
fn skip_block_comment(bytes: &[u8], from: usize) -> usize {
    let mut i = from + 2;
    let mut open = 1usize;
    while i < bytes.len() && open > 0 {
        if bytes[i] == b'/' && bytes.get(i + 1) == Some(&b'*') {
            open += 1;
            i += 2;
        } else if bytes[i] == b'*' && bytes.get(i + 1) == Some(&b'/') {
            open -= 1;
            i += 2;
        } else {
            i += 1;
        }
    }
    i
}

/// True if a `b` or `r` at `at` begins a string literal — `b"…"`, `r"…"`,
/// `br#"…"#` — rather than sitting inside an identifier such as `number`.
fn starts_string(bytes: &[u8], at: usize) -> bool {
    if at > 0 && (bytes[at - 1].is_ascii_alphanumeric() || bytes[at - 1] == b'_') {
        return false;
    }
    string_body_start(bytes, at).is_some()
}

/// Walks the `b`/`r`/`#` prefix of a string literal, returning the offset of
/// the opening quote and the hash count, or `None` if this is not one.
fn string_body_start(bytes: &[u8], at: usize) -> Option<(usize, usize)> {
    let mut i = at;
    if bytes.get(i) == Some(&b'b') {
        i += 1;
    }
    let raw = bytes.get(i) == Some(&b'r');
    if raw {
        i += 1;
    }
    let mut hashes = 0usize;
    if raw {
        while bytes.get(i) == Some(&b'#') {
            hashes += 1;
            i += 1;
        }
    }
    if bytes.get(i) != Some(&b'"') {
        return None;
    }
    Some((i + 1, if raw { hashes } else { 0 }))
}

fn skip_string_literal(bytes: &[u8], at: usize) -> usize {
    match string_body_start(bytes, at) {
        Some((body, hashes)) => skip_quoted(bytes, body, hashes),
        None => at + 1,
    }
}

/// Scans from the first byte of a string's body to just past its terminator.
/// `hashes` is the raw-string hash count; zero means backslash escapes apply.
fn skip_quoted(bytes: &[u8], from: usize, hashes: usize) -> usize {
    let mut i = from;
    while i < bytes.len() {
        if hashes == 0 && bytes[i] == b'\\' {
            i += 2;
            continue;
        }
        if bytes[i] == b'"' && bytes[i + 1..].iter().take(hashes).all(|&b| b == b'#') {
            return i + 1 + hashes;
        }
        i += 1;
    }
    i
}

/// A `'` opens a character literal only when a closing `'` follows one
/// character (or one escape) later. Otherwise it is a lifetime — `'info` is on
/// nearly every line of an Anchor program, and treating it as an unterminated
/// literal would swallow the rest of the file.
fn skip_char_literal(bytes: &[u8], at: usize) -> usize {
    let escaped = bytes.get(at + 1) == Some(&b'\\');
    // `'\n'` is four bytes, `'x'` is three; a multi-byte char is longer, and is
    // read as a lifetime, which costs nothing since it holds no delimiter.
    let close = if escaped { at + 3 } else { at + 2 };
    if bytes.get(close) == Some(&b'\'') {
        close + 1
    } else {
        at + 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn parses_valid_rust_and_keeps_source() {
        let path = std::env::temp_dir().join("vaultlint_parse_ok.rs");
        fs::write(&path, "pub fn add(a: u64, b: u64) -> u64 { a + b }\n").unwrap();

        let parsed = parse(&path).unwrap();

        assert_eq!(parsed.ast.items.len(), 1);
        assert!(parsed.source.contains("pub fn add"));
    }

    #[test]
    fn reports_error_for_invalid_rust() {
        let path = std::env::temp_dir().join("vaultlint_parse_bad.rs");
        fs::write(&path, "pub fn ( { not rust").unwrap();

        assert!(parse(&path).is_err());
    }

    /// The whole point of the guard: a file this deep aborts the process inside
    /// `syn::parse_file`, so it has to be turned away before then. It is skipped
    /// with a reason, like any other file that cannot be read.
    ///
    /// Killing mutation: delete the `MAX_DELIMITER_DEPTH` check from `parse`.
    /// The test then dies with SIGABRT instead of failing.
    #[test]
    fn refuses_a_file_nested_past_the_limit() {
        let path = std::env::temp_dir().join("vaultlint_parse_deep.rs");
        let mut source = String::from("let _x = 1;");
        for _ in 0..(MAX_DELIMITER_DEPTH + 1) {
            source = format!("{{ {source} }}");
        }
        fs::write(&path, format!("fn f() {source}\n")).unwrap();

        let Err(error) = parse(&path) else {
            panic!("a file this deep must be refused");
        };

        assert!(format!("{error:#}").contains("overflow the stack"));
    }

    /// Braces in comments and literals open nothing. `'info` in particular is on
    /// nearly every line of an Anchor program, and reading it as an
    /// unterminated character literal would swallow the rest of the file.
    ///
    /// Killing mutation: in `max_delimiter_depth`, count every delimiter byte
    /// and drop the comment and literal arms. The depth then reads 6, not 2.
    #[test]
    fn depth_ignores_comments_and_literals() {
        let source = r####"
            fn f<'info>() {
                // {{{
                /* {{ /* { */ */
                let a = "{{";
                let b = r#"{{"#;
                let c = b"{";
                let d = '{';
                let e = vec![1];
            }
        "####;

        assert_eq!(max_delimiter_depth(source), 2);
    }

    /// Real code sits nowhere near the limit, and a guard that turned away
    /// ordinary source would be worse than the crash it prevents.
    #[test]
    fn ordinary_source_is_nowhere_near_the_limit() {
        let source = include_str!("parse.rs");

        assert!(max_delimiter_depth(source) < MAX_DELIMITER_DEPTH / 8);
    }
}
