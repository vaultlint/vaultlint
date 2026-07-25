use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

pub struct ParsedFile {
    pub path: PathBuf,
    pub source: String,
    pub ast: syn::File,
}

pub fn parse(path: &Path) -> Result<ParsedFile> {
    let source =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let ast = syn::parse_file(&source).with_context(|| format!("parsing {}", path.display()))?;
    Ok(ParsedFile {
        path: path.to_path_buf(),
        source,
        ast,
    })
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
}
