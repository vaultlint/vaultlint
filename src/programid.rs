//! Collects the program ids a tree declares.
//!
//! A Solana program's `declare_id!` is the one place in the source that names
//! an address on a cluster. It is the join key between what is written in the
//! repository and what is actually running, so it is collected on every scan
//! even though only `--mainnet` has anything to ask about it.

use std::path::{Path, PathBuf};

/// A `declare_id!` whose argument decodes to a 32-byte address.
///
/// Arguments that are not string literals (`declare_id!(PROGRAM_ID)`) and
/// literals that do not decode to 32 bytes are not collected: neither can be
/// looked up, and guessing at either would put an address in the report that
/// the source does not contain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeclaredId {
    /// The address exactly as it is spelled in the source.
    pub address: String,
    pub file: PathBuf,
    pub line: usize,
    pub column: usize,
}

/// Every `declare_id!` in one parsed file, in source order.
pub fn collect(file: &Path, ast: &syn::File) -> Vec<DeclaredId> {
    let mut found = Vec::new();
    walk(file, &ast.items, &mut found);
    found
}

fn walk(file: &Path, items: &[syn::Item], found: &mut Vec<DeclaredId>) {
    for item in items {
        match item {
            syn::Item::Mod(module) => {
                if let Some((_, inner)) = &module.content {
                    walk(file, inner, found);
                }
            }
            syn::Item::Macro(item_macro) => {
                let Some(last) = item_macro.mac.path.segments.last() else {
                    continue;
                };
                if last.ident != "declare_id" {
                    continue;
                }
                let Ok(literal) = syn::parse2::<syn::LitStr>(item_macro.mac.tokens.clone()) else {
                    continue;
                };
                let address = literal.value();
                if !is_address(&address) {
                    continue;
                }
                let start = literal.span().start();
                found.push(DeclaredId {
                    address,
                    file: file.to_path_buf(),
                    line: start.line,
                    column: start.column + 1,
                });
            }
            _ => {}
        }
    }
}

/// Whether `text` is base58 for exactly 32 bytes.
pub fn is_address(text: &str) -> bool {
    decode_base58(text).is_some_and(|bytes| bytes.len() == 32)
}

const ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Big-endian base58 decode. `None` when a character is outside the alphabet.
fn decode_base58(text: &str) -> Option<Vec<u8>> {
    if text.is_empty() || text.len() > 44 {
        return None;
    }
    let mut out: Vec<u8> = Vec::with_capacity(32);
    for byte in text.bytes() {
        let mut carry = ALPHABET.iter().position(|&c| c == byte)? as u32;
        for slot in out.iter_mut().rev() {
            let value = u32::from(*slot) * 58 + carry;
            *slot = value as u8;
            carry = value >> 8;
        }
        while carry > 0 {
            out.insert(0, carry as u8);
            carry >>= 8;
        }
    }
    for byte in text.bytes() {
        if byte != b'1' {
            break;
        }
        out.insert(0, 0);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids(source: &str) -> Vec<DeclaredId> {
        let ast = crate::parse::parse_source(source).unwrap();
        collect(Path::new("lib.rs"), &ast)
    }

    /// The plain shape, and the location must point at the literal so the
    /// report can send a reader to the line that names the address.
    #[test]
    fn collects_a_top_level_declare_id_with_its_location() {
        let found = ids("use anchor_lang::prelude::*;\n\ndeclare_id!(\"M2mx93ekt1fmXSVkTrUL9xVFHkmME8HTUi5Cyc5aF7K\");\n");

        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(
            found[0].address,
            "M2mx93ekt1fmXSVkTrUL9xVFHkmME8HTUi5Cyc5aF7K"
        );
        assert_eq!(found[0].line, 3);
        assert_eq!(found[0].column, 13);
    }

    /// Anchor programs put `declare_id!` inside the `#[program]` module as often
    /// as beside it.
    ///
    /// Kill: drop the `Item::Mod` arm from `walk`.
    #[test]
    fn reaches_inside_an_inline_module() {
        let found = ids(
            "pub mod outer {\n    pub mod inner {\n        declare_id!(\"So11111111111111111111111111111111111111112\");\n    }\n}\n",
        );

        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(
            found[0].address,
            "So11111111111111111111111111111111111111112"
        );
    }

    /// A fully qualified call is the same declaration.
    #[test]
    fn matches_a_path_qualified_macro() {
        let found =
            ids("anchor_lang::declare_id!(\"So11111111111111111111111111111111111111112\");\n");

        assert_eq!(found.len(), 1, "{found:?}");
    }

    /// `declare_id!(PROGRAM_ID)` names a constant this module cannot resolve,
    /// and six files in one measured repository name a placeholder that is not
    /// an address at all. Neither can be looked up; reporting either as an
    /// address would invent one.
    ///
    /// Kill: accept any token stream, or drop the `is_address` guard.
    #[test]
    fn skips_a_non_literal_argument_and_a_literal_that_is_not_an_address() {
        assert!(ids("declare_id!(PROGRAM_ID);\n").is_empty());
        assert!(ids("declare_id!(\"YourProgramId\");\n").is_empty());
    }

    /// A 44-character string in the alphabet can still decode to 33 bytes, so
    /// length alone is not the test.
    ///
    /// Kill: replace `is_address` with a character-set-and-length check.
    #[test]
    fn rejects_base58_that_decodes_to_the_wrong_width() {
        assert!(is_address("11111111111111111111111111111111"));
        assert!(!is_address(
            "2111111111111111111111111111111111111111111111"
        ));
        assert!(!is_address("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"));
        assert!(!is_address("0OIl"));
        assert!(!is_address(""));
    }

    /// Leading `1`s are leading zero bytes, not padding to be trimmed — the
    /// system program's address is thirty-two of them.
    #[test]
    fn a_leading_one_decodes_to_a_zero_byte() {
        assert_eq!(decode_base58("11").unwrap(), vec![0, 0]);
        assert_eq!(decode_base58("1").unwrap(), vec![0]);
    }

    /// Two programs in one file, and the order is the order they are written.
    #[test]
    fn keeps_source_order() {
        let found = ids(
            "declare_id!(\"So11111111111111111111111111111111111111112\");\ndeclare_id!(\"11111111111111111111111111111111\");\n",
        );

        let addresses: Vec<_> = found.iter().map(|id| id.address.as_str()).collect();
        assert_eq!(
            addresses,
            [
                "So11111111111111111111111111111111111111112",
                "11111111111111111111111111111111"
            ]
        );
    }
}
