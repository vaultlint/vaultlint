//! Decides whether a Rust source file is "test scope" — code that never runs
//! on-chain and whose findings should be suppressed.
//!
//! Four mechanisms, all driven from declarations (Cargo manifests or `cfg`
//! attributes), never from directory or file names:
//!
//! - **M1**: Cargo integration-test / bench files — the file's path relative to
//!   its crate root starts with `tests` or `benches`.
//! - **M2**: `cargo fuzz` crates — the crate's `Cargo.toml` has
//!   `package.metadata.cargo-fuzz = true`.
//! - **M3**: Files declared as `#[cfg(test)] mod NAME;` — the attribute at the
//!   *declaration* site marks the file, not the file name itself.
//! - **M4**: Inline `#[cfg(test)] mod NAME { … }` blocks — individual findings
//!   whose line falls inside such a block are dropped after parsing.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use syn::visit::Visit;

// ─── Public surface ──────────────────────────────────────────────────────────

/// True if `file` is test/bench/fuzz code under any of M1–M3.
/// M4 is handled separately after parsing, in [`test_ranges`].
pub fn is_test_scope(file: &Path, m3_set: &HashSet<PathBuf>) -> bool {
    is_m1(file) || is_m2(file) || m3_set.contains(file)
}

/// Scans the Rust files collected by `scan::rust_files` and returns the set of
/// paths that are M3 test scope — i.e. paths that appear as the target of a
/// `#[cfg(test)] mod NAME;` declaration in *another* file.
///
/// This is called once before the main scan loop. The returned set is passed to
/// `is_test_scope` during file filtering.
pub fn collect_m3_set(files: &[PathBuf]) -> HashSet<PathBuf> {
    let mut set = HashSet::new();
    for file in files {
        let Ok(source) = std::fs::read_to_string(file) else {
            continue;
        };
        let Ok(ast) = syn::parse_file(&source) else {
            continue;
        };
        // Rust's module resolution: given `foo/bar.rs`, `mod sub;` resolves to
        // `foo/bar/sub.rs` (not `foo/sub.rs`).  The exceptions are `lib.rs`,
        // `mod.rs`, and `main.rs`, where submodules live alongside the file.
        let dir = mod_search_dir(file);
        collect_cfg_test_mods(&ast, &dir, &mut set);
    }
    set
}

/// Returns the directory in which submodule files declared by `file` are found.
///
/// For `lib.rs`, `mod.rs`, and `main.rs` that is the directory containing the
/// file itself.  For any other `NAME.rs` it is a sibling directory also called
/// `NAME` (i.e. `foo/bar.rs` → search in `foo/bar/`).
fn mod_search_dir(file: &Path) -> PathBuf {
    let parent = file.parent().unwrap_or(Path::new("."));
    let stem = file
        .file_stem()
        .map(|s| s.to_string_lossy())
        .unwrap_or_default();
    match stem.as_ref() {
        "lib" | "mod" | "main" => parent.to_path_buf(),
        _ => parent.join(stem.as_ref()),
    }
}

/// Returns the line ranges (inclusive start, inclusive end) of all inline
/// `#[cfg(test)] mod NAME { … }` blocks in `ast`.  A finding whose line falls
/// inside any of these ranges is M4 test scope.
pub fn test_ranges(ast: &syn::File) -> Vec<(usize, usize)> {
    let mut visitor = InlineTestVisitor { ranges: Vec::new() };
    visitor.visit_file(ast);
    visitor.ranges
}

/// True if `line` (1-based) falls inside any of the ranges returned by
/// [`test_ranges`].
pub fn in_test_range(line: usize, ranges: &[(usize, usize)]) -> bool {
    ranges
        .iter()
        .any(|&(start, end)| line >= start && line <= end)
}

// ─── cfg(test) recogniser ────────────────────────────────────────────────────

/// True when an attribute list contains an attribute that means exactly
/// `cfg(test)` — either `#[cfg(test)]` or `#[cfg(all(test, …))]`.
///
/// Rejects:
/// - `#[cfg(feature = "test")]`  — a feature flag, not the test harness
/// - `#[cfg(not(test))]`         — the negation
pub fn attrs_have_cfg_test(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(is_cfg_test_attr)
}

fn is_cfg_test_attr(attr: &syn::Attribute) -> bool {
    // Must be `cfg(…)`.
    if !attr.path().is_ident("cfg") {
        return false;
    }
    let Ok(meta) = attr.parse_args::<syn::Meta>() else {
        return false;
    };
    meta_contains_bare_test(&meta)
}

/// Recursively checks whether `meta` is or contains a bare `test` (i.e. a path
/// `test` with no arguments).  Handles:
///   cfg(test)           → Path("test")              → true
///   cfg(all(test, …))  → List("all", [Path("test"), …]) → true
///   cfg(feature = "…") → NameValue("feature", …)   → false
///   cfg(not(test))     → List("not", [Path("test")]) → false (blocked by !not)
fn meta_contains_bare_test(meta: &syn::Meta) -> bool {
    match meta {
        // `test` with no args — the bare path we are looking for.
        syn::Meta::Path(path) => path.is_ident("test"),

        // `all(…)` — recurse into each nested meta.
        // `not(…)` — explicitly rejected (the `not` case).
        // Any other list-form — not accepted.
        syn::Meta::List(list) => {
            if !list.path.is_ident("all") {
                return false;
            }
            // Parse the nested metas inside `all(…)`.
            let nested = list
                .parse_args_with(
                    syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated,
                )
                .unwrap_or_default();
            nested.iter().any(meta_contains_bare_test)
        }

        // `feature = "test"` and similar — never accepted.
        syn::Meta::NameValue(_) => false,
    }
}

// ─── M1: Cargo integration-test / bench files ────────────────────────────────

fn is_m1(file: &Path) -> bool {
    let Some(crate_root) = nearest_cargo_toml_dir(file) else {
        return false;
    };
    let Ok(rel) = file.strip_prefix(&crate_root) else {
        return false;
    };
    // The very first component (i.e. directly under the crate root) must be
    // `tests` or `benches`.
    let mut components = rel.components();
    let Some(first) = components.next() else {
        return false;
    };
    let first_str = first.as_os_str().to_string_lossy();
    first_str == "tests" || first_str == "benches"
}

/// Walks up the directory tree from `file` (exclusive) and returns the first
/// directory that contains a `Cargo.toml`, or `None`.
fn nearest_cargo_toml_dir(file: &Path) -> Option<PathBuf> {
    let mut dir = file.parent()?;
    loop {
        if dir.join("Cargo.toml").is_file() {
            return Some(dir.to_path_buf());
        }
        dir = dir.parent()?;
    }
}

// ─── M2: cargo-fuzz crates ───────────────────────────────────────────────────

fn is_m2(file: &Path) -> bool {
    let Some(crate_root) = nearest_cargo_toml_dir(file) else {
        return false;
    };
    let manifest = crate_root.join("Cargo.toml");
    let Ok(text) = std::fs::read_to_string(&manifest) else {
        return false;
    };
    let Ok(value) = text.parse::<toml::Value>() else {
        return false;
    };
    value
        .get("package")
        .and_then(|p| p.get("metadata"))
        .and_then(|m| m.get("cargo-fuzz"))
        .and_then(toml::Value::as_bool)
        .unwrap_or(false)
}

// ─── M3: #[cfg(test)] mod NAME; declarations ─────────────────────────────────

/// For each `#[cfg(test)] mod NAME;` item in `ast` (a module with no body),
/// resolve the target file and insert it into `set`.
fn collect_cfg_test_mods(ast: &syn::File, dir: &Path, set: &mut HashSet<PathBuf>) {
    for item in &ast.items {
        let syn::Item::Mod(item_mod) = item else {
            continue;
        };
        // We want modules with *no* body (i.e. declared as `mod NAME;`, not
        // `mod NAME { … }`).
        if item_mod.content.is_some() {
            continue;
        }
        if !attrs_have_cfg_test(&item_mod.attrs) {
            continue;
        }
        let name = item_mod.ident.to_string();
        // Resolve to `NAME.rs` or `NAME/mod.rs`, whichever exists.
        let candidate_file = dir.join(format!("{name}.rs"));
        let candidate_mod = dir.join(&name).join("mod.rs");
        if candidate_file.is_file() {
            set.insert(candidate_file);
            // Also add everything under `NAME/` (if that directory exists).
            insert_dir_contents(dir.join(&name), set);
        }
        if candidate_mod.is_file() {
            set.insert(candidate_mod);
            insert_dir_contents(dir.join(&name), set);
        }
    }
}

/// Recursively inserts all `.rs` files under `dir` into `set`.
fn insert_dir_contents(dir: PathBuf, set: &mut HashSet<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            insert_dir_contents(path, set);
        } else if path.extension().is_some_and(|e| e == "rs") {
            set.insert(path);
        }
    }
}

// ─── M4: inline #[cfg(test)] mod blocks ─────────────────────────────────────

struct InlineTestVisitor {
    ranges: Vec<(usize, usize)>,
}

impl<'ast> Visit<'ast> for InlineTestVisitor {
    fn visit_item_mod(&mut self, node: &'ast syn::ItemMod) {
        if let Some((brace, _)) = &node.content {
            if attrs_have_cfg_test(&node.attrs) {
                // `brace` gives us the open/close brace spans. The outer mod
                // declaration keyword `mod` is in the span of the ident.
                let start = node.mod_token.span.start().line;
                let end = brace.span.close().start().line;
                self.ranges.push((start, end));
            }
        }
        // Recurse into nested modules (both inline and declared).
        syn::visit::visit_item_mod(self, node);
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn tmp_dir(suffix: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("vaultlint_scope_{suffix}"));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    // ── cfg(test) recogniser ─────────────────────────────────────────────────

    fn parse_attr(tokens: &str) -> syn::Attribute {
        let item: syn::ItemStruct =
            syn::parse_str(&format!("{tokens}\nstruct S;")).expect("must parse");
        item.attrs.into_iter().next().expect("must have attribute")
    }

    /// `#[cfg(test)]` — must accept.
    #[test]
    fn cfg_test_recogniser_accepts_cfg_test() {
        let attr = parse_attr("#[cfg(test)]");
        assert!(is_cfg_test_attr(&attr));
    }

    /// `#[cfg(all(test, feature = "foo"))]` — must accept.
    #[test]
    fn cfg_test_recogniser_accepts_cfg_all_test() {
        let attr = parse_attr(r#"#[cfg(all(test, feature = "foo"))]"#);
        assert!(is_cfg_test_attr(&attr));
    }

    /// `#[cfg(feature = "test")]` — must reject (it's a feature flag).
    #[test]
    fn cfg_test_recogniser_rejects_cfg_feature_test() {
        let attr = parse_attr(r#"#[cfg(feature = "test")]"#);
        assert!(!is_cfg_test_attr(&attr));
    }

    /// `#[cfg(not(test))]` — must reject (negation).
    #[test]
    fn cfg_test_recogniser_rejects_cfg_not_test() {
        let attr = parse_attr("#[cfg(not(test))]");
        assert!(!is_cfg_test_attr(&attr));
    }

    // ── M1: integration-test / bench files ──────────────────────────────────

    /// A file whose path relative to its crate root starts with `tests` is
    /// test scope.  A file starting with `src` is not.
    ///
    /// Killing mutation: change the first-component check to accept any name.
    #[test]
    fn m1_fires_for_tests_dir() {
        let dir = tmp_dir("m1_fires");
        fs::create_dir_all(dir.join("src")).unwrap();
        fs::create_dir_all(dir.join("tests")).unwrap();
        fs::write(dir.join("Cargo.toml"), "[package]\nname = \"x\"\n").unwrap();
        fs::write(dir.join("src/lib.rs"), "").unwrap();
        fs::write(dir.join("tests/it.rs"), "").unwrap();

        let m3 = HashSet::new();
        assert!(
            is_test_scope(&dir.join("tests/it.rs"), &m3),
            "tests/it.rs must be test scope"
        );
        assert!(
            !is_test_scope(&dir.join("src/lib.rs"), &m3),
            "src/lib.rs must NOT be test scope"
        );
    }

    /// The anchor-check shape: the crate root for the nested program is its own
    /// Cargo.toml, so its `src/lib.rs` is NOT test scope even though the whole
    /// tree lives under a top-level `tests/` directory.
    ///
    /// Killing mutation: resolve the crate root from the scan root instead of
    /// from the nearest ancestor manifest — that would see `tests/` as the first
    /// component.
    #[test]
    fn m1_does_not_reach_into_nested_crate() {
        let dir = tmp_dir("m1_nested");
        let prog = dir.join("tests/example/programs/p");
        fs::create_dir_all(prog.join("src")).unwrap();
        fs::write(dir.join("Cargo.toml"), "[package]\nname = \"workspace\"\n").unwrap();
        fs::write(prog.join("Cargo.toml"), "[package]\nname = \"p\"\n").unwrap();
        fs::write(prog.join("src/lib.rs"), "").unwrap();

        let m3 = HashSet::new();
        assert!(
            !is_test_scope(&prog.join("src/lib.rs"), &m3),
            "nested src/lib.rs must NOT be test scope (its crate root is the program manifest)"
        );
    }

    // ── M2: cargo-fuzz crates ────────────────────────────────────────────────

    /// A crate whose Cargo.toml has `[package.metadata] cargo-fuzz = true` is
    /// fuzz scope.
    ///
    /// Killing mutation: remove the `cargo-fuzz` key check (always return false).
    #[test]
    fn m2_fires_for_cargo_fuzz_crate() {
        let dir = tmp_dir("m2_fires");
        fs::create_dir_all(dir.join("src")).unwrap();
        fs::write(
            dir.join("Cargo.toml"),
            "[package]\nname = \"fuzz\"\n\n[package.metadata]\ncargo-fuzz = true\n",
        )
        .unwrap();
        fs::write(dir.join("src/x.rs"), "").unwrap();

        let m3 = HashSet::new();
        assert!(
            is_test_scope(&dir.join("src/x.rs"), &m3),
            "fuzz crate file must be test scope"
        );
    }

    /// Without the `cargo-fuzz` key the crate is not fuzz scope.
    ///
    /// Killing mutation: make is_m2 always return true.
    #[test]
    fn m2_does_not_fire_without_cargo_fuzz_key() {
        let dir = tmp_dir("m2_no_key");
        fs::create_dir_all(dir.join("src")).unwrap();
        fs::write(dir.join("Cargo.toml"), "[package]\nname = \"notfuzz\"\n").unwrap();
        fs::write(dir.join("src/x.rs"), "").unwrap();

        let m3 = HashSet::new();
        assert!(
            !is_test_scope(&dir.join("src/x.rs"), &m3),
            "non-fuzz crate file must NOT be test scope"
        );
    }

    // ── M3: #[cfg(test)] mod NAME; declarations ──────────────────────────────

    /// A file declared as `#[cfg(test)] mod tests;` is test scope.
    ///
    /// Killing mutation: remove the `attrs_have_cfg_test` check in
    /// `collect_cfg_test_mods` so every `mod NAME;` is added to the set.
    /// (That mutation makes the negative test below pass as test scope, which is
    /// wrong — but it does NOT kill this test. The brief asks for the mutation
    /// that kills THIS test: remove the cfg-test check so the set is never
    /// populated — wait, that also wouldn't kill it if we remove the guard
    /// entirely… The actual killing mutation is: change `attrs_have_cfg_test` to
    /// always return false, so the set is never populated.)
    #[test]
    fn m3_fires_for_cfg_test_mod_declaration() {
        let dir = tmp_dir("m3_fires");
        fs::create_dir_all(dir.join("src")).unwrap();
        fs::write(dir.join("src/lib.rs"), "#[cfg(test)]\nmod tests;\n").unwrap();
        fs::write(dir.join("src/tests.rs"), "").unwrap();

        let files = vec![dir.join("src/lib.rs"), dir.join("src/tests.rs")];
        let m3 = collect_m3_set(&files);

        assert!(
            m3.contains(&dir.join("src/tests.rs")),
            "src/tests.rs must be in the M3 set"
        );
    }

    /// A plain `mod tests;` without `#[cfg(test)]` must NOT put the file in
    /// test scope.
    ///
    /// Killing mutation: remove the `attrs_have_cfg_test` guard in
    /// `collect_cfg_test_mods`, admitting every `mod NAME;` regardless of
    /// attribute.
    #[test]
    fn m3_does_not_fire_without_cfg_test_attribute() {
        let dir = tmp_dir("m3_no_attr");
        fs::create_dir_all(dir.join("src")).unwrap();
        fs::write(dir.join("src/lib.rs"), "mod tests;\n").unwrap();
        fs::write(dir.join("src/tests.rs"), "").unwrap();

        let files = vec![dir.join("src/lib.rs"), dir.join("src/tests.rs")];
        let m3 = collect_m3_set(&files);

        assert!(
            !m3.contains(&dir.join("src/tests.rs")),
            "src/tests.rs must NOT be in the M3 set (no cfg(test) attribute)"
        );
    }

    // ── M4: inline #[cfg(test)] mod blocks ──────────────────────────────────

    /// A finding inside `#[cfg(test)] mod tests { … }` is dropped.
    /// A finding outside the block at a higher line number survives.
    ///
    /// Killing mutation: remove the `attrs_have_cfg_test` check in
    /// `InlineTestVisitor::visit_item_mod`, making every inline mod a test range.
    #[test]
    fn m4_drops_finding_inside_cfg_test_block_and_keeps_finding_outside() {
        // Line 2: the `mod` keyword (start of range)
        // Line 4: `}` (end of range)
        // Line 6: outside the block
        let source = "\
fn outside() {}
#[cfg(test)]
mod tests {
    fn inside() {}
}
fn also_outside() {}
";
        let ast = syn::parse_file(source).unwrap();
        let ranges = test_ranges(&ast);
        assert!(!ranges.is_empty(), "must detect the inline test block");

        // Line 4 (`fn inside() {}`) is inside the block.
        assert!(
            in_test_range(4, &ranges),
            "line 4 must be inside the test block"
        );
        // Line 6 (`fn also_outside() {}`) is outside.
        assert!(
            !in_test_range(6, &ranges),
            "line 6 must NOT be inside the test block"
        );
        // Line 1 is also outside.
        assert!(
            !in_test_range(1, &ranges),
            "line 1 must NOT be inside the test block"
        );
    }

    /// Companion: a non-cfg-test inline mod must NOT produce a test range.
    ///
    /// Killing mutation: remove the `attrs_have_cfg_test` guard in
    /// `InlineTestVisitor`, so all inline mods become test ranges.
    #[test]
    fn m4_does_not_range_a_non_cfg_test_mod() {
        let source = "\
mod helpers {
    fn assist() {}
}
fn outside() {}
";
        let ast = syn::parse_file(source).unwrap();
        let ranges = test_ranges(&ast);
        assert!(
            ranges.is_empty(),
            "a non-cfg-test mod must not produce a test range"
        );
    }
}
