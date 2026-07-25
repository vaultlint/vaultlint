use std::path::{Path, PathBuf};

use walkdir::{DirEntry, WalkDir};

/// Collects every `.rs` file under `root`, in a stable order.
pub fn rust_files(root: &Path) -> Vec<PathBuf> {
    WalkDir::new(root)
        .sort_by_file_name()
        .into_iter()
        .filter_entry(|entry| !is_ignored(entry))
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_file())
        .map(DirEntry::into_path)
        .filter(|path| path.extension().is_some_and(|ext| ext == "rs"))
        .collect()
}

fn is_ignored(entry: &DirEntry) -> bool {
    if entry.depth() == 0 {
        return false;
    }
    let name = entry.file_name().to_string_lossy();
    name == "target" || name.starts_with('.')
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn collects_rust_files_and_skips_target_and_hidden() {
        let dir = std::env::temp_dir().join("vaultlint_scan_test");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("src")).unwrap();
        fs::create_dir_all(dir.join("target/debug")).unwrap();
        fs::create_dir_all(dir.join(".git")).unwrap();
        fs::write(dir.join("src/lib.rs"), "fn main() {}").unwrap();
        fs::write(dir.join("src/notes.md"), "hello").unwrap();
        fs::write(dir.join("target/debug/build.rs"), "fn main() {}").unwrap();
        fs::write(dir.join(".git/hook.rs"), "fn main() {}").unwrap();

        let found = rust_files(&dir);

        assert_eq!(found.len(), 1, "found: {found:?}");
        assert!(found[0].ends_with("src/lib.rs"));
    }
}
