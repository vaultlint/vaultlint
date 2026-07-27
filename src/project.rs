use std::cell::RefCell;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

pub struct ProjectInfo {
    pub anchor_version: Option<String>,
}

pub fn detect(root: &Path) -> ProjectInfo {
    let mut info = ProjectInfo {
        anchor_version: None,
    };
    for manifest in manifests(root) {
        let Ok(text) = std::fs::read_to_string(&manifest) else {
            continue;
        };
        let Ok(value) = text.parse::<toml::Value>() else {
            continue;
        };
        if info.anchor_version.is_none() {
            info.anchor_version = anchor_version(&value);
        }
    }
    info
}

/// Manifests in the scanned tree (Anchor programs) plus those above it.
fn manifests(root: &Path) -> Vec<PathBuf> {
    let mut found: Vec<PathBuf> = walkdir::WalkDir::new(root)
        .max_depth(4)
        .sort_by_file_name()
        .into_iter()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_name() == "Cargo.toml")
        .map(walkdir::DirEntry::into_path)
        .collect();
    for ancestor in root.ancestors().skip(1).take(4) {
        let manifest = ancestor.join("Cargo.toml");
        if manifest.is_file() {
            found.push(manifest);
        }
    }
    found
}

fn anchor_version(value: &toml::Value) -> Option<String> {
    let dependency = value.get("dependencies")?.get("anchor-lang")?;
    match dependency {
        toml::Value::String(version) => Some(version.clone()),
        toml::Value::Table(table) => table
            .get("version")
            .and_then(toml::Value::as_str)
            .map(ToString::to_string),
        _ => None,
    }
}

/// The workspace root manifest Cargo reads `[profile.release]` from, and
/// whether it enables `overflow-checks`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Workspace {
    /// The manifest Cargo would read `[profile.release]` from, or `None` when no
    /// `Cargo.toml` exists above the file.
    pub manifest: Option<PathBuf>,
    pub overflow_checks: bool,
}

pub struct WorkspaceResolver {
    /// Cache: directory → resolved Workspace.
    dir_cache: RefCell<HashMap<PathBuf, Workspace>>,
    /// Cache: manifest path → parsed TOML.
    toml_cache: RefCell<HashMap<PathBuf, toml::Value>>,
}

impl Default for WorkspaceResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl WorkspaceResolver {
    pub fn new() -> Self {
        Self {
            dir_cache: RefCell::new(HashMap::new()),
            toml_cache: RefCell::new(HashMap::new()),
        }
    }

    pub fn resolve(&self, file: &Path) -> Workspace {
        let dir = file.parent().unwrap_or(file);
        if let Some(cached) = self.dir_cache.borrow().get(dir) {
            return cached.clone();
        }
        let result = self.resolve_uncached(dir);
        self.dir_cache
            .borrow_mut()
            .insert(dir.to_path_buf(), result.clone());
        result
    }

    fn resolve_uncached(&self, dir: &Path) -> Workspace {
        // Walk up from `dir` to find the nearest ancestor with a Cargo.toml.
        let Some(package_manifest) = walk_to_cargo_toml(dir) else {
            return Workspace {
                manifest: None,
                overflow_checks: false,
            };
        };
        let root_manifest = self.find_workspace_root(&package_manifest);
        let overflow_checks = self.read_overflow_checks(&root_manifest);
        Workspace {
            manifest: Some(root_manifest),
            overflow_checks,
        }
    }

    /// Given the package manifest, locate the workspace root manifest.
    fn find_workspace_root(&self, package_manifest: &Path) -> PathBuf {
        let package_dir = package_manifest
            .parent()
            .unwrap_or(Path::new("."))
            .to_path_buf();

        // Step 3: check `package.workspace` key for an explicit pointer.
        if let Some(value) = self.read_toml(package_manifest) {
            if let Some(ws_rel) = value
                .get("package")
                .and_then(|p| p.get("workspace"))
                .and_then(toml::Value::as_str)
            {
                let candidate = package_dir.join(ws_rel).join("Cargo.toml");
                if candidate.is_file() {
                    return candidate;
                }
            }
        }

        // Step 4: walk up from the package directory's parent looking for a
        // manifest with a `[workspace]` table.
        //
        // Deliberate approximation: `workspace.members` globs are not matched.
        // A manifest that declares `[workspace]` without listing a package below
        // it makes Cargo refuse to build, so on any project that compiles,
        // "nearest `[workspace]` ancestor, minus `exclude`" is correct.
        let mut current = package_dir.parent().map(Path::to_path_buf);
        while let Some(ancestor_dir) = current {
            let ancestor_manifest = ancestor_dir.join("Cargo.toml");
            if ancestor_manifest.is_file() {
                if let Some(value) = self.read_toml(&ancestor_manifest) {
                    if value.get("workspace").is_some() {
                        // Check if `workspace.exclude` lists the package dir.
                        if is_excluded(&value, &ancestor_dir, &package_dir) {
                            // This package is excluded; it is its own root.
                            return package_manifest.to_path_buf();
                        }
                        return ancestor_manifest;
                    }
                }
            }
            current = ancestor_dir.parent().map(Path::to_path_buf);
        }

        // No ancestor has `[workspace]`: standalone package is its own root.
        package_manifest.to_path_buf()
    }

    fn read_toml(&self, manifest: &Path) -> Option<toml::Value> {
        if let Some(cached) = self.toml_cache.borrow().get(manifest) {
            return Some(cached.clone());
        }
        let text = std::fs::read_to_string(manifest).ok()?;
        let value = text.parse::<toml::Value>().ok()?;
        self.toml_cache
            .borrow_mut()
            .insert(manifest.to_path_buf(), value.clone());
        Some(value)
    }

    fn read_overflow_checks(&self, manifest: &Path) -> bool {
        self.read_toml(manifest)
            .as_ref()
            .and_then(|v| v.get("profile"))
            .and_then(|p| p.get("release"))
            .and_then(|r| r.get("overflow-checks"))
            .and_then(toml::Value::as_bool)
            .unwrap_or(false)
    }
}

/// True if the `workspace.exclude` list in `value` covers `package_dir`,
/// where entries are relative to `workspace_dir`.
fn is_excluded(value: &toml::Value, workspace_dir: &Path, package_dir: &Path) -> bool {
    let Some(excludes) = value
        .get("workspace")
        .and_then(|ws| ws.get("exclude"))
        .and_then(toml::Value::as_array)
    else {
        return false;
    };
    for entry in excludes {
        let Some(rel) = entry.as_str() else {
            continue;
        };
        let excluded_path = workspace_dir.join(rel);
        // The package is excluded if its directory starts with an excluded path.
        if package_dir.starts_with(&excluded_path) {
            return true;
        }
    }
    false
}

/// Walks up from `dir` (inclusive) and returns the first `Cargo.toml` found,
/// or `None` if none exists.
fn walk_to_cargo_toml(dir: &Path) -> Option<PathBuf> {
    let mut current = Some(dir);
    while let Some(d) = current {
        let manifest = d.join("Cargo.toml");
        if manifest.is_file() {
            return Some(manifest);
        }
        current = d.parent();
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// Detect still reads anchor-version for project-level reporting.
    #[test]
    fn detect_reads_anchor_version() {
        let dir = std::env::temp_dir().join("vaultlint_project_detect_anchor");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("Cargo.toml"),
            "[dependencies]\nanchor-lang = \"0.30.1\"\n",
        )
        .unwrap();

        let info = detect(&dir);

        assert_eq!(info.anchor_version.as_deref(), Some("0.30.1"));
    }

    /// A member's `[profile.release]` must be ignored; the workspace root decides.
    ///
    /// Kill: return the nearest manifest instead of the workspace root.
    #[test]
    fn a_member_profile_is_ignored_the_workspace_root_decides() {
        let dir = std::env::temp_dir().join("vaultlint_ws_member_profile");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("member/src")).unwrap();
        fs::write(
            dir.join("Cargo.toml"),
            "[workspace]\nmembers = [\"member\"]\n",
        )
        .unwrap();
        fs::write(
            dir.join("member/Cargo.toml"),
            "[package]\nname = \"member\"\n\n[profile.release]\noverflow-checks = true\n",
        )
        .unwrap();
        fs::write(dir.join("member/src/lib.rs"), "").unwrap();

        let resolver = WorkspaceResolver::new();
        let ws = resolver.resolve(&dir.join("member/src/lib.rs"));

        assert!(!ws.overflow_checks, "root has no profile, must be false");
        assert_eq!(ws.manifest, Some(dir.join("Cargo.toml")));
    }

    /// A standalone package (no `[workspace]`) is its own workspace root.
    ///
    /// Kill: make the resolver always walk up past any manifest.
    #[test]
    fn a_standalone_package_is_its_own_workspace_root() {
        let dir = std::env::temp_dir().join("vaultlint_ws_standalone");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("src")).unwrap();
        fs::write(
            dir.join("Cargo.toml"),
            "[package]\nname = \"standalone\"\n\n[profile.release]\noverflow-checks = true\n",
        )
        .unwrap();
        fs::write(dir.join("src/lib.rs"), "").unwrap();

        let resolver = WorkspaceResolver::new();
        let ws = resolver.resolve(&dir.join("src/lib.rs"));

        assert!(ws.overflow_checks);
        assert_eq!(ws.manifest, Some(dir.join("Cargo.toml")));
    }

    /// A package listed in `workspace.exclude` is treated as its own root.
    ///
    /// Kill: delete the `exclude` handling.
    #[test]
    fn an_excluded_package_is_its_own_root() {
        let dir = std::env::temp_dir().join("vaultlint_ws_excluded");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("ext/src")).unwrap();
        fs::write(dir.join("Cargo.toml"), "[workspace]\nexclude = [\"ext\"]\n").unwrap();
        fs::write(
            dir.join("ext/Cargo.toml"),
            "[package]\nname = \"ext\"\n\n[profile.release]\noverflow-checks = true\n",
        )
        .unwrap();
        fs::write(dir.join("ext/src/lib.rs"), "").unwrap();

        let resolver = WorkspaceResolver::new();
        let ws = resolver.resolve(&dir.join("ext/src/lib.rs"));

        assert!(ws.overflow_checks, "ext has overflow-checks, must be true");
        assert_eq!(ws.manifest, Some(dir.join("ext/Cargo.toml")));
    }
}
