use std::cell::RefCell;
use std::collections::HashMap;
use std::path::{Component, Path, PathBuf};
use std::rc::Rc;

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
    dir_cache: RefCell<HashMap<PathBuf, Workspace>>,
    toml_cache: RefCell<HashMap<PathBuf, Option<Rc<toml::Value>>>>,
    /// Whether the scan root the caller handed was relative; controls manifest
    /// path spelling in the returned `Workspace.manifest`.
    report_relative: bool,
}

impl WorkspaceResolver {
    pub fn new(root: &Path) -> Self {
        Self {
            dir_cache: RefCell::new(HashMap::new()),
            toml_cache: RefCell::new(HashMap::new()),
            report_relative: root.is_relative(),
        }
    }

    pub fn resolve(&self, file: &Path) -> Workspace {
        let abs_file = normalised(file);
        let abs_dir = abs_file.parent().unwrap_or(&abs_file).to_path_buf();
        if let Some(cached) = self.dir_cache.borrow().get(&abs_dir) {
            return cached.clone();
        }
        let result = self.resolve_uncached(&abs_dir, file);
        self.dir_cache.borrow_mut().insert(abs_dir, result.clone());
        result
    }

    fn resolve_uncached(&self, abs_dir: &Path, original_file: &Path) -> Workspace {
        let Some(package_manifest) = walk_to_cargo_toml(abs_dir) else {
            return Workspace {
                manifest: None,
                overflow_checks: false,
            };
        };
        let root_manifest = self.find_workspace_root(&package_manifest);
        let overflow_checks = self.read_overflow_checks(&root_manifest);
        let reported_manifest = self.reporting_path(&root_manifest, original_file);
        Workspace {
            manifest: Some(reported_manifest),
            overflow_checks,
        }
    }

    /// Converts an absolute resolved manifest to the path that will appear in
    /// findings. When the scan root was relative and the manifest lies under the
    /// process CWD, strip the CWD prefix so the reported path is relative too.
    fn reporting_path(&self, abs_manifest: &Path, original_file: &Path) -> PathBuf {
        if !self.report_relative {
            return abs_manifest.to_path_buf();
        }
        // Keep the same relative/absolute character as the original file the
        // caller handed.  Strip the CWD when the manifest lies inside it;
        // otherwise fall back to the absolute path so the user can still find it.
        if let Ok(cwd) = std::env::current_dir() {
            if let Ok(rel) = abs_manifest.strip_prefix(&cwd) {
                return rel.to_path_buf();
            }
        }
        // Manifest is outside the CWD; use original_file's root as a hint only
        // if it gives a better relative rendering, otherwise keep absolute.
        let _ = original_file;
        abs_manifest.to_path_buf()
    }

    /// Given the package manifest, locate the workspace root manifest.
    fn find_workspace_root(&self, package_manifest: &Path) -> PathBuf {
        // package_manifest is already absolute and normalised by the time we
        // arrive here, so parent() always succeeds.
        let package_dir = package_manifest
            .parent()
            .unwrap_or(Path::new(""))
            .to_path_buf();

        if let Some(value) = self.read_toml(package_manifest) {
            if let Some(ws_rel) = value
                .get("package")
                .and_then(|p| p.get("workspace"))
                .and_then(toml::Value::as_str)
            {
                let candidate = normalised(&package_dir.join(ws_rel).join("Cargo.toml"));
                if candidate.is_file() {
                    return candidate;
                }
            }
        }

        // Walk up from the package directory's parent looking for a manifest
        // with a `[workspace]` table.
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
                        if is_excluded(&value, &ancestor_dir, &package_dir) {
                            return package_manifest.to_path_buf();
                        }
                        return ancestor_manifest;
                    }
                }
            }
            current = ancestor_dir.parent().map(Path::to_path_buf);
        }

        package_manifest.to_path_buf()
    }

    fn read_toml(&self, manifest: &Path) -> Option<Rc<toml::Value>> {
        if let Some(cached) = self.toml_cache.borrow().get(manifest) {
            return cached.clone();
        }
        let result = std::fs::read_to_string(manifest)
            .ok()
            .and_then(|text| text.parse::<toml::Value>().ok())
            .map(Rc::new);
        self.toml_cache
            .borrow_mut()
            .insert(manifest.to_path_buf(), result.clone());
        result
    }

    fn read_overflow_checks(&self, manifest: &Path) -> bool {
        self.read_toml(manifest)
            .as_deref()
            .and_then(|v| v.get("profile"))
            .and_then(|p| p.get("release"))
            .and_then(|r| r.get("overflow-checks"))
            .and_then(toml::Value::as_bool)
            .unwrap_or(false)
    }
}

impl Default for WorkspaceResolver {
    fn default() -> Self {
        Self::new(Path::new("."))
    }
}

/// Absolute and lexically normalised: `..` popped without touching the filesystem.
///
/// Two spellings of one manifest have to be one key, and a relative scan root has to be
/// able to see a workspace root above the process working directory. `canonicalize` would
/// do both but also resolves symlinks and fails on paths that do not exist.
fn normalised(path: &Path) -> PathBuf {
    let abs = std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf());
    let mut out = PathBuf::new();
    for component in abs.components() {
        match component {
            Component::Prefix(_) | Component::RootDir => out.push(component),
            Component::CurDir => {}
            Component::Normal(part) => out.push(part),
            Component::ParentDir => {
                // Pop the last Normal component; never pop past the root.
                let last_is_normal = out
                    .components()
                    .next_back()
                    .map(|c| matches!(c, Component::Normal(_)))
                    .unwrap_or(false);
                if last_is_normal {
                    out.pop();
                }
            }
        }
    }
    out
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

        let resolver = WorkspaceResolver::new(&dir);
        let ws = resolver.resolve(&dir.join("member/src/lib.rs"));

        assert!(!ws.overflow_checks, "root has no profile, must be false");
        assert_eq!(ws.manifest, Some(dir.join("Cargo.toml")));
    }

    /// A standalone package (no `[workspace]`) is its own workspace root.
    ///
    /// Kill: make `read_overflow_checks` return `false` unconditionally.
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

        let resolver = WorkspaceResolver::new(&dir);
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

        let resolver = WorkspaceResolver::new(&dir);
        let ws = resolver.resolve(&dir.join("ext/src/lib.rs"));

        assert!(ws.overflow_checks, "ext has overflow-checks, must be true");
        assert_eq!(ws.manifest, Some(dir.join("ext/Cargo.toml")));
    }

    /// One root reached two ways — via ancestor walk from one member, and via a
    /// `package.workspace = "../.."` pointer from another — must map to the same
    /// `Workspace.manifest`.
    ///
    /// Kill: remove the `..`-popping from `normalised`.
    #[test]
    fn two_paths_to_same_root_yield_same_manifest() {
        let dir = std::env::temp_dir().join("vaultlint_ws_two_paths");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("a/src")).unwrap();
        fs::create_dir_all(dir.join("sub/b/src")).unwrap();
        fs::write(
            dir.join("Cargo.toml"),
            "[workspace]\nmembers = [\"a\", \"sub/b\"]\n",
        )
        .unwrap();
        fs::write(dir.join("a/Cargo.toml"), "[package]\nname = \"a\"\n").unwrap();
        fs::write(dir.join("a/src/lib.rs"), "").unwrap();
        fs::write(
            dir.join("sub/b/Cargo.toml"),
            "[package]\nname = \"b\"\nworkspace = \"../..\"\n",
        )
        .unwrap();
        fs::write(dir.join("sub/b/src/lib.rs"), "").unwrap();

        let resolver = WorkspaceResolver::new(&dir);
        let ws_a = resolver.resolve(&dir.join("a/src/lib.rs"));
        let ws_b = resolver.resolve(&dir.join("sub/b/src/lib.rs"));

        assert_eq!(
            ws_a.manifest, ws_b.manifest,
            "both members must resolve to the same workspace root manifest"
        );
        assert_eq!(ws_a.manifest, Some(dir.join("Cargo.toml")));
    }
}
