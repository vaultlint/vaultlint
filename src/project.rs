use std::path::{Path, PathBuf};

pub struct ProjectInfo {
    pub overflow_checks: bool,
    pub anchor_version: Option<String>,
}

pub fn detect(root: &Path) -> ProjectInfo {
    let mut info = ProjectInfo {
        overflow_checks: false,
        anchor_version: None,
    };
    for manifest in manifests(root) {
        let Ok(text) = std::fs::read_to_string(&manifest) else {
            continue;
        };
        let Ok(value) = text.parse::<toml::Value>() else {
            continue;
        };
        if !info.overflow_checks {
            info.overflow_checks = value
                .get("profile")
                .and_then(|profile| profile.get("release"))
                .and_then(|release| release.get("overflow-checks"))
                .and_then(toml::Value::as_bool)
                .unwrap_or(false);
        }
        if info.anchor_version.is_none() {
            info.anchor_version = anchor_version(&value);
        }
    }
    info
}

/// Manifests in the scanned tree (Anchor programs) plus those above it
/// (workspace root, where `[profile.release]` normally lives).
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn reads_overflow_checks_and_anchor_version() {
        let dir = std::env::temp_dir().join("vaultlint_project_test/programs/staking");
        let _ = fs::remove_dir_all(std::env::temp_dir().join("vaultlint_project_test"));
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            std::env::temp_dir().join("vaultlint_project_test/Cargo.toml"),
            "[profile.release]\noverflow-checks = true\n",
        )
        .unwrap();
        fs::write(
            dir.join("Cargo.toml"),
            "[dependencies]\nanchor-lang = \"0.30.1\"\n",
        )
        .unwrap();

        let info = detect(&dir);

        assert!(info.overflow_checks, "workspace profile must be picked up");
        assert_eq!(info.anchor_version.as_deref(), Some("0.30.1"));
    }

    #[test]
    fn defaults_are_safe_when_no_manifest_exists() {
        let dir = std::env::temp_dir().join("vaultlint_project_empty");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let info = detect(&dir);

        assert!(!info.overflow_checks);
        assert_eq!(info.anchor_version, None);
    }
}
