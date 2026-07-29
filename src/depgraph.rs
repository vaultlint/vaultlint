//! Which crates are compiled into a given crate.
//!
//! A program's own manifest names the id it deploys under, but the code that
//! runs at that address is the whole path-dependency closure below it. A shared
//! library with no `declare_id!` of its own still executes on chain, and asking
//! "does this crate declare a live id" would never see it.
//!
//! Only what ships is followed. `dev-dependencies` exist for tests and
//! `build-dependencies` run on the build host, so neither reaches the cluster.

use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::rc::Rc;

use crate::project::{self, WorkspaceResolver};

pub(crate) struct DepGraph<'a> {
    resolver: &'a WorkspaceResolver,
    parsed: HashMap<PathBuf, Option<Rc<toml::Value>>>,
}

impl<'a> DepGraph<'a> {
    pub(crate) fn new(resolver: &'a WorkspaceResolver) -> Self {
        DepGraph {
            resolver,
            parsed: HashMap::new(),
        }
    }

    /// Every package manifest whose code is compiled into the crate at
    /// `manifest`, including `manifest` itself.
    ///
    /// Paths are normalised, so the result can be compared against
    /// [`project::package_manifest`] directly. A dependency cycle terminates:
    /// a manifest already in the set is never expanded twice.
    pub(crate) fn closure(&mut self, manifest: &Path) -> BTreeSet<PathBuf> {
        let mut reached = BTreeSet::new();
        let mut pending = vec![project::normalised(manifest)];
        while let Some(current) = pending.pop() {
            if !reached.insert(current.clone()) {
                continue;
            }
            pending.extend(self.path_dependencies(&current));
        }
        reached
    }

    /// The manifests of the local crates `manifest` depends on directly.
    ///
    /// An `optional = true` dependency is skipped: whether it is compiled in
    /// depends on which features the build enables, which a manifest alone does
    /// not say. Missing a live crate is the safer error here — the mark exists
    /// to say a defect is definitely running, so guessing would ruin it.
    fn path_dependencies(&mut self, manifest: &Path) -> Vec<PathBuf> {
        let Some(value) = self.parse(manifest) else {
            return Vec::new();
        };
        let Some(dir) = manifest.parent() else {
            return Vec::new();
        };

        let mut tables: Vec<&toml::Value> = Vec::new();
        if let Some(direct) = value.get("dependencies") {
            tables.push(direct);
        }
        // `[target.'cfg(...)'.dependencies]` ships exactly like a plain one on
        // the platforms it matches, and Solana crates use it for the BPF target.
        if let Some(targets) = value.get("target").and_then(toml::Value::as_table) {
            tables.extend(targets.values().filter_map(|t| t.get("dependencies")));
        }

        let mut out = Vec::new();
        for table in tables {
            let Some(table) = table.as_table() else {
                continue;
            };
            for (name, entry) in table {
                if entry.get("optional").and_then(toml::Value::as_bool) == Some(true) {
                    continue;
                }
                if let Some(path) = entry.get("path").and_then(toml::Value::as_str) {
                    out.push(manifest_in(dir, path));
                } else if entry.get("workspace").and_then(toml::Value::as_bool) == Some(true) {
                    out.extend(self.inherited(manifest, name));
                }
            }
        }
        out
    }

    /// Resolves `name = { workspace = true }` through the workspace root's
    /// `[workspace.dependencies]`, where the `path` is relative to that root.
    fn inherited(&mut self, manifest: &Path, name: &str) -> Option<PathBuf> {
        let root = self.resolver.resolve(manifest).manifest?;
        let root = project::normalised(&root);
        let root_dir = root.parent()?.to_path_buf();
        let value = self.parse(&root)?;
        let path = value
            .get("workspace")?
            .get("dependencies")?
            .get(name)?
            .get("path")?
            .as_str()?;
        Some(manifest_in(&root_dir, path))
    }

    fn parse(&mut self, manifest: &Path) -> Option<Rc<toml::Value>> {
        if let Some(cached) = self.parsed.get(manifest) {
            return cached.clone();
        }
        let parsed = std::fs::read_to_string(manifest)
            .ok()
            .and_then(|text| text.parse::<toml::Value>().ok())
            .map(Rc::new);
        self.parsed.insert(manifest.to_path_buf(), parsed.clone());
        parsed
    }
}

/// A Cargo `path` names the crate's *directory*; the graph is keyed on manifests.
fn manifest_in(base: &Path, path: &str) -> PathBuf {
    project::normalised(&base.join(path).join("Cargo.toml"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn workspace(dir: &Path) {
        let _ = fs::remove_dir_all(dir);
        fs::create_dir_all(dir).unwrap();
        fs::write(
            dir.join("Cargo.toml"),
            "[workspace]\nmembers = [\"program\", \"shared\", \"helper\", \"harness\"]\n\n\
             [workspace.dependencies.shared]\npath = \"shared\"\n",
        )
        .unwrap();
        for member in ["program", "shared", "helper", "harness"] {
            fs::create_dir_all(dir.join(member)).unwrap();
            fs::write(
                dir.join(member).join("Cargo.toml"),
                format!("[package]\nname = \"{member}\"\n"),
            )
            .unwrap();
        }
    }

    /// The two shapes a real Solana workspace uses to name a local crate — an
    /// inline `path` and an inherited `workspace = true` — must both be followed,
    /// and transitively: `spl-concurrent-merkle-tree` is reached through a
    /// library, not from the program manifest.
    ///
    /// Kill: follow only `path`, or stop after one hop.
    #[test]
    fn both_ways_of_naming_a_local_crate_are_followed_transitively() {
        let dir = std::env::temp_dir().join("vaultlint_depgraph_shapes");
        workspace(&dir);
        fs::write(
            dir.join("program/Cargo.toml"),
            "[package]\nname = \"program\"\n\n[dependencies]\n\
             shared = { workspace = true }\nanchor-lang = \"0.29\"\n",
        )
        .unwrap();
        fs::write(
            dir.join("shared/Cargo.toml"),
            "[package]\nname = \"shared\"\n\n[dependencies]\nhelper = { path = \"../helper\" }\n",
        )
        .unwrap();

        let resolver = WorkspaceResolver::new(&dir);
        let reached = DepGraph::new(&resolver).closure(&dir.join("program/Cargo.toml"));

        assert!(reached.contains(&project::normalised(&dir.join("program/Cargo.toml"))));
        assert!(reached.contains(&project::normalised(&dir.join("shared/Cargo.toml"))));
        assert!(
            reached.contains(&project::normalised(&dir.join("helper/Cargo.toml"))),
            "reached through shared, two hops out: {reached:?}"
        );
    }

    /// A test harness and a build script never reach the cluster, and an
    /// optional crate is compiled in only if a feature nobody can see from the
    /// manifest turns it on. Claiming any of them runs on mainnet would be a
    /// statement the scan cannot support.
    ///
    /// Kill: merge `dev-dependencies` into the followed tables, or drop the
    /// `optional` check.
    #[test]
    fn nothing_that_may_not_ship_is_reached() {
        let dir = std::env::temp_dir().join("vaultlint_depgraph_excluded");
        workspace(&dir);
        fs::write(
            dir.join("program/Cargo.toml"),
            "[package]\nname = \"program\"\n\n\
             [dependencies]\nhelper = { path = \"../helper\", optional = true }\n\n\
             [dev-dependencies]\nharness = { path = \"../harness\" }\n\n\
             [build-dependencies]\nshared = { path = \"../shared\" }\n",
        )
        .unwrap();

        let resolver = WorkspaceResolver::new(&dir);
        let reached = DepGraph::new(&resolver).closure(&dir.join("program/Cargo.toml"));

        assert_eq!(
            reached,
            BTreeSet::from([project::normalised(&dir.join("program/Cargo.toml"))]),
            "only the crate itself"
        );
    }

    /// Two crates depending on each other must not spin forever. Cargo rejects a
    /// cycle, but a manifest on disk can still spell one and the scan has to
    /// survive reading it.
    ///
    /// Kill: expand a manifest that is already in the set.
    #[test]
    fn a_dependency_cycle_terminates() {
        let dir = std::env::temp_dir().join("vaultlint_depgraph_cycle");
        workspace(&dir);
        fs::write(
            dir.join("program/Cargo.toml"),
            "[package]\nname = \"program\"\n\n[dependencies]\nshared = { path = \"../shared\" }\n",
        )
        .unwrap();
        fs::write(
            dir.join("shared/Cargo.toml"),
            "[package]\nname = \"shared\"\n\n[dependencies]\nprogram = { path = \"../program\" }\n",
        )
        .unwrap();

        let resolver = WorkspaceResolver::new(&dir);
        let reached = DepGraph::new(&resolver).closure(&dir.join("program/Cargo.toml"));

        assert_eq!(
            reached,
            BTreeSet::from([
                project::normalised(&dir.join("program/Cargo.toml")),
                project::normalised(&dir.join("shared/Cargo.toml")),
            ])
        );
    }
}
