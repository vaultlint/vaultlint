use std::io::Write;

use serde::Serialize;
use serde_json::json;

use crate::onchain::{Deployment, State};
use crate::{ScanReport, SkippedFile};

/// Wire-format for a skipped file in JSON output.
#[derive(Serialize)]
struct SkippedEntry<'a> {
    path: String,
    reason: &'a str,
}

pub fn render(report: &ScanReport, out: &mut dyn Write) -> std::io::Result<()> {
    let skipped: Vec<SkippedEntry<'_>> = report
        .skipped
        .iter()
        .map(|s: &SkippedFile| SkippedEntry {
            path: s.path.to_string_lossy().into_owned(),
            reason: &s.reason,
        })
        .collect();
    let mut document = json!({
        "findings": &report.findings,
        "skipped": skipped,
    });
    // Absent rather than empty when no cluster was asked: an empty array would
    // read as "nothing is deployed", which is a claim the scan did not make.
    if !report.deployments.is_empty() {
        let programs: Vec<serde_json::Value> =
            report.deployments.iter().map(program_entry).collect();
        document["programs"] = json!(programs);
    }
    serde_json::to_writer_pretty(&mut *out, &document).map_err(std::io::Error::from)?;
    writeln!(out)?;
    Ok(())
}

/// One declared program id and what the cluster said about it.
///
/// Flattened rather than serialised from [`State`] directly, so the wire format
/// is a decision made here instead of a side effect of an internal enum.
fn program_entry(deployment: &Deployment) -> serde_json::Value {
    let mut entry = json!({
        "address": deployment.declared.address,
        "file": deployment.declared.file.to_string_lossy(),
        "line": deployment.declared.line,
    });
    match &deployment.state {
        State::Absent => entry["state"] = json!("absent"),
        State::NotAProgram { owner } => {
            entry["state"] = json!("not_a_program");
            entry["owner"] = json!(owner);
        }
        State::Immutable => entry["state"] = json!("immutable"),
        State::Frozen { last_deploy_slot } => {
            entry["state"] = json!("frozen");
            entry["last_deploy_slot"] = json!(last_deploy_slot);
        }
        State::Upgradeable {
            authority,
            last_deploy_slot,
        } => {
            entry["state"] = json!("upgradeable");
            entry["authority"] = json!(authority);
            entry["last_deploy_slot"] = json!(last_deploy_slot);
        }
        State::Unavailable { reason } => {
            entry["state"] = json!("unavailable");
            entry["reason"] = json!(reason);
        }
    }
    entry
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::programid::DeclaredId;

    fn declared() -> DeclaredId {
        DeclaredId {
            address: "M2mx93ekt1fmXSVkTrUL9xVFHkmME8HTUi5Cyc5aF7K".to_string(),
            file: std::path::PathBuf::from("programs/m2/src/lib.rs"),
            line: 14,
            column: 13,
        }
    }

    /// The state discriminant and the fields that belong to it. A consumer
    /// switching on `state` must not have to guess whether `authority` is
    /// meaningful.
    ///
    /// Kill: emit `authority` for a state that has none, or drop `state`.
    #[test]
    fn each_state_carries_only_its_own_fields() {
        let upgradeable = program_entry(&Deployment {
            declared: declared(),
            state: State::Upgradeable {
                authority: "AUTH".to_string(),
                last_deploy_slot: 9,
            },
        });
        assert_eq!(upgradeable["state"], "upgradeable");
        assert_eq!(upgradeable["authority"], "AUTH");
        assert_eq!(upgradeable["last_deploy_slot"], 9);
        assert_eq!(upgradeable["line"], 14);

        let absent = program_entry(&Deployment {
            declared: declared(),
            state: State::Absent,
        });
        assert_eq!(absent["state"], "absent");
        assert!(absent.get("authority").is_none());
        assert!(absent.get("last_deploy_slot").is_none());
    }
}
