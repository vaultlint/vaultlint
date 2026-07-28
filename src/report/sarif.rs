use std::collections::BTreeMap;
use std::io::Write;
use std::path::Path;

use serde_json::{json, Value};

use crate::finding::{Finding, Severity};
use crate::project::normalised;
use crate::ScanReport;

pub fn render(report: &ScanReport, out: &mut dyn Write) -> std::io::Result<()> {
    let scan_root = report.scan_root.as_deref();
    let mut run = json!({
        "tool": {
            "driver": {
                "name": "vaultlint",
                "informationUri": "https://vaultlint.com",
                "version": crate::version(),
                "rules": rules(report),
            }
        },
        "invocations": [invocation(report)],
        "results": report.findings.iter().map(|f| result(f, scan_root)).collect::<Vec<_>>(),
    });
    // Omit `originalUriBaseIds` entirely when there is no scan root (unit
    // tests, legacy callers).  An empty object is legal per SARIF 2.1.0
    // §3.14.14 but omitting it is cleaner.
    if let Some(base_ids) = original_uri_base_ids(scan_root) {
        run["originalUriBaseIds"] = base_ids;
    }
    let document = json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [run],
    });
    serde_json::to_writer_pretty(&mut *out, &document).map_err(std::io::Error::from)?;
    writeln!(out)?;
    Ok(())
}

// ── Rule descriptors ──────────────────────────────────────────────────────────

/// Static per-rule metadata used for the SARIF `reportingDescriptor`.
///
/// A descriptor describes the *rule*, not one of its instances.  VL003 emits
/// two different kinds of finding under one `rule_id` (Medium workspace-level
/// and Low per-site), so we cannot pull metadata from the first matching
/// finding — the text changes depending on which finding sorts first.
struct RuleDescriptor {
    name: &'static str,
    help: &'static str,
    docs_url: &'static str,
}

/// Returns static metadata for each rule ID.
fn rule_metadata(rule_id: &str) -> RuleDescriptor {
    match rule_id {
        "VL001" => RuleDescriptor {
            name: "unproven authority on init",
            help: "Validate the authority account before using its key as a seed or storing it.",
            docs_url: "https://vaultlint.com/rules/VL001/",
        },
        "VL002" => RuleDescriptor {
            name: "missing owner check",
            help: "Use `Account<'info, T>`, which checks the owner.",
            docs_url: "https://vaultlint.com/rules/VL002/",
        },
        "VL003" => RuleDescriptor {
            name: "unchecked arithmetic / overflow-checks not enabled",
            help: "Enable `overflow-checks = true` under `[profile.release]`, or use \
                   `checked_add` / `checked_sub` / `checked_mul`.",
            docs_url: "https://vaultlint.com/rules/VL003/",
        },
        "VL004" => RuleDescriptor {
            name: "unvalidated PDA bump",
            help: "Use `find_program_address` instead of `create_program_address`, or \
                   verify the bump against a trusted stored value.",
            docs_url: "https://vaultlint.com/rules/VL004/",
        },
        "VL005" => RuleDescriptor {
            name: "unchecked CPI target",
            help: "Verify the program ID before invoking an untrusted program.",
            docs_url: "https://vaultlint.com/rules/VL005/",
        },
        // Fallback for any future rule added before this table is updated.
        _ => RuleDescriptor {
            name: "unknown rule",
            help: "",
            docs_url: "",
        },
    }
}

/// One declaration per rule that actually fired, de-duplicated and ordered.
/// Metadata comes from the static table, not from the first finding, so the
/// descriptor is the same regardless of which VL003 variant sorts first.
fn rules(report: &ScanReport) -> Vec<Value> {
    let mut seen: BTreeMap<&str, ()> = BTreeMap::new();
    let mut result = Vec::new();
    for finding in &report.findings {
        if seen.insert(&finding.rule_id, ()).is_none() {
            let meta = rule_metadata(&finding.rule_id);
            result.push(json!({
                "id": finding.rule_id,
                "name": meta.name,
                "shortDescription": { "text": meta.name },
                "helpUri": meta.docs_url,
                "help": { "text": meta.help },
            }));
        }
    }
    result
}

// ── URI helpers ───────────────────────────────────────────────────────────────

/// Percent-encode a path string for use in a `file://` URI.
///
/// Only characters that are not unreserved URI characters and not `/` or `:` (needed
/// for `file:///C:/...` on Windows) are encoded. This covers the ASCII space and
/// the most common special characters without pulling in a new dependency.
fn percent_encode_path(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for byte in s.bytes() {
        match byte {
            // Unreserved: ALPHA / DIGIT / "-" / "." / "_" / "~"
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(byte as char);
            }
            // Keep path separators and the colon for drive letters.
            b'/' | b':' => out.push(byte as char),
            // Encode everything else.
            b => {
                out.push('%');
                let hi = b >> 4;
                let lo = b & 0xF;
                out.push(
                    char::from_digit(u32::from(hi), 16)
                        .unwrap()
                        .to_ascii_uppercase(),
                );
                out.push(
                    char::from_digit(u32::from(lo), 16)
                        .unwrap()
                        .to_ascii_uppercase(),
                );
            }
        }
    }
    out
}

/// Converts an absolute `Path` to a `file://` URI string.
fn path_to_file_uri(path: &Path) -> String {
    let s = path.to_string_lossy();
    // On Unix the path already starts with `/`; on Windows it starts with `C:\`.
    // Replace backslashes with forward slashes for the URI.
    let forward = s.replace('\\', "/");
    if forward.starts_with('/') {
        format!("file://{}", percent_encode_path(&forward))
    } else {
        // Windows: `C:/foo` → `file:///C:/foo`
        format!("file:///{}", percent_encode_path(&forward))
    }
}

/// Converts `path` to a forward-slash relative URI string (no leading slash).
fn path_to_relative_uri(rel: &Path) -> String {
    rel.to_string_lossy().replace('\\', "/")
}

/// Returns `originalUriBaseIds` mapping `%SRCROOT%` to the scan root, or
/// `None` when there is no scan root (omit the key from the SARIF run).
fn original_uri_base_ids(scan_root: Option<&Path>) -> Option<Value> {
    let root = scan_root?;
    let uri = path_to_file_uri(root);
    // SARIF requires the base URI to end with `/`.
    let uri = if uri.ends_with('/') {
        uri
    } else {
        format!("{uri}/")
    };
    Some(json!({ "%SRCROOT%": { "uri": uri } }))
}

/// Returns the `artifactLocation` object for a finding's path.
///
/// - If the path is inside the scan root: relative URI + `uriBaseId: "%SRCROOT%"`.
/// - If the path is outside the scan root (e.g. a workspace manifest above the
///   scanned member): absolute `file://` URI with no `uriBaseId`.
/// - If no scan root is known (unit tests): use the path as-is (legacy behaviour).
fn artifact_location(finding_path: &Path, scan_root: Option<&Path>) -> Value {
    match scan_root {
        None => {
            // Unit-test / legacy path: emit whatever string the path produces.
            json!({ "uri": finding_path.to_string_lossy().replace('\\', "/") })
        }
        Some(root) => {
            // Normalise both sides before comparing: `scan_root` is already
            // absolute (from `project::normalised`), but `finding.file` carries
            // whatever spelling the scanner produced, which is relative when the
            // user passed a relative scan root.  Without this normalisation,
            // `strip_prefix(absolute, relative)` always fails and every in-root
            // path falls into the `Err` branch.
            let abs_finding = normalised(finding_path);
            match abs_finding.strip_prefix(root) {
                Ok(rel) => json!({
                    "uri": path_to_relative_uri(rel),
                    "uriBaseId": "%SRCROOT%",
                }),
                Err(_) => json!({
                    "uri": path_to_file_uri(&abs_finding),
                }),
            }
        }
    }
}

// ── Result and invocation ─────────────────────────────────────────────────────

fn result(finding: &Finding, scan_root: Option<&Path>) -> Value {
    json!({
        "ruleId": finding.rule_id,
        "level": level(finding.severity),
        "message": { "text": format!("{}: {}", finding.title, finding.message) },
        "locations": [{
            "physicalLocation": {
                "artifactLocation": artifact_location(&finding.file, scan_root),
                "region": { "startLine": finding.line, "startColumn": finding.column },
            }
        }],
    })
}

/// Builds the single `invocation` object for this run, carrying any skipped
/// files as `toolExecutionNotifications`.
fn invocation(report: &ScanReport) -> Value {
    let notifications: Vec<Value> = report
        .skipped
        .iter()
        .map(|s| {
            json!({
                "level": "note",
                "message": {
                    "text": format!("skipped {}: {}", s.path.display(), s.reason)
                },
            })
        })
        .collect();
    json!({
        "executionSuccessful": true,
        "toolExecutionNotifications": notifications,
    })
}

fn level(severity: Severity) -> &'static str {
    match severity {
        Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low => "note",
    }
}

#[cfg(test)]
mod tests {
    use super::percent_encode_path;

    /// ASCII-safe characters pass through unencoded; spaces and non-ASCII
    /// multi-byte UTF-8 sequences are percent-encoded byte by byte.
    ///
    /// Kill: replace the `_ => { out.push('%'); … }` branch with a no-op.
    /// The space assertion fails because " " is not encoded.
    #[test]
    fn percent_encode_path_encodes_spaces_and_non_ascii() {
        assert_eq!(percent_encode_path("/plain/path"), "/plain/path");
        assert_eq!(
            percent_encode_path("/path with space"),
            "/path%20with%20space"
        );
        // "é" is U+00E9 → UTF-8 bytes 0xC3 0xA9 → %C3%A9
        assert_eq!(percent_encode_path("/café"), "/caf%C3%A9");
    }
}
