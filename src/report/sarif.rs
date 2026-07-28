use std::collections::BTreeMap;
use std::io::Write;

use serde_json::{json, Value};

use crate::finding::{Finding, Severity};
use crate::ScanReport;

pub fn render(report: &ScanReport, out: &mut dyn Write) -> anyhow::Result<()> {
    let document = json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "vaultlint",
                    "informationUri": "https://vaultlint.com",
                    "version": crate::version(),
                    "rules": rules(report),
                }
            },
            "results": report.findings.iter().map(result).collect::<Vec<_>>(),
        }]
    });
    serde_json::to_writer_pretty(&mut *out, &document).map_err(std::io::Error::from)?;
    writeln!(out)?;
    Ok(())
}

/// One declaration per rule that actually fired, de-duplicated and ordered.
fn rules(report: &ScanReport) -> Vec<Value> {
    let mut declared: BTreeMap<&str, &Finding> = BTreeMap::new();
    for finding in &report.findings {
        declared.entry(finding.rule_id).or_insert(finding);
    }
    declared
        .values()
        .map(|finding| {
            json!({
                "id": finding.rule_id,
                "name": finding.title,
                "shortDescription": { "text": finding.title },
                "helpUri": finding.docs_url,
                "help": { "text": finding.help },
            })
        })
        .collect()
}

fn result(finding: &Finding) -> Value {
    json!({
        "ruleId": finding.rule_id,
        "level": level(finding.severity),
        "message": { "text": format!("{}: {}", finding.title, finding.message) },
        "locations": [{
            "physicalLocation": {
                "artifactLocation": { "uri": finding.file.to_string_lossy() },
                "region": { "startLine": finding.line, "startColumn": finding.column },
            }
        }],
    })
}

fn level(severity: Severity) -> &'static str {
    match severity {
        Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low => "note",
    }
}
