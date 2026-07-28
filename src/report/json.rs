use std::io::Write;

use serde::Serialize;
use serde_json::json;

use crate::{ScanReport, SkippedFile};

/// Wire-format for a skipped file in JSON output.
#[derive(Serialize)]
struct SkippedEntry<'a> {
    path: String,
    reason: &'a str,
}

pub fn render(report: &ScanReport, out: &mut dyn Write) -> anyhow::Result<()> {
    let skipped: Vec<SkippedEntry<'_>> = report
        .skipped
        .iter()
        .map(|s: &SkippedFile| SkippedEntry {
            path: s.path.to_string_lossy().into_owned(),
            reason: &s.reason,
        })
        .collect();
    let document = json!({
        "findings": &report.findings,
        "skipped": skipped,
    });
    serde_json::to_writer_pretty(&mut *out, &document).map_err(std::io::Error::from)?;
    writeln!(out)?;
    Ok(())
}
