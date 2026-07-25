use std::io::Write;

use crate::ScanReport;

pub fn render(report: &ScanReport, out: &mut dyn Write) -> anyhow::Result<()> {
    serde_json::to_writer_pretty(&mut *out, &report.findings)?;
    writeln!(out)?;
    Ok(())
}
