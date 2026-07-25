use std::path::PathBuf;

use serde::Serialize;

/// Ordered from least to most severe — `Low < Medium < High`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
}

impl Severity {
    pub fn label(self) -> &'static str {
        match self {
            Severity::Low => "LOW",
            Severity::Medium => "MED",
            Severity::High => "HIGH",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub rule_id: &'static str,
    pub severity: Severity,
    pub title: &'static str,
    pub message: String,
    pub file: PathBuf,
    pub line: usize,
    pub column: usize,
    pub snippet: String,
    pub help: &'static str,
    pub docs_url: String,
}
