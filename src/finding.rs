use std::borrow::Cow;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Ordered from least to most severe — `Low < Medium < High`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
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

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Low => f.write_str("low"),
            Severity::Medium => f.write_str("medium"),
            Severity::High => f.write_str("high"),
        }
    }
}

impl std::str::FromStr for Severity {
    type Err = UnknownSeverity;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "low" => Ok(Severity::Low),
            "medium" => Ok(Severity::Medium),
            "high" => Ok(Severity::High),
            _ => Err(UnknownSeverity(s.to_string())),
        }
    }
}

/// Error returned by [`Severity::from_str`] when the input is not recognised.
#[derive(Debug, PartialEq, Eq)]
pub struct UnknownSeverity(String);

impl std::fmt::Display for UnknownSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "unknown severity {:?}; expected one of: low, medium, high",
            self.0
        )
    }
}

impl std::error::Error for UnknownSeverity {}

/// A single security finding produced by vaultlint.
///
/// The string fields `rule_id`, `title`, and `help` are `Cow<'static, str>`.
/// Internal construction uses `Cow::Borrowed` on string literals (zero allocation);
/// deserialisation produces `Cow::Owned`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[non_exhaustive]
pub struct Finding {
    pub rule_id: Cow<'static, str>,
    pub severity: Severity,
    pub title: Cow<'static, str>,
    pub message: String,
    pub file: PathBuf,
    pub line: usize,
    pub column: usize,
    pub snippet: String,
    pub help: Cow<'static, str>,
    pub docs_url: String,
}
