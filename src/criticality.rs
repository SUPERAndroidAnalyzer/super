//! Criticality module.

use std::{
    fmt::{self, Display},
    str::FromStr,
};

use serde::{Deserialize, Serialize};

use crate::ErrorKind;

/// Vulnerability criticality
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Copy, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Criticality {
    /// Warning.
    Warning,
    /// Low criticality vulnerability.
    Low,
    /// Medium criticality vulnerability.
    Medium,
    /// High criticality vulnerability.
    High,
    /// Critical vulnerability.
    Critical,
}

impl Display for Criticality {
    #[allow(clippy::use_debug)]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "{}", format!("{:?}", self).to_lowercase())
    }
}

impl FromStr for Criticality {
    type Err = ErrorKind;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "critical" => Ok(Self::Critical),
            "high" => Ok(Self::High),
            "medium" => Ok(Self::Medium),
            "low" => Ok(Self::Low),
            "warning" => Ok(Self::Warning),
            _ => Err(ErrorKind::Parse),
        }
    }
}
