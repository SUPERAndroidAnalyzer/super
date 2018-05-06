//! Criticality module.

use std::fmt;
use std::fmt::Display;
use std::str::FromStr;

use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use toml::value::Value;

use error;

/// Vulnerability criticality
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Copy, Clone)]
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
    #[cfg_attr(feature = "cargo-clippy", allow(use_debug))]
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "{}", format!("{:?}", self).to_lowercase())
    }
}

impl Serialize for Criticality {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(format!("{}", self).as_str())
    }
}

impl<'de> Deserialize<'de> for Criticality {
    fn deserialize<D>(de: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let deser_result: Value = Deserialize::deserialize(de)?;

        #[cfg_attr(feature = "cargo-clippy", allow(use_debug))]
        match deser_result {
            Value::String(ref criticality_str) => match Self::from_str(criticality_str) {
                Ok(criticality) => Ok(criticality),
                Err(_) => Err(de::Error::custom(format!(
                    "unexpected value: `{}`",
                    criticality_str
                ))),
            },
            _ => Err(de::Error::custom(format!(
                "unexpected value: `{:?}`",
                deser_result
            ))),
        }
    }
}

impl FromStr for Criticality {
    type Err = error::Kind;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "critical" => Ok(Criticality::Critical),
            "high" => Ok(Criticality::High),
            "medium" => Ok(Criticality::Medium),
            "low" => Ok(Criticality::Low),
            "warning" => Ok(Criticality::Warning),
            _ => Err(error::Kind::Parse),
        }
    }
}
