use std;
use std::fmt;
use std::fmt::Display;
use std::result;
use std::str::FromStr;
use ErrorKind;
use Serialize;
use Serializer;
pub use error::*;


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
    #[allow(use_debug)]
    fn fmt(&self, f: &mut fmt::Formatter) -> std::result::Result<(), fmt::Error> {
        write!(f, "{}", format!("{:?}", self).to_lowercase())
    }
}

impl Serialize for Criticality {
    fn serialize<S>(&self, serializer: S) -> result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(format!("{}", self).as_str())
    }
}

impl FromStr for Criticality {
    type Err = Error;
    fn from_str(s: &str) -> Result<Criticality> {
        match s.to_lowercase().as_str() {
            "critical" => Ok(Criticality::Critical),
            "high" => Ok(Criticality::High),
            "medium" => Ok(Criticality::Medium),
            "low" => Ok(Criticality::Low),
            "warning" => Ok(Criticality::Warning),
            _ => Err(ErrorKind::Parse.into()),
        }
    }
}
