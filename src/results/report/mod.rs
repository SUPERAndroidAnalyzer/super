//! Report generation module.

mod json;
mod handlebars;

use results::Results;
use config::Config;
use error::*;

pub use self::json::Json;
pub use self::handlebars::Report as HandlebarsReport;

/// Trait that represents a type that can generate a report.
pub trait Generator {
    /// Generates an actual report.
    fn generate(&mut self, config: &Config, result: &Results) -> Result<()>;
}
