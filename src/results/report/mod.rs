//! Report generation module.

mod handlebars;
mod json;

use failure::Error;

use config::Config;
use results::Results;

pub use self::handlebars::Report as HandlebarsReport;
pub use self::json::Json;

/// Trait that represents a type that can generate a report.
pub trait Generator {
    /// Generates an actual report.
    fn generate(&mut self, config: &Config, result: &Results) -> Result<(), Error>;
}
