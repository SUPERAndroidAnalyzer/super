//! Report generation module.

mod handlebars;
mod json;

pub use self::{handlebars::Report as HandlebarsReport, json::Json};
use crate::{config::Config, results::Results};
use anyhow::Result;

/// Trait that represents a type that can generate a report.
pub trait Generator {
    /// Generates an actual report.
    fn generate(&mut self, config: &Config, result: &Results) -> Result<()>;
}
