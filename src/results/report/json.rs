//! JSON report generation module.

use crate::{
    config::Config,
    results::{report::Generator, Results},
};
use anyhow::Result;
use serde_json::ser;
use std::{fs::File, io::BufWriter};

/// JSON report generator.
pub struct Json;

impl Json {
    /// Creates a new JSON report generator.
    pub fn new() -> Self {
        Self
    }
}

impl Generator for Json {
    #[allow(clippy::print_stdout)]
    fn generate(&mut self, config: &Config, results: &Results) -> Result<()> {
        if config.is_verbose() {
            println!("Starting JSON report generation. First we create the file.")
        }
        let mut f = BufWriter::new(File::create(
            config
                .results_folder()
                .join(&results.app_package())
                .join("results.json"),
        )?);
        if config.is_verbose() {
            println!("The report file has been created. Now it's time to fill it.")
        }
        ser::to_writer(&mut f, results)?;

        Ok(())
    }
}
