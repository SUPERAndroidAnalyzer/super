//! JSON report generation module.

use results::report::Generator;
use results::Results;
use config::Config;
use std::io::BufWriter;
use std::fs::File;
use serde_json::ser;

use error::*;

/// JSON report generator.
pub struct Json;

impl Json {
    /// Creates a new JSON report generator.
    pub fn new() -> Self {
        Json
    }
}

impl Generator for Json {
    #[cfg_attr(feature = "cargo-clippy", allow(print_stdout))]
    fn generate(&mut self, config: &Config, results: &Results) -> Result<()> {
        if config.is_verbose() {
            println!("Starting JSON report generation. First we create the file.")
        }
        let mut f = BufWriter::new(File::create(
            config.results_folder().join(&results.app_package()).join(
                "results.json",
            ),
        )?);
        if config.is_verbose() {
            println!("The report file has been created. Now it's time to fill it.")
        }
        ser::to_writer(&mut f, results)?;

        Ok(())
    }
}
