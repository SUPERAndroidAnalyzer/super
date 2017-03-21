use results::report::Report;
use results::Results;
use config::Config;
use std::io::BufWriter;
use std::fs::File;
use serde_json::ser;

use error::*;

pub struct Json;

impl Json {
    pub fn new() -> Self {
        Json
    }
}

impl Report for Json {
    fn generate(&mut self, config: &Config, results: &Results) -> Result<()> {
        if config.is_verbose() {
            println!("Starting JSON report generation. First we create the file.")
        }
        let mut f = BufWriter::new(File::create(config.get_results_folder()
                                                    .join(&results.get_app_package())
                                                    .join("results.json"))?);
        if config.is_verbose() {
            println!("The report file has been created. Now it's time to fill it.")
        }
        ser::to_writer(&mut f, results)?;

        Ok(())
    }
}
