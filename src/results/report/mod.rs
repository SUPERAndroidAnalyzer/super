mod json;
mod handlebars;

use results::Results;
use config::Config;
use error::*;

pub use self::json::Json;
pub use self::handlebars::HandlebarsReport;

pub trait Report {
    fn generate(&mut self, config: &Config, result: &Results) -> Result<()>;
}
