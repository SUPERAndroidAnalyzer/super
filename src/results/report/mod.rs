mod json;
mod handlebars;

use Result;
use results::Results;
use config::Config;

pub use self::json::Json;
pub use self::handlebars::HandlebarsReport;

pub trait Report {
    fn generate(&mut self, config: &Config, result: &Results) -> Result<()>;
}
