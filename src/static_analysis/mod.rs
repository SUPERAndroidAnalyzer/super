pub mod manifest;
pub mod code;

use self::manifest::*;
use self::code::*;
use results::Results;
use Config;

pub fn static_analysis(config: &Config, results: &mut Results) {
    if config.is_verbose() {
        println!("It's time to analyze the application. First, a static analysis will be \
                  performed, starting with the AndroidManifest.xml file and then going through \
                  the actual code. Let's start!");
    }

    manifest_analysis(config, results);
    code_analysis(config, results);
}
