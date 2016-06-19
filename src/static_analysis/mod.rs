pub mod manifest;
pub mod certificate;
pub mod code;

use std::time::Instant;

use self::manifest::*;
use self::certificate::*;
use self::code::*;
use results::{Results, Benchmark};
use Config;

pub fn static_analysis(config: &Config, results: &mut Results) {
    if config.is_verbose() {
        println!("It's time to analyze the application. First, a static analysis will be \
                  performed, starting with the AndroidManifest.xml file and then going through \
                  the actual code. Let's start!");
    }

    let manifest_start = Instant::now();
    let manifest = manifest_analysis(config, results);
    if config.is_bench() {
        results.add_benchmark(Benchmark::new("Manifest analysis", manifest_start.elapsed()));
    }

    let certificate_start = Instant::now();
    let certificate = certificate_analysis(config, results);
    if config.is_bench() {
        results.add_benchmark(Benchmark::new("Certificate analysis", certificate_start.elapsed()));
    }

    code_analysis(manifest, config, results);
}
