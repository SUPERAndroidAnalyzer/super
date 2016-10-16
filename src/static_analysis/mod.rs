//! Static analysis for manifest, certificate and code files.
//!
//! The static analysis of the application's source files is used to search for vulnearable
//! code, settings and any other form of implementation that might be used as an exploit.

pub mod manifest;
#[cfg(feature = "certificate")]
pub mod certificate;
pub mod code;

use std::time::Instant;

use self::manifest::*;
#[cfg(feature = "certificate")]
use self::certificate::*;
use self::code::*;
use results::{Results, Benchmark};
use Config;

/// Runs the analysis for manifest, certificate and code files.
///
/// * Benchmarking support.
pub fn static_analysis(config: &Config, results: &mut Results) {
    if config.is_verbose() {
        println!("It's time to analyze the application. First, a static analysis will be \
                  performed, starting with the AndroidManifest.xml file and then going through \
                  the actual code. Let's start!");
    }

    let manifest_start = Instant::now();
    // Run analysis for manifest file.
    let manifest = manifest_analysis(config, results);
    if config.is_bench() {
        results.add_benchmark(Benchmark::new("Manifest analysis", manifest_start.elapsed()));
    }

    if cfg!(feature = "certificate") {
        let certificate_start = Instant::now();
        // Run analysis for cerificate file.
        let _certificate = certificate_analysis(config, results);
        if config.is_bench() {
            results.add_benchmark(Benchmark::new("Certificate analysis",
                                                 certificate_start.elapsed()));
        }
    }

    // Run analysis for source code files.
    code_analysis(manifest, config, results);
}

#[cfg(not(feature = "certificate"))]
fn certificate_analysis(_config: &Config, _results: &mut Results) {}
