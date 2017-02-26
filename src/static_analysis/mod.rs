//! Static analysis for manifest, certificate and code files.
//!
//! The static analysis of the application's source files is used to search for vulnearable
//! code, settings and any other form of implementation that might be used as an exploit.

pub mod manifest;
#[cfg(feature = "certificate")]
pub mod certificate;
pub mod code;

use std::error::Error;

use self::manifest::*;
#[cfg(feature = "certificate")]
use self::certificate::*;
use results::Results;
use {Config, print_warning};
#[cfg(not(feature = "certificate"))]
use error::*;

/// Runs the analysis for manifest, certificate and code files.
///
/// * Benchmarking support.
pub fn static_analysis<S: AsRef<str>>(config: &Config, package: S, results: &mut Results) {
    if config.is_verbose() {
        println!("It's time to analyze the application. First, a static analysis will be \
                  performed, starting with the AndroidManifest.xml file and then going through \
                  the actual code. Let's start!");
    }

    // Run analysis for manifest file.
    let manifest = manifest_analysis(config, package.as_ref(), results);

    if cfg!(feature = "certificate") {
        // Run analysis for cerificate file.
        if let Err(e) = certificate_analysis(config, package.as_ref(), results) {
            print_warning(format!("There was an error analysing the certificate: {}",
                                  e.description()))
        }
    }

    // Run analysis for source code files.
    code::analysis(manifest, config, package.as_ref(), results)
}

#[cfg(not(feature = "certificate"))]
fn certificate_analysis<S: AsRef<str>>(_: &Config, _: S, _: &mut Results) -> Result<()> {
    Ok(())
}
