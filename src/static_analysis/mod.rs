//! Static analysis for manifest, certificate and code files.
//!
//! The static analysis of the application's source files is used to search for vulnerable
//! code, settings and any other form of implementation that might be used as an exploit.

#[cfg(feature = "certificate")]
pub mod certificate;
pub mod code;
pub mod manifest;

#[cfg(feature = "certificate")]
use self::certificate::certificate_analysis;
#[cfg(feature = "certificate")]
use crate::print_warning;
use crate::{results::Results, Config};

/// Runs the analysis for manifest, certificate and code files.
///
/// * Benchmarking support.
pub fn static_analysis<S: AsRef<str>>(config: &Config, package: S, results: &mut Results) {
    if config.is_verbose() {
        println!(
            "It's time to analyze the application. First, a static analysis will be performed, \
             starting with the AndroidManifest.xml file and then going through the actual code. \
             Let's start!"
        );
    }

    // Run analysis for manifest file.
    let manifest = manifest::analysis(config, package.as_ref(), results);

    #[cfg(feature = "certificate")]
    {
        // Run analysis for certificate file.
        if let Err(e) = certificate_analysis(config, package.as_ref(), results) {
            print_warning(format!(
                "there was an error analyzing the certificate: {}",
                e
            ))
        }
    }

    // Run analysis for source code files.
    code::analysis(manifest, config, package.as_ref(), results)
}
