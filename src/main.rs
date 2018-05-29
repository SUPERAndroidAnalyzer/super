//! SUPER Android Analyzer launcher.
//!
//! This code controls the CLI of the application and launches the analysis of the application
//! using the core library.

#![cfg_attr(feature = "cargo-clippy", deny(clippy))]
#![forbid(anonymous_parameters)]
#![cfg_attr(feature = "cargo-clippy", warn(clippy_pedantic))]
#![cfg_attr(feature = "cargo-clippy", allow(print_stdout))]
#![deny(
    variant_size_differences, unused_results, unused_qualifications, unused_import_braces,
    unsafe_code, trivial_numeric_casts, trivial_casts, missing_debug_implementations, missing_docs,
    missing_copy_implementations
)]

extern crate super_analyzer_core;

extern crate colored;
extern crate failure;
#[macro_use]
extern crate log;

use std::collections::BTreeMap;
use std::io::{self, Write};
use std::thread::sleep;
use std::time::{Duration, Instant};

use colored::Colorize;
use failure::{Error, ResultExt};
use log::Level;

use super_analyzer_core::*;

/// Program entry point.
///
/// This function will just call the `run()` function and report any fatal error that comes out
/// of it. It will also exit with a non-zero exit code if things go wrong.
fn main() {
    // Call the `run()` function and check for errors.
    if let Err(e) = run() {
        error!("{}", e);

        // After printing the error, print the causes, in order.
        for e in e.causes().skip(1) {
            println!("\t{}{}", "Caused by: ".bold(), e);
        }

        // If the verbose mode is not enabled, we add a message so that the user knows that can
        // get further information with the `-v` flag in the CLI.
        if !log_enabled!(Level::Debug) {
            println!(
                "If you need more information, try to run the program again with the {} flag.",
                "-v".bold()
            );
        }

        // Exit with a non-zero exit code.
        ::std::process::exit(1);
    }
}

/// Execute the analysis.
///
/// This runs the actual analysis. It checks the CLI, creates the logger, loads the configuration
/// and if everything goes well, it starts the analysis. It also runs benchmarks and shows the
/// results.
fn run() -> Result<(), Error> {
    // Check the CLI arguments.
    let cli = cli::generate().get_matches();
    let verbose = cli.is_present("verbose");
    // Initialize all logger, specifying if the user wanted verbose mode.
    initialize_logger(verbose).context("could not initialize the logger")?;

    // Load the configuration.
    let mut config = initialize_config(&cli)?;

    // Check the configuration and return an error with the loaded files.
    if !config.check() {
        let mut error_string = String::from("configuration errors were found:\n");
        for error in config.errors() {
            error_string.push_str(&error);
            error_string.push('\n');
        }
        error_string.push_str(
            "the configuration was loaded, in order, from the following files: \
             \n\t- Default built-in configuration\n",
        );
        for file in config.loaded_config_files() {
            error_string.push_str(&format!("\t- {}\n", file.display()));
        }

        return Err(error::Kind::Config {
            message: error_string,
        }.into());
    }

    // Print the banner if we are in verbose mode.
    if config.is_verbose() {
        for c in BANNER.chars() {
            print!("{}", c);
            io::stdout().flush().expect("error flushing stdout");
            sleep(Duration::from_millis(3));
        }
        println!(
            "Welcome to the SUPER Android Analyzer. We will now try to audit the given application."
        );
        println!(
            "You activated the verbose mode. {}",
            "May Tux be with you!".bold()
        );
        println!();
        sleep(Duration::from_millis(1250));
    }

    // Start benchmarks.
    let mut benchmarks = BTreeMap::new();

    let total_start = Instant::now();
    // Analyze each apk one by one.
    for package in config.app_packages() {
        config.reset_force();
        analyze_package(package, &mut config, &mut benchmarks)
            .context("application analysis failed")?;
    }

    // Print benchmarks if in benchmark mode.
    if config.is_bench() {
        let total_time = Benchmark::new("Total time", total_start.elapsed());
        println!();
        println!("{}", "Benchmarks:".bold());
        for (package_name, benchmarks) in benchmarks {
            println!("{}:", package_name.italic());
            for bench in benchmarks {
                println!("{}", bench);
            }
            println!();
        }
        println!("{}", total_time);
    }

    Ok(())
}
