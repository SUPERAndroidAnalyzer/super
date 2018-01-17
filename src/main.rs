//! SUPER Android Analyzer launcher.

#![cfg_attr(feature = "cargo-clippy", deny(clippy))]
#![forbid(anonymous_parameters)]
#![cfg_attr(feature = "cargo-clippy", warn(clippy_pedantic))]
#![cfg_attr(feature = "cargo-clippy", allow(print_stdout))]
#![deny(variant_size_differences, unused_results, unused_qualifications, unused_import_braces,
        unsafe_code, trivial_numeric_casts, trivial_casts, missing_docs,
        missing_debug_implementations, missing_copy_implementations, box_pointers)]

extern crate super_analyzer_core;

extern crate colored;
#[macro_use]
extern crate log;

use std::io::{self, Write};
use std::time::{Duration, Instant};
use std::thread::sleep;
use std::collections::BTreeMap;

use colored::Colorize;
use log::Level;

use super_analyzer_core::*;

/// Program entry point.
fn main() {
    if let Err(e) = run() {
        error!("{}", e);

        for e in e.iter().skip(1) {
            println!("\t{}{}", "Caused by: ".bold(), e);
        }

        if !log_enabled!(Level::Debug) {
            println!(
                "If you need more information, try to run the program again with the {} flag.",
                "-v".bold()
            );
        }

        if let Some(backtrace) = e.backtrace() {
            #[cfg_attr(feature = "cargo-clippy", allow(use_debug))]
            {
                println!("backtrace: {:?}", backtrace);
            }
        }

        ::std::process::exit(e.into());
    }
}

/// Analyzer executable code.
fn run() -> Result<()> {
    let cli = cli::generate().get_matches();
    let verbose = cli.is_present("verbose");
    initialize_logger(verbose);

    let mut config = initialize_config(&cli)?;

    if !config.check() {
        let mut error_string = String::from("Configuration errors were found:\n");
        for error in config.errors() {
            error_string.push_str(&error);
            error_string.push('\n');
        }
        error_string.push_str(
            "The configuration was loaded, in order, from the following files: \
             \n\t- Default built-in configuration\n",
        );
        for file in config.loaded_config_files() {
            error_string.push_str(&format!("\t- {}\n", file.display()));
        }

        return Err(ErrorKind::Config(error_string).into());
    }

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

    let mut benchmarks = BTreeMap::new();

    let total_start = Instant::now();
    for package in config.app_packages() {
        config.reset_force();
        analyze_package(package, &mut config, &mut benchmarks)
            .chain_err(|| "Application analysis failed")?;
    }

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
