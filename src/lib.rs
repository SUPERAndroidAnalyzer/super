//! SUPER Android Analyzer

// Allowing these at least for now.
#![allow(unknown_lints, missing_docs_in_private_items, print_stdout, stutter, option_unwrap_used,
    result_unwrap_used, integer_arithmetic, cast_possible_truncation, cast_possible_wrap,
    indexing_slicing, cast_precision_loss, cast_sign_loss)]
#![forbid(deprecated, overflowing_literals, stable_features, trivial_casts, unconditional_recursion,
    plugin_as_library, unused_allocation, trivial_numeric_casts, unused_features, while_true,
    unused_parens, unused_comparisons, unused_extern_crates, unused_import_braces, unused_results,
    improper_ctypes, non_shorthand_field_patterns, private_no_mangle_fns, private_no_mangle_statics,
    filter_map, used_underscore_binding, option_map_unwrap_or, option_map_unwrap_or_else,
    mutex_integer, mut_mut, mem_forget)]
#![deny(unused_qualifications, unused, unused_attributes)]
#![warn(missing_docs, variant_size_differences, enum_glob_use, if_not_else,
    invalid_upcast_comparisons, items_after_statements, non_ascii_literal, nonminimal_bool,
    pub_enum_variant_names, shadow_reuse, shadow_same, shadow_unrelated, similar_names,
    single_match_else, string_add, string_add_assign, unicode_not_nfc, unseparated_literal_suffix,
    use_debug, wrong_pub_self_convention, doc_markdown)]


#[macro_use]
extern crate clap;
extern crate colored;
extern crate xml;
extern crate serde;
extern crate serde_json;
#[macro_use]
extern crate serde_derive;
extern crate chrono;
extern crate toml;
extern crate regex;
#[macro_use]
extern crate lazy_static;
extern crate rustc_serialize;
extern crate open;
extern crate bytecount;
extern crate handlebars;
#[macro_use]
extern crate log;
extern crate env_logger;
#[macro_use]
extern crate error_chain;
extern crate abxml;
extern crate md5;
extern crate sha1;
extern crate sha2;

mod error;
/// Command Line Interface
pub mod cli;
mod decompilation;
mod static_analysis;
mod results;
mod config;
mod utils;
mod criticality;

use std::fs;
use std::time::{Instant, Duration};
use std::thread::sleep;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use clap::ArgMatches;

use colored::Colorize;

use log::{LogRecord, LogLevelFilter, LogLevel};
use env_logger::LogBuilder;
use std::env;
use decompilation::*;
use static_analysis::*;
pub use results::*;
pub use error::*;
// use criticality::*;
pub use config::Config;
pub use utils::*;

pub static BANNER: &str = include_str!("banner.txt");


/// Initialize the config with the config files and command line options
/// On UNIX, if local file ('config.toml') does not exists, but the global one does
/// ('/etc/super-analyzer/config.toml'), the latter is used.
/// Otherwise, the local file is used.
/// Finally, if non of the files could be loaded, the default config is used
pub fn initialize_config(cli: ArgMatches<'static>) -> Result<Config> {
    let config_path = PathBuf::from("config.toml");
    let global_config_path = PathBuf::from("/etc/super-analyzer/config.toml");

    let mut config =
        if cfg!(target_family = "unix") && !config_path.exists() && global_config_path.exists() {
            Config::from_file(&global_config_path).chain_err(|| {
                format!("There was an error when reading the /etc/super-analyzer/config.toml file")
            })?
        } else if config_path.exists() {
            Config::from_file(&PathBuf::from("config.toml")).chain_err(
                || {
                    format!("There was an error when reading the config.toml file")
                },
            )?
        } else {
            print_warning("Config file not found. Using default configuration");
            Config::default()
        };

    config.decorate_with_cli(cli).chain_err(
        || "There was an error reading config from CLI",
    )?;

    Ok(config)
}

/// Analyzes the given package with the given config.
pub fn analyze_package<P: AsRef<Path>>(
    package: P,
    config: &mut Config,
    benchmarks: &mut BTreeMap<String, Vec<Benchmark>>,
) -> Result<()> {
    let package_name = get_package_name(&package);
    if config.is_bench() {
        let _ = benchmarks.insert(package_name.clone(), Vec::with_capacity(4));
    }
    if !config.is_quiet() {
        println!();
        println!("Starting analysis of {}.", package_name.italic());
    }
    let start_time = Instant::now();

    // Apk decompression
    decompress(config, &package).chain_err(
        || "apk decompression failed",
    )?;

    if config.is_bench() {
        benchmarks.get_mut(&package_name).unwrap().push(
            Benchmark::new(
                "Apk decompression",
                start_time
                    .elapsed(),
            ),
        );
    }

    let dex_jar_time = Instant::now();
    // Converting the .dex to .jar.
    dex_to_jar(config, &package).chain_err(
        || "Conversion from DEX to JAR failed",
    )?;

    if config.is_bench() {
        benchmarks.get_mut(&package_name).unwrap().push(
            Benchmark::new(
                "Dex to Jar decompilation (dex2jar Java dependency)",
                dex_jar_time
                    .elapsed(),
            ),
        );
    }

    if config.is_verbose() {
        println!();
        println!(
            "Now it's time for the actual decompilation of the source code. We'll translate
                  Android JVM bytecode to Java, so that we can check the code afterwards."
        );
    }

    let decompile_start = Instant::now();

    // Decompiling the app
    decompile(config, &package).chain_err(
        || "JAR decompression failed",
    )?;

    if config.is_bench() {
        benchmarks.get_mut(&package_name).unwrap().push(
            Benchmark::new(
                "Decompilation (jd-cli Java dependency)",
                decompile_start
                    .elapsed(),
            ),
        );
    }

    let mut results = Results::init(config, &package)?;
    let static_start = Instant::now();
    // Static application analysis
    static_analysis(config, &package_name, &mut results);

    if config.is_bench() {
        benchmarks.get_mut(&package_name).unwrap().push(
            Benchmark::new(
                "Total static analysis",
                static_start
                    .elapsed(),
            ),
        );
    }

    // TODO dynamic analysis

    if !config.is_quiet() {
        println!();
    }

    let report_start = Instant::now();
    results.generate_report(config, &package_name).chain_err(
        || {
            format!(
                "There was an error generating the results report. Tried to generate at: {}",
                config.get_results_folder().join(&package_name).display()
            )
        },
    )?;

    if config.is_verbose() {
        println!("Everything went smoothly, now you can check all the results.");
        println!();
        println!("I will now analyze myself for vulnerabilities…");
        sleep(Duration::from_millis(1500));
        println!(
            "Nah, just kidding, I've been developed in {}!",
            "Rust".bold().green()
        )
    }

    if config.is_bench() {
        benchmarks.get_mut(&package_name).unwrap().push(
            Benchmark::new(
                "Report generation",
                report_start
                    .elapsed(),
            ),
        );
        benchmarks.get_mut(&package_name).unwrap().push(
            Benchmark::new(
                format!(
                    "Total time for {}",
                    package_name
                ),
                start_time
                    .elapsed(),
            ),
        );
    }

    if config.is_open() {
        let open_path = if config.has_to_generate_html() {
            config
                .get_results_folder()
                .join(results.get_app_package())
                .join("index.html")
        } else {
            config
                .get_results_folder()
                .join(results.get_app_package())
                .join("results.json")
        };

        let status = open::that(open_path).chain_err(
            || "Report could not be opened automatically",
        )?;

        if !status.success() {
            return Err(
                format!("Report opening errored with status code: {}", status).into(),
            );
        }
    }

    Ok(())
}

/// Copies the contents of `from` to `to`
///
/// If the destination folder doesn't exist is created. Note that the parent folder must exist. If
/// files in the destination folder exist with the same name as in the origin folder, they will be
/// overwriten.
pub fn copy_folder<P: AsRef<Path>>(from: P, to: P) -> Result<()> {
    if !to.as_ref().exists() {
        fs::create_dir(to.as_ref())?;
    }

    for f in fs::read_dir(from)? {
        let f = f?;
        if f.path().is_dir() {
            copy_folder(f.path(), to.as_ref().join(f.path().file_name().unwrap()))?;
        } else {
            let _ = fs::copy(f.path(), to.as_ref().join(f.path().file_name().unwrap()))?;
        }
    }
    Ok(())
}

pub fn initialize_logger(is_verbose: bool) {
    let format = |record: &LogRecord| match record.level() {
        LogLevel::Warn => {
            format!(
                "{}{}",
                "Warning: ".bold().yellow(),
                record.args().to_string().yellow()
            )
        }
        LogLevel::Error => {
            format!(
                "{}{}",
                "Error: ".bold().red(),
                record.args().to_string().red()
            )
        }
        LogLevel::Debug => format!("{}{}", "Debug: ".bold(), record.args().to_string().bold()),
        LogLevel::Info => format!("{}", record.args()),
        _ => format!("{}: {}", record.level(), record.args()),
    };

    let log_level = if is_verbose {
        LogLevelFilter::Debug
    } else {
        LogLevelFilter::Info
    };

    let mut builder = LogBuilder::new();

    let builder_state = if let Ok(env_log) = env::var("RUST_LOG") {
        builder.format(format).parse(&env_log).init()
    } else {
        builder
            .format(format)
            .filter(Some("super"), log_level)
            .init()
    };

    if let Err(e) = builder_state {
        println!("Could not initialize logger: {}", e);
    }
}

#[cfg(test)]
mod tests {
    use Criticality;
    use std::str::FromStr;

    #[test]
    fn it_criticality() {
        assert_eq!(
            Criticality::from_str("warning").unwrap(),
            Criticality::Warning
        );
        assert_eq!(
            Criticality::from_str("Warning").unwrap(),
            Criticality::Warning
        );
        assert_eq!(
            Criticality::from_str("WARNING").unwrap(),
            Criticality::Warning
        );

        assert_eq!(Criticality::from_str("low").unwrap(), Criticality::Low);
        assert_eq!(Criticality::from_str("Low").unwrap(), Criticality::Low);
        assert_eq!(Criticality::from_str("LOW").unwrap(), Criticality::Low);

        assert_eq!(
            Criticality::from_str("medium").unwrap(),
            Criticality::Medium
        );
        assert_eq!(
            Criticality::from_str("Medium").unwrap(),
            Criticality::Medium
        );
        assert_eq!(
            Criticality::from_str("MEDIUM").unwrap(),
            Criticality::Medium
        );

        assert_eq!(Criticality::from_str("high").unwrap(), Criticality::High);
        assert_eq!(Criticality::from_str("High").unwrap(), Criticality::High);
        assert_eq!(Criticality::from_str("HIGH").unwrap(), Criticality::High);

        assert_eq!(
            Criticality::from_str("critical").unwrap(),
            Criticality::Critical
        );
        assert_eq!(
            Criticality::from_str("Critical").unwrap(),
            Criticality::Critical
        );
        assert_eq!(
            Criticality::from_str("CRITICAL").unwrap(),
            Criticality::Critical
        );

        assert!(Criticality::Warning < Criticality::Low);
        assert!(Criticality::Warning < Criticality::Medium);
        assert!(Criticality::Warning < Criticality::High);
        assert!(Criticality::Warning < Criticality::Critical);
        assert!(Criticality::Low < Criticality::Medium);
        assert!(Criticality::Low < Criticality::High);
        assert!(Criticality::Low < Criticality::Critical);
        assert!(Criticality::Medium < Criticality::High);
        assert!(Criticality::Medium < Criticality::Critical);
        assert!(Criticality::High < Criticality::Critical);

        assert_eq!(format!("{}", Criticality::Warning).as_str(), "warning");
        assert_eq!(format!("{}", Criticality::Low).as_str(), "low");
        assert_eq!(format!("{}", Criticality::Medium).as_str(), "medium");
        assert_eq!(format!("{}", Criticality::High).as_str(), "high");
        assert_eq!(format!("{}", Criticality::Critical).as_str(), "critical");

        assert_eq!(format!("{:?}", Criticality::Warning).as_str(), "Warning");
        assert_eq!(format!("{:?}", Criticality::Low).as_str(), "Low");
        assert_eq!(format!("{:?}", Criticality::Medium).as_str(), "Medium");
        assert_eq!(format!("{:?}", Criticality::High).as_str(), "High");
        assert_eq!(format!("{:?}", Criticality::Critical).as_str(), "Critical");
    }
}
