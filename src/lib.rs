//! SUPER Android Analyzer core library.
//!
//! This library contains the code for analyzing Android applications. It's called by the
//! launcher and contains the main logic of the analysis, with the configuration management,
//! the logger initialization and some utility functions.

#![forbid(anonymous_parameters)]
#![warn(clippy::pedantic)]
#![deny(
    clippy::all,
    variant_size_differences,
    unused_results,
    unused_qualifications,
    unused_import_braces,
    unsafe_code,
    trivial_numeric_casts,
    trivial_casts,
    missing_docs,
    unused_extern_crates,
    missing_debug_implementations,
    missing_copy_implementations
)]
// Allowing these for now.
#![allow(
    clippy::stutter,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::non_ascii_literal
)]

#[macro_use]
extern crate failure_derive;
#[macro_use]
extern crate log;
#[macro_use]
extern crate serde_derive;

pub mod cli;
mod config;
mod criticality;
mod decompilation;
pub mod error;
mod results;
mod static_analysis;
mod utils;

use std::{
    collections::BTreeMap,
    env, fs,
    path::Path,
    thread::sleep,
    time::{Duration, Instant},
};

use clap::ArgMatches;
use colored::Colorize;
use failure::{bail, format_err, Error, ResultExt};

pub use crate::{
    config::Config,
    utils::{
        get_code, get_package_name, get_string, print_vulnerability, print_warning, Benchmark,
        PARSER_CONFIG,
    },
};
use crate::{
    decompilation::{decompile, decompress, dex_to_jar},
    results::Results,
    static_analysis::static_analysis,
};

/// Logo ASCII art, used in verbose mode.
pub static BANNER: &str = include_str!("banner.txt");

/// Initialize the config with the config files and command line options.
///
/// On UNIX, if local file, `config.toml`, does not exist, but the global one does
/// `/etc/super-analyzer/config.toml`, the latter is used. Otherwise, the local file
/// is used. Finally, if non of the files could be loaded, the default configuration
/// is used. This default configuration contains the minimal setup for running the
/// analysis.
///
/// It will then add the configuration selected with the command line interface options.
pub fn initialize_config(cli: &ArgMatches<'static>) -> Result<Config, Error> {
    let config_path = Path::new("config.toml");
    let global_config_path = Path::new("/etc/super-analyzer/config.toml");

    let mut config =
        if cfg!(target_family = "unix") && !config_path.exists() && global_config_path.exists() {
            Config::from_file(&global_config_path).context(
                "there was an error when reading the /etc/super-analyzer/config.toml file",
            )?
        } else if config_path.exists() {
            Config::from_file(&config_path)
                .context("there was an error when reading the config.toml file")?
        } else {
            print_warning("config file not found. Using default configuration");
            Config::default()
        };

    config
        .decorate_with_cli(cli)
        .context("there was an error reading the configuration from the CLI")?;

    Ok(config)
}

/// Analyzes the given package with the given configuration.
#[allow(clippy::print_stdout)]
pub fn analyze_package<P: AsRef<Path>>(
    package: P,
    config: &mut Config,
    benchmarks: &mut BTreeMap<String, Vec<Benchmark>>,
) -> Result<(), Error> {
    let package_name = get_package_name(&package);
    if config.is_bench() {
        let _ = benchmarks.insert(package_name.clone(), Vec::with_capacity(4));
    }
    if !config.is_quiet() {
        println!();
        println!("Starting analysis of {}.", package_name.italic());
    }

    // Apk decompression.
    let start_time = Instant::now();
    decompress(config, &package).context("apk decompression failed")?;

    if config.is_bench() {
        benchmarks
            .get_mut(&package_name)
            .unwrap()
            .push(Benchmark::new("Apk decompression", start_time.elapsed()));
    }

    // Converting the .dex to .jar.
    let dex_jar_time = Instant::now();
    dex_to_jar(config, &package).context("conversion from DEX to JAR failed")?;

    if config.is_bench() {
        benchmarks
            .get_mut(&package_name)
            .unwrap()
            .push(Benchmark::new(
                "Dex to Jar decompilation (dex2jar Java dependency)",
                dex_jar_time.elapsed(),
            ));
    }

    if config.is_verbose() {
        println!();
        println!(
            "Now it's time for the actual decompilation of the source code. We'll translate
             Android JVM bytecode to Java, so that we can check the code afterwards."
        );
    }

    // Decompiling the app
    let decompile_start = Instant::now();
    decompile(config, &package).context("JAR decompression failed")?;

    if config.is_bench() {
        benchmarks
            .get_mut(&package_name)
            .unwrap()
            .push(Benchmark::new(
                "Decompilation (jd-cli Java dependency)",
                decompile_start.elapsed(),
            ));
    }

    // Initialize results structure
    let mut results = Results::init(config, &package)?;

    // Static application analysis
    let static_start = Instant::now();
    static_analysis(config, &package_name, &mut results);

    if config.is_bench() {
        benchmarks
            .get_mut(&package_name)
            .unwrap()
            .push(Benchmark::new(
                "Total static analysis",
                static_start.elapsed(),
            ));
    }

    if !config.is_quiet() {
        println!();
    }

    // Generate results report.
    let report_start = Instant::now();
    results
        .generate_report(config, &package_name)
        .context(format_err!(
            "there was an error generating the results report at: {}",
            config.results_folder().join(&package_name).display()
        ))?;

    if config.is_verbose() {
        println!("Everything went smoothly, you can now check all the results.");
        println!();
        println!("I will now analyze myself for vulnerabilities…");
        sleep(Duration::from_millis(1500));
        println!(
            "Nah, just kidding, I've been developed in {}!",
            "Rust".bold().green()
        )
    }

    if config.is_bench() {
        benchmarks
            .get_mut(&package_name)
            .unwrap()
            .push(Benchmark::new("Report generation", report_start.elapsed()));
        benchmarks
            .get_mut(&package_name)
            .unwrap()
            .push(Benchmark::new(
                format!("Total time for {}", package_name),
                start_time.elapsed(),
            ));
    }

    if config.is_open() {
        let open_path = if config.has_to_generate_html() {
            config
                .results_folder()
                .join(results.app_package())
                .join("index.html")
        } else {
            config
                .results_folder()
                .join(results.app_package())
                .join("results.json")
        };

        let status =
            open::that(open_path).context("the report could not be opened automatically")?;

        if !status.success() {
            bail!("report opening failed with status code: {}", status);
        }
    }

    Ok(())
}

/// Copies the contents of `from` to `to`
///
/// If the destination folder doesn't exist is created. Note that the parent folder must exist. If
/// files in the destination folder exist with the same name as in the origin folder, they will be
/// overwritten.
pub fn copy_folder<P: AsRef<Path>>(from: P, to: P) -> Result<(), Error> {
    if !to.as_ref().exists() {
        fs::create_dir(to.as_ref())?;
    }

    for f in fs::read_dir(from)? {
        let f = f?;
        if f.path().is_dir() {
            copy_folder(
                f.path(),
                to.as_ref()
                    .join(f.path().file_name().expect("expected file name")),
            )?;
        } else {
            let _ = fs::copy(
                f.path(),
                to.as_ref()
                    .join(f.path().file_name().expect("expected file name")),
            )?;
        }
    }
    Ok(())
}

/// Initializes the logger.
///
/// This will initialize the environment logger structure so that it generates the
/// proper messages using the right colors. It's called from the launcher.
#[allow(clippy::print_stdout)]
pub fn initialize_logger(is_verbose: bool) -> Result<(), log::SetLoggerError> {
    use env_logger::fmt::{Color, Formatter};
    use env_logger::Builder;
    use log::{Level, LevelFilter, Record};
    use std::io::Write;

    // Define the style of the formatting.
    let format = |buf: &mut Formatter, record: &Record| {
        let mut level_style = buf.style();
        match record.level() {
            Level::Warn => {
                let _ = level_style.set_color(Color::Yellow).set_bold(true);
            }
            Level::Error => {
                let _ = level_style.set_color(Color::Red).set_bold(true);
            }
            Level::Debug => {
                let _ = level_style.set_bold(true);
            }
            _ => {}
        }

        writeln!(
            buf,
            "{}: {}",
            level_style.value(record.level()),
            record.args()
        )
    };

    // Define the logging level for the messages.
    let log_level = if is_verbose {
        LevelFilter::Debug
    } else {
        LevelFilter::Info
    };

    let mut builder = Builder::new();

    // Initialize the logger.
    if let Ok(env_log) = env::var("RUST_LOG") {
        builder.format(format).parse(&env_log).try_init()
    } else {
        builder
            .format(format)
            .filter(Some("super"), log_level)
            .try_init()
    }
}

/// Integration and unit tests module.
///
/// This module includes tests for the analyzer. It includes both unit tests and
/// integration tests.
#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, fs, path::Path, str::FromStr};

    use super::analyze_package;
    use crate::{config::Config, criticality::Criticality};

    /// This tests checks that the `Criticality` enumeration works as expected.
    ///
    /// It checks the conversion both from and to strings, the comparisons between
    /// criticality levels and the debug format.
    #[allow(clippy::cyclomatic_complexity)]
    #[test]
    fn it_criticality() {
        // Check "warnings" from strings
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

        // Check low criticality from strings.
        assert_eq!(Criticality::from_str("low").unwrap(), Criticality::Low);
        assert_eq!(Criticality::from_str("Low").unwrap(), Criticality::Low);
        assert_eq!(Criticality::from_str("LOW").unwrap(), Criticality::Low);

        // Check medium criticality from strings.
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

        // Check high criticality from strings.
        assert_eq!(Criticality::from_str("high").unwrap(), Criticality::High);
        assert_eq!(Criticality::from_str("High").unwrap(), Criticality::High);
        assert_eq!(Criticality::from_str("HIGH").unwrap(), Criticality::High);

        // Check critical criticality from strings.
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

        // Check that the comparisons between criticality levels is correct.
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

        // Check that the criticality is printed correctly with the `Display` trait.
        assert_eq!(format!("{}", Criticality::Warning).as_str(), "warning");
        assert_eq!(format!("{}", Criticality::Low).as_str(), "low");
        assert_eq!(format!("{}", Criticality::Medium).as_str(), "medium");
        assert_eq!(format!("{}", Criticality::High).as_str(), "high");
        assert_eq!(format!("{}", Criticality::Critical).as_str(), "critical");

        // Check that the criticality is printed correctly with the `Debug` trait.
        assert_eq!(format!("{:?}", Criticality::Warning).as_str(), "Warning");
        assert_eq!(format!("{:?}", Criticality::Low).as_str(), "Low");
        assert_eq!(format!("{:?}", Criticality::Medium).as_str(), "Medium");
        assert_eq!(format!("{:?}", Criticality::High).as_str(), "High");
        assert_eq!(format!("{:?}", Criticality::Critical).as_str(), "Critical");
    }

    /// General package analysis test, ignored by default.
    ///
    /// This will download an apk from a public repository, analyze it and
    /// generate the results. It will check that no error gets generated.
    /// It still does not check that the results are the expected results.
    #[test]
    #[ignore]
    fn it_analyze_package() {
        let need_to_create = !Path::new("downloads").exists();
        if need_to_create {
            fs::create_dir("downloads").unwrap();
        }
        // Create the destination file.
        let mut apk_file = fs::File::create("downloads/test_app.apk").unwrap();

        // TODO: use an application that we control.
        // Download the .apk fie
        let _ = reqwest::get(
            "https://github.com/javiersantos/MLManager/releases/download/v1.0.4.1/\
             com.javiersantos.mlmanager_1.0.4.1.apk",
        )
        .unwrap()
        .copy_to(&mut apk_file)
        .unwrap();

        // Initialize minimum configuration.
        let mut benchmarks = BTreeMap::new();
        let mut config = Config::from_file("config.toml").unwrap();
        config.add_app_package("downloads/test_app");

        // Run the analysis
        analyze_package("downloads/test_app.apk", &mut config, &mut benchmarks).unwrap();

        // TODO: check results.

        // Remove generated files.
        if need_to_create {
            fs::remove_dir_all("downloads").unwrap();
        } else {
            fs::remove_file("downloads/test_app.apk").unwrap();
        }
        // TODO: maybe we should only remove the application specific files.
        fs::remove_dir_all("dist").unwrap();
        fs::remove_dir_all("results").unwrap();
    }
}
