//! SUPER Android Analyzer

// #![forbid(missing_docs, warnings)]
#![deny(deprecated, improper_ctypes, non_shorthand_field_patterns, overflowing_literals,
    plugin_as_library, private_no_mangle_fns, private_no_mangle_statics, stable_features,
    unconditional_recursion, unknown_lints, unused, unused_allocation, unused_attributes,
    unused_comparisons, unused_features, unused_parens, while_true)]
#![warn(missing_docs, trivial_casts, trivial_numeric_casts, unused, unused_extern_crates,
    unused_import_braces, unused_qualifications, unused_results, variant_size_differences)]

#[macro_use]
extern crate clap;
extern crate colored;
extern crate zip;
extern crate xml;
extern crate serde;
extern crate serde_json;
extern crate yaml_rust;
extern crate chrono;
extern crate toml;
extern crate regex;
#[macro_use]
extern crate lazy_static;
extern crate crypto;
extern crate rustc_serialize;
extern crate open;
extern crate bytecount;
extern crate handlebars;
#[macro_use]
extern crate log;
extern crate env_logger;

mod cli;
mod decompilation;
mod static_analysis;
mod results;
mod config;
mod utils;

use std::{fs, io, fmt, result};
use std::path::{Path, PathBuf};
use std::fmt::Display;
use std::str::FromStr;
use std::error::Error as StdError;
use std::io::Write;
use std::process::exit;
use std::time::{Instant, Duration};
use std::thread::sleep;
use std::collections::BTreeMap;

use serde::ser::{Serialize, Serializer};
use serde_json::error::ErrorCode as JSONErrorCode;
use colored::Colorize;

use log::{LogRecord, LogLevelFilter, LogLevel};
use env_logger::LogBuilder;

use cli::generate_cli;
use decompilation::*;
use static_analysis::*;
use results::*;
pub use config::Config;
pub use utils::*;

static BANNER: &'static str = include_str!("banner.txt");

fn main() {
    let cli = generate_cli();
    let verbose = cli.is_present("verbose");
    initialize_logger(verbose);

    let mut config = match Config::from_cli(cli) {
        Ok(c) => c,
        Err(e) => {
            print_warning(format!("There was an error when reading the config.toml file: {}",
                                  e.description()),
                          verbose);
            Config::default()
        }
    };

    if !config.check() {
        let mut error_string = String::from("Configuration errors were found:\n");
        for error in config.get_errors() {
            error_string.push_str(&error);
            error_string.push('\n');
        }
        error_string.push_str("The configuration was loaded, in order, from the following \
                               files:\n\t- Default built-in configuration\n");
        for file in config.get_loaded_config_files() {
            error_string.push_str(&format!("\t- {}\n", file.display()));
        }
        print_error(error_string, verbose);
        exit(Error::Config.into());
    }

    if config.is_verbose() {
        for c in BANNER.chars() {
            print!("{}", c);
            io::stdout().flush().unwrap();
            sleep(Duration::from_millis(3));
        }
        println!("Welcome to the SUPER Android Analyzer. We will now try to audit the given \
                  application.");
        println!("You activated the verbose mode. {}",
                 "May Tux be with you!".bold());
        println!("");
        sleep(Duration::from_millis(1250));
    }

    let mut benchmarks = BTreeMap::new();

    let total_start = Instant::now();
    for package in config.get_app_packages() {
        config.reset_force();
        analyze_package(package, &mut config, &mut benchmarks);
    }

    if config.is_bench() {
        let total_time = Benchmark::new("Total time", total_start.elapsed());
        println!("");
        println!("{}", "Benchmarks:".bold());
        for (package_name, benchmarks) in benchmarks {
            println!("{}:", package_name.italic());
            for bench in benchmarks {
                println!("{}", bench);
            }
            println!("");
        }
        println!("{}", total_time);
    }
}

/// Analyzes the given package with the given config.
fn analyze_package(package: PathBuf,
                   config: &mut Config,
                   benchmarks: &mut BTreeMap<String, Vec<Benchmark>>) {
    let package_name = get_package_name(&package);
    if config.is_bench() {
        let _ = benchmarks.insert(package_name.clone(), Vec::with_capacity(4));
    }
    if !config.is_quiet() {
        println!("");
        println!("Starting analysis of {}.", package_name.italic());
    }
    let start_time = Instant::now();

    // APKTool app decompression
    decompress(config, &package);

    if config.is_bench() {
        benchmarks.get_mut(&package_name)
            .unwrap()
            .push(Benchmark::new("ApkTool decompression", start_time.elapsed()));
    }

    // Extracting the classes.dex from the .apk file
    extract_dex(config, &package, benchmarks);

    let dex_jar_time = Instant::now();
    // Converting the .dex to .jar.
    dex_to_jar(config, &package);

    if config.is_bench() {
        benchmarks.get_mut(&package_name)
            .unwrap()
            .push(Benchmark::new("Dex to Jar decompilation", dex_jar_time.elapsed()));
    }

    if config.is_verbose() {
        println!("");
        println!("Now it's time for the actual decompilation of the source code. We'll \
                  translate Android JVM bytecode to Java, so that we can check the code \
                  afterwards.");
    }

    let decompile_start = Instant::now();

    // Decompiling the app
    decompile(config, &package);

    if config.is_bench() {
        benchmarks.get_mut(&package_name)
            .unwrap()
            .push(Benchmark::new("Decompilation", decompile_start.elapsed()));
    }

    if let Some(mut results) = Results::init(config, &package) {
        let static_start = Instant::now();
        // Static application analysis
        static_analysis(config, &package_name, &mut results);

        if config.is_bench() {
            benchmarks.get_mut(&package_name)
                .unwrap()
                .push(Benchmark::new("Total static analysis", static_start.elapsed()));
        }

        // TODO dynamic analysis

        if !config.is_quiet() {
            println!("");
        }

        let report_start = Instant::now();
        match results.generate_report(config, &package_name) {
            Ok(true) => {
                if config.is_verbose() {
                    println!("The results report has been saved. Everything went smoothly, \
                              now you can check all the results.");
                    println!("");
                    println!("I will now analyze myself for vulnerabilities…");
                    sleep(Duration::from_millis(1500));
                    println!("Nah, just kidding, I've been developed in {}!",
                             "Rust".bold().green())
                } else if !config.is_quiet() {
                    println!("Report generated.");
                }
            }
            Ok(false) => {}
            Err(e) => {
                print_error(format!("There was an error generating the results report: {}",
                                    e.description()),
                            config.is_verbose());
                exit(Error::Unknown.into())
            }
        }


        if config.is_bench() {
            benchmarks.get_mut(&package_name)
                .unwrap()
                .push(Benchmark::new("Report generation", report_start.elapsed()));
            benchmarks.get_mut(&package_name)
                .unwrap()
                .push(Benchmark::new(format!("Total time for {}", package_name),
                                     start_time.elapsed()));
        }

        if config.is_open() {
            let report_path = config.get_results_folder()
                .join(results.get_app_package())
                .join("index.html");
            if let Err(e) = open::that(report_path) {
                print_error(format!("Report could not be opened automatically: {}",
                                    e.description()),
                            config.is_verbose());
            }
        }
    } else if config.is_open() {
        let report_path = config.get_results_folder()
            .join(package_name)
            .join("index.html");
        if let Err(e) = open::that(report_path) {
            print_error(format!("Report could not be opened automatically: {}",
                                e.description()),
                        config.is_verbose());
        }
    }
}

#[derive(Debug)]
/// Enum representing all error types of SUPER.
pub enum Error {
    /// The *.apk* file does not exist.
    AppNotExists,
    /// Parsing error.
    Parse,
    /// JSON error.
    JSON(JSONError),
    /// The code was not found.
    CodeNotFound,
    /// Configuration error.
    Config,
    /// I/O error.
    IO(io::Error),
    /// Template name error.
    TemplateName(String),
    /// Template error.
    Template(Box<handlebars::TemplateError>),
    /// Template rendering error.
    Render(Box<handlebars::RenderError>),
    /// Unknown error.
    Unknown,
}

impl Into<i32> for Error {
    fn into(self) -> i32 {
        match self {
            Error::AppNotExists => 10,
            Error::Parse => 20,
            Error::JSON(_) => 30,
            Error::CodeNotFound => 40,
            Error::Config => 50,
            Error::IO(_) => 100,
            Error::TemplateName(_) => 125,
            Error::Template(_) => 150,
            Error::Render(_) => 175,
            Error::Unknown => 1,
        }
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Error {
        Error::IO(err)
    }
}

impl From<handlebars::TemplateFileError> for Error {
    fn from(err: handlebars::TemplateFileError) -> Error {
        match err {
            handlebars::TemplateFileError::TemplateError(e) => e.into(),
            handlebars::TemplateFileError::IOError(e, _) => e.into(),
        }
    }
}

impl From<handlebars::TemplateError> for Error {
    fn from(err: handlebars::TemplateError) -> Error {
        Error::Template(Box::new(err))
    }
}

impl From<handlebars::RenderError> for Error {
    fn from(err: handlebars::RenderError) -> Error {
        Error::Render(Box::new(err))
    }
}

impl From<serde_json::error::Error> for Error {
    fn from(err: serde_json::error::Error) -> Error {
        match err {
            serde_json::error::Error::Syntax(code, line, column) => {
                Error::JSON(JSONError::new(code, line, column))
            }
            serde_json::error::Error::Io(err) => Error::IO(err),
        }
    }
}

impl From<yaml_rust::ScanError> for Error {
    fn from(_: yaml_rust::ScanError) -> Error {
        Error::Parse
    }
}


impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.description())
    }
}

impl StdError for Error {
    fn description(&self) -> &str {
        match *self {
            Error::AppNotExists => "the application has not been found",
            Error::Parse => "there was an error in some parsing process",
            Error::JSON(ref e) => e.description(),
            Error::CodeNotFound => "the code was not found in the file",
            Error::Config => "there was an error in the configuration",
            Error::IO(ref e) => e.description(),
            Error::TemplateName(ref e) => e,
            Error::Template(ref e) => e.description(),
            Error::Render(ref e) => e.description(),
            Error::Unknown => "an unknown error occurred",
        }
    }

    fn cause(&self) -> Option<&StdError> {
        match *self {
            Error::IO(ref e) => Some(e),
            Error::Template(ref e) => Some(e),
            Error::Render(ref e) => Some(e),
            _ => None,
        }
    }
}

/// JSON error structure.
#[derive(Debug)]
pub struct JSONError {
    description: String,
}

impl JSONError {
    fn new(code: JSONErrorCode, line: usize, column: usize) -> JSONError {
        JSONError { description: format!("{:?} at line {} column {}", code, line, column) }
    }

    fn description(&self) -> &str {
        &self.description
    }
}

/// SUPER result type.
pub type Result<T> = std::result::Result<T, Error>;

/// Vulnerability criticality
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Copy, Clone)]
pub enum Criticality {
    /// Warning.
    Warning,
    /// Low criticality vulnerability.
    Low,
    /// Medium criticality vulnerability.
    Medium,
    /// High criticality vulnerability.
    High,
    /// Critical vulnerability.
    Critical,
}

impl Display for Criticality {
    fn fmt(&self, f: &mut fmt::Formatter) -> std::result::Result<(), fmt::Error> {
        write!(f, "{}", format!("{:?}", self).to_lowercase())
    }
}

impl Serialize for Criticality {
    fn serialize<S>(&self, serializer: &mut S) -> result::Result<(), S::Error>
        where S: Serializer
    {
        serializer.serialize_str(format!("{}", self).as_str())?;
        Ok(())
    }
}

impl FromStr for Criticality {
    type Err = Error;
    fn from_str(s: &str) -> Result<Criticality> {
        match s.to_lowercase().as_str() {
            "critical" => Ok(Criticality::Critical),
            "high" => Ok(Criticality::High),
            "medium" => Ok(Criticality::Medium),
            "low" => Ok(Criticality::Low),
            "warning" => Ok(Criticality::Warning),
            _ => Err(Error::Parse),
        }
    }
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

fn initialize_logger(is_verbose: bool) {
	let format = |record: &LogRecord| {
        match record.level() {
            LogLevel::Warn => format!("{}{}", "Warning: ".bold().yellow(), record.args().to_string().yellow()),
            LogLevel::Error => format!("{}{}", "Error: ".bold().red(), record.args().to_string().red()),
            LogLevel::Debug => format!("{}{}", "Debug: ".bold(), record.args().to_string().bold()),
            LogLevel::Info => format!("{}", record.args()),
            _ => format!("{}: {}", record.level(), record.args()),
        }
    };

    let log_level = if is_verbose {
        LogLevelFilter::Debug
    } else {
        LogLevelFilter::Info
    };

    let mut builder = LogBuilder::new();
    let builder_state = builder
        .format(format)
        .filter(None, log_level)
        .init();

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
        assert_eq!(Criticality::from_str("warning").unwrap(),
                   Criticality::Warning);
        assert_eq!(Criticality::from_str("Warning").unwrap(),
                   Criticality::Warning);
        assert_eq!(Criticality::from_str("WARNING").unwrap(),
                   Criticality::Warning);

        assert_eq!(Criticality::from_str("low").unwrap(), Criticality::Low);
        assert_eq!(Criticality::from_str("Low").unwrap(), Criticality::Low);
        assert_eq!(Criticality::from_str("LOW").unwrap(), Criticality::Low);

        assert_eq!(Criticality::from_str("medium").unwrap(),
                   Criticality::Medium);
        assert_eq!(Criticality::from_str("Medium").unwrap(),
                   Criticality::Medium);
        assert_eq!(Criticality::from_str("MEDIUM").unwrap(),
                   Criticality::Medium);

        assert_eq!(Criticality::from_str("high").unwrap(), Criticality::High);
        assert_eq!(Criticality::from_str("High").unwrap(), Criticality::High);
        assert_eq!(Criticality::from_str("HIGH").unwrap(), Criticality::High);

        assert_eq!(Criticality::from_str("critical").unwrap(),
                   Criticality::Critical);
        assert_eq!(Criticality::from_str("Critical").unwrap(),
                   Criticality::Critical);
        assert_eq!(Criticality::from_str("CRITICAL").unwrap(),
                   Criticality::Critical);

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
