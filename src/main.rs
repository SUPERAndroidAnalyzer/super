#[macro_use]
extern crate clap;
extern crate colored;
extern crate zip;
extern crate xml;
extern crate serde;
extern crate serde_json;
extern crate chrono;
extern crate toml;

mod decompilation;
mod static_analysis;
mod results;

use std::{fs, io, fmt, result};
use std::path::Path;
use std::fmt::Display;
use std::convert::From;
use std::error::Error as StdError;
use std::io::{Read, Write};
use std::process::exit;

use serde::ser::{Serialize, Serializer};
use clap::{Arg, App, ArgMatches};
use colored::Colorize;

use decompilation::*;
use static_analysis::*;
use results::*;

const MAX_THREADS: i64 = std::u8::MAX as i64;

fn main() {
    let matches = get_help_menu();

    let app_id = matches.value_of("id").unwrap();
    let verbose = matches.is_present("verbose");
    let quiet = matches.is_present("quiet");
    let force = matches.is_present("force");
    let mut config = match Config::new(app_id, verbose, quiet, force) {
        Ok(c) => c,
        Err(e) => {
            print_warning(format!("There was an error when reading the config.toml file: {}", e),
                          verbose);
            let mut c: Config = Default::default();
            c.set_app_id(app_id);
            c.set_verbose(verbose);
            c.set_quiet(quiet);
            c.set_force(force);
            c
        }
    };

    if !config.check() {
        config = Default::default();
        config.set_app_id(app_id);
        config.set_verbose(verbose);
        config.set_quiet(quiet);
        config.set_force(force);

        if !config.check() {
            print_error("There is an error with the configuration.", verbose);
            exit(Error::Config.into());
        }
    }

    if config.is_verbose() {
        println!("Welcome to the Android Anti-Rebelation project. We will now try to audit the \
                  given application.");
        println!("You activated the verbose mode. {}",
                 "May Tux be with you!".bold());
        println!("");
    }

    // APKTool app decompression
    decompress(&config);

    // Extracting the classes.dex from the .apk file
    extract_dex(&config);

    if config.is_verbose() {
        println!("");
        println!("Now it's time for the actual decompilation of the source code. We'll translate \
                  Android JVM bytecode to Java, so that we can check the code afterwards.");
    }

    // Decompiling the app
    decompile(&config);

    if let Some(mut results) = Results::init(&config) {
        // Static application analysis
        static_analysis(&config, &mut results);

        // TODO dynamic analysis

        println!("");

        match results.generate_report(&config) {
            Ok(_) => {
                if config.is_verbose() {
                    println!("The results report has been saved. Everything went smoothly, now \
                              you can check all the results.");
                    println!("");
                    println!("I will now analyse myself for vulnerabilities…");
                    println!("Nah, just kidding, I've been developed in {}!",
                             "Rust".bold().green())
                } else if !config.is_quiet() {
                    println!("Report generated.");
                }
            }
            Err(e) => {
                print_error(format!("There was an error generating the results report: {}", e),
                            config.is_verbose());
                exit(Error::Unknown.into())
            }
        }
    } else if !config.is_quiet() {
        println!("Analysis cancelled.");
    }
}

fn file_exists<P: AsRef<Path>>(path: P) -> bool {
    fs::metadata(path).is_ok()
}

pub struct Config {
    app_id: String,
    verbose: bool,
    quiet: bool,
    force: bool,
    threads: u8,
    downloads_folder: String,
    dist_folder: String,
    results_folder: String,
    apktool_file: String,
    dex2jar_folder: String,
    jd_cli_file: String,
    highlight_js: String,
    highlight_css: String,
    results_css: String,
    rules_json: String,
}

impl Config {
    pub fn new(app_id: &str, verbose: bool, quiet: bool, force: bool) -> Result<Config> {
        let mut f = try!(fs::File::open("config.toml"));
        let mut toml = String::new();
        try!(f.read_to_string(&mut toml));

        let mut parser = toml::Parser::new(toml.as_str());
        let toml = match parser.parse() {
            Some(t) => t,
            None => {
                print_error(format!("There was an error parsing the config.toml file: {:?}",
                                    parser.errors),
                            verbose);
                exit(Error::ParseError.into());
            }
        };

        let mut config: Config = Default::default();
        config.app_id = String::from(app_id);
        config.verbose = verbose;
        config.quiet = quiet;
        config.force = force;

        // TODO ONLY IF FILE EXISTS

        for (key, value) in toml {
            match key.as_str() {
                "threads" => {
                    // let max_threads =  as i64;
                    match value {
                        toml::Value::Integer(1...MAX_THREADS) => {
                            config.threads = value.as_integer().unwrap() as u8
                        }
                        _ => {
                            print_warning(format!("The 'threads' option in config.toml must be \
                                                   an integer between 1 and {}. Using default.",
                                                  MAX_THREADS),
                                          verbose)
                        }
                    }
                }
                "downloads_folder" => {
                    match value {
                        toml::Value::String(s) => config.downloads_folder = s,
                        _ => {
                            print_warning("The 'downloads_folder' option in config.toml must be \
                                           an string. Using default.",
                                          verbose)
                        }
                    }
                }
                "dist_folder" => {
                    match value {
                        toml::Value::String(s) => config.dist_folder = s,
                        _ => {
                            print_warning("The 'dist_folder' option in config.toml must be an \
                                           string. Using default.",
                                          verbose)
                        }
                    }
                }
                "results_folder" => {
                    match value {
                        toml::Value::String(s) => config.results_folder = s,
                        _ => {
                            print_warning("The 'results_folder' option in config.toml must be an \
                                           string. Using default.",
                                          verbose)
                        }
                    }
                }
                "apktool_file" => {
                    match value {
                        toml::Value::String(s) => {
                            let extension = Path::new(&s).extension();
                            if extension.is_none() || extension.unwrap() != "jar" {
                                config.apktool_file = s.clone();
                            } else {
                                print_warning("The APKTool file must be a JAR file. Using default.",
                                              verbose)
                            }
                        }
                        _ => {
                            print_warning("The 'apktool_file' option in config.toml must be an \
                                           string. Using default.",
                                          verbose)
                        }
                    }
                }
                "dex2jar_folder" => {
                    match value {
                        toml::Value::String(s) => config.dex2jar_folder = s,
                        _ => {
                            print_warning("The 'dex2jar_folder' option in config.toml should be \
                                           an string. Using default.",
                                          verbose)
                        }
                    }
                }
                "jd_cli_file" => {
                    match value {
                        toml::Value::String(s) => {
                            let extension = Path::new(&s).extension();
                            if extension.is_none() || extension.unwrap() != "jar" {
                                config.jd_cli_file = s.clone();
                            } else {
                                print_warning("The JD-CLI file must be a JAR file. Using default.",
                                              verbose)
                            }
                        }
                        _ => {
                            print_warning("The 'jd_cli_file' option in config.toml must be an \
                                           string. Using default.",
                                          verbose)
                        }
                    }
                }
                "highlight_js" => {
                    match value {
                        toml::Value::String(s) => {
                            let extension = Path::new(&s).extension();
                            if extension.is_none() || extension.unwrap() != "js" {
                                config.highlight_js = s.clone();
                            } else {
                                print_warning("The highlight.js file must be a JavaScript file. \
                                               Using default.",
                                              verbose)
                            }
                        }
                        _ => {
                            print_warning("The 'highlight_js' option in config.toml must be an \
                                           string. Using default.",
                                          verbose)
                        }
                    }
                }
                "highlight_css" => {
                    match value {
                        toml::Value::String(s) => {
                            let extension = Path::new(&s).extension();
                            if extension.is_none() || extension.unwrap() != "css" {
                                config.highlight_css = s.clone();
                            } else {
                                print_warning("The highlight.css file must be a CSS file. Using \
                                               default.",
                                              verbose)
                            }
                        }
                        _ => {
                            print_warning("The 'highlight_css' option in config.toml must be an \
                                           string. Using default.",
                                          verbose)
                        }
                    }
                }
                "results_css" => {
                    match value {
                        toml::Value::String(s) => {
                            let extension = Path::new(&s).extension();
                            if extension.is_none() || extension.unwrap() != "css" {
                                config.results_css = s.clone();
                            } else {
                                print_warning("The results.css file must be a CSS file. Using \
                                               default.",
                                              verbose)
                            }
                        }
                        _ => {
                            print_warning("The 'results_css' option in config.toml must be an \
                                           string. Using default.",
                                          verbose)
                        }
                    }
                }
                "rules_json" => {
                    match value {
                        toml::Value::String(s) => {
                            let extension = Path::new(&s).extension();
                            if extension.is_none() || extension.unwrap() != "json" {
                                config.rules_json = s.clone();
                            } else {
                                print_warning("The rules.json file must be a JSON file. Using \
                                               default.",
                                              verbose)
                            }
                        }
                        _ => {
                            print_warning("The 'rules_json' option in config.toml must be an \
                                           string. Using default.",
                                          verbose)
                        }
                    }
                }
                _ => print_warning(format!("Unknown configuration option {}.", key), verbose),
            }
        }

        Ok(config)
    }

    pub fn check(&self) -> bool {
        // if !check_app_exists(app_id) {
        //     if verbose {
        //         print_error(format!("The application does not exist. It should be named {}.apk
        // and \
        //                              be stored in {}",
        //                             app_id,
        //                             DOWNLOAD_FOLDER),
        //                     true);
        //     } else {
        //         print_error(String::from("The application does not exist."), false);
        //     }
        //     exit(Error::AppNotExists.into());
        // } else if verbose {
        //     println!("Seems that {}. The next step is to decompress it.",
        //              "the app is there".green());
        // }
        true // TODO
    }

    pub fn get_app_id(&self) -> &str {
        self.app_id.as_str()
    }

    pub fn set_app_id(&mut self, app_id: &str) {
        self.app_id = String::from(app_id);
    }

    pub fn is_verbose(&self) -> bool {
        self.verbose
    }

    pub fn set_verbose(&mut self, verbose: bool) {
        self.verbose = verbose;
    }

    pub fn is_quiet(&self) -> bool {
        self.quiet
    }

    pub fn set_quiet(&mut self, quiet: bool) {
        self.quiet = quiet;
    }

    pub fn is_force(&self) -> bool {
        self.force
    }

    pub fn set_force(&mut self, force: bool) {
        self.force = force;
    }

    pub fn get_threads(&self) -> u8 {
        self.threads
    }

    pub fn get_downloads_folder(&self) -> &str {
        self.downloads_folder.as_str()
    }

    pub fn get_dist_folder(&self) -> &str {
        self.dist_folder.as_str()
    }

    pub fn get_results_folder(&self) -> &str {
        self.results_folder.as_str()
    }

    pub fn get_apktool_file(&self) -> &str {
        self.apktool_file.as_str()
    }

    pub fn get_dex2jar_folder(&self) -> &str {
        self.dex2jar_folder.as_str()
    }

    pub fn get_jd_cli_file(&self) -> &str {
        self.jd_cli_file.as_str()
    }

    pub fn get_highlight_js(&self) -> &str {
        self.highlight_js.as_str()
    }

    pub fn get_highlight_css(&self) -> &str {
        self.highlight_css.as_str()
    }

    pub fn get_results_css(&self) -> &str {
        self.results_css.as_str()
    }

    pub fn get_rules_json(&self) -> &str {
        self.rules_json.as_str()
    }
}

impl Default for Config {
    fn default() -> Config {
        Config {
            app_id: String::new(),
            verbose: false,
            quiet: false,
            force: false,
            threads: 2,
            downloads_folder: String::from("downloads"),
            dist_folder: String::from("dist"),
            results_folder: String::from("results"),
            apktool_file: String::from("vendor/apktool_2.1.1.jar"),
            dex2jar_folder: String::from("vendor/dex2jar-2.0"),
            jd_cli_file: String::from("vendor/jd-cli.jar"),
            highlight_js: String::from("vendor/highlight.pack.js"),
            highlight_css: String::from("vendor/highlight.css"),
            results_css: String::from("results.css"),
            rules_json: String::from("rules.json"),
        }
    }
}

#[derive(Debug)]
pub enum Error {
    AppNotExists,
    ParseError,
    CodeNotFound,
    Config,
    IOError(io::Error),
    Unknown,
}

impl Into<i32> for Error {
    fn into(self) -> i32 {
        match self {
            Error::AppNotExists => 10,
            Error::ParseError => 20,
            Error::CodeNotFound => 30,
            Error::Config => 40,
            Error::IOError(_) => 100,
            Error::Unknown => 1,
        }
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Error {
        Error::IOError(err)
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
            Error::ParseError => "there was an error in some parsing process",
            Error::CodeNotFound => "the code was not found in the file",
            Error::Config => "there was an error in the configuration",
            Error::IOError(ref e) => e.description(),
            Error::Unknown => "an unknown error occurred",
        }
    }

    fn cause(&self) -> Option<&StdError> {
        match *self {
            Error::IOError(ref e) => Some(e),
            _ => None,
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Copy, Clone)]
pub enum Criticity {
    Low,
    Medium,
    High,
    Critical,
}

impl Display for Criticity {
    fn fmt(&self, f: &mut fmt::Formatter) -> std::result::Result<(), fmt::Error> {
        write!(f, "{}", format!("{:?}", self).to_lowercase())
    }
}

impl Serialize for Criticity {
    fn serialize<S>(&self, serializer: &mut S) -> result::Result<(), S::Error>
        where S: Serializer
    {
        try!(serializer.serialize_str(format!("{}", self).as_str()));
        Ok(())
    }
}

fn print_error<S: AsRef<str>>(error: S, verbose: bool) {
    io::stderr()
        .write(&format!("{} {}\n", "Error:".bold().red(), error.as_ref().red()).into_bytes()[..])
        .unwrap();

    if !verbose {
        println!("If you need more information, try to run the program again with the {} flag.",
                 "-v".bold());
    }
}

fn print_warning<S: AsRef<str>>(warning: S, verbose: bool) {
    io::stderr()
        .write(&format!("{} {}\n",
                        "Warning:".bold().yellow(),
                        warning.as_ref().yellow())
                    .into_bytes()[..])
        .unwrap();

    if !verbose {
        println!("If you need more information, try to run the program again with the {} flag.",
                 "-v".bold());
    }
}

fn print_vulnerability<S: AsRef<str>>(text: S, criticity: Criticity) {
    let text = text.as_ref();
    let start = format!("Possible {} vulnerability found!:", criticity);
    let (start, message) = match criticity {
        Criticity::Low => (start.cyan(), text.cyan()),
        Criticity::Medium => (start.yellow(), text.yellow()),
        Criticity::High | Criticity::Critical => (start.red(), text.red()),
    };
    println!("{} {}", start, message);
}

fn get_line(code: &str, haystack: &str) -> Result<usize> {
    for (i, line) in code.lines().enumerate() {
        if line.contains(haystack) {
            return Ok(i + 1);
        }
    }

    Err(Error::CodeNotFound)
}

fn get_code(code: &str, line: usize) -> String {
    let mut result = String::new();
    for (i, text) in code.lines().enumerate() {
        if i > (line + 5) {
            break;
        } else if (line >= 5 && i > line - 5) || (line < 5 && i < line + 5) {
            result.push_str(text);
            result.push_str("\n");
        }
    }
    result
}

fn get_help_menu() -> ArgMatches<'static> {
    App::new("Android Anti-Revelation Project")
        .version(crate_version!())
        .author("Iban Eguia <razican@protonmail.ch>")
        .about("Audits Android apps for vulnerabilities")
        .arg(Arg::with_name("id")
                 .help("The ID string of the application to test.")
                 .value_name("ID")
                 .required(true)
                 .takes_value(true))
        .arg(Arg::with_name("verbose")
                 .short("v")
                 .long("verbose")
                 .conflicts_with("quiet")
                 .help("If you'd like the auditor to talk more than neccesary."))
        .arg(Arg::with_name("force")
                 .long("force")
                 .help("If you'd like to force the auditor to do everything from the beginning."))
        .arg(Arg::with_name("quiet")
                 .short("q")
                 .long("quiet")
                 .conflicts_with("verbose")
                 .help("If you'd like a zen auditor that won't talk unless it's 100% neccesary."))
        .get_matches()
}
