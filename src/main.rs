#[macro_use]
extern crate clap;
extern crate colored;
extern crate zip;
extern crate xml;
extern crate serde;
extern crate serde_json;
extern crate chrono;
extern crate toml;
extern crate regex;

mod decompilation;
mod static_analysis;
mod results;

use std::{fs, io, fmt, result};
use std::path::Path;
use std::fmt::Display;
use std::convert::From;
use std::str::FromStr;
use std::error::Error as StdError;
use std::io::{Read, Write};
use std::process::exit;
use std::collections::btree_set::Iter;
use std::collections::BTreeSet;
use std::cmp::{PartialOrd, Ordering};

use serde::ser::{Serialize, Serializer};
use serde_json::error::ErrorCode as JSONErrorCode;
use clap::{Arg, App, ArgMatches};
use colored::Colorize;

use decompilation::*;
use static_analysis::*;
use static_analysis::manifest::Permission;
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
            print_warning(format!("There was an error when reading the config.toml file: {}",
                                  e),
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
            print_error(format!("There is an error with the configuration: {:?}", config),
                        verbose);
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
                    println!("I will now analyze myself for vulnerabilities…");
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

#[derive(Debug, Ord, Eq)]
pub struct PermissionConfig {
    permission: Permission,
    criticity: Criticity,
    label: String,
    description: String,
}

impl PartialEq for PermissionConfig {
    fn eq(&self, other: &PermissionConfig) -> bool {
        self.permission == other.permission
    }
}

impl PartialOrd for PermissionConfig {
    fn partial_cmp(&self, other: &PermissionConfig) -> Option<Ordering> {
        if self.permission < other.permission {
            Some(Ordering::Less)
        } else if self.permission > other.permission {
            Some(Ordering::Greater)
        } else {
            Some(Ordering::Equal)
        }
    }
}

impl PermissionConfig {
    fn new(permission: Permission,
           criticity: Criticity,
           label: &str,
           description: &str)
           -> PermissionConfig {
        PermissionConfig {
            permission: permission,
            criticity: criticity,
            label: String::from(label),
            description: String::from(description),
        }
    }

    pub fn get_permission(&self) -> Permission {
        self.permission
    }

    pub fn get_criticity(&self) -> Criticity {
        self.criticity
    }

    pub fn get_label(&self) -> &str {
        self.label.as_str()
    }

    pub fn get_description(&self) -> &str {
        self.description.as_str()
    }
}

#[derive(Debug)]
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
    jd_cmd_file: String,
    results_template: String,
    rules_json: String,
    unknown_permission: (Criticity, String),
    permissions: BTreeSet<PermissionConfig>,
}

impl Config {
    pub fn new(app_id: &str, verbose: bool, quiet: bool, force: bool) -> Result<Config> {
        let mut config: Config = Default::default();
        config.app_id = String::from(app_id);
        config.verbose = verbose;
        config.quiet = quiet;
        config.force = force;

        if Path::new("config.toml").exists() {
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

            for (key, value) in toml {
                match key.as_str() {
                    "threads" => {
                        // let max_threads =  as i64;
                        match value {
                            toml::Value::Integer(1...MAX_THREADS) => {
                                config.threads = value.as_integer().unwrap() as u8
                            }
                            _ => {
                                print_warning(format!("The 'threads' option in config.toml must \
                                                       be an integer between 1 and {}.\nUsing \
                                                       default.",
                                                      MAX_THREADS),
                                              verbose)
                            }
                        }
                    }
                    "downloads_folder" => {
                        match value {
                            toml::Value::String(s) => config.downloads_folder = s,
                            _ => {
                                print_warning("The 'downloads_folder' option in config.toml must \
                                               be an string.\nUsing default.",
                                              verbose)
                            }
                        }
                    }
                    "dist_folder" => {
                        match value {
                            toml::Value::String(s) => config.dist_folder = s,
                            _ => {
                                print_warning("The 'dist_folder' option in config.toml must be an \
                                               string.\nUsing default.",
                                              verbose)
                            }
                        }
                    }
                    "results_folder" => {
                        match value {
                            toml::Value::String(s) => config.results_folder = s,
                            _ => {
                                print_warning("The 'results_folder' option in config.toml must be \
                                               an string.\nUsing default.",
                                              verbose)
                            }
                        }
                    }
                    "apktool_file" => {
                        match value {
                            toml::Value::String(s) => {
                                let extension = Path::new(&s).extension();
                                if extension.is_some() && extension.unwrap() == "jar" {
                                    config.apktool_file = s.clone();
                                } else {
                                    print_warning("The APKTool file must be a JAR file.\nUsing \
                                                   default.",
                                                  verbose)
                                }
                            }
                            _ => {
                                print_warning("The 'apktool_file' option in config.toml must be \
                                               an string.\nUsing default.",
                                              verbose)
                            }
                        }
                    }
                    "dex2jar_folder" => {
                        match value {
                            toml::Value::String(s) => config.dex2jar_folder = s,
                            _ => {
                                print_warning("The 'dex2jar_folder' option in config.toml should \
                                               be an string.\nUsing default.",
                                              verbose)
                            }
                        }
                    }
                    "jd_cmd_file" => {
                        match value {
                            toml::Value::String(s) => {
                                let extension = Path::new(&s).extension();
                                if extension.is_some() && extension.unwrap() == "jar" {
                                    config.jd_cmd_file = s.clone();
                                } else {
                                    print_warning("The JD-CMD file must be a JAR file.\nUsing \
                                                   default.",
                                                  verbose)
                                }
                            }
                            _ => {
                                print_warning("The 'jd_cmd_file' option in config.toml must be an \
                                               string.\nUsing default.",
                                              verbose)
                            }
                        }
                    }
                    "results_template" => {
                        match value {
                            toml::Value::String(s) => config.results_template = s,
                            _ => {
                                print_warning("The 'results_template' option in config.toml \
                                               should be an string.\nUsing default.",
                                              verbose)
                            }
                        }
                    }
                    "rules_json" => {
                        match value {
                            toml::Value::String(s) => {
                                let extension = Path::new(&s).extension();
                                if extension.is_some() && extension.unwrap() == "json" {
                                    config.rules_json = s.clone();
                                } else {
                                    print_warning("The rules.json file must be a JSON \
                                                   file.\nUsing default.",
                                                  verbose)
                                }
                            }
                            _ => {
                                print_warning("The 'rules_json' option in config.toml must be an \
                                               string.\nUsing default.",
                                              verbose)
                            }
                        }
                    }
                    "permissions" => {
                        match value {
                            toml::Value::Array(p) => {
                                let format_warning =
                                    format!("The permission configuration format must be the \
                                             following:\n{}\nUsing default.",
                                            "[[permissions]]\nname=\"unknown|permission.name\"\n\
                                            criticity = \"low|medium|high|critical\"\n\
                                            label = \"Permission label\"\n\
                                            description = \"Long description to explain the \
                                            vulnerability\""
                                                .italic());

                                for cfg in p {
                                    let cfg = match cfg.as_table() {
                                        Some(t) => t,
                                        None => {
                                            print_warning(format_warning, verbose);
                                            break;
                                        }
                                    };

                                    let name = match cfg.get("name") {
                                        Some(&toml::Value::String(ref n)) => n,
                                        _ => {
                                            print_warning(format_warning, verbose);
                                            break;
                                        }
                                    };

                                    let criticity = match cfg.get("criticity") {
                                        Some(&toml::Value::String(ref c)) => {
                                            match Criticity::from_str(c) {
                                                Ok(c) => c,
                                                Err(_) => {
                                                    print_warning(format!("Criticity must be \
                                                                           one of {}, {}, {} or \
                                                                           {}.\nUsing default.",
                                                                          "low".italic(),
                                                                          "medium".italic(),
                                                                          "high".italic(),
                                                                          "critical".italic()),
                                                                  verbose);
                                                    break;
                                                }
                                            }
                                        }
                                        _ => {
                                            print_warning(format_warning, verbose);
                                            break;
                                        }
                                    };

                                    let description = match cfg.get("description") {
                                        Some(&toml::Value::String(ref d)) => d,
                                        _ => {
                                            print_warning(format_warning, verbose);
                                            break;
                                        }
                                    };

                                    if name == "unknown" {
                                        if cfg.len() != 3 {
                                            print_warning(format!("The format for the unknown \
                                            permissions is the following:\n{}\nUsing default.",
                                            "[[permissions]]\nname = \"unknown\"\n\
                                            criticity = \"low|medium|high|criticity\"\n\
                                            description = \"Long description to explain the \
                                            vulnerability\"".italic()),
                                                          verbose);
                                            break;
                                        }

                                        config.unknown_permission = (criticity,
                                                                     description.clone());
                                    } else {
                                        if cfg.len() != 4 {
                                            print_warning(format_warning, verbose);
                                            break;
                                        }

                                        let permission =
                                            match Permission::from_str(name.as_str()) {
                                                Ok(p) => p,
                                                Err(_) => {
                                                    print_warning(format!("Unknown permission: \
                                                                           {}\nTo set the \
                                                                           default vulnerability \
                                                                           level for an unknown \
                                                                           permission, please, \
                                                                           use the {} \
                                                                           permission name, \
                                                                           under the {} section.",
                                                                          name.italic(),
                                                                          "unknown".italic(),
                                                                          "[[permissions]]"
                                                                              .italic()),
                                                                  verbose);
                                                    break;
                                                }
                                            };

                                        let label = match cfg.get("label") {
                                            Some(&toml::Value::String(ref l)) => l,
                                            _ => {
                                                print_warning(format_warning, verbose);
                                                break;
                                            }
                                        };
                                        config.permissions
                                            .insert(PermissionConfig::new(permission,
                                                                          criticity,
                                                                          label,
                                                                          description.as_str()));
                                    }
                                }
                            }
                            _ => {
                                print_warning("You must specify the permissions you want to \
                                               select as vulnerable.",
                                              verbose)
                            }
                        }
                    }
                    _ => print_warning(format!("Unknown configuration option {}.", key), verbose),
                }
            }
        }

        Ok(config)
    }

    pub fn check(&self) -> bool {
        file_exists(self.downloads_folder.as_str()) && file_exists(self.apktool_file.as_str()) &&
        file_exists(self.dex2jar_folder.as_str()) &&
        file_exists(self.jd_cmd_file.as_str()) &&
        file_exists(self.results_template.as_str()) && file_exists(self.rules_json.as_str())
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

    pub fn get_jd_cmd_file(&self) -> &str {
        self.jd_cmd_file.as_str()
    }

    pub fn get_results_template(&self) -> &str {
        self.results_template.as_str()
    }

    pub fn get_rules_json(&self) -> &str {
        self.rules_json.as_str()
    }

    pub fn get_unknown_permission_criticity(&self) -> Criticity {
        self.unknown_permission.0
    }

    pub fn get_unknown_permission_description(&self) -> &str {
        self.unknown_permission.1.as_str()
    }

    pub fn get_permissions(&self) -> Iter<PermissionConfig> {
        self.permissions.iter()
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
            jd_cmd_file: String::from("vendor/jd-cmd.jar"),
            results_template: String::from("vendor/results_template"),
            rules_json: String::from("rules.json"),
            unknown_permission: (Criticity::Low,
                                 String::from("Even if the application can create its own \
                                               permissions, it's discouraged, since it can lead \
                                               to missunderstanding between developers.")),
            permissions: BTreeSet::new(),
        }
    }
}

#[derive(Debug)]
pub enum Error {
    AppNotExists,
    ParseError,
    JSONError(JSONError),
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
            Error::JSONError(_) => 30,
            Error::CodeNotFound => 40,
            Error::Config => 50,
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

impl From<serde_json::error::Error> for Error {
    fn from(err: serde_json::error::Error) -> Error {
        match err {
            serde_json::error::Error::Syntax(code, line, column) => {
                Error::JSONError(JSONError::new(code, line, column))
            }
            serde_json::error::Error::Io(err) => Error::IOError(err),
            serde_json::error::Error::FromUtf8(_) => Error::ParseError,
        }
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
            Error::JSONError(ref e) => e.description(),
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

#[derive(Debug)]
pub struct JSONError {
    code: JSONErrorCode,
    description: String,
    line: usize,
    column: usize,
}

impl JSONError {
    fn new(code: JSONErrorCode, line: usize, column: usize) -> JSONError {
        let desc = format!("{:?} at line {} column {}", code, line, column);
        JSONError {
            code: code,
            description: desc,
            line: line,
            column: column,
        }
    }
    fn description(&self) -> &str {
        self.description.as_str()
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

impl FromStr for Criticity {
    type Err = Error;
    fn from_str(s: &str) -> Result<Criticity> {
        match s.to_lowercase().as_str() {
            "low" => Ok(Criticity::Low),
            "medium" => Ok(Criticity::Medium),
            "high" => Ok(Criticity::High),
            "critical" => Ok(Criticity::Critical),
            _ => Err(Error::ParseError),
        }
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
    let start = format!("Possible {} criticity vulnerability found!:", criticity);
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

/// Copies the contents of `from` to `to`
///
/// If the destination folder doesn't exist is created. Note that the parent folder must exist. If
/// files in the destination folder exist with the same name as in the origin folder, they will be
/// overwriten.
pub fn copy_folder<P: AsRef<Path>>(from: P, to: P) -> Result<()> {
    if !to.as_ref().exists() {
        try!(fs::create_dir(to.as_ref()));
    }

    for f in try!(fs::read_dir(from.as_ref())) {
        let f = try!(f);
        if f.path().is_dir() {
            try!(copy_folder(f.path(), to.as_ref().join(f.path().file_name().unwrap())));
        } else {
            try!(fs::copy(f.path(), to.as_ref().join(f.path().file_name().unwrap())));
        }
    }
    Ok(())
}
