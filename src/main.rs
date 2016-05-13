#[macro_use]
extern crate clap;
extern crate colored;
extern crate zip;
extern crate xml;

mod decompilation;
mod static_analysis;

use std::{fs, io, fmt};
use std::path::Path;
use std::fmt::Display;
use std::convert::From;
use std::error::Error as StdError;
use std::io::Write;
use std::ffi::OsStr;
use std::process::exit;
use clap::{Arg, App, ArgMatches};
use colored::Colorize;

use decompilation::*;
use static_analysis::*;

const DOWNLOAD_FOLDER: &'static str = "downloads";
const VENDOR_FOLDER: &'static str = "vendor";
const DIST_FOLDER: &'static str = "dist";
const RESULTS_FOLDER: &'static str = "results";
const APKTOOL_FILE: &'static str = "apktool_2.1.1.jar";
const DEX2JAR_FOLDER: &'static str = "dex2jar-2.0";
const JD_CLI_FILE: &'static str = "jd-cli.jar";

#[derive(Debug)]
enum Error {
    AppNotExists,
    IOError(io::Error),
    Unknown,
}

impl Into<i32> for Error {
    fn into(self) -> i32 {
        match self {
            Error::AppNotExists => 10,
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

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.description())
    }
}

impl StdError for Error {
    fn description(&self) -> &str {
        match *self {
            Error::AppNotExists => "The application has not been found.",
            Error::IOError(ref e) => e.description(),
            Error::Unknown => "An unknown error occurred.",
        }
    }

    fn cause(&self) -> Option<&StdError> {
        match *self {
            Error::IOError(ref e) => Some(e),
            _ => None,
        }
    }
}

type Result<T> = std::result::Result<T, Error>;

enum Criticity {
    Low,
    Medium,
    High,
    Critical,
}

fn print_error<S: AsRef<OsStr>>(error: S, verbose: bool) {
    io::stderr()
        .write(&format!("{} {}",
                        "Error:".bold().red(),
                        error.as_ref().to_string_lossy().red())
                    .into_bytes()[..])
        .unwrap();

    if !verbose {
        println!("If you need more information, try to run the program again with the {} flag.",
                 "-v".bold());
    }
}

fn print_warning<S: AsRef<OsStr>>(warning: S, verbose: bool) {
    io::stderr()
        .write(&format!("{} {}",
                        "Warning:".bold().yellow(),
                        warning.as_ref().to_string_lossy().yellow())
                    .into_bytes()[..])
        .unwrap();

    if !verbose {
        println!("If you need more information, try to run the program again with the {} flag.",
                 "-v".bold());
    }
}

fn print_vulnerability<S: AsRef<OsStr>>(text: S, criticity: Criticity) {
    let text = text.as_ref().to_string_lossy();
    let message = match criticity {
        Criticity::Low => text.cyan(),
        Criticity::Medium => text.yellow(),
        Criticity::High | Criticity::Critical => text.red(),
    };
    println!("Possible vulnerability found!: {}", text);
}

fn main() {
    let matches = get_help_menu();

    let app_id = matches.value_of("id").unwrap();
    let verbose = matches.is_present("verbose");
    let quiet = matches.is_present("quiet");
    let force = matches.is_present("force");
    // let threads = matches.value_of("threads").unwrap().parse::<u8>().unwrap();

    if verbose {
        println!("Welcome to the Android Anti-Rebelation project. We will now try to audit the \
                  given application.");
        println!("You activated the verbose mode. {}",
                 "May Tux be with you!".bold());
        println!("");
        println!("Let's first check if the application actually exists.");
    }

    if !check_app_exists(app_id) {
        if verbose {
            print_error(format!("The application does not exist. It should be named {}.apk and \
                                 be stored in {}",
                                app_id,
                                DOWNLOAD_FOLDER),
                        true);
        } else {
            print_error(String::from("The application does not exist."), false);
        }
        exit(Error::AppNotExists.into());
    } else if verbose {
        println!("Seems that {}. The next step is to decompress it.",
                 "the app is there".green());
    }

    // APKTool app decompression
    decompress(app_id, verbose, quiet, force);

    // Extracting the classes.dex from the .apk file
    extract_dex(app_id, verbose, quiet, force);

    if verbose {
        println!("");
        println!("Now it's time for the actual decompilation of the source code. We'll translate \
                  Android JVM bytecode to Java, so that we can check the code afterwards.");
    }

    // Decompiling the app
    decompile(&app_id, verbose, quiet, force);

    // Static application analysis
    static_analysis(&app_id, verbose, quiet);

    // TODO dynamic analysis
}

fn check_app_exists(id: &str) -> bool {
    fs::metadata(format!("{}/{}.apk", DOWNLOAD_FOLDER, id)).is_ok()
}

fn check_or_create<P: AsRef<Path> + Display>(path: P, verbose: bool) {
    if !fs::metadata(&path).is_ok() {
        if verbose {
            println!("Seems the {} folder is not there. Trying to create…",
                     path);
        }

        if let Err(e) = fs::create_dir(&path) {
            print_error(format!("There was an error when creating the folder {}: {}",
                                path,
                                e),
                        verbose);
            exit(Error::Unknown.into());
        }

        if verbose {
            println!("{}", format!("{} folder created.", path).green());
        }
    }
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
        // .arg(Arg::with_name("threads")
        //          .short("t")
        //          .long("--threads")
        //          .value_name("THREADS")
        //          .takes_value(true)
        //          .default_value("2")
        //          .help("Sets the number of threads for the application"))
        .arg(Arg::with_name("verbose")
                 .short("v")
                 .long("verbose")
                 .conflicts_with("quiet")
                 .help("If you'd like the auditor to talk more than neccesary."))
        .arg(Arg::with_name("force")
                 .long("force")
                 .help("If you'd like to force the auditor to do evrything from the beginning."))
        .arg(Arg::with_name("quiet")
                 .short("q")
                 .long("quiet")
                 .conflicts_with("verbose")
                 .help("If you'd like a zen auditor that won't talk unless it's 100% neccesary."))
        .get_matches()
}
