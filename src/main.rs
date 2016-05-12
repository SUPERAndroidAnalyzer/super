#[macro_use]
extern crate clap;
extern crate colored;
extern crate zip;

use std::{fs, io};
use std::fs::File;
use std::path::Path;
use std::fmt::Display;
use std::io::{Read, Write};
use std::ffi::OsStr;
use std::process::{Command, exit};
use clap::{Arg, App};
use colored::Colorize;

const DOWNLOAD_FOLDER: &'static str = "downloads";
const VENDOR_FOLDER: &'static str = "vendor";
const DIST_FOLDER: &'static str = "dist";
const RESULTS_FOLDER: &'static str = "results";
const APKTOOL_FILE: &'static str = "apktool_2.1.1.jar";
const DEX2JAR_FOLDER: &'static str = "dex2jar-2.0";
const JD_CLI_FILE: &'static str = "jd-cli.jar";

enum Error {
    AppNotExists,
    Unknown,
}

impl Into<i32> for Error {
    fn into(self) -> i32 {
        match self {
            Error::AppNotExists => 10,
            Error::Unknown => 1,
        }
    }
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

fn main() {
    let matches = App::new("Android Anti-Revelation Project")
                      .version(crate_version!())
                      .author("Iban Eguia <razican@protonmail.ch>")
                      .about("Audits Android apps for vulnerabilities")
                      .arg(Arg::with_name("id")
                               .help("The ID string of the application to test.")
                               .value_name("ID")
                               .required(true)
                               .takes_value(true))
                    //   .arg(Arg::with_name("threads")
                    //            .short("t")
                    //            .long("--threads")
                    //            .value_name("THREADS")
                    //            .takes_value(true)
                    //            .default_value("2")
                    //            .help("Sets the number of threads for the application"))
                      .arg(Arg::with_name("verbose")
                               .short("v")
                               .long("verbose")
                               .conflicts_with("quiet")
                               .help("If you'd like the auditor to talk more than neccesary."))
                      .arg(Arg::with_name("force")
                               .long("force")
                               .help("If you'd like to force the auditor to do evrything from the \
                                      beginning."))
                      .arg(Arg::with_name("quiet")
                               .short("q")
                               .long("quiet")
                               .conflicts_with("verbose")
                               .help("If you'd like a zen auditor that won't talk unless it's 100% \
                                      neccesary."))
                      .get_matches();

    // let threads = matches.value_of("threads").unwrap().parse::<u8>().unwrap();
    let app_id = matches.value_of("id").unwrap();
    let verbose = matches.is_present("verbose");
    let quiet = matches.is_present("quiet");
    let force = matches.is_present("force");

    if verbose {
        println!("Welcome to the Android Anti-Rebelation project. We will now try to audit the \
                  given application.");
        println!("You activated the verbose mode. {}",
                 "May Tux be with you!".bold());
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
        println!("Seems that {}. Now, we are going to decompress it.",
                 "the app is there".bold());
    }

    if force && fs::metadata(format!("{}/{}", DIST_FOLDER, app_id)).is_ok() {
        if verbose {
            println!("The application decompression folder exists. But no more…");
        }

        if let Err(e) = fs::remove_dir_all(format!("{}/{}", DIST_FOLDER, app_id)) {
            print_error(format!("An unknown error occurred when trying to delete the \
                                 decompression folder: {}",
                                e),
                        verbose);
            exit(Error::Unknown.into());
        }
    }

    check_or_create(DIST_FOLDER, verbose);
    if force || !fs::metadata(format!("{}/{}", DIST_FOLDER, app_id)).is_ok() {
        check_or_create(format!("{}/{}", DIST_FOLDER, app_id), verbose);

        if verbose {
            println!("Decompressing the application…");
        }

        let output = Command::new("java")
                         .arg("-jar")
                         .arg(format!("{}/{}", VENDOR_FOLDER, APKTOOL_FILE))
                         .arg("d")
                         .arg("-o")
                         .arg(format!("{}/{}", DIST_FOLDER, app_id))
                         .arg("-f")
                         .arg(format!("{}/{}.apk", DOWNLOAD_FOLDER, &app_id))
                         .output();

        if output.is_err() {
            print_error(format!("There was an error when executing the decompression command: {}",
                                output.err().unwrap()),
                        verbose);
            exit(Error::Unknown.into());
        }

        let output = output.unwrap();
        if !output.status.success() {
            print_error(format!("The decompression command returned an error. More info: {}",
                                String::from_utf8_lossy(&output.stderr[..])),
                        verbose);
            exit(Error::Unknown.into());
        }

        if verbose {
            println!("The application has been decompressed in {}/{}.",
                     DIST_FOLDER,
                     &app_id);
        }
    } else if verbose {
        println!("Seems that the application has already been decompressed. There is no need to \
                  do it again.");
    }

    if force || !fs::metadata(format!("{}/{}/classes.jar", DIST_FOLDER, app_id)).is_ok() {
        if verbose {
            println!("");
            println!("To decompile the app, first we need to extract the {} file.",
                     ".dex".italic());
        }

        let zip = zip::ZipArchive::new(match File::open(format!("{}/{}.apk",
                                                                DOWNLOAD_FOLDER,
                                                                &app_id)) {
            Ok(f) => f,
            Err(e) => {
                print_error(format!("There was an error when decompressing the {} file. More \
                                     info: {}",
                                    ".apk".italic(),
                                    e),
                            verbose);
                exit(Error::Unknown.into());
            }
        });
        if zip.is_err() {
            print_error(format!("There was an error when decompressing the {} file. More info: \
                                 {}",
                                ".apk".italic(),
                                zip.err().unwrap()),
                        verbose);
            exit(Error::Unknown.into());
        }

        let mut zip = zip.unwrap();
        let mut dex_file = match zip.by_name("classes.dex") {
            Ok(f) => f,
            Err(e) => {
                print_error(format!("There was an error while finding the classes.dex file \
                                     inside the {} file. More info: {}",
                                    ".apk".italic(),
                                    e),
                            verbose);
                exit(Error::Unknown.into());
            }
        };

        let mut out_file = match File::create(format!("{}/{}/classes.dex", DIST_FOLDER, &app_id)) {
            Ok(f) => f,
            Err(e) => {
                print_error(format!("There was an error while creating classes.dex file. More \
                                     info: {}",
                                    e),
                            verbose);
                exit(Error::Unknown.into());
            }
        };

        let mut bytes = Vec::with_capacity(dex_file.size() as usize);
        if let Err(e) = dex_file.read_to_end(&mut bytes) {
            print_error(format!("There was an error while reading classes.dex file from the {}. \
                                 More info: {}",
                                ".apk".italic(),
                                e),
                        verbose);
            exit(Error::Unknown.into());
        }

        if let Err(e) = out_file.write_all(&bytes[..]) {
            print_error(format!("There was an error while writting classes.dex file. More info: \
                                 {}",
                                e),
                        verbose);
            exit(Error::Unknown.into());
        }

        if verbose {
            println!("The {} file was extracted successfully!", ".dex".italic());
            println!("Now it's time to create the {} file from it's classes.",
                     ".jar".italic());
        }

        let output = Command::new(format!("{}/{}/d2j-dex2jar.sh", VENDOR_FOLDER, DEX2JAR_FOLDER))
                         .arg(format!("{}/{}/classes.dex", DIST_FOLDER, &app_id))
                         .arg("-o")
                         .arg(format!("{}/{}/classes.jar", DIST_FOLDER, &app_id))
                         .output();

        if output.is_err() {
            print_error(format!("There was an error when executing the {} to {} conversion \
                                 command: {}",
                                ".dex".italic(),
                                ".jar".italic(),
                                output.err().unwrap()),
                        verbose);
            exit(Error::Unknown.into());
        }

        let output = output.unwrap();
        if !output.status.success() {
            print_error(format!("The {} to {} conversion command returned an error. More info: \
                                 {}",
                                ".dex".italic(),
                                ".jar".italic(),
                                String::from_utf8_lossy(&output.stderr[..])),
                        verbose);
            exit(Error::Unknown.into());
        }

        if verbose {
            println!("The application {} file has been generated in  {}/{}/classes.jar.",
                     ".jar".italic(),
                     DIST_FOLDER,
                     &app_id);
        }
    } else if verbose {
        println!("Seems that there is already a {} file for the application. There is no need to \
                  create it again.",
                 ".jar".italic());
    }

    // TODO decompile app
    // TODO check app
}

fn check_app_exists(id: &str) -> bool {
    fs::metadata(format!("{}/{}.apk", DOWNLOAD_FOLDER, id)).is_ok()
}

pub fn check_or_create<P: AsRef<Path> + Display>(path: P, verbose: bool) {
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
            println!("{} folder created.", path);
        }
    }
}
