use std::fs;
use std::fs::File;
use std::io::{Read, Write};
use std::process::{Command, exit};
use colored::Colorize;
use zip::ZipArchive;

use {Error, DOWNLOAD_FOLDER, DIST_FOLDER, VENDOR_FOLDER, APKTOOL_FILE, JD_CLI_FILE,
     DEX2JAR_FOLDER, check_or_create, print_error};

pub fn decompress(app_id: &str, verbose: bool, quiet: bool, force: bool) {
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
            println!("");
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
            println!("{}",
                     format!("The application has been decompressed in {}/{}.",
                             DIST_FOLDER,
                             &app_id)
                         .green());
        } else if !quiet {
            println!("Application decompressed.");
        }
    } else if verbose {
        println!("Seems that the application has already been decompressed. There is no need to \
                  do it again.");
    }
}

pub fn extract_dex(app_id: &str, verbose: bool, quiet: bool, force: bool) {
    if force || !fs::metadata(format!("{}/{}/classes.jar", DIST_FOLDER, app_id)).is_ok() {
        if verbose {
            println!("");
            println!("To decompile the app, first we need to extract the {} file.",
                     ".dex".italic());
        }

        let zip =
            ZipArchive::new(match File::open(format!("{}/{}.apk", DOWNLOAD_FOLDER, &app_id)) {
                Ok(f) => f,
                Err(e) => {
                    print_error(format!("There was an error when decompressing the {} file. \
                                         More info: {}",
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
            println!("{}",
                     format!("The {} {}",
                             ".dex".italic().green(),
                             "file was extracted successfully!".green())
                         .green());
            println!("");
            println!("Now it's time to create the {} file from its classes.",
                     ".jar".italic());
        } else if !quiet {
            println!("Dex file extracted.");
        }

        // Converting the dex to jar
        dex_to_jar(app_id, verbose, quiet);

    } else if verbose {
        println!("Seems that there is already a {} file for the application. There is no need to \
                  create it again.",
                 ".jar".italic());
    }
}

fn dex_to_jar(app_id: &str, verbose: bool, quiet: bool) {
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
        println!("{}",
                 format!("The application {} {} {}",
                         ".jar".italic(),
                         "file has been generated in".green(),
                         format!("{}/{}/classes.jar.", DIST_FOLDER, &app_id).green())
                     .green());
    } else if !quiet {
        println!("Jar file generated.");
    }
}

pub fn decompile(app_id: &str, verbose: bool, quiet: bool, force: bool) {
    if force || !fs::metadata(format!("{}/{}/src", DIST_FOLDER, app_id)).is_ok() {
        let output = Command::new("java")
            .arg("-jar")
            .arg(format!("{}/{}", VENDOR_FOLDER, JD_CLI_FILE))
            .arg(format!("{}/{}/classes.jar", DIST_FOLDER, app_id))
            .arg("-od")
            .arg(format!("{}/{}/src", DIST_FOLDER, app_id))
            .output();

        if output.is_err() {
            print_error(format!("There was an unknown error decompiling the application: {}",
                                output.err().unwrap()),
                        verbose);
            exit(Error::Unknown.into());
        }

        let output = output.unwrap();
        if !output.status.success() {
            print_error(format!("The decompilation command returned an error. More info: {}",
                                String::from_utf8_lossy(&output.stderr[..])),
                        verbose);
            exit(Error::Unknown.into());
        }

        if verbose {
            println!("{}",
                     "The application has been succesfully decompiled!".green());
        } else if !quiet {
            println!("Application decompiled.");
        }
    } else if verbose {
        println!("Seems that there is already a source folder for the application. There is no \
                  need to decompile it again.");
    }
}
