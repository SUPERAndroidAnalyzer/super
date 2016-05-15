use std::fs;
use std::fs::File;
use std::io::{Read, Write};
use std::process::{Command, exit};
use colored::Colorize;
use zip::ZipArchive;

use {Error, Config, print_error, print_warning, file_exists};

pub fn decompress(config: &Config) {
    if config.is_force() &&
       fs::metadata(format!("{}/{}", config.get_dist_folder(), config.get_app_id())).is_ok() {
        if config.is_verbose() {
            println!("The application decompression folder exists. But no more…");
        }

        if let Err(e) = fs::remove_dir_all(format!("{}/{}",
                                                   config.get_dist_folder(),
                                                   config.get_app_id())) {
            print_error(format!("An unknown error occurred when trying to delete the \
                                 decompression folder: {}",
                                e),
                        config.is_verbose());
            exit(Error::Unknown.into());
        }
    }

    let path = format!("{}/{}", config.get_dist_folder(), config.get_app_id());
    if !file_exists(&path) || config.is_force() {
        if file_exists(&path) {
            if let Err(e) = fs::remove_dir_all(&path) {
                print_warning(format!("There was an error when removing the decompression \
                                       folder: {}",
                                      e),
                              config.is_verbose());
            }
        }

        if config.is_verbose() {
            println!("");
            println!("Decompressing the application…");
        }

        let output = Command::new("java")
                         .arg("-jar")
                         .arg(config.get_apktool_file())
                         .arg("d")
                         .arg("-o")
                         .arg(format!("{}/{}", config.get_dist_folder(), config.get_app_id()))
                         .arg("-f")
                         .arg(format!("{}/{}.apk",
                                      config.get_downloads_folder(),
                                      config.get_app_id()))
                         .output();

        let output = match output {
            Ok(o) => o,
            Err(e) => {
                print_error(format!("There was an error when executing the decompression \
                                     command: {}",
                                    e),
                            config.is_verbose());
                exit(Error::Unknown.into());
            }
        };

        if !output.status.success() {
            print_error(format!("The decompression command returned an error. More info: {}",
                                String::from_utf8_lossy(&output.stderr[..])),
                        config.is_verbose());
            exit(Error::Unknown.into());
        }

        if config.is_verbose() {
            println!("{}",
                     format!("The application has been decompressed in {}/{}.",
                             config.get_dist_folder(),
                             config.get_app_id())
                         .green());
        } else if !config.is_quiet() {
            println!("Application decompressed.");
        }
    } else if config.is_verbose() {
        println!("Seems that the application has already been decompressed. There is no need to \
                  do it again.");
    }
}

pub fn extract_dex(config: &Config) {
    if config.is_force() ||
       !file_exists(format!("{}/{}/classes.jar",
                            config.get_dist_folder(),
                            config.get_app_id())) {
        if config.is_verbose() {
            println!("");
            println!("To decompile the app, first we need to extract the {} file.",
                     ".dex".italic());
        }

        let zip = ZipArchive::new(match File::open(format!("{}/{}.apk",
                                                           config.get_downloads_folder(),
                                                           config.get_app_id())) {
            Ok(f) => f,
            Err(e) => {
                print_error(format!("There was an error when decompressing the {} file. More \
                                     info: {}",
                                    ".apk".italic(),
                                    e),
                            config.is_verbose());
                exit(Error::Unknown.into());
            }
        });
        if zip.is_err() {
            print_error(format!("There was an error when decompressing the {} file. More info: \
                                 {}",
                                ".apk".italic(),
                                zip.err().unwrap()),
                        config.is_verbose());
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
                            config.is_verbose());
                exit(Error::Unknown.into());
            }
        };

        let mut out_file = match File::create(format!("{}/{}/classes.dex",
                                                      config.get_dist_folder(),
                                                      config.get_app_id())) {
            Ok(f) => f,
            Err(e) => {
                print_error(format!("There was an error while creating classes.dex file. More \
                                     info: {}",
                                    e),
                            config.is_verbose());
                exit(Error::Unknown.into());
            }
        };

        let mut bytes = Vec::with_capacity(dex_file.size() as usize);
        if let Err(e) = dex_file.read_to_end(&mut bytes) {
            print_error(format!("There was an error while reading classes.dex file from the {}. \
                                 More info: {}",
                                ".apk".italic(),
                                e),
                        config.is_verbose());
            exit(Error::Unknown.into());
        }

        if let Err(e) = out_file.write_all(&bytes[..]) {
            print_error(format!("There was an error while writting classes.dex file. More info: \
                                 {}",
                                e),
                        config.is_verbose());
            exit(Error::Unknown.into());
        }

        if config.is_verbose() {
            println!("{}",
                     format!("The {} {}",
                             ".dex".italic().green(),
                             "file was extracted successfully!".green())
                         .green());
            println!("");
            println!("Now it's time to create the {} file from its classes.",
                     ".jar".italic());
        } else if !config.is_quiet() {
            println!("Dex file extracted.");
        }

        // Converting the dex to jar
        dex_to_jar(config);

    } else if config.is_verbose() {
        println!("Seems that there is already a {} file for the application. There is no need to \
                  create it again.",
                 ".jar".italic());
    }
}

fn dex_to_jar(config: &Config) {
    let output = Command::new(format!("{}/d2j-dex2jar.sh", config.get_dex2jar_folder()))
                     .arg(format!("{}/{}/classes.dex",
                                  config.get_dist_folder(),
                                  config.get_app_id()))
                     .arg("-o")
                     .arg(format!("{}/{}/classes.jar",
                                  config.get_dist_folder(),
                                  config.get_app_id()))
                     .output();

    if output.is_err() {
        print_error(format!("There was an error when executing the {} to {} conversion \
                             command: {}",
                            ".dex".italic(),
                            ".jar".italic(),
                            output.err().unwrap()),
                    config.is_verbose());
        exit(Error::Unknown.into());
    }

    let output = output.unwrap();
    if !output.status.success() {
        print_error(format!("The {} to {} conversion command returned an error. More info: \
                             {}",
                            ".dex".italic(),
                            ".jar".italic(),
                            String::from_utf8_lossy(&output.stderr[..])),
                    config.is_verbose());
        exit(Error::Unknown.into());
    }

    if config.is_verbose() {
        println!("{}",
                 format!("The application {} {} {}",
                         ".jar".italic(),
                         "file has been generated in".green(),
                         format!("{}/{}/classes.jar.",
                                 config.get_dist_folder(),
                                 config.get_app_id())
                             .green())
                     .green());
    } else if !config.is_quiet() {
        println!("Jar file generated.");
    }
}

pub fn decompile(config: &Config) {
    let out_path = format!("{}/{}/classes",
                           config.get_dist_folder(),
                           config.get_app_id());
    if config.is_force() || !file_exists(&out_path) {
        let output = Command::new("java")
                         .arg("-jar")
                         .arg(config.get_jd_cli_file())
                         .arg(format!("{}/{}/classes.jar",
                                      config.get_dist_folder(),
                                      config.get_app_id()))
                         .arg("-od")
                         .arg(&out_path)
                         .output();

        if output.is_err() {
            print_error(format!("There was an unknown error decompiling the application: {}",
                                output.err().unwrap()),
                        config.is_verbose());
            exit(Error::Unknown.into());
        }

        let output = output.unwrap();
        if !output.status.success() {
            print_error(format!("The decompilation command returned an error. More info: {}",
                                String::from_utf8_lossy(&output.stderr[..])),
                        config.is_verbose());
            exit(Error::Unknown.into());
        }

        if config.is_verbose() {
            println!("{}",
                     "The application has been succesfully decompiled!".green());
        } else if !config.is_quiet() {
            println!("Application decompiled.");
        }
    } else if config.is_verbose() {
        println!("Seems that there is already a source folder for the application. There is no \
                  need to decompile it again.");
    }
}
