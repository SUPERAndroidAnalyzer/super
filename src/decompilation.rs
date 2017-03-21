//! Decompilation module.
//!
//! Handles the extraction, decompression and  decompilation of _.apks_

use std::fs;
use std::path::Path;
use std::process::Command;
use std::error::Error as StdError;

use colored::Colorize;
use abxml::apk::Apk;

use error::*;
use {Config, print_warning, get_package_name};

/// Decompresses the application using _Apktool_.
pub fn decompress<P: AsRef<Path>>(config: &mut Config, package: P) -> Result<()> {
    let path = config.get_dist_folder().join(package.as_ref().file_stem().unwrap());
    if !path.exists() || config.is_force() {
        if path.exists() {
            if config.is_verbose() {
                println!("The application decompression folder exists. But no more…");
            }

            if let Err(e) = fs::remove_dir_all(&path) {
                print_warning(format!("There was an error when removing the decompression \
                                       folder: {}",
                                      e.description()));
            }
        }
        config.set_force();

        if config.is_verbose() {
            println!();
            println!("Decompressing the application…");
        }

        let mut apk = Apk::new(package.as_ref()).chain_err(|| "error loading apk file")?;
        apk.export(&path, true).chain_err(|| "could not decompress the apk file")?;

        if config.is_verbose() {
            println!("{}",
                     format!("The application has been decompressed in {}.",
                             path.display())
                             .green());
        } else if !config.is_quiet() {
            println!("Application decompressed.");
        }
    } else if config.is_verbose() {
        println!("Seems that the application has already been decompressed. There is no need to \
                  do it again.");
    } else {
        println!("Skipping decompression.");
    }

    Ok(())
}

/// Converts _.dex_ files to _.jar_ using _Dex2jar_.
pub fn dex_to_jar<P: AsRef<Path>>(config: &mut Config, package: P) -> Result<()> {
    let package_name = get_package_name(package.as_ref());
    let classes = config.get_dist_folder().join(&package_name).join("classes.jar");
    if config.is_force() || !classes.exists() {
        config.set_force();

        // Command to convert .dex to .jar. using dex2jar.
        // "-o path" to specify an output file
        let output = Command::new(config.get_dex2jar_folder()
                .join(if cfg!(target_family = "windows") {
                    "d2j-dex2jar.bat"
                } else {
                    "d2j-dex2jar.sh"
                })).arg(config.get_dist_folder()
                .join(&package_name)
                .join("classes.dex"))
            .arg("-f")
            .arg("-o")
            .arg(&classes)
            .output()
            .chain_err(|| {
                format!("There was an error when executing the {} to {} conversion command",
                        ".dex".italic(),
                        ".jar".italic())
            })?;

        let stderr = String::from_utf8_lossy(&output.stderr);
        // Here a small hack: seems that dex2jar outputs in stderr even if everything went well,
        // and the status is always success. So the only difference is if we detect the actual
        // exception that was produced. But, the thing is that in some cases it does not return an
        // exception, so we have to check if errors such as "use certain option" occur.
        if !output.status.success() || stderr.find('\n') != Some(stderr.len() - 1) ||
           stderr.contains("use") {
            let message = format!("The {} to {} conversion command returned an error. More info: \
                                 {}",
                                  ".dex".italic(),
                                  ".jar".italic(),
                                  stderr);

            return Err(message.into());
        }

        if config.is_verbose() {
            println!("{}",
                     format!("The application {} {} {}",
                             ".jar".italic(),
                             "file has been generated in".green(),
                             format!("{}", classes.display()).green())
                             .green());
        } else if !config.is_quiet() {
            println!("Jar file generated.");
        }
    } else if config.is_verbose() {
        println!("Seems that there is already a {} file for the application. There is no need to \
                  create it again.",
                 ".jar".italic());
    } else {
        println!("Skipping {} file generation.", ".jar".italic());
    }

    Ok(())
}

/// Decompiles the application using _jd\_cmd_.
pub fn decompile<P: AsRef<Path>>(config: &mut Config, package: P) -> Result<()> {
    let package_name = get_package_name(package.as_ref());
    let out_path = config.get_dist_folder().join(&package_name).join("classes");
    if config.is_force() || !out_path.exists() {
        config.set_force();

        // Command to decompile the application using jd_cmd.
        // "-od path" to specify an output directory
        let output = Command::new("java").arg("-jar")
            .arg(config.get_jd_cmd_file())
            .arg(config.get_dist_folder().join(&package_name).join("classes.jar"))
            .arg("-od")
            .arg(&out_path)
            .output()
            .chain_err(|| "There was an unknown error decompiling the application")?;

        if !output.status.success() {
            let message = format!("The decompilation command returned an error. More info:\n{}",
                                  String::from_utf8_lossy(&output.stdout));
            return Err(message.into());
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
    } else {
        println!("Skipping decompilation.");
    }

    Ok(())
}
