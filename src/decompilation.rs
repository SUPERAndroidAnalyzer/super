//! Decompilation module.
//!
//! Handles the extraction, decompression and  decompilation of `_.apks_`

use crate::{get_package_name, print_warning, Config};
use abxml::apk::Apk;
use anyhow::{bail, Context, Result};
use colored::Colorize;
use std::{fs, path::Path, process::Command};

/// Decompresses the application using `_Apktool_`.
pub fn decompress<P: AsRef<Path>>(config: &mut Config, package: P) -> Result<()> {
    let path = config
        .dist_folder()
        .join(package.as_ref().file_stem().unwrap());
    if !path.exists() || config.is_force() {
        if path.exists() {
            if config.is_verbose() {
                println!("The application decompression folder existed. But no more!");
            }

            if let Err(e) = fs::remove_dir_all(&path) {
                print_warning(format!(
                    "there was an error when removing the decompression folder: {}",
                    e
                ));
            }
        }
        config.set_force();

        if config.is_verbose() {
            println!();
            println!("Decompressing the application.");
        }

        // TODO: wait for `abxml` upgrade to `anyhow`, use `context()`
        let mut apk = match Apk::from_path(package.as_ref()) {
            Ok(apk) => apk,
            Err(_) => bail!("error loading apk file"),
        };
        // TODO: wait for `abxml` upgrade to `anyhow`, use `with_context()`
        if apk.export(&path, true).is_err() {
            bail!(
                "could not decompress the apk file. Tried to decompile at: {}",
                path.display()
            )
        }

        if config.is_verbose() {
            println!(
                "{}",
                format!(
                    "The application has been decompressed in {}.",
                    path.display()
                )
                .green()
            );
        } else if !config.is_quiet() {
            println!("Application decompressed.");
        }
    } else if config.is_verbose() {
        println!(
            "Seems that the application has already been decompressed. There is no need to do it \
             again."
        );
    } else {
        println!("Skipping decompression.");
    }

    Ok(())
}

/// Converts `_.dex_` files to `_.jar_` using `_Dex2jar_`.
pub fn dex_to_jar<P: AsRef<Path>>(config: &mut Config, package: P) -> Result<()> {
    let package_name = get_package_name(package.as_ref());
    let classes = config.dist_folder().join(&package_name).join("classes.jar");
    if config.is_force() || !classes.exists() {
        config.set_force();

        // Command to convert .dex to .jar. using dex2jar.
        // "-o path" to specify an output file
        let output = Command::new(config.dex2jar_folder().join(
            if cfg!(target_family = "windows") {
                "d2j-dex2jar.bat"
            } else {
                "d2j-dex2jar.sh"
            },
        ))
        .arg(config.dist_folder().join(&package_name).join("classes.dex"))
        .arg("-f")
        .arg("-o")
        .arg(&classes)
        .output()
        .with_context(|| {
            format!(
                "there was an error when executing the {} to {} conversion command",
                ".dex".italic(),
                ".jar".italic()
            )
        })?;

        let stderr = String::from_utf8_lossy(&output.stderr);
        // Here a small hack: seems that dex2jar outputs in stderr even if everything went well,
        // and the status is always success. So the only difference is if we detect the actual
        // exception that was produced. But in some cases it does not return an exception, so we
        // have to check if errors such as "use certain option" occur.
        let mut call_ok = output.status.success() || !stderr.contains("use");
        if stderr.find('\n') != Some(stderr.len() - 1) {
            if stderr.starts_with("Picked up _JAVA_OPTIONS:") {
                call_ok = stderr.lines().count() == 2;
            } else {
                call_ok = false;
            }
        }
        if !call_ok {
            bail!(
                "the {} to {} conversion command returned an error. More info: {}",
                ".dex".italic(),
                ".jar".italic(),
                stderr
            );
        }

        if config.is_verbose() {
            println!(
                "{}",
                format!(
                    "The application {} {} {}",
                    ".jar".italic(),
                    "file has been generated in".green(),
                    format!("{}", classes.display()).green()
                )
                .green()
            );
        } else if !config.is_quiet() {
            println!("Jar file generated.");
        }
    } else if config.is_verbose() {
        println!(
            "Seems that there is already a {} file for the application. There is no need to \
             create it again.",
            ".jar".italic()
        );
    } else {
        println!("Skipping {} file generation.", ".jar".italic());
    }

    Ok(())
}

/// Decompiles the application using `_jd\_cmd_`.
pub fn decompile<P: AsRef<Path>>(config: &mut Config, package: P) -> Result<()> {
    let package_name = get_package_name(package.as_ref());
    let out_path = config.dist_folder().join(&package_name).join("classes");
    if config.is_force() || !out_path.exists() {
        config.set_force();

        // Command to decompile the application using `jd_cmd`.
        // "-od path" to specify an output directory
        let output = Command::new("java")
            .arg("-jar")
            .arg(config.jd_cmd_file())
            .arg(config.dist_folder().join(&package_name).join("classes.jar"))
            .arg("-od")
            .arg(&out_path)
            .output()
            .context("there was an unknown error decompiling the application")?;

        if !output.status.success() {
            bail!(
                "the decompilation command returned an error. More info:\n{}",
                String::from_utf8_lossy(&output.stdout)
            );
        }

        if config.is_verbose() {
            println!(
                "{}",
                "The application has been successfully decompiled!".green()
            );
        } else if !config.is_quiet() {
            println!("Application decompiled.");
        }
    } else if config.is_verbose() {
        println!(
            "Seems that there is already a source folder for the application. There is no need to \
             decompile it again."
        );
    } else {
        println!("Skipping decompilation.");
    }

    Ok(())
}
