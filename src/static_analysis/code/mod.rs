//! Code analysis module.

mod rule;
#[cfg(test)]
mod tests;

use super::manifest::Manifest;
use crate::{
    get_code, print_vulnerability, print_warning,
    results::{Results, Vulnerability},
    Config,
};
use anyhow::Result;
use colored::Colorize;
use regex::Regex;
use rule::{load_rules, Rule};
use std::{
    borrow::Borrow,
    ffi::OsStr,
    fs::{self, DirEntry},
    path::Path,
    sync::{Arc, Mutex},
    thread,
};

/// Analyzes the whole codebase of the application.
pub fn analysis<S: AsRef<str>>(
    manifest: Option<Manifest>,
    config: &Config,
    package: S,
    results: &mut Results,
) {
    let rules = match load_rules(config) {
        Ok(r) => r,
        Err(e) => {
            print_warning(format!(
                "An error occurred when loading code analysis rules. Error: {}",
                e
            ));
            return;
        }
    };

    let mut files: Vec<DirEntry> = Vec::new();
    if let Err(e) = add_files_to_vec("", &mut files, package.as_ref(), config) {
        print_warning(format!(
            "An error occurred when reading files for analysis, the results might be incomplete. \
             Error: {}",
            e
        ));
    }
    let total_files = files.len();

    let rules = Arc::new(rules);
    let manifest = Arc::new(manifest);
    let found_vulnerabilities: Arc<Mutex<Vec<Vulnerability>>> = Arc::new(Mutex::new(Vec::new()));
    let files = Arc::new(Mutex::new(files));
    let dist_folder = Arc::new(config.dist_folder().join(package.as_ref()));

    if config.is_verbose() {
        println!(
            "Starting analysis of the code with {} threads. {} files to go!",
            format!("{}", config.threads()).bold(),
            format!("{}", total_files).bold()
        );
    }

    let handles: Vec<_> = (0..config.threads())
        .map(|_| {
            let thread_manifest = Arc::clone(&manifest);
            let thread_files = Arc::clone(&files);
            let thread_rules = Arc::clone(&rules);
            let thread_vulnerabilities = Arc::clone(&found_vulnerabilities);
            let thread_dist_folder = Arc::clone(&dist_folder);

            thread::spawn(move || {
                while let Some(f) = thread_files.lock().unwrap().pop() {
                    if let Err(e) = analyze_file(
                        f.path(),
                        &*thread_dist_folder,
                        &thread_rules,
                        &thread_manifest,
                        &thread_vulnerabilities,
                    ) {
                        print_warning(format!(
                            "could not analyze `{}`. The analysis will continue, though. \
                             Error: {}",
                            f.path().display(),
                            e
                        ))
                    }
                }
            })
        })
        .collect();

    if config.is_verbose() {
        let mut last_print = 0;

        while files.lock().map(|f| f.len()).unwrap_or(1) > 0 {
            let left = if let Ok(f) = files.lock() {
                f.len()
            } else {
                continue;
            };

            let done = total_files - left;
            if done - last_print > total_files / 10 {
                last_print = done;
                println!("{} files already analyzed.", last_print);
            }
        }
    }

    for t in handles {
        if let Err(e) = t.join() {
            #[allow(clippy::use_debug)]
            print_warning(format!(
                "an error occurred when joining analysis threads: Error: {:?}",
                e
            ));
        }
    }

    for vulnerability in Arc::try_unwrap(found_vulnerabilities)
        .unwrap()
        .into_inner()
        .unwrap()
    {
        results.add_vulnerability(vulnerability);
    }

    if config.is_verbose() {
        println!();
        println!("{}", "The source code was analyzed correctly!".green());
    } else if !config.is_quiet() {
        println!("Source code analyzed.");
    }
}

/// Analyzes the given file.
fn analyze_file<P: AsRef<Path>, T: AsRef<Path>>(
    path: P,
    dist_folder: T,
    rules: &[Rule],
    manifest: &Option<Manifest>,
    results: &Mutex<Vec<Vulnerability>>,
) -> Result<()> {
    let code = fs::read_to_string(&path)?;

    'check: for rule in rules {
        if manifest.is_some()
            && rule.max_sdk().is_some()
            && rule.max_sdk().unwrap() < manifest.as_ref().unwrap().min_sdk()
        {
            continue 'check;
        }

        let filename = path.as_ref().file_name().and_then(OsStr::to_str);

        if let Some(f) = filename {
            if !rule.has_to_check(f) {
                continue 'check;
            }
        }

        for permission in rule.permissions() {
            if manifest.is_none()
                || !manifest
                    .as_ref()
                    .unwrap()
                    .permission_checklist()
                    .needs_permission(*permission)
            {
                continue 'check;
            }
        }

        'rule: for m in rule.regex().find_iter(code.as_str()) {
            for white in rule.whitelist() {
                if white.is_match(&code[m.start()..m.end()]) {
                    continue 'rule;
                }
            }
            if let Some(check) = rule.forward_check() {
                let caps = rule.regex().captures(&code[m.start()..m.end()]).unwrap();

                let forward_check1 = caps.name("fc1");
                let forward_check2 = caps.name("fc2");
                let mut r = check.clone();

                if let Some(fc1) = forward_check1 {
                    r = r.replace("{fc1}", fc1.as_str());
                }

                if let Some(fc2) = forward_check2 {
                    r = r.replace("{fc2}", fc2.as_str());
                }

                let regex = match Regex::new(r.as_str()) {
                    Ok(r) => r,
                    Err(e) => {
                        print_warning(format!(
                            "there was an error creating the forward_check '{}'. The rule will \
                             be skipped. {}",
                            r, e
                        ));
                        break 'rule;
                    }
                };

                for m in regex.find_iter(code.as_str()) {
                    let start_line = get_line_for(m.start(), code.as_str());
                    let end_line = get_line_for(m.end(), code.as_str());
                    let mut results = results.lock().unwrap();
                    results.push(Vulnerability::new(
                        rule.criticality(),
                        rule.label(),
                        rule.description(),
                        Some(path.as_ref().strip_prefix(&dist_folder).unwrap()),
                        Some(start_line),
                        Some(end_line),
                        Some(get_code(code.as_str(), start_line, end_line)),
                    ));

                    print_vulnerability(rule.description(), rule.criticality());
                }
            } else {
                let start_line = get_line_for(m.start(), code.as_str());
                let end_line = get_line_for(m.end(), code.as_str());
                let mut results = results.lock().unwrap();
                results.push(Vulnerability::new(
                    rule.criticality(),
                    rule.label(),
                    rule.description(),
                    Some(path.as_ref().strip_prefix(&dist_folder).unwrap()),
                    Some(start_line),
                    Some(end_line),
                    Some(get_code(code.as_str(), start_line, end_line)),
                ));

                print_vulnerability(rule.description(), rule.criticality());
            }
        }
    }

    Ok(())
}

fn get_line_for<S: AsRef<str>>(index: usize, text: S) -> usize {
    let mut line = 0;
    for (i, c) in text.as_ref().char_indices() {
        if i == index {
            break;
        }
        if c == '\n' {
            line += 1
        }
    }
    line
}

fn add_files_to_vec<P: AsRef<Path>, S: AsRef<str>>(
    path: P,
    vec: &mut Vec<DirEntry>,
    package: S,
    config: &Config,
) -> Result<()> {
    if path.as_ref() == Path::new("classes/android")
        || path.as_ref() == Path::new("classes/com/google/android/gms")
        || path.as_ref() == Path::new("smali")
    {
        return Ok(());
    }
    let real_path = config.dist_folder().join(package.as_ref()).join(path);
    for f in fs::read_dir(&real_path)? {
        let f = match f {
            Ok(f) => f,
            Err(e) => {
                print_warning(format!(
                    "there was an error reading the directory {}: {}",
                    real_path.display(),
                    e
                ));
                return Err(e.into());
            }
        };
        let f_type = f.file_type()?;
        let f_path = f.path();
        let f_ext = f_path.extension();
        if f_type.is_dir() && f_path != real_path.join("original") {
            add_files_to_vec(
                f.path()
                    .strip_prefix(&config.dist_folder().join(package.as_ref()))
                    .unwrap(),
                vec,
                package.as_ref(),
                config,
            )?;
        } else if f_ext.is_some() {
            let filename = f_path.file_name().unwrap().to_string_lossy();
            if filename != "AndroidManifest.xml"
                && filename != "R.java"
                && !filename.starts_with("R$")
            {
                match f_ext.unwrap().to_string_lossy().borrow() {
                    "xml" | "java" => vec.push(f),
                    _ => {}
                }
            }
        }
    }
    Ok(())
}
