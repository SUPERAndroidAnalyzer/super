use std::fs;
use std::fs::{File, DirEntry};
use std::io::Read;
use std::str::FromStr;
use std::path::Path;
use std::borrow::Borrow;
use std::thread;
use std::sync::{Arc, Mutex};

use serde_json;
use serde_json::value::Value;
use regex::Regex;
use colored::Colorize;

use {Config, Result, Error, Criticity, print_warning, print_error};
use results::{Results, Vulnerability};

pub fn code_analysis(config: &Config, results: &mut Results) {
    let rules = match load_rules(config) {
        Ok(r) => r,
        Err(e) => {
            print_error(format!("An error occurred when loading code analysis rules. Error: {}",
                                e),
                        config.is_verbose());
            return;
        }
    };

    let mut files: Vec<DirEntry> = Vec::new();
    if let Err(e) = add_files_to_vec("", &mut files, config) {
        print_warning(format!("An error occurred when reading files for analysis, the results \
                               might be incomplete. Error: {}",
                              e),
                      config.is_verbose());
    }
    let total_files = files.len();

    let rules = Arc::new(rules);
    let found_vulns: Arc<Mutex<Vec<Vulnerability>>> = Arc::new(Mutex::new(Vec::new()));;
    let files = Arc::new(Mutex::new(files));
    let verbose = config.is_verbose();

    if config.is_verbose() {
        println!("Starting analysis of the code with {} threads. {} files to go!",
                 format!("{}", config.get_threads()).bold(),
                 format!("{}", total_files).bold());
    }

    let handles: Vec<_> = (0..config.get_threads())
        .map(|_| {
            let thread_files = files.clone();
            let thread_rules = rules.clone();
            let thread_vulns = found_vulns.clone();

            thread::spawn(move || {
                loop {
                    let f = {
                        let mut files = thread_files.lock().unwrap();
                        files.pop()
                    };
                    match f {
                        Some(f) => {
                            if let Err(e) = analyze_file(f.path(), &thread_rules, &thread_vulns) {
                                print_warning(format!("Error analyzing file {}. The analysis \
                                                       will continue, though. Error: {}",
                                                      f.path().display(),
                                                      e),
                                              verbose)
                            }
                        }
                        None => break,
                    }
                }
            })
        })
        .collect();

    if config.is_verbose() {
        let mut last_print = 0;

        while match files.lock() {
            Ok(f) => f.len(),
            Err(_) => 1,
        } > 0 {

            let left = match files.lock() {
                Ok(f) => f.len(),
                Err(_) => continue,
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
            print_warning(format!("An error occurred when joining analysis thrads: Error: {:?}",
                                  e),
                          config.is_verbose());
        }
    }

    for vuln in Arc::try_unwrap(found_vulns).unwrap().into_inner().unwrap() {
        results.add_vulnerability(vuln);
    }
}

fn analyze_file<P: AsRef<Path>>(path: P,
                                rules: &Vec<Rule>,
                                results: &Mutex<Vec<Vulnerability>>)
                                -> Result<()> {
    let mut f = try!(File::open(path));
    let mut code = String::new();
    try!(f.read_to_string(&mut code));

    Ok(())
}

fn add_files_to_vec<P: AsRef<Path>>(path: P,
                                    vec: &mut Vec<DirEntry>,
                                    config: &Config)
                                    -> Result<()> {
    let real_path = format!("{}/{}/{}",
                            config.get_dist_folder(),
                            config.get_app_id(),
                            path.as_ref().display());
    for f in try!(fs::read_dir(&real_path)) {
        let f = match f {
            Ok(f) => f,
            Err(e) => {
                print_warning(format!("There was an error reading the directory {}: {}",
                                      &real_path,
                                      e),
                              config.is_verbose());
                return Err(Error::from(e));
            }
        };
        let f_type = try!(f.file_type());
        let f_path = f.path();
        let f_ext = f_path.extension();
        if f_type.is_dir() && f_path != Path::new(&format!("{}/original", real_path)) {
            try!(add_files_to_vec(f.path()
                                      .strip_prefix(&format!("{}/{}",
                                                             config.get_dist_folder(),
                                                             config.get_app_id()))
                                      .unwrap(),
                                  vec,
                                  config));
        } else if f_ext.is_some() {
            match f_ext.unwrap().to_string_lossy().borrow() {
                "xml" | "java" => vec.push(f),
                _ => {}
            }
        }
    }
    Ok(())
}

struct Rule {
    regex: Regex,
    label: String,
    description: String,
    criticity: Criticity,
}

fn load_rules(config: &Config) -> Result<Vec<Rule>> {
    let f = try!(File::open(config.get_rules_json()));
    let rules_json: Value = try!(serde_json::from_reader(f));

    let mut rules = Vec::new();
    let rules_json = match rules_json.as_array() {
        Some(a) => a,
        None => {
            print_warning("Rules must be a JSON array.", config.is_verbose());
            return Err(Error::ParseError);
        }
    };

    for rule in rules_json {
        let format_warning = format!("Rules must be objects with the following structure:\n{}",
                                     "{ \t\"label\": \"Label for the rule\",\n\t\"description\": \
                                      \"Long description for this rule\"\n\t\"criticity\": \
                                      \"low|medium|high|critical\"\n\t\"regex\": \
                                      \"regex_to_find_vulnerability\"\n}"
                                         .italic());
        let rule = match rule.as_object() {
            Some(o) => o,
            None => {
                print_warning(format_warning, config.is_verbose());
                return Err(Error::ParseError);
            }
        };

        if rule.len() != 4 {
            print_warning(format_warning, config.is_verbose());
            return Err(Error::ParseError);
        }

        let regex = match rule.get("regex") {
            Some(&Value::String(ref r)) => {
                match Regex::new(r) {
                    Ok(r) => r,
                    Err(e) => {
                        print_warning(format!("An error occurred when compiling the regular \
                                               expresion: {}",
                                              e),
                                      config.is_verbose());
                        return Err(Error::ParseError);
                    }
                }
            }
            _ => {
                print_warning(format_warning, config.is_verbose());
                return Err(Error::ParseError);
            }
        };

        let label = match rule.get("label") {
            Some(&Value::String(ref l)) => l,
            _ => {
                print_warning(format_warning, config.is_verbose());
                return Err(Error::ParseError);
            }
        };

        let description = match rule.get("description") {
            Some(&Value::String(ref d)) => d,
            _ => {
                print_warning(format_warning, config.is_verbose());
                return Err(Error::ParseError);
            }
        };

        let criticity = match rule.get("criticity") {
            Some(&Value::String(ref c)) => {
                match Criticity::from_str(c) {
                    Ok(c) => c,
                    Err(e) => {
                        print_warning(format!("Criticity must be  one of {}, {}, {} or {}.",
                                              "low".italic(),
                                              "medium".italic(),
                                              "high".italic(),
                                              "critical".italic()),
                                      config.is_verbose());
                        return Err(e);
                    }
                }
            }
            _ => {
                print_warning(format_warning, config.is_verbose());
                return Err(Error::ParseError);
            }
        };

        rules.push(Rule {
            regex: regex,
            label: label.clone(),
            description: description.clone(),
            criticity: criticity,
        })
    }

    Ok(rules)
}
