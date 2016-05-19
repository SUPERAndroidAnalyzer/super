use std::fs;
use std::fs::{File, DirEntry};
use std::io::Read;
use std::str::FromStr;
use std::path::{Path, PathBuf};
use std::borrow::Borrow;
use std::thread;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use std::slice::Iter;

use serde_json;
use serde_json::value::Value;
use regex::Regex;
use colored::Colorize;

use {Config, Result, Error, Criticity, print_warning, print_error, print_vulnerability, get_code};
use results::{Results, Vulnerability, Benchmark};

pub fn code_analysis(config: &Config, results: &mut Results) {
    let code_start = Instant::now();
    let rules = match load_rules(config) {
        Ok(r) => r,
        Err(e) => {
            print_error(format!("An error occurred when loading code analysis rules. Error: {}",
                                e),
                        config.is_verbose());
            return;
        }
    };

    if config.is_bench() {
        results.add_benchmark(Benchmark::new("Rule loading", code_start.elapsed()));
    }

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
    let dist_folder = Arc::new(format!("{}/{}", config.get_dist_folder(), config.get_app_id()));

    if config.is_verbose() {
        println!("Starting analysis of the code with {} threads. {} files to go!",
                 format!("{}", config.get_threads()).bold(),
                 format!("{}", total_files).bold());
    }
    let analysis_start = Instant::now();

    let handles: Vec<_> = (0..config.get_threads())
        .map(|_| {
            let thread_files = files.clone();
            let thread_rules = rules.clone();
            let thread_vulns = found_vulns.clone();
            let thread_dist_folder = dist_folder.clone();

            thread::spawn(move || {
                loop {
                    let f = {
                        let mut files = thread_files.lock().unwrap();
                        files.pop()
                    };
                    match f {
                        Some(f) => {
                            if let Err(e) =
                                   analyze_file(f.path(),
                                                PathBuf::from(thread_dist_folder.as_str()),
                                                &thread_rules,
                                                &thread_vulns,
                                                verbose) {
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

    if config.is_bench() {
        results.add_benchmark(Benchmark::new("File analysis", analysis_start.elapsed()));
    }

    for vuln in Arc::try_unwrap(found_vulns).unwrap().into_inner().unwrap() {
        results.add_vulnerability(vuln);
    }

    if config.is_bench() {
        results.add_benchmark(Benchmark::new("Total code analysis", code_start.elapsed()));
    }
}

fn analyze_file<P: AsRef<Path>>(path: P,
                                dist_folder: P,
                                rules: &Vec<Rule>,
                                results: &Mutex<Vec<Vulnerability>>,
                                verbose: bool)
                                -> Result<()> {
    let mut f = try!(File::open(&path));
    let mut code = String::new();
    try!(f.read_to_string(&mut code));

    for rule in rules {
        'rule: for (s, e) in rule.get_regex().find_iter(code.as_str()) {
            for white in rule.get_whitelist() {
                if white.is_match(&code[s..e]) {
                    continue 'rule;
                }
            }
            let start_line = get_line_for(s, code.as_str());
            let mut results = results.lock().unwrap();
            results.push(Vulnerability::new(rule.get_criticity(),
                                            rule.get_label(),
                                            rule.get_description(),
                                            path.as_ref().strip_prefix(&dist_folder).unwrap(),
                                            Some(start_line),
                                            Some(get_code(code.as_str(), start_line))));

            if verbose {
                print_vulnerability(rule.get_description(), rule.get_criticity());
            }
        }
    }

    Ok(())
}

fn get_line_for(index: usize, text: &str) -> usize {
    let mut line = 0;
    for (i, c) in text.char_indices() {
        if c == '\n' {
            line += 1
        } else if i == index {
            break;
        }
    }
    line
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
            if f_path.file_name().unwrap().to_string_lossy() != "AndroidManifest.xml" {
                match f_ext.unwrap().to_string_lossy().borrow() {
                    "xml" | "java" => vec.push(f),
                    _ => {}
                }
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
    whitelist: Vec<Regex>,
}

impl Rule {
    pub fn get_regex(&self) -> &Regex {
        &self.regex
    }

    pub fn get_label(&self) -> &str {
        self.label.as_str()
    }

    pub fn get_description(&self) -> &str {
        self.description.as_str()
    }

    pub fn get_criticity(&self) -> Criticity {
        self.criticity
    }

    pub fn get_whitelist(&self) -> Iter<Regex> {
        self.whitelist.iter()
    }
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
        let format_warning =
            format!("Rules must be objects with the following structure:\n{}\nAn optional {} \
                     attribute can be added to the object, an array of regular expressions that \
                     if matched, the found match will be discarded.",
                    "{\n\t\"label\": \"Label for the rule\",\n\t\"description\": \"Long \
                     description for this rule\"\n\t\"criticity\": \
                     \"low|medium|high|critical\"\n\t\"regex\": \
                     \"regex_to_find_vulnerability\"\n}"
                        .italic(),
                    "whitelist".italic());
        let rule = match rule.as_object() {
            Some(o) => o,
            None => {
                print_warning(format_warning, config.is_verbose());
                return Err(Error::ParseError);
            }
        };

        if rule.len() != 4 && rule.len() != 5 {
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

        let whitelist = match rule.get("whitelist") {
            Some(&Value::Array(ref v)) => {
                let mut list = Vec::with_capacity(v.len());
                for r in v {
                    list.push(match r {
                        &Value::String(ref r) => {
                            match Regex::new(r) {
                                Ok(r) => r,
                                Err(e) => {
                                    print_warning(format!("An error occurred when compiling the \
                                                           regular expresion: {}",
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
                    });
                }
                list
            }
            Some(_) => {
                print_warning(format_warning, config.is_verbose());
                return Err(Error::ParseError);
            }
            None => Vec::with_capacity(0),
        };

        rules.push(Rule {
            regex: regex,
            label: label.clone(),
            description: description.clone(),
            criticity: criticity,
            whitelist: whitelist,
        })
    }

    Ok(rules)
}

#[cfg(test)]
mod tests {
    use super::{Rule, load_rules};

    fn check_match(text: &str, rule: &Rule) -> bool {
        if rule.get_regex().is_match(text) {
            for r in rule.get_whitelist() {
                if r.is_match(text) {
                    return false;
                }
            }
            true
        } else {
            false
        }
    }

    #[test]
    fn it_password_regex() {
        let config = Default::default();
        let rules = load_rules(&config).unwrap();
        let rule = rules.get(0).unwrap();

        let should_match = &["password = \"secret\";",
                             "pass = \"secret\";",
                             "pwd = \"secret\";",
                             "passwd = \"secret\";",
                             "password = \"\";",
                             "password=\"    \";",
                             "PASS = \"secret\";"];
        let should_not_match = &["p = \"android.intent.extra.EMAIL\";", "pasbook = \"hello!\";"];

        for m in should_match {
            assert!(check_match(m, rule));
        }

        for m in should_not_match {
            assert!(!check_match(m, rule));
        }
    }

    #[test]
    fn it_url_regex() {
        let config = Default::default();
        let rules = load_rules(&config).unwrap();
        let rule = rules.get(1).unwrap();

        let should_match = &["\"http://www.razican.com\"",
                             "\"https://razican.com\"",
                             "\"http://www.razican.com/hello\"",
                             "\"//www.razican.com/hello\"",
                             "\"ftp://ftp.razican.com/hello\""];
        let should_not_match = &["\"android.intent.extra.EMAIL\"",
                                 "\"hello\"",
                                 "\"http://schemas.android.com/apk/res/android\"",
                                 "\"http://www.w3.org/2005/Atom\""];

        for m in should_match {
            assert!(check_match(m, rule));
        }

        for m in should_not_match {
            assert!(!check_match(m, rule));
        }
    }
}
