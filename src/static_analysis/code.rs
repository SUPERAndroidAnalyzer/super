use std::fs;
use std::fs::{File, DirEntry};
use std::io::Read;
use std::str::FromStr;
use std::path::Path;
use std::borrow::Borrow;
use std::thread;
use std::sync::{Arc, Mutex};
use std::slice::Iter;
use std::error::Error as StdError;

use serde_json;
use serde_json::value::Value;
use regex::Regex;
use colored::Colorize;

use {Config, Criticality, print_warning, print_vulnerability, get_code};
use results::{Results, Vulnerability};
use super::manifest::{Permission, Manifest};
use error::*;

pub fn analysis<S: AsRef<str>>(manifest: Option<Manifest>,
                               config: &Config,
                               package: S,
                               results: &mut Results) {
    let rules = match load_rules(config) {
        Ok(r) => r,
        Err(e) => {
            print_warning(format!("An error occurred when loading code analysis rules. Error: {}",
                                  e.description()));
            return;
        }
    };

    let mut files: Vec<DirEntry> = Vec::new();
    if let Err(e) = add_files_to_vec("", &mut files, package.as_ref(), config) {
        print_warning(format!("An error occurred when reading files for analysis, the results \
                               might be incomplete. Error: {}",
                              e.description()));
    }
    let total_files = files.len();

    let rules = Arc::new(rules);
    let manifest = Arc::new(manifest);
    let found_vulns: Arc<Mutex<Vec<Vulnerability>>> = Arc::new(Mutex::new(Vec::new()));
    let files = Arc::new(Mutex::new(files));
    let dist_folder = Arc::new(config.get_dist_folder().join(package.as_ref()));

    if config.is_verbose() {
        println!("Starting analysis of the code with {} threads. {} files to go!",
                 format!("{}", config.get_threads()).bold(),
                 format!("{}", total_files).bold());
    }

    let handles: Vec<_> = (0..config.get_threads())
        .map(|_| {
            let thread_manifest = manifest.clone();
            let thread_files = files.clone();
            let thread_rules = rules.clone();
            let thread_vulns = found_vulns.clone();
            let thread_dist_folder = dist_folder.clone();

            thread::spawn(move || loop {
                let f = {
                    let mut files = thread_files.lock().unwrap();
                    files.pop()
                };
                match f {
                    Some(f) => {
                        if let Err(e) = analyze_file(f.path(),
                                                     &*thread_dist_folder,
                                                     &thread_rules,
                                                     &thread_manifest,
                                                     &thread_vulns) {
                            print_warning(format!("Error analyzing file {}. The analysis will \
                                                   continue, though. Error: {}",
                                                  f.path().display(),
                                                  e.description()))
                        }
                    }
                    None => break,
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
            #[allow(use_debug)]
            print_warning(format!("An error occurred when joining analysis threads: Error: {:?}",
                                  e));
        }
    }

    for vuln in Arc::try_unwrap(found_vulns).unwrap().into_inner().unwrap() {
        results.add_vulnerability(vuln);
    }

    if config.is_verbose() {
        println!();
        println!("{}", "The source code was analized correctly!".green());
    } else if !config.is_quiet() {
        println!("Source code analyzed.");
    }
}

fn analyze_file<P: AsRef<Path>, T: AsRef<Path>>(path: P,
                                                dist_folder: T,
                                                rules: &[Rule],
                                                manifest: &Option<Manifest>,
                                                results: &Mutex<Vec<Vulnerability>>)
                                                -> Result<()> {
    let mut f = File::open(&path)?;
    let mut code = String::new();
    let _ = f.read_to_string(&mut code)?;

    'check: for rule in rules {
        if manifest.is_some() && rule.get_max_sdk().is_some() &&
           rule.get_max_sdk().unwrap() < manifest.as_ref().unwrap().get_min_sdk() {
            continue 'check;
        }

        let filename = path.as_ref().file_name().and_then(|f| f.to_str());

        if let Some(f) = filename {
            if !rule.has_to_check(f) {
                continue 'check;
            }
        }

        for permission in rule.get_permissions() {
            if manifest.is_none() ||
               !manifest.as_ref()
                    .unwrap()
                    .get_permission_checklist()
                    .needs_permission(*permission) {
                continue 'check;
            }
        }

        'rule: for m in rule.get_regex().find_iter(code.as_str()) {
            for white in rule.get_whitelist() {
                if white.is_match(&code[m.start()..m.end()]) {
                    continue 'rule;
                }
            }
            match rule.get_forward_check() {
                None => {
                    let start_line = get_line_for(m.start(), code.as_str());
                    let end_line = get_line_for(m.end(), code.as_str());
                    let mut results = results.lock().unwrap();
                    results.push(Vulnerability::new(rule.get_criticality(),
                                                    rule.get_label(),
                                                    rule.get_description(),
                                                    Some(path.as_ref()
                                                             .strip_prefix(&dist_folder)
                                                             .unwrap()),
                                                    Some(start_line),
                                                    Some(end_line),
                                                    Some(get_code(code.as_str(),
                                                                  start_line,
                                                                  end_line))));

                    print_vulnerability(rule.get_description(), rule.get_criticality());
                }
                Some(check) => {
                    let caps = rule.get_regex().captures(&code[m.start()..m.end()]).unwrap();

                    let fcheck1 = caps.name("fc1");
                    let fcheck2 = caps.name("fc2");
                    let mut r = check.clone();

                    if let Some(fc1) = fcheck1 {
                        r = r.replace("{fc1}", fc1.as_str());
                    }

                    if let Some(fc2) = fcheck2 {
                        r = r.replace("{fc2}", fc2.as_str());
                    }

                    let regex = match Regex::new(r.as_str()) {
                        Ok(r) => r,
                        Err(e) => {
                            print_warning(format!("There was an error creating the \
                                                   forward_check '{}'. The rule will be \
                                                   skipped. {}",
                                                  r,
                                                  e.description()));
                            break 'rule;
                        }
                    };

                    for m in regex.find_iter(code.as_str()) {
                        let start_line = get_line_for(m.start(), code.as_str());
                        let end_line = get_line_for(m.end(), code.as_str());
                        let mut results = results.lock().unwrap();
                        results.push(Vulnerability::new(rule.get_criticality(),
                                                        rule.get_label(),
                                                        rule.get_description(),
                                                        Some(path.as_ref()
                                                                 .strip_prefix(&dist_folder)
                                                                 .unwrap()),
                                                        Some(start_line),
                                                        Some(end_line),
                                                        Some(get_code(code.as_str(),
                                                                      start_line,
                                                                      end_line))));

                        print_vulnerability(rule.get_description(), rule.get_criticality());
                    }
                }
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

fn add_files_to_vec<P: AsRef<Path>, S: AsRef<str>>(path: P,
                                                   vec: &mut Vec<DirEntry>,
                                                   package: S,
                                                   config: &Config)
                                                   -> Result<()> {
    if path.as_ref() == Path::new("classes/android") ||
       path.as_ref() == Path::new("classes/com/google/android/gms") ||
       path.as_ref() == Path::new("smali") {
        return Ok(());
    }
    let real_path = config.get_dist_folder().join(package.as_ref()).join(path);
    for f in fs::read_dir(&real_path)? {
        let f = match f {
            Ok(f) => f,
            Err(e) => {
                print_warning(format!("There was an error reading the directory {}: {}",
                                      real_path.display(),
                                      e.description()));
                return Err(e.into());
            }
        };
        let f_type = f.file_type()?;
        let f_path = f.path();
        let f_ext = f_path.extension();
        if f_type.is_dir() && f_path != real_path.join("original") {
            add_files_to_vec(f.path()
                                 .strip_prefix(&config.get_dist_folder()
                                                    .join(package.as_ref()))
                                 .unwrap(),
                             vec,
                             package.as_ref(),
                             config)?;
        } else if f_ext.is_some() {
            let filename = f_path.file_name().unwrap().to_string_lossy();
            if filename != "AndroidManifest.xml" && filename != "R.java" &&
               !filename.starts_with("R$") {
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
    permissions: Vec<Permission>,
    forward_check: Option<String>,
    max_sdk: Option<u32>,
    whitelist: Vec<Regex>,
    label: String,
    description: String,
    criticality: Criticality,
    include_file_regex: Option<Regex>,
    exclude_file_regex: Option<Regex>,
}

impl Rule {
    pub fn get_regex(&self) -> &Regex {
        &self.regex
    }

    pub fn get_permissions(&self) -> Iter<Permission> {
        self.permissions.iter()
    }

    pub fn get_forward_check(&self) -> Option<&String> {
        self.forward_check.as_ref()
    }

    pub fn get_max_sdk(&self) -> Option<u32> {
        self.max_sdk
    }

    pub fn get_label(&self) -> &str {
        self.label.as_str()
    }

    pub fn get_description(&self) -> &str {
        self.description.as_str()
    }

    pub fn get_criticality(&self) -> Criticality {
        self.criticality
    }

    pub fn get_whitelist(&self) -> Iter<Regex> {
        self.whitelist.iter()
    }

    /// Returns if this rule has to be applied to the given filename
    pub fn has_to_check(&self, filename: &str) -> bool {
        if self.include_file_regex.is_none() && self.exclude_file_regex.is_none() {
            return true;
        }

        let mut has_to_check = false;

        if let Some(ref r) = self.include_file_regex {
            has_to_check = r.is_match(filename)
        }

        if let Some(ref r) = self.exclude_file_regex {
            has_to_check = !r.is_match(filename)
        }

        has_to_check
    }
}

fn load_rules(config: &Config) -> Result<Vec<Rule>> {
    let f = File::open(config.get_rules_json())?;
    let rules_json: Value = serde_json::from_reader(f)?;

    let mut rules = Vec::new();
    let rules_json = if let Some(a) = rules_json.as_array() {
        a
    } else {
        print_warning("Rules must be a JSON array.");
        return Err(ErrorKind::Parse.into());
    };

    for rule in rules_json {
        let format_warning = format!("Rules must be objects with the following structure:\n{}\nAn optional {} \
                     attribute can be added: an array of regular expressions that if matched, \
                     the found match will be discarded. You can also include an optional {} \
                     attribute: an array of the permissions needed for this rule to be checked. \
                     And finally, an optional {} attribute can be added where you can specify a \
                     second regular expression to check if the one in the {} attribute matches. \
                     You can add one or two capture groups with name from the match to this \
                     check, with names {} and {}. To use them you have to include {} or {} in \
                     the forward check.",
                    "{\n\t\"label\": \"Label for the rule\",\n\t\"description\": \"Long \
                     description for this rule\"\n\t\"criticality\": \
                     \"warning|low|medium|high|critical\"\n\t\"regex\": \
                     \"regex_to_find_vulnerability\"\n}"
                        .italic(),
                    "whitelist".italic(),
                    "permissions".italic(),
                    "forward_check".italic(),
                    "regex".italic(),
                    "fc1".italic(),
                    "fc2".italic(),
                    "{fc1}".italic(),
                    "{fc2}".italic());
        let rule = if let Some(o) = rule.as_object() {
            o
        } else {
            print_warning(format_warning);
            return Err(ErrorKind::Parse.into());
        };

        if rule.len() < 4 || rule.len() > 8 {
            print_warning(format_warning);
            return Err(ErrorKind::Parse.into());
        }

        let regex = if let Some(&Value::String(ref r)) = rule.get("regex") {
            match Regex::new(r) {
                Ok(r) => r,
                Err(e) => {
                    print_warning(format!("An error occurred when compiling the regular \
                                           expresion: {}",
                                          e.description()));
                    return Err(ErrorKind::Parse.into());
                }
            }
        } else {
            print_warning(format_warning);
            return Err(ErrorKind::Parse.into());
        };

        let max_sdk = match rule.get("max_sdk") {
            Some(&Value::Number(ref sdk)) if sdk.is_u64() => Some(sdk.as_u64().unwrap() as u32),
            None => None,
            _ => {
                print_warning(format_warning);
                return Err(ErrorKind::Parse.into());
            }
        };

        let permissions = match rule.get("permissions") {
            Some(&Value::Array(ref v)) => {
                let mut list = Vec::with_capacity(v.len());
                for p in v {
                    list.push(if let Value::String(ref p) = *p {
                                  if let Ok(p) = Permission::from_str(p) {
                                      p
                                  } else {
                                      print_warning(format!("the permission {} is unknown",
                                                            p.italic()));
                                      return Err(ErrorKind::Parse.into());
                                  }
                              } else {
                                  print_warning(format_warning);
                                  return Err(ErrorKind::Parse.into());
                              });
                }
                list
            }
            Some(_) => {
                print_warning(format_warning);
                return Err(ErrorKind::Parse.into());
            }
            None => Vec::with_capacity(0),
        };

        let forward_check = match rule.get("forward_check") {
            Some(&Value::String(ref s)) => {
                let capture_names = regex.capture_names();
                for cap in capture_names {
                    match cap {
                        Some("fc1") => {
                            if !s.contains("{fc1}") {
                                print_warning("You must provide the '{fc1}' string where you \
                                               want the 'fc1' capture to be inserted in the \
                                               forward check.");
                                return Err(ErrorKind::Parse.into());
                            }
                        }
                        Some("fc2") => {
                            if !s.contains("{fc2}") {
                                print_warning("You must provide the '{fc2}' string where you \
                                               want the 'fc2' capture to be inserted in the \
                                               forward check.");
                                return Err(ErrorKind::Parse.into());
                            }
                        }
                        _ => {}
                    }
                }

                let mut capture_names = regex.capture_names();
                if capture_names.any(|c| c.is_some() && c.unwrap() == "fc2") &&
                   !capture_names.any(|c| c.is_some() && c.unwrap() == "fc1") {
                    print_warning("You must have a capture group named fc1 to use the capture \
                                   fc2.");
                    return Err(ErrorKind::Parse.into());
                }

                Some(s.clone())
            }
            None => None,
            _ => {
                print_warning(format_warning);
                return Err(ErrorKind::Parse.into());
            }
        };

        let label = if let Some(&Value::String(ref l)) = rule.get("label") {
            l
        } else {
            print_warning(format_warning);
            return Err(ErrorKind::Parse.into());
        };

        let description = if let Some(&Value::String(ref d)) = rule.get("description") {
            d
        } else {
            print_warning(format_warning);
            return Err(ErrorKind::Parse.into());
        };

        let criticality = if let Some(&Value::String(ref c)) = rule.get("criticality") {
            match Criticality::from_str(c) {
                Ok(c) => c,
                Err(e) => {
                    print_warning(format!("Criticality must be  one of {}, {}, {}, {} or {}.",
                                          "warning".italic(),
                                          "low".italic(),
                                          "medium".italic(),
                                          "high".italic(),
                                          "critical".italic()));
                    return Err(e);
                }
            }
        } else {
            print_warning(format_warning);
            return Err(ErrorKind::Parse.into());
        };

        let whitelist = match rule.get("whitelist") {
            Some(&Value::Array(ref v)) => {
                let mut list = Vec::with_capacity(v.len());
                for r in v {
                    list.push(if let Value::String(ref r) = *r {
                                  match Regex::new(r) {
                                      Ok(r) => r,
                                      Err(e) => {
                            print_warning(format!("An error occurred when compiling the \
                                                       regular expresion: {}",
                                                  e.description()));
                            return Err(ErrorKind::Parse.into());
                        }
                                  }
                              } else {
                                  print_warning(format_warning);
                                  return Err(ErrorKind::Parse.into());
                              });
                }
                list
            }
            Some(_) => {
                print_warning(format_warning);
                return Err(ErrorKind::Parse.into());
            }
            None => Vec::with_capacity(0),
        };

        let inclusion_regex =
            rule.get("include_file_regex").and_then(Value::as_str).and_then(|r| {
                let include_regex = Regex::new(r);
                match include_regex {
                    Ok(regex) => Some(regex),
                    Err(e) => {
                        print_warning(format!("An error ocurred when compiling the inclusion \
                                               regular expresion: {}",
                                              e.description()));
                        None
                    }
                }
            });

        let exclusion_regex =
            rule.get("exclude_file_regex").and_then(Value::as_str).and_then(|r| {
                let exclude_regex = Regex::new(r);
                match exclude_regex {
                    Ok(regex) => Some(regex),
                    Err(e) => {
                        print_warning(format!("An error ocurred when compiling the exclusion \
                                               regular expresion: {}",
                                              e.description()));
                        None
                    }
                }
            });

        if criticality >= config.get_min_criticality() {
            rules.push(Rule {
                           regex: regex,
                           permissions: permissions,
                           forward_check: forward_check,
                           max_sdk: max_sdk,
                           label: label.clone(),
                           description: description.clone(),
                           criticality: criticality,
                           whitelist: whitelist,
                           include_file_regex: inclusion_regex,
                           exclude_file_regex: exclusion_regex,
                       })
        }
    }

    Ok(rules)
}

#[cfg(test)]
mod tests {
    use regex::Regex;
    use super::{Rule, load_rules};
    use config::Config;
    use Criticality;

    fn check_match<S: AsRef<str>>(text: S, rule: &Rule) -> bool {
        if rule.get_regex().is_match(text.as_ref()) {
            for white in rule.get_whitelist() {
                if white.is_match(text.as_ref()) {
                    let m = white.find(text.as_ref()).unwrap();
                    println!("Whitelist '{}' matches the text '{}' in '{}'",
                             white.as_str(),
                             text.as_ref(),
                             &text.as_ref()[m.start()..m.end()]);
                    return false;
                }
            }
            match rule.get_forward_check() {
                None => {
                    let m = rule.get_regex().find(text.as_ref()).unwrap();
                    println!("The regular expression '{}' matches the text '{}' in '{}'",
                             rule.get_regex(),
                             text.as_ref(),
                             &text.as_ref()[m.start()..m.end()]);
                    true
                }
                Some(check) => {
                    let caps = rule.get_regex().captures(text.as_ref()).unwrap();

                    let fcheck1 = caps.name("fc1");
                    let fcheck2 = caps.name("fc2");
                    let mut r = check.clone();

                    if let Some(fc1) = fcheck1 {
                        r = r.replace("{fc1}", fc1.as_str());
                    }

                    if let Some(fc2) = fcheck2 {
                        r = r.replace("{fc2}", fc2.as_str());
                    }

                    let regex = Regex::new(r.as_str()).unwrap();
                    if regex.is_match(text.as_ref()) {
                        let m = regex.find(text.as_ref()).unwrap();
                        println!("The forward check '{}'  matches the text '{}' in '{}'",
                                 regex.as_str(),
                                 text.as_ref(),
                                 &text.as_ref()[m.start()..m.end()]);
                        true
                    } else {
                        println!("The forward check '{}' does not match the text '{}'",
                                 regex.as_str(),
                                 text.as_ref());
                        false
                    }
                }
            }
        } else {
            println!("The regular expression '{}' does not match the text '{}'",
                     rule.get_regex(),
                     text.as_ref());
            false
        }
    }

    #[test]
    fn it_url_regex() {
        let config = Config::default();
        let rules = load_rules(&config).unwrap();
        let rule = rules.get(0).unwrap();

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

    #[test]
    fn it_catch_exception() {
        let config = Config::default();
        let rules = load_rules(&config).unwrap();
        let rule = rules.get(1).unwrap();

        let should_match = &["catch (Exception e) {",
                             "catch (Exception hello) {",
                             "catch( Exception e ){",
                             "catch (IOException|Exception e) {",
                             "catch (Exception|IOException e) {",
                             "catch (IOException | Exception e) {",
                             "catch (IOException|Exception|PepeException e) {",
                             "catch (SystemException|ApplicationException|PepeException e) {",
                             "catch (IOException|Exception | PepeException e) {"];
        let should_not_match = &["catch (IOException e) {",
                                 "catch (IOException|PepeException e) {"];

        for m in should_match {
            assert!(check_match(m, rule));
        }

        for m in should_not_match {
            assert!(!check_match(m, rule));
        }
    }

    #[test]
    fn it_throws_exception() {
        let config = Config::default();
        let rules = load_rules(&config).unwrap();
        let rule = rules.get(2).unwrap();

        let should_match = &["throws Exception {",
                             "throws Exception, IOException {",
                             "throws IOException, Exception {",
                             "throws Exception,IOException{",
                             "throws IOException,Exception{",
                             "throws SystemException,Exception{",
                             "throws ApplicationException,Exception{",
                             "throws PepeException, Exception, IOException {"];
        let should_not_match = &["throws IOException {", "throws PepeException, IOException {"];

        for m in should_match {
            assert!(check_match(m, rule));
        }

        for m in should_not_match {
            assert!(!check_match(m, rule));
        }
    }

    #[test]
    fn it_hidden_fields() {
        let config = Config::default();
        let rules = load_rules(&config).unwrap();
        let rule = rules.get(3).unwrap();

        let should_match = &["setVisible(View.INVISIBLE)",
                             "setVisible ( View.invisible )",
                             "android:visibility = \"invisible\"",
                             "android:background = \"NULL\"",
                             "android:background=\"null\"",
                             "android:background = \"@null\""];
        let should_not_match = &["android:background = \"@color/red\""];

        for m in should_match {
            assert!(check_match(m, rule));
        }

        for m in should_not_match {
            assert!(!check_match(m, rule));
        }
    }

    #[test]
    fn it_ipv4_disclosure() {
        let config = Config::default();
        let rules = load_rules(&config).unwrap();
        let rule = rules.get(4).unwrap();

        let should_match = &[" 192.168.1.1", " 0.0.0.0", " 255.255.255.255", " 13.0.130.23.52"];
        let should_not_match = &["0000.000.000.000",
                                 "256.140.123.154",
                                 "135.260.120.0",
                                 "50.75.300.35",
                                 "60.35.59.300",
                                 ".5.6.7",
                                 "115..35.5",
                                 "155.232..576",
                                 "123.132.123.",
                                 "123.124.123"];

        for m in should_match {
            assert!(check_match(m, rule));
        }

        for m in should_not_match {
            assert!(!check_match(m, rule));
        }
    }

    #[test]
    fn it_math_random() {
        let config = Config::default();
        let rules = load_rules(&config).unwrap();
        let rule = rules.get(5).unwrap();

        let should_match = &["Math.random()", "Random()", "Math . random ()"];
        let should_not_match =
            &["math.random()", "MATH.random()", "Math.Randomize()", "Mathrandom()", "Math.random"];

        for m in should_match {
            assert!(check_match(m, rule));
        }

        for m in should_not_match {
            assert!(!check_match(m, rule));
        }
    }

    #[test]
    fn it_log() {
        let config = Config::default();
        let rules = load_rules(&config).unwrap();
        let rule = rules.get(6).unwrap();

        let should_match = &["Log.d(\"Diva-sqli\", \"Error occurred while searching in database: \
                              \" + messageToShow);",
                             " Log.d(\"Diva-sqli\", \"Error occurred while searching in \
                              database: \" + messageToShow + msg1 +  msg2 + msg3);",
                             " Log.d(\"Diva-sqli\", \"Error occurred while searching in \
                              database: \" + messageToShow + msg1 +  msg2 + msg3);",
                             " Log.d(\"Diva-sqli\", \"Error occurred while searching in \
                              database: \" + messageToShow + msg1 +  msg2 + msg3);"];

        let should_not_match = &["Log.e(\"Hello!\")",
                                 "Log.e(\"Hello: \" + var)",
                                 "Log.e(\"Hello: \" +var)",
                                 "Log.wtf(\"Hello: \"+var)",
                                 "Log.i(var)",
                                 "Log.println(\"Hello: \" + var + \" goodbye\")"];

        for m in should_match {
            assert!(check_match(m, rule));
        }

        for m in should_not_match {
            assert!(!check_match(m, rule));
        }
    }

    #[test]
    fn it_file_separator() {
        let config = Config::default();
        let rules = load_rules(&config).unwrap();
        let rule = rules.get(7).unwrap();

        let should_match =
            &["C:\\", "C:\\Programs\\password.txt", "D:\\", "H:\\P\\o\\password.txt"];

        let should_not_match = &["ome\\password.txt", "at:\\", "\\\\home\\sharedfile", "\\n"];

        for m in should_match {
            assert!(check_match(m, rule));
        }

        for m in should_not_match {
            assert!(!check_match(m, rule));
        }
    }

    #[test]
    fn it_weak_algs() {
        let config = Config::default();
        let rules = load_rules(&config).unwrap();
        let rule = rules.get(8).unwrap();

        let should_match = &["DESKeySpec",
                             "getInstance(MD5)",
                             "getInstance(\"MD5\")",
                             "getInstance(SHA-1)",
                             "getInstance(\"SHA-1\")",
                             "getInstance(\"MD4\")",
                             "getInstance(\"RC2\")",
                             "getInstance(\"md4\")",
                             "getInstance(\"rc2\")",
                             "getInstance(\"rc4\")",
                             "getInstance(\"RC4\")",
                             "getInstance(\"AES/ECB\")",
                             "getInstance(\"RSA/ECB/nopadding\")",
                             "getInstance(\"rsa/ECB/nopadding\")"];

        let should_not_match = &["", "", "", ""];

        for m in should_match {
            assert!(check_match(m, rule));
        }

        for m in should_not_match {
            assert!(!check_match(m, rule));
        }
    }

    #[test]
    fn it_sleep_method() {
        let config = Config::default();
        let rules = load_rules(&config).unwrap();
        let rule = rules.get(9).unwrap();

        let should_match = &["Thread.sleep(Usertime+Variable+Variable);",
                             "Thread.sleep(Usertime+13+123+1+24);",
                             "Thread . sleep (200+asdad+adasasda );",
                             "Thread . sleep (200+asdad+adasasda+30 );",
                             "Thread.sleep(10 + 10 + 10241 + Usertime);",
                             "SystemClock.sleep(Usertime);"];

        let should_not_match = &["Thread.sleep(2000);",
                                 "Thread.sleep(“1000” + Usertime);",
                                 "Thread.sleep();",
                                 "SystemClock.sleep(1000);"];

        for m in should_match {
            assert!(check_match(m, rule));
        }

        for m in should_not_match {
            assert!(!check_match(m, rule));
        }
    }

    #[test]
    fn it_world_readable_permissions() {
        let config = Config::default();
        let rules = load_rules(&config).unwrap();
        let rule = rules.get(10).unwrap();

        let should_match = &["MODE_WORLD_READABLE",
                             "openFileOutput(\"file.txt  \", 1) ",
                             "openFileOutput(\"filename\", 1) ",
                             "openFileOutput(filepath, 1) ",
                             "openFileOutput(path_to_file, 1) "];

        let should_not_match =
            &["openFileOutput(\"file.txt\", 0) ", "openFileOutput(, 1) ", "openFileOutput() ", ""];

        for m in should_match {
            assert!(check_match(m, rule));
        }

        for m in should_not_match {
            assert!(!check_match(m, rule));
        }
    }

    #[test]
    fn it_world_writable_permissions() {
        let config = Config::default();
        let rules = load_rules(&config).unwrap();
        let rule = rules.get(11).unwrap();

        let should_match = &["MODE_WORLD_WRITABLE",
                             "openFileOutput(\"file.txt  \", 2) ",
                             "openFileOutput(\"filename\", 2) ",
                             "openFileOutput(filepath, 2) ",
                             "openFileOutput(path_to_file, 2) "];

        let should_not_match =
            &["openFileOutput(\"file.txt\", 0) ", "openFileOutput(, 2) ", "openFileOutput() ", ""];

        for m in should_match {
            assert!(check_match(m, rule));
        }

        for m in should_not_match {
            assert!(!check_match(m, rule));
        }
    }

    #[test]
    fn it_external_storage_write_read() {
        let config = Config::default();
        let rules = load_rules(&config).unwrap();
        let rule = rules.get(12).unwrap();

        let should_match = &[".getExternalStorage", ".getExternalFilesDir()"];

        let should_not_match = &["", "", "", ""];

        for m in should_match {
            assert!(check_match(m, rule));
        }

        for m in should_not_match {
            assert!(!check_match(m, rule));
        }
    }

    #[test]
    fn it_temp_file() {
        let config = Config::default();
        let rules = load_rules(&config).unwrap();
        let rule = rules.get(13).unwrap();

        let should_match = &[".createTempFile()", ".createTempFile()"];

        let should_not_match = &["", "", "", ""];

        for m in should_match {
            assert!(check_match(m, rule));
        }

        for m in should_not_match {
            assert!(!check_match(m, rule));
        }
    }

    #[test]
    fn it_webview_xss() {
        let config = Config::default();
        let rules = load_rules(&config).unwrap();
        let rule = rules.get(14).unwrap();

        let should_match = &["setJavaScriptEnabled(true)    .addJavascriptInterface()"];

        let should_not_match = &["", "", "", ""];

        for m in should_match {
            assert!(check_match(m, rule));
        }

        for m in should_not_match {
            assert!(!check_match(m, rule));
        }
    }

    #[test]
    fn it_webview_ssl_errors() {
        let config = Config::default();
        let rules = load_rules(&config).unwrap();
        let rule = rules.get(15).unwrap();

        let should_match = &["onReceivedSslError(WebView view, SslErrorHandler handler, SslError \
                              error)             .proceed();"];

        let should_not_match = &["", "", "", ""];

        for m in should_match {
            assert!(check_match(m, rule));
        }

        for m in should_not_match {
            assert!(!check_match(m, rule));
        }
    }

    #[test]
    fn it_sql_injection() {
        let config = Config::default();
        let rules = load_rules(&config).unwrap();
        let rule = rules.get(16).unwrap();

        let should_match = &["android.database.sqlite   .execSQL(\"INSERT INTO myuser VALUES \
                              ('\" + paramView.getText().toString() + \"', '\" + \
                              localEditText.getText().toString() + \"');\");",
                             "android.database.sqlite   .rawQuery(\"INSERT INTO myuser VALUES \
                              ('\" + paramView.getText().toString() + \"', '\" + \
                              localEditText.getText().toString() + \"');\");"];

        let should_not_match = &[".execSQL(\"INSERT INTO myuser VALUES\"';\");",
                                 "rawQuery(\"INSERT INTO myuser VALUES\";\");",
                                 "",
                                 ""];

        for m in should_match {
            assert!(check_match(m, rule));
        }

        for m in should_not_match {
            assert!(!check_match(m, rule));
        }
    }

    #[test]
    fn it_ssl_accepting_all_certificates() {
        let config = Config::default();
        let rules = load_rules(&config).unwrap();
        let rule = rules.get(17).unwrap();

        let should_match = &["javax.net.ssl   TrustAllSSLSocket-Factory",
                             "javax.net.ssl   AllTrustSSLSocketFactory",
                             "javax.net.ssl   NonValidatingSSLSocketFactory",
                             "javax.net.ssl   ALLOW_ALL_HOSTNAME_VERIFIER",
                             "javax.net.ssl   .setDefaultHostnameVerifier()",
                             "javax.net.ssl   NullHostnameVerifier(')"];

        let should_not_match =
            &["NullHostnameVerifier(')", "javax.net.ssl", "AllTrustSSLSocketFactory", ""];

        for m in should_match {
            assert!(check_match(m, rule));
        }

        for m in should_not_match {
            assert!(!check_match(m, rule));
        }
    }

    #[test]
    fn it_sms_mms_sending() {
        let config = Config::default();
        let rules = load_rules(&config).unwrap();
        let rule = rules.get(18).unwrap();

        let should_match = &["telephony.SmsManager  sendMultipartTextMessage(String destinationAddress, String \
               scAddress, ArrayList<String> parts, ArrayList<PendingIntent> sentIntents, \
               ArrayList<PendingIntent> deliveryIntents)",
                             "telephony.SmsManager  sendTextMessage(String destinationAddress, String \
               scAddress, String text, PendingIntent sentIntent, PendingIntent deliveryIntent)",
                             "telephony.SmsManager  vnd.android-dir/mms-sms",
                             "telephony.SmsManager  vnd.android-dir/mms-sms"];

        let should_not_match = &["vnd.android-dir/mms-sms",
                                 "sendTextMessage(String destinationAddress, String scAddress, \
                                  String text, PendingIntent sentIntent, PendingIntent \
                                  deliveryIntent)",
                                 " sendMultipartTextMessage(String destinationAddress, String \
                                  scAddress, ArrayList<String> parts, ArrayList<PendingIntent> \
                                  sentIntents, ArrayList<PendingIntent> deliveryIntents)",
                                 "telephony.SmsManager "];

        for m in should_match {
            assert!(check_match(m, rule));
        }

        for m in should_not_match {
            assert!(!check_match(m, rule));
        }
    }

    #[test]
    fn it_superuser_privileges() {
        let config = Config::default();
        let rules = load_rules(&config).unwrap();
        let rule = rules.get(19).unwrap();

        let should_match = &["com.noshufou.android.su",
                             "com.thirdparty.superuser",
                             "eu.chainfire.supersu",
                             "com.koushikdutta.superuser",
                             "eu.chainfire."];

        let should_not_match = &["", "", "", ""];

        for m in should_match {
            assert!(check_match(m, rule));
        }

        for m in should_not_match {
            assert!(!check_match(m, rule));
        }
    }

    #[test]
    fn it_superuser_device_detection() {
        let config = Config::default();
        let rules = load_rules(&config).unwrap();
        let rule = rules.get(20).unwrap();

        let should_match = &[".contains(\"test-keys\")",
                             "/system/app/Superuser.apk",
                             "isDeviceRooted()",
                             "/system/bin/failsafe/su",
                             "/system/sd/xbin/su",
                             "RootTools.isAccessGiven()",
                             "RootTools.isAccessGiven()"];

        let should_not_match = &["", "", "", ""];

        for m in should_match {
            assert!(check_match(m, rule));
        }

        for m in should_not_match {
            assert!(!check_match(m, rule));
        }
    }

    #[test]
    fn it_base_station_location() {
        let config = Config::default();
        let rules = load_rules(&config).unwrap();
        let rule = rules.get(21).unwrap();

        let should_match = &["telephony.TelephonyManager    getCellLocation"];

        let should_not_match = &["telephony.TelephonyManager ", " getCellLocation", "", ""];

        for m in should_match {
            assert!(check_match(m, rule));
        }

        for m in should_not_match {
            assert!(!check_match(m, rule));
        }
    }

    #[test]
    fn it_get_device_id() {
        let config = Config::default();
        let rules = load_rules(&config).unwrap();
        let rule = rules.get(22).unwrap();

        let should_match = &["telephony.TelephonyManager      getDeviceId()"];

        let should_not_match = &["getDeviceId()", "telephony.TelephonyManager", "", ""];

        for m in should_match {
            assert!(check_match(m, rule));
        }

        for m in should_not_match {
            assert!(!check_match(m, rule));
        }
    }

    #[test]
    fn it_get_sim_serial() {
        let config = Config::default();
        let rules = load_rules(&config).unwrap();
        let rule = rules.get(23).unwrap();

        let should_match = &["telephony.TelephonyManager      getSimSerialNumber()"];

        let should_not_match = &["getSimSerialNumber()", "telephony.TelephonyManager"];

        for m in should_match {
            assert!(check_match(m, rule));
        }

        for m in should_not_match {
            assert!(!check_match(m, rule));
        }
    }

    #[test]
    fn it_gps_location() {
        let config = Config::default();
        let rules = load_rules(&config).unwrap();
        let rule = rules.get(24).unwrap();

        let should_match = &["android.location   getLastKnownLocation()",
                             "android.location   requestLocationUpdates()",
                             "android.location   getLatitude()",
                             "android.location   getLongitude()"];

        let should_not_match = &["getLastKnownLocation()",
                                 "requestLocationUpdates()",
                                 "getLatitude()",
                                 "getLongitude()",
                                 "android.location"];

        for m in should_match {
            assert!(check_match(m, rule));
        }

        for m in should_not_match {
            assert!(!check_match(m, rule));
        }
    }

    #[test]
    fn it_base64_encode() {
        let config = Config::default();
        let rules = load_rules(&config).unwrap();
        let rule = rules.get(25).unwrap();

        let should_match = &["android.util.Base64 .encodeToString()",
                             "android.util.Base64    .encode()"];

        let should_not_match = &[".encodeToString()", ".encode()", "android.util.Base64"];

        for m in should_match {
            assert!(check_match(m, rule));
        }

        for m in should_not_match {
            assert!(!check_match(m, rule));
        }
    }

    #[test]
    fn it_base64_decoding() {
        let config = Config::default();
        let rules = load_rules(&config).unwrap();
        let rule = rules.get(26).unwrap();

        let should_match = &["android.util.Base64   .decode()"];

        let should_not_match = &["android.util.Base64", ".decode()"];

        for m in should_match {
            assert!(check_match(m, rule));
        }

        for m in should_not_match {
            assert!(!check_match(m, rule));
        }
    }

    #[test]
    fn it_infinite_loop() {
        let config = Config::default();
        let rules = load_rules(&config).unwrap();
        let rule = rules.get(27).unwrap();

        let should_match = &["while(true)"];

        let should_not_match = &["while(i<10)"];

        for m in should_match {
            assert!(check_match(m, rule));
        }

        for m in should_not_match {
            assert!(!check_match(m, rule));
        }
    }

    #[test]
    fn it_email_disclosure() {
        let config = Config::default();
        let rules = load_rules(&config).unwrap();
        let rule = rules.get(28).unwrap();

        let should_match = &["super@super.es",
                             "android_analizer@dem.co.uk",
                             "foo@unadepatatas.com",
                             "android-rust69@tux.rox"];

        let should_not_match = &["@", "@strings/", "@id/user.id", "android:id=\"@id/userid\""];

        for m in should_match {
            assert!(check_match(m, rule));
        }

        for m in should_not_match {
            assert!(!check_match(m, rule));
        }
    }

    #[test]
    fn it_hardcoded_certificate() {
        let config = Config::default();
        let rules = load_rules(&config).unwrap();
        let rule = rules.get(29).unwrap();

        let should_match = &["\"key.key              ",
                             "\"cert.cert\"",
                             "\"    key.pub    ",
                             "\"    cert.pub   ",
                             "     throw new IllegalArgumentException(\"translateAPI.key is not \
                              specified\");"];

        let should_not_match = &["Iterator localIterator = paramBundle.keySet().iterator();",
                                 "import java.security.cert.X509Certificate;",
                                 "",
                                 ""];

        for m in should_match {
            assert!(check_match(m, rule));
        }

        for m in should_not_match {
            assert!(!check_match(m, rule));
        }
    }

    #[test]
    fn it_get_sim_operator() {
        let config = Config::default();
        let rules = load_rules(&config).unwrap();
        let rule = rules.get(30).unwrap();

        let should_match = &["telephony.TelephonyManager      getSimOperator()"];

        let should_not_match = &["getSimOperator()", "telephony.TelephonyManager"];

        for m in should_match {
            assert!(check_match(m, rule));
        }

        for m in should_not_match {
            assert!(!check_match(m, rule));
        }
    }

    #[test]
    fn it_get_sim_operatorname() {
        let config = Config::default();
        let rules = load_rules(&config).unwrap();
        let rule = rules.get(31).unwrap();

        let should_match = &["telephony.TelephonyManager      getSimOperatorName()"];

        let should_not_match = &["getSimOperatorName()", "telephony.TelephonyManager"];

        for m in should_match {
            assert!(check_match(m, rule));
        }

        for m in should_not_match {
            assert!(!check_match(m, rule));
        }
    }

    #[test]
    fn it_obfuscation() {
        let config = Config::default();
        let rules = load_rules(&config).unwrap();
        let rule = rules.get(32).unwrap();

        let should_match = &["android.utils.AESObfuscator getObfuscator();",
                             "android.utils.AESObfuscator   obfuscation.getObfuscator();",
                             "utils.AESObfuscator getObfuscator();",
                             "utils.AESObfuscator   obfuscation.getObfuscator();"];

        let should_not_match = &["AESObfuscator  getObfuscator();",
                                 "android.utils.AESObfuscator   obfuscation",
                                 "getObfuscator();",
                                 "android.utils.AESObfuscator"];

        for m in should_match {
            assert!(check_match(m, rule));
        }

        for m in should_not_match {
            assert!(!check_match(m, rule));
        }
    }

    #[test]
    fn it_command_exec() {
        let config = Config::default();
        let rules = load_rules(&config).unwrap();
        let rule = rules.get(33).unwrap();

        let should_match = &["Runtime.getRuntime().exec(\"command\", options);",
                             "getRuntime().exec(\"ls -la\", options);",
                             "Runtime.getRuntime().exec(\"ls -la\", options);",
                             "getRuntime().exec(\"ps -l\", options);"];

        let should_not_match = &["Runtime.getRuntime()(\"\", options);",
                                 "getRuntime()(\"\", options);",
                                 "Runtime.getRuntime()(\"\", options);",
                                 "getRuntime()(\"\", options);"];

        for m in should_match {
            assert!(check_match(m, rule));
        }

        for m in should_not_match {
            assert!(!check_match(m, rule));
        }
    }

    #[test]
    fn it_ssl_getinsecure_method() {
        let config = Config::default();
        let rules = load_rules(&config).unwrap();
        let rule = rules.get(34).unwrap();

        let should_match = &[" javax.net.ssl.SSLSocketFactory                 \
                              SSLSocketFactory.getInsecure()"];

        let should_not_match = &["getInsecure()",
                                 "javax.net.ssl.SSL  getInsecure();",
                                 "javax.net.ssl.SSLSocketFactory",
                                 "net.ssl.SSL getSecure();"];

        for m in should_match {
            assert!(check_match(m, rule));
        }

        for m in should_not_match {
            assert!(!check_match(m, rule));
        }
    }

    #[test]
    fn it_finally_with_return() {
        let config = Config::default();
        let rules = load_rules(&config).unwrap();
        let rule = rules.get(35).unwrap();

        let should_match = &["finally {                      return;",
                             "finally {                      return;}"];

        let should_not_match =
            &["finally{}", "finally{ var;}", "finally { Printf (“Hello”); return true; }"];

        for m in should_match {
            assert!(check_match(m, rule));
        }

        for m in should_not_match {
            assert!(!check_match(m, rule));
        }
    }

    #[test]
    fn it_sleep_method_notvalidated() {
        let config = Config::default();
        let rules = load_rules(&config).unwrap();
        let rule = rules.get(36).unwrap();

        let should_match = &["int var = EditText.getText  Thread.sleep(100 + var);",
                             "var = .getText  Thread.sleep(100 + var);"];

        let should_not_match = &["int var4 = EditText.getText  Thread.sleep(100 + var);",
                                 "var = .getText  Thread.sleep(100 + hola);",
                                 "",
                                 ""];

        for m in should_match {
            assert!(check_match(m, rule));
        }

        for m in should_not_match {
            assert!(!check_match(m, rule));
        }
    }

    #[test]
    fn it_has_to_check_rule_if_exclude_and_include_regexp_are_not_provided() {
        let rule = Rule {
            regex: Regex::new("").unwrap(),
            permissions: Vec::new(),
            forward_check: None,
            max_sdk: None,
            whitelist: Vec::new(),
            label: String::new(),
            description: String::new(),
            criticality: Criticality::Warning,
            include_file_regex: None,
            exclude_file_regex: None,
        };

        assert!(rule.has_to_check("filename.xml"));
    }

    #[test]
    fn it_has_to_check_rule_if_include_regexp_is_match_and_exlcude_not_provided() {
        let rule = Rule {
            regex: Regex::new("").unwrap(),
            permissions: Vec::new(),
            forward_check: None,
            max_sdk: None,
            whitelist: Vec::new(),
            label: String::new(),
            description: String::new(),
            criticality: Criticality::Warning,
            include_file_regex: Some(Regex::new(r".*\.xml").unwrap()),
            exclude_file_regex: None,
        };

        assert!(rule.has_to_check("filename.xml"));
    }

    #[test]
    fn it_does_not_have_to_check_rule_if_include_regexp_is_non_match_and_exlcude_not_provided() {
        let rule = Rule {
            regex: Regex::new("").unwrap(),
            permissions: Vec::new(),
            forward_check: None,
            max_sdk: None,
            whitelist: Vec::new(),
            label: String::new(),
            description: String::new(),
            criticality: Criticality::Warning,
            include_file_regex: Some(Regex::new(r".*\.xml").unwrap()),
            exclude_file_regex: None,
        };

        assert!(!rule.has_to_check("filename.yml"));
    }

    #[test]
    fn it_has_to_check_rule_if_include_regexp_is_match_and_exlcude_not() {
        let rule = Rule {
            regex: Regex::new("").unwrap(),
            permissions: Vec::new(),
            forward_check: None,
            max_sdk: None,
            whitelist: Vec::new(),
            label: String::new(),
            description: String::new(),
            criticality: Criticality::Warning,
            include_file_regex: Some(Regex::new(r".*\.xml").unwrap()),
            exclude_file_regex: Some(Regex::new(r"nonmatching").unwrap()),
        };

        assert!(rule.has_to_check("filename.xml"));
    }

    #[test]
    fn it_does_not_have_to_check_rule_if_exclude_is_match() {
        let rule = Rule {
            regex: Regex::new("").unwrap(),
            permissions: Vec::new(),
            forward_check: None,
            max_sdk: None,
            whitelist: Vec::new(),
            label: String::new(),
            description: String::new(),
            criticality: Criticality::Warning,
            include_file_regex: Some(Regex::new(r"nonmatching").unwrap()),
            exclude_file_regex: Some(Regex::new(r".*\.xml").unwrap()),
        };

        assert!(!rule.has_to_check("filename.xml"));
    }

    #[test]
    fn it_does_not_have_to_check_if_both_regexps_matches() {
        let rule = Rule {
            regex: Regex::new("").unwrap(),
            permissions: Vec::new(),
            forward_check: None,
            max_sdk: None,
            whitelist: Vec::new(),
            label: String::new(),
            description: String::new(),
            criticality: Criticality::Warning,
            include_file_regex: Some(Regex::new(r".*\.xml").unwrap()),
            exclude_file_regex: Some(Regex::new(r".*\.xml").unwrap()),
        };

        assert!(!rule.has_to_check("filename.xml"));
    }
}
