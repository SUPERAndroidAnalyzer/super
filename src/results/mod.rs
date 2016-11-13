use std::fs;
use std::fs::File;
use std::io::{Read, Write, BufWriter};
use std::collections::{BTreeSet, BTreeMap};
use std::path::Path;
use std::result::Result as StdResult;
use std::error::Error as StdError;

use serde::ser::{Serialize, Serializer};
use chrono::Local;
use handlebars::Handlebars;
use colored::Colorize;
use serde_json::value::Value;
use serde_json::ser;

mod utils;
mod handlebars_helpers;

pub use self::utils::{Vulnerability, split_indent, html_escape};
use self::utils::FingerPrint;
use self::handlebars_helpers::*;

use {Error, Config, Result, Criticity, print_error, print_warning, copy_folder, get_package_name};

pub struct Results {
    app_package: String,
    app_label: String,
    app_description: String,
    app_version: String,
    app_version_num: i32,
    app_min_sdk: i32,
    app_target_sdk: Option<i32>,
    app_fingerprint: FingerPrint,
    #[allow(unused)]
    certificate: String,
    warnings: BTreeSet<Vulnerability>,
    low: BTreeSet<Vulnerability>,
    medium: BTreeSet<Vulnerability>,
    high: BTreeSet<Vulnerability>,
    critical: BTreeSet<Vulnerability>,
    templates: Handlebars,
}

impl Results {
    pub fn init<P: AsRef<Path>>(config: &Config, package: P) -> Option<Results> {
        let path = config.get_results_folder().join(get_package_name(package.as_ref()));
        if !path.exists() || config.is_force() {
            if path.exists() {
                if let Err(e) = fs::remove_dir_all(&path) {
                    print_error(format!("An unknown error occurred when trying to delete the \
                                         results folder: {}",
                                        e),
                                config.is_verbose());
                    return None;
                }
            }

            let fingerprint = match FingerPrint::new(package) {
                Ok(f) => f,
                Err(e) => {
                    print_error(format!("An error occurred when trying to fingerprint the \
                                         application: {}",
                                        e),
                                config.is_verbose());
                    return None;
                }
            };
            let templates = match Results::load_templates(config) {
                Ok(r) => r,
                Err(e) => {
                    print_error(format!("An error occurred when trying to load templates: {}", e),
                                config.is_verbose());
                    return None;
                }
            };
            if config.is_verbose() {
                println!("The results struct has been created. All the vulnerabilitis will now \
                          be recorded and when the analysis ends, they will be written to result \
                          files.");
            } else if !config.is_quiet() {
                println!("Results struct created.");
            }
            Some(Results {
                app_package: String::new(),
                app_label: String::new(),
                app_description: String::new(),
                app_version: String::new(),
                app_version_num: 0,
                app_min_sdk: 0,
                app_target_sdk: None,
                app_fingerprint: fingerprint,
                certificate: String::new(),
                warnings: BTreeSet::new(),
                low: BTreeSet::new(),
                medium: BTreeSet::new(),
                high: BTreeSet::new(),
                critical: BTreeSet::new(),
                templates: templates,
            })
        } else {
            if config.is_verbose() {
                println!("The results for this application have already been generated. No need \
                          to generate them again.");
            } else {
                println!("Skipping result generation.");
            }
            None
        }
    }

    fn load_templates(config: &Config) -> Result<Handlebars> {
        let mut handlebars = Handlebars::new();
        handlebars.register_escape_fn(|s| html_escape(s).into_owned());
        let _ = handlebars.register_helper("line_numbers", Box::new(line_numbers));
        let _ = handlebars.register_helper("html_code", Box::new(html_code));
        let _ = handlebars.register_helper("report_index", Box::new(report_index));
        let _ = handlebars.register_helper("all_code", Box::new(all_code));
        let _ = handlebars.register_helper("all_lines", Box::new(all_lines));
        let _ = handlebars.register_helper("generate_menu", Box::new(generate_menu));
        for dir_entry in fs::read_dir(config.get_template_path())? {
            let dir_entry = dir_entry?;
            if let Some(ext) = dir_entry.path().extension() {
                if ext == "hbs" {
                    handlebars.register_template_file(dir_entry.path()
                                                    .file_stem()
                                                    .ok_or_else(|| {
                                                        Error::TemplateName("template files must \
                                                                             have a file name"
                                                            .to_owned())
                                                    })?
                                                    .to_str()
                                                    .ok_or_else(|| {
                                                        Error::TemplateName("template names must \
                                                                             be unicode"
                                                            .to_owned())
                                                    })?,
                                                dir_entry.path())?;
                }
            }
        }
        if handlebars.get_template("report").is_none() ||
           handlebars.get_template("src").is_none() ||
           handlebars.get_template("code").is_none() {
            Err(Error::TemplateName(format!("templates must include {}, {} and {} templates",
                                            "report".italic(),
                                            "src".italic(),
                                            "code".italic())))
        } else {
            Ok(handlebars)
        }
    }

    pub fn set_app_package<S: Into<String>>(&mut self, package: S) {
        self.app_package = package.into();
    }

    pub fn get_app_package(&self) -> &str {
        &self.app_package
    }

    #[cfg(feature = "certificate")]
    pub fn set_certificate<S: Into<String>>(&mut self, certificate: S) {
        self.certificate = certificate.into();
    }

    pub fn set_app_label<S: Into<String>>(&mut self, label: S) {
        self.app_label = label.into();
    }

    pub fn set_app_description<S: Into<String>>(&mut self, description: S) {
        self.app_description = description.into();
    }

    pub fn set_app_version<S: Into<String>>(&mut self, version: S) {
        self.app_version = version.into();
    }

    pub fn set_app_version_num(&mut self, version: i32) {
        self.app_version_num = version;
    }

    pub fn set_app_min_sdk(&mut self, sdk: i32) {
        self.app_min_sdk = sdk;
    }

    pub fn set_app_target_sdk(&mut self, sdk: i32) {
        self.app_target_sdk = Some(sdk);
    }

    pub fn add_vulnerability(&mut self, vuln: Vulnerability) {
        match vuln.get_criticity() {
            Criticity::Warning => {
                self.warnings.insert(vuln);
            }
            Criticity::Low => {
                self.low.insert(vuln);
            }
            Criticity::Medium => {
                self.medium.insert(vuln);
            }
            Criticity::High => {
                self.high.insert(vuln);
            }
            Criticity::Critical => {
                self.critical.insert(vuln);
            }
        }
    }

    pub fn generate_report<S: AsRef<str>>(&self, config: &Config, package: S) -> Result<bool> {
        let path = config.get_results_folder().join(&self.app_package);
        if config.is_force() || !path.exists() {
            if path.exists() {
                if config.is_verbose() {
                    println!("The application results folder exists. But no more…");
                }

                if let Err(e) = fs::remove_dir_all(&path) {
                    print_warning(format!("There was an error when removing the results \
                                           folder: {}",
                                          e.description()),
                                  config.is_verbose());
                }
            }
            if config.is_verbose() {
                println!("Starting report generation. First we'll create the results folder.");
            }
            fs::create_dir_all(&path)?;
            if config.is_verbose() {
                println!("Results folder created. Time to create the reports.");
            }

            self.generate_json_report(config)?;

            if config.is_verbose() {
                println!("JSON report generated.");
                println!("");
            }

            self.generate_html_report(config, package)?;

            if config.is_verbose() {
                println!("HTML report generated.");
            }
            Ok(true)
        } else {
            if config.is_verbose() {
                println!("Seems that the report has already been generated. There is no need to \
                          o it again.");
            } else {
                println!("Skipping report generation.");
            }
            Ok(false)
        }
    }

    fn generate_json_report(&self, config: &Config) -> Result<()> {
        if config.is_verbose() {
            println!("Starting JSON report generation. First we create the file.")
        }
        let mut f = BufWriter::new(File::create(config.get_results_folder()
                .join(&self.app_package)
                .join("results.json"))
            ?);
        if config.is_verbose() {
            println!("The report file has been created. Now it's time to fill it.")
        }
        ser::to_writer(&mut f, self)?;

        Ok(())
    }

    fn generate_html_report<S: AsRef<str>>(&self, config: &Config, package: S) -> Result<()> {
        if config.is_verbose() {
            println!("Starting HTML report generation. First we create the file.")
        }
        let mut f = File::create(config.get_results_folder()
                .join(&self.app_package)
                .join("index.html"))
            ?;
        if config.is_verbose() {
            println!("The report file has been created. Now it's time to fill it.")
        }

        f.write_all(self.templates.render("report", self)?.as_bytes())?;

        for entry in fs::read_dir(config.get_template_path())? {
            let entry = entry?;
            let entry_path = entry.path();
            if entry.file_type()?.is_dir() {
                copy_folder(&entry_path,
                            &config.get_results_folder()
                                .join(&self.app_package)
                                .join(entry_path.file_name().unwrap()))
                    ?;
            } else {
                match entry_path.as_path().extension() {
                    Some(e) if e == "hbs" => {}
                    None => {}
                    _ => {
                        let _ = fs::copy(&entry_path,
                                         &config.get_results_folder()
                                             .join(&self.app_package))
                            ?;
                    }
                }
            }
        }

        self.generate_code_html_files(config, package)?;

        Ok(())
    }

    fn generate_code_html_files<S: AsRef<str>>(&self, config: &Config, package: S) -> Result<()> {
        let menu = Value::Array(self.generate_code_html_folder("", config, package)?);

        let mut f = File::create(config.get_results_folder()
                .join(&self.app_package)
                .join("src")
                .join("index.html"))
            ?;

        let mut data = BTreeMap::new();
        let _ = data.insert("menu", menu);
        f.write_all(self.templates.render("src", &data)?.as_bytes())?;

        Ok(())
    }

    fn generate_code_html_folder<P: AsRef<Path>, S: AsRef<str>>(&self,
                                                                path: P,
                                                                config: &Config,
                                                                cli_package_name: S)
                                                                -> Result<Vec<Value>> {
        if path.as_ref() == Path::new("classes/android") ||
           path.as_ref() == Path::new("classes/com/google/android/gms") ||
           path.as_ref() == Path::new("smali") {
            return Ok(Vec::new());
        }
        let dir_iter = fs::read_dir(config.get_dist_folder()
                .join(cli_package_name.as_ref())
                .join(path.as_ref()))
            ?;

        fs::create_dir_all(config.get_results_folder()
                .join(&self.app_package)
                .join("src")
                .join(path.as_ref()))
            ?;

        let mut menu = Vec::new();
        for entry in dir_iter {
            let entry = entry?;
            let path = entry.path();

            let prefix = config.get_dist_folder().join(cli_package_name.as_ref());
            let stripped = path.strip_prefix(&prefix).unwrap();

            if path.is_dir() {
                if stripped != Path::new("original") {
                    let inner_menu = self.generate_code_html_folder(stripped, config,
                                                            cli_package_name.as_ref())?;
                    if !inner_menu.is_empty() {
                        let mut object = BTreeMap::new();
                        let name = path.file_name().unwrap().to_string_lossy().into_owned();

                        let _ = object.insert(String::from("name"), Value::String(name));
                        let _ = object.insert(String::from("menu"), Value::Array(inner_menu));
                        menu.push(Value::Object(object));
                    } else {
                        let path = config.get_results_folder()
                            .join(&self.app_package)
                            .join("src")
                            .join(stripped);
                        if path.exists() {
                            fs::remove_dir_all(path)?;
                        }
                    }
                }
            } else {
                match path.extension() {
                    Some(e) if e == "xml" || e == "java" => {
                        self.generate_code_html_for(&stripped, config, cli_package_name.as_ref())?;
                        let name = path.file_name().unwrap().to_string_lossy().into_owned();
                        let mut data = BTreeMap::new();
                        let _ = data.insert(String::from("name"), Value::String(name));
                        let _ = data.insert(String::from("path"),
                                            Value::String(format!("{}", stripped.display())));
                        let _ = data.insert(String::from("type"),
                                            Value::String(e.to_string_lossy().into_owned()));
                        menu.push(Value::Object(data));
                    }
                    _ => {}
                }
            }
        }

        Ok(menu)
    }

    fn generate_code_html_for<P: AsRef<Path>, S: AsRef<str>>(&self,
                                                             path: P,
                                                             config: &Config,
                                                             cli_package_name: S)
                                                             -> Result<()> {
        let mut f_in = File::open(config.get_dist_folder()
                .join(cli_package_name.as_ref())
                .join(path.as_ref()))
            ?;
        let mut f_out = File::create(format!("{}.html",
                                             config.get_results_folder()
                                                 .join(&self.app_package)
                                                 .join("src")
                                                 .join(path.as_ref())
                                                 .display()))
            ?;

        let mut code = String::new();
        let _ = f_in.read_to_string(&mut code)?;

        let mut back_path = String::new();
        for _ in path.as_ref().components() {
            back_path.push_str("../");
        }

        let mut data = BTreeMap::new();
        let _ = data.insert(String::from("path"),
                            Value::String(format!("{}", path.as_ref().display())));
        let _ = data.insert(String::from("code"), Value::String(code));
        let _ = data.insert(String::from("back_path"), Value::String(back_path));

        f_out.write_all(self.templates.render("code", &data)?.as_bytes())?;

        Ok(())
    }
}

impl Serialize for Results {
    fn serialize<S>(&self, serializer: &mut S) -> StdResult<(), S::Error>
        where S: Serializer
    {
        let now = Local::now();
        let mut state = serializer.serialize_struct("Results", 22)?;

        serializer.serialize_struct_elt(&mut state, "super_version", crate_version!())?;
        serializer.serialize_struct_elt(&mut state, "now", &now)?;
        serializer.serialize_struct_elt(&mut state, "now_rfc2822", now.to_rfc2822())?;
        serializer.serialize_struct_elt(&mut state, "now_rfc3339", now.to_rfc3339())?;

        serializer.serialize_struct_elt(&mut state, "app_package", &self.app_package)?;
        serializer.serialize_struct_elt(&mut state, "app_version", &self.app_version)?;
        serializer.serialize_struct_elt(&mut state, "app_version_number", &self.app_version_num)?;
        serializer.serialize_struct_elt(&mut state, "app_fingerprint", &self.app_fingerprint)?;
        serializer.serialize_struct_elt(&mut state, "certificate", &self.certificate)?;

        serializer.serialize_struct_elt(&mut state, "app_min_sdk", &self.app_min_sdk)?;
        serializer.serialize_struct_elt(&mut state, "app_target_sdk", &self.app_target_sdk)?;

        serializer.serialize_struct_elt(&mut state,
                                  "total_vulnerabilities",
                                  self.low.len() + self.medium.len() + self.high.len() +
                                  self.critical.len())?;
        serializer.serialize_struct_elt(&mut state, "criticals", &self.critical)?;
        serializer.serialize_struct_elt(&mut state, "criticals_len", self.critical.len())?;
        serializer.serialize_struct_elt(&mut state, "highs", &self.high)?;
        serializer.serialize_struct_elt(&mut state, "highs_len", self.high.len())?;
        serializer.serialize_struct_elt(&mut state, "mediums", &self.medium)?;
        serializer.serialize_struct_elt(&mut state, "mediums_len", self.medium.len())?;
        serializer.serialize_struct_elt(&mut state, "lows", &self.low)?;
        serializer.serialize_struct_elt(&mut state, "lows_len", self.low.len())?;
        serializer.serialize_struct_elt(&mut state, "warnings", &self.warnings)?;
        serializer.serialize_struct_elt(&mut state, "warnings_len", self.warnings.len())?;

        serializer.serialize_struct_end(state)?;
        Ok(())
    }
}
