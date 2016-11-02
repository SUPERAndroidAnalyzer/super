use std::fs;
use std::fs::File;
use std::io::{Read, Write};
use std::collections::{BTreeSet, BTreeMap};
use std::path::Path;
use std::result::Result as StdResult;

use serde_json::builder::ObjectBuilder;
use serde::ser::{Serialize, Serializer};
use chrono::Local;
use handlebars::Handlebars;
use colored::Colorize;
use serde_json::value::Value;

mod utils;
mod handlebars_helpers;

pub use self::utils::{Benchmark, Vulnerability, split_indent};
use self::utils::FingerPrint;
use self::handlebars_helpers::*;

use {Error, Config, Result, Criticity, print_error, print_warning, copy_folder};

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
    pub fn init<S: AsRef<str>>(config: &Config, package: S) -> Option<Results> {
        let path = config.get_results_folder().join(package.as_ref());
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

            let fingerprint = match FingerPrint::new(config, package.as_ref()) {
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
            }
            None
        }
    }

    fn load_templates(config: &Config) -> Result<Handlebars> {
        let mut handlebars = Handlebars::new();
        let _ = handlebars.register_helper("line_numbers", Box::new(line_numbers));
        let _ = handlebars.register_helper("html_code", Box::new(html_code));
        let _ = handlebars.register_helper("report_index", Box::new(report_index));
        let _ = handlebars.register_helper("all_code", Box::new(all_code));
        let _ = handlebars.register_helper("all_lines", Box::new(all_lines));
        for dir_entry in try!(fs::read_dir(config.get_template_path())) {
            let dir_entry = try!(dir_entry);
            if let Some(ext) = dir_entry.path().extension() {
                if ext == "hbs" {
                    try!(handlebars.register_template_file(try!(try!(dir_entry.path()
                            .file_stem()
                            .ok_or(Error::TemplateName(String::from("template files \
                                                                          must have a file \
                                                                          name"))))
                        .to_str()
                        .ok_or(Error::TemplateName(String::from("template names must be \
                                                                  unicode")))),
                                                           dir_entry.path()));
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

    pub fn generate_report<S: AsRef<str>>(&self, package: S, config: &Config) -> Result<()> {
        let path = config.get_results_folder().join(package.as_ref());
        if !path.exists() || config.is_force() {
            if path.exists() {
                if let Err(e) = fs::remove_dir_all(&path) {
                    print_warning(format!("There was an error when removing the report folder: \
                                           {}",
                                          e),
                                  config.is_verbose());
                }
            }

            if config.is_verbose() {
                println!("Starting report generation. First we'll create the results folder.");
            }
            try!(fs::create_dir_all(&path));
            if config.is_verbose() {
                println!("Results folder created. Time to create the reports.");
            }

            try!(self.generate_json_report(package.as_ref(), config));

            if config.is_verbose() {
                println!("JSON report generated.");
                println!("");
            }

            try!(self.generate_html_report(package.as_ref(), config));

            if config.is_verbose() {
                println!("HTML report generated.");
            }
        }

        Ok(())
    }

    fn generate_json_report<S: AsRef<str>>(&self, package: S, config: &Config) -> Result<()> {
        if config.is_verbose() {
            println!("Starting JSON report generation. First we create the file.")
        }
        let mut f = try!(File::create(config.get_results_folder()
            .join(package.as_ref())
            .join("results.json")));
        if config.is_verbose() {
            println!("The report file has been created. Now it's time to fill it.")
        }

        let report = ObjectBuilder::new()
            .insert("label", self.app_label.as_str())
            .insert("description", self.app_description.as_str())
            .insert("package", self.app_package.as_str())
            .insert("version", self.app_version.as_str())
            .insert("fingerprint", &self.app_fingerprint)
            .insert_array("warnings", |builder| {
                let mut builder = builder;
                for warn in &self.warnings {
                    builder = builder.push(warn);
                }
                builder
            })
            .insert_array("low", |builder| {
                let mut builder = builder;
                for vuln in &self.low {
                    builder = builder.push(vuln);
                }
                builder
            })
            .insert_array("medium", |builder| {
                let mut builder = builder;
                for vuln in &self.medium {
                    builder = builder.push(vuln);
                }
                builder
            })
            .insert_array("high", |builder| {
                let mut builder = builder;
                for vuln in &self.high {
                    builder = builder.push(vuln);
                }
                builder
            })
            .insert_array("critical", |builder| {
                let mut builder = builder;
                for vuln in &self.critical {
                    builder = builder.push(vuln);
                }
                builder
            })
            .build();

        try!(f.write_all(&format!("{:?}", report).into_bytes()));

        Ok(())
    }

    fn generate_html_report<S: AsRef<str>>(&self, package: S, config: &Config) -> Result<()> {
        if config.is_verbose() {
            println!("Starting HTML report generation. First we create the file.")
        }
        let mut f = try!(File::create(config.get_results_folder()
            .join(package.as_ref())
            .join("index.html")));
        if config.is_verbose() {
            println!("The report file has been created. Now it's time to fill it.")
        }

        try!(f.write_all(try!(self.templates.render("report", self)).as_bytes()));

        for entry in try!(fs::read_dir(config.get_template_path())) {
            let entry = try!(entry);
            let entry_path = entry.path();
            if try!(entry.file_type()).is_dir() {
                try!(copy_folder(&entry_path,
                                 &config.get_results_folder()
                                     .join(package.as_ref())
                                     .join(entry_path.file_name().unwrap())));
            } else {
                match entry_path.as_path().extension() {
                    Some(e) if e == "hbs" => {}
                    None => {}
                    _ => {
                        let _ = try!(fs::copy(&entry_path,
                                              &config.get_results_folder()
                                                  .join(package.as_ref())));
                    }
                }
            }
        }

        try!(self.generate_code_html_files(config, package.as_ref()));

        Ok(())
    }

    fn generate_code_html_files<S: AsRef<str>>(&self, config: &Config, package: S) -> Result<()> {
        let menu = Value::Array(try!(self.generate_code_html_folder("", config, package.as_ref())));

        let mut f = try!(File::create(config.get_results_folder()
            .join(package.as_ref())
            .join("src")
            .join("index.html")));

        let mut data = BTreeMap::new();
        let _ = data.insert("menu", menu);
        try!(f.write_all(try!(self.templates.render("src", &data)).as_bytes()));

        Ok(())
    }

    fn generate_code_html_folder<P: AsRef<Path>, S: AsRef<str>>(&self,
                                                                path: P,
                                                                config: &Config,
                                                                package: S)
                                                                -> Result<Vec<Value>> {
        if path.as_ref() == Path::new("classes/android") ||
           path.as_ref() == Path::new("classes/com/google/android/gms") ||
           path.as_ref() == Path::new("smali") {
            return Ok(Vec::new());
        }
        let dir_iter = try!(fs::read_dir(config.get_dist_folder()
            .join(package.as_ref())
            .join(path.as_ref())));

        try!(fs::create_dir_all(config.get_results_folder()
            .join(package.as_ref())
            .join("src")
            .join(path.as_ref())));

        let mut menu = Vec::new();
        for entry in dir_iter {
            let entry = try!(entry);
            let path = entry.path();

            if path.is_dir() {
                let prefix = config.get_dist_folder().join(package.as_ref());
                let stripped = path.strip_prefix(&prefix).unwrap();

                if stripped != Path::new("original") {
                    let inner_menu =
                        try!(self.generate_code_html_folder(stripped, config, package.as_ref()));
                    if !inner_menu.is_empty() {
                        let mut object = BTreeMap::new();
                        let name = path.file_name().unwrap().to_string_lossy().into_owned();

                        let _ = object.insert(String::from("name"), Value::String(name));
                        let _ = object.insert(String::from("menu"), Value::Array(inner_menu));
                        menu.push(Value::Object(object));
                    } else {
                        let path = config.get_results_folder()
                            .join(package.as_ref())
                            .join("src")
                            .join(stripped);
                        if path.exists() {
                            try!(fs::remove_dir_all(path));
                        }
                    }
                }
            } else {
                match path.extension() {
                    Some(e) if e == "xml" || e == "java" => {
                        let prefix = config.get_dist_folder().join(package.as_ref());
                        let path = path.strip_prefix(&prefix).unwrap();
                        try!(self.generate_code_html_for(&path, config, package.as_ref()));
                        let name = path.file_name().unwrap().to_string_lossy().into_owned();
                        let mut data = BTreeMap::new();
                        let _ = data.insert(String::from("name"), Value::String(name));
                        let _ = data.insert(String::from("path"),
                                            Value::String(format!("{}", path.display())));
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

    // fn generate_html_src_menu<P: AsRef<Path>>(&self,
    //                                           dir_path: P,
    //                                           config: &Config)
    //                                           -> Result<Value> {
    //     let iter = try!(fs::read_dir(config.get_results_folder()
    //         .join(config.get_app_package())
    //         .join("src")
    //         .join(dir_path.as_ref())));
    //     let mut menu = BTreeMap::new();
    //     for entry in iter {
    //         let entry = try!(entry);
    //         let path = entry.path();
    //         if path.is_file() {
    //             let html_file_name = entry.file_name();
    //             let html_file_name = html_file_name.as_os_str().to_string_lossy();
    //             let extension = Path::new(&html_file_name[..html_file_name.len() - 5])
    //                 .extension()
    //                 .unwrap();
    //             let link_path = match format!("{}", dir_path.as_ref().display()).as_str() {
    //                 "" => String::new(),
    //                 p => {
    //                     let mut p = String::from(p);
    //                     p.push('/');
    //                     p
    //                 }
    //             };
    //
    //             if extension == "xml" || extension == "java" {
    //                 menu.push_str(format!("<li><a href=\"{0}{1}.html\" title=\"{1}\" \
    //                                        target=\"code\"><img \
    //                                        src=\"../img/{2}-icon.png\">{1}</a></li>",
    //                                       link_path,
    //                                       &html_file_name[..html_file_name.len() - 5],
    //                                       extension.to_string_lossy())
    //                     .as_str());
    //             }
    //         } else if path.is_dir() {
    //             let dir_name = match path.file_name() {
    //                 Some(n) => String::from(n.to_string_lossy().borrow()),
    //                 None => String::new(),
    //             };
    //             let prefix = config.get_results_folder()
    //                 .join(config.get_app_package())
    //                 .join("src");
    //             let submenu =
    //                         match
    // self.generate_html_src_menu(path.strip_prefix(&prefix).unwrap(),
    //                                                     config) {
    //                             Ok(m) => m,
    //                             Err(e) => {
    //                                 let path = path.to_string_lossy();
    //                                 print_warning(format!("An error occurred when generating \
    //                                                        the menu for {}. The result \
    //                                                        generation process will continue, \
    //                                                        though. More info: {}",
    //                                                       path,
    //                                                       e),
    //                                               config.is_verbose());
    //                                 break;
    //                             }
    //                         };
    //             menu.push_str(format!("<li><a href=\"#\" title=\"{0}\"><img \
    //                                    src=\"../img/folder-icon.png\">{0}</a>{1}</li>",
    //                                   dir_name,
    //                                   submenu.as_str())
    //                 .as_str());
    //         }
    //     }
    //     Ok(menu)
    // }

    fn generate_code_html_for<P: AsRef<Path>, S: AsRef<str>>(&self,
                                                             path: P,
                                                             config: &Config,
                                                             package: S)
                                                             -> Result<()> {
        let mut f_in = try!(File::open(config.get_dist_folder()
            .join(package.as_ref())
            .join(path.as_ref())));
        let mut f_out = try!(File::create(format!("{}.html",
                                                  config.get_results_folder()
                                                      .join(package.as_ref())
                                                      .join("src")
                                                      .join(path.as_ref())
                                                      .display())));

        let mut code = String::new();
        let _ = try!(f_in.read_to_string(&mut code));

        let mut back_path = String::new();
        for _ in path.as_ref().components() {
            back_path.push_str("../");
        }

        let mut data = BTreeMap::new();
        let _ = data.insert(String::from("path"),
                            Value::String(format!("{}", path.as_ref().display())));
        let _ = data.insert(String::from("code"), Value::String(code));
        let _ = data.insert(String::from("back_path"), Value::String(back_path));

        try!(f_out.write_all(try!(self.templates.render("code", &data)).as_bytes()));

        Ok(())
    }
}

impl Serialize for Results {
    fn serialize<S>(&self, serializer: &mut S) -> StdResult<(), S::Error>
        where S: Serializer
    {
        let now = Local::now();
        let mut state = try!(serializer.serialize_struct("Results", 23));

        try!(serializer.serialize_struct_elt(&mut state, "super_version", crate_version!()));
        try!(serializer.serialize_struct_elt(&mut state, "now", &now));
        try!(serializer.serialize_struct_elt(&mut state, "now_rfc2822", now.to_rfc2822()));
        try!(serializer.serialize_struct_elt(&mut state, "now_rfc3339", now.to_rfc3339()));

        try!(serializer.serialize_struct_elt(&mut state, "app_package", &self.app_package));
        try!(serializer.serialize_struct_elt(&mut state, "app_version", &self.app_version));
        try!(serializer.serialize_struct_elt(&mut state, "app_version_number",
                                             &self.app_version_num));
        try!(serializer.serialize_struct_elt(&mut state, "app_fingerprint", &self.app_fingerprint));
        try!(serializer.serialize_struct_elt(&mut state, "certificate", &self.certificate));

        try!(serializer.serialize_struct_elt(&mut state, "app_min_sdk", &self.app_min_sdk));
        try!(serializer.serialize_struct_elt(&mut state, "app_target_sdk", &self.app_target_sdk));

        try!(serializer.serialize_struct_elt(&mut state,
                                             "total_vulnerabilities",
                                             self.low.len() + self.medium.len() + self.high.len() +
                                             self.critical.len()));
        try!(serializer.serialize_struct_elt(&mut state, "criticals", &self.critical));
        try!(serializer.serialize_struct_elt(&mut state, "criticals_len", self.critical.len()));
        try!(serializer.serialize_struct_elt(&mut state, "highs", &self.high));
        try!(serializer.serialize_struct_elt(&mut state, "highs_len", self.high.len()));
        try!(serializer.serialize_struct_elt(&mut state, "mediums", &self.medium));
        try!(serializer.serialize_struct_elt(&mut state, "mediums_len", self.medium.len()));
        try!(serializer.serialize_struct_elt(&mut state, "lows", &self.low));
        try!(serializer.serialize_struct_elt(&mut state, "lows_len", self.low.len()));
        try!(serializer.serialize_struct_elt(&mut state, "warnings", &self.warnings));
        try!(serializer.serialize_struct_elt(&mut state, "warnings_len", self.warnings.len()));

        try!(serializer.serialize_struct_end(state));
        Ok(())
    }
}
