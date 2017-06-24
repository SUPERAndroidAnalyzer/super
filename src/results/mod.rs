use std::fs;
use std::collections::BTreeSet;
use std::path::Path;
use std::result::Result as StdResult;
use std::error::Error as StdError;

use serde::ser::{Serialize, SerializeStruct, Serializer};
use chrono::Local;

mod utils;
mod handlebars_helpers;
mod report;

pub use self::utils::{Vulnerability, split_indent, html_escape};
use self::utils::FingerPrint;

use error::*;
use {Config, Criticality, print_warning};

use results::report::{Json, HandlebarsReport};
use results::report::Report;

pub struct Results {
    app_package: String,
    app_label: String,
    app_description: String,
    app_version: String,
    app_version_num: u32,
    app_min_sdk: u32,
    app_target_sdk: Option<u32>,
    app_fingerprint: FingerPrint,
    #[cfg(feature = "certificate")]
    certificate: String,
    warnings: BTreeSet<Vulnerability>,
    low: BTreeSet<Vulnerability>,
    medium: BTreeSet<Vulnerability>,
    high: BTreeSet<Vulnerability>,
    critical: BTreeSet<Vulnerability>,
}

impl Results {
    pub fn init<P: AsRef<Path>>(config: &Config, package: P) -> Result<Results> {
        let fingerprint = match FingerPrint::new(package) {
            Ok(f) => f,
            Err(e) => {
                print_warning(format!(
                    "An error occurred when trying to fingerprint the \
                                       application: {}",
                    e
                ));
                return Err(e)?;
            }
        };
        if config.is_verbose() {
            println!(
                "The results struct has been created. All the vulnerabilitis will now \
                          be recorded and when the analysis ends, they will be written to result \
                          files."
            );
        } else if !config.is_quiet() {
            println!("Results struct created.");
        }

        #[cfg(feature = "certificate")]
        {
            Ok(Results {
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
            })
        }

        #[cfg(not(feature = "certificate"))]
        {
            Ok(Results {
                app_package: String::new(),
                app_label: String::new(),
                app_description: String::new(),
                app_version: String::new(),
                app_version_num: 0,
                app_min_sdk: 0,
                app_target_sdk: None,
                app_fingerprint: fingerprint,
                warnings: BTreeSet::new(),
                low: BTreeSet::new(),
                medium: BTreeSet::new(),
                high: BTreeSet::new(),
                critical: BTreeSet::new(),
            })
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

    pub fn set_app_version_num(&mut self, version: u32) {
        self.app_version_num = version;
    }

    pub fn set_app_min_sdk(&mut self, sdk: u32) {
        self.app_min_sdk = sdk;
    }

    pub fn set_app_target_sdk(&mut self, sdk: u32) {
        self.app_target_sdk = Some(sdk);
    }

    pub fn add_vulnerability(&mut self, vuln: Vulnerability) {
        match vuln.get_criticality() {
            Criticality::Warning => {
                self.warnings.insert(vuln);
            }
            Criticality::Low => {
                self.low.insert(vuln);
            }
            Criticality::Medium => {
                self.medium.insert(vuln);
            }
            Criticality::High => {
                self.high.insert(vuln);
            }
            Criticality::Critical => {
                self.critical.insert(vuln);
            }
        }
    }

    pub fn generate_report<S: AsRef<str>>(&self, config: &Config, package: S) -> Result<()> {
        let path = config.get_results_folder().join(&self.app_package);
        if config.is_verbose() {
            println!("Starting report generation.");
        }
        if !path.exists() {
            if config.is_verbose() {
                println!("First we'll create the results folder.");
            }
            fs::create_dir_all(&path)?;
            if config.is_verbose() {
                println!("Results folder created. Time to create the reports.");
            }
        }
        if config.has_to_generate_json() {
            let path = path.join("results.json");

            if config.is_force() || !path.exists() {
                if path.exists() {
                    if config.is_verbose() {
                        println!("The application JSON results file exists. But no more…");
                    }

                    if let Err(e) = fs::remove_file(&path) {
                        print_warning(format!(
                            "There was an error when removing the JSON results \
                        file: {}",
                            e.description()
                        ));
                    }
                }
                let mut json_reporter = Json::new();

                if let Err(e) = json_reporter.generate(config, self) {
                    print_warning(format!("There was en error generating JSON report: {}", e));
                }

                if !config.is_quiet() {
                    println!("JSON report generated.");
                }
            } else {
                if config.is_verbose() {
                    println!(
                        "Seems that the JSON report has already been generated. There is no \
                              need to do it again."
                    );
                } else {
                    println!("Skipping JSON report generation.");
                }
            }
        }

        if config.has_to_generate_html() {
            let index_path = path.join("index.html");

            if config.is_force() || !index_path.exists() {
                if path.exists() {
                    if config.is_verbose() {
                        println!("The application HTML resulsts exist. But no more…");
                    }

                    for f in fs::read_dir(path).chain_err(
                        || "there was an error when removing the HTML results",
                    )?
                    {
                        let f = f?;

                        if f.file_type()?.is_dir() {
                            fs::remove_dir_all(f.path()).chain_err(
                                || "there was an error when removing the HTML results",
                            )?;
                        } else if &f.file_name() != "results.json" {
                            fs::remove_file(f.path()).chain_err(
                                || "there was an error when removing the HTML results",
                            )?;
                        }
                    }
                }

                let handelbars_report_result =
                    HandlebarsReport::new(config.get_template_path(), package.as_ref().to_owned());

                if let Ok(mut handlebars_reporter) = handelbars_report_result {
                    if let Err(e) = handlebars_reporter.generate(config, self) {
                        print_warning(format!("There was en error generating HTML report: {}", e));
                    }

                    if !config.is_quiet() {
                        println!("HTML report generated.");
                    }
                }
            } else {
                if config.is_verbose() {
                    println!(
                        "Seems that the HTML report has already been generated. There is no
                              need to do it again."
                    );
                } else {
                    println!("Skipping HTML report generation.");
                }
            }
        }

        Ok(())
    }
}

impl Serialize for Results {
    fn serialize<S>(&self, serializer: S) -> StdResult<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let now = Local::now();
        let mut ser_struct = serializer.serialize_struct(
            "Results",
            if cfg!(feature = "certificate") {
                22
            } else {
                21
            },
        )?;

        ser_struct.serialize_field(
            "super_version",
            crate_version!(),
        )?;
        ser_struct.serialize_field("now", &now)?;
        ser_struct.serialize_field("now_rfc2822", &now.to_rfc2822())?;
        ser_struct.serialize_field("now_rfc3339", &now.to_rfc3339())?;

        ser_struct.serialize_field("app_package", &self.app_package)?;
        ser_struct.serialize_field("app_version", &self.app_version)?;
        ser_struct.serialize_field(
            "app_version_number",
            &self.app_version_num,
        )?;
        ser_struct.serialize_field(
            "app_fingerprint",
            &self.app_fingerprint,
        )?;

        #[cfg(feature = "certificate")]
        {
            ser_struct.serialize_field("certificate", &self.certificate)?;
        }

        ser_struct.serialize_field("app_min_sdk", &self.app_min_sdk)?;
        ser_struct.serialize_field(
            "app_target_sdk",
            &self.app_target_sdk,
        )?;

        ser_struct.serialize_field(
            "total_vulnerabilities",
            &(self.low.len() + self.medium.len() + self.high.len() +
                  self.critical.len()),
        )?;
        ser_struct.serialize_field("criticals", &self.critical)?;
        ser_struct.serialize_field(
            "criticals_len",
            &self.critical.len(),
        )?;
        ser_struct.serialize_field("highs", &self.high)?;
        ser_struct.serialize_field("highs_len", &self.high.len())?;
        ser_struct.serialize_field("mediums", &self.medium)?;
        ser_struct.serialize_field(
            "mediums_len",
            &self.medium.len(),
        )?;
        ser_struct.serialize_field("lows", &self.low)?;
        ser_struct.serialize_field("lows_len", &self.low.len())?;
        ser_struct.serialize_field("warnings", &self.warnings)?;
        ser_struct.serialize_field(
            "warnings_len",
            &self.warnings.len(),
        )?;

        ser_struct.end()
    }
}
