//! Results generation module.

use std::{collections::BTreeSet, fs, path::Path};

use chrono::Local;
use clap::crate_version;
use failure::{Error, ResultExt};
use serde::ser::{Serialize, SerializeStruct, Serializer};

mod handlebars_helpers;
mod report;
mod sdk_number;
mod utils;

pub use self::utils::{html_escape, split_indent, Vulnerability};
use self::{
    sdk_number::{prettify_android_version, SdkNumber},
    utils::FingerPrint,
};
use crate::{
    criticality::Criticality,
    print_warning,
    results::report::{Generator, HandlebarsReport, Json},
    Config,
};

/// Results representation structure.
pub struct Results {
    /// Application package name.
    app_package: String,
    /// Application label.
    app_label: String,
    /// Application description.
    app_description: String,
    /// Application version string.
    app_version: String,
    /// Application version number.
    app_version_num: u32,
    /// Application minimum SDK.
    app_min_sdk: SdkNumber,
    /// Target SDK for the application.
    app_target_sdk: Option<SdkNumber>,
    /// Fingerprint of the application,
    app_fingerprint: FingerPrint,
    /// Certificate of the application.
    #[cfg(feature = "certificate")]
    certificate: String,
    /// List of warnings found in the application.
    warnings: BTreeSet<Vulnerability>,
    /// List of the potential low criticality vulnerabilities in the application.
    low: BTreeSet<Vulnerability>,
    /// List of the potential medium criticality vulnerabilities in the application.
    medium: BTreeSet<Vulnerability>,
    /// List of the potential high criticality vulnerabilities in the application.
    high: BTreeSet<Vulnerability>,
    /// List of the potential critical vulnerabilities in the application.
    critical: BTreeSet<Vulnerability>,
}

impl Results {
    /// Initializes the results structure.
    #[allow(clippy::print_stdout)]
    pub fn init<P: AsRef<Path>>(config: &Config, package: P) -> Result<Self, Error> {
        let fingerprint = match FingerPrint::from_package(package) {
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
                "The results struct has been created. All the vulnerabilities will now \
                 be recorded and when the analysis ends, they will be written to result \
                 files."
            );
        } else if !config.is_quiet() {
            println!("Results structure created.");
        }

        #[cfg(feature = "certificate")]
        {
            Ok(Self {
                app_package: String::new(),
                app_label: String::new(),
                app_description: String::new(),
                app_version: String::new(),
                app_version_num: 0,
                app_min_sdk: SdkNumber::Unknown(0),
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
            Ok(Self {
                app_package: String::new(),
                app_label: String::new(),
                app_description: String::new(),
                app_version: String::new(),
                app_version_num: 0,
                app_min_sdk: SdkNumber::Unknown(0),
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

    /// Sets the application's package.
    pub fn set_app_package<S: Into<String>>(&mut self, package: S) {
        self.app_package = package.into();
    }

    /// Gets the application package.
    pub fn app_package(&self) -> &str {
        &self.app_package
    }

    /// Sets the certificate string.
    #[cfg(feature = "certificate")]
    pub fn set_certificate<S: Into<String>>(&mut self, certificate: S) {
        self.certificate = certificate.into();
    }

    /// Sets the application's label.
    pub fn set_app_label<S: Into<String>>(&mut self, label: S) {
        self.app_label = label.into();
    }

    /// Sets the application description
    pub fn set_app_description<S: Into<String>>(&mut self, description: S) {
        self.app_description = description.into();
    }

    /// Sets the application version string.
    pub fn set_app_version<S: Into<String>>(&mut self, version: S) {
        self.app_version = version.into();
    }

    /// Sets the application version number.
    pub fn set_app_version_num(&mut self, version: u32) {
        self.app_version_num = version;
    }

    /// Sets the application's minimum SDK number.
    pub fn set_app_min_sdk(&mut self, sdk: u32) {
        self.app_min_sdk = SdkNumber::from(sdk);
    }

    /// Sets the application's target SDK number.
    pub fn set_app_target_sdk(&mut self, sdk: u32) {
        self.app_target_sdk = Some(SdkNumber::from(sdk));
    }

    /// Adds a vulnerability to the results.
    //#[allow(unused_variables)] // Until we remove the debug assertions
    pub fn add_vulnerability(&mut self, vulnerability: Vulnerability) {
        match vulnerability.get_criticality() {
            Criticality::Warning => {
                let _new = self.warnings.insert(vulnerability);
                // FIXME should we maintain it?
                //debug_assert!(new, "trying to insert the same warning twice");
            }
            Criticality::Low => {
                let _new = self.low.insert(vulnerability);
                // FIXME should we maintain it?
                // debug_assert!(
                //     new,
                //     "trying to insert the same low criticality vulnerability twice"
                // );
            }
            Criticality::Medium => {
                let _new = self.medium.insert(vulnerability);
                // FIXME should we maintain it?
                // debug_assert!(
                //     new,
                //     "trying to insert the same medium criticality vulnerability twice"
                // );
            }
            Criticality::High => {
                let _new = self.high.insert(vulnerability);
                // FIXME should we maintain it?
                // debug_assert!(
                //     new,
                //     "trying to insert the same high criticality vulnerability twice"
                // );
            }
            Criticality::Critical => {
                let _new = self.critical.insert(vulnerability);
                // FIXME should we maintain it?
                // debug_assert!(
                //     new,
                //     "trying to insert the same critical vulnerability twice"
                // );
            }
        }
    }

    /// Generates the report.
    #[allow(clippy::print_stdout)]
    pub fn generate_report<S: AsRef<str>>(&self, config: &Config, package: S) -> Result<(), Error> {
        let path = config.results_folder().join(&self.app_package);
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
                        println!("The application JSON results file existed. But no more!");
                    }

                    if let Err(e) = fs::remove_file(&path) {
                        print_warning(format!(
                            "there was an error when removing the JSON results file: {}",
                            e
                        ));
                    }
                }
                let mut json_reporter = Json::new();

                if let Err(e) = json_reporter.generate(config, self) {
                    print_warning(format!("there was en error generating JSON report: {}", e));
                }

                if !config.is_quiet() {
                    println!("JSON report generated.");
                }
            } else if config.is_verbose() {
                println!(
                    "Seems that the JSON report has already been generated. There is no \
                     need to do it again."
                );
            } else {
                println!("Skipping JSON report generation.");
            }
        }

        if config.has_to_generate_html() {
            let index_path = path.join("index.html");

            if config.is_force() || !index_path.exists() {
                if path.exists() {
                    if config.is_verbose() {
                        println!("The application HTML results existed. But no more!");
                    }

                    for f in fs::read_dir(path)
                        .context("there was an error when removing the HTML results")?
                    {
                        let f = f?;

                        if f.file_type()?.is_dir() {
                            fs::remove_dir_all(f.path())
                                .context("there was an error when removing the HTML results")?;
                        } else if &f.file_name() != "results.json" {
                            fs::remove_file(f.path())
                                .context("there was an error when removing the HTML results")?;
                        }
                    }
                }

                let handlebars_report_result = HandlebarsReport::from_path(
                    config.template_path(),
                    package.as_ref().to_owned(),
                );

                if let Ok(mut handlebars_reporter) = handlebars_report_result {
                    if let Err(e) = handlebars_reporter.generate(config, self) {
                        print_warning(format!("There was en error generating HTML report: {}", e));
                    }

                    if !config.is_quiet() {
                        println!("HTML report generated.");
                    }
                }
            } else if config.is_verbose() {
                println!(
                    "Seems that the HTML report has already been generated. There is no
                          need to do it again."
                );
            } else {
                println!("Skipping HTML report generation.");
            }
        }

        Ok(())
    }
}

impl Serialize for Results {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let now = Local::now();
        let len = {
            let mut len = 21;
            if cfg!(feature = "certificate") {
                len += 1;
            }
            if self.app_min_sdk.version().is_some() {
                len += 1;
            }
            if let Some(target) = self.app_target_sdk {
                if target.version().is_some() {
                    len += 3;
                } else {
                    len += 2;
                }
            }
            len
        };
        let mut ser_struct = serializer.serialize_struct("Results", len)?;

        ser_struct.serialize_field("super_version", crate_version!())?;
        ser_struct.serialize_field("now", &now)?;
        ser_struct.serialize_field("now_rfc2822", &now.to_rfc2822())?;
        ser_struct.serialize_field("now_rfc3339", &now.to_rfc3339())?;

        ser_struct.serialize_field("app_package", &self.app_package)?;
        ser_struct.serialize_field("app_version", &self.app_version)?;
        ser_struct.serialize_field("app_version_number", &self.app_version_num)?;
        ser_struct.serialize_field("app_fingerprint", &self.app_fingerprint)?;

        #[cfg(feature = "certificate")]
        {
            ser_struct.serialize_field("certificate", &self.certificate)?;
        }

        ser_struct.serialize_field("app_min_sdk_number", &self.app_min_sdk.number())?;

        ser_struct.serialize_field("app_min_sdk_name", self.app_min_sdk.name())?;

        if let Some(version) = self.app_min_sdk.version() {
            ser_struct
                .serialize_field("app_min_sdk_version", &prettify_android_version(&version))?;
        }

        if let Some(sdk) = self.app_target_sdk {
            ser_struct.serialize_field("app_target_sdk_number", &sdk.number())?;

            ser_struct.serialize_field("app_target_sdk_name", sdk.name())?;

            if let Some(version) = sdk.version() {
                ser_struct.serialize_field(
                    "app_target_sdk_version",
                    &prettify_android_version(&version),
                )?;
            }
        }

        ser_struct.serialize_field(
            "total_vulnerabilities",
            &(self.low.len() + self.medium.len() + self.high.len() + self.critical.len()),
        )?;
        ser_struct.serialize_field("criticals", &self.critical)?;
        ser_struct.serialize_field("criticals_len", &self.critical.len())?;
        ser_struct.serialize_field("highs", &self.high)?;
        ser_struct.serialize_field("highs_len", &self.high.len())?;
        ser_struct.serialize_field("mediums", &self.medium)?;
        ser_struct.serialize_field("mediums_len", &self.medium.len())?;
        ser_struct.serialize_field("lows", &self.low)?;
        ser_struct.serialize_field("lows_len", &self.low.len())?;
        ser_struct.serialize_field("warnings", &self.warnings)?;
        ser_struct.serialize_field("warnings_len", &self.warnings.len())?;

        ser_struct.end()
    }
}
