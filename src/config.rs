//! Configuration module.
//!
//! Handles and configures the initial settings and variables needed to run the program.

use std::{u8, fs};
use std::path::{Path, PathBuf};
use std::convert::From;
use std::io::Read;
use std::collections::btree_set::Iter;
use std::slice::Iter as VecIter;
use std::collections::BTreeSet;
use std::cmp::{PartialOrd, Ordering};
use std::error::Error as StdError;
use std::result;
use std::str::FromStr;

use colored::Colorize;
use clap::ArgMatches;
use toml;
use serde::Deserializer;
use serde;

use static_analysis::manifest::Permission;

use error::*;
use {Criticality, print_warning};

/// Largest number of threads allowed.
const MAX_THREADS: i64 = u8::MAX as i64;

/// Config structure.
///
/// Contains configuration related fields. It is used for storing the configuration parameters and
/// checking their values. Implements the `Default` trait.
#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Application packages to analyze.
    app_packages: Vec<PathBuf>,
    /// Boolean to represent `--verbose` mode.
    verbose: bool,
    /// Boolean to represent `--quiet` mode.
    quiet: bool,
    /// Boolean to represent overall `--force` mode.
    overall_force: bool,
    /// Boolean to represent current `--force` mode.
    force: bool,
    /// Boolean to represent `--bench` mode.
    bench: bool,
    /// Boolean to represent `--open` mode.
    open: bool,
    /// Boolean to represent `--json` mode.
    json: bool,
    /// Boolean to represent `--html` mode.
    html: bool,
    /// Minimum criticality to analyze
    min_criticality: Criticality,
    /// Number of threads.
    #[serde(deserialize_with = "ConfigDeserializer::deserialize_threads")]
    threads: u8,
    /// Folder where the applications are stored.
    downloads_folder: PathBuf,
    /// Folder with files from analyzed applications.
    dist_folder: PathBuf,
    /// Folder to store the results of analysis.
    results_folder: PathBuf,
    /// Path to the _Dex2jar_ binaries.
    dex2jar_folder: PathBuf,
    /// Path to the _JD\_CMD_ binary.
    jd_cmd_file: PathBuf,
    /// Path to the `rules.json` file.
    rules_json: PathBuf,
    /// The folder where the templates are stored.
    templates_folder: PathBuf,
    /// The name of the template to use.
    template: String,
    /// Represents an unknow permission.
    #[serde(deserialize_with = "ConfigDeserializer::deserialize_unknown_permission")]
    unknown_permission: (Criticality, String),
    /// List of permissions to analyze.
    permissions: BTreeSet<PermissionConfig>,
    /// Checker for the loaded files
    loaded_files: Vec<PathBuf>,
}

/// Helper struct that handles some specific field deserialization for `Config` struct
struct ConfigDeserializer;

impl ConfigDeserializer {
    /// Deserialize `thread` field and checks that is on the proper bounds
    pub fn deserialize_threads<'de, D>(de: D) -> result::Result<u8, D::Error>
    where
        D: Deserializer<'de>,
    {
        let deser_result: toml::value::Value = serde::Deserialize::deserialize(de)?;

        match deser_result {
            toml::value::Value::Integer(threads) => {
                if threads > 0 && threads <= MAX_THREADS {
                    Ok(threads as u8)
                } else {
                    Err(serde::de::Error::custom(
                        "Threads is not in the valid range",
                    ))
                }
            }
            _ => Err(serde::de::Error::custom(
                format!("Unexpected value: {:?}", deser_result),
            )),
        }
    }

    /// Deserialize `unknown_permission` field
    pub fn deserialize_unknown_permission<'de, D>(
        de: D,
    ) -> result::Result<(Criticality, String), D::Error>
    where
        D: Deserializer<'de>,
    {
        let deser_result: toml::value::Value = serde::Deserialize::deserialize(de)?;

        match deser_result {
            toml::value::Value::Table(ref table) => {
                let criticality_str = table.get("criticality").and_then(|v| v.as_str()).ok_or(
                    serde::de::Error::custom("Criticality field not found for unknown permission"),
                )?;
                let string = table.get("description").and_then(|v| v.as_str()).ok_or(
                    serde::de::Error::custom("Description field not found for unknown permission"),
                )?;

                let criticality = Criticality::from_str(criticality_str).map_err(|_| {
                    serde::de::Error::custom(format!(
                        "Invalid `criticality` value found: {}",
                        criticality_str
                    ))
                })?;

                Ok((criticality, string.to_string()))
            }
            _ => Err(serde::de::Error::custom(
                format!("Unexpected value: {:?}", deser_result),
            )),
        }
    }
}

impl Config {
    /// Creates a new `Config` struct.
    pub fn from_file(config_path: &PathBuf) -> Result<Config> {
        let cfg_result: Result<Config> = fs::File::open(config_path)
            .chain_err(|| "Could not open file")
            .and_then(|mut f| {
                let mut toml = String::new();
                let _ = f.read_to_string(&mut toml);

                Ok(toml)
            })
            .and_then(|file_content| {
                toml::from_str(&file_content).chain_err(|| {
                    format!(
                        "Could not decode config file: {}. Using default.",
                        config_path.to_string_lossy()
                    )
                })
            })
            .and_then(|mut new_config: Config| {
                new_config.loaded_files.push(config_path.clone());

                Ok(new_config)
            });

        cfg_result
    }

    /// Decorates the loaded config with the given flags from CLI
    pub fn decorate_with_cli(&mut self, cli: ArgMatches<'static>) -> Result<()> {
        self.set_options(&cli);

        self.verbose = cli.is_present("verbose");
        self.quiet = cli.is_present("quiet");
        self.overall_force = cli.is_present("force");
        self.force = self.overall_force;
        self.bench = cli.is_present("bench");
        self.open = cli.is_present("open");
        self.json = cli.is_present("json");
        self.html = cli.is_present("html");

        if cli.is_present("test-all") {
            self.read_apks().chain_err(
                || "Error loading all the downloaded APKs",
            )?;
        } else {
            self.add_app_package(cli.value_of("package").unwrap());
        }

        Ok(())
    }

    /// Modifies the options from the CLI.
    fn set_options(&mut self, cli: &ArgMatches<'static>) {
        if let Some(min_criticality) = cli.value_of("min_criticality") {
            if let Ok(m) = min_criticality.parse() {

                self.min_criticality = m;
            } else {
                print_warning(format!(
                    "The min_criticality option must be one of {}, {}, {}, {} \
                                       or {}.\nUsing default.",
                    "warning".italic(),
                    "low".italic(),
                    "medium".italic(),
                    "high".italic(),
                    "critical".italic()
                ));
            }
        }
        if let Some(threads) = cli.value_of("threads") {
            match threads.parse() {
                Ok(t) if t > 0_u8 => {
                    self.threads = t;
                }
                _ => {
                    print_warning(format!(
                        "The threads option must be an integer between 1 and \
                                           {}",
                        u8::MAX
                    ));
                }
            }
        }
        if let Some(downloads_folder) = cli.value_of("downloads") {
            self.downloads_folder = PathBuf::from(downloads_folder);
        }
        if let Some(dist_folder) = cli.value_of("dist") {
            self.dist_folder = PathBuf::from(dist_folder);
        }
        if let Some(results_folder) = cli.value_of("results") {
            self.results_folder = PathBuf::from(results_folder);
        }
        if let Some(dex2jar_folder) = cli.value_of("dex2jar") {
            self.dex2jar_folder = PathBuf::from(dex2jar_folder);
        }
        if let Some(jd_cmd_file) = cli.value_of("jd-cmd") {
            self.jd_cmd_file = PathBuf::from(jd_cmd_file);
        }
        if let Some(template_name) = cli.value_of("template") {
            self.template = template_name.to_owned();
        }
        if let Some(rules_json) = cli.value_of("rules") {
            self.rules_json = PathBuf::from(rules_json);
        }
    }

    /// Reads all the apk files in the downloads folder and adds them to the configuration.
    fn read_apks(&mut self) -> Result<()> {
        let iter = fs::read_dir(&self.downloads_folder)?;

        for entry in iter {
            match entry {
                Ok(entry) => {
                    if let Some(ext) = entry.path().extension() {
                        if ext == "apk" {
                            self.add_app_package(
                                entry
                                    .path()
                                    .file_stem()
                                    .unwrap()
                                    .to_string_lossy()
                                    .into_owned(),
                            )
                        }
                    }
                }
                Err(e) => {
                    print_warning(format!(
                        "There was an error when reading the \
                                                   downloads folder: {}",
                        e.description()
                    ));
                }
            }
        }

        Ok(())
    }

    /// Checks if all the needed folders and files exist.
    pub fn check(&self) -> bool {
        let check = self.downloads_folder.exists() && self.dex2jar_folder.exists() &&
            self.jd_cmd_file.exists() && self.get_template_path().exists() &&
            self.rules_json.exists();
        if check {
            for package in &self.app_packages {
                if !package.exists() {
                    return false;
                }
            }
            true
        } else {
            false
        }
    }

    /// Returns the folders and files that do not exist.
    pub fn get_errors(&self) -> Vec<String> {
        let mut errors = Vec::new();
        if !self.downloads_folder.exists() {
            errors.push(format!(
                "The downloads folder `{}` does not exist",
                self.downloads_folder.display()
            ));
        }
        for package in &self.app_packages {
            if !package.exists() {
                errors.push(format!(
                    "The APK file `{}` does not exist",
                    package.display()
                ));
            }
        }
        if !self.dex2jar_folder.exists() {
            errors.push(format!(
                "The Dex2Jar folder `{}` does not exist",
                self.dex2jar_folder.display()
            ));
        }
        if !self.jd_cmd_file.exists() {
            errors.push(format!(
                "The jd-cmd file `{}` does not exist",
                self.jd_cmd_file.display()
            ));
        }
        if !self.templates_folder.exists() {
            errors.push(format!(
                "the templates folder `{}` does not exist",
                self.templates_folder.display()
            ));
        }
        if !self.get_template_path().exists() {
            errors.push(format!(
                "the template `{}` does not exist in `{}`",
                self.template,
                self.templates_folder.display()
            ));
        }
        if !self.rules_json.exists() {
            errors.push(format!(
                "The `{}` rule file does not exist",
                self.rules_json.display()
            ));
        }
        errors
    }

    /// Returns the currently loaded config files.
    pub fn get_loaded_config_files(&self) -> VecIter<PathBuf> {
        self.loaded_files.iter()
    }

    /// Returns the app package.
    pub fn get_app_packages(&self) -> Vec<PathBuf> {
        self.app_packages.clone()
    }

    /// Adds a package to check.
    fn add_app_package<P: AsRef<Path>>(&mut self, app_package: P) {
        let mut package_path = self.downloads_folder.join(app_package);
        if package_path.extension().is_none() {
            let updated = package_path.set_extension("apk");
            debug_assert!(
                updated,
                "did not update package path extension, no file name"
            );
        } else if package_path.extension().unwrap() != "apk" {
            let mut file_name = package_path
                .file_name()
                .unwrap()
                .to_string_lossy()
                .into_owned();
            file_name.push_str(".apk");
            package_path.set_file_name(file_name);
        }

        self.app_packages.push(package_path);
    }

    /// Returns true if the application is running in `--verbose` mode, false otherwise.
    pub fn is_verbose(&self) -> bool {
        self.verbose
    }

    /// Returns true if the application is running in `--quiet` mode, false otherwise.
    pub fn is_quiet(&self) -> bool {
        self.quiet
    }

    /// Returns true if the application is running in `--force` mode, false otherwise.
    pub fn is_force(&self) -> bool {
        self.force
    }

    /// Sets the application to force recreate the analysis files and results temporarily.
    pub fn set_force(&mut self) {
        self.force = true;
    }

    /// Resets the `--force` option, so that it gets reset to the configured force option.
    pub fn reset_force(&mut self) {
        self.force = self.overall_force
    }

    /// Returns true if the application is running in `--bench` mode, false otherwise.
    pub fn is_bench(&self) -> bool {
        self.bench
    }

    /// Returns true if the application is running in `--open` mode, false otherwise.
    pub fn is_open(&self) -> bool {
        self.open
    }

    /// Returns true if the application has to generate result in JSON format.
    pub fn has_to_generate_json(&self) -> bool {
        self.json
    }

    /// Returns true if the application has to generate result in HTML format.
    pub fn has_to_generate_html(&self) -> bool {
        !self.json || self.html
    }

    /// Returns the `min_criticality` field.
    pub fn get_min_criticality(&self) -> Criticality {
        self.min_criticality
    }

    /// Returns the `threads` field.
    pub fn get_threads(&self) -> u8 {
        self.threads
    }

    /// Returns the path to the `dist_folder`.
    pub fn get_dist_folder(&self) -> &Path {
        &self.dist_folder
    }

    /// Returns the path to the `results_folder`.
    pub fn get_results_folder(&self) -> &Path {
        &self.results_folder
    }

    /// Returns the path to the `dex2jar_folder`.
    pub fn get_dex2jar_folder(&self) -> &Path {
        &self.dex2jar_folder
    }

    /// Returns the path to the `jd_cmd_file`.
    pub fn get_jd_cmd_file(&self) -> &Path {
        &self.jd_cmd_file
    }

    /// Gets the path to the template.
    pub fn get_template_path(&self) -> PathBuf {
        self.templates_folder.join(&self.template)
    }

    /// Gets the path to the templates folder.
    pub fn get_templates_folder(&self) -> &Path {
        &self.templates_folder
    }

    /// Gets the name of the template.
    pub fn get_template_name(&self) -> &str {
        &self.template
    }

    /// Returns the path to the `rules_json`.
    pub fn get_rules_json(&self) -> &Path {
        &self.rules_json
    }

    /// Returns the criticality of the `unknown_permission` field.
    pub fn get_unknown_permission_criticality(&self) -> Criticality {
        self.unknown_permission.0
    }

    /// Returns the description of the `unknown_permission` field.
    pub fn get_unknown_permission_description(&self) -> &str {
        self.unknown_permission.1.as_str()
    }

    /// Returns the loaded `permissions`.
    pub fn get_permissions(&self) -> Iter<PermissionConfig> {
        self.permissions.iter()
    }

    /// Returns the default `Config` struct.
    fn local_default() -> Config {
        Config {
            app_packages: Vec::new(),
            verbose: false,
            quiet: false,
            overall_force: false,
            force: false,
            bench: false,
            open: false,
            json: false,
            html: false,
            threads: 2,
            min_criticality: Criticality::Warning,
            downloads_folder: PathBuf::from("."),
            dist_folder: PathBuf::from("dist"),
            results_folder: PathBuf::from("results"),
            dex2jar_folder: Path::new("vendor").join("dex2jar-2.1-SNAPSHOT"),
            jd_cmd_file: Path::new("vendor").join("jd-cmd.jar"),
            templates_folder: PathBuf::from("templates"),
            template: String::from("super"),
            rules_json: PathBuf::from("rules.json"),
            unknown_permission: (
                Criticality::Low,
                String::from(
                    "Even if the application can create its own \
                                               permissions, it's discouraged, since it can \
                                               lead to missunderstanding between developers.",
                ),
            ),
            permissions: BTreeSet::new(),
            loaded_files: Vec::new(),
        }
    }
}

impl Default for Config {
    /// Creates the default `Config` struct in Unix systems.
    #[cfg(target_family = "unix")]
    fn default() -> Config {
        let mut config = Config::local_default();
        let etc_rules = PathBuf::from("/etc/super-analyzer/rules.json");
        if etc_rules.exists() {
            config.rules_json = etc_rules;
        }
        let share_path = Path::new(if cfg!(target_os = "macos") {
            "/usr/local/super-analyzer"
        } else {
            "/usr/share/super-analyzer"
        });
        if share_path.exists() {
            config.dex2jar_folder = share_path.join("vendor/dex2jar-2.1-SNAPSHOT");
            config.jd_cmd_file = share_path.join("vendor/jd-cmd.jar");
            config.templates_folder = share_path.join("templates");
        }
        config
    }

    /// Creates the default `Config` struct in Windows systems.
    #[cfg(target_family = "windows")]
    fn default() -> Config {
        Config::local_default()
    }
}

/// Vulnerable permission configuration information.
///
/// Represents a Permission with all its fields. Implements the `PartialEq` and `PartialOrd`
/// traits.
#[derive(Debug, Ord, Eq, Deserialize)]
pub struct PermissionConfig {
    /// Permission name.
    #[serde(rename = "name")]
    permission: Permission,
    /// Permission criticality.
    criticality: Criticality,
    /// Permission label.
    label: String,
    /// Permission description.
    description: String,
}

impl PartialEq for PermissionConfig {
    fn eq(&self, other: &PermissionConfig) -> bool {
        self.permission == other.permission
    }
}

impl PartialOrd for PermissionConfig {
    fn partial_cmp(&self, other: &PermissionConfig) -> Option<Ordering> {
        if self.permission < other.permission {
            Some(Ordering::Less)
        } else if self.permission > other.permission {
            Some(Ordering::Greater)
        } else {
            Some(Ordering::Equal)
        }
    }
}

impl PermissionConfig {
    /// Returns the enum that represents the `permission`.
    pub fn get_permission(&self) -> Permission {
        self.permission
    }

    /// Returns the permission's `criticality`.
    pub fn get_criticality(&self) -> Criticality {
        self.criticality
    }

    /// Returns the permission's `label`.
    pub fn get_label(&self) -> &str {
        self.label.as_str()
    }

    /// Returns the permission's `description`.
    pub fn get_description(&self) -> &str {
        self.description.as_str()
    }
}

#[cfg(test)]
mod tests {
    use Criticality;
    use static_analysis::manifest::Permission;
    use super::Config;
    use std::fs;
    use std::path::{Path, PathBuf};

    /// Test for the default configuration function.
    #[test]
    fn it_config() {
        // Create config object.
        let mut config = Config::default();

        // Check that the properties of the config object are correct.
        assert!(config.get_app_packages().is_empty());
        assert!(!config.is_verbose());
        assert!(!config.is_quiet());
        assert!(!config.is_force());
        assert!(!config.is_bench());
        assert!(!config.is_open());
        assert_eq!(config.get_threads(), 2);
        assert_eq!(config.downloads_folder, Path::new("."));
        assert_eq!(config.get_dist_folder(), Path::new("dist"));
        assert_eq!(config.get_results_folder(), Path::new("results"));
        assert_eq!(config.get_template_name(), "super");
        let share_path = Path::new(if cfg!(target_os = "macos") {
            "/usr/local/super-analyzer"
        } else if cfg!(target_family = "windows") {
            ""
        } else {
            "/usr/share/super-analyzer"
        });
        let share_path = if share_path.exists() {
            share_path
        } else {
            Path::new("")
        };
        assert_eq!(
            config.get_dex2jar_folder(),
            share_path.join("vendor").join("dex2jar-2.1-SNAPSHOT")
        );
        assert_eq!(
            config.get_jd_cmd_file(),
            share_path.join("vendor").join("jd-cmd.jar")
        );
        assert_eq!(config.get_templates_folder(), share_path.join("templates"));
        assert_eq!(
            config.get_template_path(),
            share_path.join("templates").join("super")
        );
        if cfg!(target_family = "unix") && Path::new("/etc/super-analyzer/rules.json").exists() {
            assert_eq!(
                config.get_rules_json(),
                Path::new("/etc/super-analyzer/rules.json")
            );
        } else {
            assert_eq!(config.get_rules_json(), Path::new("rules.json"));
        }
        assert_eq!(
            config.get_unknown_permission_criticality(),
            Criticality::Low
        );
        assert_eq!(
            config.get_unknown_permission_description(),
            "Even if the application can create its own permissions, it's discouraged, \
                    since it can lead to missunderstanding between developers."
        );
        assert_eq!(config.get_permissions().next(), None);

        if !config.downloads_folder.exists() {
            fs::create_dir(&config.downloads_folder).unwrap();
        }
        if !config.get_dist_folder().exists() {
            fs::create_dir(config.get_dist_folder()).unwrap();
        }
        if !config.get_results_folder().exists() {
            fs::create_dir(config.get_results_folder()).unwrap();
        }

        // Change properties.
        config.add_app_package("test_app");
        config.verbose = true;
        config.quiet = true;
        config.force = true;
        config.bench = true;
        config.open = true;

        // Check that the new properties are correct.
        let packages = config.get_app_packages();
        assert_eq!(&packages[0], &config.downloads_folder.join("test_app.apk"));
        assert!(config.is_verbose());
        assert!(config.is_quiet());
        assert!(config.is_force());
        assert!(config.is_bench());
        assert!(config.is_open());

        config.reset_force();
        assert!(!config.is_force());

        config.overall_force = true;
        config.reset_force();
        assert!(config.is_force());

        if packages[0].exists() {
            fs::remove_file(&packages[0]).unwrap();
        }
        assert!(!config.check());

        let _ = fs::File::create(&packages[0]).unwrap();
        assert!(config.check());

        let config = Config::default();
        assert!(config.check());

        fs::remove_file(&packages[0]).unwrap();
    }

    /// Test for the `config.toml.sample` sample configuration file.
    #[test]
    fn it_config_sample() {
        // Create config object.
        let mut config = Config::from_file(&PathBuf::from("config.toml.sample")).unwrap();
        config.add_app_package("test_app");

        // Check that the properties of the config object are correct.
        assert_eq!(config.get_threads(), 2);
        assert_eq!(config.downloads_folder, Path::new("downloads"));
        assert_eq!(config.get_dist_folder(), Path::new("dist"));
        assert_eq!(config.get_results_folder(), Path::new("results"));
        assert_eq!(
            config.get_dex2jar_folder(),
            Path::new("/usr/share/super-analyzer/vendor/dex2jar-2.1-SNAPSHOT")
        );
        assert_eq!(
            config.get_jd_cmd_file(),
            Path::new("/usr/share/super-analyzer/vendor/jd-cmd.jar")
        );
        assert_eq!(
            config.get_templates_folder(),
            Path::new("/usr/share/super-analyzer/templates")
        );
        assert_eq!(
            config.get_template_path(),
            Path::new("/usr/share/super-analyzer/templates/super")
        );
        assert_eq!(config.get_template_name(), "super");
        assert_eq!(
            config.get_rules_json(),
            Path::new("/etc/super-analyzer/rules.json")
        );
        assert_eq!(
            config.get_unknown_permission_criticality(),
            Criticality::Low
        );
        assert_eq!(
            config.get_unknown_permission_description(),
            "Even if the application can create its own permissions, it's discouraged, \
                    since it can lead to missunderstanding between developers."
        );

        let permission = config.get_permissions().next().unwrap();
        assert_eq!(
            permission.get_permission(),
            Permission::AndroidPermissionInternet
        );
        assert_eq!(permission.get_criticality(), Criticality::Warning);
        assert_eq!(permission.get_label(), "Internet permission");
        assert_eq!(
            permission.get_description(),
            "Allows the app to create network sockets and use custom network protocols. \
                    The browser and other applications provide means to send data to the \
                    internet, so this permission is not required to send data to the internet. \
                    Check if the permission is actually needed."
        );
    }

    /// Test to check the default reports to be generated
    #[test]
    fn it_generates_html_but_not_json_by_default() {
        let mut final_config = Config::default();
        final_config.html = false;
        final_config.json = false;

        assert!(final_config.has_to_generate_html());
        assert!(!final_config.has_to_generate_json());
    }
}
