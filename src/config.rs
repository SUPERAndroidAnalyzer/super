//! Configuration module.
//!
//! Handles and configures the initial settings and variables needed to run the program.

use std::{u8, fs};
use std::path::{Path, PathBuf};
use std::convert::From;
use std::str::FromStr;
use std::io::Read;
use std::collections::btree_set::Iter;
use std::slice::Iter as VecIter;
use std::collections::BTreeSet;
use std::cmp::{PartialOrd, Ordering};
use std::error::Error as StdError;

use colored::Colorize;
use toml::Value;
use clap::ArgMatches;

use static_analysis::manifest::Permission;

use error::*;
use {Criticality, print_warning};

/// Largest number of threads permitted.
const MAX_THREADS: i64 = u8::MAX as i64;

/// Config struct
///
/// Contains configuration related fields. It is used for storing the configuration parameters and
/// checking their values. Implements the `Default` trait.
#[derive(Debug)]
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
    unknown_permission: (Criticality, String),
    /// List of permissions to analyze.
    permissions: BTreeSet<PermissionConfig>,
    /// Checker for the loaded files
    loaded_files: Vec<PathBuf>,
}

impl Config {
    /// Creates a new `Config` struct.
    pub fn from_cli(cli: ArgMatches<'static>) -> Result<Config> {
        let mut config = Config::default();

        config.verbose = cli.is_present("verbose");
        config.quiet = cli.is_present("quiet");
        config.overall_force = cli.is_present("force");
        config.force = config.overall_force;
        config.bench = cli.is_present("bench");
        config.open = cli.is_present("open");
        config.json = cli.is_present("json");
        config.html = cli.is_present("html");

        if cfg!(target_family = "unix") {
            let config_path = PathBuf::from("/etc/config.toml");
            if config_path.exists() {
                config.load_from_file(&config_path)
                    .chain_err(|| "The config.toml file does not have the correct formatting.")?;
                config.loaded_files.push(config_path);
            }
        }
        let config_path = PathBuf::from("config.toml");
        if config_path.exists() {
            config.load_from_file(&config_path)
                .chain_err(|| "The config.toml file does not have the correct formatting.")?;
            config.loaded_files.push(config_path);
        }

        config.set_options(&cli);

        if cli.is_present("test-all") {
            config.read_apks().chain_err(|| "Error loading all the downloaded APKs")?;
        } else {
            config.add_app_package(cli.value_of("package").unwrap());
        }

        Ok(config)
    }

    /// Modifies the options from the CLI.
    fn set_options(&mut self, cli: &ArgMatches<'static>) {
        if let Some(min_criticality) = cli.value_of("min_criticality") {
            if let Ok(m) = min_criticality.parse() {

                self.min_criticality = m;
            } else {
                print_warning(format!("The min_criticality option must be one of {}, {}, {}, {} \
                                       or {}.\nUsing default.",
                                      "warning".italic(),
                                      "low".italic(),
                                      "medium".italic(),
                                      "high".italic(),
                                      "critical".italic()));
            }
        }
        if let Some(threads) = cli.value_of("threads") {
            match threads.parse() {
                Ok(t) if t > 0_u8 => {
                    self.threads = t;
                }
                _ => {
                    print_warning(format!("The threads option must be an integer between 1 and \
                                           {}",
                                          u8::MAX));
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
                            self.add_app_package(entry.path()
                                                     .file_stem()
                                                     .unwrap()
                                                     .to_string_lossy()
                                                     .into_owned())
                        }
                    }
                }
                Err(e) => {
                    print_warning(format!("There was an error when reading the \
                                                   downloads folder: {}",
                                          e.description()));
                }
            }
        }

        Ok(())
    }

    /// Checks if all the needed folders and files exist.
    pub fn check(&self) -> bool {
        let check = self.downloads_folder.exists() && self.dex2jar_folder.exists() &&
                    self.jd_cmd_file.exists() &&
                    self.get_template_path().exists() &&
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
            errors.push(format!("The downloads folder `{}` does not exist",
                                self.downloads_folder.display()));
        }
        for package in &self.app_packages {
            if !package.exists() {
                errors.push(format!("The APK file `{}` does not exist", package.display()));
            }
        }
        if !self.dex2jar_folder.exists() {
            errors.push(format!("The Dex2Jar folder `{}` does not exist",
                                self.dex2jar_folder.display()));
        }
        if !self.jd_cmd_file.exists() {
            errors.push(format!("The jd-cmd file `{}` does not exist",
                                self.jd_cmd_file.display()));
        }
        if !self.templates_folder.exists() {
            errors.push(format!("the templates folder `{}` does not exist",
                                self.templates_folder.display()));
        }
        if !self.get_template_path().exists() {
            errors.push(format!("the template `{}` does not exist in `{}`",
                                self.template,
                                self.templates_folder.display()));
        }
        if !self.rules_json.exists() {
            errors.push(format!("The `{}` rule file does not exist",
                                self.rules_json.display()));
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
            package_path.set_extension("apk");
        } else if package_path.extension().unwrap() != "apk" {
            let mut file_name = package_path.file_name()
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

    /// Loads a configuration file into the `Config` struct.
    fn load_from_file<P: AsRef<Path>>(&mut self, path: P) -> Result<()> {
        let mut f = fs::File::open(path)?;
        let mut toml = String::new();
        let _ = f.read_to_string(&mut toml)?;

        // Parse the configuration file.
        let toml = if let Value::Table(toml) =
            toml.parse::<Value>().chain_err(|| "there was an error parsing the config.toml file")? {
            toml
        } else {
            return Err(ErrorKind::Parse.into());
        };

        // Read the values from the configuration file.
        for (key, value) in toml {
            match key.as_str() {
                "threads" => self.load_threads_section(value),
                "downloads_folder" => self.load_downloads_folder_section(value),
                "dist_folder" => self.load_dist_folder_section(value),
                "results_folder" => self.load_results_folder_section(value),
                "dex2jar_folder" => self.load_dex2jar_folder_section(value),
                "jd_cmd_file" => self.load_jd_cmd_file_section(value),
                "templates_folder" => self.load_templates_folder_section(value),
                "template" => self.load_template_section(value),
                "rules_json" => self.load_rules_section(value),
                "permissions" => self.load_permissions(value),
                "html_report" => self.load_html_report_section(value),
                "json_report" => self.load_json_report_section(value),
                _ => print_warning(format!("Unknown configuration option {}.", key)),

            }
        }
        Ok(())
    }

    /// Loads threads section from the TOML value.
    fn load_threads_section(&mut self, value: Value) {
        if let Value::Integer(t @ 1...MAX_THREADS) = value {
            #[allow(cast_sign_loss)]
            {
                self.threads = t as u8;
            }
        } else {
            print_warning(format!("The 'threads' option in config.toml must be an integer \
                                   between 1 and {}.\nUsing default.",
                                  MAX_THREADS))
        }
    }

    /// Loads downloads section from the TOML value.
    fn load_downloads_folder_section(&mut self, value: Value) {
        if let Value::String(s) = value {
            self.downloads_folder = s.into();
        } else {
            print_warning("The 'downloads_folder' option in config.toml must be an string.\nUsing \
                           default.")
        }
    }

    /// Loads dist folder section from the TOML value.
    fn load_dist_folder_section(&mut self, value: Value) {
        if let Value::String(s) = value {
            self.dist_folder = s.into();
        } else {
            print_warning("The 'dist_folder' option in config.toml must be an string.\nUsing \
                           default.");
        }
    }

    /// Loads results folder section from the TOML value.
    fn load_results_folder_section(&mut self, value: Value) {
        if let Value::String(s) = value {
            self.results_folder = s.into();
        } else {
            print_warning("The 'results_folder' option in config.toml must be an string.\nUsing \
                           default.");
        }
    }

    /// Loads dex2jar folder section from the TOML value.
    fn load_dex2jar_folder_section(&mut self, value: Value) {
        if let Value::String(s) = value {
            self.dex2jar_folder = s.into();
        } else {
            print_warning("The 'dex2jar_folder' option in config.toml should be an string.\nUsing \
                           default.")
        }
    }

    /// Loads jd cmd file section from the TOML value.
    fn load_jd_cmd_file_section(&mut self, value: Value) {
        if let Value::String(s) = value {
            let extension = Path::new(&s).extension();
            if extension.is_some() && extension.unwrap() == "jar" {
                self.jd_cmd_file = PathBuf::from(s.clone());
            } else {
                print_warning("The JD-CMD file must be a JAR file.\nUsing default.");
            }
        } else {
            print_warning("The 'jd_cmd_file' option in config.toml must be an string.\nUsing \
                           default.")
        }
    }

    /// Loads templated folder section from the TOML value.
    fn load_templates_folder_section(&mut self, value: Value) {
        if let Value::String(ref s) = value {
            self.templates_folder = s.into();
        } else {
            print_warning("The 'templates_folder' option in config.toml should be an string.\n\
                           Using default.")
        }
    }

    /// Loads template section from the TOML value.
    fn load_template_section(&mut self, value: Value) {
        if let Value::String(s) = value {
            self.template = s;
        } else {
            print_warning("The 'template' option in config.toml should be an string.\nUsing \
                           default.")
        }
    }

    /// Loads rules section from the TOML value.
    fn load_rules_section(&mut self, value: Value) {
        if let Value::String(s) = value {
            let extension = Path::new(&s).extension();
            if extension.is_some() && extension.unwrap() == "json" {
                self.rules_json = PathBuf::from(s.clone());
            } else {
                print_warning("The rules.json file must be a JSON \
                                   file.\nUsing default.")
            }
        } else {
            print_warning("The 'rules_json' option in config.toml must be an string.\nUsing \
                           default.")
        }
    }

    /// Loads permissions from the TOML configuration vector.
    fn load_permissions(&mut self, value: Value) {
        if let Value::Array(permissions) = value {
            let format_warning = format!("The permission configuration format must be the following:\n{}\nUsing \
                         default.",
                        "[[permissions]]\nname=\"unknown|permission.name\"\ncriticality = \
                         \"warning|low|medium|high|critical\"\nlabel = \"Permission \
                         label\"\ndescription = \"Long description to explain the vulnerability\""
                            .italic());

            for cfg in permissions {
                let cfg = if let Some(t) = cfg.as_table() {
                    t
                } else {
                    print_warning(format_warning);
                    break;
                };

                let name = if let Some(&Value::String(ref n)) = cfg.get("name") {
                    n
                } else {
                    print_warning(format_warning);
                    break;
                };

                let criticality = if let Some(&Value::String(ref c)) = cfg.get("criticality") {
                    if let Ok(c) = Criticality::from_str(c) {
                        c
                    } else {
                        print_warning(format!("Criticality must be one of {}, {}, {}, {} or \
                                               {}.\nUsing default.",
                                              "warning".italic(),
                                              "low".italic(),
                                              "medium".italic(),
                                              "high".italic(),
                                              "critical".italic()));
                        break;
                    }
                } else {
                    print_warning(format_warning);
                    break;
                };

                let description = if let Some(&Value::String(ref d)) = cfg.get("description") {
                    d.to_owned()
                } else {
                    print_warning(format_warning);
                    break;
                };

                if name == "unknown" {
                    if cfg.len() != 3 {
                        print_warning(format!("The format for the unknown \
                             permissions is the following:\n{}\nUsing default.",
                                              "[[permissions]]\nname = \
                                                   \"unknown\"\ncriticality = \
                                                    \"warning|low|medium|high|criticality\"\n\
                                                    description = \"Long description to explain \
                                                    the vulnerability\""
                                                      .italic()));
                        break;
                    }

                    self.unknown_permission = (criticality, description.clone());
                } else {
                    if cfg.len() != 4 {
                        print_warning(format_warning);
                        break;
                    }

                    let permission = if let Ok(p) = Permission::from_str(name) {
                        p
                    } else {
                        print_warning(format!("Unknown permission: {}\nTo set the default \
                                               vulnerability level for an unknown permission, \
                                               please, use the {} permission name, under the {} \
                                               section.",
                                              name.italic(),
                                              "unknown".italic(),
                                              "[[permissions]]".italic()));
                        break;
                    };

                    let label = if let Some(&Value::String(ref l)) = cfg.get("label") {
                        l.to_owned()
                    } else {
                        print_warning(format_warning);
                        break;
                    };
                    self.permissions.insert(PermissionConfig::new(permission,
                                                                  criticality,
                                                                  label,
                                                                  description));
                }
            }
        } else {
            print_warning("You must specify the permissions you want to select as vulnerable.");
        }
    }

    /// Loads html report section from the TOML value.
    fn load_html_report_section(&mut self, value: Value) {
        if let Value::Boolean(b) = value {
            self.html = b
        } else {
            print_warning("The 'html_report' option in config.toml should be a boolean.\nUsing \
                           default.");
        }
    }

    /// Loads json report section from the TOML value.
    fn load_json_report_section(&mut self, value: Value) {
        if let Value::Boolean(b) = value {
            self.json = b;
        } else {
            print_warning("The 'json_report' option in config.toml should be a boolean.\nUsing \
                           default.");
        }
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
            unknown_permission: (Criticality::Low,
                                 String::from("Even if the application can create its own \
                                               permissions, it's discouraged, since it can \
                                               lead to missunderstanding between developers.")),
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
        let etc_rules = PathBuf::from("/etc/super/rules.json");
        if etc_rules.exists() {
            config.rules_json = etc_rules;
        }
        let share_path = Path::new(if cfg!(target_os = "macos") {
                                       "/usr/local/super"
                                   } else {
                                       "/usr/share/super"
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
#[derive(Debug, Ord, Eq)]
pub struct PermissionConfig {
    /// Permission name.
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
    /// Creates a new `PermissionConfig`.
    fn new<L: Into<String>, D: Into<String>>(permission: Permission,
                                             criticality: Criticality,
                                             label: L,
                                             description: D)
                                             -> PermissionConfig {
        PermissionConfig {
            permission: permission,
            criticality: criticality,
            label: label.into(),
            description: description.into(),
        }
    }

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
    use std::collections::BTreeMap;
    use std::str::FromStr;
    use toml::*;

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
                                       "/usr/local/super"
                                   } else if cfg!(target_family = "windows") {
            ""
        } else {
            "/usr/share/super"
        });
        let share_path = if share_path.exists() {
            share_path
        } else {
            Path::new("")
        };
        assert_eq!(config.get_dex2jar_folder(),
                   share_path.join("vendor").join("dex2jar-2.1-SNAPSHOT"));
        assert_eq!(config.get_jd_cmd_file(),
                   share_path.join("vendor").join("jd-cmd.jar"));
        assert_eq!(config.get_templates_folder(), share_path.join("templates"));
        assert_eq!(config.get_template_path(),
                   share_path.join("templates").join("super"));
        if cfg!(target_family = "unix") && Path::new("/etc/super/rules.json").exists() {
            assert_eq!(config.get_rules_json(), Path::new("/etc/super/rules.json"));
        } else {
            assert_eq!(config.get_rules_json(), Path::new("rules.json"));
        }
        assert_eq!(config.get_unknown_permission_criticality(),
                   Criticality::Low);
        assert_eq!(config.get_unknown_permission_description(),
                   "Even if the application can create its own permissions, it's discouraged, \
                    since it can lead to missunderstanding between developers.");
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
        let mut config = Config::default();
        config.load_from_file("config.toml.sample").unwrap();
        config.add_app_package("test_app");

        // Check that the properties of the config object are correct.
        assert_eq!(config.get_threads(), 2);
        assert_eq!(config.downloads_folder, Path::new("downloads"));
        assert_eq!(config.get_dist_folder(), Path::new("dist"));
        assert_eq!(config.get_results_folder(), Path::new("results"));
        assert_eq!(config.get_dex2jar_folder(),
                   Path::new("/usr/share/super/vendor/dex2jar-2.1-SNAPSHOT"));
        assert_eq!(config.get_jd_cmd_file(),
                   Path::new("/usr/share/super/vendor/jd-cmd.jar"));
        assert_eq!(config.get_templates_folder(),
                   Path::new("/usr/share/super/templates"));
        assert_eq!(config.get_template_path(),
                   Path::new("/usr/share/super/templates/super"));
        assert_eq!(config.get_template_name(), "super");
        assert_eq!(config.get_rules_json(), Path::new("/etc/super/rules.json"));
        assert_eq!(config.get_unknown_permission_criticality(),
                   Criticality::Low);
        assert_eq!(config.get_unknown_permission_description(),
                   "Even if the application can create its own permissions, it's discouraged, \
                    since it can lead to missunderstanding between developers.");

        let permission = config.get_permissions().next().unwrap();
        assert_eq!(permission.get_permission(),
                   Permission::AndroidPermissionInternet);
        assert_eq!(permission.get_criticality(), Criticality::Warning);
        assert_eq!(permission.get_label(), "Internet permission");
        assert_eq!(permission.get_description(),
                   "Allows the app to create network sockets and use custom network protocols. \
                    The browser and other applications provide means to send data to the \
                    internet, so this permission is not required to send data to the internet. \
                    Check if the permission is actually needed.");
    }

    /// Test to check a valid jd cmd file section is loaded
    #[test]
    fn it_loads_jd_cmd_file_section_if_it_is_well_formed() {
        let mut final_config = Config::default();
        let value = Value::String("/some/path/to/jd-cmd.jar".to_string());

        final_config.load_jd_cmd_file_section(value);

        assert_eq!(PathBuf::from("/some/path/to/jd-cmd.jar"),
                   final_config.jd_cmd_file)
    }

    /// Test to check an invalid jd cmd file section is not loaded
    #[test]
    fn it_do_not_load_jd_cmd_file_section_if_it_is_not_well_formed() {
        let default_config = Config::default();
        let mut final_config = Config::default();

        let values = vec![Value::String("/some/invalid/js_cmd.jpg".to_string()),
                          Value::Integer(20)];

        for value in values {
            final_config.load_jd_cmd_file_section(value);
            assert_eq!(default_config.jd_cmd_file, final_config.jd_cmd_file)
        }
    }

    /// Test to check a valid threads section is loaded
    #[test]
    fn it_loads_threads_section_if_it_is_well_formed() {
        let default_config = Config::default();
        let mut final_config = Config::default();
        let value = Value::Integer((default_config.threads + 1) as i64);

        final_config.load_threads_section(value);

        assert_eq!(default_config.threads + 1, final_config.threads)
    }

    /// Test to check an invalid threads section is not loaded
    #[test]
    fn it_do_not_loads_threads_section_if_it_is_not_well_formed() {
        let default_config = Config::default();
        let mut final_config = Config::default();

        let values = vec![Value::Integer(super::MAX_THREADS + 1), Value::Float(2.4)];

        for value in values {
            final_config.load_threads_section(value);
            assert_eq!(default_config.threads, final_config.threads)
        }
    }

    /// Test to check mixed sections that should receive string data
    #[test]
    fn it_loads_string_data_on_some_sections() {
        let mut final_config = Config::default();
        let str_value = "Valid string".to_string();

        final_config.load_downloads_folder_section(Value::String(str_value.clone()));
        final_config.load_dist_folder_section(Value::String(str_value.clone()));
        final_config.load_results_folder_section(Value::String(str_value.clone()));
        final_config.load_dex2jar_folder_section(Value::String(str_value.clone()));
        final_config.load_templates_folder_section(Value::String(str_value.clone()));
        final_config.load_template_section(Value::String(str_value.clone()));

        assert_eq!(final_config.downloads_folder,
                   PathBuf::from(str_value.clone()));
        assert_eq!(final_config.dist_folder, PathBuf::from(str_value.clone()));
        assert_eq!(final_config.results_folder,
                   PathBuf::from(str_value.clone()));
        assert_eq!(final_config.dex2jar_folder,
                   PathBuf::from(str_value.clone()));
        assert_eq!(final_config.templates_folder,
                   PathBuf::from(str_value.clone()));
        assert_eq!(final_config.template, str_value.clone());
    }

    /// Test to check mixed sections that should receive boolean data
    #[test]
    fn it_loads_boolean_data_on_some_sections() {
        let mut final_config = Config::default();

        final_config.load_html_report_section(Value::Boolean(false));
        final_config.load_json_report_section(Value::Boolean(true));

        assert_eq!(final_config.html, false);
        assert_eq!(final_config.json, true);
    }

    /// Test to check a valid rules section is loaded
    #[test]
    fn it_loads_rules_section_if_it_is_well_formed() {
        let mut final_config = Config::default();
        let value = Value::String("/some/path/to/rules.json".to_string());

        final_config.load_rules_section(value);

        assert_eq!(PathBuf::from("/some/path/to/rules.json"),
                   final_config.rules_json)
    }

    /// Test to check an invalid rules section is not loaded
    #[test]
    fn it_do_not_load_rules_section_if_it_is_not_well_formed() {
        let default_config = Config::default();
        let mut final_config = Config::default();

        let values = vec![Value::String("/some/invalid/rules.jpg".to_string()), Value::Integer(20)];

        for value in values {
            final_config.load_rules_section(value);
            assert_eq!(default_config.rules_json, final_config.rules_json)
        }
    }

    #[test]
    fn it_do_not_load_permissions_if_they_are_not_well_formed() {
        let default_config = Config::default();
        let mut final_config = Config::default();

        let permission_without_name: BTreeMap<String, Value> = BTreeMap::new();

        let mut permission_invalid_criticality: BTreeMap<String, Value> = BTreeMap::new();
        permission_invalid_criticality.insert("name".to_string(),
                                              Value::String("permission_name".to_string()))
            .is_some();
        permission_invalid_criticality.insert("criticality".to_string(),
                                              Value::String("invalid_level".to_string()))
            .is_some();

        let mut permission_without_criticality: BTreeMap<String, Value> = BTreeMap::new();
        permission_without_criticality.insert("name".to_string(),
                                              Value::String("permission_name".to_string()))
            .is_some();

        let mut permission_without_description: BTreeMap<String, Value> = BTreeMap::new();
        permission_without_description.insert("name".to_string(),
                                              Value::String("permission_name".to_string()))
            .is_some();
        permission_without_description.insert("criticality".to_string(),
                                              Value::String("low".to_string()))
            .is_some();
        permission_without_description.insert("description".to_string(),
                                              Value::String("permission description".to_string()))
            .is_some();

        let mut permission_unknown_too_much_values: BTreeMap<String, Value> = BTreeMap::new();
        permission_unknown_too_much_values.insert("name".to_string(),
                                                  Value::String("unknown".to_string()))
            .is_some();
        permission_unknown_too_much_values.insert("criticality".to_string(),
                                                  Value::String("low".to_string()))
            .is_some();
        permission_unknown_too_much_values.insert("description".to_string(),
                                                  Value::String("permission description"
                                                                    .to_string()))
            .is_some();
        permission_unknown_too_much_values.insert("additional_field".to_string(),
                                                  Value::String("additional field data"
                                                                    .to_string()))
            .is_some();

        let mut permission_known_too_much_values: BTreeMap<String, Value> = BTreeMap::new();
        permission_known_too_much_values.insert("name".to_string(),
                    Value::String("android.permission.ACCESS_ALL_EXTERNAL_STORAGE".to_string()))
            .is_some();
        permission_known_too_much_values.insert("criticality".to_string(),
                                                Value::String("low".to_string()))
            .is_some();
        permission_known_too_much_values.insert("description".to_string(),
                                                Value::String("permission description"
                                                                  .to_string()))
            .is_some();
        permission_known_too_much_values.insert("label".to_string(),
                                                Value::String("label".to_string()))
            .is_some();
        permission_known_too_much_values.insert("additional_field".to_string(),
                                                Value::String("additional field data".to_string()))
            .is_some();

        let mut permission_known_name_not_found: BTreeMap<String, Value> = BTreeMap::new();
        permission_known_name_not_found.insert("name".to_string(),
                                               Value::String("invalid name".to_string()))
            .is_some();
        permission_known_name_not_found.insert("criticality".to_string(),
                                               Value::String("low".to_string()))
            .is_some();
        permission_known_name_not_found.insert("description".to_string(),
                                               Value::String("permission description".to_string()))
            .is_some();
        permission_known_name_not_found.insert("label".to_string(),
                                               Value::String("label".to_string()))
            .is_some();

        let mut permission_without_label: BTreeMap<String, Value> = BTreeMap::new();
        permission_without_label.insert("name".to_string(),
                                        Value::String("invalid name".to_string()))
            .is_some();
        permission_without_label.insert("criticality".to_string(),
                                        Value::String("low".to_string()))
            .is_some();
        permission_without_label.insert("description".to_string(),
                                        Value::String("permission description".to_string()))
            .is_some();
        permission_without_label.insert("additional_field".to_string(),
                                        Value::String("additional field data".to_string()))
            .is_some();

        let permissions = vec![Value::Integer(20),
                               Value::Table(permission_without_name),
                               Value::Table(permission_invalid_criticality),
                               Value::Table(permission_without_criticality),
                               Value::Table(permission_without_description),
                               Value::Table(permission_unknown_too_much_values),
                               Value::Table(permission_known_too_much_values),
                               Value::Table(permission_known_name_not_found),
                               Value::Table(permission_without_label)];

        for p in permissions {
            final_config.load_permissions(Value::Array(vec![p]));

            assert_eq!(default_config.permissions, final_config.permissions);
            assert_eq!(default_config.unknown_permission,
                       final_config.unknown_permission);
        }
    }


    #[test]
    fn it_loads_an_unknown_permission() {
        let mut final_config = Config::default();

        let mut unknown_permission: BTreeMap<String, Value> = BTreeMap::new();
        unknown_permission.insert("name".to_string(), Value::String("unknown".to_string()))
            .is_some();
        unknown_permission.insert("criticality".to_string(), Value::String("low".to_string()))
            .is_some();
        unknown_permission.insert("description".to_string(),
                                  Value::String("permission description".to_string()))
            .is_some();

        final_config.load_permissions(Value::Array(vec![Value::Table(unknown_permission)]));
        assert_eq!(final_config.get_unknown_permission_criticality(),
                   Criticality::from_str("low").unwrap());
        assert_eq!(final_config.get_unknown_permission_description(),
                   "permission description");
    }

    #[test]
    fn it_loads_an_known_permission() {
        let mut final_config = Config::default();

        let mut unknown_permission: BTreeMap<String, Value> = BTreeMap::new();
        unknown_permission.insert("name".to_string(),
                                  Value::String("android.permission.ACCESS_ALL_EXTERNAL_STORAGE"
                                                    .to_string()))
            .is_some();
        unknown_permission.insert("criticality".to_string(), Value::String("low".to_string()))
            .is_some();
        unknown_permission.insert("description".to_string(),
                                  Value::String("permission description".to_string()))
            .is_some();
        unknown_permission.insert("label".to_string(), Value::String("label".to_string()))
            .is_some();

        final_config.load_permissions(Value::Array(vec![Value::Table(unknown_permission)]));

        assert_eq!(final_config.get_permissions().len(), 1)
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
