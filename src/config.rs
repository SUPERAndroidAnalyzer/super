//! Configuration module.
//!
//! Handles and configures the initial settings and variables needed to run the program.

use std::{u8, fs};
use std::path::{Path, PathBuf};
use std::convert::From;
use std::str::FromStr;
use std::io::Read;
use std::process::exit;
use std::collections::btree_set::Iter;
use std::slice::Iter as VecIter;
use std::collections::BTreeSet;
use std::cmp::{PartialOrd, Ordering};

use colored::Colorize;
use toml::{Parser, Value};

use static_analysis::manifest::Permission;

use {Error, Result, Criticity, print_error, print_warning};

/// Largest number of threads permitted.
const MAX_THREADS: i64 = u8::MAX as i64;

/// Config struct
///
/// Contains configuration related fields. It is used for storing the configuration parameters and
/// checking their values. Implements the `Default` trait.
#[derive(Debug)]
pub struct Config {
    /// Application package.
    app_package: String,
    /// Boolean to represent `--verbose` mode.
    verbose: bool,
    /// Boolean to represent `--quiet` mode.
    quiet: bool,
    /// Boolean to represent `--force` mode.
    force: bool,
    /// Boolean to represent `--bench` mode.
    bench: bool,
    /// Boolean to represent `--open` mode.
    open: bool,
    /// Number of threads.
    threads: u8,
    /// Folder where the applications are stored.
    downloads_folder: PathBuf,
    /// Folder with files from analyzed applications.
    dist_folder: PathBuf,
    /// Folder to store the results of analysis.
    results_folder: PathBuf,
    /// Path to the _Apktool_ binary.
    apktool_file: PathBuf,
    /// Path to the _Dex2jar_ binaries.
    dex2jar_folder: PathBuf,
    /// Path to the _JD\_CMD_ binary.
    jd_cmd_file: PathBuf,
    /// Path to the results template file.
    results_template: PathBuf,
    /// Path to the `rules.json` file.
    rules_json: PathBuf,
    /// Represents an unknow permission.
    unknown_permission: (Criticity, String),
    /// List of permissions to analyze.
    permissions: BTreeSet<PermissionConfig>,
    /// Checker for the loaded files
    loaded_files: Vec<PathBuf>,
}

impl Config {
    /// Creates a new `Config` struct.
    pub fn new<S: AsRef<str>>(app_package: S,
                              verbose: bool,
                              quiet: bool,
                              force: bool,
                              bench: bool,
                              open: bool)
                              -> Result<Config> {
        let mut config: Config = Default::default();
        config.app_package = app_package.as_ref().to_owned();
        config.verbose = verbose;
        config.quiet = quiet;
        config.force = force;
        config.bench = bench;
        config.open = open;

        if cfg!(target_family = "unix") {
            let config_path = PathBuf::from("/etc/config.toml");
            if config_path.exists() {
                try!(Config::load_from_file(&mut config, &config_path, verbose));
                config.loaded_files.push(config_path);
            }
        }
        let config_path = PathBuf::from("config.toml");
        if config_path.exists() {
            try!(Config::load_from_file(&mut config, &config_path, verbose));
            config.loaded_files.push(config_path);
        }

        Ok(config)
    }

    /// Checks if all the needed folders and files exist.
    pub fn check(&self) -> bool {
        self.downloads_folder.exists() && self.get_apk_file().exists() &&
        self.apktool_file.exists() && self.dex2jar_folder.exists() &&
        self.jd_cmd_file.exists() && self.results_template.exists() &&
        self.rules_json.exists()
    }

    /// Returns the folders and files that do not exist.
    pub fn get_errors(&self) -> Vec<String> {
        let mut errors = Vec::new();
        if !self.downloads_folder.exists() {
            errors.push(format!("the downloads folder `{}` does not exist",
                                self.downloads_folder.display()));
        }
        if !self.get_apk_file().exists() {
            errors.push(format!("the APK file `{}` does not exist",
                                self.get_apk_file().display()));
        }
        if !self.apktool_file.exists() {
            errors.push(format!("the APKTool JAR file `{}` does not exist",
                                self.apktool_file.display()));
        }
        if !self.dex2jar_folder.exists() {
            errors.push(format!("the Dex2Jar folder `{}` does not exist",
                                self.dex2jar_folder.display()));
        }
        if !self.jd_cmd_file.exists() {
            errors.push(format!("the jd-cmd file `{}` does not exist",
                                self.jd_cmd_file.display()));
        }
        if !self.results_template.exists() {
            errors.push(format!("the results template `{}` does not exist",
                                self.results_template.display()));
        }
        if !self.rules_json.exists() {
            errors.push(format!("the `{}` rule file does not exist",
                                self.rules_json.display()));
        }
        errors
    }

    /// Returns the currently loaded config files.
    pub fn get_loaded_config_files(&self) -> VecIter<PathBuf> {
        self.loaded_files.iter()
    }

    /// Returns the app package.
    pub fn get_app_package(&self) -> &str {
        &self.app_package
    }

    /// Changes the app package.
    pub fn set_app_package<S: AsRef<str>>(&mut self, app_package: S) {
        self.app_package = app_package.as_ref().to_owned();
    }

    /// Returns the path to the _.apk_.
    pub fn get_apk_file(&self) -> PathBuf {
        self.downloads_folder.join(format!("{}.apk", self.app_package))
    }

    /// Returns true if the application is running in `--verbose` mode, false otherwise.
    pub fn is_verbose(&self) -> bool {
        self.verbose
    }

    /// Activate or disable `--verbose` mode.
    pub fn set_verbose(&mut self, verbose: bool) {
        self.verbose = verbose;
    }

    /// Returns true if the application is running in `--quiet` mode, false otherwise.
    pub fn is_quiet(&self) -> bool {
        self.quiet
    }

    /// Activate or disable `--quiet` mode.
    pub fn set_quiet(&mut self, quiet: bool) {
        self.quiet = quiet;
    }

    /// Returns true if the application is running in `--force` mode, false otherwise.
    pub fn is_force(&self) -> bool {
        self.force
    }

    /// Activate or disable `--force` mode.
    pub fn set_force(&mut self, force: bool) {
        self.force = force;
    }

    /// Returns true if the application is running in `--bench` mode, false otherwise.
    pub fn is_bench(&self) -> bool {
        self.bench
    }

    /// Activate or disable `--bench` mode.
    pub fn set_bench(&mut self, bench: bool) {
        self.bench = bench;
    }

    /// Returns true if the application is running in `--open` mode, false otherwise.
    pub fn is_open(&self) -> bool {
        self.open
    }

    /// Activate or disable `--open` mode.
    pub fn set_open(&mut self, open: bool) {
        self.open = open;
    }

    /// Returns the `threads` field.
    pub fn get_threads(&self) -> u8 {
        self.threads
    }

    /// Returns the path to the `downloads_folder`.
    pub fn get_downloads_folder(&self) -> &Path {
        &self.downloads_folder
    }

    /// Returns the path to the `dist_folder`.
    pub fn get_dist_folder(&self) -> &Path {
        &self.dist_folder
    }

    /// Returns the path to the `results_folder`.
    pub fn get_results_folder(&self) -> &Path {
        &self.results_folder
    }

    /// Returns the path to the`apktool_file`.
    pub fn get_apktool_file(&self) -> &Path {
        &self.apktool_file
    }

    /// Returns the path to the `dex2jar_folder`.
    pub fn get_dex2jar_folder(&self) -> &Path {
        &self.dex2jar_folder
    }

    /// Returns the path to the `jd_cmd_file`.
    pub fn get_jd_cmd_file(&self) -> &Path {
        &self.jd_cmd_file
    }

    /// Returns the `results_template` field.
    pub fn get_results_template(&self) -> &Path {
        &self.results_template
    }

    /// Returns the path to the `rules_json`.
    pub fn get_rules_json(&self) -> &Path {
        &self.rules_json
    }

    /// Returns the criticity of the `unknown_permission` field.
    pub fn get_unknown_permission_criticity(&self) -> Criticity {
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
    fn load_from_file<P: AsRef<Path>>(config: &mut Config, path: P, verbose: bool) -> Result<()> {
        let mut f = try!(fs::File::open(path));
        let mut toml = String::new();
        let _ = try!(f.read_to_string(&mut toml));

        // Parse the configuration file.
        let mut parser = Parser::new(toml.as_str());
        let toml = match parser.parse() {
            Some(t) => t,
            None => {
                print_error(format!("There was an error parsing the config.toml file: {:?}",
                                    parser.errors),
                            verbose);
                exit(Error::ParseError.into());
            }
        };

        // Read the values from the configuration file.
        for (key, value) in toml {
            match key.as_str() {
                "threads" => {
                    match value {
                        Value::Integer(1...MAX_THREADS) => {
                            config.threads = value.as_integer().unwrap() as u8
                        }
                        _ => {
                            print_warning(format!("The 'threads' option in config.toml must \
                                                   be an integer between 1 and {}.\nUsing \
                                                   default.",
                                                  MAX_THREADS),
                                          verbose)
                        }
                    }
                }
                "downloads_folder" => {
                    match value {
                        Value::String(s) => config.downloads_folder = PathBuf::from(s),
                        _ => {
                            print_warning("The 'downloads_folder' option in config.toml must \
                                           be an string.\nUsing default.",
                                          verbose)
                        }
                    }
                }
                "dist_folder" => {
                    match value {
                        Value::String(s) => config.dist_folder = PathBuf::from(s),
                        _ => {
                            print_warning("The 'dist_folder' option in config.toml must be an \
                                           string.\nUsing default.",
                                          verbose)
                        }
                    }
                }
                "results_folder" => {
                    match value {
                        Value::String(s) => config.results_folder = PathBuf::from(s),
                        _ => {
                            print_warning("The 'results_folder' option in config.toml must be \
                                           an string.\nUsing default.",
                                          verbose)
                        }
                    }
                }
                "apktool_file" => {
                    match value {
                        Value::String(s) => {
                            let extension = Path::new(&s).extension();
                            if extension.is_some() && extension.unwrap() == "jar" {
                                config.apktool_file = PathBuf::from(s.clone());
                            } else {
                                print_warning("The APKTool file must be a JAR file.\nUsing \
                                               default.",
                                              verbose)
                            }
                        }
                        _ => {
                            print_warning("The 'apktool_file' option in config.toml must be \
                                           an string.\nUsing default.",
                                          verbose)
                        }
                    }
                }
                "dex2jar_folder" => {
                    match value {
                        Value::String(s) => config.dex2jar_folder = PathBuf::from(s),
                        _ => {
                            print_warning("The 'dex2jar_folder' option in config.toml should \
                                           be an string.\nUsing default.",
                                          verbose)
                        }
                    }
                }
                "jd_cmd_file" => {
                    match value {
                        Value::String(s) => {
                            let extension = Path::new(&s).extension();
                            if extension.is_some() && extension.unwrap() == "jar" {
                                config.jd_cmd_file = PathBuf::from(s.clone());
                            } else {
                                print_warning("The JD-CMD file must be a JAR file.\nUsing \
                                               default.",
                                              verbose)
                            }
                        }
                        _ => {
                            print_warning("The 'jd_cmd_file' option in config.toml must be an \
                                           string.\nUsing default.",
                                          verbose)
                        }
                    }
                }
                "results_template" => {
                    match value {
                        Value::String(s) => config.results_template = PathBuf::from(s),
                        _ => {
                            print_warning("The 'results_template' option in config.toml \
                                           should be an string.\nUsing default.",
                                          verbose)
                        }
                    }
                }
                "rules_json" => {
                    match value {
                        Value::String(s) => {
                            let extension = Path::new(&s).extension();
                            if extension.is_some() && extension.unwrap() == "json" {
                                config.rules_json = PathBuf::from(s.clone());
                            } else {
                                print_warning("The rules.json file must be a JSON \
                                               file.\nUsing default.",
                                              verbose)
                            }
                        }
                        _ => {
                            print_warning("The 'rules_json' option in config.toml must be an \
                                           string.\nUsing default.",
                                          verbose)
                        }
                    }
                }
                "permissions" => {
                    match value {
                        Value::Array(p) => {
                            let format_warning =
                                format!("The permission configuration format must be the \
                                         following:\n{}\nUsing default.",
                                        "[[permissions]]\nname=\"unknown|permission.name\"\n\
                                        criticity = \"warning|low|medium|high|critical\"\n\
                                        label = \"Permission label\"\n\
                                        description = \"Long description to explain the \
                                        vulnerability\""
                                            .italic());

                            for cfg in p {
                                let cfg = match cfg.as_table() {
                                    Some(t) => t,
                                    None => {
                                        print_warning(format_warning, verbose);
                                        break;
                                    }
                                };

                                let name = match cfg.get("name") {
                                    Some(&Value::String(ref n)) => n,
                                    _ => {
                                        print_warning(format_warning, verbose);
                                        break;
                                    }
                                };

                                let criticity = match cfg.get("criticity") {
                                    Some(&Value::String(ref c)) => {
                                        match Criticity::from_str(c) {
                                            Ok(c) => c,
                                            Err(_) => {
                                                print_warning(format!("Criticity must be \
                                                                       one of {}, {}, {}, \
                                                                       {} or {}.\nUsing \
                                                                       default.",
                                                                      "warning".italic(),
                                                                      "low".italic(),
                                                                      "medium".italic(),
                                                                      "high".italic(),
                                                                      "critical".italic()),
                                                              verbose);
                                                break;
                                            }
                                        }
                                    }
                                    _ => {
                                        print_warning(format_warning, verbose);
                                        break;
                                    }
                                };

                                let description = match cfg.get("description") {
                                    Some(&Value::String(ref d)) => d,
                                    _ => {
                                        print_warning(format_warning, verbose);
                                        break;
                                    }
                                };

                                if name == "unknown" {
                                    if cfg.len() != 3 {
                                        print_warning(format!("The format for the unknown \
                                        permissions is the following:\n{}\nUsing default.",
                                        "[[permissions]]\nname = \"unknown\"\n\
                                        criticity = \"warning|low|medium|high|criticity\"\n\
                                        description = \"Long description to explain the \
                                        vulnerability\"".italic()),
                                                      verbose);
                                        break;
                                    }

                                    config.unknown_permission = (criticity, description.clone());
                                } else {
                                    if cfg.len() != 4 {
                                        print_warning(format_warning, verbose);
                                        break;
                                    }

                                    let permission = match Permission::from_str(name.as_str()) {
                                        Ok(p) => p,
                                        Err(_) => {
                                            print_warning(format!("Unknown permission: {}\nTo \
                                                                   set the default \
                                                                   vulnerability level for an \
                                                                   unknown permission, please, \
                                                                   use the {} permission name, \
                                                                   under the {} section.",
                                                                  name.italic(),
                                                                  "unknown".italic(),
                                                                  "[[permissions]]".italic()),
                                                          verbose);
                                            break;
                                        }
                                    };

                                    let label = match cfg.get("label") {
                                        Some(&Value::String(ref l)) => l,
                                        _ => {
                                            print_warning(format_warning, verbose);
                                            break;
                                        }
                                    };
                                    config.permissions
                                        .insert(PermissionConfig::new(permission,
                                                                      criticity,
                                                                      label,
                                                                      &String::from(
                                                                          description.as_ref())));
                                }
                            }
                        }
                        _ => {
                            print_warning("You must specify the permissions you want to \
                                           select as vulnerable.",
                                          verbose)
                        }
                    }
                }
                _ => print_warning(format!("Unknown configuration option {}.", key), verbose),
            }
        }
        Ok(())
    }

    /// Returns the default `Config` struct.
    fn local_default() -> Config {
        Config {
            app_package: String::new(),
            verbose: false,
            quiet: false,
            force: false,
            bench: false,
            open: false,
            threads: 2,
            downloads_folder: PathBuf::from("downloads"),
            dist_folder: PathBuf::from("dist"),
            results_folder: PathBuf::from("results"),
            apktool_file: Path::new("vendor").join("apktool_2.2.0.jar"),
            dex2jar_folder: Path::new("vendor").join("dex2jar-2.0"),
            jd_cmd_file: Path::new("vendor").join("jd-cmd.jar"),
            results_template: Path::new("vendor").join("results_template"),
            rules_json: PathBuf::from("rules.json"),
            unknown_permission: (Criticity::Low,
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
            config.apktool_file = share_path.join("vendor/apktool_2.2.0.jar");
            config.dex2jar_folder = share_path.join("vendor/dex2jar-2.0");
            config.jd_cmd_file = share_path.join("vendor/jd-cmd.jar");
            config.results_template = share_path.join("vendor/results_template");
        }
        config
    }

    /// Creates the default `Config` struct in Windows systems.
    #[cfg(target_family = "windows")]
    fn default() -> Config {
        Config::local_default()
    }
}

/// PermissionConfig struct
///
/// Represents a Permission with all its fields. Implements the `PartialEq` and `PartialOrd`
/// traits.
#[derive(Debug, Ord, Eq)]
pub struct PermissionConfig {
    /// Permission name.
    permission: Permission,
    /// Permission criticity.
    criticity: Criticity,
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
    fn new<S: AsRef<str>>(permission: Permission,
                          criticity: Criticity,
                          label: S,
                          description: S)
                          -> PermissionConfig {
        PermissionConfig {
            permission: permission,
            criticity: criticity,
            label: String::from(label.as_ref()),
            description: String::from(description.as_ref()),
        }
    }

    /// Returns the enum that represents the `permission`.
    pub fn get_permission(&self) -> Permission {
        self.permission
    }

    /// Returns the permission's `criticity`.
    pub fn get_criticity(&self) -> Criticity {
        self.criticity
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
    use Criticity;
    use static_analysis::manifest::Permission;
    use super::Config;
    use std::fs;
    use std::path::Path;

    /// Test for the default configuration function.
    #[test]
    fn it_config() {
        // Create config object.
        let mut config: Config = Default::default();

        // Check that the properties of the config object are correct.
        assert_eq!(config.get_app_package(), "");
        assert!(!config.is_verbose());
        assert!(!config.is_quiet());
        assert!(!config.is_force());
        assert!(!config.is_bench());
        assert!(!config.is_open());
        assert_eq!(config.get_threads(), 2);
        assert_eq!(config.get_downloads_folder(), Path::new("downloads"));
        assert_eq!(config.get_dist_folder(), Path::new("dist"));
        assert_eq!(config.get_results_folder(), Path::new("results"));
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
        assert_eq!(config.get_apktool_file(),
                   share_path.join("vendor").join("apktool_2.2.0.jar"));
        assert_eq!(config.get_dex2jar_folder(),
                   share_path.join("vendor").join("dex2jar-2.0"));
        assert_eq!(config.get_jd_cmd_file(),
                   share_path.join("vendor").join("jd-cmd.jar"));
        assert_eq!(config.get_results_template(),
                   share_path.join("vendor").join("results_template"));
        if cfg!(target_family = "unix") && Path::new("/etc/super/rules.json").exists() {
            assert_eq!(config.get_rules_json(), Path::new("/etc/super/rules.json"));
        } else {
            assert_eq!(config.get_rules_json(), Path::new("rules.json"));
        }
        assert_eq!(config.get_unknown_permission_criticity(), Criticity::Low);
        assert_eq!(config.get_unknown_permission_description(),
                   "Even if the application can create its own permissions, it's discouraged, \
                    since it can lead to missunderstanding between developers.");
        assert_eq!(config.get_permissions().next(), None);

        if !config.get_downloads_folder().exists() {
            fs::create_dir(config.get_downloads_folder()).unwrap();
        }
        if !config.get_dist_folder().exists() {
            fs::create_dir(config.get_dist_folder()).unwrap();
        }
        if !config.get_results_folder().exists() {
            fs::create_dir(config.get_results_folder()).unwrap();
        }

        // Change properties.
        config.set_app_package("test_app");
        config.set_verbose(true);
        config.set_quiet(true);
        config.set_force(true);
        config.set_bench(true);
        config.set_open(true);

        // Check that the new properties are correct.
        assert_eq!(config.get_app_package(), "test_app");
        assert!(config.is_verbose());
        assert!(config.is_quiet());
        assert!(config.is_force());
        assert!(config.is_bench());
        assert!(config.is_open());

        if config.get_apk_file().exists() {
            fs::remove_file(config.get_apk_file()).unwrap();
        }
        assert!(!config.check());

        let _ = fs::File::create(config.get_apk_file()).unwrap();
        assert!(config.check());

        let config = Config::new("test_app", false, false, false, false, false).unwrap();
        let mut error_string = String::from("Configuration errors were found:\n");
        for error in config.get_errors() {
            error_string.push_str(&error);
            error_string.push('\n');
        }
        error_string.push_str("The configuration was loaded, in order, from the following \
                               files:\n\t- Default built-in configuration\n");
        for file in config.get_loaded_config_files() {
            error_string.push_str(&format!("\t- {}\n", file.display()));
        }
        println!("{}", error_string);
        assert!(config.check());

        fs::remove_file(config.get_apk_file()).unwrap();
    }

    /// Test for the `config.toml.sample` sample configuration file.
    #[test]
    fn it_config_sample() {
        // Create config object.
        let mut config = Config::default();
        Config::load_from_file(&mut config, "config.toml.sample", false).unwrap();
        config.set_app_package("test_app");

        // Check that the properties of the config object are correct.
        assert_eq!(config.get_threads(), 2);
        assert_eq!(config.get_downloads_folder(), Path::new("downloads"));
        assert_eq!(config.get_dist_folder(), Path::new("dist"));
        assert_eq!(config.get_results_folder(), Path::new("results"));
        assert_eq!(config.get_apktool_file(),
                   Path::new("/usr/share/super/vendor/apktool_2.2.0.jar"));
        assert_eq!(config.get_dex2jar_folder(),
                   Path::new("/usr/share/super/vendor/dex2jar-2.0"));
        assert_eq!(config.get_jd_cmd_file(),
                   Path::new("/usr/share/super/vendor/jd-cmd.jar"));
        assert_eq!(config.get_results_template(),
                   Path::new("/usr/share/super/vendor/results_template"));
        assert_eq!(config.get_rules_json(), Path::new("/etc/super/rules.json"));
        assert_eq!(config.get_unknown_permission_criticity(), Criticity::Low);
        assert_eq!(config.get_unknown_permission_description(),
                   "Even if the application can create its own permissions, it's discouraged, \
                    since it can lead to missunderstanding between developers.");

        let permission = config.get_permissions().next().unwrap();
        assert_eq!(permission.get_permission(),
                   Permission::AndroidPermissionInternet);
        assert_eq!(permission.get_criticity(), Criticity::Warning);
        assert_eq!(permission.get_label(), "Internet permission");
        assert_eq!(permission.get_description(),
                   "Allows the app to create network sockets and use custom network protocols. \
                    The browser and other applications provide means to send data to the \
                    internet, so this permission is not required to send data to the internet. \
                    Check if the permission is actually needed.");
    }
}
