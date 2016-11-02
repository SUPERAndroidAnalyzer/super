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
use clap::ArgMatches;

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
    /// Application packages to analyze.
    app_packages: Vec<String>,
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
    /// Path to the `rules.json` file.
    rules_json: PathBuf,
    templates_folder: PathBuf,
    template: String,
    /// Represents an unknow permission.
    unknown_permission: (Criticity, String),
    /// List of permissions to analyze.
    permissions: BTreeSet<PermissionConfig>,
    /// Checker for the loaded files
    loaded_files: Vec<PathBuf>,
}

impl Config {
    /// Creates a new `Config` struct.
    pub fn from_cli(cli: ArgMatches<'static>) -> Result<Config> {
        let mut config: Config = Default::default();

        config.verbose = cli.is_present("verbose");
        config.quiet = cli.is_present("quiet");
        config.force = cli.is_present("force");
        config.bench = cli.is_present("bench");
        config.open = cli.is_present("open");

        if cli.is_present("test-all") {
            config.read_apks();
        } else {
            config.add_app_package(cli.value_of("package").unwrap());
        }

        if cfg!(target_family = "unix") {
            let config_path = PathBuf::from("/etc/config.toml");
            if config_path.exists() {
                try!(config.load_from_file(&config_path));
                config.loaded_files.push(config_path);
            }
        }
        let config_path = PathBuf::from("config.toml");
        if config_path.exists() {
            try!(config.load_from_file(&config_path));
            config.loaded_files.push(config_path);
        }

        config.set_options(cli);

        Ok(config)
    }

    /// Modifies the options from the CLI.
    fn set_options(&mut self, cli: ArgMatches<'static>) {
        if let Some(threads) = cli.value_of("threads") {
            match threads.parse() {
                Ok(t) if t > 0u8 => {
                    self.set_threads(t);
                }
                _ => {
                    print_warning(format!("The threads options must be an integer between 1 and \
                                           {}",
                                          u8::MAX),
                                  self.verbose);
                }
            }
        }
        if let Some(downloads_folder) = cli.value_of("downloads") {
            self.set_downloads_folder(downloads_folder);
        }
        if let Some(dist_folder) = cli.value_of("dist") {
            self.set_dist_folder(dist_folder);
        }
        if let Some(results_folder) = cli.value_of("results") {
            self.set_results_folder(results_folder);
        }
        if let Some(apktool_file) = cli.value_of("apktool") {
            self.set_apktool_file(apktool_file);
        }
        if let Some(dex2jar_folder) = cli.value_of("dex2jar") {
            self.set_dex2jar_folder(dex2jar_folder);
        }
        if let Some(jd_cmd_file) = cli.value_of("jd-cmd") {
            self.set_jd_cmd_file(jd_cmd_file);
        }
        if let Some(template_name) = cli.value_of("template") {
            self.template = template_name.to_owned();
        }
        if let Some(rules_json) = cli.value_of("rules") {
            self.set_rules_json(rules_json);
        }
    }

    /// Reads all the apk files in the downloads folder and adds them to the configuration.
    fn read_apks(&mut self) {
        match fs::read_dir(&self.downloads_folder) {
            Ok(iter) => {
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
                                                  e),
                                          self.verbose);
                        }
                    }
                }
            }
            Err(e) => {
                print_error(format!("There was an error when reading the downloads folder: {}",
                                    e),
                            self.verbose);
                exit(Error::from(e).into());
            }
        }
    }

    /// Checks if all the needed folders and files exist.
    pub fn check(&self) -> bool {
        let check = self.downloads_folder.exists() && self.apktool_file.exists() &&
                    self.dex2jar_folder.exists() && self.jd_cmd_file.exists() &&
                    self.get_template_path().exists() &&
                    self.rules_json.exists();
        if check {
            for package in &self.app_packages {
                if !self.get_apk_file(package).exists() {
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
            if !self.get_apk_file(package).exists() {
                errors.push(format!("The APK file `{}` does not exist",
                                    self.get_apk_file(package).display()));
            }
        }
        if !self.apktool_file.exists() {
            errors.push(format!("The APKTool JAR file `{}` does not exist",
                                self.apktool_file.display()));
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
    pub fn get_app_packages(&self) -> &[String] {
        &self.app_packages
    }

    /// Changes the app package.
    pub fn add_app_package<S: Into<String>>(&mut self, app_package: S) {
        self.app_packages.push(app_package.into().replace(".apk", ""));
    }

    /// Returns the path to the apk file of the given package.
    pub fn get_apk_file<S: AsRef<str>>(&self, package: S) -> PathBuf {
        self.downloads_folder.join(format!("{}.apk", package.as_ref()))
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

    /// Sets the `threads` field.
    pub fn set_threads(&mut self, threads: u8) {
        self.threads = threads;
    }

    /// Returns the path to the `downloads_folder`.
    pub fn get_downloads_folder(&self) -> &Path {
        &self.downloads_folder
    }

    /// Sets the path to the `downloads_folder`.
    pub fn set_downloads_folder<P: Into<PathBuf>>(&mut self, downloads_folder: P) {
        self.downloads_folder = downloads_folder.into()
    }

    /// Returns the path to the `dist_folder`.
    pub fn get_dist_folder(&self) -> &Path {
        &self.dist_folder
    }

    /// Sets the path to the `dist_folder`.
    pub fn set_dist_folder<P: Into<PathBuf>>(&mut self, dist_folder: P) {
        self.dist_folder = dist_folder.into()
    }

    /// Returns the path to the `results_folder`.
    pub fn get_results_folder(&self) -> &Path {
        &self.results_folder
    }

    /// Sets the path to the `results_folder`.
    pub fn set_results_folder<P: Into<PathBuf>>(&mut self, results_folder: P) {
        self.results_folder = results_folder.into()
    }

    /// Returns the path to the`apktool_file`.
    pub fn get_apktool_file(&self) -> &Path {
        &self.apktool_file
    }

    /// Sets the path to the `apktool_file`.
    pub fn set_apktool_file<P: Into<PathBuf>>(&mut self, apktool_file: P) {
        self.apktool_file = apktool_file.into()
    }

    /// Returns the path to the `dex2jar_folder`.
    pub fn get_dex2jar_folder(&self) -> &Path {
        &self.dex2jar_folder
    }

    /// Sets the path to the `dex2jar_folder`.
    pub fn set_dex2jar_folder<P: Into<PathBuf>>(&mut self, dex2jar_folder: P) {
        self.dex2jar_folder = dex2jar_folder.into()
    }

    /// Returns the path to the `jd_cmd_file`.
    pub fn get_jd_cmd_file(&self) -> &Path {
        &self.jd_cmd_file
    }

    /// Sets the path to the `jd_cmd_file`.
    pub fn set_jd_cmd_file<P: Into<PathBuf>>(&mut self, jd_cmd_file: P) {
        self.jd_cmd_file = jd_cmd_file.into()
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

    /// Sets the template to use, by name.
    pub fn set_template_name<S: Into<String>>(&mut self, template_name: S) {
        self.template = template_name.into();
    }

    /// Returns the path to the `rules_json`.
    pub fn get_rules_json(&self) -> &Path {
        &self.rules_json
    }

    /// Sets the path to the `rules_json`.
    pub fn set_rules_json<P: Into<PathBuf>>(&mut self, rules_json: P) {
        self.rules_json = rules_json.into()
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
    fn load_from_file<P: AsRef<Path>>(&mut self, path: P) -> Result<()> {
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
                            self.verbose);
                exit(Error::Parse.into());
            }
        };

        // Read the values from the configuration file.
        for (key, value) in toml {
            match key.as_str() {
                "threads" => {
                    match value {
                        Value::Integer(1...MAX_THREADS) => {
                            self.threads = value.as_integer().unwrap() as u8
                        }
                        _ => {
                            print_warning(format!("The 'threads' option in config.toml must \
                                                   be an integer between 1 and {}.\nUsing \
                                                   default.",
                                                  MAX_THREADS),
                                          self.verbose)
                        }
                    }
                }
                "downloads_folder" => {
                    match value {
                        Value::String(s) => self.downloads_folder = PathBuf::from(s),
                        _ => {
                            print_warning("The 'downloads_folder' option in config.toml must \
                                           be an string.\nUsing default.",
                                          self.verbose)
                        }
                    }
                }
                "dist_folder" => {
                    match value {
                        Value::String(s) => self.dist_folder = PathBuf::from(s),
                        _ => {
                            print_warning("The 'dist_folder' option in config.toml must be an \
                                           string.\nUsing default.",
                                          self.verbose)
                        }
                    }
                }
                "results_folder" => {
                    match value {
                        Value::String(s) => self.results_folder = PathBuf::from(s),
                        _ => {
                            print_warning("The 'results_folder' option in config.toml must be \
                                           an string.\nUsing default.",
                                          self.verbose)
                        }
                    }
                }
                "apktool_file" => {
                    match value {
                        Value::String(s) => {
                            let extension = Path::new(&s).extension();
                            if extension.is_some() && extension.unwrap() == "jar" {
                                self.apktool_file = PathBuf::from(s.clone());
                            } else {
                                print_warning("The APKTool file must be a JAR file.\nUsing \
                                               default.",
                                              self.verbose)
                            }
                        }
                        _ => {
                            print_warning("The 'apktool_file' option in config.toml must be \
                                           an string.\nUsing default.",
                                          self.verbose)
                        }
                    }
                }
                "dex2jar_folder" => {
                    match value {
                        Value::String(s) => self.dex2jar_folder = PathBuf::from(s),
                        _ => {
                            print_warning("The 'dex2jar_folder' option in config.toml should \
                                           be an string.\nUsing default.",
                                          self.verbose)
                        }
                    }
                }
                "jd_cmd_file" => {
                    match value {
                        Value::String(s) => {
                            let extension = Path::new(&s).extension();
                            if extension.is_some() && extension.unwrap() == "jar" {
                                self.jd_cmd_file = PathBuf::from(s.clone());
                            } else {
                                print_warning("The JD-CMD file must be a JAR file.\nUsing \
                                               default.",
                                              self.verbose)
                            }
                        }
                        _ => {
                            print_warning("The 'jd_cmd_file' option in config.toml must be an \
                                           string.\nUsing default.",
                                          self.verbose)
                        }
                    }
                }
                "templates_folder" => {
                    match value {
                        Value::String(s) => self.templates_folder = PathBuf::from(s),
                        _ => {
                            print_warning("The 'templates_folder' option in config.toml \
                                           should be an string.\nUsing default.",
                                          self.verbose)
                        }
                    }
                }
                "template" => {
                    match value {
                        Value::String(s) => self.template = s,
                        _ => {
                            print_warning("The 'template' option in config.toml \
                                           should be an string.\nUsing default.",
                                          self.verbose)
                        }
                    }
                }
                "rules_json" => {
                    match value {
                        Value::String(s) => {
                            let extension = Path::new(&s).extension();
                            if extension.is_some() && extension.unwrap() == "json" {
                                self.rules_json = PathBuf::from(s.clone());
                            } else {
                                print_warning("The rules.json file must be a JSON \
                                               file.\nUsing default.",
                                              self.verbose)
                            }
                        }
                        _ => {
                            print_warning("The 'rules_json' option in config.toml must be an \
                                           string.\nUsing default.",
                                          self.verbose)
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
                                        print_warning(format_warning, self.verbose);
                                        break;
                                    }
                                };

                                let name = match cfg.get("name") {
                                    Some(&Value::String(ref n)) => n,
                                    _ => {
                                        print_warning(format_warning, self.verbose);
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
                                                              self.verbose);
                                                break;
                                            }
                                        }
                                    }
                                    _ => {
                                        print_warning(format_warning, self.verbose);
                                        break;
                                    }
                                };

                                let description = match cfg.get("description") {
                                    Some(&Value::String(ref d)) => d.to_owned(),
                                    _ => {
                                        print_warning(format_warning, self.verbose);
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
                                                      self.verbose);
                                        break;
                                    }

                                    self.unknown_permission = (criticity, description.clone());
                                } else {
                                    if cfg.len() != 4 {
                                        print_warning(format_warning, self.verbose);
                                        break;
                                    }

                                    let permission = match Permission::from_str(name) {
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
                                                          self.verbose);
                                            break;
                                        }
                                    };

                                    let label = match cfg.get("label") {
                                        Some(&Value::String(ref l)) => l.to_owned(),
                                        _ => {
                                            print_warning(format_warning, self.verbose);
                                            break;
                                        }
                                    };
                                    self.permissions
                                        .insert(PermissionConfig::new(permission,
                                                                      criticity,
                                                                      label,
                                                                      description));
                                }
                            }
                        }
                        _ => {
                            print_warning("You must specify the permissions you want to \
                                           select as vulnerable.",
                                          self.verbose)
                        }
                    }
                }
                _ => {
                    print_warning(format!("Unknown configuration option {}.", key),
                                  self.verbose)
                }
            }
        }
        Ok(())
    }

    /// Returns the default `Config` struct.
    fn local_default() -> Config {
        Config {
            app_packages: Vec::new(),
            verbose: false,
            quiet: false,
            force: false,
            bench: false,
            open: false,
            threads: 2,
            downloads_folder: PathBuf::from("."),
            dist_folder: PathBuf::from("dist"),
            results_folder: PathBuf::from("results"),
            apktool_file: Path::new("vendor").join("apktool_2.2.0.jar"),
            dex2jar_folder: Path::new("vendor").join("dex2jar-2.1-SNAPSHOT"),
            jd_cmd_file: Path::new("vendor").join("jd-cmd.jar"),
            templates_folder: PathBuf::from("templates"),
            template: String::from("super"),
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
    fn new<L: Into<String>, D: Into<String>>(permission: Permission,
                                             criticity: Criticity,
                                             label: L,
                                             description: D)
                                             -> PermissionConfig {
        PermissionConfig {
            permission: permission,
            criticity: criticity,
            label: label.into(),
            description: description.into(),
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
        let mut config = Config::default();

        // Check that the properties of the config object are correct.
        assert!(config.get_app_packages().is_empty());
        assert!(!config.is_verbose());
        assert!(!config.is_quiet());
        assert!(!config.is_force());
        assert!(!config.is_bench());
        assert!(!config.is_open());
        assert_eq!(config.get_threads(), 2);
        assert_eq!(config.get_downloads_folder(), Path::new("."));
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
        assert_eq!(config.get_apktool_file(),
                   share_path.join("vendor").join("apktool_2.2.0.jar"));
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
        config.add_app_package("test_app");
        config.set_verbose(true);
        config.set_quiet(true);
        config.set_force(true);
        config.set_bench(true);
        config.set_open(true);

        // Check that the new properties are correct.
        assert_eq!(config.get_app_packages()[0], "test_app");
        assert!(config.is_verbose());
        assert!(config.is_quiet());
        assert!(config.is_force());
        assert!(config.is_bench());
        assert!(config.is_open());

        if config.get_apk_file("test_app").exists() {
            fs::remove_file(config.get_apk_file("test_app")).unwrap();
        }
        assert!(!config.check());

        let _ = fs::File::create(config.get_apk_file("test_app")).unwrap();
        assert!(config.check());

        let config = Config::default();
        assert!(config.check());

        fs::remove_file(config.get_apk_file("test_app")).unwrap();
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
        assert_eq!(config.get_downloads_folder(), Path::new("downloads"));
        assert_eq!(config.get_dist_folder(), Path::new("dist"));
        assert_eq!(config.get_results_folder(), Path::new("results"));
        assert_eq!(config.get_apktool_file(),
                   Path::new("/usr/share/super/vendor/apktool_2.2.0.jar"));
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
