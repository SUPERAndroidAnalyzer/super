//! Configuration module.
//!
//! Handles and configures the initial settings and variables needed to run the program.

use std::{
    cmp::{Ordering, PartialOrd},
    collections::{btree_set::Iter, BTreeSet},
    convert::From,
    fs, i64,
    path::{Path, PathBuf},
    slice::Iter as VecIter,
    str::FromStr,
    usize,
};

use clap::ArgMatches;
use colored::Colorize;
use failure::{format_err, Error, ResultExt};
use num_cpus;
use serde::{de, Deserialize, Deserializer};
use toml::{self, value::Value};

use crate::{criticality::Criticality, print_warning, static_analysis::manifest};

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
    threads: usize,
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
    /// Represents an unknown permission.
    #[serde(deserialize_with = "ConfigDeserializer::deserialize_unknown_permission")]
    unknown_permission: (Criticality, String),
    /// List of permissions to analyze.
    permissions: BTreeSet<Permission>,
    /// Checker for the loaded files
    loaded_files: Vec<PathBuf>,
}

/// Helper struct that handles some specific field deserialization for `Config` struct
struct ConfigDeserializer;

/// `Criticality` and `String` tuple, used to shorten some return types.
type CriticalityString = (Criticality, String);

impl ConfigDeserializer {
    /// Deserialize `thread` field and checks that is on the proper bounds
    pub fn deserialize_threads<'de, D>(de: D) -> Result<usize, D::Error>
    where
        D: Deserializer<'de>,
    {
        let deserialize_result: Value = Deserialize::deserialize(de)?;

        #[allow(clippy::use_debug)]
        match deserialize_result {
            Value::Integer(threads) => {
                if threads > 0 && threads <= {
                    // TODO: change it for compile-time check.
                    if (usize::max_value() as i64) < 0 {
                        // 64-bit machine
                        i64::max_value()
                    } else {
                        // Smaller than 64 bit words.
                        usize::max_value() as i64
                    }
                } {
                    Ok(threads as usize)
                } else {
                    Err(de::Error::custom("threads is not in the valid range"))
                }
            }
            _ => Err(de::Error::custom(format!(
                "unexpected value: {:?}",
                deserialize_result
            ))),
        }
    }

    /// Deserialize `unknown_permission` field
    pub fn deserialize_unknown_permission<'de, D>(de: D) -> Result<CriticalityString, D::Error>
    where
        D: Deserializer<'de>,
    {
        let deserialize_result: Value = Deserialize::deserialize(de)?;

        #[allow(clippy::use_debug)]
        match deserialize_result {
            Value::Table(ref table) => {
                let criticality_str = table
                    .get("criticality")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| {
                        de::Error::custom("criticality field not found for unknown permission")
                    })?;
                let string = table
                    .get("description")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| {
                        de::Error::custom("description field not found for unknown permission")
                    })?;

                let criticality = Criticality::from_str(criticality_str).map_err(|_| {
                    de::Error::custom(format!(
                        "invalid `criticality` value found: {}",
                        criticality_str
                    ))
                })?;

                Ok((criticality, string.to_string()))
            }
            _ => Err(de::Error::custom(format!(
                "Unexpected value: {:?}",
                deserialize_result
            ))),
        }
    }
}

impl Config {
    /// Creates a new `Config` struct.
    pub fn from_file<P: AsRef<Path>>(config_path: P) -> Result<Self, Error> {
        let cfg_result: Result<Self, Error> = fs::read_to_string(config_path.as_ref())
            .context("could not open configuration file")
            .map_err(Error::from)
            .and_then(|file_content| {
                Ok(toml::from_str(&file_content).context(format_err!(
                    "could not decode config file: {}, using default",
                    config_path.as_ref().to_string_lossy()
                ))?)
            })
            .and_then(|mut new_config: Self| {
                new_config
                    .loaded_files
                    .push(config_path.as_ref().to_path_buf());

                Ok(new_config)
            });

        cfg_result
    }

    /// Decorates the loaded config with the given flags from CLI
    pub fn decorate_with_cli(&mut self, cli: &ArgMatches<'static>) -> Result<(), Error> {
        self.set_options(cli);

        self.verbose = cli.is_present("verbose");
        self.quiet = cli.is_present("quiet");
        self.overall_force = cli.is_present("force");
        self.force = self.overall_force;
        self.bench = cli.is_present("bench");
        self.open = cli.is_present("open");
        self.json = cli.is_present("json");
        self.html = cli.is_present("html");

        if cli.is_present("test-all") {
            self.read_apks()
                .context("error loading all the downloaded APKs")?;
        } else {
            self.add_app_package(
                cli.value_of("package")
                    .expect("expected a value for the package CLI attribute"),
            );
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
                    "The min_criticality option must be one of {}, {}, {}, {} or {}.\nUsing \
                     default.",
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
                Ok(t) if t > 0_usize => {
                    self.threads = t;
                }
                _ => {
                    print_warning(format!(
                        "The threads option must be an integer between 1 and {}",
                        usize::max_value()
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
    fn read_apks(&mut self) -> Result<(), Error> {
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
                                    .expect("expected file stem for apk file")
                                    .to_string_lossy()
                                    .into_owned(),
                            )
                        }
                    }
                }
                Err(e) => {
                    print_warning(format!(
                        "there was an error when reading the downloads folder: {}",
                        e
                    ));
                }
            }
        }

        Ok(())
    }

    /// Checks if all the needed folders and files exist.
    pub fn check(&self) -> bool {
        let check = self.downloads_folder.exists()
            && self.dex2jar_folder.exists()
            && self.jd_cmd_file.exists()
            && self.template_path().exists()
            && self.rules_json.exists();
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
    pub fn errors(&self) -> Vec<String> {
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
        if !self.template_path().exists() {
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
    pub fn loaded_config_files(&self) -> VecIter<PathBuf> {
        self.loaded_files.iter()
    }

    /// Returns the app package.
    pub fn app_packages(&self) -> Vec<PathBuf> {
        self.app_packages.clone()
    }

    /// Adds a package to check.
    pub(crate) fn add_app_package<P: AsRef<Path>>(&mut self, app_package: P) {
        let mut package_path = self.downloads_folder.join(app_package);
        if package_path.extension().is_none() {
            let updated = package_path.set_extension("apk");
            debug_assert!(
                updated,
                "did not update package path extension, no file name"
            );
        } else if package_path
            .extension()
            .expect("expected extension in package path")
            != "apk"
        {
            let mut file_name = package_path
                .file_name()
                .expect("expected file name in package path")
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
    pub fn min_criticality(&self) -> Criticality {
        self.min_criticality
    }

    /// Returns the `threads` field.
    pub fn threads(&self) -> usize {
        self.threads
    }

    /// Returns the path to the `dist_folder`.
    pub fn dist_folder(&self) -> &Path {
        &self.dist_folder
    }

    /// Returns the path to the `results_folder`.
    pub fn results_folder(&self) -> &Path {
        &self.results_folder
    }

    /// Returns the path to the `dex2jar_folder`.
    pub fn dex2jar_folder(&self) -> &Path {
        &self.dex2jar_folder
    }

    /// Returns the path to the `jd_cmd_file`.
    pub fn jd_cmd_file(&self) -> &Path {
        &self.jd_cmd_file
    }

    /// Gets the path to the template.
    pub fn template_path(&self) -> PathBuf {
        self.templates_folder.join(&self.template)
    }

    /// Gets the path to the templates folder.
    pub fn templates_folder(&self) -> &Path {
        &self.templates_folder
    }

    /// Gets the name of the template.
    pub fn template_name(&self) -> &str {
        &self.template
    }

    /// Returns the path to the `rules_json`.
    pub fn rules_json(&self) -> &Path {
        &self.rules_json
    }

    /// Returns the criticality of the `unknown_permission` field.
    pub fn unknown_permission_criticality(&self) -> Criticality {
        self.unknown_permission.0
    }

    /// Returns the description of the `unknown_permission` field.
    pub fn unknown_permission_description(&self) -> &str {
        self.unknown_permission.1.as_str()
    }

    /// Returns the loaded `permissions`.
    pub fn permissions(&self) -> Iter<Permission> {
        self.permissions.iter()
    }

    /// Returns the default `Config` struct.
    fn local_default() -> Self {
        Self {
            app_packages: Vec::new(),
            verbose: false,
            quiet: false,
            overall_force: false,
            force: false,
            bench: false,
            open: false,
            json: false,
            html: false,
            threads: num_cpus::get(),
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
                     lead to misunderstanding between developers.",
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
    fn default() -> Self {
        let mut config = Self::local_default();
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
    fn default() -> Self {
        Config::local_default()
    }
}

/// Vulnerable permission configuration information.
///
/// Represents a Permission with all its fields. Implements the `PartialEq` and `PartialOrd`
/// traits.
#[derive(Debug, Ord, Eq, Deserialize)]
pub struct Permission {
    /// Permission name.
    name: manifest::Permission,
    /// Permission criticality.
    criticality: Criticality,
    /// Permission label.
    label: String,
    /// Permission description.
    description: String,
}

impl PartialEq for Permission {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
    }
}

impl PartialOrd for Permission {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.name.cmp(&other.name))
    }
}

impl Permission {
    /// Returns the enum that represents the `name`.
    pub fn name(&self) -> manifest::Permission {
        self.name
    }

    /// Returns the permission's `criticality`.
    pub fn criticality(&self) -> Criticality {
        self.criticality
    }

    /// Returns the permission's `label`.
    pub fn label(&self) -> &str {
        self.label.as_str()
    }

    /// Returns the permission's `description`.
    pub fn description(&self) -> &str {
        self.description.as_str()
    }
}

/// Test module for the configuration.
#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::{Path, PathBuf},
    };

    use num_cpus;

    use super::Config;
    use crate::{criticality::Criticality, static_analysis::manifest};

    /// Test for the default configuration function.
    #[allow(clippy::cyclomatic_complexity)]
    #[test]
    fn it_config() {
        // Create config object.
        let mut config = Config::default();

        // Check that the properties of the config object are correct.
        assert!(config.app_packages().is_empty());
        assert!(!config.is_verbose());
        assert!(!config.is_quiet());
        assert!(!config.is_force());
        assert!(!config.is_bench());
        assert!(!config.is_open());
        assert_eq!(config.threads(), num_cpus::get());
        assert_eq!(config.downloads_folder, Path::new("."));
        assert_eq!(config.dist_folder(), Path::new("dist"));
        assert_eq!(config.results_folder(), Path::new("results"));
        assert_eq!(config.template_name(), "super");
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
            config.dex2jar_folder(),
            share_path.join("vendor").join("dex2jar-2.1-SNAPSHOT")
        );
        assert_eq!(
            config.jd_cmd_file(),
            share_path.join("vendor").join("jd-cmd.jar")
        );
        assert_eq!(config.templates_folder(), share_path.join("templates"));
        assert_eq!(
            config.template_path(),
            share_path.join("templates").join("super")
        );
        if cfg!(target_family = "unix") && Path::new("/etc/super-analyzer/rules.json").exists() {
            assert_eq!(
                config.rules_json(),
                Path::new("/etc/super-analyzer/rules.json")
            );
        } else {
            assert_eq!(config.rules_json(), Path::new("rules.json"));
        }
        assert_eq!(config.unknown_permission_criticality(), Criticality::Low);
        assert_eq!(
            config.unknown_permission_description(),
            "Even if the application can create its own permissions, it's discouraged, \
             since it can lead to misunderstanding between developers."
        );
        assert_eq!(config.permissions().next(), None);

        if !config.downloads_folder.exists() {
            fs::create_dir(&config.downloads_folder).unwrap();
        }
        if !config.dist_folder().exists() {
            fs::create_dir(config.dist_folder()).unwrap();
        }
        if !config.results_folder().exists() {
            fs::create_dir(config.results_folder()).unwrap();
        }

        // Change properties.
        config.add_app_package("test_app");
        config.verbose = true;
        config.quiet = true;
        config.force = true;
        config.bench = true;
        config.open = true;

        // Check that the new properties are correct.
        let packages = config.app_packages();
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
        assert_eq!(config.threads(), 2);
        assert_eq!(config.downloads_folder, Path::new("downloads"));
        assert_eq!(config.dist_folder(), Path::new("dist"));
        assert_eq!(config.results_folder(), Path::new("results"));
        assert_eq!(
            config.dex2jar_folder(),
            Path::new("/usr/share/super-analyzer/vendor/dex2jar-2.1-SNAPSHOT")
        );
        assert_eq!(
            config.jd_cmd_file(),
            Path::new("/usr/share/super-analyzer/vendor/jd-cmd.jar")
        );
        assert_eq!(
            config.templates_folder(),
            Path::new("/usr/share/super-analyzer/templates")
        );
        assert_eq!(
            config.template_path(),
            Path::new("/usr/share/super-analyzer/templates/super")
        );
        assert_eq!(config.template_name(), "super");
        assert_eq!(
            config.rules_json(),
            Path::new("/etc/super-analyzer/rules.json")
        );
        assert_eq!(config.unknown_permission_criticality(), Criticality::Low);
        assert_eq!(
            config.unknown_permission_description(),
            "Even if the application can create its own permissions, it's discouraged, \
             since it can lead to misunderstanding between developers."
        );

        let permission = config.permissions().next().unwrap();
        assert_eq!(
            permission.name(),
            manifest::Permission::AndroidPermissionInternet
        );
        assert_eq!(permission.criticality(), Criticality::Warning);
        assert_eq!(permission.label(), "Internet permission");
        assert_eq!(
            permission.description(),
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
