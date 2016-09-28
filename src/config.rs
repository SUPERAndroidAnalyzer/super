use std::{u8, fs};
use std::path::Path;
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

use {Error, Result, Criticity, print_error, print_warning, file_exists};

const MAX_THREADS: i64 = u8::MAX as i64;

#[derive(Debug)]
pub struct Config {
    app_id: String,
    verbose: bool,
    quiet: bool,
    force: bool,
    bench: bool,
    threads: u8,
    downloads_folder: String,
    dist_folder: String,
    results_folder: String,
    apktool_file: String,
    dex2jar_folder: String,
    jd_cmd_file: String,
    results_template: String,
    rules_json: String,
    unknown_permission: (Criticity, String),
    permissions: BTreeSet<PermissionConfig>,
    loaded_files: Vec<String>,
}

impl Config {
    #[cfg(target_family = "unix")]
    pub fn new(app_id: &str,
               verbose: bool,
               quiet: bool,
               force: bool,
               bench: bool)
               -> Result<Config> {
        let mut config: Config = Default::default();
        config.app_id = String::from(app_id);
        config.verbose = verbose;
        config.quiet = quiet;
        config.force = force;
        config.bench = bench;

        if file_exists("/etc/config.toml") {
            try!(Config::load_from_file(&mut config, "/etc/config.toml", verbose));
            config.loaded_files.push(String::from("/etc/config.toml"));
        }
        if file_exists("./config.toml") {
            try!(Config::load_from_file(&mut config, "./config.toml", verbose));
            config.loaded_files.push(String::from("./config.toml"));
        }

        Ok(config)
    }

    #[cfg(target_family = "windows")]
    pub fn new(app_id: &str,
               verbose: bool,
               quiet: bool,
               force: bool,
               bench: bool)
               -> Result<Config> {
        let mut config: Config = Default::default();
        config.app_id = String::from(app_id);
        config.verbose = verbose;
        config.quiet = quiet;
        config.force = force;
        config.bench = bench;

        if file_exists("config.toml") {
            try!(Config::load_from_file(&mut config, "config.toml", verbose));
            config.loaded_files.push(String::from("config.toml"));
        }

        Ok(config)
    }

    pub fn check(&self) -> bool {
        file_exists(&self.downloads_folder) &&
        file_exists(format!("{}/{}.apk", self.downloads_folder, self.app_id)) &&
        file_exists(&self.apktool_file) && file_exists(&self.dex2jar_folder) &&
        file_exists(&self.jd_cmd_file) && file_exists(&self.results_template) &&
        file_exists(&self.rules_json)
    }

    pub fn get_errors(&self) -> Vec<String> {
        let mut errors = Vec::new();
        if !file_exists(&self.downloads_folder) {
            errors.push(format!("the downloads folder `{}` does not exist",
                                self.downloads_folder));
        }
        if !file_exists(format!("{}/{}.apk", self.downloads_folder, self.app_id)) {
            errors.push(format!("the APK file `{}` does not exist",
                                format!("{}/{}.apk", self.downloads_folder, self.app_id)));
        }
        if !file_exists(&self.apktool_file) {
            errors.push(format!("the APKTool JAR file `{}` does not exist",
                                self.apktool_file));
        }
        if !file_exists(&self.dex2jar_folder) {
            errors.push(format!("the Dex2Jar folder `{}` does not exist",
                                self.dex2jar_folder));
        }
        if !file_exists(&self.jd_cmd_file) {
            errors.push(format!("the jd-cmd file `{}` does not exist", self.jd_cmd_file));
        }
        if !file_exists(&self.results_template) {
            errors.push(format!("the results template `{}` does not exist",
                                self.results_template));
        }
        if !file_exists(&self.rules_json) {
            errors.push(format!("the `{}` rule file does not exist", self.rules_json));
        }
        errors
    }

    pub fn get_loaded_config_files(&self) -> VecIter<String> {
        self.loaded_files.iter()
    }

    pub fn get_app_id(&self) -> &str {
        self.app_id.as_str()
    }

    pub fn set_app_id(&mut self, app_id: &str) {
        self.app_id = String::from(app_id);
    }

    pub fn is_verbose(&self) -> bool {
        self.verbose
    }

    pub fn set_verbose(&mut self, verbose: bool) {
        self.verbose = verbose;
    }

    pub fn is_quiet(&self) -> bool {
        self.quiet
    }

    pub fn set_quiet(&mut self, quiet: bool) {
        self.quiet = quiet;
    }

    pub fn is_force(&self) -> bool {
        self.force
    }

    pub fn set_force(&mut self, force: bool) {
        self.force = force;
    }

    pub fn is_bench(&self) -> bool {
        self.bench
    }

    pub fn set_bench(&mut self, bench: bool) {
        self.bench = bench;
    }

    pub fn get_threads(&self) -> u8 {
        self.threads
    }

    pub fn get_downloads_folder(&self) -> &str {
        self.downloads_folder.as_str()
    }

    pub fn get_dist_folder(&self) -> &str {
        self.dist_folder.as_str()
    }

    pub fn get_results_folder(&self) -> &str {
        self.results_folder.as_str()
    }

    pub fn get_apktool_file(&self) -> &str {
        self.apktool_file.as_str()
    }

    pub fn get_dex2jar_folder(&self) -> &str {
        self.dex2jar_folder.as_str()
    }

    pub fn get_jd_cmd_file(&self) -> &str {
        self.jd_cmd_file.as_str()
    }

    pub fn get_results_template(&self) -> &str {
        self.results_template.as_str()
    }

    pub fn get_rules_json(&self) -> &str {
        self.rules_json.as_str()
    }

    pub fn get_unknown_permission_criticity(&self) -> Criticity {
        self.unknown_permission.0
    }

    pub fn get_unknown_permission_description(&self) -> &str {
        self.unknown_permission.1.as_str()
    }

    pub fn get_permissions(&self) -> Iter<PermissionConfig> {
        self.permissions.iter()
    }

    fn load_from_file<P: AsRef<Path>>(config: &mut Config, path: P, verbose: bool) -> Result<()> {
        let mut f = try!(fs::File::open(path));
        let mut toml = String::new();
        try!(f.read_to_string(&mut toml));

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
                        Value::String(s) => config.downloads_folder = s,
                        _ => {
                            print_warning("The 'downloads_folder' option in config.toml must \
                                           be an string.\nUsing default.",
                                          verbose)
                        }
                    }
                }
                "dist_folder" => {
                    match value {
                        Value::String(s) => config.dist_folder = s,
                        _ => {
                            print_warning("The 'dist_folder' option in config.toml must be an \
                                           string.\nUsing default.",
                                          verbose)
                        }
                    }
                }
                "results_folder" => {
                    match value {
                        Value::String(s) => config.results_folder = s,
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
                                config.apktool_file = s.clone();
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
                        Value::String(s) => config.dex2jar_folder = s,
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
                                config.jd_cmd_file = s.clone();
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
                        Value::String(s) => config.results_template = s,
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
                                config.rules_json = s.clone();
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
                                                                      description.as_str()));
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
}

impl Default for Config {
    #[cfg(target_family = "unix")]
    fn default() -> Config {
        if file_exists("/usr/share/super") {
            Config {
                app_id: String::new(),
                verbose: false,
                quiet: false,
                force: false,
                bench: false,
                threads: 2,
                downloads_folder: String::from("downloads"),
                dist_folder: String::from("dist"),
                results_folder: String::from("results"),
                apktool_file: String::from("/usr/share/super/vendor/apktool_2.2.0.jar"),
                dex2jar_folder: String::from("/usr/share/super/vendor/dex2jar-2.0"),
                jd_cmd_file: String::from("/usr/share/super/vendor/jd-cmd.jar"),
                results_template: String::from("/usr/share/super/vendor/results_template"),
                rules_json: if Path::new("/etc/super").exists() {
                    String::from("/etc/super/rules.json")
                } else {
                    String::from("rules.json")
                },
                unknown_permission: (Criticity::Low,
                                     String::from("Even if the application can create its own \
                                                   permissions, it's discouraged, since it can \
                                                   lead to missunderstanding between developers.")),
                permissions: BTreeSet::new(),
                loaded_files: Vec::new(),
            }
        } else {
            Config {
                app_id: String::new(),
                verbose: false,
                quiet: false,
                force: false,
                bench: false,
                threads: 2,
                downloads_folder: String::from("downloads"),
                dist_folder: String::from("dist"),
                results_folder: String::from("results"),
                apktool_file: String::from("vendor/apktool_2.2.0.jar"),
                dex2jar_folder: String::from("vendor/dex2jar-2.0"),
                jd_cmd_file: String::from("vendor/jd-cmd.jar"),
                results_template: String::from("vendor/results_template"),
                rules_json: if file_exists("/etc/super/rules.json") {
                    String::from("/etc/super/rules.json")
                } else {
                    String::from("rules.json")
                },
                unknown_permission: (Criticity::Low,
                                     String::from("Even if the application can create its own \
                                                   permissions, it's discouraged, since it can \
                                                   lead to missunderstanding between developers.")),
                permissions: BTreeSet::new(),
                loaded_files: Vec::new(),
            }
        }
    }

    #[cfg(target_family = "windows")]
    fn default() -> Config {
        Config {
            app_id: String::new(),
            verbose: false,
            quiet: false,
            force: false,
            bench: false,
            threads: 2,
            downloads_folder: String::from("downloads"),
            dist_folder: String::from("dist"),
            results_folder: String::from("results"),
            apktool_file: String::from("vendor/apktool_2.2.0.jar"),
            dex2jar_folder: String::from("vendor/dex2jar-2.0"),
            jd_cmd_file: String::from("vendor/jd-cmd.jar"),
            results_template: String::from("vendor/results_template"),
            rules_json: String::from("rules.json"),
            unknown_permission: (Criticity::Low,
                                 String::from("Even if the application can create its own \
                                               permissions, it's discouraged, since it can lead \
                                               to missunderstanding between developers.")),
            permissions: BTreeSet::new(),
            loaded_files: Vec::new(),
        }
    }
}

#[derive(Debug, Ord, Eq)]
pub struct PermissionConfig {
    permission: Permission,
    criticity: Criticity,
    label: String,
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
    fn new(permission: Permission,
           criticity: Criticity,
           label: &str,
           description: &str)
           -> PermissionConfig {
        PermissionConfig {
            permission: permission,
            criticity: criticity,
            label: String::from(label),
            description: String::from(description),
        }
    }

    pub fn get_permission(&self) -> Permission {
        self.permission
    }

    pub fn get_criticity(&self) -> Criticity {
        self.criticity
    }

    pub fn get_label(&self) -> &str {
        self.label.as_str()
    }

    pub fn get_description(&self) -> &str {
        self.description.as_str()
    }
}

#[cfg(test)]
mod tests {
    use {Criticity, file_exists};
    use static_analysis::manifest::Permission;
    use super::Config;
    use std::fs;
    use std::path::Path;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn it_config() {
        let mut config: Config = Default::default();

        assert_eq!(config.get_app_id(), "");
        assert!(!config.is_verbose());
        assert!(!config.is_quiet());
        assert!(!config.is_force());
        assert!(!config.is_bench());
        assert_eq!(config.get_threads(), 2);
        assert_eq!(config.get_downloads_folder(), "downloads");
        assert_eq!(config.get_dist_folder(), "dist");
        assert_eq!(config.get_results_folder(), "results");
        if cfg!(target_family = "unix") && Path::new("/usr/share/super").exists() {
            assert_eq!(config.get_apktool_file(),
                       "/usr/share/super/vendor/apktool_2.2.0.jar");
            assert_eq!(config.get_dex2jar_folder(),
                       "/usr/share/super/vendor/dex2jar-2.0");
            assert_eq!(config.get_jd_cmd_file(),
                       "/usr/share/super/vendor/jd-cmd.jar");
            assert_eq!(config.get_results_template(),
                       "/usr/share/super/vendor/results_template");
        } else {
            assert_eq!(config.get_apktool_file(), "vendor/apktool_2.2.0.jar");
            assert_eq!(config.get_dex2jar_folder(), "vendor/dex2jar-2.0");
            assert_eq!(config.get_jd_cmd_file(), "vendor/jd-cmd.jar");
            assert_eq!(config.get_results_template(), "vendor/results_template");
        }
        if cfg!(target_family = "unix") && file_exists("/etc/super/rules.json") {
            assert_eq!(config.get_rules_json(), "/etc/super/rules.json");
        } else {
            assert_eq!(config.get_rules_json(), "rules.json");
        }
        assert_eq!(config.get_unknown_permission_criticity(), Criticity::Low);
        assert_eq!(config.get_unknown_permission_description(),
                   "Even if the application can create its own permissions, it's discouraged, \
                    since it can lead to missunderstanding between developers.");
        assert_eq!(config.get_permissions().next(), None);

        if !file_exists(config.get_downloads_folder()) {
            fs::create_dir(config.get_downloads_folder()).unwrap();
        }
        if !file_exists(config.get_dist_folder()) {
            fs::create_dir(config.get_dist_folder()).unwrap();
        }
        if !file_exists(config.get_results_folder()) {
            fs::create_dir(config.get_results_folder()).unwrap();
        }

        config.set_app_id("test_app");
        config.set_verbose(true);
        config.set_quiet(true);
        config.set_force(true);
        config.set_bench(true);

        assert_eq!(config.get_app_id(), "test_app");
        assert!(config.is_verbose());
        assert!(config.is_quiet());
        assert!(config.is_force());
        assert!(config.is_bench());

        if file_exists(format!("{}/{}.apk",
                               config.get_downloads_folder(),
                               config.get_app_id())) {
            fs::remove_file(format!("{}/{}.apk",
                                    config.get_downloads_folder(),
                                    config.get_app_id()))
                .unwrap();
        }
        assert!(!config.check());

        fs::File::create(format!("{}/{}.apk",
                                 config.get_downloads_folder(),
                                 config.get_app_id()))
            .unwrap();
        assert!(config.check());

        while !file_exists("config.toml.sample") {
            thread::sleep(Duration::from_millis(50));
        }
        let config = Config::new("test_app", false, false, false, false).unwrap();
        let mut error_string = String::from("Configuration errors were found:\n");
        for error in config.get_errors() {
            error_string.push_str(&error);
            error_string.push('\n');
        }
        error_string.push_str("The configuration was loaded, in order, from the following \
                               files:\n\t- Default built-in configuration");
        for file in config.get_loaded_config_files() {
            error_string.push_str(&format!("\t- {}", file));
        }
        println!("{}", error_string);
        assert!(config.check());

        fs::remove_file(format!("{}/{}.apk",
                                config.get_downloads_folder(),
                                config.get_app_id()))
            .unwrap();
    }

    #[test]
    fn it_config_sample() {
        fs::rename("config.toml", "config.toml.bk").unwrap();
        fs::rename("config.toml.sample", "config.toml").unwrap();

        let config = Config::new("test_app", false, false, false, false).unwrap();
        assert_eq!(config.get_threads(), 2);
        assert_eq!(config.get_downloads_folder(), "downloads");
        assert_eq!(config.get_dist_folder(), "dist");
        assert_eq!(config.get_results_folder(), "results");
        assert_eq!(config.get_apktool_file(),
                   "/usr/share/super/vendor/apktool_2.2.0.jar");
        assert_eq!(config.get_dex2jar_folder(),
                   "/usr/share/super/vendor/dex2jar-2.0");
        assert_eq!(config.get_jd_cmd_file(),
                   "/usr/share/super/vendor/jd-cmd.jar");
        assert_eq!(config.get_results_template(),
                   "/usr/share/super/vendor/results_template");
        assert_eq!(config.get_rules_json(), "/etc/super/rules.json");
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

        fs::rename("config.toml", "config.toml.sample").unwrap();
        fs::rename("config.toml.bk", "config.toml").unwrap();
    }
}
