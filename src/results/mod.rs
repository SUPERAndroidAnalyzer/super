use std::fs;
use std::fs::File;
use std::io::{Read, Write};
use std::collections::BTreeSet;
use std::path::Path;
use std::borrow::Borrow;
use std::slice::Iter;

use serde_json::builder::ObjectBuilder;
use chrono::{Local, Datelike};
use rustc_serialize::hex::ToHex;

mod utils;

pub use self::utils::{Benchmark, Vulnerability};
use self::utils::FingerPrint;

use {Error, Config, Result, Criticity, print_error, print_warning, file_exists, copy_folder};

pub struct Results {
    app_package: String,
    app_label: String,
    app_description: String,
    app_version: String,
    app_version_num: i32,
    app_min_sdk: i32,
    app_target_sdk: Option<i32>,
    app_fingerprint: FingerPrint,
    warnings: BTreeSet<Vulnerability>,
    low: BTreeSet<Vulnerability>,
    medium: BTreeSet<Vulnerability>,
    high: BTreeSet<Vulnerability>,
    critical: BTreeSet<Vulnerability>,
    benchmarks: Vec<Benchmark>,
}

impl Results {
    pub fn init(config: &Config) -> Option<Results> {
        let path = format!("{}/{}", config.get_results_folder(), config.get_app_id());
        if !fs::metadata(&path).is_ok() || config.is_force() {
            if fs::metadata(&path).is_ok() {
                if let Err(e) = fs::remove_dir_all(&path) {
                    print_error(format!("An unknown error occurred when trying to delete the \
                                         results folder: {}",
                                        e),
                                config.is_verbose());
                    return None;
                }
            }

            let fingerprint = match FingerPrint::new(config) {
                Ok(f) => f,
                Err(e) => {
                    print_error(format!("An error occurred when trying to fingerprint the \
                                         application: {}",
                                        e),
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
                warnings: BTreeSet::new(),
                low: BTreeSet::new(),
                medium: BTreeSet::new(),
                high: BTreeSet::new(),
                critical: BTreeSet::new(),
                benchmarks: if config.is_bench() {
                    Vec::with_capacity(10)
                } else {
                    Vec::with_capacity(0)
                },
            })
        } else {
            if config.is_verbose() {
                println!("The results for this application have already been generated. No need \
                          to generate them again.");
            }
            None
        }
    }

    pub fn set_app_package(&mut self, package: &str) {
        self.app_package = String::from(package);
    }

    pub fn set_app_label(&mut self, label: &str) {
        self.app_label = String::from(label);
    }

    pub fn set_app_description(&mut self, description: &str) {
        self.app_description = String::from(description);
    }

    pub fn set_app_version(&mut self, version: &str) {
        self.app_version = String::from(version);
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

    pub fn add_benchmark(&mut self, bench: Benchmark) {
        self.benchmarks.push(bench);
    }

    pub fn get_benchmarks(&self) -> Iter<Benchmark> {
        self.benchmarks.iter()
    }

    pub fn generate_report(&self, config: &Config) -> Result<()> {
        let path = format!("{}/{}", config.get_results_folder(), config.get_app_id());
        if !file_exists(&path) || config.is_force() {
            if file_exists(&path) {
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

            try!(self.generate_json_report(config));

            if config.is_verbose() {
                println!("JSON report generated.");
                println!("");
            }

            try!(self.generate_html_report(config));

            if config.is_verbose() {
                println!("HTML report generated.");
            }
        }

        Ok(())
    }

    fn generate_json_report(&self, config: &Config) -> Result<()> {
        if config.is_verbose() {
            println!("Starting JSON report generation. First we create the file.")
        }
        let mut f = try!(File::create(format!("{}/{}/results.json",
                                              config.get_results_folder(),
                                              config.get_app_id())));
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

    fn generate_html_report(&self, config: &Config) -> Result<()> {
        if config.is_verbose() {
            println!("Starting HTML report generation. First we create the file.")
        }
        let mut f = try!(File::create(format!("{}/{}/index.html",
                                              config.get_results_folder(),
                                              config.get_app_id())));
        if config.is_verbose() {
            println!("The report file has been created. Now it's time to fill it.")
        }

        let now = Local::now();

        // Header
        try!(f.write_all(b"<!DOCTYPE html>"));
        try!(f.write_all(b"<html lang=\"en\">"));
        try!(f.write_all(b"<head>"));
        try!(f.write_all(b"<title>Vulnerability report</title>"));
        try!(f.write_all(b"<meta charset=\"UTF-8\">"));
        try!(f.write_all(b"<link rel=\"stylesheet\" href=\"css/style.css\">"));
        try!(f.write_all(b"<link rel=\"stylesheet\" href=\"css/androidstudio.css\">"));
        try!(f.write_all(b"</head>"));
        try!(f.write_all(b"<body>"));
        try!(f.write_all(b"<section class=\"report\">"));
        try!(f.write_all(b"<a href=\"http://superanalyzer.rocks\" \
                                title=\"S.U.P.E.R. Android Analyzer\">\
                            <img src=\"img/logo.png\" alt=\"S.U.P.E.R. Android Analyzer\"></a>"));
        try!(f.write_all(b"<h1 id=\"title\">S.U.P.E.R. Android Analyzer \
                            Report</h1>"));
        try!(f.write_all(&format!("<p>This is the vulnerability report for the android \
                                   application <em>{}</em>. Report generated on {}.</p>",
                                  self.app_package,
                                  now.to_rfc2822())
            .into_bytes()));

        // Application data
        try!(f.write_all(b"<h2>Application data:</h2>"));
        try!(f.write_all(b"<ul>"));
        if !self.app_label.is_empty() {
            try!(f.write_all(&format!("<li><strong>Label:</strong> {}</li>",
                                      self.app_label.as_str())
                .into_bytes()));
        }
        if !self.app_description.is_empty() {
            try!(f.write_all(&format!("<li><strong>Description:</strong> {}</li>",
                                      self.app_description.as_str())
                .into_bytes()));
        }
        if !self.app_package.is_empty() {
            try!(f.write_all(&format!("<li><strong>Package:</strong> {}</li>",
                                      self.app_package.as_str())
                .into_bytes()));
        }
        if !self.app_version.is_empty() {
            try!(f.write_all(&format!("<li><strong>Version:</strong> {}</li>",
                                      self.app_version.as_str())
                .into_bytes()));
        }
        if self.app_version_num > 0 {
            try!(f.write_all(&format!("<li><strong>Version number:</strong> {}</li>",
                                      self.app_version_num)
                .into_bytes()));
        }
        if self.app_min_sdk > 0 {
            try!(f.write_all(&format!("<li><strong>Minimum SDK version:</strong> {}</li>",
                                      self.app_min_sdk)
                .into_bytes()));
        }
        if self.app_target_sdk.is_some() {
            try!(f.write_all(&format!("<li><strong>Target SDK:</strong> {}</li>",
                                      self.app_target_sdk.unwrap())
                .into_bytes()));
        }
        try!(f.write_all(b"<li><strong>Fingerprints:</strong><ul>"));
        try!(f.write_all(&format!("<li>MD5: {}</li>", self.app_fingerprint.get_md5().to_hex())
            .into_bytes()));
        try!(f.write_all(&format!("<li>SHA-1: {}</li>",
                                  self.app_fingerprint.get_sha1().to_hex())
            .into_bytes()));
        try!(f.write_all(&format!("<li>SHA-256: {}</li>",
                                  self.app_fingerprint.get_sha256().to_hex())
            .into_bytes()));
        try!(f.write_all(b"</ul></li>"));

        try!(f.write_all(b"<li><a href=\"src/index.html\" \
                        title=\"Source code\">Check source code</a></li>"));
        try!(f.write_all(b"</ul>"));

        // Vulnerability count
        let total_vuln = self.low.len() + self.medium.len() + self.high.len() + self.critical.len();
        try!(f.write_all(&format!("<h3>Total vulnerabilities found: {}</h3>", total_vuln)
            .into_bytes()));
        try!(f.write_all(b"<ul>"));
        if self.critical.len() == 0 {
            try!(f.write_all(b"<li>Critical: 0</li>"));
        } else {
            try!(f.write_all(&format!("<li>Critical: <span class=\"critical\">{}</span> <a \
                                       href=\"#critical\" title=\"Critical\">⇒</a></li>",
                                      self.critical.len())
                .into_bytes()));
        }
        if self.high.len() == 0 {
            try!(f.write_all(b"<li>High: 0</li>"));
        } else {
            try!(f.write_all(&format!("<li>High: <span class=\"high\">{}</span> <a \
                                       href=\"#high\" title=\"High\">⇒</a></li>",
                                      self.high.len())
                .into_bytes()));
        }
        if self.medium.len() == 0 {
            try!(f.write_all(b"<li>Medium: 0</li>"));
        } else {
            try!(f.write_all(&format!("<li>Medium: <span class=\"medium\">{}</span> <a \
                                       href=\"#medium\" title=\"Medium\">⇒</a></li>",
                                      self.medium.len())
                .into_bytes()));
        }
        if self.low.len() == 0 {
            try!(f.write_all(b"<li>Low: 0</li>"));
        } else {
            try!(f.write_all(&format!("<li>Low: <span class=\"low\">{}</span> <a href=\"#low\" \
                                       title=\"Low\">⇒</a></li>",
                                      self.low.len())
                .into_bytes()));
        }
        if self.warnings.len() == 0 {
            try!(f.write_all(b"<li>Warnings: 0</li>"));
        } else {
            try!(f.write_all(&format!("<li>Warnings: <span class=\"warnings\">{}</span> <a \
                                       href=\"#warnings\" title=\"Warnings\">⇒</a></li>",
                                      self.warnings.len())
                .into_bytes()));
        }
        try!(f.write_all(b"</ul>"));

        try!(f.write_all(b"<h2>Vulnerabilities:</h2>"));

        if self.critical.len() > 0 {
            try!(self.print_html_vuln_set(&mut f, &self.critical, Criticity::Critical))
        }

        if self.high.len() > 0 {
            try!(self.print_html_vuln_set(&mut f, &self.high, Criticity::High))
        }

        if self.medium.len() > 0 {
            try!(self.print_html_vuln_set(&mut f, &self.medium, Criticity::Medium))
        }

        if self.low.len() > 0 {
            try!(self.print_html_vuln_set(&mut f, &self.low, Criticity::Low))
        }

        if self.warnings.len() > 0 {
            try!(self.print_html_vuln_set(&mut f, &self.warnings, Criticity::Warning))
        }
        try!(f.write_all(b"</section>"));

        // Footer
        try!(f.write_all(b"<footer>"));
        try!(f.write_all(&format!("<p>Copyright © {} - S.U.P.E.R. Android Analyzer</p>",
                                  if now.year() > 2016 {
                                      format!("2016 - {}", now.year())
                                  } else {
                                      format!("{}", now.year())
                                  })
            .into_bytes()));
        try!(f.write_all(b"</footer>"));
        try!(f.write_all(b"<script src=\"js/highlight.pack.js\"></script>"));
        try!(f.write_all(b"<script>hljs.initHighlightingOnLoad();</script>"));
        try!(f.write_all(b"<script src=\"js/jquery-3.1.0.slim.min.js\"></script>"));
        try!(f.write_all(b"<script>$('.vulnerability h4 a.collapse').click(function(event) {\
            event.preventDefault();\
            $(this).parents('section.vulnerability').find('ul div').hide('slow');\
            $(this).hide('fast');\
            $(this).prev('a').show('fast');\
        });\
        $('.vulnerability h4 a.show').click(function(event) {\
            event.preventDefault();\
            $(this).parents('section.vulnerability').find('ul div').show('slow');\
            $(this).hide('fast');\
            $(this).next('a').show('fast');\
        });</script>"));
        try!(f.write_all(b"</body>"));
        try!(f.write_all(b"</html>"));

        // Copying JS and CSS files
        try!(copy_folder(config.get_results_template(),
                         &format!("{}/{}", config.get_results_folder(), config.get_app_id())));

        try!(self.generate_code_html_files(config));

        Ok(())
    }

    fn print_html_vuln_set(&self,
                           f: &mut File,
                           set: &BTreeSet<Vulnerability>,
                           criticity: Criticity)
                           -> Result<()> {
        let criticity_str = format!("{:?}", criticity);
        if criticity == Criticity::Warning {
            try!(f.write_all(&String::from("<h3 id=\"warnings\">Warnings: <a href=\"#title\" \
                                            title=\"Top\">⇮</a></h3>")
                .into_bytes()));

        } else {
            try!(f.write_all(&format!("<h3 id=\"{}\">{} criticity vulnerabilities: <a \
                                       href=\"#title\" title=\"Top\">⇮</a></h3>",
                                      criticity_str.to_lowercase(),
                                      criticity_str)
                .into_bytes()));
        }

        for (i, vuln) in set.iter().enumerate() {
            try!(f.write_all(b"<section class=\"vulnerability\">"));
            try!(f.write_all(&format!("<h4>{}{:03}: <a href=\"#\" title=\"Display \
                                       vulnerability\" class=\"show\">+</a><a href=\"#\" \
                                       style=\"display: none\" class=\"collapse\" \
                                       title=\"Collapse vulnerability\">-</a></h4>",
                                      criticity_str.chars().nth(0).unwrap(),
                                      i + 1)
                .into_bytes()));
            try!(f.write_all(b"<ul>"));
            try!(f.write_all(&format!("<li><strong>Label:</strong> {}</li>", vuln.get_name())
                .into_bytes()));
            try!(f.write_all(b"<div style=\"display: none\">"));
            try!(f.write_all(&format!("<li><strong>Description:</strong> {}</li>",
                                      vuln.get_description())
                .into_bytes()));
            if let Some(file) = vuln.get_file() {
                try!(f.write_all(&format!("<li><strong>File:</strong> <a \
                                           href=\"src/{0}.html?start_line={1}&end_line={2}&vulnerability_type={3}#code-line-{1}\">{0}</a></li>",
                                          file.display(),
                                          vuln.get_start_line().unwrap() + 1,
                                          vuln.get_end_line().unwrap() + 1,
                                          criticity_str.to_lowercase())
                    .into_bytes()));
            }
            if let Some(code) = vuln.get_code() {
                if vuln.get_start_line().unwrap() != vuln.get_end_line().unwrap() {
                    try!(f.write_all(&format!("<li><strong>Lines:</strong> {}-{}</li>",
                                              vuln.get_start_line().unwrap() + 1,
                                              vuln.get_end_line().unwrap() + 1)
                        .into_bytes()));
                } else {
                    try!(f.write_all(&format!("<li><strong>Line:</strong> {}</li>",
                                              vuln.get_start_line().unwrap() + 1)
                        .into_bytes()));
                }

                let start_line = if vuln.get_start_line().unwrap() < 5 {
                    0
                } else {
                    vuln.get_start_line().unwrap() - 4
                };

                let mut lines = String::new();
                for (i, _line) in code.lines().enumerate() {
                    if i + start_line >= vuln.get_start_line().unwrap() &&
                       i + start_line <= vuln.get_end_line().unwrap() {
                        lines.push_str(format!("-&gt;<em>{}</em><br>", i + start_line+1).as_str());
                    } else {
                        lines.push_str(format!("{}<br>", i + start_line + 1).as_str());
                    }
                }
                let lang = vuln.get_file().unwrap().extension().unwrap().to_string_lossy();
                try!(f.write_all(&format!("<li><p><strong>Affected code:</strong></p><div><div \
                                           class=\"line_numbers\">{}</div><div \
                                           class=\"code\"><pre><code \
                                           class=\"{}\">{}</code></pre></div></li>",
                                          lines,
                                          lang,
                                          Results::html_escape(code))
                    .into_bytes()));
            }
            try!(f.write_all(b"</div>"));
            try!(f.write_all(b"</ul>"));
            try!(f.write_all(b"</section>"));
        }
        Ok(())
    }

    fn generate_code_html_files(&self, config: &Config) -> Result<()> {
        try!(self.generate_code_html_folder("", config));
        let menu = try!(self.generate_html_src_menu("", config));

        let mut f = try!(fs::File::create(format!("{}/{}/src/index.html",
                                                  config.get_results_folder(),
                                                  config.get_app_id())));

        try!(f.write_all(b"<!DOCTYPE html>"));
        try!(f.write_all(b"<html lang=\"en\">"));
        try!(f.write_all(b"<head>"));
        try!(f.write_all(b"<title>Source code</title>"));
        try!(f.write_all(b"<meta charset=\"UTF-8\">"));
        try!(f.write_all(b"<link rel=\"stylesheet\" href=\"../css/style.css\">"));
        try!(f.write_all(b"</head>"));
        try!(f.write_all(b"<body class=\"src\">"));
        try!(f.write_all(b"<nav>"));
        try!(f.write_all(b"<a href=\"../index.html\" \
                        title=\"Return to report\"><h2><img \
                        src=\"../img/report.png\"><br>Return to report</h2></a>"));
        try!(f.write_all(&menu.into_bytes()));
        try!(f.write_all(b"</nav>"));
        try!(f.write_all(b"<iframe name=\"code\" src=\"AndroidManifest.xml.html\">"));
        try!(f.write_all(b"</iframe>"));
        try!(f.write_all(b"<script src=\"../js/jquery-3.1.0.slim.min.js\"></script>"));
        try!(f.write_all(b"<script src=\"../js/src_nav.js\"></script>"));
        try!(f.write_all(b"</body>"));
        try!(f.write_all(b"</html>"));

        Ok(())
    }

    fn generate_code_html_folder<P: AsRef<Path>>(&self, path: P, config: &Config) -> Result<usize> {
        if path.as_ref() == Path::new("classes/android") ||
           path.as_ref() == Path::new("classes/com/google/android/gms") ||
           path.as_ref() == Path::new("smali") {
            return Ok(0);
        }
        let dir_iter = try!(fs::read_dir(&format!("{}/{}/{}",
                                                  config.get_dist_folder(),
                                                  config.get_app_id(),
                                                  path.as_ref().display())));

        try!(fs::create_dir_all(&format!("{}/{}/src/{}",
                                         config.get_results_folder(),
                                         config.get_app_id(),
                                         path.as_ref().display())));
        let mut count = 0;

        for f in dir_iter {
            let f = match f {
                Ok(f) => f,
                Err(e) => {
                    print_warning(format!("There was an error reading the directory {}/{}/{}: {}",
                                          config.get_dist_folder(),
                                          config.get_app_id(),
                                          path.as_ref().display(),
                                          e),
                                  config.is_verbose());
                    return Err(Error::from(e));
                }
            };

            match f.path().extension() {
                Some(e) => {
                    if e.to_string_lossy() == "xml" || e.to_string_lossy() == "java" {
                        let prefix =
                            format!("{}/{}/", config.get_dist_folder(), config.get_app_id());
                        try!(self.generate_code_html_for(f.path().strip_prefix(&prefix).unwrap(),
                                                         config));
                        count += 1;
                    }
                }
                None => {
                    if f.path().is_dir() {
                        let prefix =
                            format!("{}/{}/", config.get_dist_folder(), config.get_app_id());

                        if f.path().strip_prefix(&prefix).unwrap() != Path::new("original") {
                            let f_count = try!(self.generate_code_html_folder(f.path()
                                                               .strip_prefix(&prefix)
                                                               .unwrap(),
                                                           config));
                            if f_count > 0 {
                                count += 1;
                            }
                        }
                    }
                }
            }
        }
        if count == 0 {
            try!(fs::remove_dir(&format!("{}/{}/src/{}",
                                         config.get_results_folder(),
                                         config.get_app_id(),
                                         path.as_ref().display())));
        }

        Ok(count)
    }

    fn generate_html_src_menu<P: AsRef<Path>>(&self,
                                              dir_path: P,
                                              config: &Config)
                                              -> Result<String> {
        let iter = try!(fs::read_dir(&format!("{}/{}/src/{}",
                                              config.get_results_folder(),
                                              config.get_app_id(),
                                              dir_path.as_ref().display())));
        let mut menu = String::new();
        menu.push_str("<ul>");
        for entry in iter {
            match entry {
                Ok(f) => {
                    let path = f.path();
                    if path.is_file() {
                        let html_file_name = f.file_name();
                        let html_file_name = html_file_name.as_os_str().to_string_lossy();
                        let extension = Path::new(&html_file_name[..html_file_name.len() - 5])
                            .extension()
                            .unwrap();
                        let link_path = match format!("{}", dir_path.as_ref().display()).as_str() {
                            "" => String::new(),
                            p => {
                                let mut p = String::from(p);
                                p.push('/');
                                p
                            }
                        };

                        if extension == "xml" || extension == "java" {
                            menu.push_str(format!("<li><a href=\"{0}{1}.html\" title=\"{1}\" \
                                                   target=\"code\"><img \
                                                   src=\"../img/{2}-icon.png\">{1}</a></li>",
                                                  link_path,
                                                  &html_file_name[..html_file_name.len() - 5],
                                                  extension.to_string_lossy())
                                .as_str());
                        }
                    } else if path.is_dir() {
                        let dir_name = match path.file_name() {
                            Some(n) => String::from(n.to_string_lossy().borrow() as &str),
                            None => String::new(),
                        };
                        let prefix = format!("{}/{}/src/",
                                             config.get_results_folder(),
                                             config.get_app_id());
                        let submenu =
                            match self.generate_html_src_menu(path.strip_prefix(&prefix).unwrap(),
                                                        config) {
                                Ok(m) => m,
                                Err(e) => {
                                    let path = path.to_string_lossy();
                                    print_warning(format!("An error occurred when generating \
                                                           the menu for {}. The result \
                                                           generation process will continue, \
                                                           though. More info: {}",
                                                          path,
                                                          e),
                                                  config.is_verbose());
                                    break;
                                }
                            };
                        menu.push_str(format!("<li><a href=\"#\" title=\"{0}\"><img \
                                               src=\"../img/folder-icon.png\">{0}</a>{1}</li>",
                                              dir_name,
                                              submenu.as_str())
                            .as_str());
                    }
                }
                Err(e) => {
                    print_warning(format!("An error occurred when generating the menu for {}. \
                                           The result generation process will continue, though. \
                                           More info: {}",
                                          dir_path.as_ref().display(),
                                          e),
                                  config.is_verbose());
                    break;
                }
            }
        }
        menu.push_str("</ul>");
        Ok(menu)
    }

    fn generate_code_html_for<P: AsRef<Path>>(&self, path: P, config: &Config) -> Result<()> {
        let mut f_in = try!(File::open(format!("{}/{}/{}",
                                               config.get_dist_folder(),
                                               config.get_app_id(),
                                               path.as_ref().display())));
        let mut f_out = try!(File::create(format!("{}/{}/src/{}.html",
                                                  config.get_results_folder(),
                                                  config.get_app_id(),
                                                  path.as_ref().display())));

        let mut code = String::new();
        try!(f_in.read_to_string(&mut code));
        let code = Results::html_escape(code.as_str());

        let mut back_path = String::new();
        for _ in 0..path.as_ref().components().count() {
            back_path.push_str("../");
        }

        let mut line_numbers = String::new();
        for i in 0..code.lines().count() {
            line_numbers.push_str(format!("{}<br>", i + 1).as_str());
        }

        try!(f_out.write_all(b"<!DOCTYPE html>"));
        try!(f_out.write_all(b"<html lang=\"en\">"));
        try!(f_out.write_all(b"<head>"));
        try!(f_out.write_all(&format!("<title>Source - {}</title>", path.as_ref().display())
            .into_bytes()));
        try!(f_out.write_all(b"<meta charset=\"UTF-8\">"));
        try!(f_out.write_all(&format!("<link rel=\"stylesheet\" href=\"{}css/style.css\">",
                                      back_path)
            .into_bytes()));
        try!(f_out.write_all(&format!("<link rel=\"stylesheet\" href=\"{}css/androidstudio.css\">",
                                back_path)
                .into_bytes()));
        try!(f_out.write_all(b"</head>"));
        try!(f_out.write_all(b"<body>"));
        try!(f_out.write_all(&format!("<div><div class=\"line_numbers\">{}</div>", line_numbers)
            .into_bytes()));
        try!(f_out.write_all(b"<div class=\"code\"><pre><code>"));
        for (i, line) in code.lines().enumerate() {
            try!(f_out.write_all(&format!("<code id=\"code-line-{}\">{}</code><br>", i + 1, line).into_bytes()));
        }
        try!(f_out.write_all(b"</code></pre></div></div>"));
        try!(f_out.write_all(&format!("<script src=\"{}js/jquery-3.1.0.slim.min.js\"></script>",
                                      back_path)
            .into_bytes()));
        try!(f_out.write_all(&format!("<script src=\"{}js/highlight.pack.js\"></script>",
                                      back_path)
            .into_bytes()));
        try!(f_out.write_all(b"<script>hljs.initHighlightingOnLoad();</script>"));
        try!(f_out.write_all(b"<script>
        var query_params = decodeURIComponent(window.location.search.substring(1)),
            variables = query_params.split('&'),
            start_line,
            end_line,
            vulnerability_type;
        for(var i = 0; i < variables.length; i++) {
          var pair = variables[i].split('=');
          if (pair[0] == \"start_line\") {
            start_line = pair[1];
          }
          if (pair[0] == \"end_line\") {
              end_line = pair[1];
          }
          if (pair[0] == \"vulnerability_type\") {
              vulnerability_type = pair[1];
          }
        }
        for (var i = start_line; i <= end_line; i++) {
            $(\"#code-line-\" + i).addClass(\"vulnerable_line \" + vulnerability_type);
        }</script>"));
        try!(f_out.write_all(b"</body>"));
        try!(f_out.write_all(b"</html>"));

        Ok(())
    }

    fn html_escape(code: &str) -> String {
        let mut res = String::new();
        for c in code.chars() {
            match c {
                '<' => res.push_str("&lt;"),
                '>' => res.push_str("&gt;"),
                '&' => res.push_str("&amp;"),
                c => res.push(c),
            };
        }
        res
    }
}
