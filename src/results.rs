use std::fs;
use std::fs::File;
use std::io::Write;
use std::collections::BTreeSet;
use std::cmp::Ordering;
use std::path::Path;

use super::{RESULTS_FOLDER, Result, Criticity, print_error};

pub struct Results {
    path: String,
    app_package: String,
    app_label: String,
    app_description: String,
    app_version: String,
    low: BTreeSet<Vulnerability>,
    medium: BTreeSet<Vulnerability>,
    high: BTreeSet<Vulnerability>,
    critical: BTreeSet<Vulnerability>,
}

impl Results {
    pub fn init(app_id: &str, verbose: bool, quiet: bool, force: bool) -> Option<Results> {
        let path = format!("{}/{}", RESULTS_FOLDER, app_id);
        if !fs::metadata(&path).is_ok() || force {
            if fs::metadata(&path).is_ok() {
                if let Err(e) = fs::remove_dir_all(&path) {
                    print_error(format!("An unknown error occurred when trying to delete the \
                                         results folder: {}",
                                        e),
                                verbose);
                    return None;
                }
            }
            if verbose {
                println!("The results struct has been created. All the vulnerabilitis will now \
                          be recorded and when the analysis ends, they will be written to result \
                          files.");
            } else if !quiet {
                println!("Results struct created.");
            }
            Some(Results {
                path: path,
                app_package: String::new(),
                app_label: String::new(),
                app_description: String::new(),
                app_version: String::new(),
                low: BTreeSet::new(),
                medium: BTreeSet::new(),
                high: BTreeSet::new(),
                critical: BTreeSet::new(),
            })
        } else {
            if verbose {
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

    pub fn add_vulnerability<S: AsRef<str>, P: AsRef<Path>>(&mut self,
                                                            name: S,
                                                            description: S,
                                                            file: Option<P>,
                                                            line: Option<u32>,
                                                            criticity: Criticity) {
        match criticity {
            Criticity::Low => {
                self.low.insert(Vulnerability::new(name, description, file, line, criticity));
            }
            Criticity::Medium => {
                self.medium.insert(Vulnerability::new(name, description, file, line, criticity));
            }
            Criticity::High => {
                self.high.insert(Vulnerability::new(name, description, file, line, criticity));
            }
            Criticity::Critical => {
                self.critical.insert(Vulnerability::new(name, description, file, line, criticity));
            }
        }
    }

    pub fn generate_report(&self, verbose: bool) -> Result<()> {
        if verbose {
            println!("Starting report generation. First we'll create the results folder.");
        }
        try!(fs::create_dir_all(self.path.as_str()));
        if verbose {
            println!("Results folder created. Time to create the reports.");
        }

        try!(self.generate_json_report(verbose));

        if verbose {
            println!("JSON report generated.");
        }

        try!(self.generate_txt_report(verbose));

        if verbose {
            println!("Text report generated.");
        }

        Ok(())
    }

    fn generate_json_report(&self, verbose: bool) -> Result<()> {
        if verbose {
            println!("Starting JSON report generation. First we create the file.")
        }
        let mut f = try!(File::create(format!("{}/results.json", self.path)));
        if verbose {
            println!("The report file has been created. Now it's time for the actual report.")
        }
        // TODO
        // unimplemented!();
        Ok(())
    }

    fn generate_txt_report(&self, verbose: bool) -> Result<()> {
        if verbose {
            println!("Starting text report generation. First we create the file.")
        }
        let mut f = try!(File::create(format!("{}/results.txt", self.path)));
        if verbose {
            println!("The report file has been created. Now it's time for the actual report.")
        }

        try!(f.write_all(&format!("This is the vulnerability report for the android \
                                   application {}\n",
                                  self.app_package)
                              .into_bytes()));

        try!(f.write_all(b"Application data:\n"));
        try!(f.write_all(&format!(" - Name: {}\n", self.app_label).into_bytes()));
        try!(f.write_all(&format!(" - Description: {}\n", self.app_description).into_bytes()));
        try!(f.write_all(&format!(" - Package: {}\n", self.app_package).into_bytes()));
        try!(f.write_all(&format!(" - Version: {}\n", self.app_version).into_bytes()));

        try!(f.write_all(b"\n"));

        let total_vuln = self.low.len() + self.medium.len() + self.high.len() + self.critical.len();
        try!(f.write_all(&format!("Total vulnerabilities found: {}\n", total_vuln).into_bytes()));
        try!(f.write_all(&format!(" - Critical: {}\n", self.critical.len()).into_bytes()));
        try!(f.write_all(&format!(" - High criticity: {}\n", self.high.len()).into_bytes()));
        try!(f.write_all(&format!(" - Medium criticity: {}\n", self.medium.len()).into_bytes()));
        try!(f.write_all(&format!(" - Low criticity: {}\n", self.low.len()).into_bytes()));

        try!(f.write_all(b"\n"));
        try!(f.write_all(b"------------------------------------------\n"));
        try!(f.write_all(b"\n"));

        if self.critical.len() > 0 {
            try!(f.write_all(b"Critical vulnerabilities:\n"));
            try!(f.write_all(b"\n"));

            for (i, vuln) in self.critical.iter().enumerate() {
                try!(f.write_all(&format!("C{:03}:\n", i+1).into_bytes()));
                try!(f.write_all(&format!("Name: {}\n", vuln.get_name()).into_bytes()));
                try!(f.write_all(&format!("Description: {}\n", vuln.get_description())
                                      .into_bytes()));
                if let Some(s) = vuln.get_file() {
                    try!(f.write_all(&format!("File: {}\n", s).into_bytes()));
                }
                if let Some(s) = vuln.get_line() {
                    try!(f.write_all(&format!("Line: {}\n", s).into_bytes()));
                }
            }
        }

        if self.high.len() > 0 {
            try!(f.write_all(b"High criticity vulnerabilities:\n"));
            try!(f.write_all(b"\n"));

            for (i, vuln) in self.high.iter().enumerate() {
                try!(f.write_all(&format!("H{:03}:\n", i+1).into_bytes()));
                try!(f.write_all(&format!("Name: {}\n", vuln.get_name()).into_bytes()));
                try!(f.write_all(&format!("Description: {}\n", vuln.get_description())
                                      .into_bytes()));
                if let Some(s) = vuln.get_file() {
                    try!(f.write_all(&format!("File: {}\n", s).into_bytes()));
                }
                if let Some(s) = vuln.get_line() {
                    try!(f.write_all(&format!("Line: {}\n", s).into_bytes()));
                }
            }
        }

        if self.medium.len() > 0 {
            try!(f.write_all(b"Medium criticity vulnerabilities:\n"));
            try!(f.write_all(b"\n"));

            for (i, vuln) in self.medium.iter().enumerate() {
                try!(f.write_all(&format!("M{:03}:\n", i+1).into_bytes()));
                try!(f.write_all(&format!("Name: {}\n", vuln.get_name()).into_bytes()));
                try!(f.write_all(&format!("Description: {}\n", vuln.get_description())
                                      .into_bytes()));
                if let Some(s) = vuln.get_file() {
                    try!(f.write_all(&format!("File: {}\n", s).into_bytes()));
                }
                if let Some(s) = vuln.get_line() {
                    try!(f.write_all(&format!("Line: {}\n", s).into_bytes()));
                }
            }
        }

        if self.low.len() > 0 {
            try!(f.write_all(b"Low criticity vulnerabilities:\n"));
            try!(f.write_all(b"\n"));

            for (i, vuln) in self.low.iter().enumerate() {
                try!(f.write_all(&format!("L{:03}:\n", i+1).into_bytes()));
                try!(f.write_all(&format!("Name: {}\n", vuln.get_name()).into_bytes()));
                try!(f.write_all(&format!("Description: {}\n", vuln.get_description())
                                      .into_bytes()));
                if let Some(s) = vuln.get_file() {
                    try!(f.write_all(&format!("File: {}\n", s).into_bytes()));
                }
                if let Some(s) = vuln.get_line() {
                    try!(f.write_all(&format!("Line: {}\n", s).into_bytes()));
                }
            }
        }

        Ok(())
    }
}

#[derive(Clone, PartialEq, Eq, Ord)]
struct Vulnerability {
    name: String,
    description: String,
    file: Option<String>,
    line: Option<u32>,
    criticity: Criticity,
}

impl Vulnerability {
    pub fn new<S: AsRef<str>, P: AsRef<Path>>(name: S,
                                              description: S,
                                              file: Option<P>,
                                              line: Option<u32>,
                                              criticity: Criticity)
                                              -> Vulnerability {
        Vulnerability {
            name: String::from(name.as_ref()),
            description: String::from(description.as_ref()),
            file: match file {
                Some(p) => Some(String::from(p.as_ref().to_string_lossy().into_owned())),
                None => None,
            },
            line: line,
            criticity: criticity,
        }
    }

    pub fn get_name(&self) -> &str {
        self.name.as_str()
    }

    pub fn get_description(&self) -> &str {
        self.description.as_str()
    }

    pub fn get_file(&self) -> Option<&str> {
        match self.file.as_ref() {
            Some(s) => Some(s.as_str()),
            None => None,
        }
    }

    pub fn get_line(&self) -> Option<u32> {
        self.line
    }
}

impl PartialOrd for Vulnerability {
    fn partial_cmp(&self, other: &Vulnerability) -> Option<Ordering> {
        if self.criticity < other.criticity {
            Some(Ordering::Less)
        } else if self.criticity > other.criticity {
            Some(Ordering::Greater)
        } else {
            if self.file < other.file {
                Some(Ordering::Less)
            } else if self.file > other.file {
                Some(Ordering::Greater)
            } else {
                if self.line < other.line {
                    Some(Ordering::Less)
                } else if self.line > other.line {
                    Some(Ordering::Greater)
                } else {
                    if self.name < other.name {
                        Some(Ordering::Less)
                    } else if self.name > other.name {
                        Some(Ordering::Greater)
                    } else {
                        Some(Ordering::Equal)
                    }
                }
            }
        }
    }
}
