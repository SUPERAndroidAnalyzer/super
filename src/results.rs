use std::fs;
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

    pub fn generate_report(self) -> Result<()> {
        // TODO
        unimplemented!();
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
