use std::{fmt, result};
use std::fs::File;
use std::io::Read;
use std::cmp::Ordering;
use std::path::Path;
use std::time::Duration;

use serde::ser::{Serialize, Serializer};
use crypto::digest::Digest;
use crypto::md5::Md5;
use crypto::sha1::Sha1;
use crypto::sha2::Sha256;
use rustc_serialize::hex::ToHex;

use {Config, Result, Criticity};

/// Structure to store information about a vulnerability
#[derive(Debug, Clone, PartialEq, Eq, Ord)]
pub struct Vulnerability {
    criticity: Criticity,
    name: String,
    description: String,
    file: Option<String>,
    start_line: Option<usize>,
    end_line: Option<usize>,
    code: Option<String>,
}

impl Vulnerability {
    /// Creates a new vulnerability
    pub fn new<S: AsRef<str>, P: AsRef<Path>>(criticity: Criticity,
                                              name: S,
                                              description: S,
                                              file: Option<P>,
                                              start_line: Option<usize>,
                                              end_line: Option<usize>,
                                              code: Option<String>)
                                              -> Vulnerability {
        Vulnerability {
            criticity: criticity,
            name: String::from(name.as_ref()),
            description: String::from(description.as_ref()),
            file: match file {
                Some(s) => Some(String::from(s.as_ref().to_string_lossy().into_owned())),
                None => None,
            },
            start_line: start_line,
            end_line: end_line,
            code: match code {
                Some(s) => Some(String::from(s.as_ref())),
                None => None,
            },
        }
    }

    /// Gets the criticity of the vulnerability
    pub fn get_criticity(&self) -> Criticity {
        self.criticity
    }

    /// Gets the name of the vulnerability
    pub fn get_name(&self) -> &str {
        self.name.as_str()
    }

    /// Get the description of the vulnerability
    pub fn get_description(&self) -> &str {
        self.description.as_str()
    }

    /// Gets the file where the vulnerability was found
    pub fn get_file(&self) -> Option<&Path> {
        match self.file.as_ref() {
            Some(s) => Some(Path::new(s)),
            None => None,
        }
    }

    /// Gets the code related to the vulnerability
    pub fn get_code(&self) -> Option<&str> {
        match self.code.as_ref() {
            Some(s) => Some(s.as_str()),
            None => None,
        }
    }

    /// Gets the start line of the vulnerability
    pub fn get_start_line(&self) -> Option<usize> {
        self.start_line
    }

    /// Gets the end line of the vulnerability
    pub fn get_end_line(&self) -> Option<usize> {
        self.end_line
    }
}

impl Serialize for Vulnerability {
    fn serialize<S>(&self, serializer: &mut S) -> result::Result<(), S::Error>
        where S: Serializer
    {
        let mut state = try!(serializer.serialize_struct("Vulnerability", 7));
        try!(serializer.serialize_struct_elt(&mut state, "criticity", self.criticity));
        try!(serializer.serialize_struct_elt(&mut state, "name", self.name.as_str()));
        try!(serializer.serialize_struct_elt(&mut state, "description", self.description.as_str()));
        try!(serializer.serialize_struct_elt(&mut state, "file", &self.file));
        try!(serializer.serialize_struct_elt(&mut state, "start_line", self.start_line));
        try!(serializer.serialize_struct_elt(&mut state, "end_line", self.end_line));
        try!(serializer.serialize_struct_end(state));
        Ok(())
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
                if self.start_line < other.start_line {
                    Some(Ordering::Less)
                } else if self.start_line > other.start_line {
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

/// Structure to store
pub struct FingerPrint {
    md5: [u8; 16],
    sha1: [u8; 20],
    sha256: [u8; 32],
}

impl FingerPrint {
    pub fn new(config: &Config) -> Result<FingerPrint> {
        let path = format!("{}/{}.apk",
                           config.get_downloads_folder(),
                           config.get_app_id());

        let mut f = try!(File::open(path));
        let mut buffer = Vec::with_capacity(f.metadata().unwrap().len() as usize);
        try!(f.read_to_end(&mut buffer));

        let mut md5 = Md5::new();
        let mut sha1 = Sha1::new();
        let mut sha256 = Sha256::new();

        md5.input(&buffer);
        sha1.input(&buffer);
        sha256.input(&buffer);

        let mut fingerprint = FingerPrint {
            md5: [0; 16],
            sha1: [0; 20],
            sha256: [0; 32],
        };

        md5.result(&mut fingerprint.md5);
        sha1.result(&mut fingerprint.sha1);
        sha256.result(&mut fingerprint.sha256);

        Ok(fingerprint)
    }

    /// Gets the MD5 hash
    pub fn get_md5(&self) -> &[u8] {
        &self.md5
    }

    /// Gets the SHA-1 hash
    pub fn get_sha1(&self) -> &[u8] {
        &self.sha1
    }

    /// Gets the SHA-256 hash
    pub fn get_sha256(&self) -> &[u8] {
        &self.sha256
    }
}

impl Serialize for FingerPrint {
    fn serialize<S>(&self, serializer: &mut S) -> result::Result<(), S::Error>
        where S: Serializer
    {
        let mut state = try!(serializer.serialize_struct("fingerprint", 3));
        try!(serializer.serialize_struct_elt(&mut state, "md5", self.md5.to_hex()));
        try!(serializer.serialize_struct_elt(&mut state, "sha1", self.sha1.to_hex()));
        try!(serializer.serialize_struct_elt(&mut state, "sha256", self.sha256.to_hex()));
        try!(serializer.serialize_struct_end(state));
        Ok(())
    }
}

/// Structure to store a benchmark information
pub struct Benchmark {
    label: String,
    duration: Duration,
}

impl Benchmark {
    /// Creates a new benchmark
    pub fn new(label: &str, duration: Duration) -> Benchmark {
        Benchmark {
            label: String::from(label),
            duration: duration,
        }
    }
}

impl fmt::Display for Benchmark {
    fn fmt(&self, f: &mut fmt::Formatter) -> result::Result<(), fmt::Error> {
        write!(f,
               "{}: {}.{}s",
               self.label,
               self.duration.as_secs(),
               self.duration.subsec_nanos())
    }
}
