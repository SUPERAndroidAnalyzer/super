//! Utilities for results generation.
//!
//! In this module you can find structures like `Vulnerability` and `Fingerprint` that contain the
//! information for results.

use std::{
    borrow::Cow,
    cmp::Ordering,
    fs::File,
    io::{BufReader, Read},
    path::{Path, PathBuf},
};

use failure::Error;
use hex::ToHex;
use lazy_static::lazy_static;
use regex::Regex;
use serde::ser::{Serialize, SerializeStruct, Serializer};
use {md5, sha1, sha2};

use crate::criticality::Criticality;

/// Structure to store information about a vulnerability.
#[derive(Debug, Clone, PartialEq, Eq, Ord)]
pub struct Vulnerability {
    /// Vulnerability criticality.
    criticality: Criticality,
    /// Name of the vulnerability.
    name: String,
    /// Description of the vulnerability.
    description: String,
    /// Optional file were the vulnerability was present.
    file: Option<PathBuf>,
    /// Optional starting line in the given file.
    start_line: Option<usize>,
    /// Optional ending line in the given file.
    end_line: Option<usize>,
    /// The vulnerable code snippet.
    code: Option<String>,
}

impl Vulnerability {
    /// Creates a new vulnerability.
    pub fn new<N: Into<String>, D: Into<String>, P: AsRef<Path>, C: Into<String>>(
        criticality: Criticality,
        name: N,
        description: D,
        file: Option<P>,
        start_line: Option<usize>,
        end_line: Option<usize>,
        code: Option<C>,
    ) -> Self {
        Self {
            criticality,
            name: name.into(),
            description: description.into(),
            file: file.map(|p| p.as_ref().to_path_buf()),
            start_line,
            end_line,
            code: code.map(C::into),
        }
    }

    /// Gets the criticality of the vulnerability.
    pub fn get_criticality(&self) -> Criticality {
        self.criticality
    }
}

impl Serialize for Vulnerability {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut ser_struct = serializer.serialize_struct(
            "Vulnerability",
            if self.code.is_some() {
                if self.start_line == self.end_line {
                    7
                } else {
                    8
                }
            } else {
                4
            },
        )?;
        ser_struct.serialize_field("criticality", &self.criticality)?;
        ser_struct.serialize_field("name", self.name.as_str())?;
        ser_struct.serialize_field("description", self.description.as_str())?;
        ser_struct.serialize_field("file", &self.file)?;
        if self.code.is_some() {
            ser_struct.serialize_field(
                "language",
                &self
                    .file
                    .as_ref()
                    .unwrap()
                    .extension()
                    .unwrap()
                    .to_string_lossy(),
            )?;
            if self.start_line == self.end_line {
                ser_struct.serialize_field("line", &(self.start_line.unwrap() + 1))?;
            } else {
                ser_struct.serialize_field("start_line", &(self.start_line.unwrap() + 1))?;
                ser_struct.serialize_field("end_line", &(self.end_line.unwrap() + 1))?;
            }
            ser_struct.serialize_field("code", &self.code)?;
        }
        ser_struct.end()
    }
}

impl PartialOrd for Vulnerability {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(
            (
                &self.criticality,
                &self.file,
                &self.start_line,
                &self.end_line,
                &self.name,
            )
                .cmp(&(
                    &other.criticality,
                    &other.file,
                    &other.start_line,
                    &other.end_line,
                    &other.name,
                )),
        )
    }
}

/// Structure to store the application fingerprint.
pub struct FingerPrint {
    /// MD5 hash.
    md5: md5::Digest,
    /// SHA-1 hash.
    sha1: sha1::Digest,
    /// SHA-256 hash.
    sha256: [u8; 32],
}

impl FingerPrint {
    /// Creates a new fingerprint.
    ///
    /// This function will read the complete file and generate its MD5, SHA-1 and SHA-256 hashes.
    #[allow(clippy::cast_possible_truncation)]
    pub fn from_package<P: AsRef<Path>>(package: P) -> Result<Self, Error> {
        use sha2::Digest;

        let file = File::open(package)?;
        let mut buffer = Vec::with_capacity(file.metadata()?.len() as usize);
        let _ = BufReader::new(file).read_to_end(&mut buffer)?;

        let sha1 = sha1::Sha1::from(&buffer);

        let mut sha256 = sha2::Sha256::default();
        sha256.input(&buffer);

        let mut sha256_res = [0_u8; 32];
        sha256_res.clone_from_slice(&sha256.result()[..]);
        Ok(Self {
            md5: md5::compute(&buffer),
            sha1: sha1.digest(),
            sha256: sha256_res,
        })
    }
}

impl Serialize for FingerPrint {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut ser_struct = serializer.serialize_struct("fingerprint", 3)?;
        ser_struct.serialize_field("md5", &format!("{:x}", self.md5))?;
        ser_struct.serialize_field("sha1", &self.sha1.to_string())?;
        let mut sha256_hex = String::new();
        // It should never fail, we are writing directly to memory, without I/O access
        // That's why the `expect()` should never panic.
        self.sha256
            .write_hex(&mut sha256_hex)
            .expect("the SHA-256 fingerprinting of the application failed");
        ser_struct.serialize_field("sha256", &sha256_hex)?;
        ser_struct.end()
    }
}

/// Split line into indentation and the rest of the line.
pub fn split_indent(line: &str) -> (&str, &str) {
    match line.find(|c: char| !c.is_whitespace()) {
        Some(p) => line.split_at(p),
        None => ("", line),
    }
}

/// Escapes the given input's HTML special characters.
///
/// It changes the following characters:
///  - `<` => `&lt;`
///  - `>` => `&gt;`
///  - `&` => `&amp;`
pub fn html_escape<'a, S: Into<Cow<'a, str>>>(input: S) -> Cow<'a, str> {
    lazy_static! {
        static ref REGEX: Regex = Regex::new("[<>&]").unwrap();
    }
    let input = input.into();
    let mut last_match = 0;

    if REGEX.is_match(&input) {
        let matches = REGEX.find_iter(&input);
        let mut output = String::with_capacity(input.len());
        for m in matches {
            output.push_str(&input[last_match..m.start()]);
            match &input[m.start()..m.end()] {
                "<" => output.push_str("&lt;"),
                ">" => output.push_str("&gt;"),
                "&" => output.push_str("&amp;"),
                _ => unreachable!(),
            }
            last_match = m.end();
        }
        output.push_str(&input[last_match..]);
        Cow::Owned(output)
    } else {
        input
    }
}
