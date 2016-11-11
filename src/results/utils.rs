use std::result::Result as StdResult;
use std::fs::File;
use std::io::Read;
use std::cmp::Ordering;
use std::path::{Path, PathBuf};
use std::borrow::Cow;

use serde::ser::{Serialize, Serializer};
use crypto::digest::Digest;
use crypto::md5::Md5;
use crypto::sha1::Sha1;
use crypto::sha2::Sha256;
use rustc_serialize::hex::ToHex;
use regex::Regex;

use {Result, Criticity};

/// Structure to store information about a vulnerability.
#[derive(Debug, Clone, PartialEq, Eq, Ord)]
pub struct Vulnerability {
    criticity: Criticity,
    name: String,
    description: String,
    file: Option<PathBuf>,
    start_line: Option<usize>,
    end_line: Option<usize>,
    code: Option<String>,
}

impl Vulnerability {
    /// Creates a new vulnerability.
    pub fn new<N: Into<String>, D: Into<String>, P: AsRef<Path>, C: Into<String>>
        (criticity: Criticity,
         name: N,
         description: D,
         file: Option<P>,
         start_line: Option<usize>,
         end_line: Option<usize>,
         code: Option<C>)
         -> Vulnerability {
        Vulnerability {
            criticity: criticity,
            name: name.into(),
            description: description.into(),
            file: match file {
                Some(p) => Some(p.as_ref().to_path_buf()),
                None => None,
            },
            start_line: start_line,
            end_line: end_line,
            code: match code {
                Some(c) => Some(c.into()),
                None => None,
            },
        }
    }

    /// Gets the criticity of the vulnerability.
    pub fn get_criticity(&self) -> Criticity {
        self.criticity
    }
}

impl Serialize for Vulnerability {
    fn serialize<S>(&self, serializer: &mut S) -> StdResult<(), S::Error>
        where S: Serializer
    {
        let mut state = try!(serializer.serialize_struct("Vulnerability",
                                                         if self.code.is_some() {
                                                             if self.start_line == self.end_line {
                                                                 7
                                                             } else {
                                                                 8
                                                             }
                                                         } else {
                                                             4
                                                         }));
        try!(serializer.serialize_struct_elt(&mut state, "criticity", self.criticity));
        try!(serializer.serialize_struct_elt(&mut state, "name", self.name.as_str()));
        try!(serializer.serialize_struct_elt(&mut state, "description", self.description.as_str()));
        try!(serializer.serialize_struct_elt(&mut state, "file", &self.file));
        if self.code.is_some() {
            try!(serializer.serialize_struct_elt(&mut state,
                                                 "language",
                                                 self.file
                                                     .as_ref()
                                                     .unwrap()
                                                     .extension()
                                                     .unwrap()
                                                     .to_string_lossy()));
            if self.start_line == self.end_line {
                try!(serializer.serialize_struct_elt(&mut state, "line",
                                                     self.start_line.unwrap() + 1));
            } else {
                try!(serializer.serialize_struct_elt(&mut state, "start_line",
                                                     self.start_line.unwrap()+1));
                try!(serializer.serialize_struct_elt(&mut state, "end_line",
                                                     self.end_line.unwrap() + 1));
            }
            try!(serializer.serialize_struct_elt(&mut state, "code", &self.code));
        }
        try!(serializer.serialize_struct_end(state));
        Ok(())
    }
}

impl PartialOrd for Vulnerability {
    fn partial_cmp(&self, other: &Vulnerability) -> Option<Ordering> {
        Some((&self.criticity, &self.file, &self.start_line, &self.end_line, &self.name)
            .cmp(&(&other.criticity, &other.file, &other.start_line, &other.end_line, &other.name)))
    }
}

/// Structure to store.
pub struct FingerPrint {
    md5: [u8; 16],
    sha1: [u8; 20],
    sha256: [u8; 32],
}

impl FingerPrint {
    /// Creates a new fingerprint.
    pub fn new<P: AsRef<Path>>(package: P) -> Result<FingerPrint> {
        let mut f = try!(File::open(package));
        let mut buffer = Vec::with_capacity(f.metadata().unwrap().len() as usize);
        let _ = try!(f.read_to_end(&mut buffer));

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
}

impl Serialize for FingerPrint {
    fn serialize<S>(&self, serializer: &mut S) -> StdResult<(), S::Error>
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
        for (begin, end) in matches {
            output.push_str(&input[last_match..begin]);
            match &input[begin..end] {
                "<" => output.push_str("&lt;"),
                ">" => output.push_str("&gt;"),
                "&" => output.push_str("&amp;"),
                _ => unreachable!(),
            }
            last_match = end;
        }
        output.push_str(&input[last_match..]);
        Cow::Owned(output)
    } else {
        input
    }
}
