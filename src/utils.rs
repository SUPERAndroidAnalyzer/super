//! General utilities module.

use crate::{config::Config, criticality::Criticality};
use anyhow::{Context, Result};
use colored::Colorize;
use log::{log_enabled, warn, Level};
use quick_xml::{events::Event, Reader};
use std::{fmt, fs::File, io::BufReader, path::Path, thread::sleep, time::Duration};

/// Prints a warning to `stderr` in yellow.
#[allow(clippy::print_stdout)]
pub fn print_warning<S: AsRef<str>>(warning: S) {
    if cfg!(not(test)) {
        warn!("{}", warning.as_ref());

        if log_enabled!(Level::Debug) {
            sleep(Duration::from_millis(250));
        } else if log_enabled!(Level::Warn) {
            eprintln!(
                "If you need more information, try to run the program again with the {} flag.",
                "-v".bold()
            )
        }
    }
}

/// Prints a vulnerability to `stdout` in a color depending on the criticality.
#[allow(clippy::print_stdout)]
pub fn print_vulnerability<S: AsRef<str>>(text: S, criticality: Criticality) {
    if cfg!(not(test)) && log_enabled!(Level::Debug) {
        let message = format!(
            "Possible {} criticality vulnerability found!: {}",
            criticality,
            text.as_ref()
        );

        let formatted_message = match criticality {
            Criticality::Low => message.cyan(),
            Criticality::Medium => message.yellow(),
            Criticality::High | Criticality::Critical => message.red(),
            _ => return,
        };

        println!("{}", formatted_message);
        sleep(Duration::from_millis(250));
    }
}

/// Gets the name of the package from the path of the *.apk* file.
///
/// Note: it will panic if the path has no `file_stem`.
pub fn get_package_name<P: AsRef<Path>>(path: P) -> String {
    path.as_ref()
        .file_stem()
        .expect("expected package name")
        .to_string_lossy()
        .into_owned()
}

/// Gets the code snippet near the start and end lines.
///
/// It will return 5 lines above and 5 lines below the vulnerability.
#[allow(clippy::nonminimal_bool)]
pub fn get_code<S: AsRef<str>>(code: S, s_line: usize, e_line: usize) -> String {
    let mut result = String::new();
    for (i, text) in code.as_ref().lines().enumerate() {
        if i >= (e_line + 5) {
            break;
        } else if (s_line >= 5 && i > s_line - 5) || (s_line < 5 && i < s_line + 5) {
            result.push_str(text);
            result.push_str("\n");
        }
    }
    result
}

/// Gets a string from the strings XML file.
pub fn get_string<L, P>(label: L, config: &Config, package: P) -> Result<Option<String>>
where
    L: AsRef<[u8]>,
    P: AsRef<str>,
{
    // TODO: Lazy static HashMap.
    let mut path = config
        .dist_folder()
        .join(package.as_ref())
        .join("res")
        .join("values-en")
        .join("strings.xml");

    if !path.exists() {
        path = config
            .dist_folder()
            .join(package.as_ref())
            .join("res")
            .join("values")
            .join("strings.xml");
    }

    let file = File::open(&path).with_context(|| format!("could not open `{}`", path.display()))?;

    let buffer = BufReader::new(file);

    let mut reader = Reader::from_reader(buffer);
    let _ = reader.trim_text(true);

    let mut found = false;
    let mut buf = Vec::new();
    loop {
        match reader.read_event(&mut buf) {
            Ok(Event::Start(e)) => {
                if e.local_name() == b"string" {
                    for attr in e.attributes() {
                        let attr = attr?;

                        if attr.key == b"name" && attr.value == label.as_ref() {
                            found = true;
                        }
                    }
                }
            }
            Ok(Event::CData(data)) | Ok(Event::Text(data)) => {
                if found {
                    let result = String::from_utf8(data.unescaped()?.into())?;
                    return Ok(Some(result));
                }
            }
            Ok(Event::Eof) => return Ok(None),
            _ => {}
        }
    }
}

/// Structure to store a benchmark information.
#[derive(Debug)]
pub struct Benchmark {
    /// The label for the benchmark.
    label: String,
    /// The benchmark duration.
    duration: Duration,
}

impl Benchmark {
    /// Creates a new benchmark.
    pub fn new<S: Into<String>>(label: S, duration: Duration) -> Self {
        Self {
            label: label.into(),
            duration,
        }
    }
}

impl fmt::Display for Benchmark {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(
            f,
            "{}: {}.{}s",
            self.label,
            self.duration.as_secs(),
            self.duration.subsec_nanos()
        )
    }
}

#[cfg(test)]
mod test {
    use crate::get_code;

    #[test]
    fn it_get_code() {
        let code = "Lorem ipsum dolor sit amet, consectetur adipiscing elit.\nCurabitur tortor. \
                    Pellentesque nibh. Aenean quam.\nSed lacinia, urna non tincidunt mattis, \
                    tortor neque\nPraesent blandit dolor. Sed non quam. In vel mi\nSed aliquet \
                    risus a tortor. Integer id quam. Morbi mi.\nNullam mauris orci, aliquet et, \
                    iaculis et, viverra vitae, ligula.\nPraesent mauris. Fusce nec tellus sed \
                    ugue semper porta. Mauris massa.\nProin ut ligula vel nunc egestas porttitor. \
                    Morbi lectus risus,\nVestibulum sapien. Proin quam. Etiam ultrices. \
                    Suspendisse in\nVestibulum tincidunt malesuada tellus. Ut ultrices ultrices \
                    enim.\nAenean laoreet. Vestibulum nisi lectus, commodo ac, facilisis\nInteger \
                    nec odio. Praesent libero. Sed cursus ante dapibus diam.\nPellentesque nibh. \
                    Aenean quam. In scelerisque sem at dolor.\nSed lacinia, urna non tincidunt \
                    mattis, tortor neque adipiscing\nVestibulum ante ipsum primis in faucibus \
                    orci luctus et ultrices";

        assert_eq!(
            get_code(code, 1, 1),
            "Lorem ipsum dolor sit amet, consectetur adipiscing elit.\n\
             Curabitur tortor. Pellentesque nibh. Aenean quam.\n\
             Sed lacinia, urna non tincidunt mattis, tortor neque\n\
             Praesent blandit dolor. Sed non quam. In vel mi\n\
             Sed aliquet risus a tortor. Integer id quam. Morbi mi.\n\
             Nullam mauris orci, aliquet et, iaculis et, viverra vitae, ligula.\n"
        );

        assert_eq!(
            get_code(code, 13, 13),
            "Vestibulum tincidunt malesuada tellus. Ut ultrices ultrices enim.\n\
             Aenean laoreet. Vestibulum nisi lectus, commodo ac, facilisis\n\
             Integer nec odio. Praesent libero. Sed cursus ante dapibus diam.\n\
             Pellentesque nibh. Aenean quam. In scelerisque sem at dolor.\n\
             Sed lacinia, urna non tincidunt mattis, tortor neque adipiscing\n\
             Vestibulum ante ipsum primis in faucibus orci luctus et ultrices\n"
        );

        assert_eq!(
            get_code(code, 7, 7),
            "Praesent blandit dolor. Sed non quam. In vel mi\n\
             Sed aliquet risus a tortor. Integer id quam. Morbi mi.\n\
             Nullam mauris orci, aliquet et, iaculis et, viverra vitae, ligula.\n\
             Praesent mauris. Fusce nec tellus sed ugue semper porta. Mauris massa.\n\
             Proin ut ligula vel nunc egestas porttitor. Morbi lectus risus,\n\
             Vestibulum sapien. Proin quam. Etiam ultrices. Suspendisse in\n\
             Vestibulum tincidunt malesuada tellus. Ut ultrices ultrices enim.\n\
             Aenean laoreet. Vestibulum nisi lectus, commodo ac, facilisis\n\
             Integer nec odio. Praesent libero. Sed cursus ante dapibus diam.\n"
        );

        assert_eq!(
            get_code(code, 7, 9),
            "Praesent blandit dolor. Sed non quam. In vel mi\n\
             Sed aliquet risus a tortor. Integer id quam. Morbi mi.\n\
             Nullam mauris orci, aliquet et, iaculis et, viverra vitae, ligula.\n\
             Praesent mauris. Fusce nec tellus sed ugue semper porta. Mauris massa.\n\
             Proin ut ligula vel nunc egestas porttitor. Morbi lectus risus,\n\
             Vestibulum sapien. Proin quam. Etiam ultrices. Suspendisse in\n\
             Vestibulum tincidunt malesuada tellus. Ut ultrices ultrices enim.\n\
             Aenean laoreet. Vestibulum nisi lectus, commodo ac, facilisis\n\
             Integer nec odio. Praesent libero. Sed cursus ante dapibus diam.\n\
             Pellentesque nibh. Aenean quam. In scelerisque sem at dolor.\n\
             Sed lacinia, urna non tincidunt mattis, tortor neque adipiscing\n"
        );
    }
}
