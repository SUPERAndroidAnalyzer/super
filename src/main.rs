#[macro_use]
extern crate clap;

use std::path::Path;
use clap::{Arg, App};

fn main() {
    let matches = App::new("Android Anti-Revelation Project")
                      .version(crate_version!())
                      .author("Iban Eguia <razican@protonmail.ch>")
                      .about("Audits Android apps for vulnerabilities")
                      .arg(Arg::with_name("id")
                               .help("Application id")
                               .value_name("ID")
                               .required(true)
                               .takes_value(true))
                      .arg(Arg::with_name("tempdir")
                               .short("d")
                               .long("--tempdir")
                               .value_name("TEMPDIR")
                               .takes_value(true)
                               .default_value("temp")
                               .help("Sets the temporary directory for the application"))
                      .arg(Arg::with_name("threads")
                               .short("t")
                               .long("--threads")
                               .value_name("THREADS")
                               .takes_value(true)
                               .default_value("2")
                               .help("Sets the number of threads for the application"))
                      .arg(Arg::with_name("verbose")
                               .short("v")
                               .help("Sets the level of verbosity"))
                      .get_matches();

    let tempdir = Path::new(matches.value_of("tempdir").unwrap());
    let threads = matches.value_of("threads").unwrap().parse::<u8>().unwrap();
    let app_id = matches.value_of("id").unwrap();
}
