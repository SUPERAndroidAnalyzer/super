//! SUPER Android Analyzer
extern crate super_analyzer;


extern crate clap;
extern crate colored;
extern crate xml;
extern crate serde;
extern crate serde_json;
extern crate chrono;
extern crate toml;
extern crate regex;
extern crate lazy_static;
extern crate rustc_serialize;
extern crate open;
extern crate bytecount;
extern crate handlebars;
#[macro_use]
extern crate log;
extern crate env_logger;
extern crate error_chain;
extern crate abxml;
extern crate md5;
extern crate sha1;
extern crate sha2;

use colored::Colorize;

use log::LogLevel;

// use super_analyzer::*;

use super_analyzer::run;

#[allow(print_stdout)]
fn main() {
    if let Err(e) = run() {
        error!("{}", e);

        for e in e.iter().skip(1) {
            println!("\t{}{}", "Caused by: ".bold(), e);
        }

        if !log_enabled!(LogLevel::Debug) {
            println!(
                "If you need more information, try to run the program again with the {} flag.",
                "-v".bold()
            );
        }

        if let Some(backtrace) = e.backtrace() {
            #[allow(use_debug)]
            {
                println!("backtrace: {:?}", backtrace);
            }
        }

        ::std::process::exit(e.into());
    }
}
