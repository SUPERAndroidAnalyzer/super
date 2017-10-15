//! SUPER Android Analyzer
extern crate super_analyzer;


pub extern crate clap;
pub extern crate colored;
pub extern crate xml;
pub extern crate serde;
pub extern crate serde_json;
pub extern crate chrono;
pub extern crate toml;
pub extern crate regex;
pub extern crate lazy_static;
pub extern crate rustc_serialize;
pub extern crate open;
pub extern crate bytecount;
pub extern crate handlebars;
#[macro_use]
pub extern crate log;
pub extern crate env_logger;
pub extern crate error_chain;
pub extern crate abxml;
pub extern crate md5;
pub extern crate sha1;
pub extern crate sha2;

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
