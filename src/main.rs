//! SUPER Android Analyzer

#![forbid(deprecated, overflowing_literals, stable_features, trivial_casts, unconditional_recursion,
    plugin_as_library, unused_allocation, trivial_numeric_casts, unused_features, while_truem,
    unused_parens, unused_comparisons, unused_extern_crates, unused_import_braces, unused_results,
    improper_ctypes, non_shorthand_field_patterns, private_no_mangle_fns, private_no_mangle_statics,
    filter_map, used_underscore_binding, option_map_unwrap_or, option_map_unwrap_or_else,
    mutex_integer, mut_mut, mem_forget)]
#![deny(unused_qualifications, unused, unused_attributes)]
#![warn(missing_docs, variant_size_differences, enum_glob_use, if_not_else,
    invalid_upcast_comparisons, items_after_statements, non_ascii_literal, nonminimal_bool,
    pub_enum_variant_names, shadow_reuse, shadow_same, shadow_unrelated, similar_names,
    single_match_else, string_add, string_add_assign, unicode_not_nfc, unseparated_literal_suffix,
    use_debug, wrong_pub_self_convention, doc_markdown)]
// Allowing these at least for now.
#![allow(missing_docs_in_private_items, unknown_lints, print_stdout, stutter, option_unwrap_used,
    result_unwrap_used, integer_arithmetic, cast_possible_truncation, cast_possible_wrap,
    indexing_slicing, cast_precision_loss, cast_sign_loss)]

extern crate super_analyzer;

extern crate colored;
#[macro_use]
extern crate log;

use std::io::{self, Write};
use std::time::{Instant, Duration};
use std::thread::sleep;
use std::collections::BTreeMap;

use colored::Colorize;
use log::LogLevel;
use super_analyzer::*;


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

fn run() -> Result<()> {
    let cli = cli::generate().get_matches();
    let verbose = cli.is_present("verbose");
    initialize_logger(verbose);

    let mut config = initialize_config(cli)?;

    if !config.check() {
        let mut error_string = String::from("Configuration errors were found:\n");
        for error in config.get_errors() {
            error_string.push_str(&error);
            error_string.push('\n');
        }
        error_string.push_str(
            "The configuration was loaded, in order, from the following files: \
                               \n\t- Default built-in configuration\n",
        );
        for file in config.get_loaded_config_files() {
            error_string.push_str(&format!("\t- {}\n", file.display()));
        }

        return Err(ErrorKind::Config(error_string).into());
    }

    if config.is_verbose() {
        for c in BANNER.chars() {
            print!("{}", c);
            io::stdout().flush().unwrap();
            sleep(Duration::from_millis(3));
        }
        println!(
            "Welcome to the SUPER Android Analyzer. We will now try to audit the given \
                  application."
        );
        println!(
            "You activated the verbose mode. {}",
            "May Tux be with you!".bold()
        );
        println!();
        sleep(Duration::from_millis(1250));
    }

    let mut benchmarks = BTreeMap::new();

    let total_start = Instant::now();
    for package in config.get_app_packages() {
        config.reset_force();
        analyze_package(package, &mut config, &mut benchmarks)
            .chain_err(|| "Application analysis failed")?;
    }

    if config.is_bench() {
        let total_time = Benchmark::new("Total time", total_start.elapsed());
        println!();
        println!("{}", "Benchmarks:".bold());
        for (package_name, benchmarks) in benchmarks {
            println!("{}:", package_name.italic());
            for bench in benchmarks {
                println!("{}", bench);
            }
            println!();
        }
        println!("{}", total_time);
    }

    Ok(())
}
