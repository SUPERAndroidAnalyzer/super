#[macro_use]
extern crate clap;

use std::path::PathBuf;
use std::env;
use clap::Shell;

#[path="src/cli.rs"]
mod cli;

fn main() {
    let mut cli = cli::generate();
    let mut out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    out_dir.pop();
    out_dir.pop();
    out_dir.pop();

    cli.gen_completions("super", Shell::Bash, &out_dir);
    cli.gen_completions("super", Shell::Fish, &out_dir);
    cli.gen_completions("super", Shell::Zsh, out_dir);
}
