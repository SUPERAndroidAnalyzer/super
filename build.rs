#[macro_use]
extern crate clap;

use clap::Shell;
use std::env;
use std::path::PathBuf;

#[path = "src/cli.rs"]
mod cli;

fn main() {
    let mut cli = cli::generate();
    let mut out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR variable was not set"));
    //panic!("OUT_DIR: `{}`", out_dir.display());
    //out_dir.pop();
    //out_dir.pop();
    //out_dir.pop();

    cli.gen_completions("super", Shell::Bash, &out_dir);
    cli.gen_completions("super", Shell::Fish, &out_dir);
    cli.gen_completions("super", Shell::Zsh, out_dir);
}
