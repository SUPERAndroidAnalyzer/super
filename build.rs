#[macro_use]
extern crate clap;

use std::path::PathBuf;
use clap::Shell;

#[path="src/cli.rs"]
mod cli;

fn main() {
    let mut cli = cli::generate_cli();
    let mut out_dir = PathBuf::from(env!("OUT_DIR"));
    out_dir.pop();
    out_dir.pop();
    out_dir.pop();

    cli.gen_completions("super", Shell::Bash, &out_dir);
    cli.gen_completions("super", Shell::Fish, out_dir);
    // ZSH completion script generation is blocked by:
    // https://github.com/kbknapp/clap-rs/issues/754
    // cli.gen_completions("super", Shell::Zsh, out_dir);
}
