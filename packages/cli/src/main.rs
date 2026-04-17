use std::process::ExitCode;

use clap::Parser;
use sshenv_cli_models::Cli;

fn main() -> ExitCode {
    let cli = Cli::parse();
    match sshenv::run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err}");
            let mut source = err.source();
            while let Some(e) = source {
                eprintln!("  caused by: {e}");
                source = e.source();
            }
            ExitCode::FAILURE
        }
    }
}
