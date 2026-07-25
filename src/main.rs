use std::io::IsTerminal;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};

use vaultlint::report::{self, FailOn};
use vaultlint::{scan, ScanOptions};

#[derive(Parser)]
#[command(
    name = "vaultlint",
    version,
    about = "Security linter for Solana and Anchor programs"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Scan a directory of Rust/Anchor sources
    Scan {
        /// Path to scan, e.g. ./programs
        path: PathBuf,
        #[arg(long, value_enum, default_value_t = FailOnArg::High)]
        fail_on: FailOnArg,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum FailOnArg {
    High,
    Medium,
    Low,
    Never,
}

impl From<FailOnArg> for FailOn {
    fn from(value: FailOnArg) -> Self {
        match value {
            FailOnArg::High => FailOn::High,
            FailOnArg::Medium => FailOn::Medium,
            FailOnArg::Low => FailOn::Low,
            FailOnArg::Never => FailOn::Never,
        }
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let Command::Scan { path, fail_on } = cli.command;

    if !path.exists() {
        eprintln!("error: path does not exist: {}", path.display());
        return ExitCode::from(2);
    }

    let report_data = scan(&ScanOptions { root: path });
    let colour = std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none();

    let mut stdout = std::io::stdout().lock();
    if let Err(error) = report::human::render(&report_data, &mut stdout, colour) {
        eprintln!("error: writing report: {error}");
        return ExitCode::from(2);
    }

    ExitCode::from(report::exit_code(&report_data, fail_on.into()) as u8)
}
