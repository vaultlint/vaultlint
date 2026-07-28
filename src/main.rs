use std::io::{IsTerminal, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};

use vaultlint::report::{self, FailOn, Format};
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
        #[arg(long, value_enum, default_value_t = FormatArg::Human)]
        format: FormatArg,
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

#[derive(Clone, Copy, ValueEnum)]
enum FormatArg {
    Human,
    Json,
    Sarif,
}

impl From<FormatArg> for Format {
    fn from(value: FormatArg) -> Self {
        match value {
            FormatArg::Human => Format::Human,
            FormatArg::Json => Format::Json,
            FormatArg::Sarif => Format::Sarif,
        }
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let Command::Scan {
        path,
        fail_on,
        format,
    } = cli.command;

    if !path.exists() {
        eprintln!("error: path does not exist: {}", path.display());
        return ExitCode::from(2);
    }

    // Run the scan on a thread with a large stack so that deeply nested
    // Rust code (e.g. generated code with hundreds of nested blocks) does
    // not overflow the default main-thread stack.
    // proc-macro2's SOURCE_MAP is thread-local, so span resolution must happen
    // inside this thread — do not call span.start() after join().
    let scan_thread = std::thread::Builder::new()
        .name("vaultlint-scan".into())
        .stack_size(64 << 20) // 64 MiB
        .spawn(move || scan(&ScanOptions::new(path)));

    let report_data = match scan_thread {
        Err(e) => {
            eprintln!("error: could not spawn scan thread: {e}");
            return ExitCode::from(2);
        }
        Ok(handle) => match handle.join() {
            Ok(report) => report,
            Err(_) => {
                eprintln!("error: scan thread panicked");
                return ExitCode::from(2);
            }
        },
    };

    let colour = std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none();

    let mut stdout = std::io::stdout().lock();
    if let Err(error) = report::render(&report_data, format.into(), &mut stdout, colour) {
        // A broken pipe (e.g. `vaultlint scan . | head`) is not a tool error.
        // Exit 0 and print nothing; the truncated output cannot carry a
        // trustworthy pass/fail signal anyway.
        if error.kind() == std::io::ErrorKind::BrokenPipe {
            let _ = stdout.flush();
            return ExitCode::SUCCESS;
        }

        eprintln!("error: writing report: {error}");
        return ExitCode::from(2);
    }

    ExitCode::from(report::exit_code(&report_data, fail_on.into()) as u8)
}

// The serde_json::to_writer_pretty(...).map_err(std::io::Error::from) conversion
// in json.rs and sarif.rs is load-bearing: serde_json::Error does not expose its
// inner io::Error via source(), so without this conversion a broken pipe never
// reaches the kind() == BrokenPipe check in main() and `vaultlint scan . | head`
// exits 2 instead of 0.
#[cfg(test)]
mod tests {
    #[test]
    fn serde_json_broken_pipe_propagates_as_io_error() {
        struct BrokenPipeWriter;
        impl std::io::Write for BrokenPipeWriter {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let result = serde_json::to_writer_pretty(&mut BrokenPipeWriter, &serde_json::json!(1))
            .map_err(std::io::Error::from);
        let err = result.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::BrokenPipe);
    }
}
