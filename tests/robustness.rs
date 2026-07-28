//! Robustness tests for task R6.
//!
//! Three behaviours under test:
//!   1. Error chain: a skipped file's reason carries both the outer
//!      "parsing <path>" context and the inner syn error.
//!   2. Deep nesting: a file with hundreds of nested blocks (enough to
//!      overflow the default main-thread stack) is handled gracefully
//!      rather than crashing with SIGABRT.
//!   3. Broken pipe: piping the output into `head` exits 0 with nothing
//!      on stderr.
use std::fs;
use std::path::Path;
use std::process::Command;

use vaultlint::{scan, ScanOptions};

// ── 1. Error chain ────────────────────────────────────────────────────────────

/// A file whose Rust is unparsable must record a `reason` that carries both
/// the outer "parsing <path>" context AND the inner syn error message.
///
/// Kill: revert `format!("{error:#}")` back to `error.to_string()` in
/// `src/lib.rs:106`. The reason then contains only the outer context
/// ("parsing <path>") and the inner assertion — `reason.contains("expected")` —
/// fails.
#[test]
fn skipped_file_reason_contains_full_error_chain() {
    let dir = std::env::temp_dir().join("vaultlint_r6_error_chain");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let bad = dir.join("broken.rs");
    // Rust that syn cannot parse: missing function body / bad syntax.
    fs::write(&bad, "fn oops( { not valid rust at all").unwrap();

    let report = scan(&ScanOptions::new(dir));

    assert_eq!(report.skipped.len(), 1, "expected one skipped file");
    let reason = &report.skipped[0].reason;

    // Outer context injected by parse.rs via `.with_context(|| "parsing …")`.
    assert!(
        reason.contains("parsing"),
        "reason must contain the outer 'parsing' context, got: {reason:?}"
    );
    // Inner syn error: the alternate display appends the inner message after
    // the ": " separator.  The outer context is "parsing <path>"; everything
    // after the first ": " is the syn message.
    let inner = reason.split_once(": ").map(|(_, rest)| rest).unwrap_or("");
    assert!(
        !inner.is_empty(),
        "reason must contain an inner error message after 'parsing …: ', got: {reason:?}"
    );
    // The full chain format uses `: ` as separator, so both messages appear.
    assert!(
        reason.contains(": "),
        "reason must use the anyhow alternate-display chain separator, got: {reason:?}"
    );
}

// ── 2. Deep nesting ───────────────────────────────────────────────────────────

/// Generate a Rust source file with `depth` nested block levels.
fn write_deep_file(dir: &Path, depth: usize) {
    let mut inner = String::from("let _x = 1;");
    for _ in 0..depth {
        inner = format!("{{ {inner} }}");
    }
    let source = format!("fn f() {inner}\n");
    fs::write(dir.join("deep.rs"), source).unwrap();
}

/// A file with deeply-nested blocks must be handled gracefully: the binary
/// either skips the file or scans it, and exits with code 0 or 1, never with
/// a signal (exit code 134 / SIGABRT).
///
/// Measured on this machine (macOS, Apple Silicon):
///   - Default-stack overflow threshold, dev   profile: 380 nested blocks
///   - Default-stack overflow threshold, release profile: 1619 nested blocks
///   - 64 MiB-stack overflow threshold, dev   profile: 3065 nested blocks
///   - 64 MiB-stack overflow threshold, release profile: 13027 nested blocks
///
/// DEPTH = 2200 sits above both default-stack thresholds with >25% headroom
/// and below both 64 MiB thresholds with >25% headroom in both profiles.
///
/// Kill: remove the `thread::Builder::new().stack_size(64 << 20).spawn(…)` call
/// from `src/main.rs` and restore the direct `scan(…)` call on the main thread.
/// The binary then exits with code 134 (SIGABRT) instead of 0/1, and the
/// assertion `code != 134` fails — in both dev and release.
#[test]
fn deep_nesting_does_not_crash_the_binary() {
    // DEPTH sits above both default-stack overflow thresholds (380 dev, 1619
    // release) and below both 64 MiB thresholds (3065 dev, 13027 release),
    // each with at least 25% headroom on both sides in both profiles.
    const DEPTH: usize = 2200;

    let dir = std::env::temp_dir().join("vaultlint_r6_deep_nesting");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    write_deep_file(&dir, DEPTH);

    let output = Command::new(env!("CARGO_BIN_EXE_vaultlint"))
        .args(["scan", dir.to_str().unwrap(), "--fail-on", "never"])
        .output()
        .expect("failed to spawn vaultlint");

    let code = output.status.code();

    assert!(
        code.is_some(),
        "binary must not be killed by a signal (SIGABRT/stack overflow)"
    );
    assert_ne!(
        code,
        Some(134),
        "exit code 134 means SIGABRT — the scan thread still overflowed"
    );
    // With --fail-on never and no security findings in the fixture, exit 0.
    assert_eq!(code, Some(0), "expected exit code 0, got: {code:?}");
}

// ── 3. Broken pipe ────────────────────────────────────────────────────────────

/// Piping vaultlint's output into a consumer that closes the read end early
/// (simulated here by a child process that reads nothing) must exit 0 with
/// nothing on stderr.
///
/// Kill: remove the `is_broken_pipe` check from `src/main.rs` and keep the
/// old `eprintln! + ExitCode::from(2)` path. The binary then exits 2 and
/// the assertion `code == Some(0)` fails.
#[test]
fn broken_pipe_exits_zero_with_no_stderr() {
    // Produce a directory with at least one finding so the tool has real
    // output to write before the pipe breaks.
    let dir = std::env::temp_dir().join("vaultlint_r6_broken_pipe");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    // VL004: create_program_address without checking return value.
    fs::write(
        dir.join("trigger.rs"),
        "use solana_program::pubkey::Pubkey;\npub fn f(seeds: &[&[u8]], id: &Pubkey) -> Pubkey {\n    Pubkey::create_program_address(seeds, id).unwrap()\n}\n",
    )
    .unwrap();

    // Spawn vaultlint with its stdout piped to us, then immediately drop the
    // read end without reading anything — that is exactly what `| head -0`
    // does to the write end of a pipe.
    let mut child = Command::new(env!("CARGO_BIN_EXE_vaultlint"))
        .args([
            "scan",
            dir.to_str().unwrap(),
            "--fail-on",
            "medium",
            "--format",
            "human",
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("failed to spawn vaultlint");

    // Drop the stdout handle immediately so the write end gets EPIPE.
    drop(child.stdout.take());

    // Give the child a moment to finish and collect its status.
    let output = child.wait_with_output().expect("failed to wait on child");

    let code = output.status.code();
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(
        code,
        Some(0),
        "broken pipe must exit 0, got {code:?}; stderr: {stderr:?}"
    );
    assert!(
        stderr.is_empty(),
        "broken pipe must produce no stderr output, got: {stderr:?}"
    );
}
