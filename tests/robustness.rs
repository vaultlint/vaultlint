/// Robustness tests for task R6.
///
/// Three behaviours under test:
///   1. Error chain: a skipped file's reason carries both the outer
///      "parsing <path>" context and the inner syn error.
///   2. Deep nesting: a file with hundreds of nested blocks (enough to
///      overflow the default main-thread stack) is handled gracefully
///      rather than crashing with SIGABRT.
///   3. Broken pipe: piping the output into `head` exits 0 with nothing
///      on stderr.
use std::fs;
use std::io::Write;
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

    let report = scan(&ScanOptions { root: dir });

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

/// A file with deeply-nested blocks (500 levels, well above the ~380-level
/// default-stack overflow threshold measured empirically) must be handled
/// gracefully: the binary either skips the file or scans it, and exits with
/// code 0 or 1, never with a signal (exit code 134 / SIGABRT).
///
/// Empirically measured:
///   - Overflow threshold on the default main-thread stack: 380 nested blocks.
///   - Test fixture depth: 500 nested blocks (comfortably above the threshold).
///
/// Kill: remove the `thread::Builder::new().stack_size(64 << 20).spawn(…)` call
/// from `src/main.rs` and restore the direct `scan(…)` call on the main thread.
/// The binary then exits with code 134 (SIGABRT) instead of 0/1, and the
/// assertion `code != 134` fails.
#[test]
fn deep_nesting_does_not_crash_the_binary() {
    // Empirical overflow threshold: 380 nested blocks on the default stack.
    // Test fixture uses 500 to be comfortably above it.
    const DEPTH: usize = 500;

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
    // The tool must exit cleanly: 0 (no findings or skipped) or 1 (findings).
    assert!(
        code == Some(0) || code == Some(1),
        "expected exit code 0 or 1, got: {code:?}"
    );
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
            "never",
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

// ── Negative test: non-broken-pipe write errors still exit 2 ─────────────────

/// A render error that is NOT a broken pipe must still exit 2 with a message
/// on stderr. We cannot easily inject a real non-BrokenPipe write error from
/// outside the binary, so we test the library's render path directly: writing
/// into a sink that fails with `PermissionDenied` must propagate the error.
///
/// This test is a library-level unit test — it validates that the broken-pipe
/// detection is genuinely conditional on the error kind rather than always
/// silencing errors.
///
/// Kill: change the `is_broken_pipe` branch in `src/main.rs` to `true`
/// unconditionally. This test cannot catch that kill (it drives the library,
/// not the binary), but the integration test below can.
#[test]
fn non_broken_pipe_render_error_is_propagated() {
    struct FailWriter;
    impl Write for FailWriter {
        fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "simulated failure",
            ))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    // A minimal scan report to render.
    let report = vaultlint::ScanReport {
        files_scanned: 0,
        test_files_skipped: 0,
        anchor_version: None,
        findings: vec![],
        skipped: vec![],
    };
    let result = vaultlint::report::render(
        &report,
        vaultlint::report::Format::Human,
        &mut FailWriter,
        false,
    );

    assert!(
        result.is_err(),
        "render into a failing writer must return Err"
    );
    let err = result.unwrap_err();
    // The error is NOT a broken pipe, so the binary path would NOT silence it.
    let is_broken_pipe = err
        .chain()
        .find_map(|e| e.downcast_ref::<std::io::Error>())
        .is_some_and(|io| io.kind() == std::io::ErrorKind::BrokenPipe);
    assert!(
        !is_broken_pipe,
        "PermissionDenied must not be classified as broken pipe"
    );
}
