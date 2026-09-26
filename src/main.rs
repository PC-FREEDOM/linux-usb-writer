mod device;
mod execution;
mod identity;
mod image_source;
mod linux_backend;
mod linux_monitor;
mod safety;
mod writer;

use device::SnapshotFetchOutcome;
use execution::{core, linux_access, write_job};
use identity::{compare_identity, compare_instance, IdentityComparison, InstanceComparison};
use linux_backend::{collect_device_snapshot, collect_device_snapshots};
use linux_monitor::{start_monitoring, DeviceEvent};
use safety::assess_device;
use std::io::Write as _;

fn main() -> zbus::Result<()> {
    let mut args = std::env::args().skip(1);

    match args.next().as_deref() {
        Some("monitor") => return run_monitor(),
        Some("select") => {
            let Some(target) = args.next() else {
                eprintln!("usage: cargo run -- select <udisks2-block-object-path>");
                return Ok(());
            };

            return run_select(target);
        }
        Some("open-test") => {
            let Some(target) = args.next() else {
                eprintln!("usage: cargo run -- open-test <udisks2-block-object-path>");
                return Ok(());
            };

            return run_open_test(target);
        }
        Some("prepare-test") => {
            let Some(target) = args.next() else {
                eprintln!("usage: cargo run -- prepare-test <udisks2-block-object-path>");
                return Ok(());
            };

            return run_prepare_test(target);
        }
        Some("write-test") => {
            const USAGE: &str =
                "usage: cargo run -- write-test <image-path> <udisks2-block-object-path> [verify-mode] [--test-pause-before-verify]\n\
                 verify-mode: none (default) | quick | full\n\
                 --test-pause-before-verify: TEST-ONLY diagnostic option (not for normal use).\n\
                 Pauses after write+sync, before Verify fetches a fresh device snapshot, so a\n\
                 child partition can be mounted manually in another terminal -- see this flag's\n\
                 own doc comment on `pause_before_verify_for_test` for the full rationale.\n\
                 Requires verify-mode quick or full.";

            let Some(image_path) = args.next() else {
                eprintln!("{USAGE}");
                return Ok(());
            };
            let Some(target) = args.next() else {
                eprintln!("{USAGE}");
                return Ok(());
            };

            let verify_mode_arg = args.next();
            let fourth_arg = args.next();

            let (verify_mode, test_pause_before_verify) = match parse_write_test_trailing_args(
                verify_mode_arg.as_deref(),
                fourth_arg.as_deref(),
            ) {
                Ok(parsed) => parsed,
                // Present but unrecognized -> a usage error with a
                // non-zero exit, never a silent fallback to `None` or to
                // any other mode.
                Err(WriteTestArgsError::InvalidVerifyMode) => {
                    let mode_str = verify_mode_arg.as_deref().unwrap_or("");
                    eprintln!(
                        "write-test: invalid verify-mode '{mode_str}' (expected: none | quick | full)"
                    );
                    eprintln!("{USAGE}");
                    std::process::exit(1);
                }
                // Same policy for the fourth token: an unrecognized value
                // is a usage error, never silently ignored.
                Err(WriteTestArgsError::UnrecognizedFourthArgument) => {
                    let arg = fourth_arg.as_deref().unwrap_or("");
                    eprintln!(
                        "write-test: unrecognized argument '{arg}' (expected: --test-pause-before-verify)"
                    );
                    eprintln!("{USAGE}");
                    std::process::exit(1);
                }
                // `--test-pause-before-verify` with `verify-mode none` is
                // rejected outright rather than silently accepted-but-
                // ineffective: `VerifyMode::None` never produces
                // `VerifyStart::Pending`, so the flag would have no
                // observable effect at all -- see this design's own
                // report (reports/latest.md) for why "specified but does
                // nothing" was deliberately ruled out.
                Err(WriteTestArgsError::TestPauseRequiresVerification) => {
                    eprintln!(
                        "write-test: --test-pause-before-verify requires verify-mode quick or full (verify-mode none never runs Verify pre-flight)"
                    );
                    eprintln!("{USAGE}");
                    std::process::exit(1);
                }
            };

            let exit = run_write_test(image_path, target, verify_mode, test_pause_before_verify)?;
            // `std::process::exit` only here, at the very top level, and only
            // after `run_write_test` has already returned normally -- every
            // FD/state cleanup it triggers has already happened via ordinary
            // Rust `Drop` by this point (see `write_test_exit_code`'s own
            // doc comment).
            if let Some(code) = write_test_exit_code(exit) {
                std::process::exit(code);
            }
            return Ok(());
        }
        Some("writer-test") => return run_writer_test(),
        _ => {}
    }

    let snapshots = collect_device_snapshots()?;

    println!("Safety assessments:");

    for snapshot in snapshots {
        let assessment = assess_device(&snapshot);

        println!();
        println!("Device:      {}", snapshot.device);
        println!("Model:       {} {}", snapshot.vendor, snapshot.model);
        println!("Size:        {} bytes", snapshot.size);
        println!("Bus:         {}", snapshot.connection_bus);
        println!("Removable:   {}", snapshot.removable);
        println!("Media avail: {}", snapshot.media_available);
        println!("Serial:      {}", snapshot.serial);
        println!("Major:minor: {}:{}", snapshot.major, snapshot.minor);
        println!("Diskseq:     {:?}", snapshot.diskseq);
        println!("Block path:  {}", snapshot.block_path);
        println!("Drive path:  {}", snapshot.drive_path);

        if snapshot.mount_points.is_empty() {
            println!("Mounts:      none");
        } else {
            println!("Mounts:");

            for mount in &snapshot.mount_points {
                println!("  {mount}");
            }
        }

        if snapshot.active_swap {
            println!("Active swap:");

            for swap in &snapshot.swap_devices {
                println!("  {swap}");
            }
        } else {
            println!("Active swap: none");
        }

        if snapshot.complex_storage {
            println!("Complex storage:");

            for detail in &snapshot.complex_storage_details {
                println!("  {detail}");
            }
        } else {
            println!("Complex storage: none");
        }

        println!("Risk:        {:?}", assessment.risk_level);
        println!("Writable:    {}", assessment.writable);
        println!("Reasons:     {:?}", assessment.reasons);

        let identity_self_check = compare_identity(&snapshot, &snapshot);
        println!("Identity self-check: {identity_self_check:?}");

        let instance_self_check = compare_instance(&snapshot, &snapshot);
        println!("Instance self-check: {instance_self_check:?}");
    }

    Ok(())
}

// PoC mode: read-only observation of UDisks2 D-Bus signals (`cargo run --
// monitor`). Prints raw structured events and, on each event, a fresh
// DeviceSnapshot re-read so diskseq changes (not carried by any signal) can
// be observed as they happen. Runs until interrupted with Ctrl+C.
fn run_monitor() -> zbus::Result<()> {
    println!("Monitoring UDisks2 D-Bus signals (read-only). Press Ctrl+C to stop.");

    let events = start_monitoring()?;

    for event in events {
        match &event {
            DeviceEvent::InterfacesAdded {
                object_path,
                interfaces,
            } => {
                println!("\n[InterfacesAdded] {object_path}");
                println!("  interfaces: {interfaces:?}");
            }
            DeviceEvent::InterfacesRemoved {
                object_path,
                interfaces,
            } => {
                println!("\n[InterfacesRemoved] {object_path}");
                println!("  interfaces: {interfaces:?}");
            }
            DeviceEvent::PropertiesChanged {
                object_path,
                interface,
                changed,
                invalidated,
            } => {
                println!("\n[PropertiesChanged] {object_path} ({interface})");

                for change in changed {
                    println!("  {} = {}", change.name, change.value);
                }

                if !invalidated.is_empty() {
                    println!("  invalidated: {invalidated:?}");
                }
            }
            DeviceEvent::WatcherFailed {
                object_path,
                reason,
            } => {
                eprintln!("\n[WatcherFailed] {object_path}: {reason}");
            }
        }

        println!("  -- current diskseq (re-fetched DeviceSnapshot) --");

        match collect_device_snapshots() {
            Ok(snapshots) => {
                for snapshot in &snapshots {
                    println!(
                        "  {} diskseq={:?} media_available={} size={}",
                        snapshot.device, snapshot.diskseq, snapshot.media_available, snapshot.size
                    );
                }
            }
            Err(error) => eprintln!("  snapshot refresh failed: {error}"),
        }
    }

    Ok(())
}

// PoC mode: Selection Continuity (`cargo run -- select <block_path>`).
// Performs one explicit selection, then watches UDisks2 signals and, on
// every event, both (a) folds the event into the SelectionState and (b)
// re-fetches just this one target and re-verifies Identity/Instance/Safety
// against it. Read-only throughout; never opens the device or writes to it.
// To demonstrate re-selection, stop this process (Ctrl+C) and run it again
// with `select` — a fresh process always starts from SelectionState::NoSelection,
// so the only way back to Selected is this explicit action, never automatic.
fn run_select(block_path: String) -> zbus::Result<()> {
    let mut state = attempt_select(&block_path);
    print_selection_state(&state);

    let events = start_monitoring()?;

    for event in events {
        state = core::apply_event(state, &event);

        if let core::SelectionState::Selected { baseline, .. } = &state {
            let outcome = collect_device_snapshot(&baseline.block_path);
            state = core::revalidate(state, outcome);
        }

        print_selection_state(&state);
    }

    Ok(())
}

fn attempt_select(block_path: &str) -> core::SelectionState {
    match collect_device_snapshot(block_path) {
        SnapshotFetchOutcome::Found(snapshot) => match core::select(snapshot) {
            Ok(state) => state,
            Err(error) => {
                eprintln!("select rejected: {error:?}");
                core::SelectionState::NoSelection
            }
        },
        SnapshotFetchOutcome::NotFound => {
            eprintln!("select failed: no such target: {block_path}");
            core::SelectionState::NoSelection
        }
        SnapshotFetchOutcome::Error(reason) => {
            eprintln!("select failed: {reason}");
            core::SelectionState::NoSelection
        }
    }
}

fn print_selection_state(state: &core::SelectionState) {
    match state {
        core::SelectionState::NoSelection => {
            println!("\n[Selection] NoSelection");
        }
        core::SelectionState::Selected {
            baseline,
            baseline_assessment,
            selection_generation,
        } => {
            println!(
                "\n[Selection] Selected  device={} risk={:?} writable={} diskseq={:?} selection_generation={:?}",
                baseline.device,
                baseline_assessment.risk_level,
                baseline_assessment.writable,
                baseline.diskseq,
                selection_generation
            );
        }
        core::SelectionState::Invalidated {
            baseline,
            baseline_assessment,
            reason,
            selection_generation,
        } => {
            println!(
                "\n[Selection] Invalidated  device={} reason={reason:?} (baseline was risk={:?} writable={}) selection_generation={:?}",
                baseline.device, baseline_assessment.risk_level, baseline_assessment.writable, selection_generation
            );
        }
    }
}

// PoC mode: OpenDevice safety check (`cargo run -- open-test <block_path>`).
// Runs the full pre-write safety pipeline up to — and only up to — holding an
// open file descriptor: select, one final targeted re-verification
// (Identity/Instance/Safety), OpenDevice, FD metadata inspection, an FD
// binding check against the just-re-verified snapshot, then close.
// No bytes are ever written, seeked-then-written, truncated, or otherwise
// modified through the returned descriptor — this function has no code path
// that could do so. If OpenDevice needs polkit authentication, this program
// does nothing but wait for the reply; it never falls back to sudo or any
// other bypass.
fn run_open_test(block_path: String) -> zbus::Result<()> {
    let mut state = attempt_select(&block_path);

    if let core::SelectionState::Selected { baseline, .. } = &state {
        let outcome = collect_device_snapshot(&baseline.block_path);
        state = core::revalidate(state, outcome);
    }

    print_selection_state(&state);

    if !core::is_ready_to_open(&state) {
        println!("\nSelection: invalid -- refusing to call OpenDevice.");
        return Ok(());
    }

    println!("\nSelection: valid");

    let core::SelectionState::Selected { baseline, .. } = &state else {
        unreachable!("is_ready_to_open just confirmed Selected");
    };

    println!(
        "Requesting OpenDevice(mode=\"rw\") on {}.",
        baseline.block_path
    );
    println!(
        "If a polkit authentication prompt appears, please complete it yourself -- \
         this program will not use sudo or any other privilege bypass."
    );

    let handle = match linux_access::open_device(
        &baseline.block_path,
        linux_access::OpenAccess::WriteExclusive,
    ) {
        Ok(handle) => handle,
        Err(error) => {
            println!("OpenDevice: failed ({error:?})");
            return Ok(());
        }
    };

    println!("OpenDevice: success");

    let metadata = handle.metadata();

    match &metadata {
        Some(meta) => {
            println!("FD major:minor: {}:{}", meta.major, meta.minor);
            println!(
                "Expected major:minor: {}:{}",
                baseline.major, baseline.minor
            );
            println!("FD size (BLKGETSIZE64): {:?}", meta.size);
            println!("Expected size: {}", baseline.size);

            if let Some(target) = &meta.proc_fd_target {
                println!("/proc/self/fd target: {target}");
            }
        }
        None => println!("FD metadata: unavailable"),
    }

    match core::check_fd_binding(baseline, metadata.as_ref()) {
        core::FdBindingCheck::Match => println!("FD binding: Match"),
        core::FdBindingCheck::Mismatch => {
            println!("FD binding: Mismatch -- would abort before any write")
        }
        core::FdBindingCheck::InsufficientInformation => {
            println!("FD binding: InsufficientInformation -- would abort before any write")
        }
    }

    println!("Write performed: NO (0 bytes)");

    linux_access::close_without_writing(handle);
    println!("FD closed: yes");

    Ok(())
}

// The image size this PoC pretends to be about to write. Never actually read
// or written — only used to exercise WritePlan validation and the
// confirmation token. 4 MiB, matching writer-test's own pattern size.
const PREPARE_TEST_IMAGE_SIZE: u64 = 4 * 1024 * 1024;

// PoC mode: Write Gate (`cargo run -- prepare-test <block_path>`). Exercises
// the full pre-write gate (Selection -> final re-verification -> WritePlan ->
// OpenDevice -> FD binding -> confirmation -> PreparedWrite) end to end.
// `writer::write()` is never called and is not reachable from this function
// — establishing a `PreparedWrite` here proves the gate passed, nothing more.
// If OpenDevice needs polkit authentication, this program does nothing but
// wait for the reply; it never falls back to sudo or any other bypass.
fn run_prepare_test(block_path: String) -> zbus::Result<()> {
    let mut state = attempt_select(&block_path);

    if let core::SelectionState::Selected { baseline, .. } = &state {
        let outcome = collect_device_snapshot(&baseline.block_path);
        state = core::revalidate(state, outcome);
    }

    print_selection_state(&state);

    if !core::is_ready_to_open(&state) {
        println!("\nprepare-test: Selection invalid -- stopping before the Write Gate.");
        return Ok(());
    }

    let core::SelectionState::Selected { baseline, .. } = &state else {
        unreachable!("is_ready_to_open just confirmed Selected");
    };

    // `image` is this PoC's stand-in for an explicit image selection (the
    // currently-nonexistent GUI would call `ImageSelection::new()` once,
    // when the user picks a file). The same `ImageSelection` value is reused
    // for both the confirmation and the later Gate call below, since this
    // PoC never re-selects a different image mid-run.
    let image = core::ImageSelection::new(PREPARE_TEST_IMAGE_SIZE);

    // This PoC never implements Verify itself (see CLAUDE.md/reports) --
    // `VerifyMode::None` here only means "no verify policy was chosen yet",
    // not that a future GUI must default to it.
    let verify_mode = core::VerifyMode::None;

    // `WriteIntent::from_selection` pulls `baseline` and `selection_generation`
    // out of the same `state` value -- there is no way to build one from a
    // mismatched pairing of the two. This is what the — currently
    // nonexistent — GUI would call once, at the moment the user confirms.
    let intent = match core::WriteIntent::from_selection(&state, image, verify_mode) {
        Ok(intent) => intent,
        Err(error) => {
            println!("prepare-test: WriteIntent construction rejected: {error:?}");
            return Ok(());
        }
    };
    let confirmation = core::ConfirmationToken::confirm(intent);
    println!(
        "\nprepare-test: confirmation created for {} (image_size={} bytes, verify_mode={:?})",
        confirmation.intent().target_block_path(),
        confirmation.intent().image_size(),
        confirmation.intent().verify_mode()
    );

    let refreshed_for_gate = collect_device_snapshot(&baseline.block_path);

    let ready = match core::prepare_for_open(
        &state,
        refreshed_for_gate,
        image,
        verify_mode,
        Some(&confirmation),
    ) {
        Ok(ready) => ready,
        Err(error) => {
            println!("prepare-test: Write Gate rejected before OpenDevice: {error:?}");
            return Ok(());
        }
    };

    println!(
        "prepare-test: Write Gate (pre-open) passed. WritePlan: image_size={} target_size={} chunk_size={}",
        ready.plan().image_size, ready.plan().target_size, ready.plan().chunk_size
    );

    println!(
        "prepare-test: requesting OpenDevice(mode=\"rw\") on {}.",
        ready.current().block_path
    );
    println!(
        "If a polkit authentication prompt appears, please complete it yourself -- \
         this program will not use sudo or any other privilege bypass."
    );

    let open_result = linux_access::open_device(
        &ready.current().block_path,
        linux_access::OpenAccess::WriteExclusive,
    );

    // Metadata must be read from the handle (a genuine, if tiny, bit of
    // Linux I/O -- fstat/ioctl) *before* the handle's ownership moves into
    // `finalize_prepared_write`, since that function must never call
    // `.metadata()` itself (core.rs stays free of Linux I/O calls; it only
    // ever receives already-collected data plus an opaque value to move).
    let (handle_opt, metadata) = match open_result {
        Ok(handle) => {
            println!("prepare-test: OpenDevice: success");
            let metadata = handle.metadata();
            (Some(handle), metadata)
        }
        Err(error) => {
            println!("prepare-test: OpenDevice: failed ({error:?})");
            (None, None)
        }
    };

    if let Some(meta) = &metadata {
        println!(
            "prepare-test: FD major:minor={}:{} size={:?}",
            meta.major, meta.minor, meta.size
        );
    }

    // `handle_opt` moves into `finalize_prepared_write` here. On success, the
    // returned `PreparedWrite` is now the sole owner of that handle -- this
    // function never sees it again. On rejection, the handle was already
    // dropped (closed via RAII) inside `finalize_prepared_write` itself, so
    // there is nothing left here to close explicitly either way.
    match core::finalize_prepared_write(ready, handle_opt, metadata.as_ref()) {
        Ok(prepared) => {
            println!(
                "prepare-test: PreparedWrite established for {} (target_size={} image_size={})",
                prepared.target_block_path, prepared.target_size, prepared.image_size
            );
            println!(
                "prepare-test: WRITE NOT PERFORMED (writer::write() is not called by this PoC)"
            );

            // Demonstrate the next ownership stage: PreparedWrite -> AuthorizedWrite.
            // `begin()` consumes `prepared` by value -- the fd moves once,
            // with no dup()/try_clone(), into the new AuthorizedWrite, which
            // also now bundles the exact WritePlan/VerifyMode the Gate
            // verified. `prepared` cannot be referred to again after this
            // line; the compiler enforces that, not a runtime check. Fields
            // are captured beforehand since AuthorizedWrite exposes none of
            // them publicly -- only `write_job::start()` (via the
            // crate-private `into_parts()`) is meant to take it apart.
            let target_block_path = prepared.target_block_path.clone();
            let target_size = prepared.target_size;
            let image_size = prepared.image_size;

            let authorized = prepared.begin();
            println!(
                "prepare-test: WRITE SESSION AUTHORIZED for {target_block_path} (target_size={target_size} image_size={image_size} verify_mode={verify_mode:?})"
            );
            println!(
                "prepare-test: WRITE NOT PERFORMED (AuthorizedWrite is not connected to write_job::start() by this PoC)"
            );

            drop(authorized);
            println!("prepare-test: AuthorizedWrite dropped -- FD closed via RAII");
        }
        Err(error) => {
            println!("prepare-test: Write Gate rejected after OpenDevice: {error:?}");
            println!("prepare-test: FD (if any was opened) was already closed via RAII inside the Write Gate");
        }
    }

    Ok(())
}

// Simple, dependency-free human-readable size formatting for the Pre-write
// Safety Summary in `run_write_test` below -- not a general-purpose
// formatting utility, just enough to show e.g. "8000000000 bytes
// (7.45 GiB)" without adding a crate for it.
fn format_size(bytes: u64) -> String {
    const MIB: f64 = 1024.0 * 1024.0;
    const GIB: f64 = MIB * 1024.0;

    let bytes_f = bytes as f64;

    if bytes_f >= GIB {
        format!("{bytes} bytes ({:.2} GiB)", bytes_f / GIB)
    } else if bytes_f >= MIB {
        format!("{bytes} bytes ({:.2} MiB)", bytes_f / MIB)
    } else {
        format!("{bytes} bytes")
    }
}

// Pure comparison used by the Human Confirmation prompt in `run_write_test`
// below: the operator's raw input line, trimmed, must equal the target's
// `/dev` node string exactly -- case-sensitive, no partial/prefix match, no
// "y"/"yes" shortcut. Kept as its own small function (rather than inlined)
// purely so it can be unit tested without stdin or a real device.
fn confirmation_matches(input: &str, expected_device: &str) -> bool {
    input.trim() == expected_device
}

// How often `wait_for_prompt_input` re-checks for cancellation while no
// input has arrived yet. Bounds how long a Ctrl+C during the Human
// Confirmation prompt can go unnoticed; small enough to feel immediate,
// large enough that the idle wait costs nothing measurable.
const PROMPT_CANCEL_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(100);

// The result of waiting for one line of prompt input while also watching for
// cancellation. `Line`/`Eof`/`Error` are exactly what a plain
// `stdin().read_line()` could report (`Ok(n > 0)`/`Ok(0)`/`Err`); `Cancelled`
// is the one outcome a blocking `read_line()` on the main thread could never
// produce here -- `ctrlc` installs its SIGINT handler with `SA_RESTART`, so
// the kernel silently restarts an in-progress `read()` after Ctrl+C instead
// of interrupting it (see reports/latest.md's D3 technical verification).
#[derive(Debug)]
enum PromptInput {
    Line(String),
    Eof,
    Error(std::io::Error),
    Cancelled,
}

// Starts a dedicated thread that performs exactly one blocking
// `stdin().read_line()` and sends its result back over the returned
// channel. The thread never observes cancellation itself -- it is simply
// left blocked in `read_line()` if the caller stops waiting (see
// `wait_for_prompt_input`); on that path the caller returns
// `WriteTestExit::Cancelled`, and `main()`'s top-level `std::process::exit`
// then ends the process, reader thread included. Stdin is never read again
// by anything else after a cancellation, so the abandoned thread's stdin
// lock can never block other code. A thread-spawn failure is returned to
// the caller rather than panicking.
fn spawn_prompt_reader() -> std::io::Result<std::sync::mpsc::Receiver<PromptInput>> {
    let (sender, receiver) = std::sync::mpsc::channel();

    std::thread::Builder::new()
        .name("prompt-reader".into())
        .spawn(move || {
            let mut line = String::new();
            let input = match std::io::stdin().read_line(&mut line) {
                Ok(0) => PromptInput::Eof,
                Ok(_) => PromptInput::Line(line),
                Err(error) => PromptInput::Error(error),
            };
            // The receiver may already be gone (the caller stopped waiting
            // because of a cancellation); nothing more to do in that case.
            let _ = sender.send(input);
        })?;

    Ok(receiver)
}

// Waits for the prompt reader's result while checking `is_cancelled` before
// every wait and after every received input. Cancellation always wins: an
// input that arrives at (nearly) the same moment as a Ctrl+C is discarded in
// favor of `Cancelled`, so a correctly typed confirmation can never carry a
// run past a cancellation that was already requested. Takes the receiver
// and the cancellation check as parameters (not `stdin`/`CancelHandle`
// directly) so every branch is unit-testable without a terminal. A
// disconnected channel without a result (the reader thread died without
// sending) is reported as `Error`, never as a confirmation.
fn wait_for_prompt_input(
    receiver: &std::sync::mpsc::Receiver<PromptInput>,
    is_cancelled: impl Fn() -> bool,
    poll_interval: std::time::Duration,
) -> PromptInput {
    loop {
        if is_cancelled() {
            return PromptInput::Cancelled;
        }

        match receiver.recv_timeout(poll_interval) {
            Ok(input) => {
                if is_cancelled() {
                    return PromptInput::Cancelled;
                }
                return input;
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                if is_cancelled() {
                    return PromptInput::Cancelled;
                }
                return PromptInput::Error(std::io::Error::other(
                    "prompt reader ended without reporting a result",
                ));
            }
        }
    }
}

// How a unit of blocking work handed to `run_off_main_thread` ended.
// `NotStarted` hands the input back untouched (the worker thread could not
// be created, so the work never began), letting the caller decide how to
// proceed without having lost the value.
#[derive(Debug)]
enum OffMainThread<T, R> {
    Finished(R),
    Panicked,
    NotStarted(T, std::io::Error),
}

// Runs `work(input)` on a dedicated, scoped worker thread and blocks the
// calling (main) thread in `join()` until it finishes. Exists for
// `Syncing::sync()`: `fsync()` on a block device keeps the calling thread
// in uninterruptible sleep, and the kernel delivers a terminal SIGINT to the
// main thread first -- so when the main thread itself was in `fsync()`,
// ctrlc's OS-level handler only ran once `fsync()` returned, and the
// `request_cancel()` its dispatch thread performs could lose the race
// against the post-sync cancel check (see reports/latest.md). Waiting in
// `join()` instead is an interruptible wait, so a Ctrl+C during sync is
// handled while sync is still running. This narrows the window to a
// Ctrl+C landing at (nearly) the same moment sync completes; it does not
// make that residual race impossible.
//
// The work itself is never interrupted: `join()` always waits for it to
// finish. A panic inside `work` is reported as `Panicked` rather than
// propagated into the main thread; the input was consumed by the worker in
// that case (its destructors ran there during unwinding).
fn run_off_main_thread<T: Send, R: Send>(
    input: T,
    work: impl FnOnce(T) -> R + Send,
) -> OffMainThread<T, R> {
    let mut slot = Some(input);
    let slot_ref = &mut slot;

    let joined = std::thread::scope(|scope| {
        std::thread::Builder::new()
            .name("sync-worker".into())
            .spawn_scoped(scope, move || {
                let input = slot_ref
                    .take()
                    .expect("worker input is present until the worker takes it");
                work(input)
            })
            .map(|handle| handle.join())
    });

    match joined {
        Ok(Ok(result)) => OffMainThread::Finished(result),
        Ok(Err(_panic_payload)) => OffMainThread::Panicked,
        Err(spawn_error) => match slot.take() {
            Some(input) => OffMainThread::NotStarted(input, spawn_error),
            None => OffMainThread::Panicked,
        },
    }
}

// What `run_write_test` does right after sync reported success: stop as
// `Cancelled` if a cancellation was requested (sync has already finished,
// so the full image is on the target and only verification is skipped), or
// `None` to continue into Verify. Deliberately only for the success path:
// a sync failure is always reported as that failure, never masked by a
// cancellation that happened at the same time.
fn exit_after_successful_sync(cancel_requested: bool) -> Option<WriteTestExit> {
    if cancel_requested {
        Some(WriteTestExit::Cancelled)
    } else {
        None
    }
}

// How `run_write_test` finished, for `main()` to turn into a process exit
// code -- see `write_test_exit_code` below. Deliberately not richer than
// this (no byte counts, no phase): every message a human needs has already
// been printed by `run_write_test` itself by the time this is returned;
// this exists only to answer the one question `main()` still needs
// answered afterward -- "did the user cancel this run?"
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WriteTestExit {
    Completed,
    Cancelled,
}

// Pure: no I/O, no `std::process::exit` -- `main()` is the only place that
// actually calls `std::process::exit`, and only after `run_write_test` has
// already returned normally (see the `write-test` dispatch in `main()`),
// so every FD/state cleanup `run_write_test` triggers via ordinary Rust
// `Drop` has already happened by the time this decision is acted on. `None`
// means "let `main` return `Ok(())` and exit 0 the ordinary way"; `Some`
// carries the exit code `main` should pass to `std::process::exit` instead.
// 130 (128 + SIGINT) is the conventional Unix exit code for a
// signal-interrupted process, distinguishing a deliberate user cancellation
// from both success (0) and a genuine error (1, `zbus::Result`'s own
// `Err` path).
fn write_test_exit_code(exit: WriteTestExit) -> Option<i32> {
    match exit {
        WriteTestExit::Completed => None,
        WriteTestExit::Cancelled => Some(130),
    }
}

// Installs the process-wide Ctrl+C (SIGINT) handler that lets a user
// actually cancel an in-progress `write-test` image preparation, Human
// Confirmation prompt, write, or Verify -- the
// missing "last mile" identified by the v0.1 audit: `write_job::CancelHandle`
// itself, and every write/Verify loop's use of it, already existed and were
// already unit-tested; nothing anywhere in this crate could ever trigger
// `request_cancel()` from a real user action until this function existed.
//
// The handler does exactly one thing: `cancel.request_cancel(UserRequested)`.
// Nothing else runs inside it -- no `println!`/`eprintln!`, no allocation
// beyond what capturing `cancel` itself already required, no D-Bus call, no
// file or USB I/O, no `std::process::exit`, no panic, no lock, no shell
// command, no sleep. `ctrlc` (unlike a hand-rolled `libc`/`nix` `sigaction`)
// runs this closure outside the raw OS signal context (on its own internal
// dispatch thread), which is what makes it safe to call ordinary, non-
// `async-signal-safe` Rust code such as `request_cancel()` (an `AtomicU8`
// store) here at all -- see reports/latest.md's "Cancel機能 Ctrl+C実配線 設計"
// for the fuller comparison against `signal-hook`/raw `libc` that led to
// this choice.
//
// Deliberately a small, named function rather than an inline closure at the
// call site: this is the one and only place in this crate that touches
// `ctrlc` at all, so isolating it here keeps that fact easy to audit.
//
// Because the handler only ever sets a flag, it cannot by itself end a
// blocking read: `ctrlc` registers with `SA_RESTART`, so a `read_line()`
// in progress on the main thread simply resumes after Ctrl+C. The Human
// Confirmation prompt therefore reads stdin on a separate thread and polls
// this flag instead (`spawn_prompt_reader`/`wait_for_prompt_input`), which
// keeps this closure a one-liner and keeps `std::process::exit` confined to
// `main()`. The `--test-pause-before-verify` prompt deliberately still
// blocks on the main thread (known limitation of that test-only mode).
fn install_cancel_handler(cancel: write_job::CancelHandle) -> Result<(), ctrlc::Error> {
    ctrlc::set_handler(move || {
        cancel.request_cancel(write_job::CancelReason::UserRequested);
    })
}

// TEST-ONLY diagnostic pause, enabled only by the explicit
// `--test-pause-before-verify` CLI flag (see the `write-test` dispatch in
// `main()`). Exists solely to let a real-device test manually mount a child
// partition of the target device -- in another terminal -- between write+sync
// completing and Verify fetching its fresh `DeviceSnapshot`, so the
// mount_points-allowance branch `core::verify_target_check_from_diagnostics`
// implements can actually be exercised on real hardware (see
// reports/latest.md's Mount-Allowance Real-device Test design). This is not
// a Safety bypass of any kind: every existing check (fresh snapshot fetch,
// `check_target()`'s Identity/Instance/hazard re-verification,
// `OpenDevice(mode="r")`, FD binding) still runs in full afterward, unchanged
// -- this function only delays when that sequence starts. It never touches
// the target device itself (no `udisksctl`, `mount`, or any other command is
// spawned here) -- mounting is entirely the user's own action in their own
// terminal.
//
// Blocks on `stdin`. Returns `true` only if a line was actually read (the
// user pressed Enter); `false` on EOF or an I/O error, mirroring the
// existing Human Confirmation prompt's own `Ok(0) => false` / `Err(_) =>
// false` treatment above in `run_write_test` -- the caller must never
// proceed to Verify on `false`.
fn pause_before_verify_for_test() -> bool {
    println!("write-test: TEST PAUSE (--test-pause-before-verify, test-only)");
    println!("write-test: write + sync are complete.");
    println!("write-test: the write-mode device handle is already closed.");
    println!("write-test: mount only a CHILD PARTITION of the target device in another terminal.");
    println!("write-test: do NOT mount the whole-disk device.");
    println!("write-test:   e.g. udisksctl mount -b /dev/<partition>");
    println!("write-test: after mounting, return here and press Enter to continue.");
    println!(
        "write-test: Verify will then obtain a fresh device snapshot and re-check identity, instance, and hazards."
    );
    print!("> ");
    let _ = std::io::stdout().flush();

    let mut discard = String::new();
    match std::io::stdin().read_line(&mut discard) {
        Ok(0) => false, // EOF: no input was given, never treat this as an implicit "continue".
        Ok(_) => true,
        Err(_) => false,
    }
}

// PoC mode: Production execution path wiring (`cargo run -- write-test
// <image-path> <block_path>`). This is the first CLI mode that connects the
// full, real production path in one straight line: select -> re-verify ->
// a *real* `SelectedImage` opened from `image_path` on disk (never the
// synthetic `ImageSelection::new(fixed_size)` `prepare-test` uses) ->
// WriteIntent -> confirm -> prepare_for_open -> OpenDevice -> FD binding ->
// finalize_prepared_write -> AuthorizedWrite -> AuthorizedExecution::bind()
// -> begin_write() -> WritingExecution::write() -> (on success only)
// WriteSucceeded::begin_sync().sync(). None of Selection/Identity/Instance/
// Safety/Confirmation/FD-binding is skipped -- this reuses exactly the same
// `core`/`linux_access` calls `run_prepare_test` above already exercises,
// it just does not stop at `AuthorizedWrite` and drop it.
//
// `block_path` is a UDisks2 block object path, exactly like every other CLI
// mode above (`select`/`open-test`/`prepare-test`) -- not a raw `/dev/sdX`
// string accepted with no safety checks. `image_path` is opened by
// `image_source::open_image()` exactly once; the source built from that
// open file (a `FileImageSource` for a raw image, a `CompressedImageSource`
// for a validated gzip or xz image) becomes the `SelectedImage` (`selected_image`
// below), held by this one variable, unchanged, from that point until it is
// moved into `AuthorizedExecution::bind()` -- it is never re-opened, never
// reconstructed, and no second source/`SelectedImage` is ever created for
// the same invocation.
//
// Still a linear CLI PoC, not a Controller: every step happens in this one
// function, exactly like `run_prepare_test`. If OpenDevice needs polkit
// authentication, this program does nothing but wait for the reply; it
// never falls back to sudo or any other bypass.
//
// Before reaching OpenDevice, this function also runs a Human Confirmation
// step (see below): a Pre-write Safety Summary, a destructive-write warning,
// and a prompt requiring the operator to type the target's `/dev` node
// exactly. This is a second, independent layer on top of (not a
// replacement for) `core::ConfirmationToken` -- the internal token still
// exists and is still built and checked exactly as before, just after this
// human step instead of before it. Everything that already re-verifies the
// target immediately before OpenDevice (`collect_device_snapshot` +
// `prepare_for_open`'s Identity/Instance/Safety re-check) is unchanged and,
// as a consequence of where the human prompt is placed, now runs *after*
// whatever time the operator took to read the summary and type the
// confirmation -- not before it.
fn run_write_test(
    image_path: String,
    block_path: String,
    verify_mode: core::VerifyMode,
    test_pause_before_verify: bool,
) -> zbus::Result<WriteTestExit> {
    let mut state = attempt_select(&block_path);

    if let core::SelectionState::Selected { baseline, .. } = &state {
        let outcome = collect_device_snapshot(&baseline.block_path);
        state = core::revalidate(state, outcome);
    }

    print_selection_state(&state);

    if !core::is_ready_to_open(&state) {
        println!("\nwrite-test: Selection invalid -- stopping before the Write Gate.");
        return Ok(WriteTestExit::Completed);
    }

    // What a compressed image's Preflight needs from the target, read now:
    // `state` itself is re-verified after Preflight (below), so no borrow of
    // it is held across the image preparation.
    let (target_capacity, target_block_path) = match &state {
        core::SelectionState::Selected { baseline, .. } => {
            (baseline.size, baseline.block_path.clone())
        }
        _ => unreachable!("is_ready_to_open just confirmed Selected"),
    };

    // Cancel wiring (Ctrl+C -> CancelHandle): one shared handle, created and
    // wired to Ctrl+C as soon as target selection has succeeded -- before
    // the image is opened, so image preparation (including a compressed image's
    // Preflight, which receives a `|| cancel.is_requested()` closure rather
    // than the handle itself) is covered. Ctrl+C during argument parsing or
    // device enumeration (above) keeps its ordinary "just terminate the
    // process" behavior: nothing has been opened yet at that point. The
    // same `cancel` is checked after the image is opened, watched during the
    // Human Confirmation prompt, cloned into `begin_write()`, checked again
    // after sync, and cloned into `begin_verify()` -- one Ctrl+C anywhere from here
    // through the end of Verify is honored by whichever phase happens to be
    // running. It is one-shot: there is no way to reset it, so a cancelled
    // run can never continue.
    let cancel = write_job::CancelHandle::new();

    if let Err(error) = install_cancel_handler(cancel.clone()) {
        println!("write-test: failed to install the Ctrl+C handler: {error:?}");
        println!(
            "write-test: refusing to start a destructive write without a working cancel path."
        );
        return Ok(WriteTestExit::Completed);
    }

    // The one and only place `image_path` is opened this invocation:
    // `open_image` opens it once, classifies it by content, and (for a raw
    // image) builds the `FileImageSource` from that same open file.
    // `selected_image` is what travels, as a single variable, all the way
    // to `AuthorizedExecution::bind()` below -- `selection()` (a cheap Copy)
    // is all that gets threaded through the Gate calls in between.
    //
    // Every refusal here happens before the target is opened. A refusal or
    // failure returns `Completed`, exactly like the pre-existing image-open
    // failure path; a cancellation during a compressed image's Preflight returns
    // `Cancelled` (exit 130), like every other cancellation.
    let source: Box<dyn image_source::ImageSource> = match image_source::open_image(&image_path) {
        Ok(image_source::OpenedImage::Raw(source)) => Box::new(source),
        Ok(image_source::OpenedImage::Compressed(compressed)) => {
            // gzip or xz, alike: validated end to end (Preflight) before anything else,
            // with the decoded size bounded by the target's capacity, so the
            // confirmation below shows the exact image size and an image
            // that cannot be written is refused before the target is opened.
            println!(
                "write-test: detected format: {} (compressed image); validating it before writing (nothing is written yet)",
                compressed.format().name()
            );
            let prepared = prepare_compressed_image(
                compressed,
                verify_mode,
                target_capacity,
                || cancel.is_requested(),
                |progress| println!("write-test: {}", format_preflight_progress(&progress)),
            );
            let source = match prepared {
                Ok(source) => source,
                Err(CompressedImageRejection::Preflight(
                    image_source::compressed::PreflightError::Cancelled,
                )) => {
                    for line in format_cancelled_before_confirmation() {
                        println!("write-test: {line}");
                    }
                    return Ok(WriteTestExit::Cancelled);
                }
                Err(rejection) => {
                    for line in format_compressed_image_rejected(&rejection) {
                        println!("write-test: {line}");
                    }
                    return Ok(WriteTestExit::Completed);
                }
            };

            // Validation can take a long time: re-verify the target (fresh
            // snapshot; Identity / Instance / Safety) before continuing to
            // the confirmation. The write-time re-check before OpenDevice
            // still runs later, unchanged.
            state = core::revalidate(state, collect_device_snapshot(&target_block_path));
            if !core::is_ready_to_open(&state) {
                println!("write-test: the target changed while the image was being validated:");
                print_selection_state(&state);
                println!("write-test: stopping before confirmation; nothing was written.");
                return Ok(WriteTestExit::Completed);
            }

            Box::new(source)
        }
        Err(
            error @ (image_source::ImageSourceError::UnsupportedFormat(_)
            | image_source::ImageSourceError::ExtensionMismatch { .. }),
        ) => {
            for line in format_image_format_rejected(&error) {
                println!("write-test: {line}");
            }
            return Ok(WriteTestExit::Completed);
        }
        Err(error) => {
            println!("write-test: failed to open image {image_path}: {error:?}");
            return Ok(WriteTestExit::Completed);
        }
    };
    let selected_image = image_source::SelectedImage::new(source);

    let core::SelectionState::Selected {
        baseline,
        baseline_assessment,
        ..
    } = &state
    else {
        unreachable!("is_ready_to_open confirmed Selected");
    };

    println!(
        "\nwrite-test: image selected from {image_path} (image_size={} bytes)",
        selected_image.logical_size()
    );

    // Ctrl+C may have arrived while the image was being opened. Nothing on
    // the target side has been opened at this point (OpenDevice only happens
    // after confirmation), so stopping here is unconditionally safe.
    if cancel.is_requested() {
        for line in format_cancelled_before_confirmation() {
            println!("write-test: {line}");
        }
        return Ok(WriteTestExit::Cancelled);
    }

    // ---- Pre-write Safety Summary / Destructive Warning / Human Confirmation ----
    // Reuses `baseline`/`baseline_assessment` from the same `state` that
    // `attempt_select`/`revalidate` already fetched and re-verified above --
    // no new device probe, no extra D-Bus call added just for this summary.
    println!("\nwrite-test: Pre-write Safety Summary");
    println!("Target:");
    println!("  Device:      {}", baseline.device);
    println!("  Model:       {} {}", baseline.vendor, baseline.model);
    println!("  Serial:      {}", baseline.serial);
    println!("  Size:        {}", format_size(baseline.size));
    println!("  Bus:         {}", baseline.connection_bus);
    println!("  Removable:   {}", baseline.removable);
    if baseline.mount_points.is_empty() {
        println!("  Mounts:      none");
    } else {
        println!("  Mounts:      {}", baseline.mount_points.join(", "));
    }
    println!("  Risk:        {:?}", baseline_assessment.risk_level);
    println!("  Writable:    {}", baseline_assessment.writable);
    println!("  Reasons:     {:?}", baseline_assessment.reasons);
    println!("  Block path:  {}", baseline.block_path);
    println!("  DiskSeq:     {:?}", baseline.diskseq);
    println!("Image:");
    println!("  Path:        {image_path}");
    println!(
        "  Size:        {}",
        format_size(selected_image.logical_size())
    );
    println!("Verification mode: {verify_mode:?}");
    println!();
    println!("WARNING: Writing will overwrite the target device.");
    println!("ALL EXISTING DATA ON THIS DEVICE MAY BE DESTROYED. This cannot be undone.");
    println!();

    let expected_device = baseline.device.clone();
    println!("Type the target device name exactly to continue: {expected_device}");
    print!("> ");
    let _ = std::io::stdout().flush();

    // stdin is read on a separate thread so a Ctrl+C here is noticed within
    // `PROMPT_CANCEL_POLL_INTERVAL` instead of being swallowed by the
    // `SA_RESTART`-restarted `read_line()` (see `install_cancel_handler`).
    let prompt_input = match spawn_prompt_reader() {
        Ok(receiver) => wait_for_prompt_input(
            &receiver,
            || cancel.is_requested(),
            PROMPT_CANCEL_POLL_INTERVAL,
        ),
        Err(error) => PromptInput::Error(error),
    };

    let confirmed = match prompt_input {
        PromptInput::Line(input) => confirmation_matches(&input, &expected_device),
        PromptInput::Eof => false, // EOF (e.g. stdin closed or redirected from an empty source): treat as "no answer given", never as an implicit yes.
        PromptInput::Error(error) => {
            println!("write-test: failed to read the confirmation input: {error}");
            false
        }
        PromptInput::Cancelled => {
            println!();
            for line in format_cancelled_before_confirmation() {
                println!("write-test: {line}");
            }
            return Ok(WriteTestExit::Cancelled);
        }
    };

    if !confirmed {
        println!("write-test: confirmation failed; no device was opened and nothing was written");
        return Ok(WriteTestExit::Completed);
    }

    println!("write-test: confirmation accepted for {expected_device}");

    // `verify_mode` is the CLI's own choice (see the `write-test` dispatch in
    // `main()`), frozen into the `ConfirmationToken`/`WritePlan` below via
    // the same `WriteIntent`/Gate path the target/image/generation already
    // go through -- there is no separate, second place this value is
    // threaded into later. `SyncSucceeded` (produced far below, after a
    // successful write+sync) carries this exact value forward unchanged,
    // which is what `SyncSucceeded::begin_verify()` branches on to decide
    // None/Quick/Full -- see the Built-in Verify wiring later in this
    // function.
    let intent =
        match core::WriteIntent::from_selection(&state, selected_image.selection(), verify_mode) {
            Ok(intent) => intent,
            Err(error) => {
                println!("write-test: WriteIntent construction rejected: {error:?}");
                return Ok(WriteTestExit::Completed);
            }
        };
    let confirmation = core::ConfirmationToken::confirm(intent);
    println!(
        "write-test: confirmation created for {} (image_size={} bytes, verify_mode={:?})",
        confirmation.intent().target_block_path(),
        confirmation.intent().image_size(),
        confirmation.intent().verify_mode()
    );

    let refreshed_for_gate = collect_device_snapshot(&baseline.block_path);

    let ready = match core::prepare_for_open(
        &state,
        refreshed_for_gate,
        selected_image.selection(),
        verify_mode,
        Some(&confirmation),
    ) {
        Ok(ready) => ready,
        Err(error) => {
            println!("write-test: Write Gate rejected before OpenDevice: {error:?}");
            return Ok(WriteTestExit::Completed);
        }
    };

    println!(
        "write-test: Write Gate (pre-open) passed. WritePlan: image_size={} target_size={} chunk_size={}",
        ready.plan().image_size, ready.plan().target_size, ready.plan().chunk_size
    );

    println!(
        "write-test: requesting OpenDevice(mode=\"rw\") on {}.",
        ready.current().block_path
    );
    println!(
        "If a polkit authentication prompt appears, please complete it yourself -- \
         this program will not use sudo or any other privilege bypass."
    );

    let open_result = linux_access::open_device(
        &ready.current().block_path,
        linux_access::OpenAccess::WriteExclusive,
    );

    // Metadata must be read from the handle *before* the handle's ownership
    // moves into `finalize_prepared_write`, exactly like `run_prepare_test`
    // above -- `core.rs` stays free of Linux I/O calls.
    let (handle_opt, metadata) = match open_result {
        Ok(handle) => {
            println!("write-test: OpenDevice: success");
            let metadata = handle.metadata();
            (Some(handle), metadata)
        }
        Err(error) => {
            println!("write-test: OpenDevice: failed ({error:?})");
            (None, None)
        }
    };

    if let Some(meta) = &metadata {
        println!(
            "write-test: FD major:minor={}:{} size={:?}",
            meta.major, meta.minor, meta.size
        );
    }

    let prepared = match core::finalize_prepared_write(ready, handle_opt, metadata.as_ref()) {
        // `finalize_prepared_write` can only reach `Ok` after
        // `check_fd_binding` (core.rs) itself returned `FdBindingCheck::Match`
        // -- `Mismatch`/`InsufficientInformation` both return `Err` before a
        // `PreparedWrite` is ever constructed. So printing "Match" here is
        // not a guess about internal state; it is what reaching this arm at
        // all already proves.
        Ok(prepared) => {
            println!("write-test: FD binding: Match");
            prepared
        }
        Err(error) => {
            println!("write-test: Write Gate rejected after OpenDevice: {error:?}");
            println!("write-test: FD (if any was opened) was already closed via RAII inside the Write Gate");
            return Ok(WriteTestExit::Completed);
        }
    };

    println!(
        "write-test: PreparedWrite established for {} (target_size={} image_size={})",
        prepared.target_block_path, prepared.target_size, prepared.image_size
    );

    // PreparedWrite -> AuthorizedWrite. The fd moves once, with no
    // dup()/try_clone(), exactly like `run_prepare_test`. Unlike
    // `run_prepare_test`, this `authorized` is not dropped here -- it is
    // handed straight to `AuthorizedExecution::bind()` below, together with
    // the exact same `selected_image` this function has held since the top.
    let authorized = prepared.begin();
    println!("write-test: WRITE SESSION AUTHORIZED (verify_mode={verify_mode:?})");

    let execution = match write_job::AuthorizedExecution::bind(authorized, selected_image) {
        Ok(execution) => execution,
        Err(error) => {
            println!("write-test: AuthorizedExecution::bind() rejected: {error:?}");
            println!("write-test: AuthorizedWrite dropped -- FD closed via RAII");
            return Ok(WriteTestExit::Completed);
        }
    };
    println!("write-test: AuthorizedExecution bound (image_generation/image_size match confirmed)");

    // `cancel.clone()`, not `cancel`: the shared handle created after Human
    // Confirmation above must survive this call so it can also be handed to
    // `begin_verify()` later (and read from the write progress callback
    // below) -- see that handle's own doc comment.
    let writing_execution = match execution.begin_write(cancel.clone()) {
        Ok(writing_execution) => writing_execution,
        Err(error) => {
            println!("write-test: begin_write() failed to open the image reader: {error}");
            println!(
                "write-test: AuthorizedExecution dropped -- FD closed via RAII, 0 bytes written"
            );
            return Ok(WriteTestExit::Completed);
        }
    };
    println!("write-test: write started");

    // `cancellation_notice_shown`: this progress callback is a convenient,
    // already-existing place to tell the user their Ctrl+C was seen, the
    // *first* time it's observed -- but it is only a best-effort, early
    // notice. It is not guaranteed to run at all (e.g. cancellation
    // requested after the last chunk already completed) and is never the
    // thing that decides whether the write actually stopped -- that is
    // `WriteAttemptOutcome::Cancelled` below, unconditionally.
    let mut cancellation_notice_shown = false;

    let (selected_image, outcome) = writing_execution.write(|progress| {
        if cancel.is_requested() && !cancellation_notice_shown {
            cancellation_notice_shown = true;
            println!(
                "write-test: cancellation requested -- waiting for the current operation to stop safely."
            );
        }
        let percent = if progress.total_bytes > 0 {
            (progress.bytes_written as f64 / progress.total_bytes as f64) * 100.0
        } else {
            100.0
        };
        println!(
            "write-test: progress {}/{} bytes ({percent:.1}%)",
            progress.bytes_written, progress.total_bytes
        );
    });

    let write_test_exit = match outcome {
        write_job::WriteAttemptOutcome::Succeeded(succeeded) => {
            println!(
                "write-test: write succeeded ({} of {} bytes written)",
                succeeded.bytes_written, succeeded.image_size
            );

            // Write success -> sync, in the same straight line, with no
            // branch that returns early and skips it.
            println!("write-test: syncing...");
            // Sync runs on a worker thread while this (main) thread waits in
            // an interruptible `join()` -- see `run_off_main_thread` for why
            // this matters for a Ctrl+C pressed during sync. Sync is still
            // awaited to completion; it is never interrupted.
            let syncing = succeeded.begin_sync();
            let sync_outcome = match run_off_main_thread(syncing, |syncing| syncing.sync()) {
                OffMainThread::Finished(outcome) => outcome,
                OffMainThread::NotStarted(syncing, error) => {
                    // Durability first: if no worker thread can be created,
                    // sync on this thread rather than skip it. A Ctrl+C
                    // during this sync may only be observed once it returns
                    // (the post-sync check below still runs).
                    println!(
                        "write-test: could not start the sync worker thread ({error}); syncing on the main thread instead"
                    );
                    syncing.sync()
                }
                OffMainThread::Panicked => {
                    for line in format_sync_worker_panicked() {
                        println!("write-test: {line}");
                    }
                    if cancel.is_requested() {
                        println!(
                            "write-test: cancellation was also requested; the sync failure above is the result"
                        );
                    }
                    return Ok(WriteTestExit::Completed);
                }
            };

            match sync_outcome {
                write_job::SyncAttemptOutcome::Succeeded(sync_succeeded) => {
                    println!(
                        "write-test: sync succeeded -- write + sync completed ({} bytes)",
                        sync_succeeded.bytes_written
                    );

                    // Sync itself is never interrupted (durability first),
                    // but a Ctrl+C accepted while it ran must not be silently
                    // turned into `Completed` -- for any `VerifyMode`,
                    // including `None`, which never reaches the Quick/Full
                    // early cancel check further below. That later check
                    // stays: it still covers a cancellation arriving after
                    // this point (e.g. during the test-only pause).
                    if let Some(exit) = exit_after_successful_sync(cancel.is_requested()) {
                        for line in format_cancelled_after_sync() {
                            println!("write-test: {line}");
                        }
                        return Ok(exit);
                    }

                    // ---- Built-in Verify (self-contained: this arm always
                    // returns, so `selected_image` being consumed here --
                    // via `begin_verify()` -- never conflicts with the
                    // trailing print below, which only the *other* three
                    // arms (which never touch `selected_image`) can reach.
                    // `cancel.clone()`, the same shared handle Ctrl+C was
                    // wired to right after target selection -- a
                    // cancellation requested during write or sync was
                    // already honored by the post-sync check above; one
                    // requested after that check is still honored by the
                    // early cancel check right after the TEST PAUSE block
                    // below. ----
                    match sync_succeeded.begin_verify(selected_image, cancel.clone()) {
                        write_job::VerifyStart::Skipped(image, succeeded) => {
                            println!("write-test: {}", format_verify_succeeded(&succeeded));
                            println!(
                                "write-test: SelectedImage identity preserved after verification (image_size={})",
                                image.logical_size()
                            );
                            return Ok(WriteTestExit::Completed);
                        }
                        write_job::VerifyStart::Pending(pending) => {
                            match verify_mode {
                                core::VerifyMode::Quick => println!(
                                    "write-test: Quick verification checks selected regions only. It does not verify the entire image."
                                ),
                                core::VerifyMode::Full => println!(
                                    "write-test: Full verification reads back the entire written image."
                                ),
                                core::VerifyMode::None => unreachable!(
                                    "VerifyMode::None always produces VerifyStart::Skipped, never Pending"
                                ),
                            }

                            // TEST-ONLY (implementation of the Mount-Allowance
                            // Real-device Test design, reports/latest.md):
                            // pauses here, strictly before the fresh
                            // `DeviceSnapshot` below is fetched, so a child
                            // partition can be mounted manually and actually
                            // be reflected in that fresh snapshot's
                            // `mount_points`. Everything below this block --
                            // `collect_device_snapshot`, `check_target`,
                            // Identity/Instance/hazard checks,
                            // `OpenDevice(mode="r")`, FD binding -- is
                            // unchanged and still runs in full; this flag
                            // only delays when it starts. Safe to hold
                            // `pending` here indefinitely: `begin_verify()`
                            // already dropped the write-mode FD before
                            // returning it (see `write_job.rs`'s own
                            // `SyncSucceeded::begin_verify()`), so `pending`
                            // is inert data (a cloned baseline `DeviceSnapshot`,
                            // the `SelectedImage`, `VerifyMode`, and a
                            // `CancelHandle`) with no open capability of any
                            // kind while this waits on stdin.
                            if test_pause_before_verify && !pause_before_verify_for_test() {
                                println!(
                                    "write-test: no input received on the test pause (EOF or I/O error) -- stopping before verification."
                                );
                                println!(
                                    "write-test: write + sync already completed successfully; verification was not attempted."
                                );
                                return Ok(WriteTestExit::Completed);
                            }

                            // Cancel wiring: a Ctrl+C requested after the
                            // post-sync check (during the TEST PAUSE above,
                            // or simply while reading these messages) must be
                            // honored now, before any further D-Bus call or
                            // FD is opened for Verify.
                            // `begin_verify()` itself does not check this
                            // (it only branches on `VerifyMode` -- see its
                            // own doc comment in `write_job.rs`), so this is
                            // the one place that closes that gap, entirely
                            // within `main.rs`. `pause_before_verify_for_test`
                            // itself is not made "signal aware" -- whatever
                            // it returned above, this check runs
                            // unconditionally right after it.
                            if cancel.is_requested() {
                                for line in format_verify_cancelled_before_start() {
                                    println!("write-test: {line}");
                                }
                                return Ok(WriteTestExit::Cancelled);
                            }

                            println!(
                                "write-test: requesting a fresh DeviceSnapshot for verification on {}.",
                                pending.block_path()
                            );
                            let refreshed_for_verify =
                                collect_device_snapshot(pending.block_path());

                            let ready = match pending.check_target(refreshed_for_verify) {
                                Ok(ready) => ready,
                                // Verify Pre-flight Diagnostics (implementation step
                                // 5+6): `check_target()`'s rejection carries the
                                // `VerifyTargetDiagnostics` that produced it whenever
                                // one could be computed -- only `SnapshotRefreshFailed`
                                // has none, since there is no fresh snapshot to
                                // diagnose against in that case. Write/Sync already
                                // succeeded by this point; only Verify's own
                                // pre-flight failed, and the wording below keeps that
                                // distinction explicit rather than implying the write
                                // itself failed.
                                Err((image, error, diagnostics)) => {
                                    println!("write-test: write + sync completed successfully.");
                                    println!("write-test: verification could not start: {error:?}");
                                    match diagnostics {
                                        Some(diagnostics) => {
                                            println!("write-test: verify target re-check: FAILED");
                                            for line in
                                                format_verify_diagnostics_summary(&diagnostics)
                                            {
                                                println!("write-test:   {line}");
                                            }
                                        }
                                        None => {
                                            println!(
                                                "write-test: verify target re-check: unavailable"
                                            );
                                            for line in format_verify_diagnostics_unavailable() {
                                                println!("write-test:   {line}");
                                            }
                                        }
                                    }
                                    println!(
                                        "write-test: SelectedImage identity preserved (image_size={})",
                                        image.logical_size()
                                    );
                                    return Ok(WriteTestExit::Completed);
                                }
                            };

                            // Verify Pre-flight Diagnostics (implementation step
                            // 5+6): the same five-line summary shown on the
                            // rejection path above, now for the passing case --
                            // "Simple by default": always shown, never a full
                            // `DeviceSnapshot` dump. Borrowed from `ready` before
                            // `ready.finalize(...)` consumes it below; the borrow
                            // ends at the end of this `for` loop, well before that
                            // move.
                            println!("write-test: verify target re-check: OK");
                            for line in format_verify_diagnostics_summary(ready.diagnostics()) {
                                println!("write-test:   {line}");
                            }

                            println!(
                                "write-test: requesting OpenDevice(mode=\"r\") on {} for verification.",
                                ready.block_path()
                            );
                            println!(
                                "If a polkit authentication prompt appears, please complete it yourself -- \
                                 this program will not use sudo or any other privilege bypass."
                            );

                            let open_result = linux_access::open_device(
                                ready.block_path(),
                                linux_access::OpenAccess::ReadOnly,
                            );

                            let (handle_opt, metadata) = match open_result {
                                Ok(handle) => {
                                    println!("write-test: OpenDevice(mode=\"r\"): success");
                                    let metadata = handle.metadata();
                                    (Some(handle), metadata)
                                }
                                Err(error) => {
                                    println!(
                                        "write-test: OpenDevice(mode=\"r\"): failed ({error:?})"
                                    );
                                    (None, None)
                                }
                            };

                            if let Some(meta) = &metadata {
                                println!(
                                    "write-test: verify FD major:minor={}:{} size={:?}",
                                    meta.major, meta.minor, meta.size
                                );
                            }

                            let verifying = match ready.finalize(handle_opt, metadata.as_ref()) {
                                // Reaching `Ok` here already proves
                                // `check_fd_binding` (core.rs) returned
                                // `FdBindingCheck::Match` -- same reasoning
                                // as the write path's own "FD binding:
                                // Match" line above.
                                Ok(verifying) => {
                                    println!("write-test: verify FD binding: Match");
                                    verifying
                                }
                                Err((image, error)) => {
                                    println!("write-test: write + sync completed successfully.");
                                    println!("write-test: verification could not start: {error:?}");
                                    println!(
                                        "write-test: SelectedImage identity preserved (image_size={})",
                                        image.logical_size()
                                    );
                                    return Ok(WriteTestExit::Completed);
                                }
                            };

                            println!("write-test: verification started");

                            // See the write progress callback's own comment
                            // above for why `cancellation_notice_shown` is
                            // only a best-effort notice. `last_verify_total_bytes`
                            // caches the same `total_bytes` the progress
                            // lines already display, purely so the final
                            // Cancelled message below can report "X of Y"
                            // without `write_job.rs` needing to expose a
                            // separate way to compute Quick's sampled total.
                            let mut cancellation_notice_shown = false;
                            let mut last_verify_total_bytes: u64 = 0;

                            let (image, verify_outcome) = verifying.run(|progress| {
                                last_verify_total_bytes = progress.total_bytes;
                                if cancel.is_requested() && !cancellation_notice_shown {
                                    cancellation_notice_shown = true;
                                    println!(
                                        "write-test: cancellation requested -- waiting for the current operation to stop safely."
                                    );
                                }
                                let percent = if progress.total_bytes > 0 {
                                    (progress.verified_bytes as f64 / progress.total_bytes as f64)
                                        * 100.0
                                } else {
                                    100.0
                                };
                                println!(
                                    "write-test: verify progress {}/{} bytes ({percent:.1}%)",
                                    progress.verified_bytes, progress.total_bytes
                                );
                            });

                            let verify_exit = match verify_outcome {
                                write_job::VerifyOutcome::Succeeded(succeeded) => {
                                    println!("write-test: {}", format_verify_succeeded(&succeeded));
                                    WriteTestExit::Completed
                                }
                                write_job::VerifyOutcome::Failed(failed) => {
                                    println!("write-test: write + sync completed successfully.");
                                    println!(
                                        "write-test: verification failed: {}",
                                        format_verify_failure_reason(&failed.reason)
                                    );
                                    println!(
                                        "write-test: verified_bytes={} before failure (mode={:?})",
                                        failed.verified_bytes, failed.mode
                                    );
                                    WriteTestExit::Completed
                                }
                                write_job::VerifyOutcome::Cancelled(cancelled) => {
                                    for line in
                                        format_verify_cancelled(&cancelled, last_verify_total_bytes)
                                    {
                                        println!("write-test: {line}");
                                    }
                                    WriteTestExit::Cancelled
                                }
                            };

                            println!(
                                "write-test: SelectedImage identity preserved after verification (image_size={})",
                                image.logical_size()
                            );

                            return Ok(verify_exit);
                        }
                    }
                }
                write_job::SyncAttemptOutcome::Failed(failed) => {
                    println!("write-test: sync FAILED: {failed:?}");
                    println!(
                        "write-test: retry_requires_fresh_gate={} -- not retrying automatically",
                        failed.retry_requires_fresh_gate
                    );
                    // A real sync failure is never masked by a cancellation
                    // requested at the same time: the result stays the
                    // failure (`Completed`, as before); this only notes it.
                    if cancel.is_requested() {
                        println!(
                            "write-test: cancellation was also requested; the sync failure above is the result"
                        );
                    }
                    WriteTestExit::Completed
                }
            }
        }
        write_job::WriteAttemptOutcome::Failed(failed) => {
            println!("write-test: write FAILED: {failed:?}");
            println!(
                "write-test: not syncing -- retry_requires_fresh_gate={}",
                failed.retry_requires_fresh_gate
            );
            WriteTestExit::Completed
        }
        write_job::WriteAttemptOutcome::Cancelled(cancelled) => {
            for line in format_write_cancelled(&cancelled) {
                println!("write-test: {line}");
            }
            println!(
                "write-test: not syncing -- retry_requires_fresh_gate={}",
                cancelled.retry_requires_fresh_gate
            );
            WriteTestExit::Cancelled
        }
    };

    // Reached only by the write-Failed, write-Cancelled, and sync-Failed
    // paths above -- the sync-Succeeded path always returns from within its
    // own arm (see above), together with `selected_image`, before control
    // flow can ever reach here. `selected_image` is therefore guaranteed to
    // still be owned by this scope on every path that reaches this line.
    println!(
        "write-test: SelectedImage identity preserved (image_size={})",
        selected_image.logical_size()
    );

    Ok(write_test_exit)
}

// Parses a CLI verify-mode argument (`none` | `quick` | `full`, lowercase
// only -- this PoC does not attempt case-insensitive matching). `None` means
// the argument itself did not match any known mode; the caller is
// responsible for rejecting that with a usage message and a non-zero exit,
// never for silently falling back to a default (a default is only ever
// applied when the argument is *absent* -- see the `write-test` CLI dispatch
// in `main()`).
fn parse_verify_mode(value: &str) -> Option<core::VerifyMode> {
    match value {
        "none" => Some(core::VerifyMode::None),
        "quick" => Some(core::VerifyMode::Quick),
        "full" => Some(core::VerifyMode::Full),
        _ => None,
    }
}

// Why `parse_write_test_trailing_args` (below) rejected the `write-test`
// CLI's third/fourth arguments. Kept separate from the message text itself
// (formatted at the call site in `main()`, which still has the original raw
// argument strings to include in the message) so this function stays pure
// data in, data out -- exactly like `parse_verify_mode` above.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WriteTestArgsError {
    InvalidVerifyMode,
    UnrecognizedFourthArgument,
    TestPauseRequiresVerification,
}

// Parses `write-test`'s two optional trailing arguments (verify-mode and
// `--test-pause-before-verify`) together, since the second one's validity
// depends on the first: pure data in, data out, no I/O, no `std::process::exit`
// -- the caller (`main()`) owns all user-facing messages and the actual
// process exit, exactly the same split `parse_verify_mode` already
// established. `--test-pause-before-verify` is a TEST-ONLY diagnostic option
// (see `pause_before_verify_for_test`'s own doc comment) for manually
// exercising Verify pre-flight's mount_points-allowance branch on real
// hardware -- it is deliberately rejected outright (not silently accepted
// as a no-op) when paired with `verify-mode none`, since `VerifyMode::None`
// never produces `VerifyStart::Pending` and the flag would then have no
// observable effect at all.
fn parse_write_test_trailing_args(
    verify_mode_arg: Option<&str>,
    fourth_arg: Option<&str>,
) -> Result<(core::VerifyMode, bool), WriteTestArgsError> {
    // Absent -> `VerifyMode::None` (see `parse_verify_mode`'s own doc
    // comment for why that default was chosen). Present but unrecognized ->
    // rejected, never a silent fallback to `None` or to any other mode.
    let verify_mode = match verify_mode_arg {
        None => core::VerifyMode::None,
        Some(mode_str) => {
            parse_verify_mode(mode_str).ok_or(WriteTestArgsError::InvalidVerifyMode)?
        }
    };

    // Absent -> disabled (existing behavior, unchanged). Present and exactly
    // `--test-pause-before-verify` -> enabled. Anything else -> rejected,
    // never silently ignored.
    let test_pause_before_verify = match fourth_arg {
        None => false,
        Some("--test-pause-before-verify") => true,
        Some(_) => return Err(WriteTestArgsError::UnrecognizedFourthArgument),
    };

    if test_pause_before_verify && verify_mode == core::VerifyMode::None {
        return Err(WriteTestArgsError::TestPauseRequiresVerification);
    }

    Ok((verify_mode, test_pause_before_verify))
}

// Formats a successful Verify outcome for the CLI. Shared by both
// `VerifyStart::Skipped` (VerifyMode::None) and a completed
// `Verifying::run()` (Quick/Full) -- both ultimately produce a
// `write_job::VerifySucceeded`, so this one function is the single place
// that decides how each mode's success is worded, rather than duplicating
// the match between the two call sites.
fn format_verify_succeeded(succeeded: &write_job::VerifySucceeded) -> String {
    match succeeded.mode {
        core::VerifyMode::None => "Verification: skipped".to_string(),
        core::VerifyMode::Quick => format!(
            "Quick verification succeeded ({} bytes sampled)",
            succeeded.verified_bytes
        ),
        core::VerifyMode::Full => format!(
            "Full verification succeeded ({} bytes verified)",
            succeeded.verified_bytes
        ),
    }
}

// Formats a `VerifyFailureReason` for the CLI, distinguishing source vs.
// target for both the I/O-error and unexpected-EOF cases -- which side
// failed is genuinely different diagnostic information (see
// `write_job.rs`'s own doc comment on `VerifyFailureReason`).
fn format_verify_failure_reason(reason: &write_job::VerifyFailureReason) -> String {
    match reason {
        write_job::VerifyFailureReason::Mismatch {
            offset,
            expected,
            actual,
        } => format!(
            "mismatch at offset {offset}\n  expected: 0x{expected:02x}\n  actual:   0x{actual:02x}"
        ),
        write_job::VerifyFailureReason::SourceUnexpectedEof => {
            "the image source ended before all expected bytes could be read".to_string()
        }
        write_job::VerifyFailureReason::TargetUnexpectedEof => {
            "the target device ended before all expected bytes could be read".to_string()
        }
        write_job::VerifyFailureReason::SourceReadError(error) => {
            format!("failed to read the image source: {error}")
        }
        write_job::VerifyFailureReason::TargetReadError(error) => {
            format!("failed to read the target device: {error}")
        }
        write_job::VerifyFailureReason::UnsupportedAccess => {
            "quick verification requires an image source with random-access support, which this image does not provide".to_string()
        }
        write_job::VerifyFailureReason::SourceChanged(changed) => {
            format!("{changed}; the verification result was not accepted")
        }
    }
}

// ---------------------------------------------------------------------
// Verify Pre-flight Diagnostics CLI display (implementation step 5+6).
//
// Every helper below is a pure formatter: it takes already-computed
// `core::VerifyTargetDiagnostics` data (or one of its fields) and returns a
// `String`/`Vec<String>`, never printing anything itself. `println!` calls
// live only at the two `run_write_test` call sites (success path and
// failure path), which loop over the returned lines -- this keeps the
// comparison/wording logic testable without capturing stdout, and keeps
// `core.rs`/`write_job.rs` themselves free of any UI/logging dependency
// (the diagnostics data they produce is plain data; only `main.rs` decides
// how it looks on screen).
//
// "Simple by default": normal display is a five-line, diff-centric summary
// (identity/instance/mount points/read-only/hazards), never a full
// `DeviceSnapshot` field dump -- see reports/latest.md's Verify Pre-flight
// Diagnostics Design for the fuller rationale. `diskseq`/`size`/
// `connection_bus`/`removable` diffs were considered but deliberately left
// out of this step's summary to keep it exactly matching this step's
// review scope; a future "verbose" mode remains the natural place for them.
// ---------------------------------------------------------------------

// Human-readable text for an `IdentityComparison`, matching the enum's own
// vocabulary for the successful case (`Same`) but adding a short, fixed
// explanation for the two rejection cases -- deterministic wording, not a
// paraphrase that could drift between calls.
fn format_identity_comparison(identity: IdentityComparison) -> &'static str {
    match identity {
        IdentityComparison::Same => "Same",
        IdentityComparison::Changed => "Changed (different device)",
        IdentityComparison::InsufficientIdentity => "Insufficient (no usable serial to compare)",
    }
}

// Human-readable text for an `InstanceComparison`, mirroring
// `format_identity_comparison`'s approach.
fn format_instance_comparison(instance: InstanceComparison) -> &'static str {
    match instance {
        InstanceComparison::SameInstance => "SameInstance",
        InstanceComparison::Recreated => "Recreated (disconnected and reconnected)",
        InstanceComparison::InsufficientInformation => "Insufficient (no diskseq to compare)",
    }
}

// Renders a mount-point list for display: `none` for an empty list, or a
// comma-joined list of the paths themselves. Mount paths are shown as-is
// (no masking) -- this step's design deliberately does not add a masking
// mechanism (see reports/latest.md), and the mount path is exactly the
// piece of information this diagnostic summary exists to surface.
fn format_mount_points_list(mount_points: &[String]) -> String {
    if mount_points.is_empty() {
        "none".to_string()
    } else {
        mount_points.join(", ")
    }
}

// Diffs two mount-point lists for display: `unchanged (none)` /
// `unchanged (<paths>)` when the baseline and the fresh snapshot agree,
// `<before> -> <after>` otherwise.
fn format_mount_points_change(baseline: &[String], current: &[String]) -> String {
    if baseline == current {
        format!("unchanged ({})", format_mount_points_list(baseline))
    } else {
        format!(
            "{} -> {}",
            format_mount_points_list(baseline),
            format_mount_points_list(current)
        )
    }
}

// Diffs a `read_only` flag for display: `unchanged (<value>)` or
// `<before> -> <after>`, mirroring `format_mount_points_change`.
fn format_read_only_change(baseline: bool, current: bool) -> String {
    if baseline == current {
        format!("unchanged ({current})")
    } else {
        format!("{baseline} -> {current}")
    }
}

// Human-readable text for a single `core::HardHazardReason`. Wording kept
// short and lowercase, matching this CLI's existing tone (see
// `format_verify_failure_reason` above).
fn format_hard_hazard_reason(reason: core::HardHazardReason) -> &'static str {
    match reason {
        core::HardHazardReason::SystemDevice => "system device",
        core::HardHazardReason::ActiveSwap => "active swap",
        core::HardHazardReason::ComplexStorage => "complex storage",
        core::HardHazardReason::HintIgnore => "ignored by system policy",
        core::HardHazardReason::MediaUnavailable => "media unavailable",
    }
}

// Renders every hazard `core::verify_target_hard_hazards` found, in the
// same deterministic order it already returns them in: `none` when empty,
// otherwise a comma-joined list -- never just the first one, since more
// than one hazard can apply at once (see `core.rs`'s own
// `diagnostics_report_multiple_hazards_in_deterministic_order` test).
fn format_hard_hazards(hazards: &[core::HardHazardReason]) -> String {
    if hazards.is_empty() {
        "none".to_string()
    } else {
        hazards
            .iter()
            .map(|reason| format_hard_hazard_reason(*reason))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

// The single, shared diagnostic summary for both the success path (Verify
// pre-flight passed) and the failure path (Identity/Instance/hazard
// rejection) of `PendingVerify::check_target()` -- both display exactly the
// same five lines, from the same `core::VerifyTargetDiagnostics` value, so
// there is no risk of the two call sites silently drifting into showing
// different information for what is structurally the same diagnostic data.
// Returns the *content* of each line (no `write-test:` prefix, no leading
// indentation) -- the caller decides how to prefix/indent them, keeping
// this function pure formatting with no CLI-framing baked in.
fn format_verify_diagnostics_summary(diagnostics: &core::VerifyTargetDiagnostics) -> Vec<String> {
    vec![
        format!(
            "identity: {}",
            format_identity_comparison(diagnostics.identity())
        ),
        format!(
            "instance: {}",
            format_instance_comparison(diagnostics.instance())
        ),
        format!(
            "mount points: {}",
            format_mount_points_change(
                &diagnostics.baseline().mount_points,
                &diagnostics.current().mount_points
            )
        ),
        format!(
            "read-only: {}",
            format_read_only_change(
                diagnostics.baseline().read_only,
                diagnostics.current().read_only
            )
        ),
        format!("hazards: {}", format_hard_hazards(diagnostics.hazards())),
    ]
}

// The fallback shown in place of `format_verify_diagnostics_summary`'s
// output when `check_target()` returned `VerifyStartError::SnapshotRefreshFailed`
// -- there is no fresh `DeviceSnapshot` in that case, so no diagnostics
// value exists to summarize (see `PendingVerify::check_target()`'s own doc
// comment on why this is the one rejection with no diagnostics). Returns
// the line content only, matching `format_verify_diagnostics_summary`'s own
// contract, so the caller prefixes/indents it the same way.
fn format_verify_diagnostics_unavailable() -> Vec<String> {
    vec!["no fresh device snapshot was available for diagnostics".to_string()]
}

// ---------------------------------------------------------------------
// Cancel (Ctrl+C) CLI messaging (Cancel機能 Ctrl+C実配線 implementation).
// Pure formatters, matching the existing `format_verify_diagnostics_*`
// pattern: no `println!` here, only line content for the caller to prefix.
// ---------------------------------------------------------------------

// A cancelled write is never a success: it is always reported as a
// cancellation, and `verification was not attempted` is stated
// unconditionally. What it says about the target follows
// `target_may_be_modified` -- the Job layer's safety-biased field for
// exactly this question -- OR'd with `bytes_written > 0` as a defensive
// fallback, so any disagreement between the two is resolved toward
// "partial image". Only when both say nothing was written (a cancellation
// `writer::write()` observed before its first chunk) does this say so. The
// target was still opened read-write by then, so the wording is "no data was
// written", never "not opened"/"untouched".
fn format_write_cancelled(cancelled: &write_job::Cancelled) -> Vec<String> {
    let target_line = if cancelled.target_may_be_modified || cancelled.bytes_written > 0 {
        "target may contain a partial image"
    } else {
        "no data was written to the target device"
    };

    vec![
        format!(
            "write cancelled after {} of {} bytes",
            cancelled.bytes_written, cancelled.image_size
        ),
        target_line.to_string(),
        "verification was not attempted".to_string(),
    ]
}

// Shown when a cancellation is observed before the Human Confirmation step
// completed -- after the image was opened, or while waiting at the prompt.
// At that point the target has not been opened by this program at all
// (OpenDevice only happens after confirmation), which is what makes the
// second line a statement of fact rather than a hope.
fn format_cancelled_before_confirmation() -> Vec<String> {
    vec![
        "cancelled before confirmation.".to_string(),
        "the target device has not been opened or modified.".to_string(),
    ]
}

// Shown when a cancellation requested while sync was running is observed
// right after sync succeeded. Sync is never interrupted, so by then the full
// image has been written and synced; only verification is skipped. Worded so
// it cannot be read as a partial write.
fn format_cancelled_after_sync() -> Vec<String> {
    vec![
        "cancellation was requested during sync; sync was allowed to finish.".to_string(),
        "write + sync completed successfully; the full image is on the target.".to_string(),
        "verification was not started.".to_string(),
    ]
}

// Why a compressed image was not accepted for writing. Every case stops
// before the target is opened.
#[derive(Debug)]
enum CompressedImageRejection {
    // Quick Verify needs random access, which a compressed image cannot
    // provide; refused before Preflight (and before any confirmation).
    QuickVerifyUnsupported(image_source::CompressionFormat),
    // Preflight did not validate the image (includes cancellation).
    Preflight(image_source::compressed::PreflightError),
    // Preflight succeeded, but the file is no longer in the state it was
    // opened in (compared with the snapshot `open_image` took).
    SourceChanged(image_source::source_identity::SourceChanged),
}

// Turns an opened compressed image into the source the write pipeline reads
// from: refuses Quick Verify first (L1), then validates the whole stream
// (Preflight, bounded by `max_logical_size` -- the target's capacity -- and
// cancellable via `is_cancelled`), then confirms the file did not change
// while it was being validated. The file is the one `open_image` opened; it
// is moved, never re-opened.
fn prepare_compressed_image(
    compressed: image_source::CompressedImageFile,
    verify_mode: core::VerifyMode,
    max_logical_size: u64,
    is_cancelled: impl FnMut() -> bool,
    on_progress: impl FnMut(image_source::compressed::PreflightProgress),
) -> Result<image_source::compressed::CompressedImageSource, CompressedImageRejection> {
    if verify_mode == core::VerifyMode::Quick {
        return Err(CompressedImageRejection::QuickVerifyUnsupported(
            compressed.format(),
        ));
    }

    let options = image_source::compressed::PreflightOptions { max_logical_size };
    let preflighted = compressed
        .preflight(options, is_cancelled, on_progress)
        .map_err(CompressedImageRejection::Preflight)?;

    preflighted
        .revalidate_identity()
        .map_err(CompressedImageRejection::SourceChanged)?;

    Ok(image_source::compressed::CompressedImageSource::new(
        preflighted,
    ))
}

fn format_preflight_progress(progress: &image_source::compressed::PreflightProgress) -> String {
    format!(
        "validating compressed image: {}/{} compressed bytes read, {} bytes decoded",
        progress.compressed_consumed, progress.compressed_total, progress.logical_produced
    )
}

// Shown when a compressed image was not accepted (see
// `CompressedImageRejection`). A cancellation uses
// `format_cancelled_before_confirmation` instead.
fn format_compressed_image_rejected(rejection: &CompressedImageRejection) -> Vec<String> {
    use image_source::compressed::PreflightError;

    let reason = match rejection {
        CompressedImageRejection::QuickVerifyUnsupported(format) => format!(
            "quick verification is not available for {} images (they cannot be read at random offsets); use verify-mode full or none",
            format.name()
        ),
        CompressedImageRejection::Preflight(error) => match error {
            PreflightError::Cancelled => "validation was cancelled".to_string(),
            PreflightError::Corrupt(error) => {
                format!("the compressed image is corrupt: {error}")
            }
            PreflightError::Incomplete(error) => {
                format!("the compressed image is incomplete (truncated): {error}")
            }
            PreflightError::IntegrityCheckMissing => {
                "the compressed image has no integrity check, so its content cannot be verified"
                    .to_string()
            }
            PreflightError::UnsupportedIntegrityCheck => {
                "the compressed image uses an integrity check type that cannot be verified"
                    .to_string()
            }
            PreflightError::DecoderMemoryLimitExceeded { limit } => format!(
                "decompressing the image would need more memory than the decoder's safety limit ({limit} bytes)"
            ),
            PreflightError::DecoderFailure(error) => {
                format!("the decompressor failed (not caused by the image data): {error}")
            }
            PreflightError::LogicalSizeOverflow => {
                "the decompressed size is too large to represent".to_string()
            }
            PreflightError::LogicalSizeLimitExceeded { limit } => format!(
                "the decompressed image is larger than the target device ({limit} bytes)"
            ),
            PreflightError::InputConsumptionMismatch {
                consumed,
                compressed_size,
            } => format!(
                "the compressed stream ended after {consumed} of {compressed_size} bytes"
            ),
            PreflightError::CompressedInputBudgetExceeded { .. } => {
                "the compressed image needs too much input per byte of output (refused as a resource limit)".to_string()
            }
            PreflightError::Io(error) => format!("failed to read the compressed image: {error}"),
        },
        CompressedImageRejection::SourceChanged(changed) => changed.to_string(),
    };

    vec![
        format!("compressed image rejected: {reason}"),
        "the image was not written.".to_string(),
        "the target device has not been opened or modified.".to_string(),
    ]
}

// Shown when `open_image` refused the image because of its format:
// a recognized but unsupported compressed/archive format, or a `.gz`/`.xz`
// name whose content is not that format. Either way the file was not treated
// as a raw image. Any other `ImageSourceError` keeps the pre-existing
// "failed to open image" message at the call site.
fn format_image_format_rejected(error: &image_source::ImageSourceError) -> Vec<String> {
    let reason = match error {
        image_source::ImageSourceError::UnsupportedFormat(kind) => format!(
            "the image is {} data, which is not supported; it was not treated as a raw image.",
            kind.name()
        ),
        image_source::ImageSourceError::ExtensionMismatch { expected } => format!(
            "the file name says {} but the content is not {} data; refusing to write it as a raw image.",
            expected.name(),
            expected.name()
        ),
        other => format!("the image could not be used: {other:?}"),
    };

    vec![
        reason,
        "the target device has not been opened or modified.".to_string(),
    ]
}

// Shown when the sync worker thread panicked instead of returning a
// `SyncAttemptOutcome`. Treated like a sync failure: the write had
// completed, but sync never reported success, so durability is not
// confirmed. The write-mode FD was released when the worker unwound.
fn format_sync_worker_panicked() -> Vec<String> {
    vec![
        "sync FAILED: the sync worker thread panicked before reporting a result".to_string(),
        "the image was written, but sync did not report success; durability is not confirmed."
            .to_string(),
        "verification was not started.".to_string(),
    ]
}

// Unlike a write cancellation, a Verify cancellation never implies the
// target itself is suspect: Verify is read-only, and by the time it can run
// at all, write+sync have already succeeded -- see `format_verify_cancelled`'s
// caller for why this reads "written image remains on the target" rather
// than any wording implying the target is now in doubt. `total_bytes` is the
// last value observed from the Verify progress callback (the same
// `total_bytes` the ordinary progress lines already display), not
// `image.logical_size()` -- for `VerifyMode::Quick` those two differ, and
// this must report the same "sampled total" Quick was actually checking
// against, never the full image size.
fn format_verify_cancelled(
    cancelled: &write_job::VerifyCancelled,
    total_bytes: u64,
) -> Vec<String> {
    let mode_label = match cancelled.mode {
        core::VerifyMode::Quick => "Quick",
        core::VerifyMode::Full => "Full",
        core::VerifyMode::None => {
            unreachable!(
                "VerifyMode::None never reaches Verifying -- see SyncSucceeded::begin_verify()"
            )
        }
    };

    vec![
        format!(
            "{mode_label} verification cancelled after {} of {} bytes",
            cancelled.verified_bytes, total_bytes
        ),
        "written image remains on the target".to_string(),
    ]
}

// Shown when `cancel.is_requested()` is already `true` by the time
// `VerifyStart::Pending` is reached -- before `collect_device_snapshot()`,
// `check_target()`, or `OpenDevice(mode="r")` are ever called (see the early
// cancel check in `run_write_test`). Deliberately does not claim any FD/D-Bus
// state was opened-then-closed: none of it was ever opened at all.
fn format_verify_cancelled_before_start() -> Vec<String> {
    vec![
        "verification was cancelled before it could start.".to_string(),
        "write + sync already completed successfully; the target was not re-opened for verification."
            .to_string(),
    ]
}

// PoC mode: Writer self-test (`cargo run -- writer-test`). Exercises the
// Writer Core (src/writer.rs) end to end against a throwaway *regular file*
// only — never a block device. The target path is always chosen by this
// function itself (under the OS temp directory, named with this process's
// PID), never taken from a CLI argument, specifically so this mode cannot be
// pointed at /dev/* by accident or by a caller's mistake. The temporary file
// is removed before returning, whether the test passes or fails.
fn run_writer_test() -> zbus::Result<()> {
    let temp_path = std::env::temp_dir().join(format!(
        "linux-usb-writer-selftest-{}.bin",
        std::process::id()
    ));

    let result = run_writer_test_inner(&temp_path);
    let cleanup_result = std::fs::remove_file(&temp_path);

    match &result {
        Ok(()) => println!("\nwriter-test: PASSED"),
        Err(message) => println!("\nwriter-test: FAILED -- {message}"),
    }

    match cleanup_result {
        Ok(()) => println!("Temporary file removed: {}", temp_path.display()),
        Err(error) => println!(
            "Temporary file cleanup failed for {}: {error}",
            temp_path.display()
        ),
    }

    Ok(())
}

fn run_writer_test_inner(temp_path: &std::path::Path) -> Result<(), String> {
    const PATTERN_SIZE: usize = 4 * 1024 * 1024; // 4 MiB known pattern, regular file only.

    let data: Vec<u8> = (0..PATTERN_SIZE).map(|i| (i % 256) as u8).collect();

    let plan = writer::WritePlan::new(
        data.len() as u64,
        data.len() as u64,
        writer::DEFAULT_CHUNK_SIZE,
    )
    .map_err(|error| format!("plan rejected: {error:?}"))?;

    println!(
        "writer-test: temporary target file: {}",
        temp_path.display()
    );
    println!(
        "writer-test: image size = {} bytes, chunk size = {} bytes",
        data.len(),
        plan.chunk_size
    );

    let target_file = std::fs::File::create(temp_path)
        .map_err(|error| format!("failed to create temp file: {error}"))?;

    let source = std::io::Cursor::new(data.clone());

    let written = writer::write(
        &plan,
        source,
        target_file,
        |progress| {
            println!(
                "writer-test: progress {}/{} bytes",
                progress.bytes_written, progress.total_bytes
            );
        },
        || false,
    )
    .map_err(|error| format!("write failed: {error:?}"))?;

    println!("writer-test: wrote and flushed {written} bytes");

    let written_file = std::fs::File::open(temp_path)
        .map_err(|error| format!("failed to reopen temp file for read-back: {error}"))?;

    let matches = writer::verify_equal(std::io::Cursor::new(data), written_file)
        .map_err(|error| format!("read-back comparison failed: {error}"))?;

    if !matches {
        return Err("read-back data did not match the original pattern".to_string());
    }

    println!("writer-test: read-back verified byte-for-byte identical to the original pattern");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::confirmation_matches;
    use super::{
        OffMainThread, PromptInput, WriteTestArgsError, WriteTestExit, exit_after_successful_sync,
        format_cancelled_after_sync, format_cancelled_before_confirmation, format_hard_hazards,
        format_identity_comparison, format_image_format_rejected, format_instance_comparison,
        format_sync_worker_panicked, format_verify_cancelled, format_verify_cancelled_before_start,
        format_verify_diagnostics_summary, format_verify_diagnostics_unavailable,
        format_verify_failure_reason, format_verify_succeeded, format_write_cancelled,
        parse_verify_mode, parse_write_test_trailing_args, run_off_main_thread,
        wait_for_prompt_input, write_test_exit_code,
    };
    use crate::device::DeviceSnapshot;
    use crate::execution::core::{self, HardHazardReason, VerifyMode};
    use crate::execution::write_job::{
        CancelHandle, CancelReason, Cancelled, VerifyCancelled, VerifyFailureReason,
        VerifySucceeded,
    };
    use crate::identity::{IdentityComparison, InstanceComparison};
    use crate::image_source::source_identity::SourceChanged;
    use std::cell::Cell;
    use std::sync::mpsc;
    use std::time::Duration;

    // ---------------------------------------------------------------------
    // Which `OpenAccess` each OpenDevice call site uses. The call sites are
    // D-Bus calls that cannot run in a test, so their source text is checked
    // instead: every read-write FD (open-test, prepare-test, the write in
    // write-test) is `WriteExclusive` (O_EXCL), and the Verify FD is
    // `ReadOnly` (never exclusive).
    // ---------------------------------------------------------------------

    // This file's code above its test module.
    fn production_source() -> &'static str {
        let source = include_str!("main.rs");
        let end = source
            .find("\n#[cfg(test)]\nmod tests {")
            .expect("test module marker");
        &source[..end]
    }

    // The source of the top-level `fn name(...)`, up to its closing brace.
    fn production_fn_source(name: &str) -> &'static str {
        let production = production_source();
        let start = production
            .find(&format!("\nfn {name}("))
            .unwrap_or_else(|| panic!("fn {name} not found"))
            + 1;
        let length = production[start..]
            .find("\n}\n")
            .unwrap_or_else(|| panic!("end of fn {name} not found"));
        &production[start..start + length]
    }

    #[test]
    fn every_open_device_call_uses_the_intended_access() {
        let production = production_source();
        assert_eq!(
            production.matches("linux_access::open_device(").count(),
            4,
            "a new OpenDevice call site must be added to this test"
        );

        for name in ["run_open_test", "run_prepare_test"] {
            let source = production_fn_source(name);
            assert_eq!(
                source.matches("OpenAccess::WriteExclusive").count(),
                1,
                "{name}"
            );
            assert_eq!(source.matches("OpenAccess::ReadOnly").count(), 0, "{name}");
        }

        // write-test: the write FD is exclusive, and the Verify FD opened
        // after it is read-only.
        let write_test = production_fn_source("run_write_test");
        assert_eq!(write_test.matches("OpenAccess::WriteExclusive").count(), 1);
        assert_eq!(write_test.matches("OpenAccess::ReadOnly").count(), 1);
        let write = write_test.find("OpenAccess::WriteExclusive").unwrap();
        let verify = write_test.find("OpenAccess::ReadOnly").unwrap();
        assert!(
            write < verify,
            "the write FD is opened before the Verify FD"
        );
    }

    // A. Exact match -> true.
    #[test]
    fn exact_match_confirms() {
        assert!(confirmation_matches("/dev/sdb", "/dev/sdb"));
    }

    // B. A trailing newline (as `read_line` always includes one) is
    // trimmed before comparing -> still true.
    #[test]
    fn trailing_newline_is_trimmed_before_comparing() {
        assert!(confirmation_matches("/dev/sdb\n", "/dev/sdb"));
        assert!(confirmation_matches("/dev/sdb\r\n", "/dev/sdb"));
    }

    // C. A different, even superficially similar, device string -> false.
    #[test]
    fn wrong_device_does_not_confirm() {
        assert!(!confirmation_matches("/dev/sdc", "/dev/sdb"));
        assert!(!confirmation_matches("/dev/sdb1", "/dev/sdb"));
    }

    // D. No "y"/"yes" shortcut -- only the exact device string confirms.
    #[test]
    fn yes_or_y_does_not_confirm() {
        assert!(!confirmation_matches("yes\n", "/dev/sdb"));
        assert!(!confirmation_matches("y\n", "/dev/sdb"));
    }

    // E. Empty input (including EOF, which this function never sees
    // directly since `run_write_test` special-cases it, but an empty
    // trimmed string must still never match a non-empty device) -> false.
    #[test]
    fn empty_input_does_not_confirm() {
        assert!(!confirmation_matches("", "/dev/sdb"));
        assert!(!confirmation_matches("\n", "/dev/sdb"));
    }

    // ---------------------------------------------------------------------
    // parse_verify_mode / format_verify_succeeded / format_verify_failure_reason
    // (Built-in Verify implementation step 5: write-test CLI wiring)
    // ---------------------------------------------------------------------

    // F. Each of the three documented CLI names parses to the matching
    // VerifyMode.
    #[test]
    fn parse_verify_mode_accepts_the_three_known_names() {
        assert_eq!(parse_verify_mode("none"), Some(VerifyMode::None));
        assert_eq!(parse_verify_mode("quick"), Some(VerifyMode::Quick));
        assert_eq!(parse_verify_mode("full"), Some(VerifyMode::Full));
    }

    // G. Unknown values are rejected with None, never a silent fallback to
    // any particular mode.
    #[test]
    fn parse_verify_mode_rejects_unknown_values() {
        assert_eq!(parse_verify_mode("foo"), None);
        assert_eq!(parse_verify_mode("fast"), None);
        assert_eq!(parse_verify_mode("sha256"), None);
        assert_eq!(parse_verify_mode(""), None);
    }

    // H. Case sensitivity policy: lowercase only, fixed deliberately (see
    // `parse_verify_mode`'s own doc comment) -- any other casing is rejected
    // exactly like any other unknown value, not accepted as a convenience.
    #[test]
    fn parse_verify_mode_rejects_non_lowercase_casing() {
        assert_eq!(parse_verify_mode("None"), None);
        assert_eq!(parse_verify_mode("QUICK"), None);
        assert_eq!(parse_verify_mode("Full"), None);
    }

    // I. VerifyMode::None success formats as the documented "skipped"
    // message.
    #[test]
    fn format_verify_succeeded_none_reports_skipped() {
        let succeeded = VerifySucceeded {
            mode: VerifyMode::None,
            verified_bytes: 0,
            skipped: true,
        };
        assert_eq!(format_verify_succeeded(&succeeded), "Verification: skipped");
    }

    // J. Quick success reports the sampled byte count, worded as "sampled"
    // -- never implying the whole image was checked.
    #[test]
    fn format_verify_succeeded_quick_reports_sampled_bytes() {
        let succeeded = VerifySucceeded {
            mode: VerifyMode::Quick,
            verified_bytes: 12_582_912,
            skipped: false,
        };
        assert_eq!(
            format_verify_succeeded(&succeeded),
            "Quick verification succeeded (12582912 bytes sampled)"
        );
    }

    // K. Full success reports the verified byte count, worded as
    // "verified".
    #[test]
    fn format_verify_succeeded_full_reports_verified_bytes() {
        let succeeded = VerifySucceeded {
            mode: VerifyMode::Full,
            verified_bytes: 1_828_716_544,
            skipped: false,
        };
        assert_eq!(
            format_verify_succeeded(&succeeded),
            "Full verification succeeded (1828716544 bytes verified)"
        );
    }

    // L. A Mismatch failure's formatted text includes the offset and both
    // the expected and actual byte values.
    #[test]
    fn format_verify_failure_reason_mismatch_reports_offset_and_bytes() {
        let reason = VerifyFailureReason::Mismatch {
            offset: 123456,
            expected: 0x12,
            actual: 0x34,
        };
        let formatted = format_verify_failure_reason(&reason);
        assert!(formatted.contains("123456"));
        assert!(formatted.contains("0x12"));
        assert!(formatted.contains("0x34"));
    }

    // M. Source vs. target EOF/read-error messages are distinguishable from
    // one another -- a user (or a future automated triage) should be able to
    // tell which side failed from the text alone.
    #[test]
    fn format_verify_failure_reason_distinguishes_source_and_target_eof() {
        let source = format_verify_failure_reason(&VerifyFailureReason::SourceUnexpectedEof);
        let target = format_verify_failure_reason(&VerifyFailureReason::TargetUnexpectedEof);
        assert!(source.contains("image source"));
        assert!(target.contains("target device"));
        assert_ne!(source, target);
    }

    // N. UnsupportedAccess's message makes clear that Quick specifically
    // needs random-access support, so a user understands why Quick (and not
    // necessarily Full) failed for this image.
    #[test]
    fn format_verify_failure_reason_unsupported_access_mentions_random_access() {
        let formatted = format_verify_failure_reason(&VerifyFailureReason::UnsupportedAccess);
        assert!(formatted.to_lowercase().contains("random"));
    }

    // A source change at a Verify checkpoint says the image changed and that
    // the verification result was not accepted, without naming a cause.
    #[test]
    fn format_verify_failure_reason_source_changed_rejects_the_result() {
        let changed = SourceChanged::Unverifiable(std::io::Error::other("simulated"));
        let formatted = format_verify_failure_reason(&VerifyFailureReason::SourceChanged(changed));
        assert!(formatted.contains("image file"));
        assert!(formatted.contains("not accepted"));
    }

    // ---------------------------------------------------------------------
    // Verify Pre-flight Diagnostics CLI display (implementation step 5+6)
    // ---------------------------------------------------------------------

    fn base_snapshot() -> DeviceSnapshot {
        DeviceSnapshot {
            device: "/dev/sdx".to_string(),
            block_path: "/org/freedesktop/UDisks2/block_devices/sdx".to_string(),
            drive_path: "/org/freedesktop/UDisks2/drives/Test_Model_TEST-SERIAL-0001".to_string(),
            major: 8,
            minor: 0,
            diskseq: Some(12),
            size: 8_000_000_000,
            read_only: false,
            media_available: true,
            model: "Test Model".to_string(),
            vendor: "Test Vendor".to_string(),
            serial: "TEST-SERIAL-0001".to_string(),
            connection_bus: "usb".to_string(),
            removable: true,
            hint_system: false,
            hint_ignore: false,
            hint_partitionable: true,
            mount_points: Vec::new(),
            active_swap: false,
            swap_devices: Vec::new(),
            complex_storage: false,
            complex_storage_details: Vec::new(),
        }
    }

    // O. An unchanged snapshot (Identity Same, Instance SameInstance, no
    // mount/read-only change, no hazards) produces the exact five-line
    // "everything is fine" summary.
    #[test]
    fn format_verify_diagnostics_summary_for_unchanged_snapshot() {
        let baseline = base_snapshot();
        let current = base_snapshot();
        let diagnostics = core::diagnose_identity_instance_for_verify(&baseline, &current);

        assert_eq!(
            format_verify_diagnostics_summary(&diagnostics),
            vec![
                "identity: Same".to_string(),
                "instance: SameInstance".to_string(),
                "mount points: unchanged (none)".to_string(),
                "read-only: unchanged (false)".to_string(),
                "hazards: none".to_string(),
            ]
        );
    }

    // P. mount_points growing from empty to a single path -- the real
    // post-write auto-mount scenario -- is shown as a `before -> after`
    // diff, and does not appear as a hazard.
    #[test]
    fn format_verify_diagnostics_summary_reports_a_newly_mounted_filesystem() {
        let baseline = base_snapshot();
        let mut current = base_snapshot();
        current.mount_points = vec!["/media/test/MYPOCKETOS".to_string()];
        let diagnostics = core::diagnose_identity_instance_for_verify(&baseline, &current);

        let lines = format_verify_diagnostics_summary(&diagnostics);
        assert!(lines.contains(&"mount points: none -> /media/test/MYPOCKETOS".to_string()));
        assert!(lines.contains(&"hazards: none".to_string()));
    }

    // Q. Multiple mount points are listed in a deterministic,
    // comma-separated order (the same order `DeviceSnapshot.mount_points`
    // itself carries them in -- this formatter never sorts or reorders).
    #[test]
    fn format_verify_diagnostics_summary_lists_multiple_mount_points_in_order() {
        let baseline = base_snapshot();
        let mut current = base_snapshot();
        current.mount_points = vec![
            "/media/test/MYPOCKETOS".to_string(),
            "/media/test/MYPOCKETOS-EFI".to_string(),
        ];
        let diagnostics = core::diagnose_identity_instance_for_verify(&baseline, &current);

        let lines = format_verify_diagnostics_summary(&diagnostics);
        assert!(lines.contains(
            &"mount points: none -> /media/test/MYPOCKETOS, /media/test/MYPOCKETOS-EFI".to_string()
        ));
    }

    // R. `read_only` going from `false` to `true` is shown as a
    // `before -> after` diff, and (per Step 3's deliberate design) is never
    // itself a hazard.
    #[test]
    fn format_verify_diagnostics_summary_reports_read_only_becoming_true() {
        let baseline = base_snapshot();
        let mut current = base_snapshot();
        current.read_only = true;
        let diagnostics = core::diagnose_identity_instance_for_verify(&baseline, &current);

        let lines = format_verify_diagnostics_summary(&diagnostics);
        assert!(lines.contains(&"read-only: false -> true".to_string()));
        assert!(lines.contains(&"hazards: none".to_string()));
    }

    // S. A single hazard is rendered as its human-readable text, not the
    // raw Rust enum name.
    #[test]
    fn format_verify_diagnostics_summary_reports_a_single_hazard() {
        let baseline = base_snapshot();
        let mut current = base_snapshot();
        current.hint_system = true;
        let diagnostics = core::diagnose_identity_instance_for_verify(&baseline, &current);

        let lines = format_verify_diagnostics_summary(&diagnostics);
        assert!(lines.contains(&"hazards: system device".to_string()));
    }

    // T. Multiple simultaneous hazards are listed in the same deterministic
    // order `core::verify_target_hard_hazards` produces them in.
    #[test]
    fn format_verify_diagnostics_summary_lists_multiple_hazards_in_deterministic_order() {
        let baseline = base_snapshot();
        let mut current = base_snapshot();
        current.complex_storage = true;
        current.active_swap = true;
        let diagnostics = core::diagnose_identity_instance_for_verify(&baseline, &current);

        let lines = format_verify_diagnostics_summary(&diagnostics);
        assert!(lines.contains(&"hazards: active swap, complex storage".to_string()));
    }

    // U. Every `IdentityComparison` variant has a distinct, deterministic
    // rendering -- including both rejection cases, not just `Same`.
    #[test]
    fn format_identity_comparison_covers_every_variant() {
        assert_eq!(format_identity_comparison(IdentityComparison::Same), "Same");
        assert_eq!(
            format_identity_comparison(IdentityComparison::Changed),
            "Changed (different device)"
        );
        assert_eq!(
            format_identity_comparison(IdentityComparison::InsufficientIdentity),
            "Insufficient (no usable serial to compare)"
        );
    }

    // V. Every `InstanceComparison` variant has a distinct, deterministic
    // rendering -- including both rejection cases, not just `SameInstance`.
    #[test]
    fn format_instance_comparison_covers_every_variant() {
        assert_eq!(
            format_instance_comparison(InstanceComparison::SameInstance),
            "SameInstance"
        );
        assert_eq!(
            format_instance_comparison(InstanceComparison::Recreated),
            "Recreated (disconnected and reconnected)"
        );
        assert_eq!(
            format_instance_comparison(InstanceComparison::InsufficientInformation),
            "Insufficient (no diskseq to compare)"
        );
    }

    // W. `format_hard_hazards` itself: empty, single, and multiple-reason
    // cases, independent of the full summary wiring above.
    #[test]
    fn format_hard_hazards_lists_every_reason_in_order() {
        assert_eq!(format_hard_hazards(&[]), "none");
        assert_eq!(
            format_hard_hazards(&[HardHazardReason::SystemDevice]),
            "system device"
        );
        assert_eq!(
            format_hard_hazards(&[
                HardHazardReason::ActiveSwap,
                HardHazardReason::ComplexStorage
            ]),
            "active swap, complex storage"
        );
    }

    // X. When `check_target()` rejected with `SnapshotRefreshFailed`, no
    // `VerifyTargetDiagnostics` exists -- the fallback text says so plainly,
    // rather than guessing at values that were never fetched.
    #[test]
    fn format_verify_diagnostics_unavailable_reports_no_snapshot() {
        assert_eq!(
            format_verify_diagnostics_unavailable(),
            vec!["no fresh device snapshot was available for diagnostics".to_string()]
        );
    }

    // ---------------------------------------------------------------------
    // parse_write_test_trailing_args (--test-pause-before-verify)
    // ---------------------------------------------------------------------

    // Y1. `full` + the flag is accepted.
    #[test]
    fn parse_write_test_trailing_args_accepts_full_with_test_pause() {
        assert_eq!(
            parse_write_test_trailing_args(Some("full"), Some("--test-pause-before-verify")),
            Ok((VerifyMode::Full, true))
        );
    }

    // Y2. `quick` + the flag is accepted.
    #[test]
    fn parse_write_test_trailing_args_accepts_quick_with_test_pause() {
        assert_eq!(
            parse_write_test_trailing_args(Some("quick"), Some("--test-pause-before-verify")),
            Ok((VerifyMode::Quick, true))
        );
    }

    // Y3. `none` + the flag is rejected outright -- `VerifyMode::None` never
    // produces `VerifyStart::Pending`, so the flag would have no effect.
    #[test]
    fn parse_write_test_trailing_args_rejects_none_with_test_pause() {
        assert_eq!(
            parse_write_test_trailing_args(Some("none"), Some("--test-pause-before-verify")),
            Err(WriteTestArgsError::TestPauseRequiresVerification)
        );
    }

    // Y4. An unrecognized fourth token is rejected, never silently ignored.
    #[test]
    fn parse_write_test_trailing_args_rejects_unknown_fourth_token() {
        assert_eq!(
            parse_write_test_trailing_args(Some("full"), Some("--bogus-flag")),
            Err(WriteTestArgsError::UnrecognizedFourthArgument)
        );
    }

    // Y5. No fourth argument at all -> existing behavior (flag disabled),
    // for every verify-mode including the absent (default) case.
    #[test]
    fn parse_write_test_trailing_args_without_fourth_argument_matches_existing_behavior() {
        assert_eq!(
            parse_write_test_trailing_args(None, None),
            Ok((VerifyMode::None, false))
        );
        assert_eq!(
            parse_write_test_trailing_args(Some("quick"), None),
            Ok((VerifyMode::Quick, false))
        );
        assert_eq!(
            parse_write_test_trailing_args(Some("full"), None),
            Ok((VerifyMode::Full, false))
        );
    }

    // Y6. Existing verify-mode parsing (absent -> None, unknown -> rejected)
    // is preserved unchanged through the new combined parser.
    #[test]
    fn parse_write_test_trailing_args_verify_mode_parsing_has_no_regression() {
        assert_eq!(
            parse_write_test_trailing_args(Some("none"), None),
            Ok((VerifyMode::None, false))
        );
        assert_eq!(
            parse_write_test_trailing_args(Some("bogus"), None),
            Err(WriteTestArgsError::InvalidVerifyMode)
        );
        // An invalid verify-mode is reported even when a fourth argument is
        // also present -- verify-mode is validated first.
        assert_eq!(
            parse_write_test_trailing_args(Some("bogus"), Some("--test-pause-before-verify")),
            Err(WriteTestArgsError::InvalidVerifyMode)
        );
    }

    // ---------------------------------------------------------------------
    // Cancel (Ctrl+C) CLI messaging and exit code (Cancel機能 Ctrl+C実配線
    // implementation). Shared-`CancelHandle` behavior itself (clone sees the
    // same `request_cancel()`) is already covered extensively by
    // `execution::write_job`'s own tests (e.g.
    // `cancel_partway_through_multiple_chunks_reports_partial_progress`,
    // which clones a handle into the write loop and calls `request_cancel()`
    // from the original) -- not duplicated here.
    // ---------------------------------------------------------------------

    // Z1. A write cancelled after a partial write reports the exact
    // bytes_written/image_size pair, and unconditionally states that the
    // target may be partial and that verification was not attempted.
    #[test]
    fn format_write_cancelled_reports_partial_bytes_and_no_verification() {
        let cancelled = Cancelled {
            image_size: 1_000_000,
            bytes_written: 400_000,
            reason: CancelReason::UserRequested,
            target_may_be_modified: true,
            retry_requires_fresh_gate: true,
        };

        assert_eq!(
            format_write_cancelled(&cancelled),
            vec![
                "write cancelled after 400000 of 1000000 bytes".to_string(),
                "target may contain a partial image".to_string(),
                "verification was not attempted".to_string(),
            ]
        );
    }

    // Z2. A write cancelled before any chunk completed (bytes_written == 0,
    // target_may_be_modified == false) is still reported as a cancellation,
    // but says no data was written -- never "partial image", and never "not
    // opened" (the target was opened read-write by then).
    #[test]
    fn format_write_cancelled_reports_zero_bytes_before_any_chunk() {
        let cancelled = Cancelled {
            image_size: 1_000_000,
            bytes_written: 0,
            reason: CancelReason::UserRequested,
            target_may_be_modified: false,
            retry_requires_fresh_gate: true,
        };

        let lines = format_write_cancelled(&cancelled);
        assert_eq!(
            lines,
            vec![
                "write cancelled after 0 of 1000000 bytes".to_string(),
                "no data was written to the target device".to_string(),
                "verification was not attempted".to_string(),
            ]
        );
        assert!(lines.iter().all(|line| !line.contains("partial image")));
        assert!(lines.iter().all(|line| !line.contains("not opened")));
    }

    // Z2b. Defensive: if `target_may_be_modified` is true even though
    // `bytes_written == 0` (not produced by today's `Writing::write()`, but
    // the field is the safety-biased authority), the safe-side "partial
    // image" wording wins.
    #[test]
    fn format_write_cancelled_zero_bytes_but_possibly_modified_reports_partial() {
        let cancelled = Cancelled {
            image_size: 1_000_000,
            bytes_written: 0,
            reason: CancelReason::UserRequested,
            target_may_be_modified: true,
            retry_requires_fresh_gate: true,
        };

        let lines = format_write_cancelled(&cancelled);
        assert_eq!(lines[1], "target may contain a partial image");
        assert!(
            lines
                .iter()
                .all(|line| !line.contains("no data was written"))
        );
    }

    // Z2c. Defensive in the other direction: bytes were written but the flag
    // says unmodified (also not produced today) -- still "partial image".
    #[test]
    fn format_write_cancelled_bytes_written_without_flag_reports_partial() {
        let cancelled = Cancelled {
            image_size: 1_000_000,
            bytes_written: 4096,
            reason: CancelReason::UserRequested,
            target_may_be_modified: false,
            retry_requires_fresh_gate: true,
        };

        assert_eq!(
            format_write_cancelled(&cancelled)[1],
            "target may contain a partial image"
        );
    }

    // Z2d. Cancelled before confirmation: states the target was neither
    // opened nor modified.
    #[test]
    fn format_cancelled_before_confirmation_states_target_untouched() {
        assert_eq!(
            format_cancelled_before_confirmation(),
            vec![
                "cancelled before confirmation.".to_string(),
                "the target device has not been opened or modified.".to_string(),
            ]
        );
    }

    // Z2e. Cancelled during sync: states sync finished, the full image is on
    // the target, and verification was not started -- never "partial".
    #[test]
    fn format_cancelled_after_sync_states_full_image_and_no_verification() {
        let lines = format_cancelled_after_sync();

        assert_eq!(
            lines,
            vec![
                "cancellation was requested during sync; sync was allowed to finish.".to_string(),
                "write + sync completed successfully; the full image is on the target.".to_string(),
                "verification was not started.".to_string(),
            ]
        );
        assert!(lines.iter().all(|line| !line.contains("partial")));
    }

    // ---------------------------------------------------------------------
    // Image format refusals (XZ/GZIP Phase 1): pure formatters only.
    // ---------------------------------------------------------------------

    // F2. An unsupported format names the format and says it was not treated
    // as raw; the target was not touched.
    #[test]
    fn format_image_format_rejected_for_unsupported_format() {
        let error = crate::image_source::ImageSourceError::UnsupportedFormat(
            crate::image_source::UnsupportedCompression::Zstd,
        );

        assert_eq!(
            format_image_format_rejected(&error),
            vec![
                "the image is zstd data, which is not supported; it was not treated as a raw image."
                    .to_string(),
                "the target device has not been opened or modified.".to_string(),
            ]
        );
    }

    // F3. An extension mismatch names the promised format and refuses raw.
    #[test]
    fn format_image_format_rejected_for_extension_mismatch() {
        let error = crate::image_source::ImageSourceError::ExtensionMismatch {
            expected: crate::image_source::CompressionFormat::Xz,
        };

        let lines = format_image_format_rejected(&error);
        assert_eq!(
            lines[0],
            "the file name says xz but the content is not xz data; refusing to write it as a raw image."
        );
        assert_eq!(
            lines[1],
            "the target device has not been opened or modified."
        );
    }

    // ---------------------------------------------------------------------
    // Sync off the main thread (S1): `run_off_main_thread` is exercised with
    // plain closures standing in for `Syncing::sync()` -- no block device,
    // no fsync. The real call site's `Syncing`/`SyncAttemptOutcome` Send
    // bounds are enforced by the compiler at that call site itself.
    // ---------------------------------------------------------------------

    // S1a. A successful result is returned to the caller unchanged, and the
    // work ran on a thread other than the caller's.
    #[test]
    fn off_main_thread_returns_success_from_another_thread() {
        let caller = std::thread::current().id();

        match run_off_main_thread(21u32, |value| (value * 2, std::thread::current().id())) {
            OffMainThread::Finished((result, worker)) => {
                assert_eq!(result, 42);
                assert_ne!(worker, caller, "work must not run on the calling thread");
            }
            other => panic!("expected Finished, got {other:?}"),
        }
    }

    // S1b. An error result (the stand-in for `SyncAttemptOutcome::Failed`) is
    // returned as-is -- `Finished`, not `Panicked`: a failure the work
    // reported is a result, not a crash.
    #[test]
    fn off_main_thread_returns_error_result_unchanged() {
        let outcome = run_off_main_thread((), |()| -> Result<(), std::io::Error> {
            Err(std::io::Error::other("sync failed"))
        });

        match outcome {
            OffMainThread::Finished(Err(error)) => assert_eq!(error.to_string(), "sync failed"),
            other => panic!("expected Finished(Err), got {other:?}"),
        }
    }

    // S1c. A panic in the worker is reported as `Panicked` instead of
    // propagating into the caller. (The panic message printed to stderr by
    // the default hook is expected test output.)
    #[test]
    fn off_main_thread_reports_worker_panic() {
        let outcome = run_off_main_thread((), |()| -> u32 {
            panic!("simulated sync worker panic");
        });

        assert!(matches!(outcome, OffMainThread::Panicked));
    }

    // S1d. The caller blocks until the work has fully finished -- the work is
    // never abandoned or interrupted, even if it takes a while.
    #[test]
    fn off_main_thread_waits_for_work_to_complete() {
        let outcome = run_off_main_thread(Duration::from_millis(30), |delay| {
            std::thread::sleep(delay);
            "done"
        });

        assert!(matches!(outcome, OffMainThread::Finished("done")));
    }

    // S1e. After a successful sync: cancellation requested -> Cancelled
    // (exit 130); not requested -> continue into Verify.
    #[test]
    fn exit_after_successful_sync_follows_cancel_flag() {
        assert_eq!(
            exit_after_successful_sync(true),
            Some(WriteTestExit::Cancelled)
        );
        assert_eq!(write_test_exit_code(WriteTestExit::Cancelled), Some(130));
        assert_eq!(exit_after_successful_sync(false), None);
    }

    // S1f. A panicked sync worker is reported as a sync failure: it never
    // claims success or a full, synced image.
    #[test]
    fn format_sync_worker_panicked_reports_failure_without_claiming_durability() {
        let lines = format_sync_worker_panicked();

        assert!(lines[0].starts_with("sync FAILED"));
        assert!(
            lines
                .iter()
                .any(|line| line.contains("durability is not confirmed"))
        );
        assert!(lines.iter().all(|line| !line.contains("succeeded")));
    }

    // ---------------------------------------------------------------------
    // Human Confirmation prompt wait (D3): `wait_for_prompt_input` is driven
    // here with a plain channel and a plain closure -- no stdin, no terminal,
    // no signal. A 1 ms poll interval keeps the waiting tests fast.
    // ---------------------------------------------------------------------

    const TEST_POLL: Duration = Duration::from_millis(1);

    // P1. A line that arrives with no cancellation is returned unchanged.
    #[test]
    fn prompt_wait_returns_line() {
        let (sender, receiver) = mpsc::channel();
        sender
            .send(PromptInput::Line("/dev/sdb\n".to_string()))
            .unwrap();

        match wait_for_prompt_input(&receiver, || false, TEST_POLL) {
            PromptInput::Line(line) => assert_eq!(line, "/dev/sdb\n"),
            other => panic!("expected Line, got {other:?}"),
        }
    }

    // P2. EOF is passed through as Eof (never treated as a confirmation).
    #[test]
    fn prompt_wait_returns_eof() {
        let (sender, receiver) = mpsc::channel();
        sender.send(PromptInput::Eof).unwrap();

        assert!(matches!(
            wait_for_prompt_input(&receiver, || false, TEST_POLL),
            PromptInput::Eof
        ));
    }

    // P3. A read error is passed through as Error.
    #[test]
    fn prompt_wait_returns_input_error() {
        let (sender, receiver) = mpsc::channel();
        sender
            .send(PromptInput::Error(std::io::Error::other("boom")))
            .unwrap();

        match wait_for_prompt_input(&receiver, || false, TEST_POLL) {
            PromptInput::Error(error) => assert_eq!(error.to_string(), "boom"),
            other => panic!("expected Error, got {other:?}"),
        }
    }

    // P4. Cancellation requested while waiting (no input ever arrives; the
    // sender stays alive, like a reader thread blocked in read_line) ends the
    // wait with Cancelled after a few polls.
    #[test]
    fn prompt_wait_returns_cancelled_when_cancel_arrives_while_waiting() {
        let (_sender, receiver) = mpsc::channel::<PromptInput>();
        let checks = Cell::new(0u32);

        let result = wait_for_prompt_input(
            &receiver,
            || {
                checks.set(checks.get() + 1);
                checks.get() > 3
            },
            TEST_POLL,
        );

        assert!(matches!(result, PromptInput::Cancelled));
        assert!(checks.get() > 3, "must have polled before cancelling");
    }

    // P4b. Same, driven by a real `CancelHandle` from another thread -- the
    // exact `|| cancel.is_requested()` shape `run_write_test` uses.
    #[test]
    fn prompt_wait_observes_cancel_handle_from_another_thread() {
        let (_sender, receiver) = mpsc::channel::<PromptInput>();
        let cancel = CancelHandle::new();
        let remote = cancel.clone();

        let canceller = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(20));
            remote.request_cancel(CancelReason::UserRequested);
        });

        let result = wait_for_prompt_input(&receiver, || cancel.is_requested(), TEST_POLL);
        canceller.join().unwrap();

        assert!(matches!(result, PromptInput::Cancelled));
    }

    // P5. Already cancelled before waiting starts: Cancelled, even though a
    // (correct) line is already queued.
    #[test]
    fn prompt_wait_returns_cancelled_when_already_cancelled() {
        let (sender, receiver) = mpsc::channel();
        sender
            .send(PromptInput::Line("/dev/sdb\n".to_string()))
            .unwrap();

        assert!(matches!(
            wait_for_prompt_input(&receiver, || true, TEST_POLL),
            PromptInput::Cancelled
        ));
    }

    // P6. Input and cancellation at (nearly) the same moment: the first
    // check sees no cancellation, the line is received, and the re-check
    // right after receipt sees it -- cancellation wins and the line is
    // discarded.
    #[test]
    fn prompt_wait_prefers_cancel_over_simultaneous_input() {
        let (sender, receiver) = mpsc::channel();
        sender
            .send(PromptInput::Line("/dev/sdb\n".to_string()))
            .unwrap();
        let checks = Cell::new(0u32);

        let result = wait_for_prompt_input(
            &receiver,
            || {
                checks.set(checks.get() + 1);
                checks.get() > 1
            },
            TEST_POLL,
        );

        assert!(matches!(result, PromptInput::Cancelled));
        assert_eq!(checks.get(), 2);
    }

    // P7. The reader ended without sending anything: reported as Error, never
    // as a confirmation -- unless a cancellation was requested, which wins.
    #[test]
    fn prompt_wait_disconnected_reader_is_error_or_cancelled() {
        let (sender, receiver) = mpsc::channel::<PromptInput>();
        drop(sender);
        assert!(matches!(
            wait_for_prompt_input(&receiver, || false, TEST_POLL),
            PromptInput::Error(_)
        ));

        let (sender, receiver) = mpsc::channel::<PromptInput>();
        drop(sender);
        let checks = Cell::new(0u32);
        let result = wait_for_prompt_input(
            &receiver,
            || {
                checks.set(checks.get() + 1);
                checks.get() > 1
            },
            TEST_POLL,
        );
        assert!(matches!(result, PromptInput::Cancelled));
    }

    // Z3. A cancelled Full Verify reports "Full", the bytes actually
    // verified, and the caller-supplied total (not `image.logical_size()`
    // directly, since Quick's total legitimately differs -- see Z4) -- and
    // states that the already-written image remains on the target.
    #[test]
    fn format_verify_cancelled_reports_full_mode_and_total() {
        let cancelled = VerifyCancelled {
            mode: VerifyMode::Full,
            verified_bytes: 500_000,
        };

        assert_eq!(
            format_verify_cancelled(&cancelled, 1_000_000),
            vec![
                "Full verification cancelled after 500000 of 1000000 bytes".to_string(),
                "written image remains on the target".to_string(),
            ]
        );
    }

    // Z4. A cancelled Quick Verify reports "Quick" and the sampled total
    // (e.g. 12 MiB for a 16 MiB image), never the full image size.
    #[test]
    fn format_verify_cancelled_reports_quick_mode_and_sampled_total() {
        let cancelled = VerifyCancelled {
            mode: VerifyMode::Quick,
            verified_bytes: 4_194_304,
        };

        let lines = format_verify_cancelled(&cancelled, 12_582_912);
        assert_eq!(
            lines[0],
            "Quick verification cancelled after 4194304 of 12582912 bytes"
        );
    }

    // Z5. The pre-verify early-cancel message never implies any FD or D-Bus
    // state was opened and then closed -- nothing was ever opened.
    #[test]
    fn format_verify_cancelled_before_start_does_not_mention_fd_or_opendevice() {
        let lines = format_verify_cancelled_before_start();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("cancelled before it could start"));
        assert!(lines[1].contains("write + sync already completed successfully"));
        for line in &lines {
            assert!(!line.to_lowercase().contains("opendevice"));
            assert!(!line.to_lowercase().contains("fd"));
        }
    }

    // Z6. `WriteTestExit::Cancelled` maps to exit code 130 (128 + SIGINT),
    // the conventional Unix code for a signal-interrupted process.
    #[test]
    fn write_test_exit_code_maps_cancelled_to_130() {
        assert_eq!(write_test_exit_code(WriteTestExit::Cancelled), Some(130));
    }

    // Z7. `WriteTestExit::Completed` maps to `None`, telling the caller to
    // let `main` exit the ordinary way (code 0) rather than calling
    // `std::process::exit` at all.
    #[test]
    fn write_test_exit_code_maps_completed_to_none() {
        assert_eq!(write_test_exit_code(WriteTestExit::Completed), None);
    }

    // ---------------------------------------------------------------------
    // gzip preparation (Quick L1, Preflight, post-Preflight source check)
    // and the post-Preflight target re-check. All of this happens before
    // the target is opened, so a rejection here cannot touch the target.
    // ---------------------------------------------------------------------

    use super::{
        CompressedImageRejection, format_compressed_image_rejected, format_preflight_progress,
        prepare_compressed_image,
    };
    use crate::image_source::compressed::{PreflightError, PreflightProgress};
    use crate::image_source::{
        CompressedImageFile, ImageSource, ImageSourceAccess, OpenedImage, open_image,
    };

    // A temporary `.img.gz` file, removed when dropped.
    struct TempGzip(std::path::PathBuf);

    impl Drop for TempGzip {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    fn gzip_bytes(payload: &[u8]) -> Vec<u8> {
        use std::io::Write as _;
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(payload).unwrap();
        encoder.finish().unwrap()
    }

    fn temp_gzip(tag: &str, contents: &[u8]) -> TempGzip {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "linux-usb-writer-main-test-{tag}-{}-{id}.img.gz",
            std::process::id()
        ));
        std::fs::write(&path, contents).unwrap();
        TempGzip(path)
    }

    fn open_gzip(file: &TempGzip) -> CompressedImageFile {
        match open_image(&file.0) {
            Ok(OpenedImage::Compressed(compressed)) => compressed,
            other => panic!("expected a compressed image, got {other:?}"),
        }
    }

    fn payload() -> Vec<u8> {
        (0..200_000u32).map(|i| (i % 253) as u8).collect()
    }

    // None and Full: the whole stream is validated, the source reports the
    // decoded size and sequential access, and progress ends at the exact
    // totals.
    #[test]
    fn prepare_compressed_image_accepts_valid_gzip_for_none_and_full() {
        let data = payload();
        let compressed = gzip_bytes(&data);
        for mode in [VerifyMode::None, VerifyMode::Full] {
            let file = temp_gzip("prepare-ok", &compressed);
            let mut last = None;
            let source = prepare_compressed_image(
                open_gzip(&file),
                mode,
                data.len() as u64,
                || false,
                |progress| last = Some(progress),
            )
            .unwrap_or_else(|rejection| panic!("{mode:?}: {rejection:?}"));

            assert_eq!(source.logical_size(), data.len() as u64);
            assert_eq!(source.access(), ImageSourceAccess::SequentialReplay);
            source.revalidate_identity().unwrap();
            let last = last.expect("progress reported");
            assert_eq!(last.logical_produced, data.len() as u64);
            assert_eq!(last.compressed_consumed, compressed.len() as u64);
        }
    }

    // L1: Quick is refused before any validation work (no cancellation
    // poll, no progress) -- and never silently turned into Full or None.
    #[test]
    fn prepare_compressed_image_refuses_quick_before_validating() {
        let file = temp_gzip("prepare-quick", &gzip_bytes(&payload()));
        let result = prepare_compressed_image(
            open_gzip(&file),
            VerifyMode::Quick,
            u64::MAX,
            || panic!("Quick must be refused before Preflight polls for cancellation"),
            |_| panic!("Quick must be refused before Preflight reports progress"),
        );
        assert!(matches!(
            result,
            Err(CompressedImageRejection::QuickVerifyUnsupported(
                crate::image_source::CompressionFormat::Gzip
            ))
        ));
    }

    fn expect_preflight_error(
        result: Result<
            crate::image_source::compressed::CompressedImageSource,
            CompressedImageRejection,
        >,
    ) -> PreflightError {
        match result {
            Err(CompressedImageRejection::Preflight(error)) => error,
            Err(other) => panic!("expected a Preflight rejection, got {other:?}"),
            Ok(_) => panic!("expected a Preflight rejection, got a source"),
        }
    }

    // Cancellation during Preflight is reported as such (the CLI maps it to
    // the Cancelled exit).
    #[test]
    fn prepare_compressed_image_can_be_cancelled() {
        let file = temp_gzip("prepare-cancel", &gzip_bytes(&payload()));
        let error = expect_preflight_error(prepare_compressed_image(
            open_gzip(&file),
            VerifyMode::None,
            u64::MAX,
            || true,
            |_| {},
        ));
        assert!(matches!(error, PreflightError::Cancelled));
    }

    // Corrupt, truncated and oversized images are rejected with their typed
    // Preflight reason; the size limit is the one passed in (the target's
    // capacity) and allows an image of exactly that size.
    #[test]
    fn prepare_compressed_image_rejects_bad_images_with_typed_reasons() {
        let data = payload();
        let good = gzip_bytes(&data);

        let mut corrupt = good.clone();
        let crc = corrupt.len() - 8;
        corrupt[crc] ^= 0xFF;
        let file = temp_gzip("prepare-corrupt", &corrupt);
        let error = expect_preflight_error(prepare_compressed_image(
            open_gzip(&file),
            VerifyMode::None,
            u64::MAX,
            || false,
            |_| {},
        ));
        assert!(matches!(error, PreflightError::Corrupt(_)), "{error:?}");

        let file = temp_gzip("prepare-truncated", &good[..good.len() / 2]);
        let error = expect_preflight_error(prepare_compressed_image(
            open_gzip(&file),
            VerifyMode::Full,
            u64::MAX,
            || false,
            |_| {},
        ));
        assert!(matches!(error, PreflightError::Incomplete(_)), "{error:?}");

        let file = temp_gzip("prepare-oversized", &good);
        let limit = data.len() as u64 - 1;
        let error = expect_preflight_error(prepare_compressed_image(
            open_gzip(&file),
            VerifyMode::None,
            limit,
            || false,
            |_| {},
        ));
        assert!(
            matches!(error, PreflightError::LogicalSizeLimitExceeded { limit: l } if l == limit),
            "{error:?}"
        );

        let file = temp_gzip("prepare-exact-limit", &good);
        assert!(
            prepare_compressed_image(
                open_gzip(&file),
                VerifyMode::None,
                data.len() as u64,
                || false,
                |_| {},
            )
            .is_ok()
        );
    }

    // The file changes while Preflight runs (at its final progress report):
    // validation itself succeeds, but the source is refused because it is
    // compared with the snapshot `open_image` took.
    #[test]
    fn prepare_compressed_image_refuses_a_source_changed_during_preflight() {
        let compressed = gzip_bytes(&payload());
        let file = temp_gzip("prepare-changed", &compressed);
        let path = file.0.clone();
        let data_len = payload().len() as u64;
        let result = prepare_compressed_image(
            open_gzip(&file),
            VerifyMode::None,
            u64::MAX,
            || false,
            |progress: PreflightProgress| {
                if progress.logical_produced == data_len {
                    use std::os::unix::fs::FileExt as _;
                    std::thread::sleep(std::time::Duration::from_millis(20));
                    let same = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
                    same.write_all_at(&compressed[..16], 0).unwrap();
                }
            },
        );
        assert!(
            matches!(result, Err(CompressedImageRejection::SourceChanged(_))),
            "{result:?}"
        );
    }

    // ---------------------------------------------------------------------
    // xz preparation: the same `prepare_compressed_image` as gzip -- the
    // format only picks the decoder inside Preflight.
    // ---------------------------------------------------------------------

    // A temporary `.img.xz` file, removed when dropped.
    struct TempXz(std::path::PathBuf);

    impl Drop for TempXz {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    fn xz_bytes(payload: &[u8], check: liblzma::stream::Check) -> Vec<u8> {
        use std::io::Write as _;
        let stream = liblzma::stream::Stream::new_easy_encoder(0, check).unwrap();
        let mut encoder = liblzma::write::XzEncoder::new_stream(Vec::new(), stream);
        encoder.write_all(payload).unwrap();
        encoder.finish().unwrap()
    }

    fn crc64_xz(payload: &[u8]) -> Vec<u8> {
        xz_bytes(payload, liblzma::stream::Check::Crc64)
    }

    fn temp_xz(tag: &str, contents: &[u8]) -> TempXz {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "linux-usb-writer-main-test-{tag}-{}-{id}.img.xz",
            std::process::id()
        ));
        std::fs::write(&path, contents).unwrap();
        TempXz(path)
    }

    fn open_xz(file: &TempXz) -> CompressedImageFile {
        match open_image(&file.0) {
            Ok(OpenedImage::Compressed(compressed)) => {
                assert_eq!(
                    compressed.format(),
                    crate::image_source::CompressionFormat::Xz
                );
                compressed
            }
            other => panic!("expected a compressed image, got {other:?}"),
        }
    }

    fn prepare_xz(
        tag: &str,
        contents: &[u8],
        mode: VerifyMode,
        limit: u64,
    ) -> Result<crate::image_source::compressed::CompressedImageSource, CompressedImageRejection>
    {
        let file = temp_xz(tag, contents);
        prepare_compressed_image(open_xz(&file), mode, limit, || false, |_| {})
    }

    // Rewrites a single stream's Check ID (header and footer, CRC32s
    // recomputed; same check-field size) or its first Block's LZMA2
    // dictionary byte (Block Header CRC32 recomputed). Fixed .xz offsets of
    // a stream this test just encoded.
    fn xz_patched(stream: &[u8], check_id: Option<u8>, dictionary_byte: Option<u8>) -> Vec<u8> {
        let crc32 = |bytes: &[u8]| {
            let mut crc = flate2::Crc::new();
            crc.update(bytes);
            crc.sum().to_le_bytes()
        };
        let mut patched = stream.to_vec();
        if let Some(id) = check_id {
            let footer = patched.len() - 12;
            patched[7] = id;
            patched[footer + 9] = id;
            let header_crc = crc32(&patched[6..8]);
            patched[8..12].copy_from_slice(&header_crc);
            let footer_crc = crc32(&patched[footer + 4..footer + 10]);
            patched[footer..footer + 4].copy_from_slice(&footer_crc);
        }
        if let Some(byte) = dictionary_byte {
            let header_len = (patched[12] as usize + 1) * 4;
            assert_eq!(&patched[13..16], &[0x00, 0x21, 0x01], "one LZMA2 filter");
            patched[16] = byte;
            let crc_at = 12 + header_len - 4;
            let crc = crc32(&patched[12..crc_at]);
            patched[crc_at..crc_at + 4].copy_from_slice(&crc);
        }
        patched
    }

    // None and Full: a single stream, and concatenated streams with Stream
    // Padding, are validated to their exact decoded size; the source is the
    // same sequential-replay `CompressedImageSource` gzip produces.
    #[test]
    fn prepare_compressed_image_accepts_valid_xz_for_none_and_full() {
        let data = payload();
        let (half_a, half_b) = data.split_at(data.len() / 2);
        let single = xz_bytes(&data, liblzma::stream::Check::Sha256);
        let concatenated = [
            crc64_xz(half_a),
            vec![0u8; 8],
            xz_bytes(half_b, liblzma::stream::Check::Crc32),
            vec![0u8; 4],
        ]
        .concat();

        for (name, compressed) in [("single", &single), ("concatenated", &concatenated)] {
            for mode in [VerifyMode::None, VerifyMode::Full] {
                let file = temp_xz(&format!("prepare-xz-{name}"), compressed);
                let mut last = None;
                let source = prepare_compressed_image(
                    open_xz(&file),
                    mode,
                    data.len() as u64,
                    || false,
                    |progress| last = Some(progress),
                )
                .unwrap_or_else(|rejection| panic!("{name} {mode:?}: {rejection:?}"));

                assert_eq!(source.logical_size(), data.len() as u64);
                assert_eq!(source.access(), ImageSourceAccess::SequentialReplay);
                source.revalidate_identity().unwrap();
                let last = last.expect("progress reported");
                assert_eq!(last.logical_produced, data.len() as u64);
                assert_eq!(last.compressed_consumed, compressed.len() as u64);
            }
        }
    }

    // L1 for xz: Quick is refused before any validation work, and never
    // turned into Full or None.
    #[test]
    fn prepare_compressed_image_refuses_quick_for_xz_before_validating() {
        let file = temp_xz("prepare-xz-quick", &crc64_xz(&payload()));
        let result = prepare_compressed_image(
            open_xz(&file),
            VerifyMode::Quick,
            u64::MAX,
            || panic!("Quick must be refused before Preflight polls for cancellation"),
            |_| panic!("Quick must be refused before Preflight reports progress"),
        );
        assert!(matches!(
            result,
            Err(CompressedImageRejection::QuickVerifyUnsupported(
                crate::image_source::CompressionFormat::Xz
            ))
        ));
    }

    // Bad xz images are refused by Preflight with their typed reason --
    // before the target is opened.
    #[test]
    fn prepare_compressed_image_rejects_bad_xz_with_typed_reasons() {
        let data = payload();
        let good = crc64_xz(&data);
        let reject = |tag: &str, contents: &[u8], limit: u64| {
            expect_preflight_error(prepare_xz(tag, contents, VerifyMode::Full, limit))
        };

        let mut corrupt = good.clone();
        let footer_crc = corrupt.len() - 12;
        corrupt[footer_crc] ^= 0xFF;
        let error = reject("prepare-xz-corrupt", &corrupt, u64::MAX);
        assert!(matches!(error, PreflightError::Corrupt(_)), "{error:?}");

        let error = reject("prepare-xz-truncated", &good[..good.len() / 2], u64::MAX);
        assert!(matches!(error, PreflightError::Incomplete(_)), "{error:?}");

        let none = xz_bytes(&data, liblzma::stream::Check::None);
        let error = reject("prepare-xz-none", &none, u64::MAX);
        assert!(
            matches!(error, PreflightError::IntegrityCheckMissing),
            "{error:?}"
        );

        let reserved = xz_patched(&good, Some(5), None);
        let error = reject("prepare-xz-reserved", &reserved, u64::MAX);
        assert!(
            matches!(error, PreflightError::UnsupportedIntegrityCheck),
            "{error:?}"
        );

        let huge_dictionary = xz_patched(&good, None, Some(40));
        let error = reject("prepare-xz-memlimit", &huge_dictionary, u64::MAX);
        assert!(
            matches!(error, PreflightError::DecoderMemoryLimitExceeded { .. }),
            "{error:?}"
        );

        let limit = data.len() as u64 - 1;
        let error = reject("prepare-xz-oversized", &good, limit);
        assert!(
            matches!(error, PreflightError::LogicalSizeLimitExceeded { limit: l } if l == limit),
            "{error:?}"
        );
        assert!(
            prepare_xz(
                "prepare-xz-exact",
                &good,
                VerifyMode::None,
                data.len() as u64
            )
            .is_ok()
        );
    }

    // Post-Preflight source check for xz: the file changes during Preflight
    // (at its final progress report) and the source is refused.
    #[test]
    fn prepare_compressed_image_refuses_an_xz_source_changed_during_preflight() {
        let compressed = crc64_xz(&payload());
        let file = temp_xz("prepare-xz-changed", &compressed);
        let path = file.0.clone();
        let data_len = payload().len() as u64;
        let result = prepare_compressed_image(
            open_xz(&file),
            VerifyMode::Full,
            u64::MAX,
            || false,
            |progress: PreflightProgress| {
                if progress.logical_produced == data_len
                    && progress.compressed_consumed == compressed.len() as u64
                {
                    use std::os::unix::fs::FileExt as _;
                    std::thread::sleep(std::time::Duration::from_millis(20));
                    let same = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
                    same.write_all_at(&compressed[..16], 0).unwrap();
                }
            },
        );
        assert!(
            matches!(result, Err(CompressedImageRejection::SourceChanged(_))),
            "{result:?}"
        );
    }

    // The xz-specific Preflight rejections are displayed like every other
    // one: nothing was written, the target was not touched.
    #[test]
    fn format_compressed_image_rejected_covers_xz_reasons() {
        let rejections = [
            CompressedImageRejection::QuickVerifyUnsupported(
                crate::image_source::CompressionFormat::Xz,
            ),
            CompressedImageRejection::Preflight(PreflightError::IntegrityCheckMissing),
            CompressedImageRejection::Preflight(PreflightError::UnsupportedIntegrityCheck),
            CompressedImageRejection::Preflight(PreflightError::DecoderMemoryLimitExceeded {
                limit: 512 * 1024 * 1024,
            }),
            CompressedImageRejection::Preflight(PreflightError::DecoderFailure(
                std::io::Error::other("simulated"),
            )),
        ];
        for rejection in &rejections {
            let lines = format_compressed_image_rejected(rejection);
            assert!(
                lines[0].starts_with("compressed image rejected: "),
                "{lines:?}"
            );
            assert_eq!(
                lines.last().unwrap(),
                "the target device has not been opened or modified."
            );
        }
        let quick = format_compressed_image_rejected(&rejections[0]);
        assert!(quick[0].contains("xz") && quick[0].contains("full") && quick[0].contains("none"));
    }

    // Every rejection message says nothing was written and the target was
    // not touched; the Quick message points to the modes that do work.
    #[test]
    fn format_compressed_image_rejected_states_target_untouched() {
        let rejections = [
            CompressedImageRejection::QuickVerifyUnsupported(
                crate::image_source::CompressionFormat::Gzip,
            ),
            CompressedImageRejection::Preflight(PreflightError::Corrupt(std::io::Error::other(
                "bad crc",
            ))),
            CompressedImageRejection::Preflight(PreflightError::LogicalSizeLimitExceeded {
                limit: 42,
            }),
            CompressedImageRejection::SourceChanged(
                crate::image_source::source_identity::SourceChanged::Unverifiable(
                    std::io::Error::other("simulated"),
                ),
            ),
        ];
        for rejection in &rejections {
            let lines = format_compressed_image_rejected(rejection);
            assert!(lines[0].starts_with("compressed image rejected: "));
            assert_eq!(
                lines.last().unwrap(),
                "the target device has not been opened or modified."
            );
        }
        let quick = format_compressed_image_rejected(&rejections[0]);
        assert!(quick[0].contains("full") && quick[0].contains("none"));
    }

    #[test]
    fn format_preflight_progress_shows_both_sides() {
        let line = format_preflight_progress(&PreflightProgress {
            compressed_consumed: 10,
            compressed_total: 20,
            logical_produced: 30,
        });
        assert!(line.contains("10/20") && line.contains("30 bytes decoded"));
    }

    // The post-Preflight target re-check (`core::revalidate` on a fresh
    // snapshot, then `is_ready_to_open`): a target replaced, recreated or
    // removed while Preflight ran is no longer ready to open.
    #[test]
    fn target_changed_during_preflight_is_not_ready_to_open() {
        let selected = || core::select(base_snapshot()).unwrap();

        let unchanged = core::revalidate(
            selected(),
            crate::device::SnapshotFetchOutcome::Found(base_snapshot()),
        );
        assert!(core::is_ready_to_open(&unchanged));

        let mut replaced = base_snapshot();
        replaced.serial = "OTHER-SERIAL".to_string();
        let mut recreated = base_snapshot();
        recreated.diskseq = Some(13);
        let mut resized = base_snapshot();
        resized.size = 4_000_000_000;
        let mut mounted = base_snapshot();
        mounted.mount_points = vec!["/".to_string()];

        for (name, outcome) in [
            (
                "replaced",
                crate::device::SnapshotFetchOutcome::Found(replaced),
            ),
            (
                "recreated",
                crate::device::SnapshotFetchOutcome::Found(recreated),
            ),
            (
                "resized",
                crate::device::SnapshotFetchOutcome::Found(resized),
            ),
            (
                "mounted",
                crate::device::SnapshotFetchOutcome::Found(mounted),
            ),
            ("removed", crate::device::SnapshotFetchOutcome::NotFound),
        ] {
            let state = core::revalidate(selected(), outcome);
            assert!(!core::is_ready_to_open(&state), "{name}");
        }
    }
}
