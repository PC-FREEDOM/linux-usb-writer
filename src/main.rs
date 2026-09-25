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

            return run_write_test(image_path, target, verify_mode, test_pause_before_verify);
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

    let handle = match linux_access::open_device(&baseline.block_path, "rw") {
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

    let open_result = linux_access::open_device(&ready.current().block_path, "rw");

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
// `image_source::FileImageSource::new()` exactly once; the resulting
// `SelectedImage` (`selected_image` below) is held by this one variable,
// unchanged, from that point until it is moved into
// `AuthorizedExecution::bind()` -- it is never re-opened, never
// reconstructed, and no second `FileImageSource`/`SelectedImage` is ever
// created for the same invocation.
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
) -> zbus::Result<()> {
    let mut state = attempt_select(&block_path);

    if let core::SelectionState::Selected { baseline, .. } = &state {
        let outcome = collect_device_snapshot(&baseline.block_path);
        state = core::revalidate(state, outcome);
    }

    print_selection_state(&state);

    if !core::is_ready_to_open(&state) {
        println!("\nwrite-test: Selection invalid -- stopping before the Write Gate.");
        return Ok(());
    }

    let core::SelectionState::Selected {
        baseline,
        baseline_assessment,
        ..
    } = &state
    else {
        unreachable!("is_ready_to_open just confirmed Selected");
    };

    // The one and only place `image_path` is opened this invocation.
    // `selected_image` is what travels, as a single variable, all the way
    // to `AuthorizedExecution::bind()` below -- `selection()` (a cheap Copy)
    // is all that gets threaded through the Gate calls in between.
    let source = match image_source::FileImageSource::new(&image_path) {
        Ok(source) => source,
        Err(error) => {
            println!("write-test: failed to open image {image_path}: {error:?}");
            return Ok(());
        }
    };
    let selected_image = image_source::SelectedImage::new(Box::new(source));

    println!(
        "\nwrite-test: image selected from {image_path} (image_size={} bytes)",
        selected_image.logical_size()
    );

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

    let mut confirmation_input = String::new();
    let confirmed = match std::io::stdin().read_line(&mut confirmation_input) {
        Ok(0) => false, // EOF (e.g. stdin closed or redirected from an empty source): treat as "no answer given", never as an implicit yes.
        Ok(_) => confirmation_matches(&confirmation_input, &expected_device),
        Err(_) => false,
    };

    if !confirmed {
        println!("write-test: confirmation failed; no device was opened and nothing was written");
        return Ok(());
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
                return Ok(());
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
            return Ok(());
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

    let open_result = linux_access::open_device(&ready.current().block_path, "rw");

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
            return Ok(());
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
            return Ok(());
        }
    };
    println!("write-test: AuthorizedExecution bound (image_generation/image_size match confirmed)");

    // No UI exists yet to request cancellation from another thread; a fresh,
    // never-cancelled handle is all this CLI PoC needs.
    let cancel = write_job::CancelHandle::new();

    let writing_execution = match execution.begin_write(cancel) {
        Ok(writing_execution) => writing_execution,
        Err(error) => {
            println!("write-test: begin_write() failed to open the image reader: {error}");
            println!(
                "write-test: AuthorizedExecution dropped -- FD closed via RAII, 0 bytes written"
            );
            return Ok(());
        }
    };
    println!("write-test: write started");

    let (selected_image, outcome) = writing_execution.write(|progress| {
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

    match outcome {
        write_job::WriteAttemptOutcome::Succeeded(succeeded) => {
            println!(
                "write-test: write succeeded ({} of {} bytes written)",
                succeeded.bytes_written, succeeded.image_size
            );

            // Write success -> sync, in the same straight line, with no
            // branch that returns early and skips it.
            println!("write-test: syncing...");
            match succeeded.begin_sync().sync() {
                write_job::SyncAttemptOutcome::Succeeded(sync_succeeded) => {
                    println!(
                        "write-test: sync succeeded -- write + sync completed ({} bytes)",
                        sync_succeeded.bytes_written
                    );

                    // ---- Built-in Verify (self-contained: this arm always
                    // returns, so `selected_image` being consumed here --
                    // via `begin_verify()` -- never conflicts with the
                    // trailing print below, which only the *other* three
                    // arms (which never touch `selected_image`) can reach.
                    // No UI exists yet to request cancellation, exactly like
                    // the write's own `cancel` above -- a fresh,
                    // never-cancelled handle is all this CLI PoC needs. ----
                    let verify_cancel = write_job::CancelHandle::new();

                    match sync_succeeded.begin_verify(selected_image, verify_cancel) {
                        write_job::VerifyStart::Skipped(image, succeeded) => {
                            println!("write-test: {}", format_verify_succeeded(&succeeded));
                            println!(
                                "write-test: SelectedImage identity preserved after verification (image_size={})",
                                image.logical_size()
                            );
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
                                return Ok(());
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
                                    return Ok(());
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

                            let open_result = linux_access::open_device(ready.block_path(), "r");

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
                                    return Ok(());
                                }
                            };

                            println!("write-test: verification started");

                            let (image, verify_outcome) = verifying.run(|progress| {
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

                            match verify_outcome {
                                write_job::VerifyOutcome::Succeeded(succeeded) => {
                                    println!("write-test: {}", format_verify_succeeded(&succeeded));
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
                                }
                                write_job::VerifyOutcome::Cancelled(cancelled) => {
                                    println!(
                                        "write-test: verification cancelled after {} bytes",
                                        cancelled.verified_bytes
                                    );
                                }
                            }

                            println!(
                                "write-test: SelectedImage identity preserved after verification (image_size={})",
                                image.logical_size()
                            );
                        }
                    }

                    return Ok(());
                }
                write_job::SyncAttemptOutcome::Failed(failed) => {
                    println!("write-test: sync FAILED: {failed:?}");
                    println!(
                        "write-test: retry_requires_fresh_gate={} -- not retrying automatically",
                        failed.retry_requires_fresh_gate
                    );
                }
            }
        }
        write_job::WriteAttemptOutcome::Failed(failed) => {
            println!("write-test: write FAILED: {failed:?}");
            println!(
                "write-test: not syncing -- retry_requires_fresh_gate={}",
                failed.retry_requires_fresh_gate
            );
        }
        write_job::WriteAttemptOutcome::Cancelled(cancelled) => {
            println!("write-test: write CANCELLED: {cancelled:?}");
            println!(
                "write-test: not syncing -- retry_requires_fresh_gate={}",
                cancelled.retry_requires_fresh_gate
            );
        }
    }

    // Reached only by the write-Failed, write-Cancelled, and sync-Failed
    // paths above -- the sync-Succeeded path always returns from within its
    // own arm (see above), together with `selected_image`, before control
    // flow can ever reach here. `selected_image` is therefore guaranteed to
    // still be owned by this scope on every path that reaches this line.
    println!(
        "write-test: SelectedImage identity preserved (image_size={})",
        selected_image.logical_size()
    );

    Ok(())
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
        format_hard_hazards, format_identity_comparison, format_instance_comparison,
        format_verify_diagnostics_summary, format_verify_diagnostics_unavailable,
        format_verify_failure_reason, format_verify_succeeded, parse_verify_mode,
        parse_write_test_trailing_args, WriteTestArgsError,
    };
    use crate::device::DeviceSnapshot;
    use crate::execution::core::{self, HardHazardReason, VerifyMode};
    use crate::execution::write_job::{VerifyFailureReason, VerifySucceeded};
    use crate::identity::{IdentityComparison, InstanceComparison};

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
}
