mod core;
mod device;
mod identity;
mod image_source;
mod linux_access;
mod linux_backend;
mod linux_monitor;
mod safety;
mod writer;
mod write_job;

use device::SnapshotFetchOutcome;
use identity::{compare_identity, compare_instance};
use linux_backend::{collect_device_snapshot, collect_device_snapshots};
use linux_monitor::{start_monitoring, DeviceEvent};
use safety::assess_device;

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
        Some("writer-test") => return run_writer_test(),
        _ => {}
    }

    let snapshots = collect_device_snapshots()?;

    println!("Safety assessments:");

    for snapshot in snapshots {
        let assessment = assess_device(&snapshot);

        println!();
        println!("Device:      {}", snapshot.device);
        println!(
            "Model:       {} {}",
            snapshot.vendor,
            snapshot.model
        );
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
                        snapshot.device,
                        snapshot.diskseq,
                        snapshot.media_available,
                        snapshot.size
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
            println!("prepare-test: WRITE NOT PERFORMED (writer::write() is not called by this PoC)");

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

    println!("writer-test: temporary target file: {}", temp_path.display());
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