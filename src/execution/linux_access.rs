// Linux Backend responsibility, kept separate from `linux_backend.rs`
// (read-only collection) because this module deliberately crosses into
// privileged, write-capable territory: calling UDisks2's Block.OpenDevice,
// holding the resulting file descriptor, and reading its raw kernel metadata.
//
// This module's job stops at collection, read-only FD inspection, and (as of
// this revision) handing out the one narrow write capability that exists in
// the crate (`ActiveWriteTarget`, see below). It never decides whether a
// Selection is valid, never compares against a DeviceSnapshot, and — still,
// critically — no code path anywhere in this crate today actually calls
// `writer::write()` against a device opened through this module, so no byte
// has ever been written to a real block device by this program. Those
// judgements (when to allow a write at all) belong to `core.rs`.

use std::{
    collections::HashMap,
    ffi::{c_int, c_ulong},
    fs::File,
    io::{self, Write},
    os::fd::{AsRawFd, RawFd},
    os::unix::fs::{FileExt, MetadataExt},
};

use zbus::{
    blocking::{Connection, Proxy},
    zvariant::OwnedValue,
};

use crate::linux_backend::decode_device_number;

// Fields are read only via the derived Debug impl (rustc's dead-code lint
// doesn't count that as a use), which is how call sites report the failure.
#[allow(dead_code)]
#[derive(Debug)]
pub enum OpenDeviceError {
    ConnectionFailed(String),
    CallFailed(String),
}

pub struct OpenedDeviceHandle {
    file: File,
}

// A narrow, single-purpose borrow of the underlying `File`: the only thing
// in this crate that can turn a Gate-passed handle into a `std::io::Write`.
// It exposes exactly `Write` and nothing else -- no `Read`, no `Seek`, no way
// to recover the raw fd or a plain `File` -- and its lifetime is tied to the
// `&mut OpenedDeviceHandle` borrow that produced it (see `writer_target`
// below), so it cannot outlive that one call site's exclusive borrow of the
// handle, and no two `ActiveWriteTarget`s for the same handle can exist at
// once. `pub(in crate::execution)`, not `pub(crate)`: reachable only from
// within the `execution` module tree (`core`/`linux_access`/`write_job`,
// see `execution/mod.rs`), not from `main.rs` or any other sibling module.
// The intended caller within that tree is
// `core::ActiveWrite::writer_target()` — see that method's doc comment.
#[allow(dead_code)] // exercised by core.rs's tests today; not yet called from any non-test code path.
pub(in crate::execution) struct ActiveWriteTarget<'a> {
    file: &'a mut File,
}

impl Write for ActiveWriteTarget<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.file.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

// A narrow, single-purpose borrow of the underlying `File` for durability
// operations only: the only thing in this crate that can ask the OS to
// flush a Gate-passed handle's data toward physical storage. Exposes
// exactly `sync_all()` and nothing else -- no `Read`, no `Write`, no `Seek`,
// no way to recover the raw fd or a plain `File`. Unlike `ActiveWriteTarget`
// (which needs `&mut File` because `Write` requires exclusive access),
// `File::sync_all()` only needs `&File` -- this borrows shared, not
// exclusive.
//
// `pub(in crate::execution)`, not `pub(crate)`, for the same reason as
// `ActiveWriteTarget`: the intended (and, as of this revision, only actual)
// caller is `core::ActiveWrite::sync_target()`, also inside `execution`.
//
// IMPORTANT CAVEAT: `File::sync_all()` (which calls `fsync()` on Linux) is a
// *candidate* durability primitive, not a confirmed final answer for block
// device durability. Whether it is sufficient to guarantee data has reached
// physical USB/SD/NVMe media -- accounting for drive-side write caches,
// firmware behavior, and any block-device-specific kernel/UDisks2 semantics
// -- has not been verified against official documentation; that
// verification is separate, future work. Nothing in this crate should be
// read as claiming that `sync_all()` returning `Ok` means a write is
// physically durable on real media.
#[allow(dead_code)] // exercised by core.rs's/write_job.rs's tests today; not yet called from any non-test code path.
pub(in crate::execution) struct SyncTarget<'a> {
    file: &'a File,
}

impl SyncTarget<'_> {
    #[allow(dead_code)] // exercised by core.rs's/write_job.rs's tests today; not yet called from any non-test code path.
    pub(in crate::execution) fn sync_all(&self) -> io::Result<()> {
        self.file.sync_all()
    }
}

// A narrow, single-purpose borrow of the underlying `File` for read-only,
// offset-based reads: the one and only place in this crate where a *read*
// capability for a Gate-passed FD can be created, for a future Built-in
// Verify stage to sample or fully re-read a target device's content.
// Exposes exactly `read_at()` and nothing else -- no `Write`, no `Seek`, no
// way to recover the raw fd or a plain `File`. Borrows shared (`&File`),
// like `SyncTarget` above, not exclusive (`&mut File`) like
// `ActiveWriteTarget`: `FileExt::read_at` needs no exclusive access.
//
// `pub(in crate::execution)`, not `pub(crate)`, for the same reason as
// `ActiveWriteTarget`/`SyncTarget`: this stays inside the same module
// boundary, reachable only from `core`/`linux_access`/`write_job`, never
// from `main.rs` or any other sibling module. This revision adds no
// production caller -- a future Verify state machine in `write_job.rs` is
// the intended one, exactly as `writer_target()`/`sync_target()` were added
// before `write_job.rs`'s `Writing`/`Syncing` states existed to call them.
#[allow(dead_code)] // not yet called from any non-test code path; exercised by this module's own tests below.
pub(in crate::execution) struct ReadTarget<'a> {
    file: &'a File,
}

impl ReadTarget<'_> {
    // Reads up to `buf.len()` bytes starting at `offset`, via
    // `FileExt::read_at` -- no shared cursor, no `Seek`: independent of any
    // `ActiveWriteTarget`/`Write` cursor on the same handle, and independent
    // of any other `read_at()` call on this or another `ReadTarget` over the
    // same handle. Ordinary `FileExt::read_at` semantics apply unchanged:
    // EOF -> `Ok(0)`, a short read -> `Ok(n)` with `n < buf.len()`, a real
    // I/O failure -> `Err`; no bespoke error type is introduced here.
    //
    // Deliberately does NOT clamp to any image `logical_size()`: unlike
    // `image_source::ImageSource::read_at` (which knows, and enforces, the
    // *image's* logical size), `ReadTarget` is a low-level capability over
    // the *target device* and has no notion of how many bytes a particular
    // Verify pass intends to read -- that bookkeeping belongs to whatever
    // future Verify layer calls this, exactly as this module's write path
    // never decides *whether* a write is safe (that is `core.rs`'s job).
    #[allow(dead_code)] // not yet called from any non-test code path; exercised by this module's own tests below.
    pub(in crate::execution) fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        self.file.read_at(buf, offset)
    }
}

#[derive(Debug)]
pub struct FdMetadata {
    pub major: u32,
    pub minor: u32,
    // From a read-only BLKGETSIZE64 ioctl; None if it could not be obtained.
    pub size: Option<u64>,
    // Where /proc/self/fd/<n> resolves to, for human-readable diagnostics only.
    pub proc_fd_target: Option<String>,
}

// What a device FD is opened for. Each variant fixes both the access mode
// and the open flags, so a caller can never pair a writable mode with the
// wrong flags (see `open_device_arguments`).
//
//   - `WriteExclusive`: read-write, with `O_EXCL`. For a block device this
//     makes the kernel *claim* the device for this open file: the open
//     fails with EBUSY if the device -- or any of its partitions, for a
//     whole disk -- is already claimed (mounted, active swap, used by
//     device-mapper / md, or opened exclusively by someone else), and while
//     the FD stays open nothing else can claim it (e.g. an automount of one
//     of its partitions). A second, kernel-enforced layer on top of the
//     Safety Engine and the fresh Write Gate, never a replacement for them:
//     plain (non-exclusive) opens by other processes are not affected, and
//     states the kernel does not treat as claims are not caught.
//   - `ReadOnly`: read-only, without `O_EXCL`. For Verify, which must still
//     work when the desktop auto-mounts a freshly written partition (see
//     `core::check_identity_instance_for_verify`) -- an exclusive open would
//     then fail although the write succeeded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenAccess {
    WriteExclusive,
    ReadOnly,
}

// The `mode` and `options` arguments of UDisks2's Block.OpenDevice for
// `access`. `mode` is UDisks2's own vocabulary ("r" / "rw"); UDisks2 derives
// the access mode from it and ORs `options["flags"]` (D-Bus type `i`) into
// the open(2) flags, rejecting O_RDONLY/O_WRONLY/O_RDWR there -- so the
// access mode is never put into `flags`.
fn open_device_arguments(access: OpenAccess) -> (&'static str, HashMap<String, OwnedValue>) {
    let mut options: HashMap<String, OwnedValue> = HashMap::new();

    let mode = match access {
        OpenAccess::WriteExclusive => {
            options.insert("flags".to_string(), OwnedValue::from(libc::O_EXCL));
            "rw"
        }
        OpenAccess::ReadOnly => "r",
    };

    (mode, options)
}

// Calls org.freedesktop.UDisks2.Block.OpenDevice for `access` (see
// `OpenAccess`) and returns the resulting file descriptor, wrapped so it can
// only be inspected read-only and closed — this type exposes no write/seek
// API at all.
//
// This is a genuine, unprivileged D-Bus method call — any privilege
// escalation happens inside UDisks2/polkit using the caller's own session,
// not via sudo or any bypass initiated by this program. If polkit requires
// interactive authentication, this call simply blocks until the user's own
// polkit agent (e.g. a graphical prompt) is answered or the request times
// out/is denied. An exclusive open refused because the device is in use
// fails here like any other open failure (`CallFailed`), before any FD
// exists.
pub fn open_device(
    block_path: &str,
    access: OpenAccess,
) -> Result<OpenedDeviceHandle, OpenDeviceError> {
    let connection = Connection::system()
        .map_err(|error| OpenDeviceError::ConnectionFailed(error.to_string()))?;

    let block = Proxy::new(
        &connection,
        "org.freedesktop.UDisks2",
        block_path,
        "org.freedesktop.UDisks2.Block",
    )
    .map_err(|error| OpenDeviceError::CallFailed(error.to_string()))?;

    let (mode, options) = open_device_arguments(access);

    let fd: zbus::zvariant::OwnedFd = block
        .call("OpenDevice", &(mode, options))
        .map_err(|error| OpenDeviceError::CallFailed(error.to_string()))?;

    let std_fd: std::os::fd::OwnedFd = fd.into();

    Ok(OpenedDeviceHandle {
        file: File::from(std_fd),
    })
}

// BLKGETSIZE64 = _IOR(0x12, 114, sizeof(uint64_t)), from <linux/fs.h>. A
// read-only ioctl that reports the device's size in bytes; it cannot modify
// device state. Declared as a fixed-arity extern "C" binding (rather than
// depending on the `libc` crate) — this matches how ioctl() is actually
// invoked here (exactly one pointer argument), which is ABI-compatible with
// its variadic C prototype.
const BLKGETSIZE64: c_ulong = 0x8008_1272;

unsafe extern "C" {
    fn ioctl(fd: c_int, request: c_ulong, argp: *mut u64) -> c_int;
}

fn read_size_via_ioctl(fd: RawFd) -> Option<u64> {
    let mut size: u64 = 0;

    // SAFETY: `fd` is a valid, open file descriptor for the lifetime of this
    // call (borrowed from `OpenedDeviceHandle`, which owns it), and `argp`
    // points to a valid, appropriately sized local `u64` for the ioctl to
    // write into. This ioctl is read-only: it cannot mutate the device.
    let result = unsafe { ioctl(fd, BLKGETSIZE64, &mut size) };

    if result == 0 {
        Some(size)
    } else {
        None
    }
}

impl OpenedDeviceHandle {
    // Test-only construction path. Lets unit tests (in `core.rs`) exercise
    // the Write Gate's handle-ownership handoff into `PreparedWrite` against
    // a plain, throwaway regular file -- never a block device -- without any
    // D-Bus call. This is compiled only for `cfg(test)` and is `pub(crate)`,
    // so no non-test code anywhere in the crate can reach it: the only way to
    // obtain an `OpenedDeviceHandle` in a real build remains `open_device`,
    // which is the sole path that ever calls UDisks2's Block.OpenDevice.
    #[cfg(test)]
    pub(crate) fn from_file_for_test(file: File) -> Self {
        OpenedDeviceHandle { file }
    }

    // Test-only: exposes the raw fd number itself (never the `File`, never a
    // `Write`) purely so a test can independently confirm, via
    // `/proc/self/fd/<n>`, that dropping whatever owns this handle actually
    // closed the underlying fd. `cfg(test)` + `pub(crate)` again keep this
    // out of any real build.
    #[cfg(test)]
    pub(crate) fn raw_fd_for_test(&self) -> RawFd {
        self.file.as_raw_fd()
    }

    // Hands out a short-lived, write-only borrow of the underlying File --
    // the one and only place in this crate where a write capability for a
    // Gate-passed FD can be created. Every other method on this type stays
    // strictly read-only (`metadata()`) or test-only (`from_file_for_test`,
    // `raw_fd_for_test`). Present in every build (not `#[cfg(test)]`) because
    // `core::ActiveWrite::writer_target()` needs to call it in production
    // too; `pub(crate)` keeps it from ever being reachable outside this
    // crate. See `ActiveWriteTarget`'s doc comment for why "only
    // `core::ActiveWrite` calls this" is a documented convention (verified by
    // grep) rather than a compiler-enforced guarantee.
    #[allow(dead_code)] // exercised by core.rs's tests today; not yet called from any non-test code path.
    pub(in crate::execution) fn writer_target(&mut self) -> ActiveWriteTarget<'_> {
        ActiveWriteTarget {
            file: &mut self.file,
        }
    }

    // Hands out a short-lived, sync-only borrow of the underlying File --
    // the one and only place in this crate where a durability-sync
    // capability for a Gate-passed FD can be created. Takes `&self`
    // (shared), not `&mut self`: unlike `writer_target()` (exclusive,
    // because `Write` mutates), `File::sync_all()` only needs a shared
    // reference. `pub(crate)` keeps it from ever being reachable outside
    // this crate; see `SyncTarget`'s doc comment for the caller convention
    // and the block-device durability caveat.
    #[allow(dead_code)] // exercised by core.rs's/write_job.rs's tests today; not yet called from any non-test code path.
    pub(in crate::execution) fn sync_target(&self) -> SyncTarget<'_> {
        SyncTarget { file: &self.file }
    }

    // Hands out a short-lived, read-only, offset-based borrow of the
    // underlying File -- the one and only place in this crate where a read
    // capability for a Gate-passed FD can be created. Takes `&self`
    // (shared), exactly like `sync_target()` above: `FileExt::read_at` needs
    // no exclusive access. `pub(in crate::execution)` keeps this inside the
    // same module boundary as `writer_target()`/`sync_target()` --
    // unreachable from `main.rs` or any other sibling module. See
    // `ReadTarget`'s own doc comment for why no production caller exists
    // yet.
    #[allow(dead_code)] // not yet called from any non-test code path; exercised by this module's own tests below.
    pub(in crate::execution) fn reader_target(&self) -> ReadTarget<'_> {
        ReadTarget { file: &self.file }
    }

    // Read-only metadata about the FD itself: no reads or writes of device
    // *contents* are performed, only kernel bookkeeping (fstat, ioctl,
    // /proc/self/fd).
    pub fn metadata(&self) -> Option<FdMetadata> {
        let stat = self.file.metadata().ok()?;
        let (major, minor) = decode_device_number(stat.rdev());
        let raw_fd = self.file.as_raw_fd();

        let size = read_size_via_ioctl(raw_fd);
        let proc_fd_target = std::fs::read_link(format!("/proc/self/fd/{raw_fd}"))
            .ok()
            .map(|path| path.to_string_lossy().into_owned());

        Some(FdMetadata {
            major,
            minor,
            size,
            proc_fd_target,
        })
    }
}

// Explicit, named close so call sites make the "no write happened" intent
// visible instead of relying on an implicit Drop.
pub fn close_without_writing(handle: OpenedDeviceHandle) {
    drop(handle.file);
}

// Test-only fd-closure observation helpers, shared by every test module in
// this crate that needs to confirm a Gate-passed fd was actually closed
// (`core.rs`'s and `write_job.rs`'s tests both use these). `cfg(test)` +
// `pub(crate)` keep them out of any real build, same as `from_file_for_test`
// and `raw_fd_for_test` above.
//
// A naive "does /proc/self/fd/<n> still exist" check after a drop is
// flaky: if the OS hands that same fd number to an unrelated fd before the
// check runs (a real possibility under `cargo test`'s parallel execution --
// this was observed at least once in practice), the path exists again and a
// naive check wrongly concludes "still open" even though the original fd
// was genuinely closed. Comparing the symlink's *target*, not just its
// existence, distinguishes the two cases:
//   A. the symlink is gone entirely -> closed, unambiguously.
//   B. the symlink exists but now resolves to a different target than
//      before the drop -> the number was reused by an unrelated fd, which
//      can only happen once the original was actually closed -> closed.
//   C. the symlink exists and still resolves to the exact same target as
//      before the drop -> the fd was never actually closed.
#[cfg(test)]
pub(crate) fn fd_proc_target_for_test(raw_fd: RawFd) -> Option<String> {
    std::fs::read_link(format!("/proc/self/fd/{raw_fd}"))
        .ok()
        .map(|path| path.to_string_lossy().into_owned())
}

// Call after dropping whatever owned `raw_fd`, passing the target captured
// (via `fd_proc_target_for_test`) *before* the drop. Panics only for case C
// above -- the one case that actually proves the fd was never closed.
#[cfg(test)]
pub(crate) fn assert_fd_closed_for_test(raw_fd: RawFd, target_before_drop: Option<&str>) {
    if let Some(after) = fd_proc_target_for_test(raw_fd) {
        assert_ne!(
            target_before_drop,
            Some(after.as_str()),
            "fd {raw_fd} still resolves to the same target ({after}) after drop -- it was not closed"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    // OpenDevice arguments. The write FD is a read-write, exclusive open:
    // mode "rw" plus `flags` = O_EXCL as a D-Bus `i` (i32) -- and nothing
    // else in `flags` (in particular no access-mode bits, which UDisks2
    // rejects there). If O_EXCL ever disappears from the write FD, this
    // fails.
    #[test]
    fn write_access_is_read_write_and_exclusive() {
        let (mode, options) = open_device_arguments(OpenAccess::WriteExclusive);

        assert_eq!(mode, "rw");
        assert_eq!(options.len(), 1);
        let flags = options.get("flags").expect("flags option present");
        assert_eq!(flags.value_signature().to_string(), "i");
        assert!(matches!(&**flags, zbus::zvariant::Value::I32(_)));
        let flags = i32::try_from(flags).unwrap();
        assert_eq!(flags, libc::O_EXCL);
        assert_eq!(flags & libc::O_ACCMODE, 0);
        if cfg!(target_arch = "x86_64") {
            assert_eq!(libc::O_EXCL, 0o200);
        }
    }

    // The Verify FD is read-only and not exclusive: mode "r", no flags.
    #[test]
    fn read_only_access_is_not_exclusive() {
        let (mode, options) = open_device_arguments(OpenAccess::ReadOnly);

        assert_eq!(mode, "r");
        assert!(options.is_empty(), "no flags, so no O_EXCL: {options:?}");
    }

    // Collision-avoidance identical in spirit to the temp-file helpers in
    // `core.rs`'s/`write_job.rs`'s/`image_source.rs`'s own test modules: PID
    // + a process-global counter keeps the path unique across
    // concurrently-running tests. Always a plain regular file under the OS
    // temp directory -- never a block device, and every handle here is built
    // via `from_file_for_test`, never `open_device`.
    fn temp_file_path(tag: &str) -> std::path::PathBuf {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);

        std::env::temp_dir().join(format!(
            "linux-usb-writer-linux-access-test-{tag}-{}-{id}.tmp",
            std::process::id()
        ))
    }

    // Writes `data` to a fresh temp file and reopens it read-write (needed
    // so both `reader_target()` and `writer_target()` can be exercised
    // against the same `OpenedDeviceHandle` where a test needs both).
    fn handle_with_content(tag: &str, data: &[u8]) -> (std::path::PathBuf, OpenedDeviceHandle) {
        let path = temp_file_path(tag);
        std::fs::write(&path, data).expect("write temp file for linux_access test");
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .expect("reopen temp file read-write for linux_access test");
        (path, OpenedDeviceHandle::from_file_for_test(file))
    }

    // 1. reader_target() reads from offset 0 correctly.
    #[test]
    fn reader_target_reads_from_offset_zero() {
        let data: Vec<u8> = (0..1000u32).map(|i| (i % 250) as u8).collect();
        let (path, handle) = handle_with_content("offset-zero", &data);

        let mut buf = [0u8; 100];
        let n = handle.reader_target().read_at(0, &mut buf).unwrap();

        assert_eq!(n, 100);
        assert_eq!(buf, data[..100]);
        let _ = std::fs::remove_file(&path);
    }

    // 2. reader_target() reads from a non-zero, mid-file offset correctly.
    #[test]
    fn reader_target_reads_from_middle_offset() {
        let data: Vec<u8> = (0..2000u32).map(|i| (i % 240) as u8).collect();
        let (path, handle) = handle_with_content("middle-offset", &data);

        let offset = 900u64;
        let mut buf = [0u8; 100];
        let n = handle.reader_target().read_at(offset, &mut buf).unwrap();

        assert_eq!(n, 100);
        assert_eq!(buf, data[900..1000]);
        let _ = std::fs::remove_file(&path);
    }

    // 3. Near EOF, read_at() returns a short read of exactly the remaining
    // bytes, not an error.
    #[test]
    fn reader_target_returns_a_short_read_near_eof() {
        let data: Vec<u8> = (0..500u32).map(|i| (i % 200) as u8).collect();
        let (path, handle) = handle_with_content("near-eof", &data);

        let mut buf = [0u8; 200]; // requests past the file's end (500)
        let n = handle.reader_target().read_at(400, &mut buf).unwrap();

        assert_eq!(n, 100);
        assert_eq!(&buf[..100], &data[400..500]);
        let _ = std::fs::remove_file(&path);
    }

    // 4. offset == file size returns Ok(0), no error.
    #[test]
    fn reader_target_offset_equal_to_file_size_returns_zero() {
        let (path, handle) = handle_with_content("offset-eq-size", &[1u8; 300]);

        let mut buf = [0u8; 10];
        let n = handle.reader_target().read_at(300, &mut buf).unwrap();

        assert_eq!(n, 0);
        let _ = std::fs::remove_file(&path);
    }

    // 5. offset > file size returns Ok(0), no error.
    #[test]
    fn reader_target_offset_past_file_size_returns_zero() {
        let (path, handle) = handle_with_content("offset-past-size", &[1u8; 300]);

        let mut buf = [0u8; 10];
        let n = handle.reader_target().read_at(10_000, &mut buf).unwrap();

        assert_eq!(n, 0);
        let _ = std::fs::remove_file(&path);
    }

    // 6/7. Repeated, out-of-order read_at() calls at different offsets are
    // fully independent -- there is no shared cursor for one call to
    // disturb for another.
    #[test]
    fn multiple_read_at_calls_out_of_order_are_independent() {
        let data: Vec<u8> = (0..3000u32).map(|i| (i % 230) as u8).collect();
        let (path, handle) = handle_with_content("out-of-order", &data);
        let target = handle.reader_target();

        let mut buf_end = [0u8; 100];
        let mut buf_start = [0u8; 100];
        let mut buf_middle = [0u8; 100];

        // Deliberately read out of order: end, then start, then middle.
        target.read_at(2900, &mut buf_end).unwrap();
        target.read_at(0, &mut buf_start).unwrap();
        target.read_at(1500, &mut buf_middle).unwrap();

        assert_eq!(buf_end, data[2900..3000]);
        assert_eq!(buf_start, data[0..100]);
        assert_eq!(buf_middle, data[1500..1600]);
        let _ = std::fs::remove_file(&path);
    }

    // 8. reader_target()'s read_at() never disturbs writer_target()'s
    // shared `Write`-cursor: a write, an interleaved read_at() at an
    // unrelated offset, then a second write, must land the second write's
    // bytes immediately after the first -- exactly as if the read had never
    // happened -- proving read_at() performs no seek on the shared file
    // description.
    #[test]
    fn reader_target_does_not_disturb_writer_target_cursor() {
        let (path, mut handle) = handle_with_content("writer-cursor", &[0u8; 20]);

        handle.writer_target().write_all(b"AAAAA").unwrap();

        let mut first_half = [0u8; 5];
        handle.reader_target().read_at(0, &mut first_half).unwrap();
        assert_eq!(&first_half, b"AAAAA");

        handle.writer_target().write_all(b"BBBBB").unwrap();

        let mut whole = [0u8; 10];
        handle.reader_target().read_at(0, &mut whole).unwrap();
        assert_eq!(&whole, b"AAAAABBBBB");

        let _ = std::fs::remove_file(&path);
    }

    // 9. reader_target() and sync_target() can both be used against the
    // same handle without interfering with one another.
    #[test]
    fn reader_target_and_sync_target_do_not_interfere() {
        let data = vec![7u8; 50];
        let (path, handle) = handle_with_content("sync-interop", &data);

        let mut buf = [0u8; 50];
        handle.reader_target().read_at(0, &mut buf).unwrap();
        assert_eq!(buf.to_vec(), data);

        handle
            .sync_target()
            .sync_all()
            .expect("sync_all should succeed on a regular file");

        let _ = std::fs::remove_file(&path);
    }

    // 10. An empty buffer returns Ok(0), never an error.
    #[test]
    fn reader_target_with_empty_buffer_returns_zero() {
        let (path, handle) = handle_with_content("empty-buf", &[1u8; 10]);

        let n = handle.reader_target().read_at(0, &mut []).unwrap();

        assert_eq!(n, 0);
        let _ = std::fs::remove_file(&path);
    }
}
