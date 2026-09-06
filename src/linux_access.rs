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
    os::unix::fs::MetadataExt,
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
// once. `pub(crate)`, not `pub`: nothing outside this crate could reach it
// even if it were `pub` (this is a binary crate with no library surface),
// and within the crate the only intended caller is
// `core::ActiveWrite::writer_target()` — see that method's doc comment for
// why this is a documented convention rather than something Rust's
// module-visibility system can express directly (`linux_access` and `core`
// are sibling modules, so there is no `pub(in path)` that names "only
// `core`" without also being reachable from here).
#[allow(dead_code)] // exercised by core.rs's tests today; not yet called from any non-test code path.
pub(crate) struct ActiveWriteTarget<'a> {
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
// `pub(crate)`, not `pub`, for the same reason as `ActiveWriteTarget`: the
// intended (and, as of this revision, only actual) caller is
// `core::ActiveWrite::sync_target()`. See `ActiveWriteTarget`'s doc comment
// for why "only core::ActiveWrite calls this" is a documented convention
// rather than something Rust's visibility system can enforce across sibling
// modules -- the same limitation applies here.
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
pub(crate) struct SyncTarget<'a> {
    file: &'a File,
}

impl SyncTarget<'_> {
    #[allow(dead_code)] // exercised by core.rs's/write_job.rs's tests today; not yet called from any non-test code path.
    pub(crate) fn sync_all(&self) -> io::Result<()> {
        self.file.sync_all()
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

// Calls org.freedesktop.UDisks2.Block.OpenDevice(mode, options) and returns
// the resulting file descriptor, wrapped so it can only be inspected
// read-only and closed — this type exposes no write/seek API at all.
//
// `mode` is UDisks2's own vocabulary: "r" (read-only), "w" (write-only), or
// "rw" (read-write). This is a genuine, unprivileged D-Bus method call — any
// privilege escalation happens inside UDisks2/polkit using the caller's own
// session, not via sudo or any bypass initiated by this program. If polkit
// requires interactive authentication, this call simply blocks until the
// user's own polkit agent (e.g. a graphical prompt) is answered or the
// request times out/is denied.
pub fn open_device(block_path: &str, mode: &str) -> Result<OpenedDeviceHandle, OpenDeviceError> {
    let connection =
        Connection::system().map_err(|error| OpenDeviceError::ConnectionFailed(error.to_string()))?;

    let block = Proxy::new(
        &connection,
        "org.freedesktop.UDisks2",
        block_path,
        "org.freedesktop.UDisks2.Block",
    )
    .map_err(|error| OpenDeviceError::CallFailed(error.to_string()))?;

    let options: HashMap<String, OwnedValue> = HashMap::new();

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
    pub(crate) fn writer_target(&mut self) -> ActiveWriteTarget<'_> {
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
    pub(crate) fn sync_target(&self) -> SyncTarget<'_> {
        SyncTarget { file: &self.file }
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
