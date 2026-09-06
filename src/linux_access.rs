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
