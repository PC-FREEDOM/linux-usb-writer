// Linux Backend responsibility, kept separate from `linux_backend.rs`
// (read-only collection) because this module deliberately crosses into
// privileged, write-capable territory: calling UDisks2's Block.OpenDevice,
// holding the resulting file descriptor, and reading its raw kernel metadata.
//
// This module's job stops at collection and read-only FD inspection. It
// never decides whether a Selection is valid, never compares against a
// DeviceSnapshot, and — critically for this PoC — never writes a single byte
// to the opened device. Those judgements belong to `core.rs`.

use std::{
    collections::HashMap,
    ffi::{c_int, c_ulong},
    fs::File,
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
