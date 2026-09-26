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
    alloc::{self, Layout},
    collections::HashMap,
    ffi::{c_int, c_ulong},
    fmt,
    fs::File,
    io::{self, Write},
    os::fd::{AsRawFd, RawFd},
    os::unix::fs::{FileExt, MetadataExt},
    ptr::NonNull,
};

use zbus::{
    blocking::{Connection, Proxy},
    zvariant::OwnedValue,
};

use crate::linux_backend::decode_device_number;

// Why OpenDevice did not return a file descriptor. Classified only by the
// D-Bus error name (a fixed, locale-independent identifier), never by the
// message text. For display, diagnostics and logging only: no safety
// decision depends on which variant this is, and a failed open is never
// retried -- in particular never without O_EXCL.
//
// Fields are read only via the derived Debug impl (rustc's dead-code lint
// doesn't count that as a use), which is how call sites report the failure.
#[allow(dead_code)]
#[derive(Debug)]
pub enum OpenDeviceError {
    // The system bus could not be reached.
    Connection(String),
    // polkit did not authorize the open.
    NotAuthorized(AuthorizationDenial),
    // Any other D-Bus error reply. This includes UDisks2's generic
    // org.freedesktop.UDisks2.Error.Failed, which is how the open(2) failure
    // itself is reported -- EBUSY from O_EXCL (the device is in use), EIO,
    // ENOENT, ... all alike. UDisks2 does not return the errno, only a
    // message with its text, so the cause is not classified further.
    Rejected {
        name: String,
        message: Option<String>,
    },
    // A failure that is not a D-Bus error reply (the connection was lost, the
    // reply could not be read, ...).
    Transport(String),
}

// The three authorization errors UDisks2 defines (udisksenums.h).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorizationDenial {
    // org.freedesktop.UDisks2.Error.NotAuthorized
    NotAuthorized,
    // org.freedesktop.UDisks2.Error.NotAuthorizedCanObtain: authorization is
    // possible, e.g. by authenticating, but was not obtained.
    CanObtain,
    // org.freedesktop.UDisks2.Error.NotAuthorizedDismissed: an
    // authentication prompt was shown and dismissed.
    Dismissed,
}

// Exact error-name match only; any other name is not an authorization error.
fn authorization_denial(error_name: &str) -> Option<AuthorizationDenial> {
    match error_name {
        "org.freedesktop.UDisks2.Error.NotAuthorized" => Some(AuthorizationDenial::NotAuthorized),
        "org.freedesktop.UDisks2.Error.NotAuthorizedCanObtain" => {
            Some(AuthorizationDenial::CanObtain)
        }
        "org.freedesktop.UDisks2.Error.NotAuthorizedDismissed" => {
            Some(AuthorizationDenial::Dismissed)
        }
        _ => None,
    }
}

// A D-Bus error reply, by its name. The message is kept as it is, for
// display only; it is never looked at here.
fn error_reply(error_name: &str, message: Option<&str>) -> OpenDeviceError {
    match authorization_denial(error_name) {
        Some(denial) => OpenDeviceError::NotAuthorized(denial),
        None => OpenDeviceError::Rejected {
            name: error_name.to_string(),
            message: message.map(str::to_string),
        },
    }
}

// zbus reports every D-Bus error reply as `Error::MethodError(name, detail,
// reply)`; `Error::FDO` carries a standard org.freedesktop.DBus.Error.* one
// that zbus has already decoded. Everything else is not a reply from the
// service at all.
fn open_device_error(error: zbus::Error) -> OpenDeviceError {
    use zbus::DBusError;

    match error {
        zbus::Error::MethodError(name, message, _reply) => {
            error_reply(name.as_str(), message.as_deref())
        }
        zbus::Error::FDO(error) => error_reply(error.name().as_str(), error.description()),
        other => OpenDeviceError::Transport(other.to_string()),
    }
}

pub struct OpenedDeviceHandle {
    file: File,
    // Test-only stand-in for `direct_read_geometry()`'s kernel queries,
    // which a regular test file cannot answer: `Some(Some(g))` reports `g`,
    // `Some(None)` reports a failure, `None` asks the kernel as in production.
    #[cfg(test)]
    test_direct_geometry: Option<Option<DirectReadGeometry>>,
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
    // The disk sequence number of the block device this FD is bound to, from
    // a read-only BLKGETDISKSEQ ioctl; None if it could not be obtained (not
    // a block device, or a kernel older than 5.15).
    pub diskseq: Option<u64>,
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
//   - `ReadOnlyDirect`: read-only, with `O_DIRECT`, without `O_EXCL`. For
//     Verify. `O_DIRECT` makes the kernel read the device itself instead of
//     answering from the page cache, which may still hold what was just
//     written; there is deliberately no buffered read-only access, so
//     Verify cannot fall back to one. No `O_EXCL`, because Verify must still
//     work when the desktop auto-mounts a freshly written partition (see
//     `core::check_identity_instance_for_verify`) -- an exclusive open would
//     then fail although the write succeeded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenAccess {
    WriteExclusive,
    ReadOnlyDirect,
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
        OpenAccess::ReadOnlyDirect => {
            options.insert("flags".to_string(), OwnedValue::from(libc::O_DIRECT));
            "r"
        }
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
// fails here like any other open failure (`OpenDeviceError::Rejected`),
// before any FD exists. There is exactly one OpenDevice call: a failure is
// returned as it is, never retried with other access or flags.
pub fn open_device(
    block_path: &str,
    access: OpenAccess,
) -> Result<OpenedDeviceHandle, OpenDeviceError> {
    let connection =
        Connection::system().map_err(|error| OpenDeviceError::Connection(error.to_string()))?;

    let block = Proxy::new(
        &connection,
        "org.freedesktop.UDisks2",
        block_path,
        "org.freedesktop.UDisks2.Block",
    )
    .map_err(open_device_error)?;

    let (mode, options) = open_device_arguments(access);

    let fd: zbus::zvariant::OwnedFd = block
        .call("OpenDevice", &(mode, options))
        .map_err(open_device_error)?;

    let std_fd: std::os::fd::OwnedFd = fd.into();

    Ok(OpenedDeviceHandle {
        file: File::from(std_fd),
        #[cfg(test)]
        test_direct_geometry: None,
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

// BLKGETDISKSEQ = _IOR(0x12, 128, __u64), from <linux/fs.h> (Linux 5.15+).
// Reports the sequence number of the disk the FD is bound to: the same value
// /sys/block/<name>/diskseq shows, which the kernel gives every newly created
// disk and every media change. A read-only ioctl that needs no privilege.
// The request number is taken from linux-raw-sys, which carries the value for
// each architecture, rather than written here. Any failure (ENOTTY for a
// regular file or a kernel without this ioctl) is reported as None.
fn read_diskseq_via_ioctl(fd: RawFd) -> Option<u64> {
    let mut diskseq: u64 = 0;

    // SAFETY: `fd` is a valid, open file descriptor for the lifetime of this
    // call (borrowed from `OpenedDeviceHandle`, which owns it), and the
    // pointer argument points to a valid local `u64`, the size this ioctl
    // writes. This ioctl is read-only: it cannot mutate the device.
    let result = unsafe {
        libc::ioctl(
            fd,
            linux_raw_sys::ioctl::BLKGETDISKSEQ as libc::Ioctl,
            &mut diskseq as *mut u64,
        )
    };

    if result == 0 { Some(diskseq) } else { None }
}

impl OpenedDeviceHandle {
    // Test-only construction path. Lets unit tests (in `core.rs`) exercise
    // the Write Gate's handle-ownership handoff into `PreparedWrite` against
    // a plain, throwaway regular file -- never a block device -- without any
    // D-Bus call. This is compiled only for `cfg(test)` and is `pub(crate)`,
    // so no non-test code anywhere in the crate can reach it: the only way to
    // obtain an `OpenedDeviceHandle` in a real build remains `open_device`,
    // which is the sole path that ever calls UDisks2's Block.OpenDevice.
    //
    // Its direct-read geometry is a lenient one (every offset aligned, no
    // capacity limit) so the Verify tests that predate O_DIRECT read the
    // file as before; tests of the direct-read rules set their own with
    // `set_direct_geometry_for_test`.
    #[cfg(test)]
    pub(crate) fn from_file_for_test(file: File) -> Self {
        OpenedDeviceHandle {
            file,
            test_direct_geometry: Some(Some(DirectReadGeometry::for_test(1, 1, u64::MAX))),
        }
    }

    #[cfg(test)]
    pub(in crate::execution) fn set_direct_geometry_for_test(
        &mut self,
        geometry: Option<DirectReadGeometry>,
    ) {
        self.test_direct_geometry = Some(geometry);
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
        let diskseq = read_diskseq_via_ioctl(raw_fd);
        let proc_fd_target = std::fs::read_link(format!("/proc/self/fd/{raw_fd}"))
            .ok()
            .map(|path| path.to_string_lossy().into_owned());

        Some(FdMetadata {
            major,
            minor,
            size,
            diskseq,
            proc_fd_target,
        })
    }
}

impl OpenedDeviceHandle {
    // The alignment rules for reading this FD with O_DIRECT, asked from the
    // kernel for this very FD -- never assumed. See `DirectReadGeometry`.
    pub(in crate::execution) fn direct_read_geometry(
        &self,
    ) -> Result<DirectReadGeometry, DirectReadSetupError> {
        #[cfg(test)]
        if let Some(geometry) = self.test_direct_geometry {
            return geometry.ok_or(DirectReadSetupError::LogicalBlockSize(io::Error::other(
                "test: no direct-read geometry",
            )));
        }

        query_direct_read_geometry(&self.file)
    }

    // A reader of this FD that follows `geometry`, for ranges of up to
    // `max_want` bytes.
    pub(in crate::execution) fn direct_read_target(
        &self,
        geometry: DirectReadGeometry,
        max_want: usize,
    ) -> io::Result<DirectReadTarget<'_>> {
        let buffer = AlignedBuffer::new(geometry.buffer_len(max_want)?, geometry.buffer_alignment)?;

        Ok(DirectReadTarget {
            target: self.reader_target(),
            geometry,
            buffer,
        })
    }
}

// The most one direct read asks for. With the buffer aligned to at least a
// page, such a read covers at most 256 pages, which the kernel serves with
// a single bio (BIO_MAX_VECS); it is also what Verify compares at a time.
const MAX_DIRECT_READ: u64 = 1024 * 1024;

// How an O_DIRECT FD must be read, as the kernel reports it for that FD:
//
//   - `logical_block_size` (BLKSSZGET): every read's file offset and length
//     must be a multiple of it, or the kernel refuses the read (EINVAL);
//   - `memory_alignment` (statx STATX_DIOALIGN, `stx_dio_mem_align`: for a
//     block device, its DMA alignment + 1): every read's buffer position
//     must be a multiple of it. The buffer itself is allocated aligned to
//     that or to the page size, whichever is larger -- a power of two that
//     is a multiple of the other -- so a read starting at the buffer (or a
//     whole MAX_DIRECT_READ into it) also starts on a page boundary;
//   - `capacity` (BLKGETSIZE64): a read never extends past the device's end.
//
// Obtained only from a successful kernel query: there is no default, so a
// value that cannot be read ends Verify before it starts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::execution) struct DirectReadGeometry {
    logical_block_size: u64,
    memory_alignment: u64,
    buffer_alignment: usize,
    capacity: u64,
}

// Why an FD cannot be read under the direct-read rules. Fields are read
// only via the derived Debug impl, which is how call sites report it.
#[allow(dead_code)]
#[derive(Debug)]
pub enum DirectReadSetupError {
    // The FD is not open with O_DIRECT, so its reads could come from the
    // page cache.
    NotDirect,
    // BLKSSZGET failed.
    LogicalBlockSize(io::Error),
    // statx failed, or did not report STATX_DIOALIGN (a kernel older than
    // 6.11 does not for block devices).
    DirectIoAlignment(Option<io::Error>),
    // BLKGETSIZE64 failed.
    Capacity,
    // The page size could not be read.
    PageSize,
    // The reported values cannot be used: `logical_block_size` and
    // `offset_alignment` must agree, and every value must be a power of two
    // that a MAX_DIRECT_READ-sized read can respect.
    Unusable {
        logical_block_size: u64,
        offset_alignment: u64,
        memory_alignment: u64,
        page_size: u64,
    },
}

impl DirectReadGeometry {
    // Checks the kernel-reported values and derives the buffer alignment.
    fn from_reported(
        is_direct: bool,
        logical_block_size: u64,
        offset_alignment: u64,
        memory_alignment: u64,
        capacity: u64,
        page_size: u64,
    ) -> Result<Self, DirectReadSetupError> {
        if !is_direct {
            return Err(DirectReadSetupError::NotDirect);
        }

        let unusable = DirectReadSetupError::Unusable {
            logical_block_size,
            offset_alignment,
            memory_alignment,
            page_size,
        };
        let fits = |value: u64| value.is_power_of_two() && value <= MAX_DIRECT_READ;

        if offset_alignment != logical_block_size
            || !fits(logical_block_size)
            || !fits(memory_alignment)
            || !fits(page_size)
        {
            return Err(unusable);
        }

        let buffer_alignment =
            usize::try_from(memory_alignment.max(page_size)).map_err(|_| unusable)?;

        Ok(DirectReadGeometry {
            logical_block_size,
            memory_alignment,
            buffer_alignment,
            capacity,
        })
    }

    // Test-only: a geometry as if reported, with a 4096-byte page.
    #[cfg(test)]
    pub(in crate::execution) fn for_test(
        logical_block_size: u64,
        memory_alignment: u64,
        capacity: u64,
    ) -> Self {
        DirectReadGeometry {
            logical_block_size,
            memory_alignment,
            buffer_alignment: memory_alignment.max(4096) as usize,
            capacity,
        }
    }

    // The buffer a range of up to `max_want` bytes needs once widened to
    // block boundaries: at most one block on each side.
    fn buffer_len(&self, max_want: usize) -> io::Result<usize> {
        let block = self.logical_block_size;
        let len = (max_want as u64)
            .checked_next_multiple_of(block)
            .and_then(|len| len.checked_add(block))
            .ok_or_else(|| io::Error::other("direct read buffer size overflows"))?;

        usize::try_from(len.max(1)).map_err(|_| io::Error::other("direct read buffer too large"))
    }

    // The block-aligned range to read so that it covers the `want` bytes
    // at `offset`: [start, start + len) with start <= offset and
    // start + len >= offset + want. Refused when it would reach past the
    // device's end -- the rounding is never assumed to fit.
    fn aligned_span(&self, offset: u64, want: u64) -> Result<(u64, u64), DirectReadFailure> {
        let block = self.logical_block_size;
        let start = offset - offset % block;
        let end = offset
            .checked_add(want)
            .and_then(|end| end.checked_next_multiple_of(block))
            .ok_or(DirectReadFailure::OutsideDevice)?;

        if end > self.capacity {
            return Err(DirectReadFailure::OutsideDevice);
        }

        Ok((start, end - start))
    }
}

fn query_direct_read_geometry(file: &File) -> Result<DirectReadGeometry, DirectReadSetupError> {
    let fd = file.as_raw_fd();

    // SAFETY: F_GETFL takes no argument and only reads the FD's flags.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags == -1 {
        return Err(DirectReadSetupError::NotDirect);
    }
    if flags & libc::O_DIRECT == 0 {
        return Err(DirectReadSetupError::NotDirect);
    }

    let mut logical_block_size: c_int = 0;
    // SAFETY: `fd` is open for the duration of the call, and BLKSSZGET
    // writes one `int` into the pointed-to local. Read-only ioctl.
    let result = unsafe { libc::ioctl(fd, libc::BLKSSZGET, &mut logical_block_size as *mut c_int) };
    if result != 0 {
        return Err(DirectReadSetupError::LogicalBlockSize(
            io::Error::last_os_error(),
        ));
    }
    let logical_block_size = u64::try_from(logical_block_size).unwrap_or(0);

    // SAFETY: an all-zero `statx` is a valid value of this plain C struct.
    let mut stat: libc::statx = unsafe { std::mem::zeroed() };
    // SAFETY: `fd` is open; the empty, NUL-terminated path with AT_EMPTY_PATH
    // makes statx describe `fd` itself; `stat` is a valid, writable struct.
    let result = unsafe {
        libc::statx(
            fd,
            c"".as_ptr(),
            libc::AT_EMPTY_PATH,
            libc::STATX_DIOALIGN,
            &mut stat,
        )
    };
    if result != 0 {
        return Err(DirectReadSetupError::DirectIoAlignment(Some(
            io::Error::last_os_error(),
        )));
    }
    if stat.stx_mask & libc::STATX_DIOALIGN == 0 {
        return Err(DirectReadSetupError::DirectIoAlignment(None));
    }

    let capacity = read_size_via_ioctl(fd).ok_or(DirectReadSetupError::Capacity)?;

    // SAFETY: sysconf only reads a system value.
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    let page_size = u64::try_from(page_size).map_err(|_| DirectReadSetupError::PageSize)?;

    DirectReadGeometry::from_reported(
        true,
        logical_block_size,
        u64::from(stat.stx_dio_offset_align),
        u64::from(stat.stx_dio_mem_align),
        capacity,
        page_size,
    )
}

// A zero-filled heap buffer with a chosen alignment, freed on drop. The
// only unsafe code is the allocation, the slice views and the matching
// deallocation, all with the one `layout` it was allocated with.
struct AlignedBuffer {
    ptr: NonNull<u8>,
    layout: Layout,
}

impl AlignedBuffer {
    fn new(len: usize, alignment: usize) -> io::Result<Self> {
        let layout = Layout::from_size_align(len.max(1), alignment)
            .map_err(|error| io::Error::other(format!("direct read buffer layout: {error}")))?;

        // SAFETY: `layout` has a non-zero size.
        let ptr = unsafe { alloc::alloc_zeroed(layout) };
        let ptr = NonNull::new(ptr).ok_or_else(|| io::Error::from(io::ErrorKind::OutOfMemory))?;

        Ok(AlignedBuffer { ptr, layout })
    }

    fn len(&self) -> usize {
        self.layout.size()
    }

    fn as_mut_slice(&mut self) -> &mut [u8] {
        // SAFETY: `ptr` points to `layout.size()` initialised (zeroed) bytes
        // owned by this buffer, borrowed mutably through `&mut self`.
        unsafe { std::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.layout.size()) }
    }
}

impl Drop for AlignedBuffer {
    fn drop(&mut self) {
        // SAFETY: `ptr` was allocated by `alloc_zeroed` with this `layout`
        // and is freed exactly once, here.
        unsafe { alloc::dealloc(self.ptr.as_ptr(), self.layout) }
    }
}

// Why a direct read did not deliver the requested bytes (the payload of the
// `io::Error` it returns, unless the kernel itself reported an error).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectReadFailure {
    // The block-aligned range would reach past the device's end.
    OutsideDevice,
    // A read returned fewer bytes than asked, and reading on from there
    // would break the alignment rules: the length is not a whole number of
    // blocks, or the buffer position after it is not memory-aligned.
    UnalignedShortRead,
    // The range does not fit the reader's buffer.
    TooLarge,
}

impl fmt::Display for DirectReadFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            DirectReadFailure::OutsideDevice => {
                "the block-aligned direct read would reach past the end of the device"
            }
            DirectReadFailure::UnalignedShortRead => {
                "a direct read returned fewer bytes than asked, ending where it cannot be continued aligned"
            }
            DirectReadFailure::TooLarge => "the direct read range does not fit the buffer",
        };
        f.write_str(text)
    }
}

impl std::error::Error for DirectReadFailure {}

// Reads a Verify FD opened with O_DIRECT under its `DirectReadGeometry`.
pub(in crate::execution) struct DirectReadTarget<'a> {
    target: ReadTarget<'a>,
    geometry: DirectReadGeometry,
    buffer: AlignedBuffer,
}

impl DirectReadTarget<'_> {
    // The `want` bytes of the device at `offset`, read directly: see
    // `direct_read`.
    pub(in crate::execution) fn read(&mut self, offset: u64, want: usize) -> io::Result<&[u8]> {
        let target = &self.target;
        direct_read(
            |buf, at| target.read_at(at, buf),
            &self.geometry,
            &mut self.buffer,
            offset,
            want,
        )
    }
}

// Reads the block-aligned range covering [offset, offset + want) into
// `buffer` through `read_at` and returns exactly the requested bytes. Every
// read starts at a block-aligned offset, at a memory-aligned buffer
// position, and asks for a whole number of blocks (at most
// MAX_DIRECT_READ). A shorter read is continued from where it ended only if
// the next read would still meet all of that; otherwise it is an error, and
// a read of 0 bytes is an UnexpectedEof error. There is no other way to
// read: no buffered retry.
fn direct_read<'b>(
    mut read_at: impl FnMut(&mut [u8], u64) -> io::Result<usize>,
    geometry: &DirectReadGeometry,
    buffer: &'b mut AlignedBuffer,
    offset: u64,
    want: usize,
) -> io::Result<&'b [u8]> {
    let failed = |failure: DirectReadFailure| io::Error::new(io::ErrorKind::InvalidInput, failure);

    if want == 0 {
        return Ok(&buffer.as_mut_slice()[..0]);
    }

    let (start, len) = geometry.aligned_span(offset, want as u64).map_err(failed)?;
    let len = usize::try_from(len).map_err(|_| failed(DirectReadFailure::TooLarge))?;
    if len > buffer.len() {
        return Err(failed(DirectReadFailure::TooLarge));
    }

    let block = geometry.logical_block_size as usize;
    let buf = buffer.as_mut_slice();
    let mut filled = 0usize;

    while filled < len {
        let piece = (len - filled).min(MAX_DIRECT_READ as usize);
        let n = match read_at(&mut buf[filled..filled + piece], start + filled as u64) {
            Ok(n) => n,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        };

        if n == 0 {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
        }
        filled += n;

        if filled < len && (n % block != 0 || filled as u64 % geometry.memory_alignment != 0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                DirectReadFailure::UnalignedShortRead,
            ));
        }
    }

    let skip = (offset - start) as usize;
    Ok(&buf[skip..skip + want])
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

    // A D-Bus error reply to an OpenDevice call, as zbus hands it to us
    // (`Error::MethodError`, built from a real error message).
    fn method_error(name: &str, message: &str) -> zbus::Error {
        let call =
            zbus::Message::method_call("/org/freedesktop/UDisks2/block_devices/sdx", "OpenDevice")
                .unwrap()
                .build(&())
                .unwrap();
        let reply = zbus::Message::error(&call.header(), name)
            .unwrap()
            .build(&(message,))
            .unwrap();

        let error = zbus::Error::from(reply);
        assert!(matches!(error, zbus::Error::MethodError(..)));
        error
    }

    // OpenDevice errors 1-3. The three UDisks2 authorization errors are told
    // apart by their exact name.
    #[test]
    fn authorization_errors_are_classified_by_exact_name() {
        let cases = [
            (
                "org.freedesktop.UDisks2.Error.NotAuthorized",
                AuthorizationDenial::NotAuthorized,
            ),
            (
                "org.freedesktop.UDisks2.Error.NotAuthorizedCanObtain",
                AuthorizationDenial::CanObtain,
            ),
            (
                "org.freedesktop.UDisks2.Error.NotAuthorizedDismissed",
                AuthorizationDenial::Dismissed,
            ),
        ];

        for (name, expected) in cases {
            let error =
                open_device_error(method_error(name, "Not authorized to perform operation"));

            assert!(
                matches!(error, OpenDeviceError::NotAuthorized(denial) if denial == expected),
                "{name}: {error:?}"
            );
        }
    }

    // OpenDevice errors 4-7. UDisks2's generic Error.Failed, and any name not
    // known here, are Rejected with the name and message kept as they are.
    #[test]
    fn other_error_replies_are_rejected_with_name_and_message() {
        for (name, message) in [
            (
                "org.freedesktop.UDisks2.Error.Failed",
                "Error opening device /dev/sdx: Input/output error",
            ),
            ("org.example.Unknown.Error", "something else"),
        ] {
            let error = open_device_error(method_error(name, message));

            match error {
                OpenDeviceError::Rejected {
                    name: kept_name,
                    message: kept_message,
                } => {
                    assert_eq!(kept_name, name);
                    assert_eq!(kept_message.as_deref(), Some(message));
                }
                other => panic!("{name}: expected Rejected, got {other:?}"),
            }
        }
    }

    // A standard org.freedesktop.DBus.Error.* reply that zbus hands over
    // already decoded (`Error::FDO`) keeps its name the same way.
    #[test]
    fn decoded_standard_error_replies_keep_their_name() {
        let error = open_device_error(zbus::Error::FDO(Box::new(zbus::fdo::Error::AccessDenied(
            "denied".to_string(),
        ))));

        assert!(matches!(
            error,
            OpenDeviceError::Rejected { ref name, ref message }
                if name == "org.freedesktop.DBus.Error.AccessDenied"
                    && message.as_deref() == Some("denied")
        ));
    }

    // OpenDevice errors 8. A failure that is not an error reply is Transport.
    #[test]
    fn failures_other_than_error_replies_are_transport() {
        for error in [
            zbus::Error::InvalidReply,
            zbus::Error::Failure("connection lost".to_string()),
        ] {
            assert!(matches!(
                open_device_error(error),
                OpenDeviceError::Transport(_)
            ));
        }
    }

    // OpenDevice errors 9. Only the name classifies: a message saying the
    // device is busy (or even saying "not authorized") does not change an
    // Error.Failed reply, and a name that merely starts like an
    // authorization error is not one. There is no Busy classification.
    #[test]
    fn message_text_never_affects_the_classification() {
        for message in [
            "Error opening device /dev/sdx: Device or resource busy",
            "Not authorized to perform operation",
        ] {
            let error = open_device_error(method_error(
                "org.freedesktop.UDisks2.Error.Failed",
                message,
            ));
            assert!(
                matches!(error, OpenDeviceError::Rejected { ref name, .. }
                    if name == "org.freedesktop.UDisks2.Error.Failed"),
                "{message}: {error:?}"
            );
        }

        let error = open_device_error(method_error(
            "org.freedesktop.UDisks2.Error.NotAuthorizedLater",
            "Not authorized",
        ));
        assert!(
            matches!(error, OpenDeviceError::Rejected { .. }),
            "{error:?}"
        );
    }

    // OpenDevice errors 10. `open_device` makes exactly one OpenDevice call,
    // with the arguments of the access it was given: a failed exclusive open
    // is returned, never retried read-only or without O_EXCL. (main.rs fixes
    // each call site's access separately.)
    #[test]
    fn open_device_calls_open_device_exactly_once_with_the_given_access() {
        let source = include_str!("linux_access.rs");
        let production = &source[..source
            .find("\n#[cfg(test)]\nmod tests {")
            .expect("tests module marker")];

        assert_eq!(production.matches(".call(\"OpenDevice\"").count(), 1);
        assert_eq!(production.matches("open_device_arguments(").count(), 2);

        let start = production
            .find("\npub fn open_device(")
            .expect("open_device definition");
        let end = start
            + production[start..]
                .find("\n}\n")
                .expect("end of open_device");
        let body = &production[start..end];

        assert_eq!(body.matches("open_device_arguments(access)").count(), 1);
        assert!(!body.contains("OpenAccess::"));
        assert!(!body.contains("O_EXCL"));
    }

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
        assert_eq!(flags & libc::O_DIRECT, 0);
        assert_eq!(flags & libc::O_ACCMODE, 0);
        if cfg!(target_arch = "x86_64") {
            assert_eq!(libc::O_EXCL, 0o200);
        }
    }

    // The Verify FD is read-only, direct and not exclusive: mode "r" plus
    // `flags` = O_DIRECT only -- no O_EXCL, no access-mode bits.
    #[test]
    fn read_only_direct_access_is_direct_and_not_exclusive() {
        let (mode, options) = open_device_arguments(OpenAccess::ReadOnlyDirect);

        assert_eq!(mode, "r");
        assert_eq!(options.len(), 1);
        let flags = options.get("flags").expect("flags option present");
        assert_eq!(flags.value_signature().to_string(), "i");
        let flags = i32::try_from(flags).unwrap();
        assert_eq!(flags, libc::O_DIRECT);
        assert_eq!(flags & libc::O_EXCL, 0);
        assert_eq!(flags & libc::O_ACCMODE, 0);
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

    // ---------------------------------------------------------------------
    // Direct reads (O_DIRECT Verify): the geometry the kernel reports, the
    // aligned buffer, the block-aligned range, and the read loop -- against
    // a fake device, since O_DIRECT on a regular file is filesystem-specific
    // and proves nothing about block devices.
    // ---------------------------------------------------------------------

    const MIB: u64 = 1024 * 1024;

    // A test geometry: block size, required memory alignment, capacity.
    fn geometry(
        logical_block_size: u64,
        memory_alignment: u64,
        capacity: u64,
    ) -> DirectReadGeometry {
        DirectReadGeometry::for_test(logical_block_size, memory_alignment, capacity)
    }

    // Values as the kernel reports them for a block device are accepted, and
    // the buffer alignment is the larger of the reported memory alignment
    // and the page size.
    #[test]
    fn direct_geometry_accepts_reported_values() {
        let g = DirectReadGeometry::from_reported(true, 512, 512, 512, 8 * MIB, 4096).unwrap();
        assert_eq!(g, geometry(512, 512, 8 * MIB));
        assert_eq!(g.buffer_alignment, 4096);

        let g = DirectReadGeometry::from_reported(true, 4096, 4096, 4, 8 * MIB, 4096).unwrap();
        assert_eq!(g, geometry(4096, 4, 8 * MIB));
        assert_eq!(g.buffer_alignment, 4096);

        let g = DirectReadGeometry::from_reported(true, 512, 512, 65536, 8 * MIB, 4096).unwrap();
        assert_eq!(g, geometry(512, 65536, 8 * MIB));
        assert_eq!(g.buffer_alignment, 65536);
    }

    // An FD without O_DIRECT is refused: its reads could come from the page
    // cache, and there is no buffered Verify to fall back to.
    #[test]
    fn direct_geometry_requires_o_direct() {
        assert!(matches!(
            DirectReadGeometry::from_reported(false, 512, 512, 512, 8 * MIB, 4096),
            Err(DirectReadSetupError::NotDirect)
        ));
    }

    // Values that cannot be used are refused, never replaced by defaults.
    #[test]
    fn direct_geometry_refuses_unusable_values() {
        for (block, offset, memory, page) in [
            (512, 4096, 512, 4096),  // offset alignment disagrees with the block size
            (0, 0, 512, 4096),       // no block size
            (1000, 1000, 512, 4096), // not a power of two
            (512, 512, 0, 4096),     // no memory alignment
            (512, 512, 3, 4096),     // not a power of two
            (512, 512, 512, 0),      // no page size
            (2 * MIB, 2 * MIB, 512, 4096), // larger than one direct read
        ] {
            assert!(
                matches!(
                    DirectReadGeometry::from_reported(true, block, offset, memory, 8 * MIB, page),
                    Err(DirectReadSetupError::Unusable { .. })
                ),
                "{block} {offset} {memory} {page}"
            );
        }
    }

    // A regular file cannot report a block device's geometry: without
    // O_DIRECT it is refused as such; with O_DIRECT, BLKSSZGET fails and the
    // failure is reported -- no 512-byte default.
    #[test]
    fn a_regular_file_has_no_direct_read_geometry() {
        use std::os::unix::fs::OpenOptionsExt;

        let path = temp_file_path("no-geometry");
        std::fs::write(&path, vec![0u8; 4096]).unwrap();

        let buffered = File::open(&path).unwrap();
        assert!(matches!(
            query_direct_read_geometry(&buffered),
            Err(DirectReadSetupError::NotDirect)
        ));

        if let Ok(direct) = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECT)
            .open(&path)
        {
            assert!(matches!(
                query_direct_read_geometry(&direct),
                Err(DirectReadSetupError::LogicalBlockSize(_))
            ));
        }

        let _ = std::fs::remove_file(&path);
    }

    // The buffer has the requested alignment and length, starts zeroed, and
    // is freed on drop.
    #[test]
    fn aligned_buffer_has_the_requested_alignment() {
        for alignment in [512usize, 4096, 65536] {
            for len in [1usize, 4096, MIB as usize + 8192] {
                let mut buffer = AlignedBuffer::new(len, alignment).unwrap();
                assert_eq!(buffer.as_mut_slice().as_ptr() as usize % alignment, 0);
                assert_eq!(buffer.len(), len);
                assert!(buffer.as_mut_slice().iter().all(|&b| b == 0));
            }
        }
    }

    // Block-aligned ranges: already aligned; an unaligned offset; an
    // unaligned length; both.
    #[test]
    fn aligned_span_widens_to_block_boundaries() {
        let g = geometry(512, 512, 100 * MIB);

        assert_eq!(g.aligned_span(0, 4096), Ok((0, 4096)));
        assert_eq!(g.aligned_span(1000, 24), Ok((512, 512)));
        assert_eq!(g.aligned_span(1000, 100), Ok((512, 1024)));
        assert_eq!(g.aligned_span(0, 1000), Ok((0, 1024)));
        assert_eq!(g.aligned_span(MIB + 777, MIB), Ok((MIB + 512, MIB + 512)));

        let g = geometry(4096, 512, 100 * MIB);
        assert_eq!(g.aligned_span(4097, 1), Ok((4096, 4096)));
    }

    // The device's end: an image ending inside the last block is read up to
    // that block's end only if the block lies within the device; a range
    // whose rounding would pass the end is refused, never assumed to fit.
    #[test]
    fn aligned_span_never_passes_the_device_end() {
        // Capacity on a block boundary: the image's last partial block is
        // read in full.
        let g = geometry(512, 512, 10 * 512);
        assert_eq!(g.aligned_span(9 * 512, 100), Ok((9 * 512, 512)));
        assert_eq!(g.aligned_span(0, 10 * 512), Ok((0, 10 * 512)));
        assert_eq!(
            g.aligned_span(0, 10 * 512 + 1),
            Err(DirectReadFailure::OutsideDevice)
        );

        // Capacity not on a block boundary (not expected of a real device,
        // but never assumed away): the last partial block cannot be read.
        let g = geometry(512, 512, 10 * 512 + 100);
        assert_eq!(
            g.aligned_span(10 * 512, 100),
            Err(DirectReadFailure::OutsideDevice)
        );
        assert_eq!(g.aligned_span(0, 10 * 512), Ok((0, 10 * 512)));

        // Arithmetic overflow is refused too.
        assert_eq!(
            geometry(512, 512, u64::MAX).aligned_span(u64::MAX - 10, 100),
            Err(DirectReadFailure::OutsideDevice)
        );
    }

    fn device_bytes(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i.wrapping_mul(31) >> 3) as u8).collect()
    }

    // A fake device: serves `device` like pread, recording every read (the
    // offset, length and buffer address the direct-read rules constrain), and
    // lets a test shape each reply.
    struct FakeDevice {
        device: Vec<u8>,
        reads: Vec<(u64, usize, usize)>,
    }

    impl FakeDevice {
        fn new(len: usize) -> Self {
            FakeDevice {
                device: device_bytes(len),
                reads: Vec::new(),
            }
        }

        fn serve(
            &mut self,
            buf: &mut [u8],
            offset: u64,
            limit: Option<usize>,
        ) -> io::Result<usize> {
            self.reads.push((offset, buf.len(), buf.as_ptr() as usize));
            let start = offset as usize;
            let n = buf.len().min(self.device.len().saturating_sub(start));
            let n = limit.map_or(n, |limit| n.min(limit));
            buf[..n].copy_from_slice(&self.device[start..start + n]);
            Ok(n)
        }

        fn assert_reads_follow(&self, g: &DirectReadGeometry) {
            assert!(!self.reads.is_empty());
            for &(offset, len, address) in &self.reads {
                assert_eq!(offset % g.logical_block_size, 0, "offset {offset}");
                assert_eq!(len as u64 % g.logical_block_size, 0, "length {len}");
                assert!(len as u64 <= MAX_DIRECT_READ, "length {len}");
                assert_eq!(
                    address as u64 % g.memory_alignment,
                    0,
                    "buffer {address:#x}"
                );
            }
            let first = self.reads[0].2;
            assert_eq!(first % g.buffer_alignment, 0, "first buffer {first:#x}");
        }
    }

    // Only the requested bytes come back, whatever the widened range read;
    // every read follows the rules. Includes offsets like Quick's middle and
    // last windows (not on block boundaries) and an image ending inside a
    // block.
    #[test]
    fn direct_read_returns_exactly_the_requested_bytes() {
        let capacity = 16 * MIB as usize;
        let g = geometry(512, 512, capacity as u64);
        let image_size = 9 * MIB + 777;
        let window = 4 * MIB;
        let middle = image_size / 2 - window / 2;
        let last = image_size - window;

        for (offset, want) in [
            (0u64, MIB as usize),
            (middle, MIB as usize),
            (last + 3 * MIB, MIB as usize),
            (image_size - 777, 777),
            (1000, 1),
            (4096, MIB as usize - 4096),
        ] {
            let mut fake = FakeDevice::new(capacity);
            let mut buffer =
                AlignedBuffer::new(g.buffer_len(MIB as usize).unwrap(), g.buffer_alignment)
                    .unwrap();

            let bytes = direct_read(
                |buf, at| fake.serve(buf, at, None),
                &g,
                &mut buffer,
                offset,
                want,
            )
            .unwrap()
            .to_vec();

            let start = offset as usize;
            assert_eq!(bytes, fake.device[start..start + want], "{offset} {want}");
            fake.assert_reads_follow(&g);
        }
    }

    // Short reads: a shorter read is continued from where it ended when the
    // next read still meets the rules (whole blocks, memory-aligned buffer
    // position); otherwise -- part of a block, a position the memory
    // alignment forbids, or nothing at all -- it is an error. Every attempt
    // is a direct read under the rules; nothing else is tried.
    #[test]
    fn direct_read_short_reads() {
        let g = geometry(512, 512, 4 * MIB);
        let mut buffer =
            AlignedBuffer::new(g.buffer_len(MIB as usize).unwrap(), g.buffer_alignment).unwrap();

        // Whole blocks, 2 at a time: continued to the end.
        let mut fake = FakeDevice::new(4 * MIB as usize);
        let bytes = direct_read(
            |buf, at| fake.serve(buf, at, Some(1024)),
            &g,
            &mut buffer,
            700,
            5000,
        )
        .unwrap()
        .to_vec();
        assert_eq!(bytes, fake.device[700..5700]);
        fake.assert_reads_follow(&g);
        assert!(fake.reads.len() > 1);

        // Part of a block: refused.
        let mut fake = FakeDevice::new(4 * MIB as usize);
        let error = direct_read(
            |buf, at| fake.serve(buf, at, Some(100)),
            &g,
            &mut buffer,
            0,
            5000,
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(fake.reads.len(), 1);

        // Whole blocks, but ending where the required memory alignment
        // (4096 here) would be broken: refused, not continued misaligned.
        let strict = geometry(512, 4096, 4 * MIB);
        let mut strict_buffer = AlignedBuffer::new(
            strict.buffer_len(MIB as usize).unwrap(),
            strict.buffer_alignment,
        )
        .unwrap();
        let mut fake = FakeDevice::new(4 * MIB as usize);
        let error = direct_read(
            |buf, at| fake.serve(buf, at, Some(1024)),
            &strict,
            &mut strict_buffer,
            0,
            8192,
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(fake.reads.len(), 1);

        // Nothing: the device ended early.
        let mut fake = FakeDevice::new(4 * MIB as usize);
        let error = direct_read(
            |buf, at| fake.serve(buf, at, Some(0)),
            &g,
            &mut buffer,
            0,
            5000,
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
        assert_eq!(fake.reads.len(), 1);
    }

    // A failed direct read is returned as it is -- the only read attempted.
    // An interrupted one is simply retried.
    #[test]
    fn direct_read_failures_are_returned_without_another_attempt() {
        let g = geometry(512, 512, 4 * MIB);
        let mut buffer =
            AlignedBuffer::new(g.buffer_len(MIB as usize).unwrap(), g.buffer_alignment).unwrap();

        let mut attempts = 0;
        let error = direct_read(
            |_, _| {
                attempts += 1;
                Err(io::Error::from_raw_os_error(libc::EINVAL))
            },
            &g,
            &mut buffer,
            0,
            4096,
        )
        .unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EINVAL));
        assert_eq!(attempts, 1);

        let mut fake = FakeDevice::new(4 * MIB as usize);
        let mut interrupted = true;
        let bytes = direct_read(
            |buf, at| {
                if std::mem::take(&mut interrupted) {
                    return Err(io::Error::from(io::ErrorKind::Interrupted));
                }
                fake.serve(buf, at, None)
            },
            &g,
            &mut buffer,
            0,
            4096,
        )
        .unwrap()
        .to_vec();
        assert_eq!(bytes, fake.device[..4096]);
    }

    // A range outside the device or larger than the buffer is refused before
    // anything is read.
    #[test]
    fn direct_read_refuses_ranges_it_cannot_read_directly() {
        let g = geometry(512, 512, 10 * 512 + 100);
        let mut buffer =
            AlignedBuffer::new(g.buffer_len(4096).unwrap(), g.buffer_alignment).unwrap();
        let mut attempts = 0;
        let mut read = |_: &mut [u8], _: u64| {
            attempts += 1;
            Ok(0)
        };

        let error = direct_read(&mut read, &g, &mut buffer, 10 * 512, 100).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        let error = direct_read(&mut read, &g, &mut buffer, 0, 8192).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(attempts, 0);
    }
}
