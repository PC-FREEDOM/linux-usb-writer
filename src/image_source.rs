// ImageSource: a pure, target-agnostic abstraction over "how to read the
// image the user selected." This module knows nothing about the write
// target: no `DeviceSnapshot`, `SelectionState`, `WriteIntent`,
// `ConfirmationToken`, `VerifyMode`, `WritePlan`, `OpenedDeviceHandle`,
// `ActiveWrite`, `AuthorizedWrite`, `RawFd`, UDisks2 types, or
// `CancelHandle` appear anywhere below -- those all belong to the Write
// Gate / Job layers in `core.rs`/`write_job.rs`, and mixing them in here
// would be exactly the kind of cross-layer responsibility CLAUDE.md's
// architecture section warns against.
//
// This is deliberately a distinct responsibility from `core::ImageSelection`
// (`image_size` + `image_generation`): `ImageSelection` answers "what did
// the user explicitly choose, and when?" (a Selection-event identity, no
// I/O involved) -- `ImageSource` answers "given that choice, how do I
// actually read its bytes?" `ImageGeneration` minting and Selection-event
// bookkeeping stay entirely on the `ImageSelection` side; nothing here
// mints a generation or tracks a selection event. `SelectedImage` (below)
// is the type that binds a confirmed `ImageSelection` to the specific
// `ImageSource` it was computed from, so the two can't be mismatched the
// way a caller could otherwise pair one image's `ImageSelection` with a
// different image's `ImageSource` -- see its own doc comment. Whether a
// specific `SelectedImage` matches what a Gate-authorized write actually
// confirmed is a further check `write_job.rs`'s `AuthorizedExecution::
// bind()` performs, immediately before a write starts; that binding
// capability lives in `write_job.rs`, not here (see "Not implemented here"
// below).
//
// The central capability this module exists to provide: **fresh readers
// over a fixed file identity**. `write_job::AuthorizedExecution::
// begin_write()` (the only production caller of `open_reader()` this
// revision has) takes a single, already-owned reader and consumes it once
// per write attempt. A future Full Verify needs to read the same logical
// image a second time (write once, then read-back-compare against the
// target) -- which a single, already-consumed `Read` cannot do.
// `ImageSource::open_reader()` can be called any number of times, and each
// call returns an independent reader that starts at the image's beginning,
// unaffected by how far any previously returned reader was read -- and,
// critically, every reader reads the exact same underlying file description
// `FileImageSource::new` originally opened, never a fresh `File::open()` of
// whatever the path currently resolves to. See `FileImageSource`'s doc
// comment for why this matters and exactly what it does/doesn't guarantee.
//
// Not implemented here (deliberately out of scope this revision): wiring
// `write_job::AuthorizedExecution`/`WritingExecution` into any real
// Controller/`main.rs` production call site, a compressed (gzip/xz)
// `ImageSource` implementation, a URL/network `ImageSource` implementation,
// and any `Verifying`/Quick-Verify/Full-Verify logic that would consume a
// second `open_reader()` call. Only the abstraction itself, plus a single
// plain-file implementation and the `SelectedImage` binding type, exist
// below.
//
// This whole module is therefore unreachable from any production code path
// today (`main.rs` only declares `mod image_source;`, it never names
// anything inside it), which is why every public item below would otherwise
// trigger rustc's `dead_code` lint under a plain `cargo check`. A single
// module-level allow says so once, honestly, instead of scattering
// per-item annotations that would all say the same thing -- the same
// convention `write_job.rs` already uses for the same reason. This is a
// temporary measure: once a real write/verify path actually connects to
// `ImageSource`, this module-wide allow should be removed.
#![allow(dead_code)]

use std::fs::File;
use std::io::{self, Read};
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::core::ImageSelection;

// Why `FileImageSource::new` refused to construct a source. Deliberately
// small and specific to construction-time failures -- `open_reader()`
// itself still reports `io::Result` (see the trait below), so this type
// does not need to cover every possible I/O failure, only the ones
// `new()` can observe before any `ImageSource` value exists to hand back.
#[derive(Debug)]
pub enum ImageSourceError {
    // Opening the path, or reading its metadata, failed at the OS level
    // (not found, permission denied, etc.).
    Io(io::Error),
    // The path resolved to something other than a regular file (a
    // directory, a block/character device, a FIFO, a socket, ...) --
    // obviously inappropriate as a USB-writer image, so this is rejected
    // at construction rather than left for a confusing failure later.
    // Checked via the *opened* file's own metadata (an `fstat` on the
    // already-open fd), not a separate path-based `stat`/`lstat` call, so
    // a symlink that ultimately resolves to a regular file is accepted --
    // this only rejects what the file actually *is*, not how the path
    // reached it.
    NotRegularFile,
}

// The kind of repeated access an `ImageSource` can honestly provide,
// beyond the baseline "call `open_reader()` again for a fresh full replay"
// every implementation must support. This exists purely so a future Quick
// Verify design has something to branch on -- no Quick Verify algorithm is
// decided or implemented here.
//
// `#[allow(dead_code)]`: `RandomAccess` is not constructed by anything in
// this revision (this trait exposes no seek/offset-based read method for
// an implementation to honestly claim it), mirroring `VerifyMode`'s
// `Quick`/`Full` variants -- the shape is declared now so a future
// capability (e.g. an `open_reader_at(offset)` method, or a `Seek`-bound
// variant of `open_reader()`) has a variant to report through without a
// breaking API change.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageSourceAccess {
    // The only access pattern any implementation below actually provides:
    // `open_reader()` can be called repeatedly, and each call replays the
    // image from the beginning, but there is no way to jump to an
    // arbitrary offset within a single reader.
    SequentialReplay,
    RandomAccess,
}

// A selected image, reduced to the one thing the write/verify path needs
// from it: the ability to open independent, fresh readers over its bytes,
// as many times as needed. Deliberately minimal -- see the module doc
// comment for the full list of target-side concerns this trait must never
// grow to know about.
//
// Object-safe on purpose (no generic methods, no `Self` in argument or
// non-`Box`/reference return position): nothing here requires
// `Box<dyn ImageSource>` today, but a future GUI/Controller layer choosing
// between a `FileImageSource`/a future compressed source/a future network
// source at runtime will need exactly that, and this shape already
// supports it without changes.
//
// No `Send`/`Sync`/`'static`/`Seek`/`BufRead` bound is required here. Those
// are real constraints a future background-thread Job runner or a future
// Quick-Verify random-access design might need, but adding them
// speculatively now would already rule out perfectly reasonable future
// sources (e.g. a `Read`-only decompressing stream cannot always be
// rewound, so it must never be forced to implement `Seek`) for no benefit
// today.
pub trait ImageSource {
    // The logical size of the image, fixed at construction time and
    // independent of how many times (or whether) it has been read yet, and
    // independent of what may happen to the underlying file afterward (see
    // `FileImageSource`'s doc comment). Needed wherever a byte count must
    // be known before/without opening a reader -- e.g. building a
    // `core::ImageSelection`/`writer::WritePlan` with the same value this
    // method reports. This module does not connect the two automatically;
    // see the module doc comment and `reports/latest.md` for why.
    fn logical_size(&self) -> u64;

    // What kind of repeated access this source can honestly provide,
    // beyond plain sequential replay via `open_reader()`. See
    // `ImageSourceAccess`'s doc comment.
    fn access(&self) -> ImageSourceAccess;

    // Opens a brand-new, independent reader starting at the image's first
    // byte. Calling this multiple times must never return readers that
    // share read position with one another, and consuming one returned
    // reader down to EOF must have no effect on any other reader obtained
    // from this same source, before or after. `io::Result`, not a bespoke
    // error type: what can go wrong while actually streaming bytes is
    // exactly the same class of failure `std::io` already models, and
    // every consumer of this trait already works with `io::Result` via
    // `std::io::Read` elsewhere in this crate.
    fn open_reader(&self) -> io::Result<Box<dyn Read>>;
}

// The only `ImageSource` implementation in this revision: a plain regular
// file on local disk. Deliberately does not attempt to handle compressed
// (gzip/xz) or network (URL) images -- those are separate, future
// implementations of the same trait, not variants of this one.
//
// v0.1 safety guarantee (path-swap TOCTOU): `new()` opens `path` exactly
// once and keeps that open file (`Arc<File>`) for the lifetime of this
// value. `open_reader()` below never calls `File::open(&self.path)` again
// -- every reader it hands out reads from the *same* already-open file
// description `new()` obtained, via `std::os::unix::fs::FileExt::read_at`
// (a positional `pread`, not the shared stream position `Read::read` on a
// bare `File` would use). This means:
//
//   - if `path` is later deleted, renamed away, or made to point at a
//     different file (`rename()` over it, a symlink retargeted, ...),
//     every `open_reader()` call still reads the original file this
//     `FileImageSource` was constructed from -- Unix open-file semantics
//     keep an already-open file description valid and referring to the
//     same underlying file regardless of what its original path now
//     resolves to (this holds even after the path is unlinked entirely);
//   - `logical_size()` is fixed at construction time and never re-read
//     from the filesystem afterward, so a reader can never read past the
//     size this `FileImageSource` reported when it was built, even if the
//     same underlying file is later grown;
//   - `path` itself is kept only for diagnostics (see `path()` below) --
//     it is never touched again by `open_reader()`.
//
// What this does NOT guarantee (kept as known, documented v0.1 limits --
// see `reports/latest.md`'s TOCTOU section for the full discussion):
//
//   - content mutation of the *same* underlying file (an external process
//     `pwrite`-ing, `mmap`-writing, or truncating the same inode this
//     `FileImageSource` has open) is not detected or prevented. A shrink
//     surfaces naturally as a short read once `open_reader()`'s reader
//     runs past the file's current real end (`read_at` returns `Ok(0)`
//     there, well before `logical_size` bytes have been read), which the
//     existing `writer::write()` already reports as
//     `WriteError::SourceTooShort` rather than a silently short "success"
//     -- so this is *detected downstream*, not prevented here;
//   - there is no whole-image hash, no full pre-read, and no temporary
//     snapshot copy -- this module trades a stronger content-fixation
//     guarantee for keeping `open_reader()` cheap (open-once, then plain
//     positional reads) in line with this project's "Safety before write,
//     minimal overhead during write" principle. A full defense against
//     same-inode content mutation, if ever needed, is future work, not
//     something this revision attempts.
#[derive(Debug, Clone)]
pub struct FileImageSource {
    file: Arc<File>,
    path: PathBuf,
    logical_size: u64,
}

impl FileImageSource {
    // Opens `path` once, up front, and keeps that exact open file for the
    // lifetime of this value (see the struct's own doc comment for why).
    // Size/regular-file checks are read from the *opened* file's own
    // metadata (`File::metadata()`, an `fstat` on the fd) rather than a
    // separate `std::fs::metadata(path)` path-based call, so what they
    // observe is guaranteed to be about the exact file that was just
    // opened -- the same file every subsequent `open_reader()` call will
    // read from, never a different one.
    //
    // Zero-size files are accepted here (`logical_size` can be `0`):
    // deciding whether a zero-byte image is usable for a write is
    // `writer::WritePlan::new`'s job (it already rejects `image_size == 0`
    // via `WriteError::InvalidSize`), not this constructor's. Re-checking
    // the same condition here would duplicate that responsibility in two
    // places for no benefit -- `ImageSource`'s only job is to faithfully
    // represent what is actually on disk, not to judge whether it is
    // writable.
    pub fn new(path: impl Into<PathBuf>) -> Result<Self, ImageSourceError> {
        let path = path.into();
        let file = File::open(&path).map_err(ImageSourceError::Io)?;
        let metadata = file.metadata().map_err(ImageSourceError::Io)?;

        if !metadata.is_file() {
            return Err(ImageSourceError::NotRegularFile);
        }

        Ok(FileImageSource {
            file: Arc::new(file),
            path,
            logical_size: metadata.len(),
        })
    }

    // The path this source was constructed from. `pub` purely for
    // diagnostics (e.g. a future GUI showing "reading from: <path>") --
    // nothing in this crate reads it back to compare against anything
    // today, and `open_reader()` never re-opens it: this getter exists for
    // *display*, not for locating the bytes to read.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl ImageSource for FileImageSource {
    fn logical_size(&self) -> u64 {
        self.logical_size
    }

    // Only `SequentialReplay`: this implementation exposes no seek/offset
    // API (see the trait's own doc comment), even though `read_at` is used
    // internally -- what matters here is what this abstraction actually
    // promises callers (a `Box<dyn Read>`, nothing more), not what the
    // implementation happens to use underneath.
    fn access(&self) -> ImageSourceAccess {
        ImageSourceAccess::SequentialReplay
    }

    // Hands out a `FileImageReader` sharing this source's already-open
    // `Arc<File>` -- no `File::open(&self.path)` call here at all. Each
    // call clones the `Arc` (a refcount bump, not a syscall) and starts a
    // brand-new reader at position 0; the `Arc` clone is exactly why
    // multiple simultaneously-held readers can each keep the underlying
    // file alive and keep reading from it independently.
    fn open_reader(&self) -> io::Result<Box<dyn Read>> {
        Ok(Box::new(FileImageReader {
            file: Arc::clone(&self.file),
            position: 0,
            logical_size: self.logical_size,
        }))
    }
}

// One independent reader over a `FileImageSource`'s already-open file.
// Deliberately does NOT use `Read`/`Seek` on a shared `File` (which has a
// single, shared OS-level file offset that concurrent readers would step
// on): `position` is private, per-reader state, and every read is a
// positional `pread` (`FileExt::read_at`) at that exact offset, so this
// reader's progress can never be affected by, or affect, any other reader
// over the same `Arc<File>`. Not `pub`: nothing outside this module needs
// to name this type, since `ImageSource::open_reader()` only ever hands it
// back as an opaque `Box<dyn Read>`.
struct FileImageReader {
    file: Arc<File>,
    position: u64,
    logical_size: u64,
}

impl Read for FileImageReader {
    // Never reads past `logical_size`, regardless of how large the
    // underlying file has since grown (a `File::read`-based reader would
    // happily keep reading past the size seen at construction time; this
    // one deliberately stops there). If the underlying file has instead
    // shrunk below `logical_size`, `read_at` itself returns `Ok(0)` once
    // `self.position` reaches the file's actual current end -- this simply
    // propagates that as a short read (fewer total bytes than
    // `logical_size`), which the caller (`writer::write()`'s
    // `read_fully`/`SourceTooShort` handling) already treats as an
    // explicit failure, never a silently short "success".
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let remaining = self.logical_size.saturating_sub(self.position);

        if remaining == 0 {
            return Ok(0);
        }

        let to_read = (buf.len() as u64).min(remaining) as usize;
        let n = self.file.read_at(&mut buf[..to_read], self.position)?;

        // `n <= to_read <= remaining == logical_size - position`, so
        // `position + n <= logical_size` always -- this addition can never
        // overflow a `u64`, and `position` can never run past
        // `logical_size` as a result of this call.
        self.position += n as u64;

        Ok(n)
    }
}

// Binds a single "which image, and how do I read it" choice into one value:
// the `ImageSelection` (what/when the user chose) and the `ImageSource` (how
// to read it) that were computed from the *same* selection event. This
// closes the same class of gap `WriteIntent::from_selection` closes on the
// target side: without `SelectedImage`, a caller holding an `ImageSelection`
// and an `ImageSource` separately could freely pair them with a *different*
// selection's counterpart (e.g. an `ImageSelection` confirmed for image A
// alongside an `ImageSource` that actually reads image B). `SelectedImage`
// makes that impossible to express -- the only way to ever have one is via
// `new()`, which mints the `ImageSelection` itself, from the `ImageSource`
// already in hand, in the same call.
//
// Fields are private, there is no setter, and no `Clone`/`Copy` impl: the
// `source` is a linearly-owned `Box<dyn ImageSource>` (not `Clone`-able even
// if we wanted to), and duplicating a `SelectedImage` would raise exactly
// the "which copy is the real one" question this type exists to avoid. A
// `source()` getter is deliberately not provided either -- the only
// capabilities exposed are the ones a caller legitimately needs
// (`selection()`/`logical_size()`/`access()`/`open_reader()`), never the raw
// `ImageSource` itself, which would let a caller extract it and pair it with
// a *different* `ImageSelection` by hand.
pub struct SelectedImage {
    selection: ImageSelection,
    source: Box<dyn ImageSource>,
}

impl SelectedImage {
    // The only way to construct one. Mints the `ImageSelection` (a fresh
    // `image_generation`, unconditionally -- see `ImageSelection::new`'s own
    // doc comment) from `source.logical_size()` in this same call, so the
    // two can never be supplied independently by the caller. Explicitly
    // reselecting the same path/file/size still produces a new
    // `SelectedImage` with a new `image_generation`, because it requires a
    // new `ImageSource` (a fresh `FileImageSource::new()` call, itself
    // reopening the file) to call this constructor with in the first place.
    pub fn new(source: Box<dyn ImageSource>) -> Self {
        let selection = ImageSelection::new(source.logical_size());

        SelectedImage { selection, source }
    }

    // `ImageSelection` is `Copy`; returning it by value lets a caller pass
    // it into `WriteIntent::from_selection`/`prepare_for_open` without
    // borrowing this `SelectedImage`. A copied-out `ImageSelection` alone
    // cannot be used to obtain a reader -- that capability stays behind
    // `open_reader()` below, reachable only through this `SelectedImage` (or
    // the `source` it still owns).
    pub fn selection(&self) -> ImageSelection {
        self.selection
    }

    pub fn logical_size(&self) -> u64 {
        self.selection.image_size()
    }

    pub fn access(&self) -> ImageSourceAccess {
        self.source.access()
    }

    // Delegates to `self.source.open_reader()`. Every call returns an
    // independent, fresh reader (see `ImageSource::open_reader`'s contract);
    // callers needing a write-time reader and a later verify-time reader
    // call this twice on the same `SelectedImage`, never through two
    // different `SelectedImage`/`ImageSource` values.
    pub fn open_reader(&self) -> io::Result<Box<dyn Read>> {
        self.source.open_reader()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::OpenOptions;
    use std::io::Write as _;
    use std::sync::atomic::{AtomicU64, Ordering};

    // Collision-avoidance identical in spirit to the temp-file helpers in
    // `core.rs`'s own test module: PID + a process-global counter keeps the
    // path unique across concurrently-running tests. Always a plain
    // regular file under the OS temp directory -- never a block device.
    fn temp_file_path(tag: &str) -> PathBuf {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);

        std::env::temp_dir().join(format!(
            "linux-usb-writer-image-source-test-{tag}-{}-{id}.tmp",
            std::process::id()
        ))
    }

    fn write_temp_file(tag: &str, contents: &[u8]) -> PathBuf {
        let path = temp_file_path(tag);
        std::fs::write(&path, contents).expect("write temp file for image_source test");
        path
    }

    fn read_all(mut reader: impl Read) -> Vec<u8> {
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf).expect("read_to_end");
        buf
    }

    // A. Constructing a FileImageSource over a known-size file reports the
    // correct logical_size.
    #[test]
    fn file_image_source_reports_correct_logical_size() {
        let data = vec![7u8; 12_345];
        let path = write_temp_file("logical-size", &data);

        let source = FileImageSource::new(&path).unwrap();

        assert_eq!(source.logical_size(), data.len() as u64);
        let _ = std::fs::remove_file(&path);
    }

    // B. open_reader() reads back exactly the original file content.
    #[test]
    fn open_reader_reads_back_exact_content() {
        let data: Vec<u8> = (0..5000u32).map(|i| (i % 251) as u8).collect();
        let path = write_temp_file("read-back", &data);
        let source = FileImageSource::new(&path).unwrap();

        let read_back = read_all(source.open_reader().unwrap());

        assert_eq!(read_back, data);
        let _ = std::fs::remove_file(&path);
    }

    // C. Two independent open_reader() calls both start from the
    // beginning and both read the same, full content.
    #[test]
    fn two_open_reader_calls_each_read_the_full_content_from_the_start() {
        let data: Vec<u8> = (0..4000u32).map(|i| (i % 200) as u8).collect();
        let path = write_temp_file("two-readers", &data);
        let source = FileImageSource::new(&path).unwrap();

        let first = read_all(source.open_reader().unwrap());
        let second = read_all(source.open_reader().unwrap());

        assert_eq!(first, data);
        assert_eq!(second, data);
        let _ = std::fs::remove_file(&path);
    }

    // D. Fully consuming one reader (to EOF) has no effect on a
    // subsequently opened reader -- it still starts at byte 0. This is the
    // exact property a future Full Verify (write once, then re-read to
    // compare) depends on.
    #[test]
    fn consuming_one_reader_to_eof_does_not_affect_a_later_reader() {
        let data: Vec<u8> = (0..2000u32).map(|i| (i % 128) as u8).collect();
        let path = write_temp_file("consume-then-reopen", &data);
        let source = FileImageSource::new(&path).unwrap();

        let mut reader_a = source.open_reader().unwrap();
        let mut drained = Vec::new();
        reader_a.read_to_end(&mut drained).unwrap();
        assert_eq!(drained, data);
        // `reader_a` is now at EOF; dropped here.
        drop(reader_a);

        let reader_b_content = read_all(source.open_reader().unwrap());
        assert_eq!(reader_b_content, data);
        let _ = std::fs::remove_file(&path);
    }

    // E. Two readers held open at the same time have fully independent
    // read positions -- reading from one does not advance the other.
    #[test]
    fn two_simultaneously_held_readers_have_independent_positions() {
        let data: Vec<u8> = (0..1000u32).map(|i| (i % 90) as u8).collect();
        let path = write_temp_file("simultaneous", &data);
        let source = FileImageSource::new(&path).unwrap();

        let mut reader_a = source.open_reader().unwrap();
        let mut reader_b = source.open_reader().unwrap();

        let mut buf_a = [0u8; 100];
        reader_a.read_exact(&mut buf_a).unwrap();
        assert_eq!(buf_a, data[..100]);

        // `reader_b` must still be at the very beginning, unaffected by
        // the 100 bytes just consumed from `reader_a`.
        let mut buf_b = [0u8; 100];
        reader_b.read_exact(&mut buf_b).unwrap();
        assert_eq!(buf_b, data[..100]);

        let _ = std::fs::remove_file(&path);
    }

    // F. A nonexistent path is rejected with ImageSourceError::Io.
    #[test]
    fn nonexistent_path_is_rejected_with_io_error() {
        let path = temp_file_path("does-not-exist");

        let result = FileImageSource::new(&path);

        assert!(matches!(result, Err(ImageSourceError::Io(_))));
    }

    // G. A directory is rejected as not a regular file.
    #[test]
    fn directory_is_rejected_as_not_a_regular_file() {
        let dir_path = std::env::temp_dir().join(format!(
            "linux-usb-writer-image-source-test-dir-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir_path).expect("create temp dir for image_source test");

        let result = FileImageSource::new(&dir_path);

        assert!(matches!(result, Err(ImageSourceError::NotRegularFile)));
        let _ = std::fs::remove_dir(&dir_path);
    }

    // H. A zero-byte file is accepted at construction (logical_size() ==
    // 0); rejecting an unusable-for-writing zero-size image is
    // `writer::WritePlan::new`'s responsibility, not this constructor's --
    // see `FileImageSource::new`'s doc comment.
    #[test]
    fn zero_byte_file_is_accepted_with_zero_logical_size() {
        let path = write_temp_file("zero-byte", &[]);

        let source = FileImageSource::new(&path).unwrap();

        assert_eq!(source.logical_size(), 0);
        let read_back = read_all(source.open_reader().unwrap());
        assert!(read_back.is_empty());
        let _ = std::fs::remove_file(&path);
    }

    // I. access() reports SequentialReplay for FileImageSource, matching
    // what its API actually provides (no seek/offset method).
    #[test]
    fn file_image_source_reports_sequential_replay_access() {
        let path = write_temp_file("access-kind", b"abc");
        let source = FileImageSource::new(&path).unwrap();

        assert_eq!(source.access(), ImageSourceAccess::SequentialReplay);
        let _ = std::fs::remove_file(&path);
    }

    // J (TOCTOU core test). `FileImageSource::new` opens the file, and the
    // path is then made to point at a *completely different* file (via
    // `rename()`, which atomically retargets the directory entry to a
    // different inode -- the classic path-swap TOCTOU shape this fix
    // exists to close). `open_reader()` must still read the ORIGINAL
    // content, never the replacement's, proving it never re-resolves
    // `path` via a fresh `File::open`.
    #[test]
    fn open_reader_reads_original_content_after_path_is_replaced() {
        let original = b"original content selected by the user".to_vec();
        let replacement = b"a completely different file now at the same path!!".to_vec();

        let path = write_temp_file("path-replaced", &original);
        let source = FileImageSource::new(&path).unwrap();

        let replacement_path = write_temp_file("path-replaced-incoming", &replacement);
        std::fs::rename(&replacement_path, &path)
            .expect("rename replacement file over the original path");

        let read_back = read_all(source.open_reader().unwrap());

        assert_eq!(read_back, original);
        assert_ne!(read_back, replacement);
        let _ = std::fs::remove_file(&path);
    }

    // K (unlink). After `path` is removed entirely, `open_reader()` can
    // still read the original content -- ordinary Unix open-file
    // semantics keep an already-open file description valid (and its
    // bytes readable) even once its directory entry is gone.
    #[test]
    fn open_reader_reads_original_content_after_path_is_unlinked() {
        let data: Vec<u8> = (0..3000u32).map(|i| (i % 250) as u8).collect();
        let path = write_temp_file("unlinked", &data);
        let source = FileImageSource::new(&path).unwrap();

        std::fs::remove_file(&path).expect("unlink original path");

        let read_back = read_all(source.open_reader().unwrap());

        assert_eq!(read_back, data);
        // Nothing left to clean up -- the path was already removed above.
    }

    // L (file growth). The *same* underlying file (not swapped, not
    // truncated -- just appended to after construction) grows past the
    // `logical_size` recorded at construction time. `open_reader()` must
    // stop reading at exactly the original `logical_size`, never
    // following the file's new, larger extent.
    #[test]
    fn open_reader_never_reads_past_logical_size_after_the_file_grows() {
        let original: Vec<u8> = (0..2500u32).map(|i| (i % 200) as u8).collect();
        let appended = vec![0xEEu8; 1000];

        let path = write_temp_file("grows", &original);
        let source = FileImageSource::new(&path).unwrap();
        let recorded_logical_size = source.logical_size();
        assert_eq!(recorded_logical_size, original.len() as u64);

        {
            let mut file = OpenOptions::new()
                .append(true)
                .open(&path)
                .expect("reopen the same file to append to it");
            file.write_all(&appended).expect("append growth bytes");
        }

        let read_back = read_all(source.open_reader().unwrap());

        assert_eq!(read_back.len() as u64, recorded_logical_size);
        assert_eq!(read_back, original);
        let _ = std::fs::remove_file(&path);
    }

    // M (file shrink). The *same* underlying file is truncated smaller
    // than the `logical_size` recorded at construction time.
    // `ImageSource` itself does not turn this into an error -- it is
    // expected to surface downstream, in `writer::write()`, as
    // `WriteError::SourceTooShort` once the reader runs out of real bytes
    // before reaching `logical_size`. This test only confirms the
    // `ImageSource`-level symptom (fewer bytes than `logical_size` are
    // ever returned); the downstream detection itself is exercised by
    // `writer.rs`'s own `source_shorter_than_planned_image_is_error` test
    // against the same `read_fully`/`SourceTooShort` path.
    #[test]
    fn open_reader_returns_fewer_bytes_than_logical_size_after_the_file_shrinks() {
        let original: Vec<u8> = (0..2000u32).map(|i| (i % 200) as u8).collect();
        let shrink_to: u64 = 500;

        let path = write_temp_file("shrinks", &original);
        let source = FileImageSource::new(&path).unwrap();
        assert_eq!(source.logical_size(), original.len() as u64);

        {
            let file = OpenOptions::new()
                .write(true)
                .open(&path)
                .expect("reopen the same file to truncate it");
            file.set_len(shrink_to).expect("truncate file");
        }

        let read_back = read_all(source.open_reader().unwrap());

        assert!((read_back.len() as u64) < source.logical_size());
        assert_eq!(read_back, original[..shrink_to as usize]);
        let _ = std::fs::remove_file(&path);
    }

    // ---------------------------------------------------------------------
    // SelectedImage
    // ---------------------------------------------------------------------

    // SelectedImage A. logical_size() matches the source's own logical_size.
    #[test]
    fn selected_image_logical_size_matches_source_logical_size() {
        let data = vec![3u8; 9_000];
        let path = write_temp_file("selected-logical-size", &data);
        let source = FileImageSource::new(&path).unwrap();
        let source_logical_size = source.logical_size();

        let selected = SelectedImage::new(Box::new(source));

        assert_eq!(selected.logical_size(), source_logical_size);
        let _ = std::fs::remove_file(&path);
    }

    // SelectedImage B. The minted ImageSelection's image_size matches the
    // source's logical_size exactly (they are minted together in `new()`,
    // never supplied independently).
    #[test]
    fn selected_image_selection_image_size_matches_source_logical_size() {
        let data = vec![4u8; 6_500];
        let path = write_temp_file("selected-selection-size", &data);
        let source = FileImageSource::new(&path).unwrap();
        let source_logical_size = source.logical_size();

        let selected = SelectedImage::new(Box::new(source));

        assert_eq!(selected.selection().image_size(), source_logical_size);
        let _ = std::fs::remove_file(&path);
    }

    // SelectedImage C. open_reader() called twice on the same SelectedImage
    // each produce an independent, fresh reader (delegates straight through
    // to the underlying ImageSource, whose own fresh-reader contract is
    // already covered above).
    #[test]
    fn selected_image_open_reader_called_twice_reads_full_content_each_time() {
        let data: Vec<u8> = (0..3300u32).map(|i| (i % 211) as u8).collect();
        let path = write_temp_file("selected-fresh-reader", &data);
        let source = FileImageSource::new(&path).unwrap();
        let selected = SelectedImage::new(Box::new(source));

        let first = read_all(selected.open_reader().unwrap());
        let second = read_all(selected.open_reader().unwrap());

        assert_eq!(first, data);
        assert_eq!(second, data);
        let _ = std::fs::remove_file(&path);
    }

    // SelectedImage D. Explicitly reselecting the exact same file (a fresh
    // FileImageSource::new() over the same path) and wrapping it in a new
    // SelectedImage mints a new image_generation -- mirrors
    // `ImageSelection::new`'s own "always mints, even for the identical
    // choice" contract, now carried through `SelectedImage::new()`.
    #[test]
    fn selected_image_explicit_reselect_of_same_file_mints_a_new_generation() {
        let data = vec![5u8; 2048];
        let path = write_temp_file("selected-reselect", &data);

        let source_a = FileImageSource::new(&path).unwrap();
        let selected_a = SelectedImage::new(Box::new(source_a));

        let source_b = FileImageSource::new(&path).unwrap();
        let selected_b = SelectedImage::new(Box::new(source_b));

        assert_ne!(
            selected_a.selection().image_generation(),
            selected_b.selection().image_generation()
        );
        let _ = std::fs::remove_file(&path);
    }

    // SelectedImage E. A zero-byte source still produces a SelectedImage;
    // rejecting it as unusable-for-writing is `writer::WritePlan::new`'s
    // job, not `SelectedImage`'s or `FileImageSource`'s -- see
    // `FileImageSource::new`'s doc comment for the same responsibility split.
    #[test]
    fn selected_image_accepts_zero_size_source() {
        let path = write_temp_file("selected-zero-byte", &[]);
        let source = FileImageSource::new(&path).unwrap();

        let selected = SelectedImage::new(Box::new(source));

        assert_eq!(selected.logical_size(), 0);
        assert_eq!(selected.selection().image_size(), 0);
        let _ = std::fs::remove_file(&path);
    }
}
