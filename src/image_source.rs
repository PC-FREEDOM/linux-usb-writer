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

use crate::execution::core::ImageSelection;
use source_identity::{SourceChanged, SourceIdentity};

// Compressed image validation (`CompressedImageFile::preflight` and its
// types), reached as `image_source::compressed::*`.
pub mod compressed;
mod detect;
// Detecting that a selected image file changed after it was opened
// (`SourceIdentity` / `SourceChanged`), reached as
// `image_source::source_identity::*`.
#[cfg(test)]
mod gzip_behavior;
pub mod source_identity;

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
    // `open_image` only: the content carries the signature of a known
    // compressed/archive format this program cannot write. Such a file is
    // never treated as a raw image -- writing its bytes as-is would produce
    // a target that looks written but cannot boot.
    UnsupportedFormat(UnsupportedCompression),
    // `open_image` only: the file name ends in `.gz`/`.xz` but the content is
    // not that format (raw data, or the other compression format). Refused
    // rather than written as raw: a misnamed or damaged download is far
    // more likely than a raw image deliberately named `.gz`.
    ExtensionMismatch { expected: CompressionFormat },
}

// A compressed image format this crate recognizes and intends to write
// (after decompression). Detected from the file's content, never its name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressionFormat {
    Gzip,
    Xz,
}

impl CompressionFormat {
    pub fn name(self) -> &'static str {
        match self {
            CompressionFormat::Gzip => "gzip",
            CompressionFormat::Xz => "xz",
        }
    }
}

// Compressed/archive formats that are recognized by signature only so they
// can be refused explicitly (see `ImageSourceError::UnsupportedFormat`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnsupportedCompression {
    Zstd,
    Bzip2,
    Zip,
    SevenZip,
    Lz4,
}

impl UnsupportedCompression {
    pub fn name(self) -> &'static str {
        match self {
            UnsupportedCompression::Zstd => "zstd",
            UnsupportedCompression::Bzip2 => "bzip2",
            UnsupportedCompression::Zip => "zip",
            UnsupportedCompression::SevenZip => "7z",
            UnsupportedCompression::Lz4 => "lz4",
        }
    }
}

// What `open_image` found at the path, already opened exactly once.
//
// `Raw` is a ready-to-use `FileImageSource` built from that same open file
// -- identical in every respect to what `FileImageSource::new` produces.
// `Compressed` is the same open file, identified as gzip/xz but not yet
// validated or decoded: it deliberately does not implement `ImageSource`
// (its logical size is unknown until the whole stream has been checked), so
// it cannot be turned into a `SelectedImage` or written. Validating it into
// a readable source is a separate, later step that consumes this value.
#[derive(Debug)]
pub enum OpenedImage {
    Raw(FileImageSource),
    Compressed(CompressedImageFile),
}

// A compressed image file, opened once and identified by its content. Holds
// the open `File` so the later validation/decoding step reads exactly the
// file that was detected here, never a re-opened path.
#[derive(Debug)]
pub struct CompressedImageFile {
    file: File,
    path: PathBuf,
    format: CompressionFormat,
    compressed_size: u64,
    // Metadata snapshot taken at open time, from the same `fstat` as
    // `compressed_size`. Carried unchanged through Preflight: the reference
    // point for later revalidation is always the moment of selection.
    identity: SourceIdentity,
}

impl CompressedImageFile {
    pub fn format(&self) -> CompressionFormat {
        self.format
    }

    // For display only, like `FileImageSource::path()`.
    pub fn path(&self) -> &Path {
        &self.path
    }

    // The size of the compressed file itself (from `fstat` at open time) --
    // never the size of the decompressed image.
    pub fn compressed_size(&self) -> u64 {
        self.compressed_size
    }
}

// The single entry point for opening a user-selected image: opens `path`
// exactly once, checks it is a regular file, reads its leading bytes from
// that same open file (positional reads only -- the file's shared offset is
// never moved), and classifies it by content:
//
//   - no known signature           -> `OpenedImage::Raw` (a `FileImageSource`
//                                      built from the same `File`)
//   - gzip / xz signature          -> `OpenedImage::Compressed`
//   - zstd/bzip2/zip/7z/lz4        -> `Err(UnsupportedFormat)`, never raw
//   - `.gz`/`.xz` name, other data -> `Err(ExtensionMismatch)`, never raw
//
// A short or empty file is simply `Raw` if no whole signature fits; its size
// is judged later exactly as before (e.g. a 0-byte image is still rejected
// by the Write Gate's `WritePlan` validation).
pub fn open_image(path: impl Into<PathBuf>) -> Result<OpenedImage, ImageSourceError> {
    let path = path.into();
    let file = File::open(&path).map_err(ImageSourceError::Io)?;
    let metadata = file.metadata().map_err(ImageSourceError::Io)?;

    // Checked before reading any content: reading a non-regular file (a
    // FIFO, a device) could block or consume data.
    if !metadata.is_file() {
        return Err(ImageSourceError::NotRegularFile);
    }

    let mut head = [0u8; detect::DETECTION_HEAD_LEN];
    let head_len = read_head(&file, &mut head).map_err(ImageSourceError::Io)?;
    let detected = detect::detect_format(&head[..head_len]);

    if let detect::DetectedFormat::Unsupported(kind) = detected {
        return Err(ImageSourceError::UnsupportedFormat(kind));
    }

    detect::check_name_matches_content(&path, detected)?;

    match detected {
        detect::DetectedFormat::Raw => Ok(OpenedImage::Raw(FileImageSource::from_open_file(
            file, path,
        )?)),
        detect::DetectedFormat::Compressed(format) => {
            Ok(OpenedImage::Compressed(CompressedImageFile {
                file,
                path,
                format,
                compressed_size: metadata.len(),
                identity: SourceIdentity::from_metadata(&metadata),
            }))
        }
        detect::DetectedFormat::Unsupported(kind) => Err(ImageSourceError::UnsupportedFormat(kind)),
    }
}

// Fills `buf` from offset 0 of `file` with positional reads (`pread`), so
// the file's shared offset is untouched. Returns how many bytes were read:
// fewer than `buf.len()` only when the file itself is shorter.
fn read_head(file: &File, buf: &mut [u8]) -> io::Result<usize> {
    let mut filled = 0;

    while filled < buf.len() {
        match file.read_at(&mut buf[filled..], filled as u64) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }

    Ok(filled)
}

// The kind of repeated access an `ImageSource` can honestly provide,
// beyond the baseline "call `open_reader()` again for a fresh full replay"
// every implementation must support. This exists so a future Quick Verify
// has something to branch on -- no Quick Verify algorithm is decided or
// implemented here, only the capability query it would use.
//
// `RandomAccess` is now backed by a real capability (`ImageSource::read_at`,
// above) rather than being a declared-but-unusable shape: `FileImageSource`
// (below) implements `read_at` honestly and reports `RandomAccess`
// accordingly. A future non-seekable source (e.g. a streaming decompressor)
// that cannot honor `read_at` should keep reporting `SequentialReplay` and
// is expected to make `read_at` return an error for any non-trivial
// request -- this enum does not itself enforce that, the same way nothing
// here stops a caller from ignoring `access()` and calling `read_at`
// anyway; deciding how a future caller should react to a `SequentialReplay`
// source's `read_at` failing is left to that future work, not decided here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageSourceAccess {
    // The only access pattern `FileImageSource` provided before this
    // revision, and still the only one some future `ImageSource` (e.g. a
    // non-seekable stream) may ever honestly support: `open_reader()` can
    // be called repeatedly, and each call replays the
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

    // Reads up to `buf.len()` bytes starting at `offset`, independent of
    // any `open_reader()` reader's position and independent of any other
    // `read_at()` call -- there is no shared cursor here, exactly like
    // `FileExt::read_at` itself.
    //
    // Provided, not required: the first candidate considered here was a
    // required method (no default), on the reasoning that a Quick Verify
    // built on this needs genuine, cheap random access to actually be
    // quick, and a silent sequential-read-and-discard fallback would
    // misrepresent that as an implementation detail rather than a real
    // performance cliff. Checking the existing code surfaced a concrete
    // reason that plan does not fit today: `execution::write_job`'s own
    // test suite already defines a second, test-only `ImageSource`
    // implementor (`FailingImageSource`, used to simulate an `open_reader`
    // failure) that legitimately has no random-access story at all and
    // correctly reports `access() == ImageSourceAccess::SequentialReplay`
    // -- a required method would force that unrelated test file to grow an
    // `read_at` implementation it will never exercise, for no benefit,
    // which is out of scope for this change (see this module's own
    // constraints). The default below -- returning an `Unsupported` error
    // -- keeps the trait honest without forcing that: any source that
    // cannot honor random access simply inherits it, `access()` already
    // told a well-behaved caller not to call this in the first place (see
    // `ImageSourceAccess`'s own doc comment), and `FileImageSource` (below)
    // still overrides it with a real, cheap implementation. This is
    // deliberately NOT a sequential-read-and-discard fallback (that was
    // rejected for the reason above); a default that quietly "worked" by
    // discarding bytes could hide the exact performance cliff this method
    // exists to avoid.
    //
    // Must never read past `logical_size()`, regardless of how large the
    // underlying storage has grown since this source was constructed (see
    // `FileImageSource`'s own doc comment for why): `offset >= logical_size()`
    // returns `Ok(0)`, and a `buf` that would extend past `logical_size()`
    // is clamped so only the bytes up to `logical_size()` are read/reported,
    // even if more physical bytes exist and could otherwise have been read.
    // A `buf` shorter than the remaining logical bytes is filled as far as
    // it goes -- a partial read (fewer bytes than requested, but more than
    // zero) is permitted and is not itself an error; distinguishing a
    // legitimate partial read from a same-underlying-file shrink (an
    // unexpectedly short read considered a failure) is left to the caller,
    // exactly as it already is for `open_reader()`'s readers. These rules
    // bind any overriding implementation (see `FileImageSource::read_at`);
    // they are vacuously satisfied by this default, which never returns a
    // successful read at all.
    fn read_at(&self, _offset: u64, _buf: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "this ImageSource does not support offset-based reads",
        ))
    }

    // Confirms the source is still in the state it was selected in: the
    // metadata of the already-open file must match the snapshot taken when
    // it was opened (see `source_identity`). Metadata only -- no path, no
    // data read. Called at checkpoints (in particular immediately before the
    // first byte is written to the target), never per read.
    //
    // Required, with no default: a default of "unchanged" would let a new
    // source type silently skip the check.
    fn revalidate_identity(&self) -> Result<(), SourceChanged>;
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
    // Metadata snapshot taken at open time, from the same `fstat` as
    // `logical_size` (see `source_identity`).
    identity: SourceIdentity,
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

        Self::from_open_file(file, path)
    }

    // The shared initialization behind both `new()` and `open_image()`:
    // takes ownership of an already-open `file` (so `open_image` can build
    // the source from the very file it just inspected, without re-opening
    // `path`) and applies exactly the checks and size capture `new()` always
    // has. `path` is kept for diagnostics only, as before.
    fn from_open_file(file: File, path: PathBuf) -> Result<Self, ImageSourceError> {
        let metadata = file.metadata().map_err(ImageSourceError::Io)?;

        if !metadata.is_file() {
            return Err(ImageSourceError::NotRegularFile);
        }

        Ok(FileImageSource {
            file: Arc::new(file),
            path,
            logical_size: metadata.len(),
            identity: SourceIdentity::from_metadata(&metadata),
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

    fn revalidate_identity(&self) -> Result<(), SourceChanged> {
        self.identity.revalidate(&self.file)
    }

    // `RandomAccess`: `read_at` (below) genuinely reads at an arbitrary
    // offset via `FileExt::read_at`, independent of any `open_reader()`
    // reader's position and of any other `read_at()` call -- this is an
    // honest capability claim, not merely a reflection of what the
    // implementation happens to use internally elsewhere.
    fn access(&self) -> ImageSourceAccess {
        ImageSourceAccess::RandomAccess
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

    // Delegates straight to the already-open `self.file`'s `FileExt::read_at`
    // -- no `File::open(&self.path)` call, exactly like `open_reader()`
    // above, so this shares every TOCTOU property `FileImageSource`'s own
    // doc comment already claims (path replacement/unlink do not affect
    // it; growth past `logical_size` is ignored; shrink surfaces as a short
    // or empty read, not a special error).
    //
    // Clamps to `logical_size` before ever calling `read_at` on the
    // underlying file: `offset >= logical_size` returns `Ok(0)` without
    // touching `self.file` at all, and a `buf` that would otherwise read
    // past `logical_size` is shortened first, so the underlying file's
    // current real extent (which may have grown since construction) can
    // never leak additional bytes beyond what this source reported as its
    // logical size. `checked_add`/`min`/`saturating_sub` throughout --
    // `offset` and `buf.len()` are both attacker/caller-controlled-ish
    // values (a Verify layer computing sample windows), so this must not
    // panic or wrap on a pathological combination of the two.
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        if offset >= self.logical_size || buf.is_empty() {
            return Ok(0);
        }

        let remaining = self.logical_size - offset;
        let to_read = (buf.len() as u64).min(remaining) as usize;

        self.file.read_at(&mut buf[..to_read], offset)
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

    // Delegates to `self.source.read_at()` -- the minimal capability a
    // future Quick Verify (in `execution::write_job`) needs to sample a few
    // small windows of the image without paying for a full sequential
    // read-and-discard. `pub(crate)`, not `pub`: unlike
    // `selection()`/`logical_size()`/`access()`/`open_reader()` above,
    // nothing outside this crate's own future `execution` module has a
    // reason to call this, so it is kept one notch narrower than this
    // type's existing public surface rather than following it by default.
    // (This crate has no library target -- see `Cargo.toml` -- so
    // `pub(in crate::execution)` is not expressible here: `execution` and
    // `image_source` are sibling modules, and `pub(in path)` requires
    // `path` to be an ancestor of this method's own module; `pub(crate)` is
    // the narrowest visibility Rust's module system actually offers for a
    // cross-sibling-module call site like this one.)
    //
    // No `source()` getter is added anywhere on this type to provide this
    // some other way -- see this struct's own doc comment for why a raw
    // `&dyn ImageSource` must never be handed out.
    pub(crate) fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        self.source.read_at(offset, buf)
    }

    // Delegates to `self.source.revalidate_identity()`: used by the write
    // path (`write_job`) immediately before the first target write.
    pub(crate) fn revalidate_identity(&self) -> Result<(), SourceChanged> {
        self.source.revalidate_identity()
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

    // I. access() reports RandomAccess for FileImageSource, matching what
    // its API actually provides now that read_at() is a real, honest
    // offset-based read capability.
    #[test]
    fn file_image_source_reports_random_access() {
        let path = write_temp_file("access-kind", b"abc");
        let source = FileImageSource::new(&path).unwrap();

        assert_eq!(source.access(), ImageSourceAccess::RandomAccess);
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
    // ImageSource::read_at -- default (provided) implementation
    // ---------------------------------------------------------------------

    // A minimal `ImageSource` that only implements the methods that were
    // required before this revision, deliberately leaving `read_at`
    // unoverridden -- exactly the shape `execution::write_job`'s own
    // test-only `FailingImageSource` has today (see the trait method's own
    // doc comment for why that mattered to this design).
    struct SequentialOnlySource {
        logical_size: u64,
    }

    impl ImageSource for SequentialOnlySource {
        fn logical_size(&self) -> u64 {
            self.logical_size
        }

        // Not file-backed: there is no file whose state could change.
        fn revalidate_identity(&self) -> Result<(), SourceChanged> {
            Ok(())
        }

        fn access(&self) -> ImageSourceAccess {
            ImageSourceAccess::SequentialReplay
        }

        fn open_reader(&self) -> io::Result<Box<dyn Read>> {
            Ok(Box::new(std::io::Cursor::new(vec![
                0u8;
                self.logical_size
                    as usize
            ])))
        }
    }

    // O1. A source that does not override read_at() inherits the default,
    // which reports Unsupported rather than silently succeeding with a
    // sequential-read-and-discard fallback.
    #[test]
    fn default_read_at_reports_unsupported_for_a_sequential_only_source() {
        let source = SequentialOnlySource { logical_size: 1000 };

        let mut buf = [0u8; 10];
        let error = source.read_at(0, &mut buf).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
    }

    // ---------------------------------------------------------------------
    // ImageSource::read_at (FileImageSource)
    // ---------------------------------------------------------------------

    // N1. read_at at offset 0 reads the first bytes correctly.
    #[test]
    fn read_at_offset_zero_reads_from_the_start() {
        let data: Vec<u8> = (0..1000u32).map(|i| (i % 250) as u8).collect();
        let path = write_temp_file("read-at-zero", &data);
        let source = FileImageSource::new(&path).unwrap();

        let mut buf = [0u8; 100];
        let n = source.read_at(0, &mut buf).unwrap();

        assert_eq!(n, 100);
        assert_eq!(buf, data[..100]);
        let _ = std::fs::remove_file(&path);
    }

    // N2. read_at at a non-zero, mid-file offset reads exactly the bytes
    // located there -- also covers "non-zero offset returns correct bytes".
    #[test]
    fn read_at_middle_offset_reads_correct_bytes() {
        let data: Vec<u8> = (0..5000u32).map(|i| (i % 253) as u8).collect();
        let path = write_temp_file("read-at-middle", &data);
        let source = FileImageSource::new(&path).unwrap();

        let offset = 2000u64;
        let mut buf = [0u8; 300];
        let n = source.read_at(offset, &mut buf).unwrap();

        assert_eq!(n, 300);
        assert_eq!(buf, data[offset as usize..offset as usize + 300]);
        let _ = std::fs::remove_file(&path);
    }

    // N3. read_at near EOF returns a short read (fewer bytes than
    // requested) containing exactly the tail of the image, not an error.
    #[test]
    fn read_at_near_eof_returns_a_short_read_of_the_tail() {
        let data: Vec<u8> = (0..1000u32).map(|i| (i % 200) as u8).collect();
        let path = write_temp_file("read-at-near-eof", &data);
        let source = FileImageSource::new(&path).unwrap();

        let offset = 900u64;
        let mut buf = [0u8; 500]; // requests past logical_size (1000)
        let n = source.read_at(offset, &mut buf).unwrap();

        assert_eq!(n, 100);
        assert_eq!(&buf[..100], &data[900..1000]);
        let _ = std::fs::remove_file(&path);
    }

    // N4. offset == logical_size returns Ok(0), no error.
    #[test]
    fn read_at_offset_equal_to_logical_size_returns_zero() {
        let path = write_temp_file("read-at-eq-size", &[1u8; 500]);
        let source = FileImageSource::new(&path).unwrap();

        let mut buf = [0u8; 10];
        let n = source.read_at(source.logical_size(), &mut buf).unwrap();

        assert_eq!(n, 0);
        let _ = std::fs::remove_file(&path);
    }

    // N5. offset > logical_size returns Ok(0), no error.
    #[test]
    fn read_at_offset_past_logical_size_returns_zero() {
        let path = write_temp_file("read-at-past-size", &[1u8; 500]);
        let source = FileImageSource::new(&path).unwrap();

        let mut buf = [0u8; 10];
        let n = source
            .read_at(source.logical_size() + 1000, &mut buf)
            .unwrap();

        assert_eq!(n, 0);
        let _ = std::fs::remove_file(&path);
    }

    // N6. A buffer extending past logical_size is clamped: only the bytes
    // up to logical_size are read/reported, even though the request asked
    // for more.
    #[test]
    fn read_at_buffer_extending_past_logical_size_is_clamped() {
        let data = vec![9u8; 200];
        let path = write_temp_file("read-at-clamped", &data);
        let source = FileImageSource::new(&path).unwrap();

        let offset = 150u64;
        let mut buf = [0u8; 100]; // 150 + 100 = 250 > logical_size (200)
        let n = source.read_at(offset, &mut buf).unwrap();

        assert_eq!(n, 50); // only up to logical_size
        assert_eq!(&buf[..50], &data[150..200]);
        let _ = std::fs::remove_file(&path);
    }

    // N7. Repeated read_at calls at different offsets do not affect one
    // another -- there is no shared cursor to disturb.
    #[test]
    fn multiple_read_at_calls_do_not_affect_each_other() {
        let data: Vec<u8> = (0..3000u32).map(|i| (i % 240) as u8).collect();
        let path = write_temp_file("read-at-independent-calls", &data);
        let source = FileImageSource::new(&path).unwrap();

        let mut buf_a = [0u8; 100];
        let mut buf_b = [0u8; 100];
        let mut buf_c = [0u8; 100];

        // Deliberately read out of order: end, then start, then middle.
        source.read_at(2900, &mut buf_a).unwrap();
        source.read_at(0, &mut buf_b).unwrap();
        source.read_at(1500, &mut buf_c).unwrap();

        assert_eq!(buf_a, data[2900..3000]);
        assert_eq!(buf_b, data[0..100]);
        assert_eq!(buf_c, data[1500..1600]);
        let _ = std::fs::remove_file(&path);
    }

    // N8. Fully consuming an open_reader() to EOF has no effect on a
    // subsequent read_at() call -- they share the underlying `Arc<File>`
    // but never a position.
    #[test]
    fn read_at_is_unaffected_by_a_previously_consumed_open_reader() {
        let data: Vec<u8> = (0..2000u32).map(|i| (i % 230) as u8).collect();
        let path = write_temp_file("read-at-after-open-reader", &data);
        let source = FileImageSource::new(&path).unwrap();

        let drained = read_all(source.open_reader().unwrap());
        assert_eq!(drained, data);

        let mut buf = [0u8; 100];
        let n = source.read_at(500, &mut buf).unwrap();

        assert_eq!(n, 100);
        assert_eq!(buf, data[500..600]);
        let _ = std::fs::remove_file(&path);
    }

    // N9. A read_at() call has no effect on a later open_reader() -- it
    // still starts at byte 0 and reads the full content.
    #[test]
    fn open_reader_after_read_at_still_reads_from_the_start() {
        let data: Vec<u8> = (0..2000u32).map(|i| (i % 230) as u8).collect();
        let path = write_temp_file("open-reader-after-read-at", &data);
        let source = FileImageSource::new(&path).unwrap();

        let mut buf = [0u8; 100];
        source.read_at(1000, &mut buf).unwrap();

        let read_back = read_all(source.open_reader().unwrap());

        assert_eq!(read_back, data);
        let _ = std::fs::remove_file(&path);
    }

    // N10. An empty buffer returns Ok(0), never an error.
    #[test]
    fn read_at_with_empty_buffer_returns_zero() {
        let path = write_temp_file("read-at-empty-buf", &[1u8; 100]);
        let source = FileImageSource::new(&path).unwrap();

        let n = source.read_at(10, &mut []).unwrap();

        assert_eq!(n, 0);
        let _ = std::fs::remove_file(&path);
    }

    // N11. A zero-byte image's read_at always returns Ok(0), regardless of
    // offset.
    #[test]
    fn read_at_on_zero_byte_image_always_returns_zero() {
        let path = write_temp_file("read-at-zero-byte-image", &[]);
        let source = FileImageSource::new(&path).unwrap();

        let mut buf = [0u8; 10];
        assert_eq!(source.read_at(0, &mut buf).unwrap(), 0);
        assert_eq!(source.read_at(5, &mut buf).unwrap(), 0);
        let _ = std::fs::remove_file(&path);
    }

    // N12 (TOCTOU: path replacement). After the path is made to point at a
    // completely different file (rename over it), read_at still reads the
    // ORIGINAL content -- it never re-resolves `path`.
    #[test]
    fn read_at_reads_original_content_after_path_is_replaced() {
        let original = b"original content selected by the user".to_vec();
        let replacement = b"a completely different file now at the same path!!".to_vec();

        let path = write_temp_file("read-at-path-replaced", &original);
        let source = FileImageSource::new(&path).unwrap();

        let replacement_path = write_temp_file("read-at-path-replaced-incoming", &replacement);
        std::fs::rename(&replacement_path, &path)
            .expect("rename replacement file over the original path");

        let mut buf = vec![0u8; original.len()];
        let n = source.read_at(0, &mut buf).unwrap();

        assert_eq!(&buf[..n], &original[..]);
        let _ = std::fs::remove_file(&path);
    }

    // N13 (TOCTOU: unlink). After the path is removed entirely, read_at can
    // still read the original content.
    #[test]
    fn read_at_reads_original_content_after_path_is_unlinked() {
        let data: Vec<u8> = (0..1000u32).map(|i| (i % 240) as u8).collect();
        let path = write_temp_file("read-at-unlinked", &data);
        let source = FileImageSource::new(&path).unwrap();

        std::fs::remove_file(&path).expect("unlink original path");

        let mut buf = [0u8; 200];
        let n = source.read_at(300, &mut buf).unwrap();

        assert_eq!(n, 200);
        assert_eq!(buf, data[300..500]);
    }

    // N14 (TOCTOU: growth). The same underlying file grows past the
    // recorded logical_size. read_at must never read into the grown
    // region: an offset at or beyond the original logical_size returns
    // Ok(0), even though the file itself now has more real bytes there.
    #[test]
    fn read_at_never_reads_past_logical_size_after_the_file_grows() {
        let original: Vec<u8> = (0..1000u32).map(|i| (i % 200) as u8).collect();
        let appended = vec![0xEEu8; 500];

        let path = write_temp_file("read-at-grows", &original);
        let source = FileImageSource::new(&path).unwrap();
        let recorded_logical_size = source.logical_size();

        {
            let mut file = OpenOptions::new()
                .append(true)
                .open(&path)
                .expect("reopen the same file to append to it");
            file.write_all(&appended).expect("append growth bytes");
        }

        // A read starting exactly at the old logical_size must see nothing.
        let mut buf = [0u8; 100];
        let n = source.read_at(recorded_logical_size, &mut buf).unwrap();
        assert_eq!(n, 0);

        // A read whose buffer would otherwise extend into the grown region
        // is clamped to the original logical_size.
        let mut buf2 = [0u8; 200];
        let n2 = source
            .read_at(recorded_logical_size - 100, &mut buf2)
            .unwrap();
        assert_eq!(n2, 100);
        assert_eq!(&buf2[..100], &original[900..1000]);

        let _ = std::fs::remove_file(&path);
    }

    // N15 (TOCTOU: shrink). The same underlying file is truncated smaller
    // than the recorded logical_size. read_at surfaces this as a short (or
    // empty) read via ordinary `FileExt::read_at`/EOF semantics -- this
    // layer does not invent a special error for it (that interpretation is
    // left to a future Verify layer).
    #[test]
    fn read_at_returns_a_short_read_after_the_file_shrinks() {
        let original: Vec<u8> = (0..2000u32).map(|i| (i % 200) as u8).collect();
        let shrink_to: u64 = 500;

        let path = write_temp_file("read-at-shrinks", &original);
        let source = FileImageSource::new(&path).unwrap();
        assert_eq!(source.logical_size(), original.len() as u64);

        {
            let file = OpenOptions::new()
                .write(true)
                .open(&path)
                .expect("reopen the same file to truncate it");
            file.set_len(shrink_to).expect("truncate file");
        }

        // A request starting before the new real end still reads what
        // remains, and no further.
        let mut buf = [0u8; 1000]; // would read up to logical_size (2000) if not shrunk
        let n = source.read_at(300, &mut buf).unwrap();

        assert!((n as u64) < 1000);
        assert_eq!(&buf[..n], &original[300..300 + n]);
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

    // SelectedImage F. read_at() delegates straight through to the
    // underlying source, exactly like open_reader() already does.
    #[test]
    fn selected_image_read_at_delegates_to_the_underlying_source() {
        let data: Vec<u8> = (0..2000u32).map(|i| (i % 233) as u8).collect();
        let path = write_temp_file("selected-read-at", &data);
        let source = FileImageSource::new(&path).unwrap();
        let selected = SelectedImage::new(Box::new(source));

        let mut buf = [0u8; 100];
        let n = selected.read_at(500, &mut buf).unwrap();

        assert_eq!(n, 100);
        assert_eq!(buf, data[500..600]);
        let _ = std::fs::remove_file(&path);
    }

    // SelectedImage G. read_at() on a SelectedImage is independent of
    // open_reader() called on the same value, in both directions -- the
    // same guarantee already proven for the underlying ImageSource alone
    // (tests N8/N9 above), now confirmed through the SelectedImage wrapper.
    #[test]
    fn selected_image_read_at_and_open_reader_are_mutually_independent() {
        let data: Vec<u8> = (0..1500u32).map(|i| (i % 217) as u8).collect();
        let path = write_temp_file("selected-read-at-independent", &data);
        let source = FileImageSource::new(&path).unwrap();
        let selected = SelectedImage::new(Box::new(source));

        let drained = read_all(selected.open_reader().unwrap());
        assert_eq!(drained, data);

        let mut buf = [0u8; 100];
        let n = selected.read_at(700, &mut buf).unwrap();
        assert_eq!(n, 100);
        assert_eq!(buf, data[700..800]);

        let read_back_again = read_all(selected.open_reader().unwrap());
        assert_eq!(read_back_again, data);
        let _ = std::fs::remove_file(&path);
    }

    // ---------------------------------------------------------------------
    // open_image (format detection + same-FD raw source). Regular temp files
    // only -- never a block device.
    // ---------------------------------------------------------------------

    // Like `write_temp_file`, but with a caller-chosen file name suffix, since
    // `open_image` looks at the final extension.
    fn write_named_temp_file(tag: &str, suffix: &str, contents: &[u8]) -> PathBuf {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "linux-usb-writer-open-image-test-{tag}-{}-{id}{suffix}",
            std::process::id()
        ));
        std::fs::write(&path, contents).expect("write temp file for open_image test");
        path
    }

    fn open_raw(path: &Path) -> FileImageSource {
        match open_image(path) {
            Ok(OpenedImage::Raw(source)) => source,
            other => panic!("expected OpenedImage::Raw for {path:?}, got {other:?}"),
        }
    }

    fn open_compressed(path: &Path) -> CompressedImageFile {
        match open_image(path) {
            Ok(OpenedImage::Compressed(file)) => file,
            other => panic!("expected OpenedImage::Compressed for {path:?}, got {other:?}"),
        }
    }

    const GZIP_HEAD: &[u8] = &[0x1F, 0x8B, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00];
    const XZ_HEAD: &[u8] = &[0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00, 0x00, 0x04];

    // OI1. A raw image opened through `open_image` behaves exactly like one
    // opened through `FileImageSource::new`: same logical size, same bytes
    // via `open_reader()` and `read_at()`, same RandomAccess capability.
    #[test]
    fn open_image_raw_matches_file_image_source_new() {
        let data: Vec<u8> = (0..10_000u32).map(|i| (i % 251) as u8).collect();
        let path = write_named_temp_file("raw-same", ".img", &data);

        let via_open_image = open_raw(&path);
        let via_new = FileImageSource::new(&path).unwrap();

        assert_eq!(via_open_image.logical_size(), via_new.logical_size());
        assert_eq!(via_open_image.logical_size(), data.len() as u64);
        assert_eq!(via_open_image.access(), ImageSourceAccess::RandomAccess);
        assert_eq!(read_all(via_open_image.open_reader().unwrap()), data);

        let mut window = [0u8; 16];
        let n = via_open_image.read_at(5_000, &mut window).unwrap();
        assert_eq!(&window[..n], &data[5_000..5_016]);
        assert_eq!(via_open_image.path(), path.as_path());

        let _ = std::fs::remove_file(&path);
    }

    // OI2. Same-FD guarantee: after `open_image`, renaming the path away,
    // putting a different file at the original path, and then unlinking
    // everything does not change what the source reads -- it keeps reading
    // the file it detected, never a re-opened path.
    #[test]
    fn open_image_raw_keeps_reading_the_file_it_detected() {
        let original = b"original raw image contents".to_vec();
        let path = write_named_temp_file("raw-swap", ".iso", &original);
        let moved = path.with_extension("moved");

        let source = open_raw(&path);

        std::fs::rename(&path, &moved).unwrap();
        std::fs::write(&path, b"a completely different replacement file").unwrap();
        std::fs::remove_file(&moved).unwrap();
        std::fs::remove_file(&path).unwrap();

        assert_eq!(source.logical_size(), original.len() as u64);
        assert_eq!(read_all(source.open_reader().unwrap()), original);
    }

    // OI3. Detection reads with positional reads only: the shared file
    // offset is not moved, so the first reader still starts at byte 0 (also
    // covered by OI1's full read, asserted here explicitly on a file whose
    // first bytes differ from later ones).
    #[test]
    fn open_image_raw_reader_starts_at_byte_zero_after_detection() {
        let data = b"0123456789abcdef".to_vec();
        let path = write_named_temp_file("raw-offset", ".raw", &data);

        let source = open_raw(&path);
        let mut first = [0u8; 4];
        let mut reader = source.open_reader().unwrap();
        reader.read_exact(&mut first).unwrap();
        assert_eq!(&first, b"0123");

        let _ = std::fs::remove_file(&path);
    }

    // OI4. Empty and short files are Raw and keep the existing size
    // semantics (0 bytes is still accepted here; the Write Gate rejects it
    // later, exactly as for `FileImageSource::new`).
    #[test]
    fn open_image_empty_and_short_files_are_raw() {
        for (tag, contents) in [
            ("empty", &b""[..]),
            ("one", &[0x1F][..]),
            ("five-xz-prefix", &[0xFD, 0x37, 0x7A, 0x58, 0x5A][..]),
        ] {
            let path = write_named_temp_file(tag, ".img", contents);
            let source = open_raw(&path);
            assert_eq!(source.logical_size(), contents.len() as u64, "{tag}");
            assert_eq!(read_all(source.open_reader().unwrap()), contents, "{tag}");
            let _ = std::fs::remove_file(&path);
        }
    }

    // OI5. gzip / xz content is recognized as compressed -- never Raw --
    // whatever the name says (content decides), and the compressed file's
    // own size is reported.
    #[test]
    fn open_image_recognizes_gzip_and_xz_by_content() {
        let cases = [
            ("gz", ".gz", GZIP_HEAD, CompressionFormat::Gzip),
            ("GZ", ".GZ", GZIP_HEAD, CompressionFormat::Gzip),
            ("iso-gz", ".iso.gz", GZIP_HEAD, CompressionFormat::Gzip),
            ("noext-gz", "", GZIP_HEAD, CompressionFormat::Gzip),
            ("xz", ".xz", XZ_HEAD, CompressionFormat::Xz),
            ("XZ", ".XZ", XZ_HEAD, CompressionFormat::Xz),
            ("img-xz", ".img.xz", XZ_HEAD, CompressionFormat::Xz),
            ("iso-holding-xz", ".iso", XZ_HEAD, CompressionFormat::Xz),
        ];

        for (tag, suffix, contents, expected) in cases {
            let path = write_named_temp_file(tag, suffix, contents);
            let compressed = open_compressed(&path);
            assert_eq!(compressed.format(), expected, "{tag}");
            assert_eq!(compressed.compressed_size(), contents.len() as u64, "{tag}");
            assert_eq!(compressed.path(), path.as_path(), "{tag}");
            let _ = std::fs::remove_file(&path);
        }
    }

    // OI6. Known unsupported compressed/archive formats are refused, never
    // opened as Raw -- even under a name that looks like a disk image.
    #[test]
    fn open_image_refuses_known_unsupported_formats() {
        let cases: [(&str, &[u8], UnsupportedCompression); 5] = [
            (
                "zstd",
                &[0x28, 0xB5, 0x2F, 0xFD, 0x00, 0x00],
                UnsupportedCompression::Zstd,
            ),
            ("bzip2", b"BZh91AY&SY", UnsupportedCompression::Bzip2),
            (
                "zip",
                &[0x50, 0x4B, 0x03, 0x04, 0x14, 0x00],
                UnsupportedCompression::Zip,
            ),
            (
                "7z",
                &[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C],
                UnsupportedCompression::SevenZip,
            ),
            (
                "lz4",
                &[0x04, 0x22, 0x4D, 0x18, 0x64, 0x40],
                UnsupportedCompression::Lz4,
            ),
        ];

        for (tag, contents, expected) in cases {
            let path = write_named_temp_file(tag, ".img", contents);
            match open_image(&path) {
                Err(ImageSourceError::UnsupportedFormat(kind)) => {
                    assert_eq!(kind, expected, "{tag}")
                }
                other => panic!("{tag}: expected UnsupportedFormat, got {other:?}"),
            }
            let _ = std::fs::remove_file(&path);
        }
    }

    // OI7. A `.gz`/`.xz` name without matching content is refused, never
    // opened as Raw -- including raw data and the other compression format.
    #[test]
    fn open_image_refuses_compression_extension_without_matching_content() {
        let raw = b"plain raw bytes".to_vec();
        let cases: [(&str, &str, &[u8], CompressionFormat); 5] = [
            ("gz-raw", ".gz", &raw, CompressionFormat::Gzip),
            ("GZ-raw", ".GZ", &raw, CompressionFormat::Gzip),
            ("xz-raw", ".img.xz", &raw, CompressionFormat::Xz),
            ("gz-holding-xz", ".gz", XZ_HEAD, CompressionFormat::Gzip),
            ("xz-holding-gz", ".xz", GZIP_HEAD, CompressionFormat::Xz),
        ];

        for (tag, suffix, contents, expected) in cases {
            let path = write_named_temp_file(tag, suffix, contents);
            match open_image(&path) {
                Err(ImageSourceError::ExtensionMismatch { expected: got }) => {
                    assert_eq!(got, expected, "{tag}")
                }
                other => panic!("{tag}: expected ExtensionMismatch, got {other:?}"),
            }
            let _ = std::fs::remove_file(&path);
        }
    }

    // OI8. Non-regular files and missing paths keep their existing errors.
    #[test]
    fn open_image_keeps_existing_open_errors() {
        let dir = std::env::temp_dir();
        assert!(matches!(
            open_image(&dir),
            Err(ImageSourceError::NotRegularFile)
        ));

        let missing = dir.join(format!(
            "linux-usb-writer-open-image-test-missing-{}.img",
            std::process::id()
        ));
        assert!(matches!(open_image(&missing), Err(ImageSourceError::Io(_))));
    }

    // OI9. A raw image opened via `open_image` goes through `SelectedImage`
    // exactly like before: the selection carries the same logical size.
    #[test]
    fn open_image_raw_source_builds_selected_image_as_before() {
        let data = vec![7u8; 4096];
        let path = write_named_temp_file("raw-selected", ".img", &data);

        let selected = SelectedImage::new(Box::new(open_raw(&path)));
        assert_eq!(selected.logical_size(), 4096);
        assert_eq!(selected.selection().image_size(), 4096);
        assert_eq!(selected.access(), ImageSourceAccess::RandomAccess);
        assert_eq!(read_all(selected.open_reader().unwrap()), data);

        let _ = std::fs::remove_file(&path);
    }

    // ---------------------------------------------------------------------
    // Source identity (raw): two separate contracts, tested separately.
    //   - same open file: reads keep coming from the file that was opened;
    //   - unchanged since selection: `revalidate_identity()` reports any
    //     change to that file's metadata, including path operations.
    // ---------------------------------------------------------------------

    fn changed(result: Result<(), SourceChanged>) -> bool {
        matches!(result, Err(SourceChanged::Metadata { .. }))
    }

    // Filesystems without fine-grained timestamps only advance them once per
    // clock tick; waiting briefly before a change avoids depending on that.
    fn let_the_clock_tick() {
        std::thread::sleep(std::time::Duration::from_millis(20));
    }

    #[test]
    fn raw_source_unchanged_revalidates_repeatedly() {
        let data = b"raw image contents".to_vec();
        let path = write_named_temp_file("identity-unchanged", ".img", &data);
        let source = open_raw(&path);

        for _ in 0..3 {
            source.revalidate_identity().unwrap();
        }
        assert_eq!(read_all(source.open_reader().unwrap()), data);
        source.revalidate_identity().unwrap();
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn raw_source_content_changes_are_detected() {
        type Mutation = fn(&Path);
        let mutations: [(&str, Mutation); 3] = [
            ("append", |path| {
                let mut file = OpenOptions::new().append(true).open(path).unwrap();
                file.write_all(b"appended").unwrap();
            }),
            ("truncate", |path| {
                OpenOptions::new()
                    .write(true)
                    .open(path)
                    .unwrap()
                    .set_len(4)
                    .unwrap();
            }),
            ("overwrite", |path| {
                let file = OpenOptions::new().write(true).open(path).unwrap();
                file.write_all_at(b"RAW", 0).unwrap();
            }),
        ];

        for (name, mutate) in mutations {
            let path = write_named_temp_file(name, ".img", b"raw image contents");
            let source = open_raw(&path);

            let_the_clock_tick();
            mutate(&path);

            assert!(changed(source.revalidate_identity()), "{name}");
            let _ = std::fs::remove_file(&path);
        }
    }

    // Rename / unlink / rename + replacement / hard link: the open file keeps
    // being read (no swap to whatever the path now names), and at the same
    // time revalidation reports that the selected file was touched.
    #[test]
    fn raw_source_path_operations_keep_the_open_file_but_are_reported() {
        let original = b"the selected raw image".to_vec();
        type PathOperation = fn(&Path);
        let operations: [(&str, PathOperation); 4] = [
            ("rename", |path| {
                std::fs::rename(path, path.with_extension("moved")).unwrap();
            }),
            ("unlink", |path| {
                std::fs::remove_file(path).unwrap();
            }),
            ("replace", |path| {
                std::fs::rename(path, path.with_extension("moved")).unwrap();
                std::fs::write(path, b"a replacement file at the old path").unwrap();
            }),
            ("hard-link", |path| {
                std::fs::hard_link(path, path.with_extension("link")).unwrap();
            }),
        ];

        for (name, operate) in operations {
            let path = write_named_temp_file(name, ".img", &original);
            let source = open_raw(&path);

            let_the_clock_tick();
            operate(&path);

            // Same-FD contract: still the originally opened content.
            assert_eq!(read_all(source.open_reader().unwrap()), original, "{name}");
            // Source-identity contract: reported as changed.
            assert!(changed(source.revalidate_identity()), "{name}");

            for leftover in [
                path.clone(),
                path.with_extension("moved"),
                path.with_extension("link"),
            ] {
                let _ = std::fs::remove_file(leftover);
            }
        }
    }

    // SelectedImage delegates to its source.
    #[test]
    fn selected_image_revalidates_its_source() {
        let path = write_named_temp_file("identity-selected", ".img", b"raw image");
        let selected = SelectedImage::new(Box::new(open_raw(&path)));
        selected.revalidate_identity().unwrap();

        let_the_clock_tick();
        OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(1)
            .unwrap();
        assert!(changed(selected.revalidate_identity()));
        let _ = std::fs::remove_file(&path);
    }
}
