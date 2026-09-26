// Job/Controller layer: orchestrates exactly one write attempt against an
// `ActiveWrite`, consuming it so the same Gate-passed capability can never be
// reused. This module never decides *whether* a write is safe (that is
// `core.rs`'s Write Gate) and never implements the copy algorithm itself
// (that is `writer.rs`) -- it only drives one call to `writer::write()`,
// relays its progress, and translates the outcome into a small state
// machine.
//
// This module also owns the *execution binding* between a Gate-authorized
// write (`core::AuthorizedWrite`) and a confirmed image input
// (`image_source::SelectedImage`): `ImageBindingError`/`AuthorizedExecution`/
// `WriteStart`/`WritingExecution` (below) exist so that starting a real
// `Writing` is reachable only by first proving, via
// `AuthorizedExecution::bind()`, that the `AuthorizedWrite` and the
// `SelectedImage` come from the same confirmed selection event
// (`image_generation` match) -- see those types' own doc comments for the
// full reasoning. This is a one-directional dependency
// (`write_job.rs -> image_source.rs`, for `SelectedImage`/`ImageSource`
// only); `image_source.rs` never depends back on `write_job.rs`.
//
// State progression implemented in this revision (each arrow consumes the
// value on its left -- there is no method anywhere in this module that goes
// backwards):
//
//   core::AuthorizedWrite + image_source::SelectedImage
//       |  (AuthorizedExecution::bind(): checks image_generation/image_size)
//       v
//   AuthorizedExecution
//       |  (begin_write(self, cancel): opens a reader from the *same*
//       |   SelectedImage, builds a private WriteStart, calls start_inner())
//       v
//   WritingExecution { writing: Writing<Box<dyn Read>>, image: SelectedImage }
//       |  (holds `image` alive for a future write/verify; see doc comment)
//       v
//   Writing<R>
//       |  (write(self): consumes Writing, calls writer::write() exactly once)
//       v
//   WriteSucceeded   |   Failed   |   Cancelled
//       |  (begin_sync(self): consumes WriteSucceeded)
//       v
//   Syncing
//       |  (sync(self): consumes Syncing, calls SyncTarget::sync_all() exactly once)
//       v
//   SyncSucceeded   |   Failed(stage = Syncing)
//       |  (begin_verify(self, image, cancel): consumes SyncSucceeded --
//       |   see below for the VerifyMode::None short-circuit and the
//       |   Quick/Full pre-flight phases)
//       v
//   VerifyStart::Skipped(image, VerifySucceeded)   -- VerifyMode::None
//   VerifyStart::Pending(PendingVerify)            -- VerifyMode::Quick/Full
//       |  (check_target(self, refreshed): Identity/Instance/hazard re-check,
//       |   via core::check_identity_instance_for_verify -- Step 3)
//       v
//   VerifyReadyToOpen
//       |  (caller calls linux_access::open_device(block_path, OpenAccess::ReadOnly), outside
//       |   this module; finalize(self, opened_handle, fd_metadata): FD
//       |   binding check, via core::check_fd_binding -- the same anti-TOCTOU
//       |   final check the write path already uses)
//       v
//   Verifying
//       |  (run(self, on_progress): consumes Verifying, runs Quick or Full)
//       v
//   (SelectedImage, VerifyOutcome)   -- Succeeded | Failed | Cancelled
//
// `WriteSucceeded` is deliberately NOT a "Completed" outcome: a successful
// `writer::write()` call (and its internal `Write::flush()`) says nothing
// about durable, synced storage or verified content. `SyncSucceeded` is
// likewise NOT "Completed": `sync_all()` returning `Ok` is a *candidate*
// durability signal (see `linux_access::SyncTarget`'s doc comment for the
// block-device durability caveat -- this crate does not claim `sync_all()`
// succeeding means data has physically reached USB/SD/NVMe media). Only
// `VerifySucceeded`/`VerifyOutcome::Succeeded` (or an explicit
// `VerifyMode::None`, which the user chose) says anything at all about
// read-back content -- and even then, see `Verifying::run()`'s own doc
// comment for the page-cache honesty caveat carried over from the design
// phase.
//
// The write-mode FD is retired (dropped) the moment `begin_verify()` is
// called, for every `VerifyMode` including `None` -- Verify never reuses the
// write/sync capability (`core::ActiveWrite`/`ActiveWriteTarget`/
// `SyncTarget`), even to merely hold it open. `VerifyMode::Quick`/`Full`
// instead open a brand-new, independent, read-only FD via
// `linux_access::open_device(block_path, OpenAccess::ReadOnly)`, re-validated from scratch
// (fresh `DeviceSnapshot`, Identity, Instance, hazard, FD binding) exactly
// like the original write-mode open was -- this is "Approach B" from the
// Built-in Verify design phase (reports/latest.md), chosen over reusing the
// same FD or holding both FDs open simultaneously, specifically to keep the
// write capability's lifetime as short as possible and to give Verify its
// own, independently-checked TOCTOU defense rather than trusting the one
// already performed for the write.
//
// NOT implemented in this revision (future, separate steps):
//   - a final "Completed" type unifying write+sync+verify into one summary
//   - wiring a device-removal signal into `CancelHandle` (the handle itself
//     is generic enough to support it later; nothing here talks to
//     `linux_monitor`)
//   - cancelling mid-sync (`File::sync_all()` is a single blocking syscall
//     with no chunk loop to poll a cancel flag between iterations -- see
//     `Syncing::sync()`'s doc comment) -- Verify's own read loop IS
//     cancellable, unlike sync, since it has a chunk loop to check between
//     iterations (see `Verifying::run()`)
//   - retrying a failed/cancelled Verify without a fresh write+sync:
//     `begin_verify()` consumes `SyncSucceeded`, and neither
//     `VerifyFailed`/`VerifyCancelled` nor a `VerifyStartError` exposes any
//     way to reach a `Verifying` again -- a deliberate v0.1 simplicity
//     choice, not an oversight (see reports/latest.md)
//   - O_DIRECT / BLKFLSBUF / any other cache-bypassing read strategy for
//     Verify -- a deliberate v0.1 safety/simplicity choice, see
//     `Verifying::run()`'s doc comment
//   - any connection from `main.rs` or any other production call site to
//     this module -- everything here is exercised only by this module's own
//     `#[cfg(test)]` tests, against plain regular temp files, never a real
//     block device. In particular, nothing in this module ever calls
//     `linux_backend::collect_device_snapshot()` or
//     `linux_access::open_device()` itself -- exactly like the existing
//     write path, `check_target()`/`finalize()` (above) take their results
//     as caller-supplied parameters, so a future `main.rs` Controller (not
//     this step) is the one that actually performs those two D-Bus calls,
//     the same way it already does for the write path's own
//     `collect_device_snapshot`/`open_device(OpenAccess::WriteExclusive)` calls today.
//
// This whole module is therefore unreachable from any production code path
// today (`main.rs` never names anything in it), which is why every public
// item below would otherwise trigger rustc's `dead_code` lint under a plain
// `cargo check`. A single module-level allow says so once, honestly, instead
// of scattering per-item annotations that would all say the same thing. This
// is a temporary measure: once a real Controller/UI actually connects to
// `write_job`, this module-wide allow should be removed (individual items
// that remain genuinely unused at that point can be annotated on their own,
// or deleted).
#![allow(dead_code)]

use std::io::{self, Read};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;

use super::core::{
    check_fd_binding, diagnose_identity_instance_for_verify, verify_target_check_from_diagnostics,
    ActiveWrite, AuthorizedWrite, FdBindingCheck, VerifyMode, VerifyTargetCheckError,
    VerifyTargetDiagnostics,
};
use super::linux_access::{FdMetadata, OpenedDeviceHandle, ReadTarget};
use crate::device::{DeviceSnapshot, SnapshotFetchOutcome};
use crate::image_source::source_identity::SourceChanged;
use crate::image_source::{ImageSourceAccess, SelectedImage};
use crate::writer::{self, WriteError, WritePlan, WriteProgress};

const CANCEL_NONE: u8 = 0;
const CANCEL_USER_REQUESTED: u8 = 1;
const CANCEL_DEVICE_LOST: u8 = 2;

// Why a cancellation was requested. `Unknown` is not something callers are
// expected to request deliberately -- it exists as `CancelHandle::reason()`'s
// safe fallback (see there) so resolving a reason can never panic even if
// something unforeseen ends up in the underlying flag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CancelReason {
    UserRequested,
    DeviceLost,
    Unknown,
}

// A single shared flag + reason, standard-library only (no new dependency):
// `writer::write()`'s cancellation contract is a plain `FnMut() -> bool`
// closure checked once per chunk, so a `bool`-shaped signal behind an
// `Arc<AtomicU8>` is all that is needed -- no channel, no async runtime,
// nothing this crate doesn't already use elsewhere. `CancelHandle` is
// `Clone` (cloning shares the same underlying flag via the `Arc`): whoever
// holds a clone can call `request_cancel()`, and `Writing::write()` holds
// its own clone to read from, so a future caller can keep a handle to
// request cancellation from anywhere (a UI callback, a future
// device-removal watcher) without needing `&mut` access to the `Writing`
// value itself.
//
// Device-removal wiring is intentionally NOT implemented here: nothing in
// this module talks to `linux_monitor`. `CancelReason::DeviceLost` exists so
// that *when* such wiring is added later, it has a reason to record --
// today, tests set it directly, exactly like a future device-removal watcher
// would.
#[derive(Debug, Clone)]
pub struct CancelHandle {
    state: Arc<AtomicU8>,
}

impl CancelHandle {
    pub fn new() -> Self {
        CancelHandle {
            state: Arc::new(AtomicU8::new(CANCEL_NONE)),
        }
    }

    // Records that cancellation was requested, for the given reason. Callable
    // any number of times (e.g. a racing user-cancel and device-lost signal);
    // whichever call lands last wins, which is acceptable since the exact
    // reason is a best-effort diagnostic, not a safety-relevant fact -- the
    // fact that *some* cancellation was requested is what `writer::write()`
    // actually acts on.
    pub fn request_cancel(&self, reason: CancelReason) {
        let value = match reason {
            CancelReason::UserRequested => CANCEL_USER_REQUESTED,
            CancelReason::DeviceLost => CANCEL_DEVICE_LOST,
            CancelReason::Unknown => CANCEL_USER_REQUESTED,
        };
        self.state.store(value, Ordering::SeqCst);
    }

    pub fn is_requested(&self) -> bool {
        self.state.load(Ordering::SeqCst) != CANCEL_NONE
    }

    // The reason recorded at the moment this is called. Falls back to
    // `CancelReason::Unknown` for any value that isn't one of the two known
    // "requested" encodings -- this can only happen if `writer::write()`
    // somehow observed cancellation without this handle's own
    // `request_cancel()` ever having been the source (not possible through
    // this module's own API today, but `Writing::write()` still calls this
    // defensively rather than assuming a reason must be present). Never
    // panics.
    fn reason(&self) -> CancelReason {
        match self.state.load(Ordering::SeqCst) {
            CANCEL_USER_REQUESTED => CancelReason::UserRequested,
            CANCEL_DEVICE_LOST => CancelReason::DeviceLost,
            _ => CancelReason::Unknown,
        }
    }
}

impl Default for CancelHandle {
    fn default() -> Self {
        CancelHandle::new()
    }
}

// Which phase of the job a `Failed` outcome happened in. `Verifying` is a
// future variant once that stage is implemented, not modeled yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteStage {
    Writing,
    Syncing,
}

// What underlying error a `Failed` outcome wraps. Exists as a distinct type
// (rather than exposing `writer::WriteError`/`io::Error` directly as the
// Job's own terminal error) so that a future `Verify(..)` variant can be
// added later without reshaping `writer.rs`, `linux_access.rs`, or the
// Gate's own `WriteGateError`. `Sync(io::Error)` is kept as a raw
// `io::Error` for now, deliberately not summarized into a curated
// GUI-facing type -- there is no GUI/API boundary in this codebase yet
// (see CLAUDE.md), and `Write(WriteError)` already isn't summarized either;
// designing a presentation layer for Job-level errors is a single future
// concern that should cover both variants together, not something to solve
// piecemeal per error source.
#[derive(Debug)]
pub enum WriteJobFailureCause {
    Write(WriteError),
    Sync(io::Error),
    // The source image was no longer in the state it was selected in, at
    // one of the two write-stage checkpoints (see `WritingExecution::write`):
    // just before the first byte (nothing was written,
    // `target_may_be_modified == false`) or just after the writer finished
    // (the whole image was written, `target_may_be_modified == true`, and
    // sync was not run). Carries the metadata comparison; it deliberately
    // does not guess *why* the source changed (content rewrite, rename,
    // deletion and replacement all look alike in metadata).
    SourceChanged(SourceChanged),
}

// Whether a terminal outcome leaves the target possibly modified, computed
// from a `WriteError` using the safety-side-biased rules below. Deliberately
// NOT `bytes_written > 0` (see the module-level rationale on
// `target_may_be_modified_for_error`): several `WriteError` variants report
// no byte count at all, or can report 0 while an OS-level write() call was
// still actually attempted.
fn target_may_be_modified_for_error(error: &WriteError) -> bool {
    match error {
        // Pure pre-loop validation failures: `writer::write()` returns these
        // before ever touching `source` or `target`. In practice a
        // Gate-produced `WritePlan` should never trigger these here, but the
        // match must stay exhaustive.
        WriteError::InvalidSize | WriteError::InvalidChunkSize | WriteError::ImageTooLarge => false,

        // Cancelled/SourceTooShort report exactly how many bytes were
        // confirmed written before stopping. Zero means the very first
        // cancellation/short-read check in the copy loop fired before a
        // single `target.write_all()` call was ever made this attempt --
        // the one case where "not modified" is honestly true.
        WriteError::Cancelled { bytes_written } => *bytes_written > 0,
        WriteError::SourceTooShort { bytes_written } => *bytes_written > 0,

        // A write() call to the target was attempted and failed. Even a "0
        // bytes written" report cannot be trusted here: `write_all()` may
        // have pushed some bytes to the OS/device before the error surfaced,
        // and `WriteError::TargetWrite` carries no byte count to disprove
        // that -- always treat the target as possibly modified.
        WriteError::TargetWrite(_) => true,

        // A source read failed mid-loop. Earlier chunks in this same call
        // may already have reached the target, and this variant carries no
        // bytes_written either -- conservatively assume modified.
        WriteError::SourceRead(_) => true,

        // flush() is only reached after every chunk already succeeded, i.e.
        // the full image was already handed to the target -- unambiguously
        // modified.
        WriteError::FlushFailed(_) => true,
    }
}

// How many bytes a non-Cancelled `WriteError` reports as written. Only
// `SourceTooShort` carries this; every other variant reports 0 here as a
// *reporting default*, never as a claim that nothing reached the target --
// `target_may_be_modified_for_error` above is what actually carries that
// safety-relevant fact, precisely so a `bytes_written == 0` field can never
// be misread as "the target is untouched".
fn write_error_bytes_written(error: &WriteError) -> u64 {
    match error {
        WriteError::SourceTooShort { bytes_written } => *bytes_written,
        // `Writing::write()` peels `Cancelled` off into its own branch
        // before this function is ever called, so this arm is unreachable
        // in practice today -- kept only so this match stays exhaustive
        // against `WriteError` as a whole, rather than silently going stale
        // if that call site is ever restructured.
        WriteError::Cancelled { bytes_written } => *bytes_written,
        WriteError::InvalidSize
        | WriteError::InvalidChunkSize
        | WriteError::ImageTooLarge
        | WriteError::SourceRead(_)
        | WriteError::TargetWrite(_)
        | WriteError::FlushFailed(_) => 0,
    }
}

// Every non-Cancelled `WriteError` becomes a `Failed`. `target_may_be_modified`
// and `retry_requires_fresh_gate` are always present so a caller never has to
// guess: `retry_requires_fresh_gate` is unconditionally `true` here because
// there is no API anywhere in this crate that hands back a reusable
// `ActiveWrite`/`Writing` after a failed attempt -- any retry necessarily
// means going through Selection/Safety/Identity/Instance/Confirmation/Gate
// again from scratch.
#[derive(Debug)]
pub struct Failed {
    pub image_size: u64,
    pub bytes_written: u64,
    pub stage: WriteStage,
    pub cause: WriteJobFailureCause,
    pub target_may_be_modified: bool,
    pub retry_requires_fresh_gate: bool,
}

// `WriteError::Cancelled` becomes a `Cancelled`, tagged with why (as best
// `CancelHandle` can tell -- see `CancelHandle::reason()`). Same
// `retry_requires_fresh_gate` rationale as `Failed`.
#[derive(Debug)]
pub struct Cancelled {
    pub image_size: u64,
    pub bytes_written: u64,
    pub reason: CancelReason,
    pub target_may_be_modified: bool,
    pub retry_requires_fresh_gate: bool,
}

// Raw `writer::write()` (and its internal `Write::flush()`) succeeded: every
// `image_size` byte was handed to the target and flushed at the userspace
// buffering level. This is deliberately NOT a "Completed" outcome -- no
// OS-level durability guarantee (fsync/fdatasync) and no read-back
// verification have happened yet; the type name and this comment exist so
// nobody mistakes reaching this value for "safe to tell the user the write
// finished".
//
// Retains the consumed `ActiveWrite` (hence its `OpenedDeviceHandle`, hence
// the real fd) privately, unwrapped and un-dropped, specifically so a future
// `Syncing` stage can move it further without reopening the device or
// duplicating the fd. Nothing here exposes that handle, a raw `File`, or a
// `RawFd` publicly -- `active` has no accessor at all today.
pub struct WriteSucceeded {
    pub image_size: u64,
    pub bytes_written: u64,
    pub target_may_be_modified: bool,
    pub retry_requires_fresh_gate: bool,
    // Carried through unchanged from the `AuthorizedWrite` this attempt
    // started from -- not read or branched on anywhere in `Writing::write()`
    // itself, only relayed forward for a future `Verifying` stage to act on.
    pub verify_mode: VerifyMode,
    active: ActiveWrite,
}

impl std::fmt::Debug for WriteSucceeded {
    // `ActiveWrite` itself has no `Debug` impl (see `core.rs`), so this is
    // written by hand rather than derived; `finish_non_exhaustive()` makes
    // clear that `active` exists but is deliberately not shown.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WriteSucceeded")
            .field("image_size", &self.image_size)
            .field("bytes_written", &self.bytes_written)
            .field("target_may_be_modified", &self.target_may_be_modified)
            .field("retry_requires_fresh_gate", &self.retry_requires_fresh_gate)
            .field("verify_mode", &self.verify_mode)
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
pub enum WriteAttemptOutcome {
    Succeeded(WriteSucceeded),
    Failed(Failed),
    Cancelled(Cancelled),
}

// One write attempt's execution state: the result of consuming an
// `ActiveWrite` to start it. Deliberately not `Clone`/`Copy` -- exactly like
// `PreparedWrite`/`ActiveWrite` before it, the point of `write(self)`
// consuming `self` is that a given `Writing` can produce at most one
// `WriteAttemptOutcome`, ever.
//
// `R: Read` mirrors `writer::write()`'s own generic source parameter as-is;
// this is deliberately not treated as this type's final, fixed shape. Once
// write completes, `source` (and this `Writing` value) is gone -- a future
// Full Verify needs to compare the target's content against the *original*
// image again, and a plain `R: Read` cannot be rewound in general (a
// `Cursor`/`File` can be `Seek`'d back to the start, but a future streaming
// decompressor for a compressed image source, e.g. gzip/xz, generally
// cannot be rewound at all). Designing how a future Verify stage re-reads
// the original image -- e.g. an `ImageSource` abstraction that can hand out
// a fresh reader, or computing a digest while writing and comparing that
// against a digest of the read-back instead of a byte-for-byte replay -- is
// explicitly left to the Verify design step; nothing here should be read as
// having settled that question.
pub struct Writing<R: Read> {
    active: ActiveWrite,
    plan: WritePlan,
    verify_mode: VerifyMode,
    source: R,
    cancel: CancelHandle,
}

// The one and only way to reach a `Writing`. Consumes `authorized` by value:
// the `AuthorizedWrite` passed in can never be referred to again afterward
// (the Rust compiler enforces this, not a runtime check), and there is no
// way to mint a second `Writing` from it since nothing here keeps a copy.
// `into_parts()` (the only way to take an `AuthorizedWrite` apart) hands
// back the exact `ActiveWrite`/`WritePlan`/`VerifyMode` the Gate bundled
// together -- there is no way to call this with an `ActiveWrite`,
// `WritePlan`, and `VerifyMode` supplied as three independent arguments, so
// a caller cannot accidentally pair a Gate-approved FD with a plan or
// verify mode from a different Gate pass. No fd is duplicated -- `active`
// is moved, never cloned (`ActiveWrite` is not `Clone`/`Copy`), and
// `writer_target()` (called later, inside `Writing::write`) only ever
// borrows it.
//
// Deliberately NOT `pub`/`pub(crate)`: `authorized` and `source` are still
// two independent parameters here, which is exactly the shape
// `AuthorizedExecution::bind()`/`WriteStart` (below) exist to make
// unreachable from outside this module. This plain-private function is the
// one place that shape is still allowed to exist -- reachable only from
// `AuthorizedExecution::begin_write()` (same module, below) and this
// module's own `#[cfg(test)]` tests (a plain-private `fn` is visible to a
// module's descendants, and `mod tests` is one), never from any sibling
// module such as `image_source.rs`.
fn start_inner<R: Read>(
    authorized: AuthorizedWrite,
    source: R,
    cancel: CancelHandle,
) -> Writing<R> {
    let (active, plan, verify_mode) = authorized.into_parts();

    Writing {
        active,
        plan,
        verify_mode,
        source,
        cancel,
    }
}

// Why `AuthorizedExecution::bind()` refused to bind an `AuthorizedWrite` to a
// `SelectedImage`. The first two are identity checks -- not a cryptographic
// content check, and not meant to be: `GenerationMismatch` is the real,
// reachable case (the image was reselected, or a stale `AuthorizedWrite`
// from an earlier Gate pass is being reused against a newer selection).
// `SizeMismatch` is defense-in-depth only: `image_generation` and
// `image_size` are always minted together, atomically, by
// `core::ImageSelection::new()` (see its own doc comment), so a matching
// generation already implies a matching size by construction -- this
// variant exists to fail loudly (an `Err`, not a silent proceed) if that
// invariant is ever violated by a future bug, not because it is expected to
// ever actually fire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageBindingError {
    GenerationMismatch,
    SizeMismatch,
    // The Gate authorized Quick Verify, but the image cannot be read at
    // random offsets (e.g. a compressed image): Quick Verify could never
    // run, so the write is refused before it starts rather than after it.
    // Defense in depth -- the CLI refuses this combination before any
    // confirmation, and the verifier itself still refuses it
    // (`VerifyFailureReason::UnsupportedAccess`).
    QuickVerifyUnsupported,
}

// Proof that a Gate-authorized write (`AuthorizedWrite`) and a confirmed
// image input (`SelectedImage`) come from the *same* confirmed selection
// event, checked immediately before a write starts. Closes the gap
// `SelectedImage` alone cannot: `SelectedImage` only guarantees its own
// `ImageSelection` and `ImageSource` were minted together, but says nothing
// about whether it is the *same* `SelectedImage` the Gate's confirmation was
// made against -- a caller could still call `WriteIntent::from_selection`
// with one `SelectedImage`'s `.selection()` and later try to start a write
// with a *different* `SelectedImage`'s reader. `bind()` is the point where
// an actual `SelectedImage` is first compared against the frozen,
// Gate-carried `image_generation` (see `core::AuthorizedWrite::
// image_generation()`'s doc comment).
//
// Fields are private, there is no setter, and no `Clone`/`Copy` impl (the
// same reasoning as `SelectedImage`'s own doc comment: `authorized` owns an
// FD, `image` owns a `Box<dyn ImageSource>`, and duplicating either would
// raise the same "which copy is real" question). `bind()` is the only
// public constructor; on success it holds both `authorized`/`image`
// *whole*, never decomposed -- there is no public way to pull them back
// apart and recombine them with something else (`begin_write()` below
// consumes `self` entirely, it does not expose the pieces).
pub struct AuthorizedExecution {
    authorized: AuthorizedWrite,
    image: SelectedImage,
}

impl AuthorizedExecution {
    // Checks `image_generation` first (the real identity判定) and only then
    // `image_size` (defense-in-depth, see `ImageBindingError`'s doc
    // comment) -- not content hashing, and not a guarantee that the two
    // values' underlying bytes are identical, only that they were minted
    // from the same explicit selection event.
    pub fn bind(
        authorized: AuthorizedWrite,
        image: SelectedImage,
    ) -> Result<Self, ImageBindingError> {
        if authorized.image_generation() != image.selection().image_generation() {
            return Err(ImageBindingError::GenerationMismatch);
        }

        if authorized.image_size() != image.logical_size() {
            return Err(ImageBindingError::SizeMismatch);
        }

        if authorized.verify_mode() == VerifyMode::Quick
            && image.access() != ImageSourceAccess::RandomAccess
        {
            return Err(ImageBindingError::QuickVerifyUnsupported);
        }

        Ok(AuthorizedExecution { authorized, image })
    }

    // Consumes this `AuthorizedExecution` to start the one write it was
    // bound for. Opens a reader from `self.image` (the *same* `SelectedImage`
    // that was proven, in `bind()`, to match `self.authorized`'s confirmed
    // `image_generation`) -- the caller has no way to supply a different
    // reader, since this method takes no reader parameter at all. Builds a
    // private `WriteStart` purely to hand its two fields to `start_inner()`
    // in one line; `WriteStart` is never returned or exposed outside this
    // function.
    //
    // On success, `WritingExecution` keeps `self.image` alive alongside the
    // resulting `Writing`, so a future write/verify orchestration can still
    // reach the same `SelectedImage` for a second, verify-time
    // `open_reader()` call once write/sync complete (see
    // `WritingExecution`'s own doc comment).
    //
    // On failure (`self.image.open_reader()` returning an `io::Error`),
    // `self` -- and everything it owns, including `self.authorized`'s FD --
    // is dropped via the early `?` return; ordinary RAII closes the target
    // FD exactly like every other Gate-rejection path in this crate. No
    // write is attempted, 0 bytes reach the target, and (matching every
    // other failure path in this module) a retry requires a fresh Gate pass
    // and a fresh `SelectedImage`, since both `self.authorized` and
    // `self.image` are gone.
    pub fn begin_write(self, cancel: CancelHandle) -> io::Result<WritingExecution> {
        let reader = self.image.open_reader()?;

        let start = WriteStart {
            authorized: self.authorized,
            reader,
        };

        let writing = start_inner(start.authorized, start.reader, cancel);

        Ok(WritingExecution {
            writing,
            image: self.image,
        })
    }
}

// A momentary, module-internal value: proof that an `AuthorizedWrite` and a
// `Box<dyn Read>` were paired inside this module, immediately before being
// handed to `start_inner()`. Carries no logic of its own -- the actual
// generation/size check already happened in `AuthorizedExecution::bind()`;
// this type exists only to give `authorized`+`reader` a single, private
// struct-literal construction site.
//
// No `pub`, no constructor beyond the plain struct literal inside
// `begin_write()` above (the only place in this file that writes
// `WriteStart { ... }`), no getters, no `into_parts()`. Rust's field
// visibility rule (private = visible within the defining module and its
// descendants) means this struct literal can only ever be written inside
// `write_job.rs` itself -- not `image_source.rs`, not `main.rs`, not any
// other sibling module. This is a *module*-level guarantee, not a
// function-level one: nothing about Rust's visibility system singles out
// `begin_write()` specifically as the only permitted caller, only
// `write_job.rs` as the only permitted module. `begin_write()` happens to be
// the only code in this file that ever does construct one, which is what
// actually makes it the sole creation path in practice.
struct WriteStart {
    authorized: AuthorizedWrite,
    reader: Box<dyn Read>,
}

// The result of `AuthorizedExecution::begin_write()`: an in-progress
// `Writing`, paired with the exact `SelectedImage` it was authorized
// against. Deliberately minimal -- this revision does not implement
// Verifying, so `WritingExecution` does not yet grow a full write/sync/
// verify orchestration API (a public `into_parts()`-style decomposition is
// deliberately not added either, for the same reason `AuthorizedExecution`
// does not expose one: pulling `writing`/`image` apart would let a caller
// recombine either with something unrelated).
//
// `image` staying alive here (rather than being dropped once `writing`
// starts) is the whole point: a future write/sync/verify orchestration
// needs `image.open_reader()` a second time, once write and sync have
// completed, to compare the target's content back against the *same*
// confirmed image -- not a freshly supplied, potentially different one.
// Neither field is exposed publicly in this revision; any access needed by
// this module's own tests uses plain field access from within `write_job.rs`
// itself.
pub struct WritingExecution {
    writing: Writing<Box<dyn Read>>,
    image: SelectedImage,
}

impl WritingExecution {
    // The minimal public surface needed to actually drive a
    // `WritingExecution` to completion from outside this module. Before this
    // method existed, `WritingExecution` had no `impl` block at all: both
    // fields are private, so a caller outside `write_job.rs` holding one
    // could do nothing with it whatsoever (see this struct's own doc comment
    // above). This method closes exactly that gap, and nothing more.
    //
    // Delegates straight to `Writing::write()` (unchanged, exercised by this
    // module's own tests since day one) and adds no behavior of its own
    // beyond also returning `self.image` alongside the result. Takes `self`
    // by value: the same "consumed exactly once" guarantee every other
    // state-transition method in this module already provides
    // (`Writing::write()`, `WriteSucceeded::begin_sync()`,
    // `Syncing::sync()`) -- there is no `&self`/`&mut self` variant, so the
    // same `WritingExecution` can never be written twice. Takes no reader
    // parameter, mirroring `AuthorizedExecution::begin_write()`: the only
    // bytes ever written are the ones `self.image` already produced when
    // `begin_write()` opened its reader: there is no way for a caller to
    // substitute a different one here.
    //
    // Returns `(SelectedImage, WriteAttemptOutcome)` rather than exposing
    // `self.writing`/`self.image` separately, so the two can never be pulled
    // apart and recombined with something unrelated (the same reasoning
    // `AuthorizedExecution`/`WritingExecution`'s own doc comments already
    // give for not exposing their fields). The returned `SelectedImage` is
    // the exact same value `AuthorizedExecution::bind()` was given -- never
    // a freshly constructed one, and `open_reader()` is not called again
    // here -- so a future write/sync/verify orchestration can still reach it
    // for a second, verify-time reader (see `WritingExecution`'s own doc
    // comment for why that matters). `WriteAttemptOutcome` is returned
    // exactly as `Writing::write()` already produces it --
    // `Succeeded`/`Failed`/`Cancelled` keep their existing fields and
    // meaning unchanged; this method does not interpret, wrap, or summarize
    // it further.
    //
    // Returns no `ActiveWrite`/`ActiveWriteTarget`/`OpenedDeviceHandle`/raw
    // fd/`dyn Write`: this method exposes nothing beyond what
    // `WriteAttemptOutcome`'s existing variants already choose to expose
    // (`Failed`/`Cancelled` do not carry `active` at all; `WriteSucceeded`
    // keeps it private with no accessor). The Raw Write Capability Boundary
    // (`pub(in crate::execution)` on `ActiveWrite::writer_target()` etc.) is
    // therefore unaffected by adding this method.
    //
    // Source gate: immediately before the first byte is written, the source
    // image is revalidated (`SelectedImage::revalidate_identity`: one
    // metadata read of the already-open file, compared with the snapshot
    // taken when it was opened). Everything about the target -- fresh
    // snapshot, Identity/Instance/Safety re-check, FD binding -- was already
    // verified before `AuthorizedExecution::bind()`, so the order is target
    // revalidation, then source revalidation, then the first write. This is
    // the latest point every write passes through (`Writing` has no public
    // constructor), so no caller can reach the target without it.
    //
    // If the source changed, the result is `Failed` with
    // `WriteJobFailureCause::SourceChanged`, 0 bytes written and the target
    // untouched; being `Failed`, it cannot lead to sync or Verify, and a
    // retry needs a fresh selection and a fresh Gate pass.
    //
    // Post-write source checkpoint: when the writer reports success, the
    // source is revalidated once more before `WriteSucceeded` is handed out
    // -- i.e. before sync, and for every `VerifyMode` including `None`. The
    // bytes just written came from a source that may have changed while it
    // was being read, so a change here turns the success into `Failed`
    // (`SourceChanged`, stage `Writing`, the real `bytes_written`,
    // `target_may_be_modified == true`); sync and Verify are not reached.
    // Only a success is checked: a writer failure or cancellation is
    // returned exactly as the writer reported it, never replaced by
    // `SourceChanged`.
    //
    // Source checkpoints always compare against the snapshot taken when the
    // image was opened, never against the previous checkpoint, so they are
    // cumulative: each one also covers every earlier moment. The contract
    // runs through the last read of the source for the chosen Verify mode:
    // this post-write check for `VerifyMode::None` (the source is never read
    // again), the post-verify check in `Verifying::run` for Quick / Full.
    pub fn write(
        self,
        on_progress: impl FnMut(WriteProgress),
    ) -> (SelectedImage, WriteAttemptOutcome) {
        let WritingExecution { writing, image } = self;

        if let Err(changed) = image.revalidate_identity() {
            let failed = Failed {
                image_size: writing.plan.image_size,
                bytes_written: 0,
                stage: WriteStage::Writing,
                target_may_be_modified: false,
                retry_requires_fresh_gate: true,
                cause: WriteJobFailureCause::SourceChanged(changed),
            };
            // `writing` (and the target FD inside it) is dropped here,
            // unused: no write call was ever made.
            return (image, WriteAttemptOutcome::Failed(failed));
        }

        let outcome = match writing.write(on_progress) {
            WriteAttemptOutcome::Succeeded(succeeded) => match image.revalidate_identity() {
                Ok(()) => WriteAttemptOutcome::Succeeded(succeeded),
                // `succeeded` (and the target FD inside it) is dropped here,
                // unsynced; the write itself already happened.
                Err(changed) => WriteAttemptOutcome::Failed(Failed {
                    image_size: succeeded.image_size,
                    bytes_written: succeeded.bytes_written,
                    stage: WriteStage::Writing,
                    target_may_be_modified: true,
                    retry_requires_fresh_gate: true,
                    cause: WriteJobFailureCause::SourceChanged(changed),
                }),
            },
            other => other,
        };

        (image, outcome)
    }
}

impl<R: Read> Writing<R> {
    // Consumes this `Writing` to run the one write attempt it was set up
    // for. Calls `writer::write()` exactly once, with `active.writer_target()`
    // (the only source of a `std::io::Write` anywhere in this crate) as the
    // target and `self.cancel.is_requested()` as the cancellation check --
    // `writer.rs` itself is untouched; this only drives its existing,
    // unmodified API. `on_progress` is relayed to `writer::write()`'s own
    // progress callback unchanged.
    //
    // Because `self` is consumed here, the same `Writing` value cannot be
    // used to attempt a second `writer::write()` call -- there is no `&self`
    // or `&mut self` variant of this method, so after calling it once, the
    // variable that held this `Writing` no longer exists for the caller to
    // reuse (verified by the fact that this compiles at all; there is no
    // runtime test that could demonstrate a compile-time property like this
    // one any more directly).
    pub fn write(self, mut on_progress: impl FnMut(WriteProgress)) -> WriteAttemptOutcome {
        let Writing {
            mut active,
            plan,
            verify_mode,
            source,
            cancel,
        } = self;

        let result = writer::write(
            &plan,
            source,
            active.writer_target(),
            |progress| on_progress(progress),
            || cancel.is_requested(),
        );

        match result {
            Ok(bytes_written) => WriteAttemptOutcome::Succeeded(WriteSucceeded {
                image_size: plan.image_size,
                bytes_written,
                // A successful write is, by definition, an intentional and
                // complete modification of the target (rule E).
                target_may_be_modified: true,
                retry_requires_fresh_gate: true,
                verify_mode,
                active,
            }),
            Err(WriteError::Cancelled { bytes_written }) => {
                WriteAttemptOutcome::Cancelled(Cancelled {
                    image_size: plan.image_size,
                    bytes_written,
                    reason: cancel.reason(),
                    target_may_be_modified: bytes_written > 0,
                    retry_requires_fresh_gate: true,
                })
            }
            Err(error) => {
                let bytes_written = write_error_bytes_written(&error);
                let target_may_be_modified = target_may_be_modified_for_error(&error);

                WriteAttemptOutcome::Failed(Failed {
                    image_size: plan.image_size,
                    bytes_written,
                    stage: WriteStage::Writing,
                    target_may_be_modified,
                    retry_requires_fresh_gate: true,
                    cause: WriteJobFailureCause::Write(error),
                })
            }
        }
    }
}

// Converts a sync failure into a `Failed`, as a pure function independent of
// any real `SyncTarget`/`File::sync_all()` call. This is what makes sync
// failure handling testable without needing to force a real `fsync()` to
// fail -- hard to do deterministically against a plain regular file, and
// this crate adds no trait abstraction or mock framework to work around
// that; the conversion logic itself is simply tested directly with a
// synthetic `io::Error`, the same way `target_may_be_modified_for_error`
// and `write_error_bytes_written` above are tested without a real
// `writer::write()` call.
//
// `bytes_written` here is always the full amount the preceding
// `WriteSucceeded` reported (in practice == the `WritePlan`'s `image_size`,
// since `Syncing` is only reachable after a fully successful write).
// `target_may_be_modified` is unconditionally `true`: raw write already
// succeeded before `Syncing` was ever reached, so the target has already
// been intentionally, completely modified regardless of what `sync_all()`
// itself reports -- a sync failure never means "nothing was written".
fn sync_error_to_failed(image_size: u64, bytes_written: u64, error: io::Error) -> Failed {
    Failed {
        image_size,
        bytes_written,
        stage: WriteStage::Syncing,
        target_may_be_modified: true,
        retry_requires_fresh_gate: true,
        cause: WriteJobFailureCause::Sync(error),
    }
}

// The result of consuming a `WriteSucceeded` to start durability sync.
// Deliberately minimal: no `VerifyMode` (whether Verify needs any input
// here at all is a separate future design step -- see the module-level doc
// comment), no `CancelHandle` (see `Syncing::sync()`'s doc comment for why
// sync is not cancellable), no GUI-facing summary fields beyond what
// `Failed`/`SyncSucceeded` already carry once `sync()` resolves. Not
// `Clone`/`Copy`, for the same reason `Writing`/`WriteSucceeded` are not.
pub struct Syncing {
    active: ActiveWrite,
    image_size: u64,
    bytes_written: u64,
    verify_mode: VerifyMode,
}

impl WriteSucceeded {
    // The one and only way to reach a `Syncing`. Takes `self` by value, so
    // the `WriteSucceeded` passed in can never be used again afterward --
    // the same "consumed exactly once" guarantee `PreparedWrite::begin()`
    // provides. No fd is duplicated: `active` moves straight from
    // `WriteSucceeded` into `Syncing`, unwrapped and un-dropped. A plain
    // method (not a free function like `start_inner()`) because, unlike
    // `Writing`, `Syncing` needs no additional caller-supplied input beyond
    // what `WriteSucceeded` already carries -- the same reasoning that makes
    // `PreparedWrite::begin(self) -> ActiveWrite` a method rather than a
    // free function.
    pub fn begin_sync(self) -> Syncing {
        Syncing {
            active: self.active,
            image_size: self.image_size,
            bytes_written: self.bytes_written,
            verify_mode: self.verify_mode,
        }
    }
}

// `SyncTarget::sync_all()` (a *candidate* durability primitive -- see its
// doc comment in `linux_access.rs` for the caveat that this is not a
// confirmed final answer for block device durability) returned `Ok`.
// Deliberately NOT a "Completed" outcome: no read-back verification has
// happened yet, and the type name and this comment exist so nobody mistakes
// reaching this value for "verified", or for "physically durable on real
// media" beyond what the OS itself reported.
//
// Retains the consumed `ActiveWrite` privately, unwrapped and un-dropped --
// not so a future `Verifying` stage can keep using the same fd (it does not:
// `begin_verify()`, below, retires this exact fd by dropping `active` before
// doing anything else, and opens a brand-new read-only fd for Verify --
// "Approach B" from the Built-in Verify design phase), but so
// `begin_verify()` itself can still read `active.baseline()` -- the
// write-approved `DeviceSnapshot` Verify's own Identity/Instance re-check is
// measured against -- one last time before that retirement happens.
pub struct SyncSucceeded {
    pub image_size: u64,
    pub bytes_written: u64,
    pub target_may_be_modified: bool,
    pub retry_requires_fresh_gate: bool,
    // Carried through unchanged from `Syncing`, which itself carried it
    // through unchanged from `WriteSucceeded`. `Syncing::sync()` never
    // branches on this -- it only relays it forward so a future `Verifying`
    // stage (`SyncSucceeded -> Verifying`) knows which policy (None / Quick
    // / Full) to apply.
    pub verify_mode: VerifyMode,
    active: ActiveWrite,
}

impl std::fmt::Debug for SyncSucceeded {
    // `ActiveWrite` has no `Debug` impl (see `core.rs`), so this is written
    // by hand rather than derived, exactly like `WriteSucceeded`'s.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SyncSucceeded")
            .field("image_size", &self.image_size)
            .field("bytes_written", &self.bytes_written)
            .field("target_may_be_modified", &self.target_may_be_modified)
            .field("retry_requires_fresh_gate", &self.retry_requires_fresh_gate)
            .field("verify_mode", &self.verify_mode)
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
pub enum SyncAttemptOutcome {
    Succeeded(SyncSucceeded),
    Failed(Failed),
}

impl Syncing {
    // Consumes this `Syncing` to run the one sync attempt it was set up for.
    // Calls `SyncTarget::sync_all()` (via `active.sync_target()`, the only
    // source of that capability) exactly once. Because `self` is consumed,
    // the same `Syncing` value cannot be used to attempt a second sync call
    // -- the same compile-time, ownership-enforced guarantee as
    // `Writing::write()`.
    //
    // No cancellation parameter here, unlike `Writing::write()`: unlike the
    // chunked copy loop, `File::sync_all()` is a single blocking syscall
    // with no loop in which to poll a cancel flag between iterations, so
    // there is nothing for a `CancelHandle` to do partway through a sync
    // attempt. Whether a cancel request raised before `Writing` finished
    // should cause `Syncing` to be skipped entirely is a policy question for
    // a future, higher-level Controller -- this type does not decide it.
    pub fn sync(self) -> SyncAttemptOutcome {
        let Syncing {
            active,
            image_size,
            bytes_written,
            verify_mode,
        } = self;

        match active.sync_target().sync_all() {
            Ok(()) => SyncAttemptOutcome::Succeeded(SyncSucceeded {
                image_size,
                bytes_written,
                // sync succeeding changes nothing about whether the target
                // was modified -- the raw write already made it so.
                target_may_be_modified: true,
                retry_requires_fresh_gate: true,
                verify_mode,
                active,
            }),
            Err(error) => {
                SyncAttemptOutcome::Failed(sync_error_to_failed(image_size, bytes_written, error))
            }
        }
    }
}

// ---------------------------------------------------------------------
// Built-in Verify (implementation step 4): SyncSucceeded -> begin_verify()
// -> VerifyStart -> [Quick/Full pre-flight] -> Verifying -> run() ->
// (SelectedImage, VerifyOutcome). See the module-level doc comment above for
// the full state diagram and reports/latest.md for the design-phase
// rationale this implementation follows.
// ---------------------------------------------------------------------

// Quick Verify's fixed sample-window size (design phase: "first 4 MiB,
// middle 4 MiB, last 4 MiB"). A separate constant from
// `writer::DEFAULT_CHUNK_SIZE`: the window size decides *how much* of the
// image Quick Verify samples, while the chunk size (reused from `writer.rs`,
// see `run_full_verify`/`run_quick_verify` below) decides how much is read
// into memory at once -- two independent concerns that happen to both
// default to a "MiB-scale" constant.
const QUICK_VERIFY_WINDOW_SIZE: u64 = 4 * 1024 * 1024;

// Why `PendingVerify::check_target()` refused to let a Quick/Full Verify
// proceed past the Identity/Instance/hazard re-check, why
// `VerifyReadyToOpen::finalize()` refused to let it proceed past the FD
// binding re-check, or why the snapshot refresh/OpenDevice step itself
// failed. Deliberately one flat enum for the whole pre-flight sequence
// (rather than a separate type per phase): every variant here describes a
// *pre-flight* rejection -- no byte has been read from the target when any
// of these is produced, exactly mirroring `WriteGateError`'s own existing
// precedent of covering write's entire multi-phase Gate (Identity/Instance/
// Safety/size/confirmation/OpenDevice/FD-binding) in one flat type rather
// than one per phase. `IdentityChanged`/`IdentityInsufficient`/
// `InstanceRecreated`/`InstanceInsufficient`/`UnsafeTargetState` are a
// direct relabeling of `core::VerifyTargetCheckError`'s own variants (see
// `verify_start_error_from_target_check` below) -- not a re-implementation
// of that check, just this module's own vocabulary for the same outcome,
// exactly how `prepare_for_open` relabels `InvalidationReason` into
// `WriteGateError` variants today. `OpenDeviceFailed`/`FdBindingMismatch`/
// `FdBindingInsufficient` mirror `WriteGateError`'s own identically-named,
// payload-less variants (the underlying `OpenDeviceError`/`FdBindingCheck`
// detail is discarded at this same boundary in the write path already, so
// this does the same, rather than introducing a new precedent).
#[derive(Debug)]
pub enum VerifyStartError {
    SnapshotRefreshFailed,
    IdentityChanged,
    IdentityInsufficient,
    InstanceRecreated,
    InstanceInsufficient,
    UnsafeTargetState,
    OpenDeviceFailed,
    FdBindingMismatch,
    FdBindingInsufficient,
}

// Pure relabeling, no new logic: `core::verify_target_check_from_diagnostics`
// (Verify Pre-flight Diagnostics implementation step 3+4) already decided
// everything, from a `VerifyTargetDiagnostics` value `check_target()` (below)
// computed via a single `diagnose_identity_instance_for_verify()` call. This
// module never re-implements the Identity -> Instance -> hazards priority
// order itself -- that decision now lives in exactly one place,
// `core::verify_target_check_from_diagnostics`, shared by this module and by
// `core::check_identity_instance_for_verify`. This function only translates
// its small, `execution`-internal `VerifyTargetCheckError` into this
// module's own, `pub` `VerifyStartError` vocabulary -- see `VerifyStartError`'s
// own doc comment for why this mirrors `prepare_for_open`'s existing
// `InvalidationReason` -> `WriteGateError` relabeling.
fn verify_start_error_from_target_check(error: VerifyTargetCheckError) -> VerifyStartError {
    match error {
        VerifyTargetCheckError::IdentityChanged => VerifyStartError::IdentityChanged,
        VerifyTargetCheckError::IdentityInsufficient => VerifyStartError::IdentityInsufficient,
        VerifyTargetCheckError::InstanceRecreated => VerifyStartError::InstanceRecreated,
        VerifyTargetCheckError::InstanceInsufficient => VerifyStartError::InstanceInsufficient,
        VerifyTargetCheckError::UnsafeTargetState => VerifyStartError::UnsafeTargetState,
    }
}

// The result of calling `SyncSucceeded::begin_verify()`. `VerifyMode::None`
// resolves immediately and synchronously -- no `DeviceSnapshot` refresh, no
// D-Bus call, no FD ever opened, exactly as the design phase specified --
// which is why this variant already carries the final
// `(SelectedImage, VerifySucceeded)` pair rather than some intermediate
// state. `VerifyMode::Quick`/`Full` instead need a fresh `DeviceSnapshot`
// before anything else can be decided, so they produce a `PendingVerify` for
// the caller to continue from.
pub enum VerifyStart {
    Skipped(SelectedImage, VerifySucceeded),
    Pending(PendingVerify),
}

// The first pre-flight phase for `VerifyMode::Quick`/`Full`: everything
// `begin_verify()` could decide *before* a fresh `DeviceSnapshot` exists.
// Holds `baseline` -- the exact `DeviceSnapshot` this write was authorized
// against (`core::ActiveWrite::baseline()`, itself the `ReadyToOpen.current`
// the write Gate re-verified immediately before OpenDevice -- see
// `core::PreparedWrite::baseline`'s doc comment) -- specifically because it
// must NOT be a snapshot taken at Verify time: that would make a device
// silently replaced between write and verify unverifiable, defeating the
// entire point of re-checking Identity/Instance here at all.
//
// Deliberately does not itself perform the snapshot refresh (no D-Bus, no
// I/O anywhere in this module -- see the module-level doc comment): the
// caller fetches a fresh `DeviceSnapshot` for `block_path()` (in production,
// via `linux_backend::collect_device_snapshot`, exactly as the write path's
// own caller already does) and passes the result to `check_target()`.
pub struct PendingVerify {
    baseline: DeviceSnapshot,
    image: SelectedImage,
    mode: VerifyMode,
    cancel: CancelHandle,
}

impl PendingVerify {
    // The target to re-fetch a `DeviceSnapshot` for. `&str`, not
    // `&DeviceSnapshot`: nothing outside this module needs any other field
    // of `baseline` before the fresh snapshot exists, and this narrower
    // return type cannot be mistaken for the fresh snapshot itself.
    pub fn block_path(&self) -> &str {
        &self.baseline.block_path
    }

    // Identity/Instance/hazard re-check (Step 3's
    // `check_identity_instance_for_verify`, now reached via
    // `core::diagnose_identity_instance_for_verify` +
    // `core::verify_target_check_from_diagnostics` -- the same shared
    // priority order that function itself uses, see its doc comment for
    // why this module cannot call `check_identity_instance_for_verify`
    // directly without recomputing the diagnostics a second time) against a
    // freshly re-fetched snapshot. On any rejection, `self.image` is
    // returned alongside the error rather than silently dropped -- the same
    // "never silently drop a caller-supplied resource" discipline
    // `WritingExecution::write()` already established for the write path.
    //
    // Verify Pre-flight Diagnostics (implementation step 3+4): the freshly
    // computed `VerifyTargetDiagnostics` is now returned to the caller on
    // every path but one. On success it travels inside the returned
    // `VerifyReadyToOpen` (see that struct's own doc comment); on an
    // Identity/Instance/hazard rejection it is the third element of the
    // error tuple, `Some(diagnostics)` -- the caller (a future `main.rs`
    // diagnostic log line, not this step) can inspect exactly which
    // comparison/hazard produced the rejection. The one exception is
    // `SnapshotRefreshFailed`: there is no fresh `DeviceSnapshot` to compare
    // against in that case (the refresh itself failed), so no diagnostics
    // value can exist -- the third element is `None`, never a diagnostics
    // built from a stale or fabricated `current`.
    pub fn check_target(
        self,
        refreshed: SnapshotFetchOutcome,
    ) -> Result<
        VerifyReadyToOpen,
        (
            SelectedImage,
            VerifyStartError,
            Option<VerifyTargetDiagnostics>,
        ),
    > {
        let current = match refreshed {
            SnapshotFetchOutcome::Found(snapshot) => snapshot,
            SnapshotFetchOutcome::NotFound | SnapshotFetchOutcome::Error(_) => {
                return Err((self.image, VerifyStartError::SnapshotRefreshFailed, None));
            }
        };

        // Single source of truth: one `diagnose_identity_instance_for_verify`
        // call computes Identity/Instance/hazards exactly once. The
        // allow/reject decision (`core::verify_target_check_from_diagnostics`
        // -- the same shared priority order `core::check_identity_instance_for_verify`
        // itself uses) and the diagnostics value returned to the caller (on
        // every path) both come from this same value -- never a second,
        // independently recomputed one, and never a second, independently
        // implemented priority order.
        let diagnostics = diagnose_identity_instance_for_verify(&self.baseline, &current);

        if let Err(error) = verify_target_check_from_diagnostics(&diagnostics) {
            return Err((
                self.image,
                verify_start_error_from_target_check(error),
                Some(diagnostics),
            ));
        }

        Ok(VerifyReadyToOpen {
            current,
            diagnostics,
            image: self.image,
            mode: self.mode,
            cancel: self.cancel,
        })
    }
}

// The second, and final, pre-flight phase: Identity/Instance/hazard already
// passed against `current`; the caller must now call
// `linux_access::open_device(block_path(), OpenAccess::ReadOnly)` (outside this module -- see
// the module-level doc comment) and pass the result to `finalize()`. Mirrors
// `core::ReadyToOpen` exactly, one step later in the chain and for a
// read-only open instead of a write-mode one.
//
// `diagnostics` (Verify Pre-flight Diagnostics, implementation step 3+4):
// the exact `VerifyTargetDiagnostics` `check_target()` computed to decide
// this pass was clean, carried through unchanged rather than dropped now
// that the decision has been made. Private, like `current`/`image`/`mode`/
// `cancel` above it: the only way to obtain one is the value `check_target()`
// itself already verified -- there is no constructor or setter anywhere that
// would let a caller substitute an arbitrary, unverified
// `VerifyTargetDiagnostics` here (no "arbitrary diagnostics injection", per
// this step's own constraint). A `pub(crate)` read-only accessor
// (`diagnostics()`, below) was added in implementation step 5+6, once
// `main.rs`'s CLI wiring became this field's first production caller.
pub struct VerifyReadyToOpen {
    current: DeviceSnapshot,
    diagnostics: VerifyTargetDiagnostics,
    image: SelectedImage,
    mode: VerifyMode,
    cancel: CancelHandle,
}

impl VerifyReadyToOpen {
    pub fn block_path(&self) -> &str {
        &self.current.block_path
    }

    // Read-only access to the diagnostics that already decided this pass
    // was clean -- `main.rs` (Verify Pre-flight Diagnostics implementation
    // step 5+6) reads this to display a diagnostic summary before calling
    // `open_device(block_path(), OpenAccess::ReadOnly)`. Returns a borrow, not a clone: the
    // caller only needs to read the value to format it, never to own or
    // outlive `self`. `pub(crate)`, matching `VerifyTargetDiagnostics`'s own
    // visibility -- no setter or alternate constructor exists anywhere, so
    // this cannot be used to substitute an arbitrary diagnostics value.
    pub(crate) fn diagnostics(&self) -> &VerifyTargetDiagnostics {
        &self.diagnostics
    }

    // FD binding check (`core::check_fd_binding`, the exact same anti-TOCTOU
    // final check the write path already uses) against the just-opened
    // read-only FD's own kernel-reported metadata -- independent of D-Bus,
    // exactly like the write path's own final check. `opened_handle: None`
    // means the caller's `open_device(..., OpenAccess::ReadOnly)` call itself failed (there
    // is no handle to check); `fd_metadata` must already have been read (by
    // the caller, via `OpenedDeviceHandle::metadata()`) from that same
    // handle before calling this, exactly mirroring
    // `core::finalize_prepared_write`'s own contract. On any rejection, the
    // handle (if any) is simply dropped at the end of this function's scope
    // -- ordinary RAII closes the fd -- and `self.image` is returned
    // alongside the error, never silently dropped.
    pub fn finalize(
        self,
        opened_handle: Option<OpenedDeviceHandle>,
        fd_metadata: Option<&FdMetadata>,
    ) -> Result<Verifying, (SelectedImage, VerifyStartError)> {
        let handle = match opened_handle {
            Some(handle) => handle,
            None => return Err((self.image, VerifyStartError::OpenDeviceFailed)),
        };

        match check_fd_binding(&self.current, fd_metadata) {
            FdBindingCheck::Match => {}
            FdBindingCheck::Mismatch => {
                return Err((self.image, VerifyStartError::FdBindingMismatch))
            }
            FdBindingCheck::InsufficientInformation => {
                return Err((self.image, VerifyStartError::FdBindingInsufficient));
            }
        }

        Ok(Verifying {
            handle,
            image: self.image,
            mode: self.mode,
            cancel: self.cancel,
        })
    }
}

// Every condition needed to safely start reading the target for Verify has
// now held: fresh Identity, fresh Instance, no hard hazard, and the
// just-opened read-only FD is proven bound to the exact device node just
// re-verified. `handle` is a brand-new, independent, read-only
// `OpenedDeviceHandle` -- never the write-mode handle `begin_verify()`
// already dropped (see the module-level doc comment for "Approach B").
// Deliberately minimal, like `Writing<R>` before it: no
// `ImageSourceAccess`/range pre-computation stored here -- `run()` (below)
// computes what it needs (`quick_verify_ranges()` for `Quick`) from `image`
// itself, so there is no risk of a stored, stale duplicate of information
// `image`/`mode` already carry.
pub struct Verifying {
    handle: OpenedDeviceHandle,
    image: SelectedImage,
    mode: VerifyMode,
    cancel: CancelHandle,
}

impl SyncSucceeded {
    // The one and only way to begin Verify. Takes `self` by value (consumed,
    // like every other stage transition in this module) plus the exact
    // `SelectedImage` `AuthorizedExecution::bind()` originally bound this
    // write to -- `SyncSucceeded` itself does not carry a `SelectedImage`
    // (see `WritingExecution::write()`'s own doc comment for why: it is
    // returned to the caller alongside `WriteAttemptOutcome` well before
    // `Syncing`/`SyncSucceeded` exist, and the caller is the one expected to
    // hold onto it across the sync stage, exactly as `main.rs`'s own
    // `run_write_test` PoC already does with its local `selected_image`
    // variable) -- so it must be supplied here.
    //
    // Retires the write-mode capability unconditionally, for every
    // `VerifyMode` including `None`: `self.active` is dropped (after reading
    // `baseline()` out of it, for `Quick`/`Full`) before this method returns
    // anything at all. No FD is ever duplicated or reused across the
    // write/sync stage and the verify stage -- see the module-level doc
    // comment's "Approach B" note.
    pub fn begin_verify(self, image: SelectedImage, cancel: CancelHandle) -> VerifyStart {
        let SyncSucceeded {
            active,
            verify_mode,
            ..
        } = self;

        match verify_mode {
            VerifyMode::None => {
                drop(active);

                VerifyStart::Skipped(
                    image,
                    VerifySucceeded {
                        mode: VerifyMode::None,
                        verified_bytes: 0,
                        skipped: true,
                    },
                )
            }
            mode @ (VerifyMode::Quick | VerifyMode::Full) => {
                let baseline = active.baseline().clone();
                drop(active);

                VerifyStart::Pending(PendingVerify {
                    baseline,
                    image,
                    mode,
                    cancel,
                })
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct VerifyProgress {
    pub verified_bytes: u64,
    pub total_bytes: u64,
    pub mode: VerifyMode,
}

// `VerifyMode::None`: `mode == VerifyMode::None`, `verified_bytes == 0`,
// `skipped == true`. `Quick`/`Full` success: `skipped == false`,
// `verified_bytes` equal to the total this mode actually promised to check
// (the full `image.logical_size()` for `Full`; the merged sample-range total
// for `Quick` -- see `quick_verify_ranges()` -- never `image.logical_size()`
// itself for `Quick`, so a caller can never mistake a Quick pass for having
// checked the whole image).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifySucceeded {
    pub mode: VerifyMode,
    pub verified_bytes: u64,
    pub skipped: bool,
}

// Why a Quick/Full Verify attempt failed, once byte reading had actually
// started (contrast `VerifyStartError`, which covers everything that can go
// wrong *before* any byte is read). `SourceUnexpectedEof`/
// `TargetUnexpectedEof` are kept distinct from each other (rather than one
// generic `UnexpectedEof`) because which side ran out is genuinely different
// diagnostic information -- a short source usually means the same-inode
// external-modification/shrink limitation `image_source.rs` already
// documents, while a short target usually means the device shrank or was
// otherwise not what it claimed to be -- but no further than that: this is
// not split per-hazard the way it might be, matching `VerifyTargetCheckError
// ::UnsafeTargetState`'s own precedent of not over-fragmenting a pre-check
// error type. `Mismatch` keeps only the *first* mismatching byte -- see its
// own field docs.
#[derive(Debug)]
pub enum VerifyFailureReason {
    SourceReadError(io::Error),
    TargetReadError(io::Error),
    SourceUnexpectedEof,
    TargetUnexpectedEof,
    // The first byte at which source and target disagreed. Only the first
    // is ever recorded -- collecting every mismatch would cost unbounded
    // memory for a large image and provide no more diagnostic value than
    // "verification failed, and here is where it first went wrong", which
    // is exactly the design phase's stated goal.
    Mismatch {
        offset: u64,
        expected: u8,
        actual: u8,
    },
    // `VerifyMode::Quick` was requested against a `SelectedImage` whose
    // `access()` is not `ImageSourceAccess::RandomAccess` (see
    // `run_quick_verify()`). Deliberately a hard failure, not a silent
    // fallback to sequential-read-and-discard or to `Full` -- see the design
    // phase's reasoning: a silent fallback would either misrepresent Quick's
    // actual performance characteristics, or silently do more work than the
    // user asked for.
    UnsupportedAccess,
    // The source image was no longer in the state it was selected in, at
    // one of Verify's two source checkpoints (see `Verifying::run`): before
    // any byte was compared (`verified_bytes == 0`, no progress reported),
    // or after every comparison matched (`verified_bytes` is how much was
    // compared). In the second case the match is *not* accepted: the
    // source may have changed while it was being compared. Like every Verify
    // outcome, this is only reachable after write and sync succeeded, so
    // the target has been modified. Carries the metadata comparison without
    // guessing a cause.
    SourceChanged(SourceChanged),
}

#[derive(Debug)]
pub struct VerifyFailed {
    pub mode: VerifyMode,
    pub verified_bytes: u64,
    pub reason: VerifyFailureReason,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifyCancelled {
    pub mode: VerifyMode,
    pub verified_bytes: u64,
}

#[derive(Debug)]
pub enum VerifyOutcome {
    Succeeded(VerifySucceeded),
    Failed(VerifyFailed),
    Cancelled(VerifyCancelled),
}

impl Verifying {
    // Consumes this `Verifying` to run the one Verify attempt it was set up
    // for -- `VerifyMode::Quick` or `Full` only; `VerifyMode::None` never
    // reaches this type at all (see `SyncSucceeded::begin_verify()`).
    // Returns `self.image` back alongside the outcome, exactly like
    // `WritingExecution::write()` returns `SelectedImage` alongside
    // `WriteAttemptOutcome` -- on every path (`Succeeded`/`Failed`/
    // `Cancelled`), never only on success, so a caller never loses the image
    // it supplied regardless of how Verify ends.
    //
    // CACHE HONESTY CAVEAT (carried over from the design phase, see
    // reports/latest.md): this reads the target via a freshly opened
    // read-only FD, after `sync_all()` already succeeded during the Sync
    // stage. Linux's page cache for a block device is keyed to the device
    // itself, not to any one file descriptor, so this fresh FD does not, by
    // itself, guarantee the bytes returned bypass all caching and come from
    // physical media -- no `O_DIRECT`/`BLKFLSBUF` is used here, deliberately
    // (see the module-level doc comment's "NOT implemented" list). This
    // Verify confirms the OS reports back the same bytes that were written,
    // via the same kernel/page-cache path an ordinary read would use --
    // exactly the same class of evidence this project's own manual
    // `sudo head -c <size> /dev/sdX | sha256sum` real-device tests already
    // relied on, now automated and `sudo`-free.
    //
    // Source checkpoints: the source is revalidated (one metadata read of
    // the already-open file) immediately before Verify starts -- after the
    // whole target pre-flight, so a change during it, including the
    // test-only pause, is caught -- and again after a successful comparison,
    // before that success is returned. A change before the start means no
    // byte is read and no progress is reported; a change after it means the
    // matching comparison is not accepted. Both become `Failed` with
    // `VerifyFailureReason::SourceChanged`. Only a success is re-checked at
    // the end: a Verify failure or cancellation is returned as it is, never
    // replaced by `SourceChanged`.
    pub fn run(self, on_progress: impl FnMut(VerifyProgress)) -> (SelectedImage, VerifyOutcome) {
        let Verifying {
            handle,
            image,
            mode,
            cancel,
        } = self;

        if let Err(changed) = image.revalidate_identity() {
            let outcome = VerifyOutcome::Failed(VerifyFailed {
                mode,
                verified_bytes: 0,
                reason: VerifyFailureReason::SourceChanged(changed),
            });
            return (image, outcome);
        }

        let outcome = match mode {
            VerifyMode::Full => run_full_verify(&handle, &image, &cancel, on_progress),
            VerifyMode::Quick => run_quick_verify(&handle, &image, &cancel, on_progress),
            VerifyMode::None => unreachable!(
                "VerifyMode::None never reaches Verifying -- see SyncSucceeded::begin_verify()"
            ),
        };

        let outcome = match outcome {
            VerifyOutcome::Succeeded(succeeded) => match image.revalidate_identity() {
                Ok(()) => VerifyOutcome::Succeeded(succeeded),
                Err(changed) => VerifyOutcome::Failed(VerifyFailed {
                    mode: succeeded.mode,
                    verified_bytes: succeeded.verified_bytes,
                    reason: VerifyFailureReason::SourceChanged(changed),
                }),
            },
            other => other,
        };

        (image, outcome)
    }
}

// Reads until `buf` is full or the source is exhausted, retrying on
// `Interrupted`. Deliberately re-implemented here rather than reused from
// `writer.rs`: `writer::read_fully` is a private helper of that module (this
// step's change scope does not extend to `writer.rs`), but the contract
// needed on Verify's source side -- "a short read that is not an error means
// true EOF, not 'try again'" -- is identical, so this is a small, independent
// equivalent rather than a divergent one.
fn read_fully<R: Read + ?Sized>(reader: &mut R, buf: &mut [u8]) -> io::Result<usize> {
    let mut total = 0;

    while total < buf.len() {
        match reader.read(&mut buf[total..]) {
            Ok(0) => break,
            Ok(n) => total += n,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }

    Ok(total)
}

// The `read_at`-based counterpart to `read_fully` above, for
// `ReadTarget::read_at`'s positional, no-shared-cursor interface: retries a
// short read by advancing `offset` (never touching any shared file position,
// since `read_at` has none) until `buf` is full or the target reports true
// EOF (`Ok(0)`).
fn read_at_fully(target: &ReadTarget<'_>, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
    let mut filled = 0;

    while filled < buf.len() {
        match target.read_at(offset + filled as u64, &mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }

    Ok(filled)
}

// The offset of the first byte at which `a` and `b` differ, within the
// shared length of the two slices (both are always called here with equal
// lengths -- see `run_full_verify`/`run_quick_verify`). `None` means the two
// slices are identical.
fn first_mismatch(a: &[u8], b: &[u8]) -> Option<usize> {
    a.iter().zip(b.iter()).position(|(x, y)| x != y)
}

// Full Verify: reads `image.logical_size()` bytes from a *second*,
// independent `open_reader()` call on `image` (never rewinding the
// write-time reader `Writing::write()` already consumed -- see
// `image_source.rs`'s own doc comment for why `SelectedImage` supports this)
// and from `handle`'s read-only target, in lockstep, `writer::
// DEFAULT_CHUNK_SIZE` (1 MiB, the same constant the write path already uses)
// bytes at a time, comparing each chunk and stopping at the very first
// mismatching byte. Checks `cancel` once before any I/O and once per chunk
// thereafter -- no chunk is read after a cancellation request is observed.
fn run_full_verify(
    handle: &OpenedDeviceHandle,
    image: &SelectedImage,
    cancel: &CancelHandle,
    mut on_progress: impl FnMut(VerifyProgress),
) -> VerifyOutcome {
    if cancel.is_requested() {
        return VerifyOutcome::Cancelled(VerifyCancelled {
            mode: VerifyMode::Full,
            verified_bytes: 0,
        });
    }

    let image_size = image.logical_size();

    let mut source = match image.open_reader() {
        Ok(reader) => reader,
        Err(error) => {
            return VerifyOutcome::Failed(VerifyFailed {
                mode: VerifyMode::Full,
                verified_bytes: 0,
                reason: VerifyFailureReason::SourceReadError(error),
            });
        }
    };

    let target = handle.reader_target();
    let chunk_size = writer::DEFAULT_CHUNK_SIZE;
    let mut source_buf = vec![0u8; chunk_size];
    let mut target_buf = vec![0u8; chunk_size];
    let mut offset: u64 = 0;

    while offset < image_size {
        if cancel.is_requested() {
            return VerifyOutcome::Cancelled(VerifyCancelled {
                mode: VerifyMode::Full,
                verified_bytes: offset,
            });
        }

        let remaining = image_size - offset;
        let want = remaining.min(chunk_size as u64) as usize;

        let n_src = match read_fully(&mut *source, &mut source_buf[..want]) {
            Ok(n) => n,
            Err(error) => {
                return VerifyOutcome::Failed(VerifyFailed {
                    mode: VerifyMode::Full,
                    verified_bytes: offset,
                    reason: VerifyFailureReason::SourceReadError(error),
                });
            }
        };

        if n_src < want {
            return VerifyOutcome::Failed(VerifyFailed {
                mode: VerifyMode::Full,
                verified_bytes: offset,
                reason: VerifyFailureReason::SourceUnexpectedEof,
            });
        }

        let n_tgt = match read_at_fully(&target, offset, &mut target_buf[..want]) {
            Ok(n) => n,
            Err(error) => {
                return VerifyOutcome::Failed(VerifyFailed {
                    mode: VerifyMode::Full,
                    verified_bytes: offset,
                    reason: VerifyFailureReason::TargetReadError(error),
                });
            }
        };

        if n_tgt < want {
            return VerifyOutcome::Failed(VerifyFailed {
                mode: VerifyMode::Full,
                verified_bytes: offset,
                reason: VerifyFailureReason::TargetUnexpectedEof,
            });
        }

        if let Some(index) = first_mismatch(&source_buf[..want], &target_buf[..want]) {
            return VerifyOutcome::Failed(VerifyFailed {
                mode: VerifyMode::Full,
                verified_bytes: offset,
                reason: VerifyFailureReason::Mismatch {
                    offset: offset + index as u64,
                    expected: source_buf[index],
                    actual: target_buf[index],
                },
            });
        }

        offset += want as u64;

        on_progress(VerifyProgress {
            verified_bytes: offset,
            total_bytes: image_size,
            mode: VerifyMode::Full,
        });
    }

    VerifyOutcome::Succeeded(VerifySucceeded {
        mode: VerifyMode::Full,
        verified_bytes: offset,
        skipped: false,
    })
}

// Computes the byte ranges Quick Verify samples for an image of
// `image_size` bytes: first `QUICK_VERIFY_WINDOW_SIZE`, middle
// `QUICK_VERIFY_WINDOW_SIZE`, last `QUICK_VERIFY_WINDOW_SIZE`, each clamped
// to `image_size`, then sorted and merged so overlapping or adjacent windows
// collapse into one. For `image_size <= 3 * QUICK_VERIFY_WINDOW_SIZE` (or
// smaller), the three windows overlap enough that this naturally collapses
// to a single `(0, image_size)` range -- Quick Verify's actual coverage
// becomes identical to Full's for a small enough image, exactly as the
// design phase specified, with no special-cased "small image" branch needed
// here: the merge logic alone produces that result. Pure, no I/O, no
// allocation beyond the small `Vec` returned -- trivially unit-testable on
// its own (see this module's tests).
fn quick_verify_ranges(image_size: u64) -> Vec<(u64, u64)> {
    if image_size == 0 {
        return Vec::new();
    }

    let window = QUICK_VERIFY_WINDOW_SIZE.min(image_size);

    let first = (0u64, window);
    let last = (image_size - window, window);
    let middle_start = (image_size / 2)
        .saturating_sub(window / 2)
        .min(image_size - window);
    let middle = (middle_start, window);

    let mut ranges = [first, middle, last];
    ranges.sort_by_key(|&(offset, _)| offset);

    let mut merged: Vec<(u64, u64)> = Vec::new();
    for (offset, len) in ranges {
        let end = offset + len;

        if let Some(last_range) = merged.last_mut() {
            let (last_offset, last_len) = *last_range;
            let last_end = last_offset + last_len;

            if offset <= last_end {
                *last_range = (last_offset, end.max(last_end) - last_offset);
                continue;
            }
        }

        merged.push((offset, len));
    }

    merged
}

// Quick Verify: refuses to start against a `SelectedImage` whose `access()`
// is not `ImageSourceAccess::RandomAccess` (see `VerifyFailureReason::
// UnsupportedAccess`'s own doc comment for why this is a hard failure, not a
// silent fallback) -- checked first, before any I/O. Otherwise, reads each
// merged sample range (`quick_verify_ranges()`) via `SelectedImage::
// read_at()` on the source side and `ReadTarget::read_at()` on the target
// side, `writer::DEFAULT_CHUNK_SIZE`-sized pieces at a time within each range
// (never the whole 4 MiB window as one buffer, to keep memory use the same
// as Full Verify's), comparing as it goes and stopping at the first
// mismatch. `total_bytes` for progress is the sum of the merged ranges'
// lengths, never `image.logical_size()` -- see `VerifyProgress`'s own doc
// comment.
fn run_quick_verify(
    handle: &OpenedDeviceHandle,
    image: &SelectedImage,
    cancel: &CancelHandle,
    mut on_progress: impl FnMut(VerifyProgress),
) -> VerifyOutcome {
    if image.access() != ImageSourceAccess::RandomAccess {
        return VerifyOutcome::Failed(VerifyFailed {
            mode: VerifyMode::Quick,
            verified_bytes: 0,
            reason: VerifyFailureReason::UnsupportedAccess,
        });
    }

    if cancel.is_requested() {
        return VerifyOutcome::Cancelled(VerifyCancelled {
            mode: VerifyMode::Quick,
            verified_bytes: 0,
        });
    }

    let ranges = quick_verify_ranges(image.logical_size());
    let total_bytes: u64 = ranges.iter().map(|&(_, len)| len).sum();

    let target = handle.reader_target();
    let chunk_size = writer::DEFAULT_CHUNK_SIZE;
    let mut source_buf = vec![0u8; chunk_size];
    let mut target_buf = vec![0u8; chunk_size];
    let mut verified_bytes: u64 = 0;

    for (range_offset, range_len) in ranges {
        let mut inner_offset: u64 = 0;

        while inner_offset < range_len {
            if cancel.is_requested() {
                return VerifyOutcome::Cancelled(VerifyCancelled {
                    mode: VerifyMode::Quick,
                    verified_bytes,
                });
            }

            let remaining_in_range = range_len - inner_offset;
            let want = remaining_in_range.min(chunk_size as u64) as usize;
            let absolute_offset = range_offset + inner_offset;

            let n_src = match image.read_at(absolute_offset, &mut source_buf[..want]) {
                Ok(n) => n,
                Err(error) => {
                    return VerifyOutcome::Failed(VerifyFailed {
                        mode: VerifyMode::Quick,
                        verified_bytes,
                        reason: VerifyFailureReason::SourceReadError(error),
                    });
                }
            };

            if n_src < want {
                return VerifyOutcome::Failed(VerifyFailed {
                    mode: VerifyMode::Quick,
                    verified_bytes,
                    reason: VerifyFailureReason::SourceUnexpectedEof,
                });
            }

            let n_tgt = match read_at_fully(&target, absolute_offset, &mut target_buf[..want]) {
                Ok(n) => n,
                Err(error) => {
                    return VerifyOutcome::Failed(VerifyFailed {
                        mode: VerifyMode::Quick,
                        verified_bytes,
                        reason: VerifyFailureReason::TargetReadError(error),
                    });
                }
            };

            if n_tgt < want {
                return VerifyOutcome::Failed(VerifyFailed {
                    mode: VerifyMode::Quick,
                    verified_bytes,
                    reason: VerifyFailureReason::TargetUnexpectedEof,
                });
            }

            if let Some(index) = first_mismatch(&source_buf[..want], &target_buf[..want]) {
                return VerifyOutcome::Failed(VerifyFailed {
                    mode: VerifyMode::Quick,
                    verified_bytes,
                    reason: VerifyFailureReason::Mismatch {
                        offset: absolute_offset + index as u64,
                        expected: source_buf[index],
                        actual: target_buf[index],
                    },
                });
            }

            inner_offset += want as u64;
            verified_bytes += want as u64;

            on_progress(VerifyProgress {
                verified_bytes,
                total_bytes,
                mode: VerifyMode::Quick,
            });
        }
    }

    VerifyOutcome::Succeeded(VerifySucceeded {
        mode: VerifyMode::Quick,
        verified_bytes,
        skipped: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::{DeviceSnapshot, SnapshotFetchOutcome};
    use crate::execution::core::{self, ConfirmationToken, HardHazardReason};
    use crate::execution::linux_access::{FdMetadata, OpenedDeviceHandle};
    use crate::identity::{IdentityComparison, InstanceComparison};
    use crate::image_source::{FileImageSource, ImageSource, ImageSourceAccess};
    use std::io::Cursor;

    fn base_device(size: u64) -> DeviceSnapshot {
        DeviceSnapshot {
            device: "/dev/sdx".to_string(),
            block_path: "/org/freedesktop/UDisks2/block_devices/sdx".to_string(),
            drive_path: "/org/freedesktop/UDisks2/drives/Test_Model_TEST-SERIAL-0001".to_string(),
            major: 8,
            minor: 0,
            diskseq: Some(12),
            size,
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

    fn fd_metadata_matching(snapshot: &DeviceSnapshot) -> FdMetadata {
        FdMetadata {
            major: snapshot.major,
            minor: snapshot.minor,
            size: Some(snapshot.size),
            diskseq: snapshot.diskseq,
            proc_fd_target: None,
        }
    }

    // Drives the full production Gate sequence -- select -> WriteIntent ->
    // ConfirmationToken -> prepare_for_open -> (simulated OpenDevice via the
    // test-only `from_file_for_test`) -> finalize_prepared_write -> begin()
    // -- against a plain, throwaway regular file, never a block device,
    // never real D-Bus/OpenDevice. Returns the resulting `AuthorizedWrite`
    // (bundling the `ActiveWrite`, `WritePlan`, and `VerifyMode` the Gate
    // verified) -- the exact value `start_inner()` (via `AuthorizedExecution::begin_write()`) now requires.
    // `persistent` selects whether the temp file's directory entry survives
    // (needed only by tests that reopen it by path afterward to check
    // written content).
    fn gate_pass_active_write(
        tag: &str,
        image_size: u64,
        target_size: u64,
        persistent: bool,
    ) -> (Option<std::path::PathBuf>, AuthorizedWrite) {
        let image = core::ImageSelection::new(image_size);
        gate_pass_active_write_for_image(tag, image, target_size, persistent)
    }

    // Like `gate_pass_active_write`, but threads a caller-supplied
    // `ImageSelection` (typically obtained via an existing `SelectedImage`'s
    // `.selection()`) through the same Gate sequence instead of minting a
    // fresh one internally. Needed so `AuthorizedExecution::bind()` tests
    // can produce an `AuthorizedWrite` whose confirmed `image_generation` is
    // provably the *same* generation a specific `SelectedImage` already
    // holds (for a successful bind), or provably a *different* one (for a
    // mismatch).
    fn gate_pass_active_write_for_image(
        tag: &str,
        image: core::ImageSelection,
        target_size: u64,
        persistent: bool,
    ) -> (Option<std::path::PathBuf>, AuthorizedWrite) {
        use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};

        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, AtomicOrdering::Relaxed);

        let snapshot = base_device(target_size);
        let state = core::select(snapshot.clone()).unwrap();
        let verify_mode = VerifyMode::None;
        let intent = core::write_intent_for_test(
            &snapshot,
            image,
            core::selection_generation_of(&state),
            verify_mode,
        );
        let confirmation = ConfirmationToken::confirm(intent);

        let ready = core::prepare_for_open(
            &state,
            SnapshotFetchOutcome::Found(snapshot.clone()),
            image,
            verify_mode,
            Some(&confirmation),
        )
        .expect("prepare_for_open should succeed for a freshly matching snapshot/confirmation");

        let metadata = fd_metadata_matching(&snapshot);

        let path = std::env::temp_dir().join(format!(
            "linux-usb-writer-write-job-test-{tag}-{}-{id}.tmp",
            std::process::id()
        ));
        let file = std::fs::File::create(&path).expect("create temp file for write_job test");
        if !persistent {
            std::fs::remove_file(&path).expect("unlink temp file for write_job test");
        }
        let handle = OpenedDeviceHandle::from_file_for_test(file);

        let prepared = core::finalize_prepared_write(ready, Some(handle), Some(&metadata))
            .expect("finalize_prepared_write should succeed with matching FD metadata");

        let returned_path = if persistent { Some(path) } else { None };
        (returned_path, prepared.begin())
    }

    // Builds on `gate_pass_active_write` by also running the write attempt
    // to completion and asserting it succeeds. The Sync tests below only
    // care about what happens *after* a write has already succeeded, so
    // they start from here rather than repeating the full Gate + write
    // setup each time.
    fn gate_pass_write_succeeded(
        tag: &str,
        image_size: u64,
        target_size: u64,
        persistent: bool,
    ) -> (Option<std::path::PathBuf>, WriteSucceeded) {
        let (path, authorized) = gate_pass_active_write(tag, image_size, target_size, persistent);
        let data = vec![6u8; image_size as usize];
        let writing = start_inner(authorized, Cursor::new(data), CancelHandle::new());

        let outcome = writing.write(|_| {});
        let succeeded = match outcome {
            WriteAttemptOutcome::Succeeded(s) => s,
            other => panic!("expected Succeeded while setting up a sync test, got {other:?}"),
        };

        (path, succeeded)
    }

    // A. `start_inner()` consumes `active` by value: this compiles only because
    // `active` moves into `start_inner`. There is no runtime assertion that could
    // prove "the original ActiveWrite cannot be reused" beyond the fact that
    // this test never refers to it again after this line -- the Rust
    // ownership/borrow checker is the actual enforcement mechanism.
    #[test]
    fn start_consumes_active_write_into_writing() {
        let (_path, authorized) = gate_pass_active_write("start", 10, 20, false);
        let source = Cursor::new(vec![0u8; 10]);
        let cancel = CancelHandle::new();

        let _writing: Writing<Cursor<Vec<u8>>> = start_inner(authorized, source, cancel);
        // `authorized` is not, and cannot be, referred to again here.
    }

    // B/C. A successful write produces WriteSucceeded with bytes_written ==
    // image_size, target_may_be_modified == true (rule E), and the regular
    // file's content matching the source exactly.
    #[test]
    fn write_success_produces_write_succeeded_with_matching_content() {
        const SOURCE: &[u8] = b"write_job integration test: known small source";
        let image_size = SOURCE.len() as u64;
        let target_size = image_size + 100;

        let (path, authorized) = gate_pass_active_write("success", image_size, target_size, true);
        let path = path.expect("persistent temp file path");

        let writing = start_inner(
            authorized,
            Cursor::new(SOURCE.to_vec()),
            CancelHandle::new(),
        );
        let outcome = writing.write(|_| {});

        let succeeded = match outcome {
            WriteAttemptOutcome::Succeeded(s) => s,
            other => panic!("expected Succeeded, got {other:?}"),
        };

        assert_eq!(succeeded.bytes_written, image_size);
        assert_eq!(succeeded.image_size, image_size);
        assert!(succeeded.target_may_be_modified);
        assert!(succeeded.retry_requires_fresh_gate);

        let on_disk = std::fs::read(&path).expect("reopen temp file for read-back");
        let _ = std::fs::remove_file(&path);
        assert_eq!(on_disk, SOURCE);
    }

    // D. Requesting cancellation before any chunk is attempted yields
    // Cancelled with reason == UserRequested and retry_requires_fresh_gate ==
    // true. bytes_written == 0 here is the one case where
    // target_may_be_modified can honestly be false (rule A): no
    // `target.write_all()` call was ever made for this attempt.
    #[test]
    fn cancel_before_any_chunk_is_cancelled_with_user_requested_reason() {
        let image_size = 100u64;
        let target_size = 200u64;
        let (_path, authorized) =
            gate_pass_active_write("cancel-immediate", image_size, target_size, false);

        let cancel = CancelHandle::new();
        cancel.request_cancel(CancelReason::UserRequested);

        let writing = start_inner(
            authorized,
            Cursor::new(vec![1u8; image_size as usize]),
            cancel,
        );
        let outcome = writing.write(|_| {});

        let cancelled = match outcome {
            WriteAttemptOutcome::Cancelled(c) => c,
            other => panic!("expected Cancelled, got {other:?}"),
        };

        assert_eq!(cancelled.bytes_written, 0);
        assert_eq!(cancelled.reason, CancelReason::UserRequested);
        assert!(!cancelled.target_may_be_modified);
        assert!(cancelled.retry_requires_fresh_gate);
    }

    // E. Cancelling partway through a multi-chunk write leaves
    // 0 < bytes_written < image_size and target_may_be_modified == true
    // (rule B): at least one target.write_all() call has already happened.
    #[test]
    fn cancel_partway_through_multiple_chunks_reports_partial_progress() {
        let image_size = 3 * writer::DEFAULT_CHUNK_SIZE as u64;
        let target_size = image_size;
        let (_path, authorized) =
            gate_pass_active_write("cancel-partial", image_size, target_size, false);

        let cancel = CancelHandle::new();
        let writing = start_inner(
            authorized,
            Cursor::new(vec![2u8; image_size as usize]),
            cancel.clone(),
        );

        let mut chunks_seen = 0;
        let outcome = writing.write(|_progress| {
            chunks_seen += 1;
            if chunks_seen == 1 {
                cancel.request_cancel(CancelReason::UserRequested);
            }
        });

        let cancelled = match outcome {
            WriteAttemptOutcome::Cancelled(c) => c,
            other => panic!("expected Cancelled, got {other:?}"),
        };

        assert!(cancelled.bytes_written > 0);
        assert!(cancelled.bytes_written < image_size);
        assert!(cancelled.target_may_be_modified);
    }

    // F. A source shorter than the Gate-approved image_size becomes Failed
    // with cause SourceTooShort, bytes_written matching the source's actual
    // length, and target_may_be_modified == true (rule D, since bytes_written
    // > 0 here).
    #[test]
    fn source_too_short_is_failed_with_matching_bytes_written() {
        let image_size = 1000u64;
        let target_size = 2000u64;
        let (_path, authorized) =
            gate_pass_active_write("source-short", image_size, target_size, false);

        let short_source = vec![3u8; 400];
        let writing = start_inner(authorized, Cursor::new(short_source), CancelHandle::new());
        let outcome = writing.write(|_| {});

        let failed = match outcome {
            WriteAttemptOutcome::Failed(f) => f,
            other => panic!("expected Failed, got {other:?}"),
        };

        assert!(matches!(
            failed.cause,
            WriteJobFailureCause::Write(WriteError::SourceTooShort { bytes_written: 400 })
        ));
        assert_eq!(failed.bytes_written, 400);
        assert!(failed.target_may_be_modified);
        assert_eq!(failed.stage, WriteStage::Writing);
        assert!(failed.retry_requires_fresh_gate);
    }

    // G. A genuine write() syscall failure (EBADF, from writing to an fd
    // opened read-only) becomes Failed with cause TargetWrite. This is also
    // the safety-side-bias case from the design brief: WriteError::TargetWrite
    // carries no byte count, so bytes_written is reported as 0 here, yet
    // target_may_be_modified must still be true -- a "0 bytes written"
    // report must never be read as proof the target is untouched (rule C).
    #[test]
    fn target_write_error_is_failed_and_conservatively_flagged_as_modified_even_with_zero_bytes_written(
    ) {
        let image_size = 64u64;
        let target_size = 128u64;

        let snapshot = base_device(target_size);
        let state = core::select(snapshot.clone()).unwrap();
        let image = core::ImageSelection::new(image_size);
        let verify_mode = VerifyMode::None;
        let intent = core::write_intent_for_test(
            &snapshot,
            image,
            core::selection_generation_of(&state),
            verify_mode,
        );
        let confirmation = ConfirmationToken::confirm(intent);
        let ready = core::prepare_for_open(
            &state,
            SnapshotFetchOutcome::Found(snapshot.clone()),
            image,
            verify_mode,
            Some(&confirmation),
        )
        .unwrap();
        let metadata = fd_metadata_matching(&snapshot);

        let path = std::env::temp_dir().join(format!(
            "linux-usb-writer-write-job-test-target-write-error-{}.tmp",
            std::process::id()
        ));
        std::fs::File::create(&path).expect("create temp file for read-only test");
        let read_only_file = std::fs::OpenOptions::new()
            .read(true)
            .open(&path)
            .expect("reopen temp file read-only");
        let handle = OpenedDeviceHandle::from_file_for_test(read_only_file);

        let prepared = core::finalize_prepared_write(ready, Some(handle), Some(&metadata)).unwrap();
        let authorized = prepared.begin();

        let source = Cursor::new(vec![7u8; image_size as usize]);
        let writing = start_inner(authorized, source, CancelHandle::new());
        let outcome = writing.write(|_| {});

        let _ = std::fs::remove_file(&path);

        let failed = match outcome {
            WriteAttemptOutcome::Failed(f) => f,
            other => panic!("expected Failed, got {other:?}"),
        };

        assert!(matches!(
            failed.cause,
            WriteJobFailureCause::Write(WriteError::TargetWrite(_))
        ));
        assert_eq!(failed.bytes_written, 0);
        assert!(
            failed.target_may_be_modified,
            "TargetWrite errors must be treated as possibly-modified even when bytes_written is reported as 0"
        );
    }

    // H. The progress callback is relayed unchanged from writer::write():
    // monotonically increasing and ending exactly at image_size.
    #[test]
    fn progress_is_monotonic_and_ends_at_image_size() {
        let image_size = 2 * writer::DEFAULT_CHUNK_SIZE as u64;
        let target_size = image_size;
        let (_path, authorized) =
            gate_pass_active_write("progress", image_size, target_size, false);
        let data = vec![5u8; image_size as usize];

        let writing = start_inner(authorized, Cursor::new(data), CancelHandle::new());

        let mut progress_log = Vec::new();
        let outcome = writing.write(|progress| progress_log.push(progress.bytes_written));

        assert!(matches!(outcome, WriteAttemptOutcome::Succeeded(_)));
        assert!(!progress_log.is_empty());
        assert!(progress_log.windows(2).all(|pair| pair[0] < pair[1]));
        assert_eq!(*progress_log.last().unwrap(), image_size);
    }

    // I/J. Neither a consumed `Writing` nor any of the three terminal types
    // (`WriteSucceeded`/`Failed`/`Cancelled`) has a method that advances
    // state, retries the same attempt, or hands back a reusable
    // `ActiveWrite`/`Writing`. This is a structural fact verified by code
    // review/grep (no such methods exist anywhere in this file), not a
    // runtime test -- there is no way to write a `#[test]` that proves an
    // API's absence any more directly than the API simply not being there.

    // Sync A. `begin_sync()` consumes a `WriteSucceeded` by value, producing
    // a `Syncing`. Sync B (the same `WriteSucceeded` cannot be used to call
    // `begin_sync()` a second time) is, like Writing test A, a compile-time
    // ownership fact rather than something a runtime assertion could prove
    // any more directly than this test simply compiling.
    #[test]
    fn begin_sync_consumes_write_succeeded_into_syncing() {
        let (_path, succeeded) = gate_pass_write_succeeded("sync-begin", 10, 20, false);

        let _syncing: Syncing = succeeded.begin_sync();
        // `succeeded` is not, and cannot be, referred to again here.
    }

    // Sync C/D. A successful sync produces SyncSucceeded carrying forward
    // the exact bytes_written/image_size the preceding WriteSucceeded
    // reported, with target_may_be_modified and retry_requires_fresh_gate
    // both true. Runs a real `File::sync_all()` against a plain regular temp
    // file -- deterministic and fast, no real block device involved.
    #[test]
    fn sync_success_produces_sync_succeeded_with_matching_fields() {
        let image_size = 4096u64;
        let target_size = image_size;
        let (_path, succeeded) =
            gate_pass_write_succeeded("sync-success", image_size, target_size, false);
        let bytes_written = succeeded.bytes_written;

        let syncing = succeeded.begin_sync();
        let outcome = syncing.sync();

        let synced = match outcome {
            SyncAttemptOutcome::Succeeded(s) => s,
            other => panic!("expected Succeeded, got {other:?}"),
        };

        assert_eq!(synced.bytes_written, bytes_written);
        assert_eq!(synced.image_size, image_size);
        assert!(synced.target_may_be_modified);
        assert!(synced.retry_requires_fresh_gate);
    }

    // Sync E. The pure `io::Error -> Failed` conversion, tested directly
    // with a synthetic error rather than trying to force a real `fsync()`
    // failure against a regular file (impractical to do deterministically,
    // and not worth a trait/mock abstraction just for this).
    #[test]
    fn sync_error_to_failed_reports_syncing_stage_and_conservative_modification_flag() {
        let error = io::Error::new(io::ErrorKind::Other, "simulated sync failure");
        let failed = sync_error_to_failed(4096, 4096, error);

        assert_eq!(failed.stage, WriteStage::Syncing);
        assert_eq!(failed.image_size, 4096);
        assert_eq!(failed.bytes_written, 4096);
        assert!(failed.target_may_be_modified);
        assert!(failed.retry_requires_fresh_gate);
        assert!(matches!(failed.cause, WriteJobFailureCause::Sync(_)));
    }

    // Sync F/G. `Syncing::sync(self)` consumes `self`, so the same `Syncing`
    // cannot attempt a second sync call, and neither `SyncSucceeded` nor
    // `Failed` has any method that re-syncs or hands back a reusable
    // `ActiveWrite`/`Syncing`. Structural facts verified by code review/grep,
    // like Sync B above -- not runtime-testable any more directly than the
    // API simply not existing.

    // Sync H/I/J. The fd stays open (verified via the fd-number-reuse-proof
    // helpers in `linux_access.rs`, not a naive existence check) all the way
    // through WriteSucceeded -> Syncing -> SyncSucceeded, and is closed only
    // once SyncSucceeded itself is dropped.
    #[test]
    fn sync_succeeded_holds_moved_fd_until_dropped() {
        let image_size = 4096u64;
        let target_size = image_size;

        let snapshot = base_device(target_size);
        let state = core::select(snapshot.clone()).unwrap();
        let image = core::ImageSelection::new(image_size);
        let verify_mode = VerifyMode::None;
        let intent = core::write_intent_for_test(
            &snapshot,
            image,
            core::selection_generation_of(&state),
            verify_mode,
        );
        let confirmation = ConfirmationToken::confirm(intent);
        let ready = core::prepare_for_open(
            &state,
            SnapshotFetchOutcome::Found(snapshot.clone()),
            image,
            verify_mode,
            Some(&confirmation),
        )
        .unwrap();
        let metadata = fd_metadata_matching(&snapshot);

        let path = std::env::temp_dir().join(format!(
            "linux-usb-writer-write-job-test-sync-fd-{}.tmp",
            std::process::id()
        ));
        let file = std::fs::File::create(&path).expect("create temp file for sync fd test");
        std::fs::remove_file(&path).expect("unlink temp file for sync fd test");
        let handle = OpenedDeviceHandle::from_file_for_test(file);
        let raw_fd = handle.raw_fd_for_test();

        let prepared = core::finalize_prepared_write(ready, Some(handle), Some(&metadata)).unwrap();
        let authorized = prepared.begin();

        let data = vec![8u8; image_size as usize];
        let writing = start_inner(authorized, Cursor::new(data), CancelHandle::new());
        let outcome = writing.write(|_| {});
        let succeeded = match outcome {
            WriteAttemptOutcome::Succeeded(s) => s,
            other => panic!("expected Succeeded, got {other:?}"),
        };

        // H: still open once ownership has moved into Syncing.
        let syncing = succeeded.begin_sync();
        assert!(
            crate::execution::linux_access::fd_proc_target_for_test(raw_fd).is_some(),
            "fd should still be open once ownership has moved into Syncing"
        );

        let sync_outcome = syncing.sync();
        let synced = match sync_outcome {
            SyncAttemptOutcome::Succeeded(s) => s,
            other => panic!("expected Succeeded, got {other:?}"),
        };

        // I: still open while SyncSucceeded is alive.
        let target_before_drop = crate::execution::linux_access::fd_proc_target_for_test(raw_fd);
        assert!(
            target_before_drop.is_some(),
            "fd should still be open while SyncSucceeded is alive"
        );

        drop(synced);

        // J: closed once SyncSucceeded is dropped.
        crate::execution::linux_access::assert_fd_closed_for_test(
            raw_fd,
            target_before_drop.as_deref(),
        );
    }

    // ---------------------------------------------------------------------
    // AuthorizedExecution::bind() / begin_write()
    // ---------------------------------------------------------------------

    fn write_temp_image_file(tag: &str, contents: &[u8]) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};

        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, AtomicOrdering::Relaxed);

        let path = std::env::temp_dir().join(format!(
            "linux-usb-writer-write-job-binding-test-{tag}-{}-{id}.tmp",
            std::process::id()
        ));
        std::fs::write(&path, contents).expect("write temp image file for binding test");
        path
    }

    // A minimal `ImageSource` whose `open_reader()` always fails, used only
    // to exercise `begin_write()`'s error path (test M below). No real
    // `FileImageSource` can be made to fail here on demand: it deliberately
    // never re-opens its path (see its own doc comment), so deleting or
    // otherwise tampering with the file after construction does not make
    // its `open_reader()` fail either.
    struct FailingImageSource {
        logical_size: u64,
    }

    impl ImageSource for FailingImageSource {
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
            Err(io::Error::other("simulated image open failure"))
        }
    }

    // F. An AuthorizedWrite confirmed against a SelectedImage's own
    // selection() binds successfully with that same SelectedImage.
    #[test]
    fn authorized_execution_bind_succeeds_for_matching_generation_and_size() {
        let data = vec![1u8; 4096];
        let path = write_temp_image_file("bind-success", &data);
        let selected = SelectedImage::new(Box::new(FileImageSource::new(&path).unwrap()));

        let (_target_path, authorized) = gate_pass_active_write_for_image(
            "bind-success-target",
            selected.selection(),
            data.len() as u64,
            false,
        );

        let result = AuthorizedExecution::bind(authorized, selected);

        assert!(result.is_ok());
        let _ = std::fs::remove_file(&path);
    }

    // G / same-size different image (the core safety condition this
    // session's design exists to close). Image A and Image B happen to be
    // the exact same size but have different content and therefore
    // different image_generations -- binding an AuthorizedWrite confirmed
    // for A against SelectedImage B must be rejected.
    #[test]
    fn authorized_execution_bind_rejects_same_size_different_image() {
        let data_a = vec![1u8; 4096];
        let data_b = vec![2u8; 4096];
        let path_a = write_temp_image_file("bind-diff-a", &data_a);
        let path_b = write_temp_image_file("bind-diff-b", &data_b);

        let selected_a = SelectedImage::new(Box::new(FileImageSource::new(&path_a).unwrap()));
        let selected_b = SelectedImage::new(Box::new(FileImageSource::new(&path_b).unwrap()));

        let (_target_path, authorized_for_a) = gate_pass_active_write_for_image(
            "bind-diff-target",
            selected_a.selection(),
            data_a.len() as u64,
            false,
        );

        let result = AuthorizedExecution::bind(authorized_for_a, selected_b);

        assert!(matches!(result, Err(ImageBindingError::GenerationMismatch)));
        let _ = std::fs::remove_file(&path_a);
        let _ = std::fs::remove_file(&path_b);
    }

    // H. Explicitly reselecting the exact same file (a fresh
    // FileImageSource::new() over the same path, hence a fresh
    // SelectedImage) still mints a new image_generation -- binding an old
    // AuthorizedWrite against the reselected SelectedImage is rejected.
    #[test]
    fn authorized_execution_bind_rejects_after_explicit_reselect_of_same_file() {
        let data = vec![3u8; 2048];
        let path = write_temp_image_file("bind-reselect", &data);

        let selected_a = SelectedImage::new(Box::new(FileImageSource::new(&path).unwrap()));
        let (_target_path, authorized_for_a) = gate_pass_active_write_for_image(
            "bind-reselect-target",
            selected_a.selection(),
            data.len() as u64,
            false,
        );

        let selected_b = SelectedImage::new(Box::new(FileImageSource::new(&path).unwrap()));

        let result = AuthorizedExecution::bind(authorized_for_a, selected_b);

        assert!(matches!(result, Err(ImageBindingError::GenerationMismatch)));
        let _ = std::fs::remove_file(&path);
    }

    // I. A stale AuthorizedWrite (confirmed against an old SelectedImage)
    // must not bind against a completely new, later selection -- a
    // different path, different content, different size. Generation is
    // checked first (see `AuthorizedExecution::bind`'s doc comment), so this
    // is rejected before size is ever compared.
    #[test]
    fn authorized_execution_bind_rejects_stale_authorized_write_against_new_selection() {
        let old_data = vec![4u8; 1024];
        let old_path = write_temp_image_file("bind-stale-old", &old_data);
        let selected_old = SelectedImage::new(Box::new(FileImageSource::new(&old_path).unwrap()));

        let (_target_path, authorized_for_old) = gate_pass_active_write_for_image(
            "bind-stale-target",
            selected_old.selection(),
            old_data.len() as u64,
            false,
        );

        // Time passes; the user selects a brand new image (different path,
        // different size).
        let new_data = vec![5u8; 5000];
        let new_path = write_temp_image_file("bind-stale-new", &new_data);
        let selected_new = SelectedImage::new(Box::new(FileImageSource::new(&new_path).unwrap()));

        let result = AuthorizedExecution::bind(authorized_for_old, selected_new);

        assert!(matches!(result, Err(ImageBindingError::GenerationMismatch)));
        let _ = std::fs::remove_file(&old_path);
        let _ = std::fs::remove_file(&new_path);
    }

    // J (size mismatch). Not implemented as a runtime test: `image_size`
    // and `image_generation` are always minted together, atomically, by
    // `core::ImageSelection::new()` (see `ImageBindingError`'s doc
    // comment), so a matching generation already implies a matching size --
    // there is no way to reach `ImageBindingError::SizeMismatch` through
    // the real, production `SelectedImage`/`AuthorizedWrite` construction
    // paths without adding a test-only backdoor constructor that weakens
    // those types' own invariants. Per this session's instructions, no such
    // backdoor is added; `SizeMismatch` remains a structurally-unreachable
    // defense-in-depth check, documented as such rather than forced into a
    // test.

    // K / L. A successful bind followed by begin_write() produces a
    // WritingExecution whose Writing, once run, writes exactly the source
    // image's content to the target -- proving the reader begin_write()
    // used came from the same SelectedImage bind() was given, not a
    // separately supplied one (there is no reader parameter to supply one
    // through in the first place).
    #[test]
    fn begin_write_uses_a_reader_from_the_same_selected_image() {
        let data: Vec<u8> = (0..4096u32).map(|i| (i % 250) as u8).collect();
        let path = write_temp_image_file("begin-write-reader", &data);
        let selected = SelectedImage::new(Box::new(FileImageSource::new(&path).unwrap()));

        let (target_path, authorized) = gate_pass_active_write_for_image(
            "begin-write-target",
            selected.selection(),
            data.len() as u64,
            true,
        );
        let target_path = target_path.expect("persistent temp target path");

        let execution = AuthorizedExecution::bind(authorized, selected).unwrap();
        let writing_execution = execution.begin_write(CancelHandle::new()).unwrap();

        let outcome = writing_execution.writing.write(|_| {});
        let succeeded = match outcome {
            WriteAttemptOutcome::Succeeded(s) => s,
            other => panic!("expected Succeeded, got {other:?}"),
        };
        assert_eq!(succeeded.bytes_written, data.len() as u64);

        let written = std::fs::read(&target_path).expect("reopen target temp file for read-back");
        let _ = std::fs::remove_file(&target_path);
        let _ = std::fs::remove_file(&path);
        assert_eq!(written, data);
    }

    // M. self.image.open_reader() failing inside begin_write() surfaces as
    // an Err before any write is attempted: the target temp file (created
    // empty by gate_pass_active_write_for_image) is left untouched at 0
    // bytes, and the consumed AuthorizedExecution (with the target FD it
    // owned) is safely dropped via ordinary RAII.
    #[test]
    fn begin_write_reader_open_failure_leaves_target_untouched() {
        let logical_size = 4096u64;
        let selected = SelectedImage::new(Box::new(FailingImageSource { logical_size }));

        let (target_path, authorized) = gate_pass_active_write_for_image(
            "begin-write-open-failure-target",
            selected.selection(),
            logical_size,
            true,
        );
        let target_path = target_path.expect("persistent temp target path");

        let execution = AuthorizedExecution::bind(authorized, selected).unwrap();

        let result = execution.begin_write(CancelHandle::new());

        assert!(result.is_err());

        let target_contents = std::fs::read(&target_path).expect("reopen target temp file");
        assert!(
            target_contents.is_empty(),
            "no bytes should have reached the target"
        );
        let _ = std::fs::remove_file(&target_path);
    }

    // N. WritingExecution retains the exact SelectedImage bind() was given,
    // still independently readable after begin_write() has already opened
    // its own write-time reader from it -- the property a future write/sync/
    // verify orchestration needs to obtain a second, verify-time reader.
    #[test]
    fn writing_execution_retains_the_selected_image_for_later_use() {
        let data: Vec<u8> = (0..1500u32).map(|i| (i % 200) as u8).collect();
        let path = write_temp_image_file("writing-execution-retains-image", &data);
        let selected = SelectedImage::new(Box::new(FileImageSource::new(&path).unwrap()));

        let (_target_path, authorized) = gate_pass_active_write_for_image(
            "writing-execution-retains-target",
            selected.selection(),
            data.len() as u64,
            false,
        );

        let execution = AuthorizedExecution::bind(authorized, selected).unwrap();
        let writing_execution = execution.begin_write(CancelHandle::new()).unwrap();

        let mut verify_reader = writing_execution.image.open_reader().unwrap();
        let mut read_back = Vec::new();
        verify_reader.read_to_end(&mut read_back).unwrap();

        assert_eq!(read_back, data);
        let _ = std::fs::remove_file(&path);
    }

    // ---------------------------------------------------------------------
    // WritingExecution::write()
    // ---------------------------------------------------------------------

    // O. WritingExecution::write() (the new public entry point) actually
    // runs the write, relays progress, returns Succeeded, and hands back the
    // exact same SelectedImage -- checked via its own existing public
    // identity getters (`selection().image_generation()`/`logical_size()`),
    // not a new test-only constructor.
    #[test]
    fn writing_execution_write_succeeds_and_returns_the_same_selected_image() {
        let data: Vec<u8> = (0..3000u32).map(|i| (i % 240) as u8).collect();
        let path = write_temp_image_file("writing-execution-write-success", &data);
        let selected = SelectedImage::new(Box::new(FileImageSource::new(&path).unwrap()));
        let original_generation = selected.selection().image_generation();
        let original_logical_size = selected.logical_size();

        let (target_path, authorized) = gate_pass_active_write_for_image(
            "writing-execution-write-success-target",
            selected.selection(),
            data.len() as u64,
            true,
        );
        let target_path = target_path.expect("persistent temp target path");

        let execution = AuthorizedExecution::bind(authorized, selected).unwrap();
        let writing_execution = execution.begin_write(CancelHandle::new()).unwrap();

        let mut progress_log = Vec::new();
        let (returned_image, outcome) =
            writing_execution.write(|progress| progress_log.push(progress.bytes_written));

        assert_eq!(
            returned_image.selection().image_generation(),
            original_generation
        );
        assert_eq!(returned_image.logical_size(), original_logical_size);
        assert!(
            !progress_log.is_empty(),
            "on_progress should be called at least once"
        );

        let succeeded = match outcome {
            WriteAttemptOutcome::Succeeded(s) => s,
            other => panic!("expected Succeeded, got {other:?}"),
        };
        assert_eq!(succeeded.bytes_written, data.len() as u64);

        let written = std::fs::read(&target_path).expect("reopen target temp file for read-back");
        let _ = std::fs::remove_file(&target_path);
        let _ = std::fs::remove_file(&path);
        assert_eq!(written, data);
    }

    // P. WritingExecution::write(), cancelled before any chunk, still
    // returns the same SelectedImage alongside WriteAttemptOutcome::Cancelled
    // -- reusing the exact same pre-cancel technique as
    // `cancel_before_any_chunk_is_cancelled_with_user_requested_reason`
    // above, just through the new public entry point.
    #[test]
    fn writing_execution_write_cancelled_before_any_chunk_returns_cancelled_and_same_image() {
        let data = vec![9u8; 5000];
        let path = write_temp_image_file("writing-execution-write-cancel", &data);
        let selected = SelectedImage::new(Box::new(FileImageSource::new(&path).unwrap()));
        let original_generation = selected.selection().image_generation();

        let (_target_path, authorized) = gate_pass_active_write_for_image(
            "writing-execution-write-cancel-target",
            selected.selection(),
            data.len() as u64,
            false,
        );

        let execution = AuthorizedExecution::bind(authorized, selected).unwrap();
        let cancel = CancelHandle::new();
        cancel.request_cancel(CancelReason::UserRequested);
        let writing_execution = execution.begin_write(cancel).unwrap();

        let (returned_image, outcome) = writing_execution.write(|_| {});

        assert_eq!(
            returned_image.selection().image_generation(),
            original_generation
        );
        let cancelled = match outcome {
            WriteAttemptOutcome::Cancelled(c) => c,
            other => panic!("expected Cancelled, got {other:?}"),
        };
        assert_eq!(cancelled.bytes_written, 0);
        assert_eq!(cancelled.reason, CancelReason::UserRequested);

        let _ = std::fs::remove_file(&path);
    }

    // Q. WritingExecution::write(), a genuine target write() failure (EBADF
    // via a read-only fd -- the same technique as
    // `target_write_error_is_failed_and_conservatively_flagged_as_modified_even_with_zero_bytes_written`
    // above) becomes Failed, and the same SelectedImage is still returned.
    #[test]
    fn writing_execution_write_target_error_returns_failed_and_same_image() {
        let image_size = 64u64;
        let target_size = 128u64;
        let data = vec![7u8; image_size as usize];
        let path = write_temp_image_file("writing-execution-write-failure", &data);
        let selected = SelectedImage::new(Box::new(FileImageSource::new(&path).unwrap()));
        let original_generation = selected.selection().image_generation();

        let snapshot = base_device(target_size);
        let state = core::select(snapshot.clone()).unwrap();
        let verify_mode = VerifyMode::None;
        let intent = core::write_intent_for_test(
            &snapshot,
            selected.selection(),
            core::selection_generation_of(&state),
            verify_mode,
        );
        let confirmation = ConfirmationToken::confirm(intent);
        let ready = core::prepare_for_open(
            &state,
            SnapshotFetchOutcome::Found(snapshot.clone()),
            selected.selection(),
            verify_mode,
            Some(&confirmation),
        )
        .unwrap();
        let metadata = fd_metadata_matching(&snapshot);

        let target_path = std::env::temp_dir().join(format!(
            "linux-usb-writer-write-job-test-writing-execution-write-failure-{}.tmp",
            std::process::id()
        ));
        std::fs::File::create(&target_path).expect("create temp file for read-only test");
        let read_only_file = std::fs::OpenOptions::new()
            .read(true)
            .open(&target_path)
            .expect("reopen temp file read-only");
        let handle = OpenedDeviceHandle::from_file_for_test(read_only_file);

        let prepared = core::finalize_prepared_write(ready, Some(handle), Some(&metadata)).unwrap();
        let authorized = prepared.begin();

        let execution = AuthorizedExecution::bind(authorized, selected).unwrap();
        let writing_execution = execution.begin_write(CancelHandle::new()).unwrap();

        let (returned_image, outcome) = writing_execution.write(|_| {});

        let _ = std::fs::remove_file(&target_path);
        let _ = std::fs::remove_file(&path);

        assert_eq!(
            returned_image.selection().image_generation(),
            original_generation
        );
        let failed = match outcome {
            WriteAttemptOutcome::Failed(f) => f,
            other => panic!("expected Failed, got {other:?}"),
        };
        assert!(matches!(
            failed.cause,
            WriteJobFailureCause::Write(WriteError::TargetWrite(_))
        ));
    }

    // ---------------------------------------------------------------------
    // Built-in Verify (implementation step 4)
    // ---------------------------------------------------------------------

    // Drives the full production chain -- Gate -> AuthorizedExecution::bind()
    // -> begin_write() -> write() -> begin_sync() -> sync() -- from a real
    // `SelectedImage`/`FileImageSource` (unlike `gate_pass_write_succeeded`
    // above, which uses a raw in-memory `Cursor`), because Full/Quick Verify
    // need a genuine `open_reader()`/`read_at()`-capable source, never a
    // block device. Returns the target path (always persistent -- Verify
    // tests need to reopen, and sometimes corrupt, it afterward), the same
    // `SelectedImage` `WritingExecution::write()` handed back, the resulting
    // `SyncSucceeded`, and the `DeviceSnapshot` used as the Gate's baseline
    // (so a test can build a deliberately-modified "fresh" snapshot from it).
    //
    // The target path is returned as `VerifyFixtureFiles`, which also owns
    // the temporary source file and removes both when dropped.
    fn gate_pass_sync_succeeded(
        tag: &str,
        source_data: &[u8],
        target_size: u64,
        verify_mode: VerifyMode,
    ) -> (
        VerifyFixtureFiles,
        SelectedImage,
        SyncSucceeded,
        DeviceSnapshot,
    ) {
        let source = TempFile(write_temp_image_file(
            &format!("verify-source-{tag}"),
            source_data,
        ));
        let (target_path, writing_execution, snapshot) = gate_pass_writing_execution(
            tag,
            &source.0,
            target_size,
            verify_mode,
            CancelHandle::new(),
        );
        let files = VerifyFixtureFiles {
            target: TempFile(target_path),
            source,
        };

        let (selected_image, outcome) = writing_execution.write(|_| {});
        let write_succeeded = match outcome {
            WriteAttemptOutcome::Succeeded(s) => s,
            other => {
                panic!("expected write to succeed while setting up a verify test, got {other:?}")
            }
        };

        let sync_outcome = write_succeeded.begin_sync().sync();
        let sync_succeeded = match sync_outcome {
            SyncAttemptOutcome::Succeeded(s) => s,
            other => {
                panic!("expected sync to succeed while setting up a verify test, got {other:?}")
            }
        };

        (files, selected_image, sync_succeeded, snapshot)
    }

    // A temporary file a test fixture created, removed when this is dropped
    // -- including while unwinding from a failed assertion. A failed removal
    // (e.g. the test already removed it) is ignored, so it can never panic
    // during a panic.
    struct TempFile(std::path::PathBuf);

    impl Drop for TempFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    // The files behind a `gate_pass_sync_succeeded` fixture. Derefs to the
    // target path, which is what tests use it as. Callers bind it first in
    // the returned tuple, so it is dropped after the image and handles that
    // keep those files open.
    struct VerifyFixtureFiles {
        target: TempFile,
        source: TempFile,
    }

    impl std::ops::Deref for VerifyFixtureFiles {
        type Target = std::path::Path;

        fn deref(&self) -> &std::path::Path {
            &self.target.0
        }
    }

    impl AsRef<std::path::Path> for VerifyFixtureFiles {
        fn as_ref(&self) -> &std::path::Path {
            &self.target.0
        }
    }

    // The fixture's temporary source and target files are removed when the
    // fixture is dropped, both normally and while unwinding from a panic.
    #[test]
    fn verify_fixture_files_are_removed_on_drop_and_on_panic() {
        let (files, image, sync_succeeded, _snapshot) =
            gate_pass_sync_succeeded("cleanup-drop", b"cleanup", 64, VerifyMode::None);
        let source = files.source.0.clone();
        let target = files.target.0.clone();
        assert!(source.exists() && target.exists());
        drop(sync_succeeded);
        drop(image);
        drop(files);
        assert!(!source.exists(), "source left behind");
        assert!(!target.exists(), "target left behind");

        let mut created = None;
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let (files, _image, _sync_succeeded, _snapshot) =
                gate_pass_sync_succeeded("cleanup-panic", b"cleanup", 64, VerifyMode::None);
            created = Some((files.source.0.clone(), files.target.0.clone()));
            panic!("simulated test failure");
        }));
        assert!(result.is_err());
        let (source, target) = created.expect("fixture was created before the panic");
        assert!(!source.exists(), "source left behind after a panic");
        assert!(!target.exists(), "target left behind after a panic");
    }

    // The part of `gate_pass_sync_succeeded` up to `begin_write()`, for
    // tests that need to act while the write runs (the source file at
    // `source_path` stays at a known path so it can be changed).
    fn gate_pass_writing_execution(
        tag: &str,
        source_path: &std::path::Path,
        target_size: u64,
        verify_mode: VerifyMode,
        cancel: CancelHandle,
    ) -> (std::path::PathBuf, WritingExecution, DeviceSnapshot) {
        let source = FileImageSource::new(source_path).expect("open source image for verify test");
        gate_pass_writing_execution_for_image(
            tag,
            SelectedImage::new(Box::new(source)),
            target_size,
            verify_mode,
            cancel,
        )
    }

    // The same, for any already-built `SelectedImage` (e.g. a compressed
    // source).
    fn gate_pass_writing_execution_for_image(
        tag: &str,
        selected_image: SelectedImage,
        target_size: u64,
        verify_mode: VerifyMode,
        cancel: CancelHandle,
    ) -> (std::path::PathBuf, WritingExecution, DeviceSnapshot) {
        let (target_path, authorized, snapshot) =
            gate_pass_authorized_for_image(tag, &selected_image, target_size, verify_mode);

        let execution = AuthorizedExecution::bind(authorized, selected_image)
            .expect("bind should succeed for a freshly minted SelectedImage");
        let writing_execution = execution
            .begin_write(cancel)
            .expect("begin_write should succeed for a freshly opened reader");

        (target_path, writing_execution, snapshot)
    }

    // The Gate part of `gate_pass_writing_execution_for_image`, up to the
    // `AuthorizedWrite` (the target file exists, empty, and is opened).
    fn gate_pass_authorized_for_image(
        tag: &str,
        selected_image: &SelectedImage,
        target_size: u64,
        verify_mode: VerifyMode,
    ) -> (std::path::PathBuf, AuthorizedWrite, DeviceSnapshot) {
        use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};

        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, AtomicOrdering::Relaxed);

        let snapshot = base_device(target_size);
        let state = core::select(snapshot.clone()).unwrap();
        let intent = core::write_intent_for_test(
            &snapshot,
            selected_image.selection(),
            core::selection_generation_of(&state),
            verify_mode,
        );
        let confirmation = ConfirmationToken::confirm(intent);

        let ready = core::prepare_for_open(
            &state,
            SnapshotFetchOutcome::Found(snapshot.clone()),
            selected_image.selection(),
            verify_mode,
            Some(&confirmation),
        )
        .expect("prepare_for_open should succeed for a freshly matching snapshot/confirmation");

        let metadata = fd_metadata_matching(&snapshot);

        let target_path = std::env::temp_dir().join(format!(
            "linux-usb-writer-write-job-verify-test-{tag}-{}-{id}.tmp",
            std::process::id()
        ));
        let target_file =
            std::fs::File::create(&target_path).expect("create target temp file for verify test");
        let handle = OpenedDeviceHandle::from_file_for_test(target_file);

        let prepared = core::finalize_prepared_write(ready, Some(handle), Some(&metadata))
            .expect("finalize_prepared_write should succeed with matching FD metadata");

        (target_path, prepared.begin(), snapshot)
    }

    // Drives `sync_succeeded` all the way to a `Verifying`, using
    // `target_snapshot` as the "freshly re-fetched" snapshot (identical to
    // the Gate's own baseline for every test that isn't specifically
    // exercising Identity/Instance/hazard rejection) and reopening
    // `target_path` read-only as the "just-opened read-only FD"
    // `linux_access::open_device(block_path, OpenAccess::ReadOnly)` would have produced in
    // production. Panics loudly (with the actual error) if either
    // pre-flight phase unexpectedly rejects -- exactly what a test setup
    // helper should do, since an unexpected rejection here means the test
    // itself is broken, not the thing under test.
    fn verifying_from_sync_succeeded(
        sync_succeeded: SyncSucceeded,
        image: SelectedImage,
        cancel: CancelHandle,
        target_snapshot: &DeviceSnapshot,
        target_path: &std::path::Path,
    ) -> Verifying {
        let pending = match sync_succeeded.begin_verify(image, cancel) {
            VerifyStart::Pending(pending) => pending,
            VerifyStart::Skipped(..) => {
                panic!("expected Pending for a Quick/Full verify_mode, got Skipped")
            }
        };

        let ready = pending
            .check_target(SnapshotFetchOutcome::Found(target_snapshot.clone()))
            .unwrap_or_else(|(_, error, _)| {
                panic!("check_target should succeed for a matching fresh snapshot, got {error:?}")
            });

        let read_file = std::fs::OpenOptions::new()
            .read(true)
            .open(target_path)
            .expect("reopen target file read-only for verify test");
        let read_handle = OpenedDeviceHandle::from_file_for_test(read_file);
        let metadata = fd_metadata_matching(target_snapshot);

        ready
            .finalize(Some(read_handle), Some(&metadata))
            .unwrap_or_else(|(_, error)| {
                panic!("finalize should succeed for a matching FD, got {error:?}")
            })
    }

    // Overwrites the byte at `offset` in the file at `path` -- used to
    // simulate a post-write corruption (bit rot, a bad sector, wrong target,
    // ...) for the Full/Quick mismatch-detection tests below. Never touches
    // any other byte, so tests can reason exactly about which single offset
    // should be reported as the first mismatch.
    fn corrupt_byte_at(path: &std::path::Path, offset: u64, new_byte: u8) {
        use std::io::{Seek, SeekFrom, Write as _};

        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .open(path)
            .expect("reopen target file to corrupt a byte for verify test");
        file.seek(SeekFrom::Start(offset))
            .expect("seek to corruption offset");
        file.write_all(&[new_byte]).expect("write corrupted byte");
    }

    // A minimal `ImageSource` whose reader yields `fail_after` real bytes and
    // then a genuine `io::Error` -- used only to exercise Full/Quick Verify's
    // `SourceReadError` path. `FileImageSource` cannot be made to fail a
    // read on demand (same reasoning as `FailingImageSource` above, which
    // covers the *open* failure case instead), so this is a small,
    // independent test-only source.
    struct FailingAfterNBytesSource {
        logical_size: u64,
        fail_after: usize,
    }

    struct FailingAfterNBytesReader {
        remaining_ok: usize,
    }

    impl Read for FailingAfterNBytesReader {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.remaining_ok == 0 {
                return Err(io::Error::other("simulated source read failure"));
            }
            let to_write = buf.len().min(self.remaining_ok);
            for byte in &mut buf[..to_write] {
                *byte = 0xAA;
            }
            self.remaining_ok -= to_write;
            Ok(to_write)
        }
    }

    impl ImageSource for FailingAfterNBytesSource {
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
            Ok(Box::new(FailingAfterNBytesReader {
                remaining_ok: self.fail_after,
            }))
        }
    }

    // V1 (VerifyMode::None). begin_verify() with VerifyMode::None resolves
    // immediately to Skipped(image, VerifySucceeded{mode:None,
    // verified_bytes:0, skipped:true}) -- no DeviceSnapshot, no
    // OpenedDeviceHandle, no FdMetadata is ever constructed or passed in
    // this test, which is itself the proof that begin_verify() cannot need
    // any of them for this mode (there is no other way for this test to
    // even compile if it did).
    #[test]
    fn verify_mode_none_produces_immediate_skipped_success_without_any_handle() {
        let (_path, _image, sync_succeeded) = {
            let (path, image, sync_succeeded, _snapshot) =
                gate_pass_sync_succeeded("none-mode", b"hello verify", 100, VerifyMode::None);
            (path, image, sync_succeeded)
        };

        let start = sync_succeeded.begin_verify(_image, CancelHandle::new());

        let (returned_image, succeeded) = match start {
            VerifyStart::Skipped(image, succeeded) => (image, succeeded),
            VerifyStart::Pending(_) => panic!("expected Skipped for VerifyMode::None"),
        };

        assert_eq!(succeeded.mode, VerifyMode::None);
        assert_eq!(succeeded.verified_bytes, 0);
        assert!(succeeded.skipped);
        assert_eq!(returned_image.logical_size(), 12);

        let _ = std::fs::remove_file(&_path);
    }

    // V2 (Full success). Exact match: Full Verify succeeds,
    // verified_bytes == image_size, and progress's final report also equals
    // image_size.
    #[test]
    fn full_verify_exact_match_succeeds_with_progress_reaching_image_size() {
        let data = b"full verify exact match test data, several chunks worth".repeat(20_000);
        let (target_path, image, sync_succeeded, snapshot) = gate_pass_sync_succeeded(
            "full-exact-match",
            &data,
            data.len() as u64,
            VerifyMode::Full,
        );

        let verifying = verifying_from_sync_succeeded(
            sync_succeeded,
            image,
            CancelHandle::new(),
            &snapshot,
            &target_path,
        );

        let mut progress_log = Vec::new();
        let (_image, outcome) = verifying.run(|p| progress_log.push(p));

        let _ = std::fs::remove_file(&target_path);

        let succeeded = match outcome {
            VerifyOutcome::Succeeded(s) => s,
            other => panic!("expected Succeeded, got {other:?}"),
        };
        assert_eq!(succeeded.mode, VerifyMode::Full);
        assert_eq!(succeeded.verified_bytes, data.len() as u64);
        assert!(!succeeded.skipped);
        assert_eq!(
            progress_log.last().unwrap().verified_bytes,
            data.len() as u64
        );
        assert_eq!(progress_log.last().unwrap().total_bytes, data.len() as u64);
    }

    // V3 (Full mismatch at first byte). A corruption at offset 0 is
    // detected with the exact offset/expected/actual bytes, and
    // verified_bytes reflects how far comparison got before stopping (0,
    // since the very first chunk's compare already failed).
    #[test]
    fn full_verify_detects_mismatch_at_first_byte() {
        let data = vec![0x11u8; 5000];
        let (target_path, image, sync_succeeded, snapshot) = gate_pass_sync_succeeded(
            "full-mismatch-first",
            &data,
            data.len() as u64,
            VerifyMode::Full,
        );
        corrupt_byte_at(&target_path, 0, 0x99);

        let verifying = verifying_from_sync_succeeded(
            sync_succeeded,
            image,
            CancelHandle::new(),
            &snapshot,
            &target_path,
        );

        let (_image, outcome) = verifying.run(|_| {});
        let _ = std::fs::remove_file(&target_path);

        let failed = match outcome {
            VerifyOutcome::Failed(f) => f,
            other => panic!("expected Failed, got {other:?}"),
        };
        assert_eq!(failed.verified_bytes, 0);
        assert!(matches!(
            failed.reason,
            VerifyFailureReason::Mismatch {
                offset: 0,
                expected: 0x11,
                actual: 0x99
            }
        ));
    }

    // V4 (Full mismatch in the middle). The reported offset is the exact
    // absolute byte, and verified_bytes equals the chunk-aligned amount
    // already confirmed matching before the mismatching chunk.
    #[test]
    fn full_verify_detects_mismatch_in_the_middle_with_correct_offset() {
        let image_size = 3 * writer::DEFAULT_CHUNK_SIZE as u64;
        let data = vec![0x22u8; image_size as usize];
        let (target_path, image, sync_succeeded, snapshot) =
            gate_pass_sync_succeeded("full-mismatch-middle", &data, image_size, VerifyMode::Full);
        let corrupt_offset = writer::DEFAULT_CHUNK_SIZE as u64 + 500;
        corrupt_byte_at(&target_path, corrupt_offset, 0x77);

        let verifying = verifying_from_sync_succeeded(
            sync_succeeded,
            image,
            CancelHandle::new(),
            &snapshot,
            &target_path,
        );

        let (_image, outcome) = verifying.run(|_| {});
        let _ = std::fs::remove_file(&target_path);

        let failed = match outcome {
            VerifyOutcome::Failed(f) => f,
            other => panic!("expected Failed, got {other:?}"),
        };
        assert_eq!(failed.verified_bytes, writer::DEFAULT_CHUNK_SIZE as u64);
        assert!(matches!(
            failed.reason,
            VerifyFailureReason::Mismatch { offset, expected: 0x22, actual: 0x77 }
                if offset == corrupt_offset
        ));
    }

    // V5 (Full mismatch at the last byte). The final byte of a
    // non-chunk-aligned image is compared and correctly reported.
    #[test]
    fn full_verify_detects_mismatch_at_last_byte() {
        let image_size = writer::DEFAULT_CHUNK_SIZE as u64 + 777;
        let data = vec![0x33u8; image_size as usize];
        let (target_path, image, sync_succeeded, snapshot) =
            gate_pass_sync_succeeded("full-mismatch-last", &data, image_size, VerifyMode::Full);
        let last_offset = image_size - 1;
        corrupt_byte_at(&target_path, last_offset, 0x44);

        let verifying = verifying_from_sync_succeeded(
            sync_succeeded,
            image,
            CancelHandle::new(),
            &snapshot,
            &target_path,
        );

        let (_image, outcome) = verifying.run(|_| {});
        let _ = std::fs::remove_file(&target_path);

        let failed = match outcome {
            VerifyOutcome::Failed(f) => f,
            other => panic!("expected Failed, got {other:?}"),
        };
        assert!(matches!(
            failed.reason,
            VerifyFailureReason::Mismatch { offset, expected: 0x33, actual: 0x44 }
                if offset == last_offset
        ));
    }

    // V6 (target shorter than image). The target file is truncated shorter
    // than image_size after write/sync (simulating the device somehow
    // reporting less data than expected) -- Full Verify reports
    // TargetUnexpectedEof, not a silent short success.
    #[test]
    fn full_verify_target_shorter_than_image_is_target_unexpected_eof() {
        let image_size = 5000u64;
        let data = vec![0x55u8; image_size as usize];
        let (target_path, image, sync_succeeded, snapshot) =
            gate_pass_sync_succeeded("full-target-short", &data, image_size, VerifyMode::Full);

        {
            let file = std::fs::OpenOptions::new()
                .write(true)
                .open(&target_path)
                .expect("reopen target to truncate it");
            file.set_len(3000).expect("truncate target file");
        }

        let verifying = verifying_from_sync_succeeded(
            sync_succeeded,
            image,
            CancelHandle::new(),
            &snapshot,
            &target_path,
        );

        let (_image, outcome) = verifying.run(|_| {});
        let _ = std::fs::remove_file(&target_path);

        let failed = match outcome {
            VerifyOutcome::Failed(f) => f,
            other => panic!("expected Failed, got {other:?}"),
        };
        assert!(matches!(
            failed.reason,
            VerifyFailureReason::TargetUnexpectedEof
        ));
    }

    // V7 (source read error). The source errors genuinely (not merely runs
    // short) partway through -- reported as SourceReadError, distinct from
    // SourceUnexpectedEof. Uses a normal, working write/sync setup for the
    // target (via `gate_pass_sync_succeeded`), then swaps in a deliberately
    // failing `SelectedImage` only for the `begin_verify()` call itself --
    // `begin_verify()`/`PendingVerify`/`Verifying` never re-check that the
    // image passed to them is the same one `AuthorizedExecution::bind()`
    // used at write time (that binding only matters for starting a write),
    // so this is a legitimate, minimal way to exercise Verify's own
    // source-read-error path in isolation, without needing a whole second
    // Gate/write/sync sequence to fail on purpose.
    #[test]
    fn full_verify_source_read_error_is_reported() {
        let image_size = 5000u64;
        let (target_path, _working_image, sync_succeeded, snapshot) = gate_pass_sync_succeeded(
            "full-source-error",
            &vec![0u8; image_size as usize],
            image_size,
            VerifyMode::Full,
        );

        let failing_image = SelectedImage::new(Box::new(FailingAfterNBytesSource {
            logical_size: image_size,
            fail_after: 2000,
        }));

        let verifying = verifying_from_sync_succeeded(
            sync_succeeded,
            failing_image,
            CancelHandle::new(),
            &snapshot,
            &target_path,
        );

        let (_image, outcome) = verifying.run(|_| {});
        let _ = std::fs::remove_file(&target_path);

        let failed = match outcome {
            VerifyOutcome::Failed(f) => f,
            other => panic!("expected Failed, got {other:?}"),
        };
        assert!(matches!(
            failed.reason,
            VerifyFailureReason::SourceReadError(_)
        ));
    }

    // V8 (target read error). Opening the "read-only" handle without read
    // permission (write-only) forces a genuine EBADF on the first
    // `read_at()` call -- reported as TargetReadError.
    #[test]
    fn full_verify_target_read_error_is_reported() {
        let image_size = 4000u64;
        let data = vec![0x66u8; image_size as usize];
        let (target_path, image, sync_succeeded, snapshot) =
            gate_pass_sync_succeeded("full-target-error", &data, image_size, VerifyMode::Full);

        let pending = match sync_succeeded.begin_verify(image, CancelHandle::new()) {
            VerifyStart::Pending(p) => p,
            VerifyStart::Skipped(..) => panic!("expected Pending"),
        };
        let ready = pending
            .check_target(SnapshotFetchOutcome::Found(snapshot.clone()))
            .unwrap_or_else(|(_, e, _)| panic!("check_target should succeed, got {e:?}"));

        // Write-only, no read permission -- read_at() on this handle must
        // fail with a genuine I/O error, not merely a short read.
        let write_only_file = std::fs::OpenOptions::new()
            .write(true)
            .open(&target_path)
            .expect("reopen target write-only for target-read-error test");
        let handle = OpenedDeviceHandle::from_file_for_test(write_only_file);
        let metadata = fd_metadata_matching(&snapshot);

        let verifying = ready
            .finalize(Some(handle), Some(&metadata))
            .unwrap_or_else(|(_, e)| panic!("finalize should succeed, got {e:?}"));

        let (_image, outcome) = verifying.run(|_| {});
        let _ = std::fs::remove_file(&target_path);

        let failed = match outcome {
            VerifyOutcome::Failed(f) => f,
            other => panic!("expected Failed, got {other:?}"),
        };
        assert!(matches!(
            failed.reason,
            VerifyFailureReason::TargetReadError(_)
        ));
    }

    // V9. quick_verify_ranges() for a large image produces three distinct,
    // non-overlapping first/middle/last ranges, and their total matches the
    // sum QuickVerify's own progress total would report.
    #[test]
    fn quick_verify_ranges_for_large_image_produces_distinct_ranges() {
        let image_size = 100 * 1024 * 1024u64;
        let ranges = quick_verify_ranges(image_size);

        assert_eq!(ranges.len(), 3);
        for &(offset, len) in &ranges {
            assert_eq!(len, QUICK_VERIFY_WINDOW_SIZE);
            assert!(offset + len <= image_size);
        }
        // Ranges are sorted and non-overlapping.
        assert!(ranges[0].0 + ranges[0].1 <= ranges[1].0);
        assert!(ranges[1].0 + ranges[1].1 <= ranges[2].0);

        let total: u64 = ranges.iter().map(|&(_, len)| len).sum();
        assert_eq!(total, 3 * QUICK_VERIFY_WINDOW_SIZE);
    }

    // V10. quick_verify_ranges() for a small image (<= 3 windows) merges
    // into a single range covering the entire image -- Quick's coverage
    // becomes identical to Full's.
    #[test]
    fn quick_verify_ranges_for_small_image_merges_to_full_coverage() {
        let image_size = 5 * 1024 * 1024u64; // < 3 * 4 MiB
        let ranges = quick_verify_ranges(image_size);

        assert_eq!(ranges, vec![(0, image_size)]);
    }

    // V11 (Quick success). An exact match passes Quick Verify, and
    // verified_bytes/progress total equal the merged sample total, never
    // image.logical_size().
    #[test]
    fn quick_verify_exact_match_succeeds_with_sampled_total_bytes() {
        let image_size = 20 * 1024 * 1024u64; // large enough for 3 distinct windows
        let data = vec![0x88u8; image_size as usize];
        let (target_path, image, sync_succeeded, snapshot) =
            gate_pass_sync_succeeded("quick-exact-match", &data, image_size, VerifyMode::Quick);

        let verifying = verifying_from_sync_succeeded(
            sync_succeeded,
            image,
            CancelHandle::new(),
            &snapshot,
            &target_path,
        );

        let mut progress_log = Vec::new();
        let (_image, outcome) = verifying.run(|p| progress_log.push(p));
        let _ = std::fs::remove_file(&target_path);

        let succeeded = match outcome {
            VerifyOutcome::Succeeded(s) => s,
            other => panic!("expected Succeeded, got {other:?}"),
        };
        let expected_total = 3 * QUICK_VERIFY_WINDOW_SIZE;
        assert_eq!(succeeded.verified_bytes, expected_total);
        assert_ne!(expected_total, image_size, "sanity: sampled total must differ from the full image size for this test to be meaningful");
        assert_eq!(progress_log.last().unwrap().total_bytes, expected_total);
        assert_eq!(progress_log.last().unwrap().verified_bytes, expected_total);
    }

    // V12 (Quick sampled mismatch). A corruption placed inside the first
    // sample window is detected.
    #[test]
    fn quick_verify_detects_mismatch_in_a_sampled_region() {
        let image_size = 20 * 1024 * 1024u64;
        let data = vec![0x99u8; image_size as usize];
        let (target_path, image, sync_succeeded, snapshot) = gate_pass_sync_succeeded(
            "quick-sampled-mismatch",
            &data,
            image_size,
            VerifyMode::Quick,
        );
        // Offset 10 is within the first 4 MiB window.
        corrupt_byte_at(&target_path, 10, 0x00);

        let verifying = verifying_from_sync_succeeded(
            sync_succeeded,
            image,
            CancelHandle::new(),
            &snapshot,
            &target_path,
        );

        let (_image, outcome) = verifying.run(|_| {});
        let _ = std::fs::remove_file(&target_path);

        let failed = match outcome {
            VerifyOutcome::Failed(f) => f,
            other => panic!("expected Failed, got {other:?}"),
        };
        assert!(matches!(
            failed.reason,
            VerifyFailureReason::Mismatch {
                offset: 10,
                expected: 0x99,
                actual: 0x00
            }
        ));
    }

    // V13 (Quick's documented limitation, pinned). A corruption placed
    // strictly between the sampled windows is NOT detected -- Quick Verify
    // still reports Succeeded. This is not a bug: it is the exact,
    // documented boundary of what Quick Verify promises (see
    // `VerifyFailureReason`'s and the module-level doc comment's own
    // discussion). This test exists so a future change to the sampling
    // algorithm cannot silently make Quick secretly-Full (or vice versa)
    // without this test failing to flag the behavior change.
    #[test]
    fn quick_verify_does_not_detect_mismatch_in_an_unsampled_region() {
        let image_size = 20 * 1024 * 1024u64;
        let data = vec![0xAAu8; image_size as usize];
        let (target_path, image, sync_succeeded, snapshot) = gate_pass_sync_succeeded(
            "quick-unsampled-mismatch",
            &data,
            image_size,
            VerifyMode::Quick,
        );

        // Confirm this offset really does fall strictly outside every
        // sampled range before relying on that fact.
        let ranges = quick_verify_ranges(image_size);
        // For a 20 MiB image the three 4 MiB windows sit at [0,4), [8,12),
        // [16,20) MiB -- 6 MiB falls squarely in the [4,8) MiB gap between
        // the first and middle windows.
        let corrupt_offset = 6 * 1024 * 1024u64;
        assert!(
            ranges
                .iter()
                .all(|&(offset, len)| corrupt_offset < offset || corrupt_offset >= offset + len),
            "test setup bug: corruption offset falls inside a sampled range"
        );
        corrupt_byte_at(&target_path, corrupt_offset, 0xFF);

        let verifying = verifying_from_sync_succeeded(
            sync_succeeded,
            image,
            CancelHandle::new(),
            &snapshot,
            &target_path,
        );

        let (_image, outcome) = verifying.run(|_| {});
        let _ = std::fs::remove_file(&target_path);

        assert!(
            matches!(outcome, VerifyOutcome::Succeeded(_)),
            "expected Quick Verify to succeed despite the unsampled corruption, got {outcome:?}"
        );
    }

    // V14. Quick Verify against a non-RandomAccess `SelectedImage` fails
    // immediately with UnsupportedAccess, rather than silently falling back
    // to a sequential read-and-discard or to Full.
    #[test]
    fn quick_verify_refuses_a_non_random_access_source() {
        let image_size = 20 * 1024 * 1024u64;
        let data = vec![0xBBu8; image_size as usize];
        let (target_path, _image, sync_succeeded, snapshot) = gate_pass_sync_succeeded(
            "quick-unsupported-access",
            &data,
            image_size,
            VerifyMode::Quick,
        );

        // A `FailingAfterNBytesSource` with a huge `fail_after` never
        // actually fails a read in this test -- it exists here purely
        // because it reports `SequentialReplay`, unlike `FileImageSource`.
        let sequential_image = SelectedImage::new(Box::new(FailingAfterNBytesSource {
            logical_size: image_size,
            fail_after: usize::MAX,
        }));

        let verifying = verifying_from_sync_succeeded(
            sync_succeeded,
            sequential_image,
            CancelHandle::new(),
            &snapshot,
            &target_path,
        );

        let (_image, outcome) = verifying.run(|_| {});
        let _ = std::fs::remove_file(&target_path);

        let failed = match outcome {
            VerifyOutcome::Failed(f) => f,
            other => panic!("expected Failed, got {other:?}"),
        };
        assert!(matches!(
            failed.reason,
            VerifyFailureReason::UnsupportedAccess
        ));
        assert_eq!(failed.verified_bytes, 0);
    }

    // V15 (Full cancellation before any chunk). Requesting cancellation
    // before `run()` is even called yields Cancelled with verified_bytes ==
    // 0, and no chunk comparison is ever attempted.
    #[test]
    fn full_verify_cancel_before_any_chunk_is_cancelled_with_zero_verified_bytes() {
        let image_size = 5000u64;
        let data = vec![0xCCu8; image_size as usize];
        let (target_path, image, sync_succeeded, snapshot) =
            gate_pass_sync_succeeded("full-cancel-immediate", &data, image_size, VerifyMode::Full);

        let cancel = CancelHandle::new();
        cancel.request_cancel(CancelReason::UserRequested);

        let verifying =
            verifying_from_sync_succeeded(sync_succeeded, image, cancel, &snapshot, &target_path);

        let (_image, outcome) = verifying.run(|_| {});
        let _ = std::fs::remove_file(&target_path);

        let cancelled = match outcome {
            VerifyOutcome::Cancelled(c) => c,
            other => panic!("expected Cancelled, got {other:?}"),
        };
        assert_eq!(cancelled.mode, VerifyMode::Full);
        assert_eq!(cancelled.verified_bytes, 0);
    }

    // V16 (Full cancellation partway). Cancelling after the first chunk
    // leaves 0 < verified_bytes < image_size.
    #[test]
    fn full_verify_cancel_partway_reports_partial_verified_bytes() {
        let image_size = 3 * writer::DEFAULT_CHUNK_SIZE as u64;
        let data = vec![0xDDu8; image_size as usize];
        let (target_path, image, sync_succeeded, snapshot) =
            gate_pass_sync_succeeded("full-cancel-partial", &data, image_size, VerifyMode::Full);

        let cancel = CancelHandle::new();
        let verifying = verifying_from_sync_succeeded(
            sync_succeeded,
            image,
            cancel.clone(),
            &snapshot,
            &target_path,
        );

        let mut chunks_seen = 0;
        let (_image, outcome) = verifying.run(|_progress| {
            chunks_seen += 1;
            if chunks_seen == 1 {
                cancel.request_cancel(CancelReason::UserRequested);
            }
        });
        let _ = std::fs::remove_file(&target_path);

        let cancelled = match outcome {
            VerifyOutcome::Cancelled(c) => c,
            other => panic!("expected Cancelled, got {other:?}"),
        };
        assert!(cancelled.verified_bytes > 0);
        assert!(cancelled.verified_bytes < image_size);
    }

    // V17 (Quick cancellation partway). Cancelling after the first chunk of
    // the first sample range leaves 0 < verified_bytes < the sampled total.
    #[test]
    fn quick_verify_cancel_partway_reports_partial_verified_bytes() {
        let image_size = 20 * 1024 * 1024u64;
        let data = vec![0xEEu8; image_size as usize];
        let (target_path, image, sync_succeeded, snapshot) =
            gate_pass_sync_succeeded("quick-cancel-partial", &data, image_size, VerifyMode::Quick);

        let cancel = CancelHandle::new();
        let verifying = verifying_from_sync_succeeded(
            sync_succeeded,
            image,
            cancel.clone(),
            &snapshot,
            &target_path,
        );

        let mut chunks_seen = 0;
        let (_image, outcome) = verifying.run(|_progress| {
            chunks_seen += 1;
            if chunks_seen == 1 {
                cancel.request_cancel(CancelReason::UserRequested);
            }
        });
        let _ = std::fs::remove_file(&target_path);

        let cancelled = match outcome {
            VerifyOutcome::Cancelled(c) => c,
            other => panic!("expected Cancelled, got {other:?}"),
        };
        let expected_total = 3 * QUICK_VERIFY_WINDOW_SIZE;
        assert!(cancelled.verified_bytes > 0);
        assert!(cancelled.verified_bytes < expected_total);
    }

    // V18 (Verify start: Identity changed). A freshly re-fetched snapshot
    // with a different serial is rejected before any FD is ever opened.
    #[test]
    fn begin_verify_check_target_rejects_identity_changed() {
        let image_size = 1000u64;
        let data = vec![1u8; image_size as usize];
        let (target_path, image, sync_succeeded, snapshot) = gate_pass_sync_succeeded(
            "verify-start-identity-changed",
            &data,
            image_size,
            VerifyMode::Full,
        );

        let pending = match sync_succeeded.begin_verify(image, CancelHandle::new()) {
            VerifyStart::Pending(p) => p,
            VerifyStart::Skipped(..) => panic!("expected Pending"),
        };

        let mut changed = snapshot.clone();
        changed.serial = "DIFFERENT-SERIAL".to_string();

        let result = pending.check_target(SnapshotFetchOutcome::Found(changed));
        let _ = std::fs::remove_file(&target_path);

        let (_returned_image, error, diagnostics) = match result {
            Err(rejection) => rejection,
            Ok(_) => panic!("expected identity-changed rejection"),
        };
        assert!(matches!(error, VerifyStartError::IdentityChanged));

        // Verify Pre-flight Diagnostics (step 3+4): an Identity/Instance/
        // hazard rejection must still carry the diagnostics that produced
        // it -- only `SnapshotRefreshFailed` returns `None` (see the
        // dedicated test for that case below).
        let diagnostics =
            diagnostics.expect("diagnostics should be present for an Identity rejection");
        assert_eq!(diagnostics.identity(), IdentityComparison::Changed);
    }

    // V19 (Verify start: Instance recreated). A freshly re-fetched snapshot
    // with a different diskseq is rejected.
    #[test]
    fn begin_verify_check_target_rejects_instance_recreated() {
        let image_size = 1000u64;
        let data = vec![2u8; image_size as usize];
        let (target_path, image, sync_succeeded, snapshot) = gate_pass_sync_succeeded(
            "verify-start-instance-recreated",
            &data,
            image_size,
            VerifyMode::Full,
        );

        let pending = match sync_succeeded.begin_verify(image, CancelHandle::new()) {
            VerifyStart::Pending(p) => p,
            VerifyStart::Skipped(..) => panic!("expected Pending"),
        };

        let mut changed = snapshot.clone();
        changed.diskseq = Some(99999);

        let result = pending.check_target(SnapshotFetchOutcome::Found(changed));
        let _ = std::fs::remove_file(&target_path);

        let (_returned_image, error, diagnostics) = match result {
            Err(rejection) => rejection,
            Ok(_) => panic!("expected instance-recreated rejection"),
        };
        assert!(matches!(error, VerifyStartError::InstanceRecreated));

        let diagnostics =
            diagnostics.expect("diagnostics should be present for an Instance rejection");
        assert_eq!(diagnostics.instance(), InstanceComparison::Recreated);
    }

    // V20 (the key regression test). A freshly re-fetched snapshot whose
    // mount_points grew from empty to non-empty -- exactly the real
    // post-write auto-mount scenario observed with the MyPocketOS Hybrid ISO
    // -- does NOT block Verify. This is Built-in Verify implementation step
    // 3's entire reason for existing, now confirmed all the way through
    // step 4's actual `check_target()` call site.
    #[test]
    fn begin_verify_check_target_allows_newly_mounted_filesystem() {
        let image_size = 1000u64;
        let data = vec![3u8; image_size as usize];
        let (target_path, image, sync_succeeded, snapshot) = gate_pass_sync_succeeded(
            "verify-start-mount-increase",
            &data,
            image_size,
            VerifyMode::Full,
        );

        let pending = match sync_succeeded.begin_verify(image, CancelHandle::new()) {
            VerifyStart::Pending(p) => p,
            VerifyStart::Skipped(..) => panic!("expected Pending"),
        };

        let mut mounted = snapshot.clone();
        mounted.mount_points = vec!["/media/example".to_string()];

        let result = pending.check_target(SnapshotFetchOutcome::Found(mounted));
        let _ = std::fs::remove_file(&target_path);

        let ready = result.unwrap_or_else(|(_, error, _)| {
            panic!("expected Verify to still be allowed after a benign mount-state change, got {error:?}")
        });

        // The diagnostics carried inside `VerifyReadyToOpen` preserve the
        // observed mount-state change (for a future diagnostic log line to
        // report) even though it did not block Verify.
        assert_eq!(
            ready.diagnostics.current().mount_points,
            vec!["/media/example".to_string()]
        );
        assert!(ready.diagnostics.baseline().mount_points.is_empty());
        assert!(ready.diagnostics.hazards().is_empty());
    }

    // V20b. `read_only` going from `false` to `true` on the freshly
    // re-fetched snapshot does not block Verify (Step 3's deliberate
    // decision, see `core::verify_target_has_hard_hazard`'s doc comment),
    // and the diagnostics carried inside `VerifyReadyToOpen` preserve the
    // change for observability.
    #[test]
    fn begin_verify_check_target_allows_read_only_change_and_preserves_diagnostics() {
        let image_size = 1000u64;
        let data = vec![6u8; image_size as usize];
        let (target_path, image, sync_succeeded, snapshot) = gate_pass_sync_succeeded(
            "verify-start-read-only-change",
            &data,
            image_size,
            VerifyMode::Full,
        );

        let pending = match sync_succeeded.begin_verify(image, CancelHandle::new()) {
            VerifyStart::Pending(p) => p,
            VerifyStart::Skipped(..) => panic!("expected Pending"),
        };

        let mut read_only_now = snapshot.clone();
        read_only_now.read_only = true;

        let result = pending.check_target(SnapshotFetchOutcome::Found(read_only_now));
        let _ = std::fs::remove_file(&target_path);

        let ready = result.unwrap_or_else(|(_, error, _)| {
            panic!(
                "expected Verify to still be allowed after read_only becoming true, got {error:?}"
            )
        });

        assert!(!ready.diagnostics.baseline().read_only);
        assert!(ready.diagnostics.current().read_only);
        assert!(ready.diagnostics.hazards().is_empty());
    }

    // V21 (Verify start: unsafe target state). A freshly re-fetched
    // snapshot reporting the target as a system disk is rejected.
    #[test]
    fn begin_verify_check_target_rejects_unsafe_target_state() {
        let image_size = 1000u64;
        let data = vec![4u8; image_size as usize];
        let (target_path, image, sync_succeeded, snapshot) = gate_pass_sync_succeeded(
            "verify-start-unsafe-state",
            &data,
            image_size,
            VerifyMode::Full,
        );

        let pending = match sync_succeeded.begin_verify(image, CancelHandle::new()) {
            VerifyStart::Pending(p) => p,
            VerifyStart::Skipped(..) => panic!("expected Pending"),
        };

        let mut unsafe_snapshot = snapshot.clone();
        unsafe_snapshot.hint_system = true;

        let result = pending.check_target(SnapshotFetchOutcome::Found(unsafe_snapshot));
        let _ = std::fs::remove_file(&target_path);

        let (_returned_image, error, diagnostics) = match result {
            Err(rejection) => rejection,
            Ok(_) => panic!("expected unsafe-target-state rejection"),
        };
        assert!(matches!(error, VerifyStartError::UnsafeTargetState));

        let diagnostics =
            diagnostics.expect("diagnostics should be present for a hazard rejection");
        assert_eq!(diagnostics.hazards(), &[HardHazardReason::SystemDevice]);
    }

    // V21b. Identity insufficient (no usable serial on either side) is
    // rejected exactly like write time, and the diagnostics that produced
    // the rejection are still returned to the caller.
    #[test]
    fn begin_verify_check_target_rejects_identity_insufficient() {
        let image_size = 1000u64;
        let data = vec![7u8; image_size as usize];
        let (target_path, image, sync_succeeded, mut snapshot) = gate_pass_sync_succeeded(
            "verify-start-identity-insufficient",
            &data,
            image_size,
            VerifyMode::Full,
        );
        snapshot.serial = String::new();

        let pending = match sync_succeeded.begin_verify(image, CancelHandle::new()) {
            VerifyStart::Pending(p) => p,
            VerifyStart::Skipped(..) => panic!("expected Pending"),
        };

        // The freshly re-fetched snapshot also lacks a usable serial, so
        // Identity cannot be proven from either side.
        let current = snapshot.clone();
        let result = pending.check_target(SnapshotFetchOutcome::Found(current));
        let _ = std::fs::remove_file(&target_path);

        let (_returned_image, error, diagnostics) = match result {
            Err(rejection) => rejection,
            Ok(_) => panic!("expected identity-insufficient rejection"),
        };
        assert!(matches!(error, VerifyStartError::IdentityInsufficient));

        let diagnostics =
            diagnostics.expect("diagnostics should be present for an Identity rejection");
        assert_eq!(
            diagnostics.identity(),
            IdentityComparison::InsufficientIdentity
        );
    }

    // V21c. Instance insufficient (diskseq missing on the freshly re-fetched
    // snapshot) is rejected exactly like write time, and the diagnostics
    // that produced the rejection are still returned to the caller.
    #[test]
    fn begin_verify_check_target_rejects_instance_insufficient() {
        let image_size = 1000u64;
        let data = vec![8u8; image_size as usize];
        let (target_path, image, sync_succeeded, snapshot) = gate_pass_sync_succeeded(
            "verify-start-instance-insufficient",
            &data,
            image_size,
            VerifyMode::Full,
        );

        let pending = match sync_succeeded.begin_verify(image, CancelHandle::new()) {
            VerifyStart::Pending(p) => p,
            VerifyStart::Skipped(..) => panic!("expected Pending"),
        };

        let mut missing_diskseq = snapshot.clone();
        missing_diskseq.diskseq = None;

        let result = pending.check_target(SnapshotFetchOutcome::Found(missing_diskseq));
        let _ = std::fs::remove_file(&target_path);

        let (_returned_image, error, diagnostics) = match result {
            Err(rejection) => rejection,
            Ok(_) => panic!("expected instance-insufficient rejection"),
        };
        assert!(matches!(error, VerifyStartError::InstanceInsufficient));

        let diagnostics =
            diagnostics.expect("diagnostics should be present for an Instance rejection");
        assert_eq!(
            diagnostics.instance(),
            InstanceComparison::InsufficientInformation
        );
    }

    // V21d. Multiple simultaneous hazards (active_swap and complex_storage)
    // are all reported by the diagnostics, in the same deterministic order
    // `core::verify_target_hard_hazards` documents, regardless of the
    // rejection still collapsing to a single `UnsafeTargetState` error.
    #[test]
    fn begin_verify_check_target_reports_multiple_hazards_in_deterministic_order() {
        let image_size = 1000u64;
        let data = vec![9u8; image_size as usize];
        let (target_path, image, sync_succeeded, snapshot) = gate_pass_sync_succeeded(
            "verify-start-multiple-hazards",
            &data,
            image_size,
            VerifyMode::Full,
        );

        let pending = match sync_succeeded.begin_verify(image, CancelHandle::new()) {
            VerifyStart::Pending(p) => p,
            VerifyStart::Skipped(..) => panic!("expected Pending"),
        };

        let mut hazardous = snapshot.clone();
        hazardous.complex_storage = true;
        hazardous.active_swap = true;

        let result = pending.check_target(SnapshotFetchOutcome::Found(hazardous));
        let _ = std::fs::remove_file(&target_path);

        let (_returned_image, error, diagnostics) = match result {
            Err(rejection) => rejection,
            Ok(_) => panic!("expected unsafe-target-state rejection"),
        };
        assert!(matches!(error, VerifyStartError::UnsafeTargetState));

        let diagnostics =
            diagnostics.expect("diagnostics should be present for a hazard rejection");
        assert_eq!(
            diagnostics.hazards(),
            &[
                HardHazardReason::ActiveSwap,
                HardHazardReason::ComplexStorage
            ]
        );
    }

    // V21e. When the fresh `DeviceSnapshot` refresh itself fails
    // (`SnapshotFetchOutcome::NotFound`/`Error`), there is no `current`
    // snapshot to compare against, so no `VerifyTargetDiagnostics` can
    // exist -- the third element of the error tuple must be `None`, not a
    // diagnostics built from a stale or fabricated snapshot.
    #[test]
    fn begin_verify_check_target_snapshot_refresh_failed_has_no_diagnostics() {
        let image_size = 1000u64;
        let data = vec![11u8; image_size as usize];
        let (target_path, image, sync_succeeded, _snapshot) = gate_pass_sync_succeeded(
            "verify-start-snapshot-refresh-failed",
            &data,
            image_size,
            VerifyMode::Full,
        );

        let pending = match sync_succeeded.begin_verify(image, CancelHandle::new()) {
            VerifyStart::Pending(p) => p,
            VerifyStart::Skipped(..) => panic!("expected Pending"),
        };

        let result = pending.check_target(SnapshotFetchOutcome::NotFound);
        let _ = std::fs::remove_file(&target_path);

        let (_returned_image, error, diagnostics) = match result {
            Err(rejection) => rejection,
            Ok(_) => panic!("expected snapshot-refresh-failed rejection"),
        };
        assert!(matches!(error, VerifyStartError::SnapshotRefreshFailed));
        assert!(diagnostics.is_none());
    }

    // V21f (the success-path counterpart to V18/V19/V21 above). An
    // identical baseline/current snapshot produces clean diagnostics
    // (Identity Same, Instance SameInstance, no hazards) alongside the
    // successful `VerifyReadyToOpen`.
    #[test]
    fn begin_verify_check_target_success_diagnostics_are_clean() {
        let image_size = 1000u64;
        let data = vec![12u8; image_size as usize];
        let (target_path, image, sync_succeeded, snapshot) = gate_pass_sync_succeeded(
            "verify-start-clean-diagnostics",
            &data,
            image_size,
            VerifyMode::Full,
        );

        let pending = match sync_succeeded.begin_verify(image, CancelHandle::new()) {
            VerifyStart::Pending(p) => p,
            VerifyStart::Skipped(..) => panic!("expected Pending"),
        };

        let result = pending.check_target(SnapshotFetchOutcome::Found(snapshot.clone()));
        let _ = std::fs::remove_file(&target_path);

        let ready = result
            .unwrap_or_else(|(_, error, _)| panic!("check_target should succeed, got {error:?}"));

        assert_eq!(ready.diagnostics.identity(), IdentityComparison::Same);
        assert_eq!(
            ready.diagnostics.instance(),
            InstanceComparison::SameInstance
        );
        assert!(ready.diagnostics.hazards().is_empty());
    }

    // V22 (Verify start: FD binding mismatch). A read-only handle whose
    // kernel-reported size disagrees with the freshly re-verified snapshot
    // is rejected before any byte is read.
    #[test]
    fn begin_verify_finalize_rejects_fd_binding_mismatch() {
        let image_size = 1000u64;
        let data = vec![5u8; image_size as usize];
        let (target_path, image, sync_succeeded, snapshot) = gate_pass_sync_succeeded(
            "verify-start-fd-mismatch",
            &data,
            image_size,
            VerifyMode::Full,
        );

        let pending = match sync_succeeded.begin_verify(image, CancelHandle::new()) {
            VerifyStart::Pending(p) => p,
            VerifyStart::Skipped(..) => panic!("expected Pending"),
        };
        let ready = pending
            .check_target(SnapshotFetchOutcome::Found(snapshot.clone()))
            .unwrap_or_else(|(_, e, _)| panic!("check_target should succeed, got {e:?}"));

        let read_file = std::fs::OpenOptions::new()
            .read(true)
            .open(&target_path)
            .expect("reopen target read-only");
        let handle = OpenedDeviceHandle::from_file_for_test(read_file);

        let mut mismatched_metadata = fd_metadata_matching(&snapshot);
        mismatched_metadata.size = Some(snapshot.size + 1);

        let result = ready.finalize(Some(handle), Some(&mismatched_metadata));
        let _ = std::fs::remove_file(&target_path);

        let (_returned_image, error) = match result {
            Err(rejection) => rejection,
            Ok(_) => panic!("expected FD binding mismatch rejection"),
        };
        assert!(matches!(error, VerifyStartError::FdBindingMismatch));
    }

    // The Verify FD goes through the same diskseq check as the write FD: a
    // diskseq that could not be read is refused as insufficient, a different
    // one as a mismatch, before any byte is read.
    #[test]
    fn begin_verify_finalize_rejects_missing_or_different_fd_diskseq() {
        let cases = [(None, "missing"), (Some(1), "different")];

        for (diskseq_offset, label) in cases {
            let image_size = 1000u64;
            let data = vec![5u8; image_size as usize];
            let (target_path, image, sync_succeeded, snapshot) = gate_pass_sync_succeeded(
                &format!("verify-start-fd-diskseq-{label}"),
                &data,
                image_size,
                VerifyMode::Full,
            );

            let pending = match sync_succeeded.begin_verify(image, CancelHandle::new()) {
                VerifyStart::Pending(p) => p,
                VerifyStart::Skipped(..) => panic!("expected Pending"),
            };
            let ready = pending
                .check_target(SnapshotFetchOutcome::Found(snapshot.clone()))
                .unwrap_or_else(|(_, e, _)| panic!("check_target should succeed, got {e:?}"));

            let read_file = std::fs::OpenOptions::new()
                .read(true)
                .open(&target_path)
                .expect("reopen target read-only");
            let handle = OpenedDeviceHandle::from_file_for_test(read_file);

            let mut metadata = fd_metadata_matching(&snapshot);
            metadata.diskseq =
                diskseq_offset.and_then(|offset| snapshot.diskseq.map(|diskseq| diskseq + offset));

            let result = ready.finalize(Some(handle), Some(&metadata));
            let _ = std::fs::remove_file(&target_path);

            let (_returned_image, error) = match result {
                Err(rejection) => rejection,
                Ok(_) => panic!("{label}: expected an FD binding rejection"),
            };
            match label {
                "missing" => assert!(
                    matches!(error, VerifyStartError::FdBindingInsufficient),
                    "{label}: {error:?}"
                ),
                _ => assert!(
                    matches!(error, VerifyStartError::FdBindingMismatch),
                    "{label}: {error:?}"
                ),
            }
        }
    }

    // V23 (write FD retirement). begin_verify() closes the write-mode fd
    // for every VerifyMode, including None -- confirmed via the same
    // /proc/self/fd-target-comparison technique `sync_succeeded_holds_moved
    // _fd_until_dropped` above already uses for the write/sync path.
    #[test]
    fn begin_verify_drops_the_write_fd_for_every_verify_mode() {
        for mode in [VerifyMode::None, VerifyMode::Quick, VerifyMode::Full] {
            let image_size = 1000u64;
            let data = vec![6u8; image_size as usize];
            let (target_path, image, sync_succeeded, _snapshot) =
                gate_pass_sync_succeeded("verify-fd-retirement", &data, image_size, mode);

            // `SyncSucceeded` has no public accessor for the raw fd (by
            // design -- see `ActiveWrite`'s own doc comment), so this test
            // captures the fd number and its /proc target *before* calling
            // begin_verify() by reaching into the same module-private
            // structure this test module already has access to.
            let raw_fd = sync_succeeded_raw_fd_for_test(&sync_succeeded);
            let target_before = crate::execution::linux_access::fd_proc_target_for_test(raw_fd);

            let start = sync_succeeded.begin_verify(image, CancelHandle::new());
            // Whichever branch this is, the write fd must already be closed
            // by the time begin_verify() returns.
            crate::execution::linux_access::assert_fd_closed_for_test(
                raw_fd,
                target_before.as_deref(),
            );

            match start {
                VerifyStart::Skipped(_, _) => {}
                VerifyStart::Pending(_) => {}
            }

            let _ = std::fs::remove_file(&target_path);
        }
    }

    // Thin wrapper around `core::ActiveWrite::raw_fd_for_test()`, since
    // `SyncSucceeded.active` is a private field of this module -- exists so
    // `begin_verify_drops_the_write_fd_for_every_verify_mode` above can
    // reach it without exposing the field itself any more broadly.
    fn sync_succeeded_raw_fd_for_test(succeeded: &SyncSucceeded) -> std::os::fd::RawFd {
        succeeded.active.raw_fd_for_test()
    }

    // ---------------------------------------------------------------------
    // Pre-write source gate (`WritingExecution::write`).
    // ---------------------------------------------------------------------

    fn let_the_clock_tick() {
        std::thread::sleep(std::time::Duration::from_millis(20));
    }

    // An unchanged source passes the gate and is written normally through
    // the production entry point.
    #[test]
    fn unchanged_source_passes_the_pre_write_gate() {
        let data: Vec<u8> = (0..4096u32).map(|i| (i % 251) as u8).collect();
        let path = write_temp_image_file("gate-unchanged", &data);
        let selected = SelectedImage::new(Box::new(FileImageSource::new(&path).unwrap()));
        let (target_path, authorized) = gate_pass_active_write_for_image(
            "gate-unchanged-target",
            selected.selection(),
            data.len() as u64,
            true,
        );
        let target_path = target_path.expect("persistent temp target path");

        let execution = AuthorizedExecution::bind(authorized, selected).unwrap();
        let writing_execution = execution.begin_write(CancelHandle::new()).unwrap();
        let (_image, outcome) = writing_execution.write(|_| {});

        assert!(matches!(outcome, WriteAttemptOutcome::Succeeded(_)));
        assert_eq!(std::fs::read(&target_path).unwrap(), data);
        let _ = std::fs::remove_file(&target_path);
        let _ = std::fs::remove_file(&path);
    }

    // A source changed after the Gate (after bind and after the write-time
    // reader was opened) is caught at the last moment: the outcome is a
    // typed `SourceChanged` failure, nothing reaches the target, and being
    // `Failed` it cannot proceed to sync or Verify.
    #[test]
    fn changed_source_is_refused_before_any_byte_is_written() {
        type Mutation = fn(&std::path::Path);
        let mutations: [(&str, Mutation); 3] = [
            ("append", |path| {
                use std::io::Write as _;
                let mut file = std::fs::OpenOptions::new().append(true).open(path).unwrap();
                file.write_all(b"appended").unwrap();
            }),
            ("overwrite", |path| {
                use std::os::unix::fs::FileExt as _;
                let file = std::fs::OpenOptions::new().write(true).open(path).unwrap();
                file.write_all_at(b"XXXX", 0).unwrap();
            }),
            ("rename", |path| {
                std::fs::rename(path, path.with_extension("moved")).unwrap();
            }),
        ];

        for (name, mutate) in mutations {
            let data: Vec<u8> = (0..4096u32).map(|i| (i % 251) as u8).collect();
            let path = write_temp_image_file(&format!("gate-{name}"), &data);
            let selected = SelectedImage::new(Box::new(FileImageSource::new(&path).unwrap()));
            let (target_path, authorized) = gate_pass_active_write_for_image(
                &format!("gate-{name}-target"),
                selected.selection(),
                data.len() as u64,
                true,
            );
            let target_path = target_path.expect("persistent temp target path");

            let execution = AuthorizedExecution::bind(authorized, selected).unwrap();
            let writing_execution = execution.begin_write(CancelHandle::new()).unwrap();

            let_the_clock_tick();
            mutate(&path);

            let (_image, outcome) = writing_execution
                .write(|_| panic!("{name}: no progress may be reported: nothing may be written"));

            let failed = match outcome {
                WriteAttemptOutcome::Failed(failed) => failed,
                other => panic!("{name}: expected Failed, got {other:?}"),
            };
            assert!(
                matches!(failed.cause, WriteJobFailureCause::SourceChanged(_)),
                "{name}: {:?}",
                failed.cause
            );
            assert_eq!(failed.bytes_written, 0, "{name}");
            assert!(!failed.target_may_be_modified, "{name}");
            assert!(failed.retry_requires_fresh_gate, "{name}");
            assert_eq!(failed.stage, WriteStage::Writing, "{name}");

            let target_contents = std::fs::read(&target_path).unwrap();
            assert!(
                target_contents.is_empty(),
                "{name}: target must be untouched"
            );

            let _ = std::fs::remove_file(&target_path);
            let _ = std::fs::remove_file(&path);
            let _ = std::fs::remove_file(path.with_extension("moved"));
        }
    }

    // ---------------------------------------------------------------------
    // Source checkpoint lifecycle: post-write (`WritingExecution::write`),
    // pre-verify and post-verify (`Verifying::run`). The source is changed
    // from inside a progress callback, which runs at a known point of the
    // write/Verify loop -- no hook exists in production code.
    // ---------------------------------------------------------------------

    type SourceMutation = fn(&std::path::Path);

    // Changes that leave the first `logical_size` bytes as they were, so a
    // Verify comparing them would still match: only the checkpoints can
    // notice them.
    fn content_preserving_source_mutations() -> [(&'static str, SourceMutation); 3] {
        [
            ("append", |path| {
                use std::io::Write as _;
                let mut file = std::fs::OpenOptions::new().append(true).open(path).unwrap();
                file.write_all(b"appended").unwrap();
            }),
            ("rewrite-same-bytes", |path| {
                use std::os::unix::fs::FileExt as _;
                let file = std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(path)
                    .unwrap();
                let mut first = [0u8; 16];
                file.read_exact_at(&mut first, 0).unwrap();
                file.write_all_at(&first, 0).unwrap();
            }),
            ("rename", |path| {
                std::fs::rename(path, path.with_extension("moved")).unwrap();
            }),
        ]
    }

    fn remove_source_files(path: &std::path::Path) {
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(path.with_extension("moved"));
    }

    fn patterned_data(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i % 251) as u8).collect()
    }

    // More than one write/Verify chunk, so "after the first chunk" is a
    // point in the middle of the loop.
    fn multi_chunk_data() -> Vec<u8> {
        patterned_data(writer::DEFAULT_CHUNK_SIZE * 2 + 4096)
    }

    // Write and sync through the production entry points, both expected to
    // succeed (the post-write checkpoint included).
    fn write_and_sync(
        writing_execution: WritingExecution,
        context: &str,
    ) -> (SelectedImage, SyncSucceeded) {
        let (image, outcome) = writing_execution.write(|_| {});
        let write_succeeded = match outcome {
            WriteAttemptOutcome::Succeeded(s) => s,
            other => panic!("{context}: expected write success, got {other:?}"),
        };
        match write_succeeded.begin_sync().sync() {
            SyncAttemptOutcome::Succeeded(s) => (image, s),
            other => panic!("{context}: expected sync success, got {other:?}"),
        }
    }

    fn expect_write_source_changed(outcome: WriteAttemptOutcome, context: &str) -> Failed {
        let failed = match outcome {
            WriteAttemptOutcome::Failed(failed) => failed,
            other => panic!("{context}: expected Failed, got {other:?}"),
        };
        assert!(
            matches!(failed.cause, WriteJobFailureCause::SourceChanged(_)),
            "{context}: {:?}",
            failed.cause
        );
        failed
    }

    fn expect_verify_source_changed(outcome: VerifyOutcome, context: &str) -> VerifyFailed {
        let failed = match outcome {
            VerifyOutcome::Failed(failed) => failed,
            other => panic!("{context}: expected Failed, got {other:?}"),
        };
        assert!(
            matches!(failed.reason, VerifyFailureReason::SourceChanged(_)),
            "{context}: {:?}",
            failed.reason
        );
        failed
    }

    // Post-write: the source changes after its last byte was read and
    // written (the final progress callback), before the writer returns.
    // The write happened, but it is not reported as a success: it is a
    // typed `SourceChanged` with the real byte count and the target marked
    // as modified, and without a `WriteSucceeded` there is no way to sync or
    // verify.
    #[test]
    fn post_write_source_change_turns_the_write_into_a_failure() {
        for (name, mutate) in content_preserving_source_mutations() {
            let data = patterned_data(64 * 1024);
            let path = write_temp_image_file(&format!("post-write-{name}"), &data);
            let (target_path, writing_execution, _snapshot) = gate_pass_writing_execution(
                &format!("post-write-{name}"),
                &path,
                data.len() as u64,
                VerifyMode::Full,
                CancelHandle::new(),
            );

            let_the_clock_tick();
            let total = data.len() as u64;
            let (_image, outcome) = writing_execution.write(|progress| {
                if progress.bytes_written == total {
                    mutate(&path);
                }
            });

            let failed = expect_write_source_changed(outcome, name);
            assert_eq!(failed.stage, WriteStage::Writing, "{name}");
            assert_eq!(failed.bytes_written, total, "{name}");
            assert!(failed.target_may_be_modified, "{name}");
            assert!(failed.retry_requires_fresh_gate, "{name}");
            assert_eq!(
                std::fs::read(&target_path).unwrap(),
                data,
                "{name}: the write itself did happen"
            );

            let _ = std::fs::remove_file(&target_path);
            remove_source_files(&path);
        }
    }

    // Post-write runs for `VerifyMode::None` too: not verifying does not
    // mean not checking the source after the write.
    #[test]
    fn post_write_checkpoint_runs_without_verify() {
        let data = patterned_data(64 * 1024);
        let path = write_temp_image_file("post-write-verify-none", &data);
        let (target_path, writing_execution, _snapshot) = gate_pass_writing_execution(
            "post-write-verify-none",
            &path,
            data.len() as u64,
            VerifyMode::None,
            CancelHandle::new(),
        );

        let_the_clock_tick();
        let total = data.len() as u64;
        let (_image, outcome) = writing_execution.write(|progress| {
            if progress.bytes_written == total {
                std::fs::rename(&path, path.with_extension("moved")).unwrap();
            }
        });

        let failed = expect_write_source_changed(outcome, "verify none");
        assert_eq!(failed.bytes_written, total);
        assert!(failed.target_may_be_modified);
        assert!(failed.retry_requires_fresh_gate);

        let _ = std::fs::remove_file(&target_path);
        remove_source_files(&path);
    }

    // Pre-verify: write, post-write check and sync all succeed; the source
    // then changes while the target pre-flight runs. Verify does not
    // start: no byte is compared and no progress is reported.
    #[test]
    fn pre_verify_source_change_prevents_verify_from_starting() {
        for mode in [VerifyMode::Quick, VerifyMode::Full] {
            for (name, mutate) in content_preserving_source_mutations() {
                let context = format!("{mode:?} {name}");
                let data = patterned_data(64 * 1024);
                let path = write_temp_image_file(&format!("pre-verify-{name}"), &data);
                let (target_path, writing_execution, snapshot) = gate_pass_writing_execution(
                    &format!("pre-verify-{mode:?}-{name}"),
                    &path,
                    data.len() as u64,
                    mode,
                    CancelHandle::new(),
                );
                let (image, sync_succeeded) = write_and_sync(writing_execution, &context);

                let verifying = verifying_from_sync_succeeded(
                    sync_succeeded,
                    image,
                    CancelHandle::new(),
                    &snapshot,
                    &target_path,
                );

                let_the_clock_tick();
                mutate(&path);

                let (_image, outcome) =
                    verifying.run(|_| panic!("{context}: Verify must not start, so no progress"));

                let failed = expect_verify_source_changed(outcome, &context);
                assert_eq!(failed.mode, mode, "{context}");
                assert_eq!(failed.verified_bytes, 0, "{context}");

                let _ = std::fs::remove_file(&target_path);
                remove_source_files(&path);
            }
        }
    }

    // Post-verify: the source changes during Verify (at its final progress
    // callback, after every compared byte matched). The matching result is
    // not accepted.
    #[test]
    fn post_verify_source_change_rejects_a_matching_verify() {
        for mode in [VerifyMode::Quick, VerifyMode::Full] {
            for (name, mutate) in content_preserving_source_mutations() {
                let context = format!("{mode:?} {name}");
                let data = patterned_data(64 * 1024);
                let path = write_temp_image_file(&format!("post-verify-{name}"), &data);
                let (target_path, writing_execution, snapshot) = gate_pass_writing_execution(
                    &format!("post-verify-{mode:?}-{name}"),
                    &path,
                    data.len() as u64,
                    mode,
                    CancelHandle::new(),
                );
                let (image, sync_succeeded) = write_and_sync(writing_execution, &context);

                let verifying = verifying_from_sync_succeeded(
                    sync_succeeded,
                    image,
                    CancelHandle::new(),
                    &snapshot,
                    &target_path,
                );

                let_the_clock_tick();
                let mut progress_seen = false;
                let (_image, outcome) = verifying.run(|progress| {
                    progress_seen = true;
                    if progress.verified_bytes == progress.total_bytes {
                        mutate(&path);
                    }
                });

                assert!(progress_seen, "{context}: Verify must have run");
                let failed = expect_verify_source_changed(outcome, &context);
                assert_eq!(failed.mode, mode, "{context}");
                assert_eq!(failed.verified_bytes, data.len() as u64, "{context}");

                let _ = std::fs::remove_file(&target_path);
                remove_source_files(&path);
            }
        }
    }

    // An unchanged source passes all four checkpoints (pre-write,
    // post-write, pre-verify, post-verify) and every mode ends exactly as
    // before: None skipped, Quick and Full succeeded over the whole (small)
    // image.
    #[test]
    fn unchanged_source_passes_every_checkpoint_in_every_verify_mode() {
        for mode in [VerifyMode::None, VerifyMode::Quick, VerifyMode::Full] {
            let context = format!("{mode:?}");
            let data = patterned_data(64 * 1024);
            let path = write_temp_image_file(&format!("lifecycle-{mode:?}"), &data);
            let (target_path, writing_execution, snapshot) = gate_pass_writing_execution(
                &format!("lifecycle-{mode:?}"),
                &path,
                data.len() as u64,
                mode,
                CancelHandle::new(),
            );
            let (image, sync_succeeded) = write_and_sync(writing_execution, &context);
            assert_eq!(std::fs::read(&target_path).unwrap(), data, "{context}");

            let succeeded = match mode {
                VerifyMode::None => match sync_succeeded.begin_verify(image, CancelHandle::new()) {
                    VerifyStart::Skipped(_, succeeded) => succeeded,
                    VerifyStart::Pending(_) => panic!("{context}: expected Skipped"),
                },
                VerifyMode::Quick | VerifyMode::Full => {
                    let verifying = verifying_from_sync_succeeded(
                        sync_succeeded,
                        image,
                        CancelHandle::new(),
                        &snapshot,
                        &target_path,
                    );
                    match verifying.run(|_| {}) {
                        (_, VerifyOutcome::Succeeded(succeeded)) => succeeded,
                        (_, other) => panic!("{context}: expected Succeeded, got {other:?}"),
                    }
                }
            };

            assert_eq!(succeeded.mode, mode, "{context}");
            assert_eq!(succeeded.skipped, mode == VerifyMode::None, "{context}");
            let expected_verified = if mode == VerifyMode::None {
                0
            } else {
                data.len() as u64
            };
            assert_eq!(succeeded.verified_bytes, expected_verified, "{context}");

            let _ = std::fs::remove_file(&target_path);
            remove_source_files(&path);
        }
    }

    // The contract runs through the last read of the source for each Verify
    // mode. The source changes after the post-write checkpoint passed,
    // before sync. With `None` the source is never read again, so the bytes
    // already written are unaffected and the job succeeds. Quick / Full read
    // the source again, and since checks compare against the open-time
    // snapshot (cumulative), Verify is refused before it starts.
    #[test]
    fn source_identity_contract_extends_through_last_source_read() {
        for mode in [VerifyMode::None, VerifyMode::Quick, VerifyMode::Full] {
            let context = format!("{mode:?}");
            let data = patterned_data(64 * 1024);
            let path = write_temp_image_file(&format!("contract-{mode:?}"), &data);
            let (target_path, writing_execution, snapshot) = gate_pass_writing_execution(
                &format!("contract-{mode:?}"),
                &path,
                data.len() as u64,
                mode,
                CancelHandle::new(),
            );

            let (image, outcome) = writing_execution.write(|_| {});
            let write_succeeded = match outcome {
                WriteAttemptOutcome::Succeeded(s) => s,
                other => panic!("{context}: expected post-write to pass, got {other:?}"),
            };

            let_the_clock_tick();
            std::fs::rename(&path, path.with_extension("moved")).unwrap();

            let sync_succeeded = match write_succeeded.begin_sync().sync() {
                SyncAttemptOutcome::Succeeded(s) => s,
                other => panic!("{context}: expected sync success, got {other:?}"),
            };

            match mode {
                VerifyMode::None => match sync_succeeded.begin_verify(image, CancelHandle::new()) {
                    VerifyStart::Skipped(_, succeeded) => assert!(succeeded.skipped),
                    VerifyStart::Pending(_) => panic!("{context}: expected Skipped"),
                },
                VerifyMode::Quick | VerifyMode::Full => {
                    let verifying = verifying_from_sync_succeeded(
                        sync_succeeded,
                        image,
                        CancelHandle::new(),
                        &snapshot,
                        &target_path,
                    );
                    let (_image, outcome) =
                        verifying.run(|_| panic!("{context}: Verify must not start"));
                    let failed = expect_verify_source_changed(outcome, &context);
                    assert_eq!(failed.verified_bytes, 0, "{context}");
                }
            }
            assert_eq!(std::fs::read(&target_path).unwrap(), data, "{context}");

            let _ = std::fs::remove_file(&target_path);
            remove_source_files(&path);
        }
    }

    // A write cancelled partway, with the source also changed before the
    // writer stopped, stays `Cancelled`: the post-write checkpoint only
    // looks at a successful write.
    #[test]
    fn write_cancel_is_not_replaced_by_source_changed() {
        let data = multi_chunk_data();
        let path = write_temp_image_file("priority-write-cancel", &data);
        let cancel = CancelHandle::new();
        let (target_path, writing_execution, _snapshot) = gate_pass_writing_execution(
            "priority-write-cancel",
            &path,
            data.len() as u64,
            VerifyMode::Full,
            cancel.clone(),
        );

        let_the_clock_tick();
        let (_image, outcome) = writing_execution.write(|progress| {
            if progress.bytes_written == writer::DEFAULT_CHUNK_SIZE as u64 {
                std::fs::rename(&path, path.with_extension("moved")).unwrap();
                cancel.request_cancel(CancelReason::UserRequested);
            }
        });

        let cancelled = match outcome {
            WriteAttemptOutcome::Cancelled(cancelled) => cancelled,
            other => panic!("expected Cancelled, got {other:?}"),
        };
        assert_eq!(cancelled.bytes_written, writer::DEFAULT_CHUNK_SIZE as u64);
        assert!(cancelled.target_may_be_modified);

        let _ = std::fs::remove_file(&target_path);
        remove_source_files(&path);
    }

    // A write that failed on its own (the source was truncated mid-write,
    // so it ran short) stays that failure, not `SourceChanged`.
    #[test]
    fn write_failure_is_not_replaced_by_source_changed() {
        let data = multi_chunk_data();
        let path = write_temp_image_file("priority-write-failure", &data);
        let (target_path, writing_execution, _snapshot) = gate_pass_writing_execution(
            "priority-write-failure",
            &path,
            data.len() as u64,
            VerifyMode::Full,
            CancelHandle::new(),
        );

        let (_image, outcome) = writing_execution.write(|progress| {
            if progress.bytes_written == writer::DEFAULT_CHUNK_SIZE as u64 {
                let file = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
                file.set_len(writer::DEFAULT_CHUNK_SIZE as u64).unwrap();
            }
        });

        let failed = match outcome {
            WriteAttemptOutcome::Failed(failed) => failed,
            other => panic!("expected Failed, got {other:?}"),
        };
        assert!(
            matches!(
                failed.cause,
                WriteJobFailureCause::Write(WriteError::SourceTooShort { .. })
            ),
            "{:?}",
            failed.cause
        );

        let _ = std::fs::remove_file(&target_path);
        remove_source_files(&path);
    }

    // Verify outcomes that are already a failure or a cancellation stay as
    // they are when the source also changed during Verify: the post-verify
    // checkpoint only looks at a successful comparison.
    #[test]
    fn verify_failure_and_cancel_are_not_replaced_by_source_changed() {
        enum Expect {
            Cancelled,
            Mismatch,
            SourceUnexpectedEof,
        }
        let cases = [
            ("cancel", Expect::Cancelled),
            ("mismatch", Expect::Mismatch),
            ("source-eof", Expect::SourceUnexpectedEof),
        ];

        for (name, expect) in cases {
            let data = multi_chunk_data();
            let path = write_temp_image_file(&format!("priority-verify-{name}"), &data);
            let (target_path, writing_execution, snapshot) = gate_pass_writing_execution(
                &format!("priority-verify-{name}"),
                &path,
                data.len() as u64,
                VerifyMode::Full,
                CancelHandle::new(),
            );
            let (image, sync_succeeded) = write_and_sync(writing_execution, name);
            if matches!(expect, Expect::Mismatch) {
                let last = data.len() as u64 - 1;
                corrupt_byte_at(&target_path, last, !data[data.len() - 1]);
            }

            let cancel = CancelHandle::new();
            let verifying = verifying_from_sync_succeeded(
                sync_succeeded,
                image,
                cancel.clone(),
                &snapshot,
                &target_path,
            );

            let_the_clock_tick();
            let (_image, outcome) = verifying.run(|progress| {
                if progress.verified_bytes != writer::DEFAULT_CHUNK_SIZE as u64 {
                    return;
                }
                match expect {
                    Expect::Cancelled => {
                        std::fs::rename(&path, path.with_extension("moved")).unwrap();
                        cancel.request_cancel(CancelReason::UserRequested);
                    }
                    Expect::Mismatch => {
                        std::fs::rename(&path, path.with_extension("moved")).unwrap();
                    }
                    Expect::SourceUnexpectedEof => {
                        let file = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
                        file.set_len(writer::DEFAULT_CHUNK_SIZE as u64).unwrap();
                    }
                }
            });

            match (expect, outcome) {
                (Expect::Cancelled, VerifyOutcome::Cancelled(cancelled)) => {
                    assert_eq!(cancelled.verified_bytes, writer::DEFAULT_CHUNK_SIZE as u64);
                }
                (Expect::Mismatch, VerifyOutcome::Failed(failed)) => {
                    assert!(
                        matches!(failed.reason, VerifyFailureReason::Mismatch { .. }),
                        "{name}: {:?}",
                        failed.reason
                    );
                }
                (Expect::SourceUnexpectedEof, VerifyOutcome::Failed(failed)) => {
                    assert!(
                        matches!(failed.reason, VerifyFailureReason::SourceUnexpectedEof),
                        "{name}: {:?}",
                        failed.reason
                    );
                }
                (_, other) => panic!("{name}: unexpected outcome {other:?}"),
            }

            let _ = std::fs::remove_file(&target_path);
            remove_source_files(&path);
        }
    }

    // ---------------------------------------------------------------------
    // gzip through the production preparation (`crate::prepare_compressed_image`:
    // Quick refusal, Preflight bounded by the target's capacity,
    // post-Preflight source check) and then the existing write / Verify path.
    // ---------------------------------------------------------------------

    fn temp_gzip_image(tag: &str, payload: &[u8]) -> std::path::PathBuf {
        use std::io::Write as _;

        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(payload).unwrap();
        let path = write_temp_image_file(tag, &encoder.finish().unwrap());
        let gz = path.with_extension("img.gz");
        std::fs::rename(&path, &gz).unwrap();
        gz
    }

    fn open_gzip_image(path: &std::path::Path) -> crate::image_source::CompressedImageFile {
        use crate::image_source::{OpenedImage, open_image};

        match open_image(path) {
            Ok(OpenedImage::Compressed(file)) => file,
            other => panic!("expected a compressed image, got {other:?}"),
        }
    }

    // The production preparation, as `run_write_test` does it, with the
    // target's capacity as the Preflight limit.
    fn prepared_gzip_image(
        path: &std::path::Path,
        verify_mode: VerifyMode,
        target_capacity: u64,
    ) -> SelectedImage {
        let source = crate::prepare_compressed_image(
            open_gzip_image(path),
            verify_mode,
            target_capacity,
            || false,
            |_| {},
        )
        .unwrap_or_else(|rejection| panic!("gzip preparation failed: {rejection:?}"));
        SelectedImage::new(Box::new(source))
    }

    // None: Preflight -> write (a replay) -> sync -> Verify skipped; the
    // target holds the decoded payload. Full: the same, then Full Verify
    // decodes a second, fresh replay and matches every byte.
    #[test]
    fn gzip_image_writes_through_the_production_pipeline() {
        let payload = patterned_data(writer::DEFAULT_CHUNK_SIZE * 2 + 777);

        for mode in [VerifyMode::None, VerifyMode::Full] {
            let context = format!("{mode:?}");
            let path = temp_gzip_image(&format!("gzip-pipeline-{mode:?}"), &payload);
            let image = prepared_gzip_image(&path, mode, payload.len() as u64);
            assert_eq!(image.logical_size(), payload.len() as u64);
            assert_eq!(image.access(), ImageSourceAccess::SequentialReplay);

            let (target_path, writing_execution, snapshot) = gate_pass_writing_execution_for_image(
                &format!("gzip-pipeline-{mode:?}"),
                image,
                payload.len() as u64,
                mode,
                CancelHandle::new(),
            );
            let (image, sync_succeeded) = write_and_sync(writing_execution, &context);
            assert_eq!(std::fs::read(&target_path).unwrap(), payload, "{context}");

            match mode {
                VerifyMode::None => match sync_succeeded.begin_verify(image, CancelHandle::new()) {
                    VerifyStart::Skipped(_, succeeded) => assert!(succeeded.skipped),
                    VerifyStart::Pending(_) => panic!("{context}: expected Skipped"),
                },
                _ => {
                    let verifying = verifying_from_sync_succeeded(
                        sync_succeeded,
                        image,
                        CancelHandle::new(),
                        &snapshot,
                        &target_path,
                    );
                    match verifying.run(|_| {}) {
                        (_, VerifyOutcome::Succeeded(succeeded)) => {
                            assert_eq!(succeeded.verified_bytes, payload.len() as u64);
                        }
                        (_, other) => panic!("{context}: expected Succeeded, got {other:?}"),
                    }
                }
            }

            let _ = std::fs::remove_file(&target_path);
            let _ = std::fs::remove_file(&path);
        }
    }

    // L2: even if a compressed image reached the Gate with Quick authorized
    // (bypassing the CLI's L1 refusal), `bind()` refuses it before any write:
    // the target stays empty. L3 (`UnsupportedAccess` in the verifier) is
    // covered by `quick_verify_refuses_a_non_random_access_source`.
    #[test]
    fn gzip_image_with_quick_verify_is_refused_at_bind() {
        use crate::image_source::compressed::{CompressedImageSource, PreflightOptions};

        let payload = patterned_data(64 * 1024);
        let path = temp_gzip_image("gzip-quick-l2", &payload);
        let options = PreflightOptions {
            max_logical_size: u64::MAX,
        };
        let preflighted = open_gzip_image(&path)
            .preflight(options, || false, |_| {})
            .unwrap();
        let image = SelectedImage::new(Box::new(CompressedImageSource::new(preflighted)));

        let (target_path, authorized, _snapshot) = gate_pass_authorized_for_image(
            "gzip-quick-l2",
            &image,
            payload.len() as u64,
            VerifyMode::Quick,
        );
        let result = AuthorizedExecution::bind(authorized, image);

        assert!(matches!(
            result,
            Err(ImageBindingError::QuickVerifyUnsupported)
        ));
        assert!(std::fs::read(&target_path).unwrap().is_empty());
        let _ = std::fs::remove_file(&target_path);
        let _ = std::fs::remove_file(&path);
    }

    // The path is replaced after the image was prepared: the prepared
    // source keeps the file it opened, and the pre-write source gate refuses
    // the write -- the replacement is never read and nothing is written.
    #[test]
    fn gzip_image_path_replacement_after_preparation_is_refused() {
        let payload = patterned_data(64 * 1024);
        let path = temp_gzip_image("gzip-replaced", &payload);
        let image = prepared_gzip_image(&path, VerifyMode::Full, payload.len() as u64);

        let (target_path, writing_execution, _snapshot) = gate_pass_writing_execution_for_image(
            "gzip-replaced",
            image,
            payload.len() as u64,
            VerifyMode::Full,
            CancelHandle::new(),
        );

        std::thread::sleep(std::time::Duration::from_millis(20));
        std::fs::rename(&path, path.with_extension("moved")).unwrap();
        std::fs::write(&path, b"a different file").unwrap();

        let (_image, outcome) =
            writing_execution.write(|_| panic!("nothing may be written after the source changed"));
        let failed = expect_write_source_changed(outcome, "replaced");
        assert_eq!(failed.bytes_written, 0);
        assert!(!failed.target_may_be_modified);
        assert!(std::fs::read(&target_path).unwrap().is_empty());

        let _ = std::fs::remove_file(&target_path);
        remove_source_files(&path);
    }

    // ---------------------------------------------------------------------
    // xz through the same production preparation and the same write /
    // Verify path as gzip. Nothing here is xz-specific except the file: the
    // Gate, `bind()`, the writer, the source checkpoints and Verify are the
    // generic ones, reached through the `CompressedImageSource` that
    // `crate::prepare_compressed_image` returns.
    // ---------------------------------------------------------------------

    fn xz_bytes(payload: &[u8], check: liblzma::stream::Check) -> Vec<u8> {
        use std::io::Write as _;

        let stream = liblzma::stream::Stream::new_easy_encoder(0, check).unwrap();
        let mut encoder = liblzma::write::XzEncoder::new_stream(Vec::new(), stream);
        encoder.write_all(payload).unwrap();
        encoder.finish().unwrap()
    }

    fn temp_xz_image(tag: &str, contents: &[u8]) -> std::path::PathBuf {
        let path = write_temp_image_file(tag, contents);
        let xz = path.with_extension("img.xz");
        std::fs::rename(&path, &xz).unwrap();
        xz
    }

    fn prepared_xz_source(
        path: &std::path::Path,
        verify_mode: VerifyMode,
        target_capacity: u64,
    ) -> crate::image_source::compressed::CompressedImageSource {
        let compressed = open_gzip_image(path); // any compressed image; xz here
        assert_eq!(
            compressed.format(),
            crate::image_source::CompressionFormat::Xz
        );
        crate::prepare_compressed_image(compressed, verify_mode, target_capacity, || false, |_| {})
            .unwrap_or_else(|rejection| panic!("xz preparation failed: {rejection:?}"))
    }

    // Counts `open_reader()` calls on the source it wraps, delegating
    // everything else unchanged -- to observe how many fresh replays the
    // generic write / Verify path opens.
    struct CountingSource {
        inner: crate::image_source::compressed::CompressedImageSource,
        opened: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    }

    impl ImageSource for CountingSource {
        fn logical_size(&self) -> u64 {
            self.inner.logical_size()
        }

        fn access(&self) -> ImageSourceAccess {
            self.inner.access()
        }

        fn open_reader(&self) -> io::Result<Box<dyn Read>> {
            self.opened
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.inner.open_reader()
        }

        fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
            self.inner.read_at(offset, buf)
        }

        fn revalidate_identity(&self) -> Result<(), SourceChanged> {
            self.inner.revalidate_identity()
        }
    }

    // A multi-chunk payload as one xz stream, and split over concatenated
    // streams (different checks) with Stream Padding between and after.
    fn xz_pipeline_fixtures(payload: &[u8]) -> [(&'static str, Vec<u8>); 2] {
        use liblzma::stream::Check;

        let third = payload.len() / 3;
        [
            ("single", xz_bytes(payload, Check::Crc64)),
            (
                "concatenated",
                [
                    xz_bytes(&payload[..third], Check::Crc32),
                    vec![0u8; 8],
                    xz_bytes(&payload[third..2 * third], Check::Sha256),
                    xz_bytes(&payload[2 * third..], Check::Crc64),
                    vec![0u8; 4],
                ]
                .concat(),
            ),
        ]
    }

    // None: Preflight -> one fresh replay for the write -> sync -> Verify
    // skipped (no second replay). Full: the same, then Full Verify opens a
    // second, fresh replay and matches every byte. The target holds the
    // decoded bytes; the writer only ever saw a plain byte stream.
    #[test]
    fn xz_image_writes_through_the_production_pipeline() {
        let payload = patterned_data(writer::DEFAULT_CHUNK_SIZE * 2 + 777);

        for (name, contents) in xz_pipeline_fixtures(&payload) {
            for mode in [VerifyMode::None, VerifyMode::Full] {
                let context = format!("{name} {mode:?}");
                let path = temp_xz_image(&format!("xz-pipeline-{name}-{mode:?}"), &contents);
                let opened = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
                let source = CountingSource {
                    inner: prepared_xz_source(&path, mode, payload.len() as u64),
                    opened: std::sync::Arc::clone(&opened),
                };
                let image = SelectedImage::new(Box::new(source));
                assert_eq!(image.logical_size(), payload.len() as u64, "{context}");
                assert_eq!(image.access(), ImageSourceAccess::SequentialReplay);

                let (target_path, writing_execution, snapshot) =
                    gate_pass_writing_execution_for_image(
                        &format!("xz-pipeline-{name}-{mode:?}"),
                        image,
                        payload.len() as u64,
                        mode,
                        CancelHandle::new(),
                    );
                assert_eq!(opened.load(std::sync::atomic::Ordering::SeqCst), 1);
                let (image, sync_succeeded) = write_and_sync(writing_execution, &context);
                assert_eq!(std::fs::read(&target_path).unwrap(), payload, "{context}");

                match mode {
                    VerifyMode::None => {
                        match sync_succeeded.begin_verify(image, CancelHandle::new()) {
                            VerifyStart::Skipped(_, succeeded) => assert!(succeeded.skipped),
                            VerifyStart::Pending(_) => panic!("{context}: expected Skipped"),
                        }
                        assert_eq!(
                            opened.load(std::sync::atomic::Ordering::SeqCst),
                            1,
                            "{context}: no replay for Verify None"
                        );
                    }
                    _ => {
                        let verifying = verifying_from_sync_succeeded(
                            sync_succeeded,
                            image,
                            CancelHandle::new(),
                            &snapshot,
                            &target_path,
                        );
                        match verifying.run(|_| {}) {
                            (_, VerifyOutcome::Succeeded(succeeded)) => {
                                assert_eq!(succeeded.verified_bytes, payload.len() as u64);
                            }
                            (_, other) => panic!("{context}: expected Succeeded, got {other:?}"),
                        }
                        assert_eq!(
                            opened.load(std::sync::atomic::Ordering::SeqCst),
                            2,
                            "{context}: Full Verify opens its own fresh replay"
                        );
                    }
                }

                let _ = std::fs::remove_file(&target_path);
                let _ = std::fs::remove_file(&path);
            }
        }
    }

    // L2 for xz: a compressed image that reached the Gate with Quick
    // authorized (bypassing L1) is refused by `bind()` before any write.
    #[test]
    fn xz_image_with_quick_verify_is_refused_at_bind() {
        use crate::image_source::compressed::{CompressedImageSource, PreflightOptions};

        let payload = patterned_data(64 * 1024);
        let path = temp_xz_image(
            "xz-quick-l2",
            &xz_bytes(&payload, liblzma::stream::Check::Crc64),
        );
        let options = PreflightOptions {
            max_logical_size: u64::MAX,
        };
        let preflighted = open_gzip_image(&path)
            .preflight(options, || false, |_| {})
            .unwrap();
        let image = SelectedImage::new(Box::new(CompressedImageSource::new(preflighted)));

        let (target_path, authorized, _snapshot) = gate_pass_authorized_for_image(
            "xz-quick-l2",
            &image,
            payload.len() as u64,
            VerifyMode::Quick,
        );
        let result = AuthorizedExecution::bind(authorized, image);

        assert!(matches!(
            result,
            Err(ImageBindingError::QuickVerifyUnsupported)
        ));
        assert!(std::fs::read(&target_path).unwrap().is_empty());
        let _ = std::fs::remove_file(&target_path);
        let _ = std::fs::remove_file(&path);
    }

    // The generic source checkpoints apply to an xz source exactly as to
    // gzip / raw: pre-write (path replaced after preparation: nothing
    // written), post-write, pre-verify and post-verify (the file renamed at
    // those points). The replacement is never read.
    #[test]
    fn xz_image_source_changes_are_caught_at_every_checkpoint() {
        let payload = patterned_data(64 * 1024);
        let contents = xz_bytes(&payload, liblzma::stream::Check::Crc64);
        let rename = |path: &std::path::Path| {
            std::fs::rename(path, path.with_extension("moved")).unwrap();
        };

        // Pre-write.
        let path = temp_xz_image("xz-cp-pre-write", &contents);
        let image = SelectedImage::new(Box::new(prepared_xz_source(
            &path,
            VerifyMode::Full,
            payload.len() as u64,
        )));
        let (target_path, writing_execution, _snapshot) = gate_pass_writing_execution_for_image(
            "xz-cp-pre-write",
            image,
            payload.len() as u64,
            VerifyMode::Full,
            CancelHandle::new(),
        );
        let_the_clock_tick();
        rename(&path);
        std::fs::write(&path, b"a different file").unwrap();
        let (_image, outcome) =
            writing_execution.write(|_| panic!("nothing may be written after the source changed"));
        let failed = expect_write_source_changed(outcome, "xz pre-write");
        assert_eq!(failed.bytes_written, 0);
        assert!(std::fs::read(&target_path).unwrap().is_empty());
        let _ = std::fs::remove_file(&target_path);
        remove_source_files(&path);

        // Post-write (Verify None: the check still runs).
        let path = temp_xz_image("xz-cp-post-write", &contents);
        let image = SelectedImage::new(Box::new(prepared_xz_source(
            &path,
            VerifyMode::None,
            payload.len() as u64,
        )));
        let (target_path, writing_execution, _snapshot) = gate_pass_writing_execution_for_image(
            "xz-cp-post-write",
            image,
            payload.len() as u64,
            VerifyMode::None,
            CancelHandle::new(),
        );
        let_the_clock_tick();
        let total = payload.len() as u64;
        let (_image, outcome) = writing_execution.write(|progress| {
            if progress.bytes_written == total {
                rename(&path);
            }
        });
        let failed = expect_write_source_changed(outcome, "xz post-write");
        assert_eq!(failed.bytes_written, total);
        assert!(failed.target_may_be_modified);
        let _ = std::fs::remove_file(&target_path);
        remove_source_files(&path);

        // Pre-verify and post-verify (Full).
        for pre_verify in [true, false] {
            let context = if pre_verify {
                "xz pre-verify"
            } else {
                "xz post-verify"
            };
            let path = temp_xz_image(&format!("xz-cp-{pre_verify}"), &contents);
            let image = SelectedImage::new(Box::new(prepared_xz_source(
                &path,
                VerifyMode::Full,
                payload.len() as u64,
            )));
            let (target_path, writing_execution, snapshot) = gate_pass_writing_execution_for_image(
                &format!("xz-cp-{pre_verify}"),
                image,
                payload.len() as u64,
                VerifyMode::Full,
                CancelHandle::new(),
            );
            let (image, sync_succeeded) = write_and_sync(writing_execution, context);
            let verifying = verifying_from_sync_succeeded(
                sync_succeeded,
                image,
                CancelHandle::new(),
                &snapshot,
                &target_path,
            );
            let_the_clock_tick();
            if pre_verify {
                rename(&path);
            }
            let (_image, outcome) = verifying.run(|progress| {
                assert!(!pre_verify, "{context}: Verify must not start");
                if progress.verified_bytes == progress.total_bytes {
                    rename(&path);
                }
            });
            let failed = expect_verify_source_changed(outcome, context);
            let expected = if pre_verify { 0 } else { payload.len() as u64 };
            assert_eq!(failed.verified_bytes, expected, "{context}");
            let _ = std::fs::remove_file(&target_path);
            remove_source_files(&path);
        }
    }

    // Ctrl+C during an xz write, and during an xz Full Verify, stops at the
    // next chunk through the ordinary cancel path.
    #[test]
    fn xz_image_write_and_full_verify_can_be_cancelled() {
        let payload = multi_chunk_data();
        let contents = xz_bytes(&payload, liblzma::stream::Check::Crc64);
        let chunk = writer::DEFAULT_CHUNK_SIZE as u64;

        let path = temp_xz_image("xz-cancel-write", &contents);
        let cancel = CancelHandle::new();
        let image = SelectedImage::new(Box::new(prepared_xz_source(
            &path,
            VerifyMode::Full,
            payload.len() as u64,
        )));
        let (target_path, writing_execution, _snapshot) = gate_pass_writing_execution_for_image(
            "xz-cancel-write",
            image,
            payload.len() as u64,
            VerifyMode::Full,
            cancel.clone(),
        );
        let (_image, outcome) = writing_execution.write(|progress| {
            if progress.bytes_written == chunk {
                cancel.request_cancel(CancelReason::UserRequested);
            }
        });
        match outcome {
            WriteAttemptOutcome::Cancelled(cancelled) => {
                assert_eq!(cancelled.bytes_written, chunk);
            }
            other => panic!("expected Cancelled, got {other:?}"),
        }
        let _ = std::fs::remove_file(&target_path);
        let _ = std::fs::remove_file(&path);

        let path = temp_xz_image("xz-cancel-verify", &contents);
        let cancel = CancelHandle::new();
        let image = SelectedImage::new(Box::new(prepared_xz_source(
            &path,
            VerifyMode::Full,
            payload.len() as u64,
        )));
        let (target_path, writing_execution, snapshot) = gate_pass_writing_execution_for_image(
            "xz-cancel-verify",
            image,
            payload.len() as u64,
            VerifyMode::Full,
            CancelHandle::new(),
        );
        let (image, sync_succeeded) = write_and_sync(writing_execution, "xz cancel verify");
        let verifying = verifying_from_sync_succeeded(
            sync_succeeded,
            image,
            cancel.clone(),
            &snapshot,
            &target_path,
        );
        let (_image, outcome) = verifying.run(|progress| {
            if progress.verified_bytes == chunk {
                cancel.request_cancel(CancelReason::UserRequested);
            }
        });
        match outcome {
            VerifyOutcome::Cancelled(cancelled) => {
                assert_eq!(cancelled.mode, VerifyMode::Full);
                assert_eq!(cancelled.verified_bytes, chunk);
            }
            other => panic!("expected Cancelled, got {other:?}"),
        }
        let _ = std::fs::remove_file(&target_path);
        let _ = std::fs::remove_file(&path);
    }
}
