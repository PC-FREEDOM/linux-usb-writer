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
//
// `WriteSucceeded` is deliberately NOT a "Completed" outcome: a successful
// `writer::write()` call (and its internal `Write::flush()`) says nothing
// about durable, synced storage or verified content. `SyncSucceeded` is
// likewise NOT "Completed": `sync_all()` returning `Ok` is a *candidate*
// durability signal (see `linux_access::SyncTarget`'s doc comment for the
// block-device durability caveat -- this crate does not claim `sync_all()`
// succeeding means data has physically reached USB/SD/NVMe media), and no
// read-back verification has happened yet either way. Wiring
// `SyncSucceeded -> Verifying -> Completed` is future work this module does
// not implement yet -- see the doc comment on `SyncSucceeded` for how it
// keeps that door open.
//
// NOT implemented in this revision (future, separate steps):
//   - Verifying / Quick Verify / Full Verify
//   - a final "Completed" type
//   - wiring a device-removal signal into `CancelHandle` (the handle itself
//     is generic enough to support it later; nothing here talks to
//     `linux_monitor`)
//   - cancelling mid-sync (`File::sync_all()` is a single blocking syscall
//     with no chunk loop to poll a cancel flag between iterations -- see
//     `Syncing::sync()`'s doc comment)
//   - any connection from `main.rs` or any other production call site to
//     this module -- everything here is exercised only by this module's own
//     `#[cfg(test)]` tests, against plain regular temp files, never a real
//     block device.
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

use super::core::{ActiveWrite, AuthorizedWrite, VerifyMode};
use crate::image_source::SelectedImage;
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
        WriteError::InvalidSize | WriteError::InvalidChunkSize | WriteError::ImageTooLarge => {
            false
        }

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
fn start_inner<R: Read>(authorized: AuthorizedWrite, source: R, cancel: CancelHandle) -> Writing<R> {
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
// `SelectedImage`. Deliberately just 2 variants -- not a cryptographic
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
    pub fn bind(authorized: AuthorizedWrite, image: SelectedImage) -> Result<Self, ImageBindingError> {
        if authorized.image_generation() != image.selection().image_generation() {
            return Err(ImageBindingError::GenerationMismatch);
        }

        if authorized.image_size() != image.logical_size() {
            return Err(ImageBindingError::SizeMismatch);
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
    pub fn write(self, on_progress: impl FnMut(WriteProgress)) -> (SelectedImage, WriteAttemptOutcome) {
        let WritingExecution { writing, image } = self;

        (image, writing.write(on_progress))
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
// Retains the consumed `ActiveWrite` privately, unwrapped and un-dropped,
// for exactly the reason `WriteSucceeded` does: a future `Verifying` stage
// needs to move the same fd further without reopening the device or
// duplicating it.
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::{DeviceSnapshot, SnapshotFetchOutcome};
    use crate::execution::core::{self, ConfirmationToken};
    use crate::execution::linux_access::{FdMetadata, OpenedDeviceHandle};
    use crate::image_source::{FileImageSource, ImageSource, ImageSourceAccess};
    use std::io::Cursor;

    fn base_device(size: u64) -> DeviceSnapshot {
        DeviceSnapshot {
            device: "/dev/sdx".to_string(),
            block_path: "/org/freedesktop/UDisks2/block_devices/sdx".to_string(),
            drive_path: "/org/freedesktop/UDisks2/drives/Test_Model_TEST-SERIAL-0001"
                .to_string(),
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

        let (path, authorized) =
            gate_pass_active_write("success", image_size, target_size, true);
        let path = path.expect("persistent temp file path");

        let writing = start_inner(authorized, Cursor::new(SOURCE.to_vec()), CancelHandle::new());
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

        let writing = start_inner(authorized, Cursor::new(vec![1u8; image_size as usize]), cancel);
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

        let prepared =
            core::finalize_prepared_write(ready, Some(handle), Some(&metadata)).unwrap();
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

        let prepared =
            core::finalize_prepared_write(ready, Some(handle), Some(&metadata)).unwrap();
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
        crate::execution::linux_access::assert_fd_closed_for_test(raw_fd, target_before_drop.as_deref());
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
        assert!(target_contents.is_empty(), "no bytes should have reached the target");
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
        assert!(!progress_log.is_empty(), "on_progress should be called at least once");

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

        let prepared =
            core::finalize_prepared_write(ready, Some(handle), Some(&metadata)).unwrap();
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
}
