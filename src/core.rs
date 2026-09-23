// Core layer (Selection Continuity). This module never talks to UDisks2,
// D-Bus, or /sys directly — it only receives already-collected data
// (`DeviceSnapshot`, `SnapshotFetchOutcome`, `DeviceEvent`) and already-computed
// judgements (`SafetyAssessment`, `IdentityComparison`, `InstanceComparison`)
// from the Linux Backend / Safety Engine / Identity modules, and decides what
// they mean for the user's current Selection.

use std::sync::atomic::{AtomicU64, Ordering};

use crate::device::{DeviceSnapshot, SnapshotFetchOutcome};
use crate::identity::{compare_identity, compare_instance, IdentityComparison, InstanceComparison};
use crate::linux_access::{ActiveWriteTarget, FdMetadata, OpenedDeviceHandle, SyncTarget};
use crate::linux_monitor::DeviceEvent;
use crate::safety::{assess_device, RiskLevel, SafetyAssessment};
use crate::writer::{WriteError as WriterError, WritePlan, DEFAULT_CHUNK_SIZE};

#[derive(Debug)]
pub enum InvalidationReason {
    TargetRemoved,
    MediaUnavailable,
    InstanceRecreated,
    IdentityChanged,
    IdentityInsufficient,
    InstanceInformationInsufficient,
    SnapshotRefreshFailed,
    SafetyChanged,
}

// An opaque, process-local generation counter for explicit Selection events
// (`select()` calls) -- not a device identity, not a diskseq replacement,
// never persisted, and never meant to be compared across process runs. Two
// different physical devices selected in sequence get two different
// generations, but so does the *same* device explicitly reselected twice in
// a row with nothing about the device itself having changed (no replug, same
// diskseq, same identity). That is precisely the gap `diskseq` alone cannot
// close: diskseq only changes when the kernel recreates the block-device
// instance (a physical replug), never when the user simply reselects the
// still-connected instance again. `diskseq` (Instance identity, owned by
// `identity::compare_instance`) and `SelectionGeneration` (Selection-event
// identity, owned by this module) are deliberately independent and both
// retained side by side in `confirmation_matches` below -- neither alone
// covers what the other catches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SelectionGeneration(u64);

// Starts at 1 purely so the first-ever issued generation is a visibly
// non-default value in Debug output; the exact starting value carries no
// meaning beyond that -- only strict monotonic increase and uniqueness
// within this process matter.
static NEXT_SELECTION_GENERATION: AtomicU64 = AtomicU64::new(1);

// The only way to mint a `SelectionGeneration`. Called exactly once per
// `select()` invocation (see `select()` below) -- never from `apply_event`
// or `revalidate`, which must carry an existing generation through
// unchanged, and never merely because a `SelectionState` is cloned or
// pattern-matched.
//
// Overflow policy: `fetch_update` with `checked_add`, not a plain
// `fetch_add`. A plain `fetch_add` would silently wrap back to 0 once the
// counter reached `u64::MAX`, which would let a generation value be reissued
// within the same process -- exactly the ambiguity this type exists to rule
// out. At roughly 1.8*10^19 possible values this is not a practical concern
// for any real run of this program, but "safe side by default" means this
// must fail loudly rather than silently reuse a value if that were ever
// reached. A `Result`-returning API (threading a new error variant through
// `select()`, and therefore every caller) was considered and rejected as
// over-engineering for a condition this far outside any realistic run; a
// panic is the minimal choice that still refuses to wrap silently.
fn next_selection_generation() -> SelectionGeneration {
    let previous = NEXT_SELECTION_GENERATION
        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |value| {
            value.checked_add(1)
        })
        .expect(
            "selection_generation counter overflowed u64 -- refusing to silently wrap and reissue a generation value",
        );

    SelectionGeneration(previous)
}

#[derive(Debug)]
pub enum SelectionState {
    NoSelection,
    Selected {
        baseline: DeviceSnapshot,
        baseline_assessment: SafetyAssessment,
        selection_generation: SelectionGeneration,
    },
    Invalidated {
        baseline: DeviceSnapshot,
        baseline_assessment: SafetyAssessment,
        reason: InvalidationReason,
        selection_generation: SelectionGeneration,
    },
}

#[derive(Debug)]
pub enum SelectionError {
    NotSelectable,
}

fn is_selectable(snapshot: &DeviceSnapshot, assessment: &SafetyAssessment) -> bool {
    assessment.writable
        && matches!(assessment.risk_level, RiskLevel::Normal)
        && snapshot.media_available
        && snapshot.size > 0
}

// Explicit, user-driven action: always starts a fresh Selection from the
// given baseline, regardless of any prior SelectionState (including a prior
// Invalidated one). There is no path back to Selected other than calling
// this again — an Invalidated Selection never revives on its own.
pub fn select(baseline: DeviceSnapshot) -> Result<SelectionState, SelectionError> {
    let baseline_assessment = assess_device(&baseline);

    if !is_selectable(&baseline, &baseline_assessment) {
        return Err(SelectionError::NotSelectable);
    }

    // A fresh generation every time, unconditionally -- including a reselect
    // of the exact same device with nothing else changed. This is what makes
    // `selection_generation` answer "was this Selection event confirmed
    // against?" rather than "is this the same device?" (`diskseq`/identity
    // already answer that question elsewhere).
    Ok(SelectionState::Selected {
        baseline,
        baseline_assessment,
        selection_generation: next_selection_generation(),
    })
}

// Folds one DeviceEvent into the current SelectionState. Only ever narrows
// Selected -> Invalidated; never the reverse. If `state` is not currently
// Selected (NoSelection, or already Invalidated), the event is ignored and
// `state` is returned unchanged — in particular, an `InterfacesAdded` for the
// previously-selected path (e.g. the same device replugged) does NOT revive
// an Invalidated selection.
pub fn apply_event(state: SelectionState, event: &DeviceEvent) -> SelectionState {
    let SelectionState::Selected {
        baseline,
        baseline_assessment,
        selection_generation,
    } = state
    else {
        return state;
    };

    let path = event.object_path();
    let matches_block = path == baseline.block_path;
    let matches_drive = path == baseline.drive_path;

    if !matches_block && !matches_drive {
        return SelectionState::Selected {
            baseline,
            baseline_assessment,
            selection_generation,
        };
    }

    match event {
        DeviceEvent::InterfacesRemoved { .. } => SelectionState::Invalidated {
            baseline,
            baseline_assessment,
            reason: InvalidationReason::TargetRemoved,
            selection_generation,
        },
        DeviceEvent::PropertiesChanged {
            interface, changed, ..
        } if matches_drive && interface == "org.freedesktop.UDisks2.Drive" => {
            let media_now_unavailable = changed
                .iter()
                .any(|change| change.name == "MediaAvailable" && change.as_bool == Some(false));

            if media_now_unavailable {
                SelectionState::Invalidated {
                    baseline,
                    baseline_assessment,
                    reason: InvalidationReason::MediaUnavailable,
                    selection_generation,
                }
            } else {
                SelectionState::Selected {
                    baseline,
                    baseline_assessment,
                    selection_generation,
                }
            }
        }
        // InterfacesAdded, unrelated PropertiesChanged, WatcherFailed: no
        // decision to make from the event alone. In particular, an
        // InterfacesAdded here (e.g. the same device replugged under the
        // same path) is deliberately not treated as a reason to do anything
        // — replugging is a new connection generation, not a continuation of
        // the old Selection.
        _ => SelectionState::Selected {
            baseline,
            baseline_assessment,
            selection_generation,
        },
    }
}

// Shared by `revalidate()` (continuous Selection Continuity monitoring) and
// the write gate (`prepare_for_open`, a point-in-time pre-open check): given
// a baseline and a freshly re-fetched current snapshot, confirms Identity is
// still the same physical drive, Instance is still the same block-device
// generation, and the Safety Engine still allows writing to it. Re-running
// `assess_device` here (rather than reusing `baseline`'s old assessment)
// matters because the verdict can change independently of Identity/Instance
// — e.g. the target got mounted, or an active swap appeared.
fn check_identity_instance_safety(
    baseline: &DeviceSnapshot,
    current: &DeviceSnapshot,
) -> Result<(), InvalidationReason> {
    match compare_identity(baseline, current) {
        IdentityComparison::Changed => return Err(InvalidationReason::IdentityChanged),
        IdentityComparison::InsufficientIdentity => {
            return Err(InvalidationReason::IdentityInsufficient);
        }
        IdentityComparison::Same => {}
    }

    match compare_instance(baseline, current) {
        InstanceComparison::Recreated => return Err(InvalidationReason::InstanceRecreated),
        InstanceComparison::InsufficientInformation => {
            return Err(InvalidationReason::InstanceInformationInsufficient);
        }
        InstanceComparison::SameInstance => {}
    }

    let assessment = assess_device(current);

    if !assessment.writable || !matches!(assessment.risk_level, RiskLevel::Normal) {
        return Err(InvalidationReason::SafetyChanged);
    }

    Ok(())
}

// Re-verifies the current Selection against a freshly re-fetched
// DeviceSnapshot for the same target (see
// `linux_backend::collect_device_snapshot`). Like `apply_event`, this only
// ever narrows Selected -> Invalidated and leaves any other state unchanged
// (so re-running this after Invalidated is a no-op).
pub fn revalidate(state: SelectionState, outcome: SnapshotFetchOutcome) -> SelectionState {
    let SelectionState::Selected {
        baseline,
        baseline_assessment,
        selection_generation,
    } = state
    else {
        return state;
    };

    let current = match outcome {
        SnapshotFetchOutcome::Found(snapshot) => snapshot,
        SnapshotFetchOutcome::NotFound => {
            return SelectionState::Invalidated {
                baseline,
                baseline_assessment,
                reason: InvalidationReason::TargetRemoved,
                selection_generation,
            };
        }
        SnapshotFetchOutcome::Error(_) => {
            return SelectionState::Invalidated {
                baseline,
                baseline_assessment,
                reason: InvalidationReason::SnapshotRefreshFailed,
                selection_generation,
            };
        }
    };

    if let Err(reason) = check_identity_instance_safety(&baseline, &current) {
        return SelectionState::Invalidated {
            baseline,
            baseline_assessment,
            reason,
            selection_generation,
        };
    }

    SelectionState::Selected {
        baseline,
        baseline_assessment,
        selection_generation,
    }
}

// The gate immediately before calling OpenDevice: proceed only if the
// Selection is currently valid. This exists as a named, testable predicate
// so the "OpenDevice must not be attempted unless Selected" rule doesn't
// have to be re-derived ad hoc at every call site.
pub fn is_ready_to_open(state: &SelectionState) -> bool {
    matches!(state, SelectionState::Selected { .. })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FdBindingCheck {
    Match,
    Mismatch,
    InsufficientInformation,
}

// The last TOCTOU defense line: after OpenDevice returns a file descriptor,
// confirm — from the FD itself, not from anything UDisks2 told us about it —
// that it really is the block device we just re-verified. This is a
// different question from Device Identity (same physical drive?) or Device
// Instance (same block-device generation?): it only asks whether *this
// specific FD* is bound to the *device node* the caller expects, using the
// kernel's own st_rdev/BLKGETSIZE64, independent of D-Bus entirely.
pub fn check_fd_binding(current: &DeviceSnapshot, fd_metadata: Option<&FdMetadata>) -> FdBindingCheck {
    let Some(fd_metadata) = fd_metadata else {
        return FdBindingCheck::InsufficientInformation;
    };

    if fd_metadata.major != current.major || fd_metadata.minor != current.minor {
        return FdBindingCheck::Mismatch;
    }

    match fd_metadata.size {
        Some(size) if size != current.size => FdBindingCheck::Mismatch,
        Some(_) => FdBindingCheck::Match,
        None => FdBindingCheck::InsufficientInformation,
    }
}

// ---------------------------------------------------------------------
// Write Gate / Write Preparation
//
// Everything below answers one question: "is it safe to hand a write-mode
// FD to the Writer right now?" It never opens a device, never touches D-Bus,
// and never calls `writer::write()` — it only combines results the caller
// already obtained from the Linux Backend / `linux_access` / the user, and
// decides whether every one of the required conditions holds. There is no
// code path anywhere in this module that reaches `writer::write()`;
// connecting a `PreparedWrite`/`ActiveWrite` to the Writer is explicitly a
// later step.
//
// The full state progression this module implements so far (each arrow is a
// consuming transition — the value on the left cannot be used again once the
// value on the right has been produced):
//
//   SelectionState::Selected
//       |  (prepare_for_open: Identity/Instance/Safety re-check + WritePlan)
//       v
//   ReadyToOpen
//       |  (caller calls OpenDevice, outside this module; finalize_prepared_write:
//       |   FD binding check)
//       v
//   PreparedWrite            -- owns the Gate-passed OpenedDeviceHandle
//       |  (PreparedWrite::begin(self), a one-way consuming move)
//       v
//   ActiveWrite               -- same handle, moved (never duplicated)
//       |  (future work, not implemented here)
//       v
//   WrittenTarget / Failed / Cancelled   -- NOT YET IMPLEMENTED
//
// This revision implements up to and including `ActiveWrite`, and adds one
// capability on top of it: `ActiveWrite::writer_target()` can now produce a
// genuine `std::io::Write` (`linux_access::ActiveWriteTarget`) borrowed from
// the handle it owns. Critically, this is a type-level *capability*, not a
// *connection* — nothing anywhere in this crate calls `writer::write()` with
// it. `PreparedWrite` still exposes no such method at all (only `begin()`,
// which consumes it), and `OpenedDeviceHandle` on its own (before it becomes
// part of an `ActiveWrite`) exposes no public way to reach
// `ActiveWriteTarget` either. Wiring `ActiveWrite`'s write capability into an
// actual call to `writer::write()`, and the WrittenTarget/Failed/Cancelled
// outcomes such a call would produce, remain future, separate steps.
// ---------------------------------------------------------------------

// An opaque, process-local generation counter for explicit image-selection
// events -- the image-side counterpart to `SelectionGeneration`. It is
// *not* a content hash or checksum, and proves nothing about whether two
// images are byte-for-byte identical: two completely different images of
// the same size, or even the exact same file selected twice in a row, get
// two different generations. What it answers is narrower and is all this
// module needs: "is this the same explicit image-selection event the
// confirmation was made against?" A hash would answer a different, stronger
// question (are the *contents* the same?) that this design does not need
// and deliberately does not attempt -- see `ImageSelection` below for why
// that stays out of scope here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImageGeneration(u64);

// Starts at 1 for the same reason `NEXT_SELECTION_GENERATION` does: purely
// so the first issued value is visibly non-default in Debug output.
static NEXT_IMAGE_GENERATION: AtomicU64 = AtomicU64::new(1);

// The only way to mint an `ImageGeneration`. Called exactly once per
// `ImageSelection::new()` (see below) -- an `ImageSelection` value being
// copied around afterward never mints another one, exactly like
// `SelectionGeneration`/`select()`.
//
// Overflow policy: identical to `next_selection_generation()` above --
// `fetch_update` + `checked_add`, panicking via `.expect()` rather than
// silently wrapping. Deliberately not a different policy for this
// generation type: both exist to rule out the same class of ambiguity
// (a generation value being reissued within one process), so both fail the
// same way for the same reason. See `next_selection_generation()`'s doc
// comment for the full overflow rationale (Result-based API rejected as
// over-engineering for a practically unreachable condition).
fn next_image_generation() -> ImageGeneration {
    let previous = NEXT_IMAGE_GENERATION
        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |value| {
            value.checked_add(1)
        })
        .expect(
            "image_generation counter overflowed u64 -- refusing to silently wrap and reissue a generation value",
        );

    ImageGeneration(previous)
}

// A pure data snapshot of "which image the user explicitly selected, and
// when" -- the image-side counterpart to `SelectionState`'s
// `selection_generation` field. Deliberately minimal: only the logical
// image size (what `WritePlan`/`ConfirmationToken` actually need to
// validate) and the opaque generation identifying the selection event
// itself. No path, `File`, `RawFd`, reader, compression info, or hash --
// those questions belong to a future `ImageSource` I/O abstraction ("how do
// I read the bytes?"), which is a distinct concern from this type's own
// question ("what, and which selection event, did the user mean?"). Mixing
// the two here would be exactly the kind of cross-layer responsibility this
// codebase avoids (see CLAUDE.md's architecture section).
// Fields are deliberately private: `image_size` and `image_generation` must
// always travel together as a single value minted by `new()`, never
// reassembled field-by-field from two different `ImageSelection`s (e.g.
// `ImageSelection { image_size: <from B>, image_generation: <from A>'s
// generation }`). A struct-literal with `pub` fields cannot rule that out --
// any code holding two `ImageSelection`s could freely mix their fields into
// a third, fabricated one. Private fields plus `new()` as the only
// constructor closes that gap: the only way to ever have an
// `image_generation` in hand is as half of an `ImageSelection` that was
// minted whole, by exactly one `new()` call, alongside the `image_size` it
// is paired with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImageSelection {
    image_size: u64,
    image_generation: ImageGeneration,
}

impl ImageSelection {
    // The only way to construct one. Mints a fresh `image_generation` every
    // time, unconditionally -- including reselecting an image of the exact
    // same size, or even the exact same file. Mirrors `select()`'s contract
    // for `selection_generation` on purpose: both answer "was this
    // confirmed against the same explicit choice?", never "is this the same
    // content?". Copying an existing `ImageSelection` (it is `Copy`) never
    // goes through this constructor and therefore never mints a new
    // generation -- only an explicit, new image selection does.
    pub fn new(image_size: u64) -> Self {
        ImageSelection {
            image_size,
            image_generation: next_image_generation(),
        }
    }

    // The one field callers outside this module have any legitimate need
    // for on its own (e.g. displaying "image_size=N bytes" in `main.rs`'s
    // PoC output). `pub`, unlike `image_generation()` below.
    pub fn image_size(&self) -> u64 {
        self.image_size
    }

    // `pub(crate)`, not `pub`: the generation is opaque by design (see
    // `ImageGeneration`'s doc comment) and the only legitimate consumers of
    // its raw value are `ConfirmationToken::new`/`confirmation_matches`
    // (both in this module) and this crate's own tests -- nothing outside
    // the crate has a reason to read it in isolation from the
    // `ImageSelection` it came from.
    pub(crate) fn image_generation(&self) -> ImageGeneration {
        self.image_generation
    }
}

// Binds a single "yes, write this image to this target" confirmation to the
// exact target (by block_path), its exact size, the exact image selection
// (size and generation), the target's block-device generation (diskseq),
// and the Selection-event generation (`selection_generation`) at
// confirmation time. A token is data only — there is no UI in this
// codebase yet, so (for now) the only way to obtain one is to construct it
// directly from the snapshot and `ImageSelection` the user was actually
// looking at, and the `SelectionState` that snapshot came from, when they
// confirmed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfirmationToken {
    pub target_block_path: String,
    pub target_size: u64,
    pub image_size: u64,
    pub image_generation: ImageGeneration,
    pub target_diskseq: Option<u64>,
    pub selection_generation: SelectionGeneration,
}

impl ConfirmationToken {
    // `image` and `selection_generation` must both be copied from the
    // caller's current, already-explicit choices -- an `ImageSelection` the
    // caller already obtained via `ImageSelection::new()`, and the
    // `selection_generation` field of the caller's current `SelectionState`
    // -- never minted fresh here. Taking `image` as a single `ImageSelection`
    // (rather than a separate `image_size: u64` and `image_generation:
    // ImageGeneration`) is deliberate: it structurally rules out the mistake
    // of pairing one image's size with a *different* image's generation,
    // since both fields always travel together as the one value the caller
    // got back from a single `ImageSelection::new()` call. Minting either
    // value fresh here would defeat the entire mechanism: the token has to
    // freeze exactly what was current *at confirmation time*, so a later
    // reselect of either the target or the image shows up as a mismatch in
    // `confirmation_matches` below.
    pub fn new(
        target: &DeviceSnapshot,
        image: ImageSelection,
        selection_generation: SelectionGeneration,
    ) -> Self {
        ConfirmationToken {
            target_block_path: target.block_path.clone(),
            target_size: target.size,
            image_size: image.image_size(),
            image_generation: image.image_generation(),
            target_diskseq: target.diskseq,
            selection_generation,
        }
    }
}

// A token only ever authorizes the exact (target, size, image size, image
// generation, diskseq generation, selection generation) it was made for.
// Any difference — a different target, a resized image, a *different*
// image of the same size (a new `image_generation`, even with `image_size`
// unchanged), the target having been replugged (a new diskseq) since the
// token was made, or the user having explicitly reselected the target since
// (a new `selection_generation`) — is a mismatch, not a "close enough".
// `image_generation` is what closes the gap `image_size` alone cannot:
// `image_size` only catches a *resized* image, never same-size image A
// silently swapped for same-size image B.
fn confirmation_matches(
    token: &ConfirmationToken,
    current: &DeviceSnapshot,
    image: ImageSelection,
    current_selection_generation: SelectionGeneration,
) -> bool {
    token.target_block_path == current.block_path
        && token.target_size == current.size
        && token.image_size == image.image_size()
        && token.image_generation == image.image_generation()
        && token.target_diskseq == current.diskseq
        && token.selection_generation == current_selection_generation
}

#[allow(dead_code)]
#[derive(Debug)]
pub enum WriteGateError {
    NoSelection,
    SelectionInvalidated,
    SnapshotRefreshFailed,
    IdentityChanged,
    IdentityInsufficient,
    InstanceRecreated,
    InstanceInsufficient,
    SafetyRejected,
    InvalidImageSize,
    ImageTooLarge,
    ConfirmationMissing,
    ConfirmationMismatch,
    OpenDeviceFailed,
    FdBindingMismatch,
    FdBindingInsufficient,
}

// Output of the pure, pre-OpenDevice half of the gate (`prepare_for_open`):
// everything that can be checked without any Linux I/O has passed, and the
// caller now has the freshly re-verified snapshot plus a valid WritePlan to
// use when actually calling OpenDevice. Holding this value proves nothing
// about the FD yet — that is `finalize_prepared_write`'s job.
#[derive(Debug)]
pub struct ReadyToOpen {
    pub current: DeviceSnapshot,
    pub plan: WritePlan,
}

// Proof that every gate condition (A through K, plus a matching
// confirmation) held at the moment this value was constructed. As of this
// revision it *does* own the Gate-passed `OpenedDeviceHandle` — the whole
// point being that "a PreparedWrite exists" and "we are holding the exact FD
// that was just re-verified" become the same fact, instead of two values (a
// bool/metadata here, a handle held separately by the caller) that a caller
// could mismatch. `handle` is deliberately private: this struct still
// exposes no method that could perform a write, since nothing in this module
// (or anywhere else, today) can turn that private field into a `Write` for
// an outside caller. Connecting it to `writer::write()` is a distinct, later
// step this module does not implement.
pub struct PreparedWrite {
    pub target_block_path: String,
    pub target_size: u64,
    pub image_size: u64,
    #[allow(dead_code)]
    handle: OpenedDeviceHandle,
}

// The pure half of the gate: conditions A-I plus the confirmation check.
// Takes the current `SelectionState` (by reference — this does not mutate
// ongoing Selection Continuity monitoring) and a target-specific re-fetch
// the caller already performed (condition B). Reuses `writer::WritePlan` for
// F/G/H/I instead of re-implementing size validation here.
pub fn prepare_for_open(
    state: &SelectionState,
    refreshed: SnapshotFetchOutcome,
    image: ImageSelection,
    confirmation: Option<&ConfirmationToken>,
) -> Result<ReadyToOpen, WriteGateError> {
    let (baseline, _baseline_assessment, selection_generation) = match state {
        SelectionState::NoSelection => return Err(WriteGateError::NoSelection),
        SelectionState::Invalidated { .. } => return Err(WriteGateError::SelectionInvalidated),
        SelectionState::Selected {
            baseline,
            baseline_assessment,
            selection_generation,
        } => (baseline, baseline_assessment, selection_generation),
    };

    // B: the target-specific snapshot re-fetch must have actually succeeded.
    let current = match refreshed {
        SnapshotFetchOutcome::Found(snapshot) => snapshot,
        SnapshotFetchOutcome::NotFound | SnapshotFetchOutcome::Error(_) => {
            return Err(WriteGateError::SnapshotRefreshFailed);
        }
    };

    // C, D, E: Identity, Instance, and a fresh Safety re-evaluation.
    if let Err(reason) = check_identity_instance_safety(baseline, &current) {
        return Err(match reason {
            InvalidationReason::IdentityChanged => WriteGateError::IdentityChanged,
            InvalidationReason::IdentityInsufficient => WriteGateError::IdentityInsufficient,
            InvalidationReason::InstanceRecreated => WriteGateError::InstanceRecreated,
            InvalidationReason::InstanceInformationInsufficient => {
                WriteGateError::InstanceInsufficient
            }
            InvalidationReason::SafetyChanged => WriteGateError::SafetyRejected,
            // TargetRemoved/MediaUnavailable/SnapshotRefreshFailed are not
            // reachable from this helper (it never sees those cases) — kept
            // exhaustive rather than panicking on a theoretical future variant.
            _ => WriteGateError::SafetyRejected,
        });
    }

    // F, G, H, I: image_size > 0, target_size > 0, image_size <= target_size,
    // and a valid chunk size — all delegated to `WritePlan::new` rather than
    // re-implemented here.
    let plan = match WritePlan::new(image.image_size(), current.size, DEFAULT_CHUNK_SIZE) {
        Ok(plan) => plan,
        Err(WriterError::ImageTooLarge) => return Err(WriteGateError::ImageTooLarge),
        // InvalidSize covers both image_size == 0 and target_size == 0;
        // InvalidChunkSize/SourceRead/TargetWrite/FlushFailed/SourceTooShort/
        // Cancelled cannot occur here since DEFAULT_CHUNK_SIZE is a fixed,
        // non-zero constant and no copying happens in this function.
        Err(_) => return Err(WriteGateError::InvalidImageSize),
    };

    // Confirmation: required regardless of how clean everything else is, and
    // must match this exact target/image/generation.
    let token = confirmation.ok_or(WriteGateError::ConfirmationMissing)?;

    if !confirmation_matches(token, &current, image, *selection_generation) {
        return Err(WriteGateError::ConfirmationMismatch);
    }

    Ok(ReadyToOpen { current, plan })
}

// The second half of the gate (conditions J and K), run after the caller has
// used `ReadyToOpen` to actually call OpenDevice (Linux I/O, outside this
// module). Consumes `ReadyToOpen` and, if OpenDevice succeeded, the resulting
// `OpenedDeviceHandle` itself (by value) plus its already-collected metadata,
// and produces a `PreparedWrite` — now the sole owner of that handle — only
// if OpenDevice succeeded and the FD is bound to the exact device node just
// re-verified.
//
// `opened_handle` is `None` when the caller's OpenDevice call itself failed
// (there is no handle to hand over in that case) and `Some(handle)` when it
// succeeded. This function never calls any method on `opened_handle` besides
// taking ownership of it — in particular it never calls `.metadata()` itself;
// `fd_metadata` must already have been read (by the caller, via
// `linux_access`) from that same handle before calling this function. That
// keeps this module free of Linux I/O: it only moves an opaque value it was
// handed, it never performs a syscall on it.
//
// On any rejection (OpenDeviceFailed / FdBindingMismatch /
// FdBindingInsufficient) `opened_handle` is simply dropped at the end of this
// function's scope — ordinary RAII closes the underlying fd via `File`'s own
// `Drop` impl. No explicit close call is needed here.
pub fn finalize_prepared_write(
    ready: ReadyToOpen,
    opened_handle: Option<OpenedDeviceHandle>,
    fd_metadata: Option<&FdMetadata>,
) -> Result<PreparedWrite, WriteGateError> {
    let handle = opened_handle.ok_or(WriteGateError::OpenDeviceFailed)?;

    match check_fd_binding(&ready.current, fd_metadata) {
        FdBindingCheck::Match => {}
        FdBindingCheck::Mismatch => return Err(WriteGateError::FdBindingMismatch),
        FdBindingCheck::InsufficientInformation => {
            return Err(WriteGateError::FdBindingInsufficient);
        }
    }

    Ok(PreparedWrite {
        target_block_path: ready.current.block_path,
        target_size: ready.current.size,
        image_size: ready.plan.image_size,
        handle,
    })
}

// A single write attempt's execution state: the result of choosing to start
// the one write `PreparedWrite` was proof-of-readiness for. Deliberately not
// `Clone`/`Copy` (nor is `PreparedWrite`) — the whole point of `begin()`
// consuming `self` is that at most one `ActiveWrite` can ever exist per
// `PreparedWrite`, and once it exists, the `PreparedWrite` it came from is
// gone. `handle` is the exact same `OpenedDeviceHandle` `PreparedWrite` held,
// moved here without ever being duplicated (no `dup()`/`try_clone()` — a
// single fd travels a single, one-way path through these types).
//
// `ActiveWrite` is deliberately the *only* type in this crate with a method
// that can produce a `std::io::Write` (see `writer_target()` below).
// `PreparedWrite` has no such method, and `OpenedDeviceHandle` on its own
// exposes no *public* way to reach one either. This struct itself still does
// not implement `Write` — the capability lives entirely in the short-lived
// `ActiveWriteTarget` borrow `writer_target()` hands out, never in
// `ActiveWrite` directly. Connecting that capability to an actual call to
// `writer::write()`, and the WrittenTarget/Failed/Cancelled outcomes a real
// write attempt would produce, remain distinct, later steps this module does
// not implement.
pub struct ActiveWrite {
    pub target_block_path: String,
    pub target_size: u64,
    pub image_size: u64,
    handle: OpenedDeviceHandle,
}

impl PreparedWrite {
    // The one and only way to reach an `ActiveWrite`. Takes `self` by value
    // (not `&self`/`&mut self`), so calling this is the last thing that can
    // ever be done with a given `PreparedWrite` — the Rust compiler refuses
    // any further use of the variable that was passed in, which is exactly
    // the "consumed exactly once" guarantee this type exists to provide.
    pub fn begin(self) -> ActiveWrite {
        ActiveWrite {
            target_block_path: self.target_block_path,
            target_size: self.target_size,
            image_size: self.image_size,
            handle: self.handle,
        }
    }
}

impl ActiveWrite {
    // The sole source, anywhere in this crate, of a `std::io::Write` backed
    // by a Gate-passed FD. Returns a short-lived `ActiveWriteTarget` that
    // borrows `self` mutably: while the returned value is alive, `self`
    // cannot be read, written, dropped, or handed to anything else (Rust's
    // ordinary exclusive-borrow rules), and once it goes out of scope `self`
    // is fully usable again. No FD is duplicated to produce it — this is a
    // plain `&mut` borrow of the handle `ActiveWrite` already owns, nothing
    // more.
    //
    // `pub(crate)` rather than `pub`: this stays reachable only from within
    // this crate (irrelevant in practice, since this is a binary crate with
    // no external consumers), and — by documented convention, not something
    // Rust's visibility system can enforce across sibling modules — nothing
    // in `main.rs` calls this yet. Wiring an `ActiveWriteTarget` obtained
    // here into an actual `writer::write()` call is a distinct, later step;
    // this method only proves the capability can be obtained, not that it is
    // ever used to write anything.
    #[allow(dead_code)] // exercised by this module's own tests today; not yet called from main.rs.
    pub(crate) fn writer_target(&mut self) -> ActiveWriteTarget<'_> {
        self.handle.writer_target()
    }

    // The sole source, anywhere in this crate, of a durability-sync
    // capability backed by a Gate-passed FD -- the sync-only counterpart to
    // `writer_target()`. Returns a short-lived `SyncTarget` borrowing `self`
    // *shared* (`&self`, not `&mut self`): `File::sync_all()` needs no
    // exclusive access, unlike `Write`. This module never calls
    // `sync_all()` itself -- it only delegates the capability, exactly like
    // `writer_target()` delegates write capability; the actual call happens
    // in `write_job.rs`'s `Syncing::sync()`. See `linux_access::SyncTarget`'s
    // doc comment for the block-device durability caveat: a successful sync
    // is not, by itself, a confirmed guarantee of physical media durability.
    //
    // `pub(crate)` rather than `pub`, for the same convention (and the same
    // Rust visibility limitation across sibling modules) as `writer_target()`.
    #[allow(dead_code)] // exercised by this module's/write_job.rs's tests today; not yet called from main.rs.
    pub(crate) fn sync_target(&self) -> SyncTarget<'_> {
        self.handle.sync_target()
    }
}

// Test-only accessor: extracts the `selection_generation` a `Selected` or
// `Invalidated` `SelectionState` carries. Exists purely so tests (both this
// module's own, and `write_job.rs`'s, which never constructs `SelectionState`
// directly — only ever via the real `select()`/`apply_event()`/`revalidate()`
// API) can bind a `ConfirmationToken` to whatever generation a real Selection
// actually holds, without adding a public accessor to the production API
// surface (production code that needs this value gets it the same way
// `prepare_for_open` and `main.rs` do: by pattern-matching the
// `SelectionState` variant directly).
#[cfg(test)]
pub(crate) fn selection_generation_of(state: &SelectionState) -> SelectionGeneration {
    match state {
        SelectionState::Selected {
            selection_generation,
            ..
        }
        | SelectionState::Invalidated {
            selection_generation,
            ..
        } => *selection_generation,
        SelectionState::NoSelection => panic!("NoSelection has no selection_generation"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::linux_access;
    use crate::linux_monitor::PropertyChange;
    use crate::writer;
    use std::io::Write;

    fn base_device() -> DeviceSnapshot {
        DeviceSnapshot {
            device: "/dev/sdx".to_string(),
            block_path: "/org/freedesktop/UDisks2/block_devices/sdx".to_string(),
            drive_path: "/org/freedesktop/UDisks2/drives/Test_Model_TEST-SERIAL-0001"
                .to_string(),
            major: 8,
            minor: 0,
            diskseq: Some(12),
            size: 8_000_000_000,
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

    fn interfaces_removed(object_path: &str) -> DeviceEvent {
        DeviceEvent::InterfacesRemoved {
            object_path: object_path.to_string(),
            interfaces: vec!["org.freedesktop.UDisks2.Block".to_string()],
        }
    }

    fn media_unavailable_changed(object_path: &str) -> DeviceEvent {
        DeviceEvent::PropertiesChanged {
            object_path: object_path.to_string(),
            interface: "org.freedesktop.UDisks2.Drive".to_string(),
            changed: vec![PropertyChange {
                name: "MediaAvailable".to_string(),
                value: "OwnedValue(Bool(false))".to_string(),
                as_bool: Some(false),
            }],
            invalidated: Vec::new(),
        }
    }

    // A. Selecting a normal, writable target succeeds and becomes Selected.
    #[test]
    fn select_valid_target_becomes_selected() {
        let state = select(base_device());

        assert!(matches!(state, Ok(SelectionState::Selected { .. })));
    }

    // B. A target the Safety Engine won't allow to be written is rejected at
    // selection time, before any Selection state is created.
    #[test]
    fn select_rejects_non_writable_target() {
        let mut snapshot = base_device();
        snapshot.hint_system = true;

        let state = select(snapshot);

        assert!(matches!(state, Err(SelectionError::NotSelectable)));
    }

    // C. InterfacesRemoved on the selected target's own block_path -> Invalidated(TargetRemoved).
    #[test]
    fn interfaces_removed_on_selected_block_path_invalidates() {
        let snapshot = base_device();
        let block_path = snapshot.block_path.clone();
        let state = select(snapshot).unwrap();

        let state = apply_event(state, &interfaces_removed(&block_path));

        assert!(matches!(
            state,
            SelectionState::Invalidated {
                reason: InvalidationReason::TargetRemoved,
                ..
            }
        ));
    }

    // D. InterfacesRemoved on an unrelated device's path must not affect the
    // current Selection.
    #[test]
    fn interfaces_removed_on_unrelated_device_is_ignored() {
        let state = select(base_device()).unwrap();

        let unrelated = interfaces_removed("/org/freedesktop/UDisks2/block_devices/sdz");
        let state = apply_event(state, &unrelated);

        assert!(matches!(state, SelectionState::Selected { .. }));
    }

    // E. Drive.MediaAvailable=false on the selected target's drive_path -> Invalidated(MediaUnavailable).
    #[test]
    fn media_unavailable_on_selected_drive_path_invalidates() {
        let snapshot = base_device();
        let drive_path = snapshot.drive_path.clone();
        let state = select(snapshot).unwrap();

        let state = apply_event(state, &media_unavailable_changed(&drive_path));

        assert!(matches!(
            state,
            SelectionState::Invalidated {
                reason: InvalidationReason::MediaUnavailable,
                ..
            }
        ));
    }

    // F. compare_identity() == Changed -> Invalidated(IdentityChanged).
    #[test]
    fn identity_changed_invalidates() {
        let state = select(base_device()).unwrap();

        let mut current = base_device();
        current.serial = "OTHER-SERIAL-0002".to_string();

        let state = revalidate(state, SnapshotFetchOutcome::Found(current));

        assert!(matches!(
            state,
            SelectionState::Invalidated {
                reason: InvalidationReason::IdentityChanged,
                ..
            }
        ));
    }

    // G. compare_identity() == InsufficientIdentity -> Invalidated(IdentityInsufficient).
    #[test]
    fn identity_insufficient_invalidates() {
        let state = select(base_device()).unwrap();

        let mut current = base_device();
        current.serial = String::new();

        let state = revalidate(state, SnapshotFetchOutcome::Found(current));

        assert!(matches!(
            state,
            SelectionState::Invalidated {
                reason: InvalidationReason::IdentityInsufficient,
                ..
            }
        ));
    }

    // H. compare_instance() == Recreated -> Invalidated(InstanceRecreated).
    #[test]
    fn instance_recreated_invalidates() {
        let state = select(base_device()).unwrap();

        let mut current = base_device();
        current.diskseq = Some(19);

        let state = revalidate(state, SnapshotFetchOutcome::Found(current));

        assert!(matches!(
            state,
            SelectionState::Invalidated {
                reason: InvalidationReason::InstanceRecreated,
                ..
            }
        ));
    }

    // I. compare_instance() == InsufficientInformation -> Invalidated(InstanceInformationInsufficient).
    #[test]
    fn instance_information_insufficient_invalidates() {
        let state = select(base_device()).unwrap();

        let mut current = base_device();
        current.diskseq = None;

        let state = revalidate(state, SnapshotFetchOutcome::Found(current));

        assert!(matches!(
            state,
            SelectionState::Invalidated {
                reason: InvalidationReason::InstanceInformationInsufficient,
                ..
            }
        ));
    }

    // J. Identity/Instance both still match, but re-running the Safety Engine
    // on `current` now yields Blocked -> Invalidated(SafetyChanged).
    #[test]
    fn current_safety_blocked_invalidates() {
        let state = select(base_device()).unwrap();

        let mut current = base_device();
        current.hint_system = true;

        let state = revalidate(state, SnapshotFetchOutcome::Found(current));

        assert!(matches!(
            state,
            SelectionState::Invalidated {
                reason: InvalidationReason::SafetyChanged,
                ..
            }
        ));
    }

    // K. The targeted re-fetch itself failing -> Invalidated(SnapshotRefreshFailed).
    #[test]
    fn snapshot_refresh_failure_invalidates() {
        let state = select(base_device()).unwrap();

        let state = revalidate(
            state,
            SnapshotFetchOutcome::Error("simulated D-Bus failure".to_string()),
        );

        assert!(matches!(
            state,
            SelectionState::Invalidated {
                reason: InvalidationReason::SnapshotRefreshFailed,
                ..
            }
        ));
    }

    // L. Once Invalidated, a subsequent revalidate() with a perfectly clean
    // current snapshot must NOT revive the Selection. This is the core
    // "no automatic recovery" guarantee.
    #[test]
    fn invalidated_selection_does_not_recover_on_its_own() {
        let snapshot = base_device();
        let block_path = snapshot.block_path.clone();
        let state = select(snapshot).unwrap();
        let state = apply_event(state, &interfaces_removed(&block_path));

        assert!(matches!(state, SelectionState::Invalidated { .. }));

        // A subsequent, perfectly healthy re-fetch must not undo the
        // invalidation.
        let state = revalidate(state, SnapshotFetchOutcome::Found(base_device()));

        assert!(matches!(
            state,
            SelectionState::Invalidated {
                reason: InvalidationReason::TargetRemoved,
                ..
            }
        ));

        // Nor does a benign, unrelated event undo it.
        let state = apply_event(
            state,
            &DeviceEvent::InterfacesAdded {
                object_path: block_path,
                interfaces: vec!["org.freedesktop.UDisks2.Block".to_string()],
            },
        );

        assert!(matches!(state, SelectionState::Invalidated { .. }));
    }

    // M. An explicit user re-selection always starts a brand new Selection
    // with a new baseline, regardless of any prior state.
    #[test]
    fn explicit_reselect_creates_new_selection_regardless_of_prior_state() {
        let snapshot = base_device();
        let block_path = snapshot.block_path.clone();
        let state = select(snapshot).unwrap();
        let state = apply_event(state, &interfaces_removed(&block_path));

        assert!(matches!(state, SelectionState::Invalidated { .. }));

        // The old, invalidated `state` is simply not consulted here — select()
        // takes only the new baseline.
        let mut new_baseline = base_device();
        new_baseline.diskseq = Some(99);
        let reselected = select(new_baseline).unwrap();

        assert!(matches!(reselected, SelectionState::Selected { .. }));
    }

    fn fd_metadata(major: u32, minor: u32, size: Option<u64>) -> FdMetadata {
        FdMetadata {
            major,
            minor,
            size,
            proc_fd_target: None,
        }
    }

    // Opens a plain, throwaway regular file under the OS temp directory --
    // never a block device -- and wraps it via the test-only constructor, so
    // Write Gate tests can exercise real handle-ownership transfer without
    // any D-Bus call. `tag` plus a process-global counter keep the path
    // unique across concurrently-running tests. The directory entry is
    // removed immediately (the open fd stays perfectly valid on Linux after
    // unlinking), so no leftover file survives a test, including a panicking
    // one. Returns the path anyway, purely as a diagnostic label a test can
    // grep for in `/proc/self/fd/<n>` while the fd is still open.
    fn test_handle_with_temp_file(tag: &str) -> (std::path::PathBuf, OpenedDeviceHandle) {
        use std::sync::atomic::{AtomicU64, Ordering};

        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);

        let path = std::env::temp_dir().join(format!(
            "linux-usb-writer-core-test-{tag}-{}-{id}.tmp",
            std::process::id()
        ));

        let file = std::fs::File::create(&path).expect("create temp file for core.rs test");
        std::fs::remove_file(&path).expect("unlink temp file for core.rs test");

        (path, OpenedDeviceHandle::from_file_for_test(file))
    }

    // Same as `test_handle_with_temp_file`, but the directory entry is left
    // in place instead of being unlinked immediately. Only needed by tests
    // that must reopen the file *by path* afterward (to check what was
    // actually written to it) -- every other test uses the unlink-immediately
    // variant above. The caller is responsible for removing the returned
    // path once done with it.
    fn test_handle_with_persistent_temp_file(tag: &str) -> (std::path::PathBuf, OpenedDeviceHandle) {
        use std::sync::atomic::{AtomicU64, Ordering};

        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);

        let path = std::env::temp_dir().join(format!(
            "linux-usb-writer-core-test-{tag}-{}-{id}.persistent.tmp",
            std::process::id()
        ));

        let file = std::fs::File::create(&path).expect("create temp file for core.rs test");

        (path, OpenedDeviceHandle::from_file_for_test(file))
    }

    // FD-binding A. FD major/minor and size all match the current snapshot -> Match.
    #[test]
    fn fd_binding_matching_major_minor_and_size_is_match() {
        let snapshot = base_device();
        let metadata = fd_metadata(snapshot.major, snapshot.minor, Some(snapshot.size));

        assert_eq!(
            check_fd_binding(&snapshot, Some(&metadata)),
            FdBindingCheck::Match
        );
    }

    // FD-binding B. FD major differs from the snapshot's -> Mismatch.
    #[test]
    fn fd_binding_major_mismatch_is_mismatch() {
        let snapshot = base_device();
        let metadata = fd_metadata(snapshot.major + 1, snapshot.minor, Some(snapshot.size));

        assert_eq!(
            check_fd_binding(&snapshot, Some(&metadata)),
            FdBindingCheck::Mismatch
        );
    }

    // FD-binding C. FD minor differs from the snapshot's -> Mismatch.
    #[test]
    fn fd_binding_minor_mismatch_is_mismatch() {
        let snapshot = base_device();
        let metadata = fd_metadata(snapshot.major, snapshot.minor + 1, Some(snapshot.size));

        assert_eq!(
            check_fd_binding(&snapshot, Some(&metadata)),
            FdBindingCheck::Mismatch
        );
    }

    // FD-binding D. major/minor match but the ioctl-reported size doesn't -> Mismatch.
    #[test]
    fn fd_binding_size_mismatch_is_mismatch() {
        let snapshot = base_device();
        let metadata = fd_metadata(snapshot.major, snapshot.minor, Some(snapshot.size + 1));

        assert_eq!(
            check_fd_binding(&snapshot, Some(&metadata)),
            FdBindingCheck::Mismatch
        );
    }

    // FD-binding E. No FD metadata could be obtained at all -> InsufficientInformation
    // (never assumed to be a Match).
    #[test]
    fn fd_binding_missing_metadata_is_insufficient_information() {
        let snapshot = base_device();

        assert_eq!(
            check_fd_binding(&snapshot, None),
            FdBindingCheck::InsufficientInformation
        );
    }

    // Pre-open F. An Invalidated Selection must never be considered ready to
    // open, regardless of why it was invalidated.
    #[test]
    fn invalidated_selection_is_not_ready_to_open() {
        let snapshot = base_device();
        let block_path = snapshot.block_path.clone();
        let state = select(snapshot).unwrap();
        let state = apply_event(state, &interfaces_removed(&block_path));

        assert!(matches!(state, SelectionState::Invalidated { .. }));
        assert!(!is_ready_to_open(&state));
    }

    // Pre-open G. A target the Safety Engine blocks (e.g. a system disk like
    // an internal NVMe with a critical mount) is rejected by `select()`
    // itself, so no SelectionState ever reaches "ready to open" for it — the
    // Safety Engine's own logic is reused, not re-derived here.
    #[test]
    fn blocked_target_never_becomes_ready_to_open() {
        let mut system_disk = base_device();
        system_disk.hint_system = true;
        system_disk.mount_points = vec!["/".to_string()];

        let result = select(system_disk);

        assert!(matches!(result, Err(SelectionError::NotSelectable)));
        assert!(!is_ready_to_open(&SelectionState::NoSelection));
    }

    fn matching_fd_metadata(snapshot: &DeviceSnapshot) -> FdMetadata {
        fd_metadata(snapshot.major, snapshot.minor, Some(snapshot.size))
    }

    const TEST_IMAGE_SIZE: u64 = 1_000_000;

    // Gate A / Confirmation success. Every condition holds and the
    // confirmation matches exactly -> prepare_for_open succeeds, and
    // finalize_prepared_write with a matching FD produces a PreparedWrite.
    #[test]
    fn prepare_for_open_succeeds_with_matching_confirmation() {
        let snapshot = base_device();
        let state = select(snapshot.clone()).unwrap();
        let image = ImageSelection::new(TEST_IMAGE_SIZE);
        let token = ConfirmationToken::new(&snapshot, image, selection_generation_of(&state));

        let ready = prepare_for_open(
            &state,
            SnapshotFetchOutcome::Found(base_device()),
            image,
            Some(&token),
        )
        .unwrap();

        let metadata = matching_fd_metadata(&snapshot);
        let (_path, handle) = test_handle_with_temp_file("succeeds");
        let prepared = finalize_prepared_write(ready, Some(handle), Some(&metadata)).unwrap();

        assert_eq!(prepared.target_block_path, snapshot.block_path);
        assert_eq!(prepared.target_size, snapshot.size);
        assert_eq!(prepared.image_size, TEST_IMAGE_SIZE);
    }

    // Gate: NoSelection can never reach OpenDevice.
    #[test]
    fn prepare_for_open_rejects_no_selection() {
        let result = prepare_for_open(
            &SelectionState::NoSelection,
            SnapshotFetchOutcome::Found(base_device()),
            ImageSelection::new(TEST_IMAGE_SIZE),
            None,
        );

        assert!(matches!(result, Err(WriteGateError::NoSelection)));
    }

    // Gate B. confirmationなし -> ConfirmationMissing, even though every
    // other condition is satisfied.
    #[test]
    fn prepare_for_open_rejects_missing_confirmation() {
        let state = select(base_device()).unwrap();

        let result = prepare_for_open(
            &state,
            SnapshotFetchOutcome::Found(base_device()),
            ImageSelection::new(TEST_IMAGE_SIZE),
            None,
        );

        assert!(matches!(result, Err(WriteGateError::ConfirmationMissing)));
    }

    // Gate C / Confirmation-mismatch A. A confirmation made for target A
    // must not authorize a write to a different target B.
    #[test]
    fn prepare_for_open_rejects_confirmation_for_different_target() {
        let snapshot = base_device();
        let state = select(snapshot.clone()).unwrap();

        let mut other_target = base_device();
        other_target.block_path = "/org/freedesktop/UDisks2/block_devices/sdz".to_string();
        let image = ImageSelection::new(TEST_IMAGE_SIZE);
        let token = ConfirmationToken::new(&other_target, image, selection_generation_of(&state));

        let result = prepare_for_open(
            &state,
            SnapshotFetchOutcome::Found(snapshot),
            image,
            Some(&token),
        );

        assert!(matches!(result, Err(WriteGateError::ConfirmationMismatch)));
    }

    // Gate D / Confirmation-mismatch B. A confirmation made for one image
    // size must not authorize writing a different-sized image.
    #[test]
    fn prepare_for_open_rejects_confirmation_for_different_image_size() {
        let snapshot = base_device();
        let state = select(snapshot.clone()).unwrap();
        let image = ImageSelection::new(TEST_IMAGE_SIZE);
        let token = ConfirmationToken::new(&snapshot, image, selection_generation_of(&state));

        let result = prepare_for_open(
            &state,
            SnapshotFetchOutcome::Found(snapshot),
            ImageSelection::new(TEST_IMAGE_SIZE * 5),
            Some(&token),
        );

        assert!(matches!(result, Err(WriteGateError::ConfirmationMismatch)));
    }

    // Gate E. An already-Invalidated Selection can never reach OpenDevice,
    // confirmation or not.
    #[test]
    fn prepare_for_open_rejects_invalidated_selection() {
        let snapshot = base_device();
        let block_path = snapshot.block_path.clone();
        let state = select(snapshot.clone()).unwrap();
        let state = apply_event(state, &interfaces_removed(&block_path));
        let image = ImageSelection::new(TEST_IMAGE_SIZE);
        let token = ConfirmationToken::new(&snapshot, image, selection_generation_of(&state));

        let result = prepare_for_open(
            &state,
            SnapshotFetchOutcome::Found(snapshot),
            image,
            Some(&token),
        );

        assert!(matches!(result, Err(WriteGateError::SelectionInvalidated)));
    }

    // Gate: the target-specific re-fetch itself failing (or reporting the
    // target gone) must block the gate.
    #[test]
    fn prepare_for_open_rejects_snapshot_refresh_failure() {
        let snapshot = base_device();
        let state = select(snapshot.clone()).unwrap();
        let image = ImageSelection::new(TEST_IMAGE_SIZE);
        let token = ConfirmationToken::new(&snapshot, image, selection_generation_of(&state));

        let result = prepare_for_open(
            &state,
            SnapshotFetchOutcome::Error("simulated D-Bus failure".to_string()),
            image,
            Some(&token),
        );

        assert!(matches!(result, Err(WriteGateError::SnapshotRefreshFailed)));
    }

    // Gate F. Identity Changed on the re-fetched current -> IdentityChanged.
    #[test]
    fn prepare_for_open_rejects_identity_changed() {
        let snapshot = base_device();
        let state = select(snapshot.clone()).unwrap();
        let image = ImageSelection::new(TEST_IMAGE_SIZE);
        let token = ConfirmationToken::new(&snapshot, image, selection_generation_of(&state));

        let mut current = snapshot;
        current.serial = "OTHER-SERIAL-0002".to_string();

        let result = prepare_for_open(
            &state,
            SnapshotFetchOutcome::Found(current),
            image,
            Some(&token),
        );

        assert!(matches!(result, Err(WriteGateError::IdentityChanged)));
    }

    // Gate: Identity InsufficientIdentity -> IdentityInsufficient.
    #[test]
    fn prepare_for_open_rejects_identity_insufficient() {
        let snapshot = base_device();
        let state = select(snapshot.clone()).unwrap();
        let image = ImageSelection::new(TEST_IMAGE_SIZE);
        let token = ConfirmationToken::new(&snapshot, image, selection_generation_of(&state));

        let mut current = snapshot;
        current.serial = String::new();

        let result = prepare_for_open(
            &state,
            SnapshotFetchOutcome::Found(current),
            image,
            Some(&token),
        );

        assert!(matches!(result, Err(WriteGateError::IdentityInsufficient)));
    }

    // Gate G. Instance Recreated (diskseq changed) -> InstanceRecreated.
    #[test]
    fn prepare_for_open_rejects_instance_recreated() {
        let snapshot = base_device();
        let state = select(snapshot.clone()).unwrap();
        let image = ImageSelection::new(TEST_IMAGE_SIZE);
        let token = ConfirmationToken::new(&snapshot, image, selection_generation_of(&state));

        let mut current = snapshot;
        current.diskseq = Some(19);

        let result = prepare_for_open(
            &state,
            SnapshotFetchOutcome::Found(current),
            image,
            Some(&token),
        );

        assert!(matches!(result, Err(WriteGateError::InstanceRecreated)));
    }

    // Gate: Instance InsufficientInformation -> InstanceInsufficient.
    #[test]
    fn prepare_for_open_rejects_instance_insufficient() {
        let snapshot = base_device();
        let state = select(snapshot.clone()).unwrap();
        let image = ImageSelection::new(TEST_IMAGE_SIZE);
        let token = ConfirmationToken::new(&snapshot, image, selection_generation_of(&state));

        let mut current = snapshot;
        current.diskseq = None;

        let result = prepare_for_open(
            &state,
            SnapshotFetchOutcome::Found(current),
            image,
            Some(&token),
        );

        assert!(matches!(result, Err(WriteGateError::InstanceInsufficient)));
    }

    // Gate H. Safety re-evaluation on current now Blocked -> SafetyRejected.
    #[test]
    fn prepare_for_open_rejects_safety_blocked() {
        let snapshot = base_device();
        let state = select(snapshot.clone()).unwrap();
        let image = ImageSelection::new(TEST_IMAGE_SIZE);
        let token = ConfirmationToken::new(&snapshot, image, selection_generation_of(&state));

        let mut current = snapshot;
        current.hint_system = true;

        let result = prepare_for_open(
            &state,
            SnapshotFetchOutcome::Found(current),
            image,
            Some(&token),
        );

        assert!(matches!(result, Err(WriteGateError::SafetyRejected)));
    }

    // Gate I. image_size > target_size -> ImageTooLarge.
    #[test]
    fn prepare_for_open_rejects_image_larger_than_target() {
        let snapshot = base_device();
        let state = select(snapshot.clone()).unwrap();
        let too_large = snapshot.size + 1;
        let image = ImageSelection::new(too_large);
        let token = ConfirmationToken::new(&snapshot, image, selection_generation_of(&state));

        let result = prepare_for_open(
            &state,
            SnapshotFetchOutcome::Found(snapshot),
            image,
            Some(&token),
        );

        assert!(matches!(result, Err(WriteGateError::ImageTooLarge)));
    }

    // finalize J. OpenDevice itself failing (represented as `None` — there is
    // no handle to hand over) -> OpenDeviceFailed, regardless of FD metadata
    // (there is none to check yet).
    #[test]
    fn finalize_prepared_write_rejects_open_device_failure() {
        let snapshot = base_device();
        let ready = ReadyToOpen {
            plan: WritePlan::new(TEST_IMAGE_SIZE, snapshot.size, DEFAULT_CHUNK_SIZE).unwrap(),
            current: snapshot,
        };

        let result = finalize_prepared_write(ready, None, None);

        assert!(matches!(result, Err(WriteGateError::OpenDeviceFailed)));
    }

    // finalize K (Mismatch). OpenDevice succeeded (a real, owned test handle
    // is handed over) but the FD's own major/minor don't match the
    // just-verified snapshot -> FdBindingMismatch, and no PreparedWrite is
    // produced (the handle is simply dropped/closed inside the rejected call).
    #[test]
    fn finalize_prepared_write_rejects_fd_binding_mismatch() {
        let snapshot = base_device();
        let metadata = fd_metadata(snapshot.major + 1, snapshot.minor, Some(snapshot.size));
        let ready = ReadyToOpen {
            plan: WritePlan::new(TEST_IMAGE_SIZE, snapshot.size, DEFAULT_CHUNK_SIZE).unwrap(),
            current: snapshot,
        };
        let (_path, handle) = test_handle_with_temp_file("mismatch");

        let result = finalize_prepared_write(ready, Some(handle), Some(&metadata));

        assert!(matches!(result, Err(WriteGateError::FdBindingMismatch)));
    }

    // finalize K (InsufficientInformation). OpenDevice succeeded (a real
    // handle is handed over) but FD metadata could not be obtained ->
    // FdBindingInsufficient, never assumed to be a Match, and no
    // PreparedWrite is produced.
    #[test]
    fn finalize_prepared_write_rejects_fd_binding_insufficient_information() {
        let snapshot = base_device();
        let ready = ReadyToOpen {
            plan: WritePlan::new(TEST_IMAGE_SIZE, snapshot.size, DEFAULT_CHUNK_SIZE).unwrap(),
            current: snapshot,
        };
        let (_path, handle) = test_handle_with_temp_file("insufficient");

        let result = finalize_prepared_write(ready, Some(handle), None);

        assert!(matches!(result, Err(WriteGateError::FdBindingInsufficient)));
    }

    // finalize (ownership). On success, PreparedWrite is now the sole owner
    // of the handle that was handed to finalize_prepared_write: dropping the
    // PreparedWrite must close the underlying fd via ordinary RAII, with no
    // explicit close call anywhere in this module. Verified via
    // `linux_access::{fd_proc_target_for_test, assert_fd_closed_for_test}`
    // (fd-number-reuse-proof; see their doc comments -- a naive "does
    // /proc/self/fd/<n> still exist" check previously caused a real,
    // observed flaky failure here, since a concurrently-running test can
    // have the OS hand the same fd number to an unrelated fd before the
    // check runs). This also doubles as ActiveWrite test E: a PreparedWrite
    // that is dropped *without* ever calling `begin()` still closes its fd.
    #[test]
    fn finalize_prepared_write_success_owns_handle_and_drop_closes_it() {
        let snapshot = base_device();
        let ready = ReadyToOpen {
            plan: WritePlan::new(TEST_IMAGE_SIZE, snapshot.size, DEFAULT_CHUNK_SIZE).unwrap(),
            current: snapshot.clone(),
        };
        let metadata = matching_fd_metadata(&snapshot);
        let (_path, handle) = test_handle_with_temp_file("drop-closes-fd");
        let raw_fd = handle.raw_fd_for_test();

        assert!(
            std::path::Path::new(&format!("/proc/self/fd/{raw_fd}")).exists(),
            "fd should still be open before finalize_prepared_write"
        );

        let prepared = finalize_prepared_write(ready, Some(handle), Some(&metadata)).unwrap();

        let target_before_drop = linux_access::fd_proc_target_for_test(raw_fd);
        assert!(
            target_before_drop.is_some(),
            "fd should still be open while PreparedWrite is alive"
        );

        drop(prepared);

        linux_access::assert_fd_closed_for_test(raw_fd, target_before_drop.as_deref());
    }

    // ActiveWrite A/B. `begin()` consumes a PreparedWrite and carries its
    // target/image identification over unchanged into the new ActiveWrite.
    // (The PreparedWrite value itself is gone after this -- there is no way
    // to re-read its fields afterward, which is why they are captured first.)
    #[test]
    fn prepared_write_begin_consumes_into_active_write_with_matching_fields() {
        let snapshot = base_device();
        let ready = ReadyToOpen {
            plan: WritePlan::new(TEST_IMAGE_SIZE, snapshot.size, DEFAULT_CHUNK_SIZE).unwrap(),
            current: snapshot.clone(),
        };
        let metadata = matching_fd_metadata(&snapshot);
        let (_path, handle) = test_handle_with_temp_file("begin-fields");
        let prepared = finalize_prepared_write(ready, Some(handle), Some(&metadata)).unwrap();

        let expected_block_path = prepared.target_block_path.clone();
        let expected_target_size = prepared.target_size;
        let expected_image_size = prepared.image_size;

        let active = prepared.begin();

        assert_eq!(active.target_block_path, expected_block_path);
        assert_eq!(active.target_size, expected_target_size);
        assert_eq!(active.image_size, expected_image_size);
    }

    // ActiveWrite C/D. The fd moves from PreparedWrite to ActiveWrite with no
    // duplication anywhere (no dup()/try_clone()): it stays open for the
    // entire lifetime of the ActiveWrite, and closes via ordinary RAII
    // exactly when the ActiveWrite itself is dropped -- not before, not
    // after. Uses the fd-number-reuse-proof close check (see
    // `linux_access::assert_fd_closed_for_test`'s doc comment): this exact
    // test previously failed once under `cargo test`'s parallel execution
    // because a naive "does /proc/self/fd/<n> still exist" check was fooled
    // by the OS reusing the just-closed fd number for an unrelated fd before
    // the check ran.
    #[test]
    fn active_write_holds_moved_fd_until_dropped() {
        let snapshot = base_device();
        let ready = ReadyToOpen {
            plan: WritePlan::new(TEST_IMAGE_SIZE, snapshot.size, DEFAULT_CHUNK_SIZE).unwrap(),
            current: snapshot.clone(),
        };
        let metadata = matching_fd_metadata(&snapshot);
        let (_path, handle) = test_handle_with_temp_file("active-drop-closes-fd");
        let raw_fd = handle.raw_fd_for_test();

        let prepared = finalize_prepared_write(ready, Some(handle), Some(&metadata)).unwrap();
        assert!(
            std::path::Path::new(&format!("/proc/self/fd/{raw_fd}")).exists(),
            "fd should still be open right after finalize_prepared_write"
        );

        let active = prepared.begin();
        let target_before_drop = linux_access::fd_proc_target_for_test(raw_fd);
        assert!(
            target_before_drop.is_some(),
            "fd should still be open once ownership has moved into ActiveWrite"
        );

        drop(active);
        linux_access::assert_fd_closed_for_test(raw_fd, target_before_drop.as_deref());
    }

    // ActiveWrite C/D/E/F. `writer_target()` yields a genuine `std::io::Write`
    // borrowed from the FD `ActiveWrite` owns: a known, small pattern written
    // through it round-trips exactly when the (regular, never a block
    // device) temp file is reopened by path afterward. The borrow itself is
    // scoped -- once it ends, `active`'s own plain data fields are still
    // readable, proving `writer_target()` did not consume or otherwise
    // invalidate `active`.
    #[test]
    fn active_write_target_writes_known_data_to_regular_file() {
        let snapshot = base_device();
        let ready = ReadyToOpen {
            plan: WritePlan::new(TEST_IMAGE_SIZE, snapshot.size, DEFAULT_CHUNK_SIZE).unwrap(),
            current: snapshot.clone(),
        };
        let metadata = matching_fd_metadata(&snapshot);
        let (path, handle) = test_handle_with_persistent_temp_file("write-known-data");
        let prepared = finalize_prepared_write(ready, Some(handle), Some(&metadata)).unwrap();
        let mut active = prepared.begin();

        const PATTERN: &[u8] = b"linux-usb-writer ActiveWriteTarget self-test pattern";

        {
            // C: obtained only via ActiveWrite. D: a genuine Write.
            let mut target = active.writer_target();
            target
                .write_all(PATTERN)
                .expect("write_all through ActiveWriteTarget");
            target.flush().expect("flush through ActiveWriteTarget");
        }

        // F: the exclusive borrow above has ended; `active` is still alive
        // and its own fields are still readable.
        assert_eq!(active.target_block_path, snapshot.block_path);

        drop(active);

        // E: the regular file's content matches exactly what was written.
        let written = std::fs::read(&path).expect("reopen temp file for read-back");
        let _ = std::fs::remove_file(&path);

        assert_eq!(written, PATTERN);
    }

    // Requirement 9 (Writer Core type compatibility). `ActiveWriteTarget`
    // must be usable anywhere a bare `W: std::io::Write` is expected -- e.g.
    // a future `writer::write(&plan, source, active.writer_target(), ...)`
    // call -- checked here purely at the type level. `writer::write()` itself
    // is never called; this only proves the type would fit its `W` parameter.
    fn accepts_write<T: std::io::Write>(_: &mut T) {}

    #[test]
    fn active_write_target_is_compatible_with_generic_write_bound() {
        let snapshot = base_device();
        let ready = ReadyToOpen {
            plan: WritePlan::new(TEST_IMAGE_SIZE, snapshot.size, DEFAULT_CHUNK_SIZE).unwrap(),
            current: snapshot.clone(),
        };
        let metadata = matching_fd_metadata(&snapshot);
        let (_path, handle) = test_handle_with_temp_file("type-compat");
        let prepared = finalize_prepared_write(ready, Some(handle), Some(&metadata)).unwrap();
        let mut active = prepared.begin();

        let mut target = active.writer_target();
        accepts_write(&mut target);
    }

    // ---------------------------------------------------------------------
    // Integration: ActiveWrite -> ActiveWriteTarget -> writer::write()
    // (regular files only)
    //
    // Everything below drives the *entire* production sequence --
    // select -> ConfirmationToken -> prepare_for_open -> (simulated
    // OpenDevice via the test-only `from_file_for_test`) ->
    // finalize_prepared_write -> PreparedWrite -> begin() -> ActiveWrite ->
    // writer_target() -- and then, for the first time anywhere in this
    // crate, actually calls `writer::write()` with the resulting
    // `ActiveWriteTarget` as its `W: Write` target. `writer.rs` itself is
    // untouched: every call below uses its existing, unmodified `WritePlan`,
    // `write()`, `WriteError`, and the Gate's own `DEFAULT_CHUNK_SIZE`-based
    // plan (nothing here fabricates a bespoke plan the real Gate wouldn't
    // produce).
    //
    // This connection is reachable ONLY from this `#[cfg(test)]` module: the
    // real path (`linux_access::open_device` -> a real `OpenedDeviceHandle`)
    // never appears here, `from_file_for_test` is `#[cfg(test)]`-only and
    // unreachable from any production build, and `main.rs` calls none of
    // this. No `/dev/*` path, no real USB/SD/NVMe device, and no
    // `linux_access::open_device` call appears anywhere below.
    // ---------------------------------------------------------------------

    // Drives the full Gate sequence above against a plain, throwaway regular
    // file and returns the resulting `ActiveWrite` together with the exact
    // `WritePlan` `prepare_for_open` produced for it (the same plan a real
    // caller would pass to `writer::write()`). `image_size` doubles as the
    // DeviceSnapshot's declared size floor and the ConfirmationToken's bound
    // value, exactly as a real Write Gate pass requires them to agree.
    // `persistent` selects between the unlink-immediately temp file helper
    // (when the test never needs to reopen it by path) and the
    // path-preserving one (when it does, e.g. to check written content).
    fn gate_pass_active_write(
        tag: &str,
        image_size: u64,
        target_size: u64,
        persistent: bool,
    ) -> (Option<std::path::PathBuf>, ActiveWrite, WritePlan) {
        let mut snapshot = base_device();
        snapshot.size = target_size;

        let state = select(snapshot.clone()).unwrap();
        let image = ImageSelection::new(image_size);
        let confirmation = ConfirmationToken::new(&snapshot, image, selection_generation_of(&state));

        let ready = prepare_for_open(
            &state,
            SnapshotFetchOutcome::Found(snapshot.clone()),
            image,
            Some(&confirmation),
        )
        .expect("prepare_for_open should succeed for a freshly matching snapshot/confirmation");

        let plan = ready.plan;
        let metadata = matching_fd_metadata(&snapshot);

        let (path, handle) = if persistent {
            let (path, handle) = test_handle_with_persistent_temp_file(tag);
            (Some(path), handle)
        } else {
            let (_path, handle) = test_handle_with_temp_file(tag);
            (None, handle)
        };

        let prepared = finalize_prepared_write(ready, Some(handle), Some(&metadata))
            .expect("finalize_prepared_write should succeed with matching FD metadata");

        (path, prepared.begin(), plan)
    }

    // Integration A (normal case). The full chain connects end to end for
    // the first time: a known, small source writes completely through
    // `writer::write()` into an `ActiveWriteTarget`. The written byte count
    // matches `image_size`, the regular file's content matches the source
    // exactly, and `active` itself is still usable (its own fields are still
    // readable) once the `write()` call -- and the borrow it took via
    // `writer_target()` -- has returned.
    #[test]
    fn integration_writes_small_known_source_through_full_gate_chain() {
        const SOURCE: &[u8] = b"linux-usb-writer integration test: small known source";
        let image_size = SOURCE.len() as u64;
        let target_size = image_size + 1024;

        let (path, mut active, plan) =
            gate_pass_active_write("integration-small", image_size, target_size, true);
        let path = path.expect("persistent temp file path");

        let written = writer::write(
            &plan,
            std::io::Cursor::new(SOURCE.to_vec()),
            active.writer_target(),
            |_| {},
            || false,
        )
        .expect("write through the full gate chain should succeed");

        assert_eq!(written, image_size);
        assert_eq!(active.target_block_path, base_device().block_path);

        drop(active);

        let on_disk = std::fs::read(&path).expect("reopen temp file for read-back");
        let _ = std::fs::remove_file(&path);
        assert_eq!(on_disk, SOURCE);
    }

    // Integration B/C (multiple chunks + progress). The Gate's `WritePlan`
    // always uses `DEFAULT_CHUNK_SIZE`, so an image over 1 MiB forces more
    // than one chunk. Confirms the reconstructed file is byte-for-byte
    // correct AND that the existing progress callback still reports a
    // monotonically increasing `bytes_written` ending exactly at
    // `image_size` when the target is an `ActiveWriteTarget`.
    #[test]
    fn integration_multiple_chunks_and_monotonic_progress_through_full_gate_chain() {
        let image_size = 2 * DEFAULT_CHUNK_SIZE as u64;
        let target_size = image_size;
        let data: Vec<u8> = (0..image_size).map(|i| (i % 256) as u8).collect();

        let (path, mut active, plan) =
            gate_pass_active_write("integration-multi-chunk", image_size, target_size, true);
        let path = path.expect("persistent temp file path");

        let mut progress_log = Vec::new();
        let written = writer::write(
            &plan,
            std::io::Cursor::new(data.clone()),
            active.writer_target(),
            |progress| progress_log.push(progress.bytes_written),
            || false,
        )
        .expect("multi-chunk write through the full gate chain should succeed");

        assert_eq!(written, image_size);
        assert!(!progress_log.is_empty());
        assert!(progress_log.windows(2).all(|pair| pair[0] < pair[1]));
        assert_eq!(*progress_log.last().unwrap(), image_size);

        drop(active);

        let on_disk = std::fs::read(&path).expect("reopen temp file for read-back");
        let _ = std::fs::remove_file(&path);
        assert_eq!(on_disk, data);
    }

    // Integration D (cancellation). `is_cancelled` -- the same closure
    // parameter `writer::write()` has always had -- still works when the
    // target is an `ActiveWriteTarget`: the write stops partway through,
    // leaving the target only partially written and reporting exactly how
    // far it got, never silently completing.
    #[test]
    fn integration_cancellation_stops_partway_through_full_gate_chain() {
        let image_size = 3 * DEFAULT_CHUNK_SIZE as u64;
        let target_size = image_size;
        let data = vec![9u8; image_size as usize];

        let (_path, mut active, plan) =
            gate_pass_active_write("integration-cancel", image_size, target_size, false);

        let mut checks = 0;
        let result = writer::write(
            &plan,
            std::io::Cursor::new(data),
            active.writer_target(),
            |_| {},
            || {
                checks += 1;
                checks > 1
            },
        );

        match result {
            Err(writer::WriteError::Cancelled { bytes_written }) => {
                assert!(bytes_written > 0);
                assert!(bytes_written < image_size);
            }
            other => panic!("expected Cancelled, got {other:?}"),
        }
    }

    // Integration E (source shorter than planned). A source shorter than
    // the Gate-approved `image_size` must still be reported as
    // `SourceTooShort` through the full gate chain, never as a silently
    // short "successful" write.
    #[test]
    fn integration_source_too_short_through_full_gate_chain() {
        let image_size = 1000u64;
        let target_size = 2000u64;
        let short_source = vec![1u8; 400];

        let (_path, mut active, plan) =
            gate_pass_active_write("integration-short-source", image_size, target_size, false);

        let result = writer::write(
            &plan,
            std::io::Cursor::new(short_source),
            active.writer_target(),
            |_| {},
            || false,
        );

        match result {
            Err(writer::WriteError::SourceTooShort { bytes_written }) => {
                assert_eq!(bytes_written, 400);
            }
            other => panic!("expected SourceTooShort, got {other:?}"),
        }
    }

    // Integration F (target write error). A genuine `write()` syscall
    // failure (EBADF, from writing to an fd opened read-only) surfaces as
    // `WriteError::TargetWrite` through the full gate chain. Reopening the
    // *same* regular file read-only is enough to make real writes fail at
    // the OS level, so this needs no change to `ActiveWriteTarget`'s own
    // design to inject the failure.
    #[test]
    fn integration_target_write_error_through_full_gate_chain() {
        let image_size = 64u64;
        let target_size = 128u64;

        let mut snapshot = base_device();
        snapshot.size = target_size;
        let state = select(snapshot.clone()).unwrap();
        let image = ImageSelection::new(image_size);
        let confirmation = ConfirmationToken::new(&snapshot, image, selection_generation_of(&state));
        let ready = prepare_for_open(
            &state,
            SnapshotFetchOutcome::Found(snapshot.clone()),
            image,
            Some(&confirmation),
        )
        .unwrap();
        let plan = ready.plan;
        let metadata = matching_fd_metadata(&snapshot);

        let path = std::env::temp_dir().join(format!(
            "linux-usb-writer-core-test-target-write-error-{}.tmp",
            std::process::id()
        ));
        std::fs::File::create(&path).expect("create temp file for read-only test");
        let read_only_file = std::fs::OpenOptions::new()
            .read(true)
            .open(&path)
            .expect("reopen temp file read-only");
        let handle = OpenedDeviceHandle::from_file_for_test(read_only_file);

        let prepared = finalize_prepared_write(ready, Some(handle), Some(&metadata)).unwrap();
        let mut active = prepared.begin();

        let source = std::io::Cursor::new(vec![7u8; image_size as usize]);
        let result = writer::write(&plan, source, active.writer_target(), |_| {}, || false);

        let _ = std::fs::remove_file(&path);

        assert!(matches!(result, Err(writer::WriteError::TargetWrite(_))));
    }

    // Gate L / Confirmation-mismatch C. A confirmation captured against an
    // earlier generation (diskseq) of the target must not authorize a write
    // once the target's current diskseq has moved on — even though Identity
    // and Instance both still agree the *baseline* and *current* are the
    // same generation. This is exactly the case a plain Identity/Instance
    // re-check cannot catch on its own: it takes the confirmation's own
    // remembered diskseq to detect it.
    #[test]
    fn prepare_for_open_rejects_confirmation_with_stale_diskseq() {
        let old_snapshot = base_device(); // diskseq = Some(12)

        let mut new_snapshot = base_device();
        new_snapshot.diskseq = Some(99);
        let state = select(new_snapshot.clone()).unwrap();

        // Same selection_generation as `state` -- built from `old_snapshot`
        // only to carry its stale diskseq, so diskseq is the sole varying
        // condition this test isolates (see the two dedicated
        // selection_generation-only tests below for the reselect case). Same
        // ImageSelection on both sides too, so image_generation is not the
        // condition under test here either.
        let image = ImageSelection::new(TEST_IMAGE_SIZE);
        let stale_token = ConfirmationToken::new(
            &old_snapshot,
            image,
            selection_generation_of(&state),
        );

        let result = prepare_for_open(
            &state,
            SnapshotFetchOutcome::Found(new_snapshot),
            image,
            Some(&stale_token),
        );

        assert!(matches!(result, Err(WriteGateError::ConfirmationMismatch)));
    }

    // Gate M / Confirmation-mismatch D / instance change. After a Selection
    // is Invalidated and the user explicitly re-selects following a real
    // replug (a fresh baseline, new diskseq), a confirmation obtained before
    // that re-selection must not carry over. This is the diskseq/Instance
    // side of the story; see the two selection_generation-only tests below
    // for the same-device, unchanged-diskseq case diskseq alone cannot
    // catch.
    #[test]
    fn prepare_for_open_rejects_confirmation_after_reselect_with_diskseq_change() {
        let original = base_device();
        let block_path = original.block_path.clone();
        let state = select(original.clone()).unwrap();
        let image = ImageSelection::new(TEST_IMAGE_SIZE);
        let old_token = ConfirmationToken::new(
            &original,
            image,
            selection_generation_of(&state),
        );

        let state = apply_event(state, &interfaces_removed(&block_path));
        assert!(matches!(state, SelectionState::Invalidated { .. }));

        let mut reselected_snapshot = base_device();
        reselected_snapshot.diskseq = Some(99);
        let state = select(reselected_snapshot.clone()).unwrap();

        let result = prepare_for_open(
            &state,
            SnapshotFetchOutcome::Found(reselected_snapshot),
            image,
            Some(&old_token),
        );

        assert!(matches!(result, Err(WriteGateError::ConfirmationMismatch)));
    }

    // selection_generation A / Confirmation-mismatch E. Reselecting the
    // *exact same*, still-connected device -- same block_path, same size,
    // same identity, same diskseq, nothing physically changed at all -- must
    // still invalidate a confirmation obtained before that reselect. This is
    // precisely the gap `target_diskseq` alone cannot close (diskseq is
    // unchanged here, deliberately, unlike the test above): only
    // `selection_generation` catches it, because `select()` always mints a
    // fresh generation on every explicit call, even for the same device.
    #[test]
    fn prepare_for_open_rejects_confirmation_after_same_device_reselect_with_unchanged_diskseq() {
        let snapshot = base_device();
        let state = select(snapshot.clone()).unwrap();
        // Same ImageSelection (same image_generation) on both sides -- this
        // test isolates selection_generation alone, not image_generation.
        let image = ImageSelection::new(TEST_IMAGE_SIZE);
        let old_token = ConfirmationToken::new(&snapshot, image, selection_generation_of(&state));

        // Explicit reselect of the exact same device. No replug, no field on
        // `snapshot` differs at all -- only `selection_generation` changes.
        let state = select(snapshot.clone()).unwrap();

        let result = prepare_for_open(
            &state,
            SnapshotFetchOutcome::Found(snapshot),
            image,
            Some(&old_token),
        );

        assert!(matches!(result, Err(WriteGateError::ConfirmationMismatch)));
    }

    // selection_generation B. The same same-device reselect as above does
    // not permanently lock the device out -- only the stale token. A freshly
    // issued ConfirmationToken, bound to the new selection_generation, lets
    // prepare_for_open succeed against the identical snapshot.
    #[test]
    fn prepare_for_open_succeeds_with_fresh_confirmation_after_same_device_reselect() {
        let snapshot = base_device();
        let _first_state = select(snapshot.clone()).unwrap();

        let state = select(snapshot.clone()).unwrap();
        let image = ImageSelection::new(TEST_IMAGE_SIZE);
        let new_token = ConfirmationToken::new(&snapshot, image, selection_generation_of(&state));

        let result = prepare_for_open(
            &state,
            SnapshotFetchOutcome::Found(snapshot),
            image,
            Some(&new_token),
        );

        assert!(result.is_ok());
    }

    // selection_generation C. Every explicit select() call mints a strictly
    // new generation, regardless of whether the device changed: the same
    // device selected twice in a row yields two different generations, which
    // is the property the two tests above rely on.
    #[test]
    fn select_always_mints_a_new_generation_even_for_the_same_device() {
        let snapshot = base_device();

        let first = select(snapshot.clone()).unwrap();
        let second = select(snapshot).unwrap();

        assert_ne!(
            selection_generation_of(&first),
            selection_generation_of(&second)
        );
    }

    // selection_generation D. apply_event()/revalidate() must carry the
    // existing selection_generation through unchanged -- only select()
    // itself ever mints a new one. Checked here via apply_event(); revalidate
    // shares the same destructure/reconstruct pattern.
    #[test]
    fn selection_generation_is_preserved_across_invalidation() {
        let snapshot = base_device();
        let block_path = snapshot.block_path.clone();
        let state = select(snapshot).unwrap();
        let original_generation = selection_generation_of(&state);

        let state = apply_event(state, &interfaces_removed(&block_path));

        assert!(matches!(state, SelectionState::Invalidated { .. }));
        assert_eq!(selection_generation_of(&state), original_generation);
    }

    // image_generation A / Confirmation-mismatch F (most important test for
    // this feature). The user selects image A, gets a confirmation, then --
    // without touching the target selection at all -- explicitly selects a
    // *different* image B of the exact same size. Nothing about the target
    // changed (same block_path, same target_size, same diskseq, same
    // selection_generation -- `state` is never re-derived here) and
    // image_size is identical too; only image_generation differs. The old
    // confirmation must still be rejected, proving image_size alone cannot
    // catch a same-size image swap.
    #[test]
    fn prepare_for_open_rejects_confirmation_after_same_size_image_reselect() {
        let snapshot = base_device();
        let state = select(snapshot.clone()).unwrap();

        let image_a = ImageSelection::new(TEST_IMAGE_SIZE);
        let old_token = ConfirmationToken::new(&snapshot, image_a, selection_generation_of(&state));

        // Explicit reselect of a different image, same size. `state` (the
        // target selection) is untouched.
        let image_b = ImageSelection::new(TEST_IMAGE_SIZE);
        assert_eq!(image_a.image_size(), image_b.image_size());
        assert_ne!(image_a.image_generation(), image_b.image_generation());

        let result = prepare_for_open(
            &state,
            SnapshotFetchOutcome::Found(snapshot),
            image_b,
            Some(&old_token),
        );

        assert!(matches!(result, Err(WriteGateError::ConfirmationMismatch)));
    }

    // image_generation B. The same same-size image reselect as above does
    // not permanently lock the target out -- only the stale token. A freshly
    // issued ConfirmationToken, bound to the new image_generation, lets
    // prepare_for_open succeed against the identical target.
    #[test]
    fn prepare_for_open_succeeds_with_fresh_confirmation_after_image_reselect() {
        let snapshot = base_device();
        let state = select(snapshot.clone()).unwrap();

        let _image_a = ImageSelection::new(TEST_IMAGE_SIZE);
        let image_b = ImageSelection::new(TEST_IMAGE_SIZE);
        let new_token = ConfirmationToken::new(&snapshot, image_b, selection_generation_of(&state));

        let result = prepare_for_open(
            &state,
            SnapshotFetchOutcome::Found(snapshot),
            image_b,
            Some(&new_token),
        );

        assert!(result.is_ok());
    }

    // image_generation C. Every explicit ImageSelection::new() call mints a
    // strictly new generation, regardless of whether image_size matches: the
    // same size selected twice in a row (e.g. two different 4 GiB images, or
    // even the same file picked again) yields two different generations,
    // which is the property the two tests above rely on. This is also the
    // direct evidence that `image_generation` is not a content hash: it says
    // nothing about whether the two selections' bytes are equal, only that
    // they are two distinct selection events.
    #[test]
    fn image_selection_always_mints_a_new_generation_even_for_the_same_size() {
        let first = ImageSelection::new(TEST_IMAGE_SIZE);
        let second = ImageSelection::new(TEST_IMAGE_SIZE);

        assert_eq!(first.image_size(), second.image_size());
        assert_ne!(first.image_generation(), second.image_generation());
    }

    // image_generation D. Copying an existing ImageSelection (it is `Copy`)
    // must never mint a new generation -- only an explicit `ImageSelection::
    // new()` call does. Mirrors `selection_generation`'s equivalent
    // guarantee for `SelectionState`.
    #[test]
    fn image_selection_copy_does_not_mint_a_new_generation() {
        let original = ImageSelection::new(TEST_IMAGE_SIZE);
        let copied = original;

        assert_eq!(original.image_generation(), copied.image_generation());
    }

    // selection_generation / image_generation E. The two generations vary
    // fully independently: reselecting only the target changes
    // selection_generation without affecting whatever ImageSelection is
    // already held, reselecting only the image changes image_generation
    // without affecting selection_generation, and reselecting both changes
    // both. This is the structural guarantee the two mismatch tests above
    // (target-only and image-only) each exercise in isolation.
    #[test]
    fn selection_generation_and_image_generation_vary_independently() {
        let snapshot = base_device();

        let state_1 = select(snapshot.clone()).unwrap();
        let image_1 = ImageSelection::new(TEST_IMAGE_SIZE);

        // Target reselect only: selection_generation changes; `image_1`
        // itself is an already-held plain value, not re-derived by this.
        let state_2 = select(snapshot.clone()).unwrap();
        assert_ne!(
            selection_generation_of(&state_1),
            selection_generation_of(&state_2)
        );

        // Image reselect only: image_generation changes, independent of
        // selection_generation.
        let image_2 = ImageSelection::new(TEST_IMAGE_SIZE);
        assert_ne!(image_1.image_generation(), image_2.image_generation());

        // Both reselected: both generations differ from their originals.
        let state_3 = select(snapshot).unwrap();
        let image_3 = ImageSelection::new(TEST_IMAGE_SIZE);
        assert_ne!(
            selection_generation_of(&state_1),
            selection_generation_of(&state_3)
        );
        assert_ne!(image_1.image_generation(), image_3.image_generation());
    }
}
