// Core layer (Selection Continuity). This module never talks to UDisks2,
// D-Bus, or /sys directly — it only receives already-collected data
// (`DeviceSnapshot`, `SnapshotFetchOutcome`, `DeviceEvent`) and already-computed
// judgements (`SafetyAssessment`, `IdentityComparison`, `InstanceComparison`)
// from the Linux Backend / Safety Engine / Identity modules, and decides what
// they mean for the user's current Selection.

use std::sync::atomic::{AtomicU64, Ordering};

use super::linux_access::{ActiveWriteTarget, FdMetadata, OpenedDeviceHandle, SyncTarget};
use crate::device::{DeviceSnapshot, SnapshotFetchOutcome};
use crate::identity::{compare_identity, compare_instance, IdentityComparison, InstanceComparison};
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

// Why `check_identity_instance_for_verify` (below) refused to allow a
// Verify pass to proceed. Deliberately small and flat, the same style as
// `IntentBuildError`/`FdBindingCheck` above rather than `InvalidationReason`
// (which is `Debug`-only, since nothing compares it): this type exists to
// be matched and asserted on directly, both by this module's own tests and
// by a future `write_job.rs` Verify state machine converting it into its
// own, larger `VerifyStartError` -- exactly how `prepare_for_open` (below)
// already converts `InvalidationReason` into the matching `WriteGateError`
// variants. `UnsafeTargetState` is deliberately not split further (e.g. into
// per-field variants such as `SystemDevice`/`ActiveSwap`/`ComplexStorage`):
// `InvalidationReason::SafetyChanged` sets the existing precedent for not
// carrying that level of detail in this kind of small, flat pre-check
// error, and a future Verify layer that needs the specific reason can
// re-inspect the same `DeviceSnapshot` it already has in hand.
//
// `pub(in crate::execution)`, not the plain `pub` `FdBindingCheck`/
// `WriteGateError` use: unlike `check_fd_binding`/`prepare_for_open` (both
// plain `pub fn`), `check_identity_instance_for_verify` itself is
// `pub(in crate::execution)` (its only intended caller, a future
// `write_job.rs` Verify state machine, is a sibling module inside
// `execution`) -- keeping this error type at the same, narrower visibility
// avoids leaving a fully public type reachable crate-wide for a function
// nothing outside `execution` can actually call yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::execution) enum VerifyTargetCheckError {
    IdentityChanged,
    IdentityInsufficient,
    InstanceRecreated,
    InstanceInsufficient,
    UnsafeTargetState,
}

// The specific reason(s) `verify_target_hard_hazards` (below) found a fresh
// `DeviceSnapshot` unsafe to read from during Verify. Introduced as part of
// the Verify Pre-flight Diagnostics design so a future caller (a
// `write_job.rs` Verify state machine, or a diagnostic log line) can report
// *which* condition(s) triggered `VerifyTargetCheckError::UnsafeTargetState`
// instead of only that one did -- `UnsafeTargetState` itself is deliberately
// left unchanged (see its own doc comment above): this enum supplements it
// with detail, rather than replacing or subdividing it.
//
// `pub(crate)` (Verify Pre-flight Diagnostics implementation step 5+6):
// `main.rs` now reads `VerifyTargetDiagnostics::hazards()` (a
// `&[HardHazardReason]`) to build its human-readable hazard summary, so this
// must be at least as visible as that accessor. Still not plain `pub` --
// this is CLI-facing display data for this crate's own binary, not a public
// library API.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HardHazardReason {
    SystemDevice,
    ActiveSwap,
    ComplexStorage,
    HintIgnore,
    MediaUnavailable,
}

// Pure function: every hard hazard a fresh `DeviceSnapshot` currently
// exhibits, in a fixed, deterministic order (checked in the same order
// `verify_target_has_hard_hazard`'s boolean chain always has: SystemDevice,
// ActiveSwap, ComplexStorage, HintIgnore, MediaUnavailable). Returns every
// applicable reason, not just the first -- a snapshot can fail more than one
// of these independently (e.g. `active_swap` and `complex_storage` both
// `true` at once), and a diagnostic log line should be able to say so.
// `verify_target_has_hard_hazard` below is now a thin wrapper over this.
fn verify_target_hard_hazards(current: &DeviceSnapshot) -> Vec<HardHazardReason> {
    let mut hazards = Vec::new();

    if current.hint_system {
        hazards.push(HardHazardReason::SystemDevice);
    }
    if current.active_swap {
        hazards.push(HardHazardReason::ActiveSwap);
    }
    if current.complex_storage {
        hazards.push(HardHazardReason::ComplexStorage);
    }
    if current.hint_ignore {
        hazards.push(HardHazardReason::HintIgnore);
    }
    if !current.media_available {
        hazards.push(HardHazardReason::MediaUnavailable);
    }

    hazards
}

// A single, pure snapshot of everything `check_identity_instance_for_verify`
// needs to decide whether Verify may proceed -- Identity comparison,
// Instance comparison, and every hard hazard found -- plus the two
// `DeviceSnapshot`s that comparison was made from. Exists so that decision
// and diagnostic detail are computed exactly once, from exactly one call
// (`diagnose_identity_instance_for_verify` below), instead of the check path
// and a future logging path re-running `compare_identity`/`compare_instance`/
// `verify_target_hard_hazards` independently and risking the two silently
// drifting apart (single source of truth).
//
// Fields are private, not `pub`: nothing outside this module should be able
// to construct one from independently-sourced parts (the same rationale as
// `ImageSelection`/`WriteIntent` above) -- `diagnose_identity_instance_for_verify`
// is the only constructor. `pub(crate)`, not the narrower `pub(in
// crate::execution)` this type started implementation step 1+2 with: Verify
// Pre-flight Diagnostics implementation step 3+4 threads this type through
// `write_job::PendingVerify::check_target()`'s public, `pub(crate)`-reachable
// return type, and `main.rs` (outside `crate::execution`) must call that
// method -- Rust requires a `pub`/`pub(crate)` function's return type to be
// at least as visible as the function itself at every call site that can
// actually reach it (confirmed the hard way: `pub(in crate::execution)`
// here produced a hard "private type" error at the `main.rs` call site, not
// merely a lint, once `main.rs` was updated to match `check_target()`'s new
// three-element error tuple). `main.rs` still does not read any field of
// this type or call any of its accessors today -- it only discards the
// value (`Err((image, error, _diagnostics))`) to keep compiling against the
// new shape -- so this widening is the minimum Rust's own privacy rules
// leave available, not a step toward exposing the type's contents; whether
// `main.rs` should actually read from it is still Step 5's decision, not
// this one's. `Debug, Clone` only -- `DeviceSnapshot` itself does not derive
// `Copy`/`PartialEq`/`Eq`, so neither can this type without first changing
// `device.rs`, which is out of scope for this step.
#[derive(Debug, Clone)]
pub(crate) struct VerifyTargetDiagnostics {
    baseline: DeviceSnapshot,
    current: DeviceSnapshot,
    identity: IdentityComparison,
    instance: InstanceComparison,
    hazards: Vec<HardHazardReason>,
}

// `#[allow(dead_code)]` on every accessor below: this module's own tests
// reach the private fields directly (ordinary same-module field access,
// since privacy in Rust is module-scoped, not `impl`-scoped), so nothing
// calls these yet -- they exist for a future `write_job.rs` consumer that,
// unlike this module's tests, is a different module and therefore cannot
// reach the private fields directly.
// `pub(crate)`, matching `VerifyTargetDiagnostics` itself (Verify
// Pre-flight Diagnostics implementation step 5+6): `main.rs` (outside
// `crate::execution`) reads these to build its diagnostic CLI summary,
// exactly the caller `VerifyTargetDiagnostics`'s own visibility widening
// (step 3+4) already anticipated. Still not plain `pub` -- nothing outside
// this crate has, or needs, a reason to read Verify's internal diagnostic
// model. Every getter returns a borrow or a `Copy` value, never a clone of
// owned data -- `main.rs`'s formatting helpers only ever need to read these
// fields, never to own or outlive `self`.
impl VerifyTargetDiagnostics {
    pub(crate) fn baseline(&self) -> &DeviceSnapshot {
        &self.baseline
    }

    pub(crate) fn current(&self) -> &DeviceSnapshot {
        &self.current
    }

    pub(crate) fn identity(&self) -> IdentityComparison {
        self.identity
    }

    pub(crate) fn instance(&self) -> InstanceComparison {
        self.instance
    }

    pub(crate) fn hazards(&self) -> &[HardHazardReason] {
        &self.hazards
    }
}

// The only constructor for `VerifyTargetDiagnostics`. Pure: no D-Bus, no
// file I/O, no global state, no logging/formatting -- takes only the two
// snapshots already in the caller's hand and returns plain data, exactly
// like `check_identity_instance_for_verify` itself. `check_identity_instance_for_verify`
// (below) is now implemented in terms of this function's result rather than
// recomputing `compare_identity`/`compare_instance`/`verify_target_hard_hazards`
// a second time, so the value a future diagnostic log line would report and
// the value the allow/reject decision is actually based on can never
// diverge. `write_job::PendingVerify::check_target()` is its production
// caller today.
//
// `pub(crate)`, not the narrower `pub(in crate::execution)` this function
// started with: `main.rs`'s own unit tests for its Verify Pre-flight
// Diagnostics CLI formatters (implementation step 5+6) need a realistic way
// to build a `VerifyTargetDiagnostics` value -- there is no other
// constructor, by design (see that type's own doc comment on why an
// arbitrary struct literal is deliberately not available outside this
// module) -- so this is the minimum widening that lets those tests build
// one from ordinary `DeviceSnapshot` fixtures instead of adding a second,
// test-only construction path.
pub(crate) fn diagnose_identity_instance_for_verify(
    baseline: &DeviceSnapshot,
    current: &DeviceSnapshot,
) -> VerifyTargetDiagnostics {
    VerifyTargetDiagnostics {
        baseline: baseline.clone(),
        current: current.clone(),
        identity: compare_identity(baseline, current),
        instance: compare_instance(baseline, current),
        hazards: verify_target_hard_hazards(current),
    }
}

// Verify-specific counterpart to `check_identity_instance_safety` above,
// intended as the pre-flight check a future Verify orchestration
// (`write_job.rs`, a later step) runs immediately before opening a
// read-only FD for verification. Deliberately NOT implemented by calling
// `check_identity_instance_safety` and loosening its result afterward: that
// function requires `assess_device(current).risk_level == Normal &&
// writable` -- a gate shaped for "is it safe to *write*?". Verify is
// read-only, and several conditions that correctly make `assess_device`
// return `Caution`/`writable: false` are expected, benign side effects of a
// write that already succeeded -- most importantly, the OS/desktop
// auto-mounting a newly-written filesystem (`RiskReason::MountedFilesystem`)
// or a hybrid image changing how its partition table is recognized
// (`RiskReason::NotPartitionable`). Reusing the write-time gate here would
// make Verify spuriously fail on exactly the real, already-proven-successful
// MyPocketOS Hybrid ISO scenario (write, then an auto-mounted partition).
//
// Identity and Instance are checked with the exact same strictness as write
// time -- a wrong or replaced target is exactly as unacceptable to read
// from as it is to write to, so Verify does not relax either check. What
// Verify does NOT reuse from write time is the Safety Engine's
// `writable`/`RiskLevel` verdict: instead, a small, explicit set of hazard
// conditions is checked directly against the fresh `DeviceSnapshot` (see
// `verify_target_has_hard_hazard` below) -- `safety::assess_device` itself
// is not called, and is not modified by this function.
//
// Pure: no D-Bus, no file I/O, no global state -- takes only the two
// snapshots already in the caller's hand, exactly like
// `check_identity_instance_safety`.
// The *only* place the Identity -> Instance -> hazards priority order for
// Verify's pre-flight decision is encoded. Introduced so that
// `check_identity_instance_for_verify` (below, this module) and
// `write_job::PendingVerify::check_target()` (a sibling module) can both
// reach the exact same allow/reject decision from an already-computed
// `VerifyTargetDiagnostics` value, without either one re-implementing this
// priority order independently -- two independent copies of "which error
// wins when more than one condition applies" were found to drift into being
// exactly that risk during Verify Pre-flight Diagnostics implementation
// step 3+4, which is why this helper exists as the single, shared decision
// point instead. Pure: reads only the fields of `diagnostics` already
// computed by `diagnose_identity_instance_for_verify` -- no comparison is
// performed here, only a priority selection over results computed exactly
// once by the caller.
//
// `pub(in crate::execution)`, matching `VerifyTargetCheckError`/
// `VerifyTargetDiagnostics`: `write_job.rs` (a sibling module inside
// `execution`) is the intended caller for the failure-path/success-path
// diagnostics-carrying case; nothing outside `execution` needs this.
pub(in crate::execution) fn verify_target_check_from_diagnostics(
    diagnostics: &VerifyTargetDiagnostics,
) -> Result<(), VerifyTargetCheckError> {
    match diagnostics.identity {
        IdentityComparison::Changed => return Err(VerifyTargetCheckError::IdentityChanged),
        IdentityComparison::InsufficientIdentity => {
            return Err(VerifyTargetCheckError::IdentityInsufficient);
        }
        IdentityComparison::Same => {}
    }

    match diagnostics.instance {
        InstanceComparison::Recreated => return Err(VerifyTargetCheckError::InstanceRecreated),
        InstanceComparison::InsufficientInformation => {
            return Err(VerifyTargetCheckError::InstanceInsufficient);
        }
        InstanceComparison::SameInstance => {}
    }

    if !diagnostics.hazards.is_empty() {
        return Err(VerifyTargetCheckError::UnsafeTargetState);
    }

    Ok(())
}

#[allow(dead_code)] // no production caller yet; a future Verify state machine (write_job.rs) is the intended one. Exercised by this module's own tests below.
pub(in crate::execution) fn check_identity_instance_for_verify(
    baseline: &DeviceSnapshot,
    current: &DeviceSnapshot,
) -> Result<(), VerifyTargetCheckError> {
    // Single source of truth: the diagnostics below are the one and only
    // place Identity/Instance/hazards are computed for this check. A future
    // diagnostic log line reads the exact same `VerifyTargetDiagnostics`
    // value (via `diagnose_identity_instance_for_verify`) that this decision
    // is based on -- never a second, independently recomputed copy. The
    // priority order itself lives in `verify_target_check_from_diagnostics`
    // above, shared with `write_job::PendingVerify::check_target()`.
    let diagnostics = diagnose_identity_instance_for_verify(baseline, current);
    verify_target_check_from_diagnostics(&diagnostics)
}

// The narrow set of `DeviceSnapshot` conditions that block Verify, read
// directly from the fresh snapshot rather than through
// `safety::assess_device` -- see `check_identity_instance_for_verify`'s doc
// comment for why. Every field checked here also appears somewhere in
// `assess_device`'s own rule chain, but this is not a re-derivation or a
// mechanical subset of it: it is Verify's own, independent judgement of
// which conditions matter for a *read*, and it deliberately omits every
// condition `assess_device` treats as a write-time-only concern.
//
// Excluded on purpose (allowed for Verify -- tolerated as benign or
// irrelevant post-write changes):
//   - `mount_points` becoming non-empty (`assess_device`'s
//     `MountedFilesystem` -> `Caution`) -- expected after writing any
//     filesystem-bearing image; this is this step's whole reason for
//     existing (see the regression test below).
//   - `hint_partitionable` becoming `false` (`assess_device`'s
//     `NotPartitionable` -> `Caution`) -- some hybrid images legitimately
//     change how their partition table is recognized.
//   - `removable`/`connection_bus` reclassification -- if this reflects an
//     actual device swap, Identity/Instance above already reject it; a
//     classification change alone (e.g. udev re-enumeration timing) is not
//     itself treated as a hazard here.
//   - `read_only` becoming `true` -- reconsidered explicitly for this step
//     (it was only a tentative hard-hazard candidate in the earlier design
//     phase). `read_only` reflects UDisks2's own `Block.ReadOnly` property
//     (see `linux_backend.rs`), a write-restriction signal -- it says
//     nothing about whether the device can still be *read*, which is all
//     Verify ever does. Blocking Verify on a newly-`true` `read_only` would
//     also work against Verify's actual purpose: the scenario most likely
//     to *cause* an unexpected read-only flip after a successful write --
//     a hardware fault or media error -- is exactly the scenario where a
//     user most needs Verify to still be able to read back and report what
//     is actually on the device. Deliberately not blocked.
//
// Included (still block Verify, unchanged from the design phase):
//   - `hint_system` -- a device the system now considers a system disk is
//     never an acceptable Verify target, identity match or not.
//   - `active_swap` -- newly-active swap on a device that was just given a
//     plain image is a strong signal something is wrong with this target.
//   - `complex_storage` -- a LUKS/LVM/RAID signature suddenly appearing
//     indicates either target confusion or a highly unusual write result;
//     either way, not a state Verify should silently read through.
//   - `hint_ignore` -- the system now says to leave this device alone.
//   - `!media_available` -- there is no media to read from at all.
// Thin wrapper over `verify_target_hard_hazards`: kept for the boolean-only
// question this module's doc comments above already reference by name.
// `check_identity_instance_for_verify` itself no longer calls this -- it
// reads `diagnostics.hazards` directly (see the single-source-of-truth note
// on that function) -- so this exists purely as a small, still-useful
// predicate for any future caller that only needs a yes/no answer.
#[allow(dead_code)] // no caller left after the diagnostics refactor; kept as a thin, documented predicate per the Verify Pre-flight Diagnostics design.
fn verify_target_has_hard_hazard(current: &DeviceSnapshot) -> bool {
    !verify_target_hard_hazards(current).is_empty()
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
// kernel's own st_rdev/BLKGETSIZE64/BLKGETDISKSEQ, independent of D-Bus
// entirely.
//
// Three checks, all required: major:minor, size, and diskseq. The diskseq
// check catches what the other two cannot -- a different disk of the same
// size appearing under the same device node between the gate and the open
// (the kernel gives every new disk and every media change a new diskseq).
// A definite difference in any of them is a Mismatch, even when another
// value is missing; a missing value alone is InsufficientInformation, never
// a Match.
pub fn check_fd_binding(
    current: &DeviceSnapshot,
    fd_metadata: Option<&FdMetadata>,
) -> FdBindingCheck {
    let Some(fd_metadata) = fd_metadata else {
        return FdBindingCheck::InsufficientInformation;
    };

    if fd_metadata.major != current.major || fd_metadata.minor != current.minor {
        return FdBindingCheck::Mismatch;
    }

    if fd_metadata.size.is_some_and(|size| size != current.size) {
        return FdBindingCheck::Mismatch;
    }

    match (fd_metadata.diskseq, current.diskseq) {
        (Some(fd_diskseq), Some(current_diskseq)) if fd_diskseq != current_diskseq => {
            return FdBindingCheck::Mismatch;
        }
        (Some(_), Some(_)) => {}
        _ => return FdBindingCheck::InsufficientInformation,
    }

    if fd_metadata.size.is_none() {
        return FdBindingCheck::InsufficientInformation;
    }

    FdBindingCheck::Match
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
    // its raw value are `WriteIntent::from_selection`/`confirmation_matches`
    // (both in this module) and this crate's own tests -- nothing outside
    // the crate has a reason to read it in isolation from the
    // `ImageSelection` it came from.
    pub(crate) fn image_generation(&self) -> ImageGeneration {
        self.image_generation
    }
}

// Fixed once, before a write starts, and carried unchanged through the
// entire Job -- never branched on inside `Writing`'s or `Syncing`'s hot
// loops (see `write_job.rs`). `None` still means write + flush + sync
// happen as normal; it only means no read-back verification stage runs
// afterward. `Quick`/`Full` name a policy for a future `Verifying` stage
// that this revision does not implement -- see `write_job.rs`'s
// module-level doc comment.
// `#[allow(dead_code)]`: `Quick`/`Full` are not yet constructed by any
// production call site (`main.rs`'s PoC only ever passes `None` -- Verify
// itself is not implemented this revision, see the module-level doc
// comment on `write_job.rs`), mirroring `WriteGateError`'s existing
// `#[allow(dead_code)]` for the same reason.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyMode {
    None,
    Quick,
    Full,
}

// Why `WriteIntent::from_selection` refused to build a `WriteIntent`. Kept
// deliberately separate from `WriteGateError` (15 variants, almost all of
// which describe re-verification failures that can only happen inside
// `prepare_for_open`, after a `WriteIntent` already exists) -- mirrors the
// existing `SelectionError` precedent of a small, single-purpose error type
// per construction step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntentBuildError {
    NoSelection,
    SelectionInvalidated,
}

// A pure, immutable snapshot of "what the user confirmed": which target
// (by block_path/size/diskseq), which Selection event
// (`selection_generation`), which image (`image_size`/`image_generation`),
// and under which `VerifyMode` -- all frozen together at the moment of
// confirmation. `Copy` is not derived (the `String` field rules it out),
// but this is still a one-time, pre-write construction, never something
// built inside a write's hot loop.
//
// Fields are deliberately private, for the same reason `ImageSelection`'s
// are: `target_block_path`/`target_size`/`target_diskseq` and
// `selection_generation` must always come from the *same* `SelectionState`
// value, never `baseline` from one Selection paired with
// `selection_generation` from a different one. A struct literal with `pub`
// fields (or a loose-value constructor taking `baseline` and
// `selection_generation` as two independent parameters) cannot rule that
// mismatch out; `from_selection` below is the only way to obtain one, and
// it destructures both fields out of the same `SelectionState::Selected`
// match arm.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteIntent {
    target_block_path: String,
    target_size: u64,
    target_diskseq: Option<u64>,
    selection_generation: SelectionGeneration,
    image_size: u64,
    image_generation: ImageGeneration,
    verify_mode: VerifyMode,
}

impl WriteIntent {
    // The only way to construct a `WriteIntent`. `baseline` and
    // `selection_generation` are pulled out of the same `SelectionState`
    // match arm, so they can never be mismatched the way two independent
    // loose parameters could be. Only `SelectionState::Selected` can ever
    // produce a `WriteIntent`: `NoSelection` and `Invalidated` are rejected
    // outright, since neither has a baseline worth confirming against.
    pub fn from_selection(
        state: &SelectionState,
        image: ImageSelection,
        verify_mode: VerifyMode,
    ) -> Result<WriteIntent, IntentBuildError> {
        let (baseline, selection_generation) = match state {
            SelectionState::NoSelection => return Err(IntentBuildError::NoSelection),
            SelectionState::Invalidated { .. } => {
                return Err(IntentBuildError::SelectionInvalidated);
            }
            SelectionState::Selected {
                baseline,
                selection_generation,
                ..
            } => (baseline, selection_generation),
        };

        Ok(WriteIntent {
            target_block_path: baseline.block_path.clone(),
            target_size: baseline.size,
            target_diskseq: baseline.diskseq,
            selection_generation: *selection_generation,
            image_size: image.image_size(),
            image_generation: image.image_generation(),
            verify_mode,
        })
    }

    pub fn target_block_path(&self) -> &str {
        &self.target_block_path
    }

    pub fn target_size(&self) -> u64 {
        self.target_size
    }

    pub fn target_diskseq(&self) -> Option<u64> {
        self.target_diskseq
    }

    pub fn image_size(&self) -> u64 {
        self.image_size
    }

    pub fn verify_mode(&self) -> VerifyMode {
        self.verify_mode
    }

    // `pub(crate)`, not `pub`, for the same reason as
    // `ImageSelection::image_generation()`: opaque by design, only needed by
    // `confirmation_matches` (below) and this crate's own tests.
    pub(crate) fn selection_generation(&self) -> SelectionGeneration {
        self.selection_generation
    }

    pub(crate) fn image_generation(&self) -> ImageGeneration {
        self.image_generation
    }
}

// A token only ever proves "this exact `WriteIntent` was confirmed" -- it
// is data, not a cryptographic credential, and needs no generation of its
// own (a stale `WriteIntent` inside it is already stale via the
// `selection_generation`/`image_generation` it carries). `confirm()` is the
// only constructor: there is no UI in this codebase yet, so (for now) the
// only way to obtain a token is to build a `WriteIntent` first and confirm
// it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfirmationToken {
    intent: WriteIntent,
}

impl ConfirmationToken {
    pub fn confirm(intent: WriteIntent) -> Self {
        ConfirmationToken { intent }
    }

    // `pub(crate)`: only `confirmation_matches` (below, same module) and
    // this crate's own tests have a legitimate reason to look inside a
    // confirmed token.
    pub(crate) fn intent(&self) -> &WriteIntent {
        &self.intent
    }
}

// A token only ever authorizes the exact (target, size, diskseq, selection
// generation, image size, image generation, verify mode) its frozen
// `WriteIntent` was built for. Any difference -- a different target, a
// resized image, a *different* image of the same size (a new
// `image_generation`), the target having been replugged (a new diskseq)
// since the token was made, the user having explicitly reselected the
// target since (a new `selection_generation`), or the confirmed
// `VerifyMode` having changed -- is a mismatch, not a "close enough".
fn confirmation_matches(
    token: &ConfirmationToken,
    current: &DeviceSnapshot,
    image: ImageSelection,
    current_selection_generation: SelectionGeneration,
    current_verify_mode: VerifyMode,
) -> bool {
    let intent = token.intent();

    intent.target_block_path() == current.block_path.as_str()
        && intent.target_size() == current.size
        && intent.target_diskseq() == current.diskseq
        && intent.selection_generation() == current_selection_generation
        && intent.image_size() == image.image_size()
        && intent.image_generation() == image.image_generation()
        && intent.verify_mode() == current_verify_mode
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
//
// Fields are deliberately private: with `pub` fields, a caller holding a
// `ReadyToOpen` could overwrite `plan`/`verify_mode` with values the Gate
// never verified, or swap `current` for a different snapshot, before
// passing it into `finalize_prepared_write` -- silently defeating the
// "Gate-decided values travel through unmodified" guarantee `PreparedWrite`/
// `AuthorizedWrite` already rely on. `prepare_for_open` (below, same module)
// is the only constructor; there is no public one.
#[derive(Debug)]
pub struct ReadyToOpen {
    current: DeviceSnapshot,
    plan: WritePlan,
    verify_mode: VerifyMode,
    // Carried through to `PreparedWrite`/`AuthorizedWrite` unchanged -- the
    // confirmed `image_generation` a future `AuthorizedExecution::bind()`
    // (write_job.rs) needs to compare against a `SelectedImage` right before
    // a write starts. No getter here: `finalize_prepared_write` (below, same
    // module) is the only reader.
    image_generation: ImageGeneration,
}

impl ReadyToOpen {
    // `&DeviceSnapshot`, not a narrower projection: `main.rs`'s PoC reads
    // `block_path` from it today, and `DeviceSnapshot`'s own fields are
    // already `pub` (see `device.rs`), so this is the minimal way to expose
    // read access without re-deciding `DeviceSnapshot`'s own field
    // visibility here.
    pub fn current(&self) -> &DeviceSnapshot {
        &self.current
    }

    // `WritePlan` is `Copy`, so returning it by value is a plain copy, not a
    // borrow -- consistent with how `ImageSelection`/`WriteIntent` getters
    // return their `Copy` fields by value elsewhere in this module.
    pub fn plan(&self) -> WritePlan {
        self.plan
    }
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
    // `plan`/`verify_mode`/`image_generation` travel from here straight into
    // `AuthorizedWrite` via `begin()` below -- private, since a caller must
    // never be able to re-supply or override any of them; the only values
    // that can ever reach `AuthorizedWrite` are the exact ones
    // `prepare_for_open` verified.
    plan: WritePlan,
    verify_mode: VerifyMode,
    image_generation: ImageGeneration,
    // The exact `DeviceSnapshot` re-verified by `prepare_for_open`/
    // `finalize_prepared_write` immediately before this write was allowed to
    // proceed (`ReadyToOpen`'s own `current`, cloned once here) -- carried
    // through to `ActiveWrite`/`WriteSucceeded`/`Syncing`/`SyncSucceeded`
    // unchanged, for a future Built-in Verify stage to compare a freshly
    // re-fetched snapshot against (see `write_job.rs`'s Verify state
    // machine). Deliberately private, unlike `target_block_path`/
    // `target_size`/`image_size` above: those three are read-only
    // diagnostics whose accuracy does not affect safety (the real authority
    // is `handle`, already FD-bound-checked), but `baseline` is the anchor
    // Verify's own Identity/Instance re-check is measured against --
    // letting a caller freely overwrite it (as a `pub` field would allow)
    // would defeat exactly the device-replacement detection this field
    // exists to preserve. No setter exists anywhere on this struct or on
    // `ActiveWrite` below; the only way to obtain one is the clone taken
    // here, from the value `prepare_for_open` itself already verified.
    baseline: DeviceSnapshot,
    #[allow(dead_code)]
    handle: OpenedDeviceHandle,
}

// The pure half of the gate: conditions A-I plus the confirmation check.
// Takes the current `SelectionState` (by reference — this does not mutate
// ongoing Selection Continuity monitoring) and a target-specific re-fetch
// the caller already performed (condition B). Reuses `writer::WritePlan` for
// F/G/H/I instead of re-implementing size validation here. `verify_mode` is
// not derived from `confirmation` -- it is the caller's current choice,
// checked *against* the confirmation's frozen `WriteIntent` exactly like
// every other condition below, so a `VerifyMode` change after confirming
// surfaces as a `ConfirmationMismatch` like any other stale confirmation.
pub fn prepare_for_open(
    state: &SelectionState,
    refreshed: SnapshotFetchOutcome,
    image: ImageSelection,
    verify_mode: VerifyMode,
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

    if !confirmation_matches(token, &current, image, *selection_generation, verify_mode) {
        return Err(WriteGateError::ConfirmationMismatch);
    }

    Ok(ReadyToOpen {
        current,
        plan,
        verify_mode,
        // The current `image`'s generation, already proven (by
        // `confirmation_matches` above) to match what was confirmed -- not
        // a fresh value, and never re-derived later.
        image_generation: image.image_generation(),
    })
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

    // Cloned before any field of `ready.current` is partially moved out
    // below -- see `PreparedWrite::baseline`'s own doc comment for why this
    // must be the exact snapshot the Gate just re-verified, not a fresh
    // re-fetch taken later.
    let baseline = ready.current.clone();

    Ok(PreparedWrite {
        target_block_path: ready.current.block_path,
        target_size: ready.current.size,
        image_size: ready.plan.image_size,
        plan: ready.plan,
        verify_mode: ready.verify_mode,
        image_generation: ready.image_generation,
        baseline,
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
// `#[allow(dead_code)]`: these three `pub` fields are read by this module's
// own tests and exist for a future GUI/Controller's diagnostics, but no
// production code path reads them today -- `AuthorizedWrite` (what
// `PreparedWrite::begin()` now returns) does not expose `ActiveWrite`'s
// fields directly, and `main.rs`'s prepare-test PoC captures the same
// information from `PreparedWrite` before `begin()` consumes it. Mirrors
// `write_job.rs`'s own module-level `#![allow(dead_code)]`: nothing here is
// wired into a real write path yet (`Real-device execution path: NOT
// CONNECTED`).
#[allow(dead_code)]
pub struct ActiveWrite {
    pub target_block_path: String,
    pub target_size: u64,
    pub image_size: u64,
    // See `PreparedWrite::baseline`'s doc comment for why this is private
    // (unlike the three `pub` fields above) and only reachable via the
    // `baseline()` getter below.
    baseline: DeviceSnapshot,
    handle: OpenedDeviceHandle,
}

// Proof that the Gate authorized not just an FD (`ActiveWrite`), but a
// specific `WritePlan` and `VerifyMode` to use with it. Bundling the three
// together as one value closes the same class of gap `ImageSelection` and
// `WriteIntent` close elsewhere: nothing outside this module can pair the
// `ActiveWrite` the Gate approved with a `WritePlan`/`VerifyMode` from a
// different, unrelated Gate pass, because there is no public constructor
// that accepts them as independent parameters. `WritePlan`/`VerifyMode` are
// both `Copy`, so bundling them here costs nothing at runtime (no heap
// allocation, no syscalls) -- this is still a one-time value built once
// before the write starts, not something reconstructed per chunk.
pub struct AuthorizedWrite {
    active: ActiveWrite,
    plan: WritePlan,
    verify_mode: VerifyMode,
    // The confirmed `image_generation`, carried through unchanged from
    // `prepare_for_open`. Exposed only via the `pub(crate)` getters below,
    // for `write_job.rs`'s `AuthorizedExecution::bind()` to compare against
    // a `SelectedImage` immediately before a write starts.
    image_generation: ImageGeneration,
}

impl PreparedWrite {
    // The one and only way to reach an `AuthorizedWrite`. Takes `self` by
    // value (not `&self`/`&mut self`), so calling this is the last thing
    // that can ever be done with a given `PreparedWrite` — the Rust
    // compiler refuses any further use of the variable that was passed in,
    // which is exactly the "consumed exactly once" guarantee this type
    // exists to provide. `plan`/`verify_mode` are carried straight through
    // from the Gate-verified values `PreparedWrite` already held -- never
    // re-derived, never re-supplied by the caller.
    pub fn begin(self) -> AuthorizedWrite {
        let active = ActiveWrite {
            target_block_path: self.target_block_path,
            target_size: self.target_size,
            image_size: self.image_size,
            baseline: self.baseline,
            handle: self.handle,
        };

        AuthorizedWrite {
            active,
            plan: self.plan,
            verify_mode: self.verify_mode,
            image_generation: self.image_generation,
        }
    }
}

impl AuthorizedWrite {
    // `pub(in crate::execution)`, not `pub(crate)`: the only legitimate
    // consumer is `write_job::start_inner()`, which immediately re-bundles
    // the pieces into `Writing`. No public constructor exists for
    // `AuthorizedWrite` itself, so this is the only way its parts ever
    // become independently reachable, and only from within the `execution`
    // module tree (`core`/`linux_access`/`write_job`) -- not from `main.rs`,
    // `image_source.rs`, or any other sibling module (see the Raw Write
    // Capability Boundary note at the top of `execution/mod.rs`). Deliberately
    // still a 3-tuple, not 4: `image_generation` is not added here, since
    // nothing in the write/sync hot path needs it -- only
    // `write_job::AuthorizedExecution::bind()` does, and it reads
    // `image_generation()`/`image_size()` below instead, without consuming
    // `self`.
    pub(in crate::execution) fn into_parts(self) -> (ActiveWrite, WritePlan, VerifyMode) {
        (self.active, self.plan, self.verify_mode)
    }

    // `pub(crate)`: the only legitimate consumer is
    // `write_job::AuthorizedExecution::bind()`, comparing this
    // Gate-confirmed value against a `SelectedImage`'s own
    // `image_generation` immediately before a write starts. `ImageGeneration`
    // is opaque by design (see its doc comment) -- nothing outside the
    // crate has a reason to read it in isolation.
    pub(crate) fn image_generation(&self) -> ImageGeneration {
        self.image_generation
    }

    // `pub(crate)`, for the same reason as `image_generation()` above.
    // Deliberately delegates to `self.plan.image_size` rather than storing a
    // second, independent copy of the same value -- `WritePlan` (inside
    // `self.plan`) already carries it, and duplicating it here would be
    // exactly the kind of "two fields that could quietly drift apart" this
    // codebase avoids elsewhere (see `ImageSelection`'s own doc comment).
    pub(crate) fn image_size(&self) -> u64 {
        self.plan.image_size
    }

    // `pub(crate)`, for the same consumer: `bind()` refuses a Quick Verify
    // authorization paired with an image that cannot be read at random
    // offsets.
    pub(crate) fn verify_mode(&self) -> VerifyMode {
        self.verify_mode
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
    // `pub(in crate::execution)` rather than `pub(crate)`: reachable only
    // from within the `execution` module tree, compiler-enforced (see
    // `execution/mod.rs`) -- not from `main.rs` or any other sibling module.
    // Wiring an `ActiveWriteTarget` obtained here into an actual
    // `writer::write()` call is a distinct, later step; this method only
    // proves the capability can be obtained, not that it is ever used to
    // write anything.
    #[allow(dead_code)] // exercised by this module's own tests today; not yet called from main.rs.
    pub(in crate::execution) fn writer_target(&mut self) -> ActiveWriteTarget<'_> {
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
    // `pub(in crate::execution)` rather than `pub(crate)`, for the same
    // reason as `writer_target()` above.
    #[allow(dead_code)] // exercised by this module's/write_job.rs's tests today; not yet called from main.rs.
    pub(in crate::execution) fn sync_target(&self) -> SyncTarget<'_> {
        self.handle.sync_target()
    }

    // The exact `DeviceSnapshot` this write was authorized against (see
    // `PreparedWrite::baseline`'s doc comment for the full rationale and why
    // it is deliberately not a `pub` field). Returns a borrow, not a clone:
    // every caller of this today (`write_job.rs`'s Verify state machine)
    // only needs to compare it against a freshly re-fetched snapshot via
    // `check_identity_instance_for_verify`, which itself takes
    // `&DeviceSnapshot` -- no owned copy is required merely to read it.
    // `pub(crate)`, matching `AuthorizedWrite::image_generation()`/
    // `image_size()` above: the only legitimate reader is this crate's own
    // `write_job.rs`, not `main.rs` or any other sibling module (nothing
    // about `baseline` itself is a raw write/read capability the way
    // `writer_target()`/`sync_target()` are, so the narrower
    // `pub(in crate::execution)` used for those two is not required here --
    // `pub(crate)` already matches this type's own precedent for
    // non-capability, read-only data).
    pub(crate) fn baseline(&self) -> &DeviceSnapshot {
        &self.baseline
    }

    // Test-only: exposes the raw fd number this `ActiveWrite` still holds
    // (never the `File`/`OpenedDeviceHandle` itself), purely so a test can
    // independently confirm -- via `/proc/self/fd/<n>`, exactly like
    // `OpenedDeviceHandle::raw_fd_for_test()`'s own precedent -- that
    // dropping whatever owns this `ActiveWrite` actually closed the
    // underlying fd. `write_job.rs`'s own tests use this to confirm
    // `SyncSucceeded::begin_verify()` retires the write-mode fd for every
    // `VerifyMode`, including `None`. `#[cfg(test)]` keeps this out of any
    // real build, same as `OpenedDeviceHandle::raw_fd_for_test()`.
    #[cfg(test)]
    pub(crate) fn raw_fd_for_test(&self) -> std::os::fd::RawFd {
        self.handle.raw_fd_for_test()
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

// Test-only, direct `WriteIntent` construction from independent raw parts --
// the loose-value shape `WriteIntent::from_selection` deliberately does NOT
// expose in production (see its doc comment). Tests need this to construct
// intentionally-stale/mismatched `WriteIntent`s (e.g. an old target paired
// with a current selection_generation) to prove `confirmation_matches`
// rejects each field independently; production code has no such need and
// must always go through `from_selection`.
#[cfg(test)]
pub(crate) fn write_intent_for_test(
    target: &DeviceSnapshot,
    image: ImageSelection,
    selection_generation: SelectionGeneration,
    verify_mode: VerifyMode,
) -> WriteIntent {
    WriteIntent {
        target_block_path: target.block_path.clone(),
        target_size: target.size,
        target_diskseq: target.diskseq,
        selection_generation,
        image_size: image.image_size(),
        image_generation: image.image_generation(),
        verify_mode,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::execution::linux_access;
    use crate::linux_monitor::PropertyChange;
    use crate::writer;
    use std::io::Write;

    fn base_device() -> DeviceSnapshot {
        DeviceSnapshot {
            device: "/dev/sdx".to_string(),
            block_path: "/org/freedesktop/UDisks2/block_devices/sdx".to_string(),
            drive_path: "/org/freedesktop/UDisks2/drives/Test_Model_TEST-SERIAL-0001".to_string(),
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

    fn fd_metadata(major: u32, minor: u32, size: Option<u64>, diskseq: Option<u64>) -> FdMetadata {
        FdMetadata {
            major,
            minor,
            size,
            diskseq,
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
    fn test_handle_with_persistent_temp_file(
        tag: &str,
    ) -> (std::path::PathBuf, OpenedDeviceHandle) {
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
        let metadata = fd_metadata(
            snapshot.major,
            snapshot.minor,
            Some(snapshot.size),
            snapshot.diskseq,
        );

        assert_eq!(
            check_fd_binding(&snapshot, Some(&metadata)),
            FdBindingCheck::Match
        );
    }

    // FD-binding B. FD major differs from the snapshot's -> Mismatch.
    #[test]
    fn fd_binding_major_mismatch_is_mismatch() {
        let snapshot = base_device();
        let metadata = fd_metadata(
            snapshot.major + 1,
            snapshot.minor,
            Some(snapshot.size),
            snapshot.diskseq,
        );

        assert_eq!(
            check_fd_binding(&snapshot, Some(&metadata)),
            FdBindingCheck::Mismatch
        );
    }

    // FD-binding C. FD minor differs from the snapshot's -> Mismatch.
    #[test]
    fn fd_binding_minor_mismatch_is_mismatch() {
        let snapshot = base_device();
        let metadata = fd_metadata(
            snapshot.major,
            snapshot.minor + 1,
            Some(snapshot.size),
            snapshot.diskseq,
        );

        assert_eq!(
            check_fd_binding(&snapshot, Some(&metadata)),
            FdBindingCheck::Mismatch
        );
    }

    // FD-binding D. major/minor match but the ioctl-reported size doesn't -> Mismatch.
    #[test]
    fn fd_binding_size_mismatch_is_mismatch() {
        let snapshot = base_device();
        let metadata = fd_metadata(
            snapshot.major,
            snapshot.minor,
            Some(snapshot.size + 1),
            snapshot.diskseq,
        );

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

    // FD-binding F. The FD's diskseq equals the snapshot's (and major:minor
    // and size match) -> Match.
    #[test]
    fn fd_binding_matching_diskseq_is_match() {
        let snapshot = base_device();
        assert!(snapshot.diskseq.is_some());
        let metadata = matching_fd_metadata(&snapshot);

        assert_eq!(
            check_fd_binding(&snapshot, Some(&metadata)),
            FdBindingCheck::Match
        );
    }

    // FD-binding G. Same device node and size, different diskseq: another
    // disk now sits behind the node -> Mismatch.
    #[test]
    fn fd_binding_diskseq_mismatch_is_mismatch() {
        let snapshot = base_device();
        let mut metadata = matching_fd_metadata(&snapshot);
        metadata.diskseq = snapshot.diskseq.map(|diskseq| diskseq + 1);

        assert_eq!(
            check_fd_binding(&snapshot, Some(&metadata)),
            FdBindingCheck::Mismatch
        );
    }

    // FD-binding H. The FD's diskseq could not be read -> never assumed to
    // match.
    #[test]
    fn fd_binding_missing_fd_diskseq_is_insufficient_information() {
        let snapshot = base_device();
        let mut metadata = matching_fd_metadata(&snapshot);
        metadata.diskseq = None;

        assert_eq!(
            check_fd_binding(&snapshot, Some(&metadata)),
            FdBindingCheck::InsufficientInformation
        );
    }

    // FD-binding I. The snapshot has no diskseq to compare against ->
    // InsufficientInformation, even though the FD reported one.
    #[test]
    fn fd_binding_missing_snapshot_diskseq_is_insufficient_information() {
        let mut snapshot = base_device();
        let metadata = matching_fd_metadata(&snapshot);
        snapshot.diskseq = None;

        assert_eq!(
            check_fd_binding(&snapshot, Some(&metadata)),
            FdBindingCheck::InsufficientInformation
        );
    }

    // FD-binding J. A matching diskseq never outweighs a major:minor or size
    // mismatch.
    #[test]
    fn fd_binding_matching_diskseq_does_not_hide_other_mismatches() {
        let snapshot = base_device();

        let mut other_node = matching_fd_metadata(&snapshot);
        other_node.minor += 1;
        assert_eq!(
            check_fd_binding(&snapshot, Some(&other_node)),
            FdBindingCheck::Mismatch
        );

        let mut other_size = matching_fd_metadata(&snapshot);
        other_size.size = Some(snapshot.size + 1);
        assert_eq!(
            check_fd_binding(&snapshot, Some(&other_size)),
            FdBindingCheck::Mismatch
        );
    }

    // FD-binding K. A definite mismatch wins over a missing value, whichever
    // of the three checks each comes from.
    #[test]
    fn fd_binding_mismatch_takes_priority_over_missing_information() {
        let snapshot = base_device();

        let mut node_and_no_diskseq = matching_fd_metadata(&snapshot);
        node_and_no_diskseq.major += 1;
        node_and_no_diskseq.diskseq = None;
        assert_eq!(
            check_fd_binding(&snapshot, Some(&node_and_no_diskseq)),
            FdBindingCheck::Mismatch
        );

        let mut size_and_no_diskseq = matching_fd_metadata(&snapshot);
        size_and_no_diskseq.size = Some(snapshot.size + 1);
        size_and_no_diskseq.diskseq = None;
        assert_eq!(
            check_fd_binding(&snapshot, Some(&size_and_no_diskseq)),
            FdBindingCheck::Mismatch
        );

        let mut diskseq_and_no_size = matching_fd_metadata(&snapshot);
        diskseq_and_no_size.diskseq = snapshot.diskseq.map(|diskseq| diskseq + 1);
        diskseq_and_no_size.size = None;
        assert_eq!(
            check_fd_binding(&snapshot, Some(&diskseq_and_no_size)),
            FdBindingCheck::Mismatch
        );
    }

    // FD-binding L. A regular file is not a block device: BLKGETDISKSEQ fails
    // on it, `metadata()` reports that as None (no panic), and the binding
    // then refuses it even when every other value is made to match.
    #[test]
    fn fd_binding_regular_file_has_no_diskseq_and_is_insufficient() {
        let snapshot = base_device();
        let (_path, handle) = test_handle_with_temp_file("no-diskseq");

        let real = handle.metadata().expect("fstat of a regular file");
        assert_eq!(real.diskseq, None);

        let mut metadata = matching_fd_metadata(&snapshot);
        metadata.diskseq = real.diskseq;

        assert_eq!(
            check_fd_binding(&snapshot, Some(&metadata)),
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
        fd_metadata(
            snapshot.major,
            snapshot.minor,
            Some(snapshot.size),
            snapshot.diskseq,
        )
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
        let token = ConfirmationToken::confirm(write_intent_for_test(
            &snapshot,
            image,
            selection_generation_of(&state),
            VerifyMode::None,
        ));

        let ready = prepare_for_open(
            &state,
            SnapshotFetchOutcome::Found(base_device()),
            image,
            VerifyMode::None,
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
            VerifyMode::None,
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
            VerifyMode::None,
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
        let token = ConfirmationToken::confirm(write_intent_for_test(
            &other_target,
            image,
            selection_generation_of(&state),
            VerifyMode::None,
        ));

        let result = prepare_for_open(
            &state,
            SnapshotFetchOutcome::Found(snapshot),
            image,
            VerifyMode::None,
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
        let token = ConfirmationToken::confirm(write_intent_for_test(
            &snapshot,
            image,
            selection_generation_of(&state),
            VerifyMode::None,
        ));

        let result = prepare_for_open(
            &state,
            SnapshotFetchOutcome::Found(snapshot),
            ImageSelection::new(TEST_IMAGE_SIZE * 5),
            VerifyMode::None,
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
        let token = ConfirmationToken::confirm(write_intent_for_test(
            &snapshot,
            image,
            selection_generation_of(&state),
            VerifyMode::None,
        ));

        let result = prepare_for_open(
            &state,
            SnapshotFetchOutcome::Found(snapshot),
            image,
            VerifyMode::None,
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
        let token = ConfirmationToken::confirm(write_intent_for_test(
            &snapshot,
            image,
            selection_generation_of(&state),
            VerifyMode::None,
        ));

        let result = prepare_for_open(
            &state,
            SnapshotFetchOutcome::Error("simulated D-Bus failure".to_string()),
            image,
            VerifyMode::None,
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
        let token = ConfirmationToken::confirm(write_intent_for_test(
            &snapshot,
            image,
            selection_generation_of(&state),
            VerifyMode::None,
        ));

        let mut current = snapshot;
        current.serial = "OTHER-SERIAL-0002".to_string();

        let result = prepare_for_open(
            &state,
            SnapshotFetchOutcome::Found(current),
            image,
            VerifyMode::None,
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
        let token = ConfirmationToken::confirm(write_intent_for_test(
            &snapshot,
            image,
            selection_generation_of(&state),
            VerifyMode::None,
        ));

        let mut current = snapshot;
        current.serial = String::new();

        let result = prepare_for_open(
            &state,
            SnapshotFetchOutcome::Found(current),
            image,
            VerifyMode::None,
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
        let token = ConfirmationToken::confirm(write_intent_for_test(
            &snapshot,
            image,
            selection_generation_of(&state),
            VerifyMode::None,
        ));

        let mut current = snapshot;
        current.diskseq = Some(19);

        let result = prepare_for_open(
            &state,
            SnapshotFetchOutcome::Found(current),
            image,
            VerifyMode::None,
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
        let token = ConfirmationToken::confirm(write_intent_for_test(
            &snapshot,
            image,
            selection_generation_of(&state),
            VerifyMode::None,
        ));

        let mut current = snapshot;
        current.diskseq = None;

        let result = prepare_for_open(
            &state,
            SnapshotFetchOutcome::Found(current),
            image,
            VerifyMode::None,
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
        let token = ConfirmationToken::confirm(write_intent_for_test(
            &snapshot,
            image,
            selection_generation_of(&state),
            VerifyMode::None,
        ));

        let mut current = snapshot;
        current.hint_system = true;

        let result = prepare_for_open(
            &state,
            SnapshotFetchOutcome::Found(current),
            image,
            VerifyMode::None,
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
        let token = ConfirmationToken::confirm(write_intent_for_test(
            &snapshot,
            image,
            selection_generation_of(&state),
            VerifyMode::None,
        ));

        let result = prepare_for_open(
            &state,
            SnapshotFetchOutcome::Found(snapshot),
            image,
            VerifyMode::None,
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
            verify_mode: VerifyMode::None,
            image_generation: ImageSelection::new(TEST_IMAGE_SIZE).image_generation(),
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
        let metadata = fd_metadata(
            snapshot.major + 1,
            snapshot.minor,
            Some(snapshot.size),
            snapshot.diskseq,
        );
        let ready = ReadyToOpen {
            plan: WritePlan::new(TEST_IMAGE_SIZE, snapshot.size, DEFAULT_CHUNK_SIZE).unwrap(),
            current: snapshot,
            verify_mode: VerifyMode::None,
            image_generation: ImageSelection::new(TEST_IMAGE_SIZE).image_generation(),
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
            verify_mode: VerifyMode::None,
            image_generation: ImageSelection::new(TEST_IMAGE_SIZE).image_generation(),
        };
        let (_path, handle) = test_handle_with_temp_file("insufficient");

        let result = finalize_prepared_write(ready, Some(handle), None);

        assert!(matches!(result, Err(WriteGateError::FdBindingInsufficient)));
    }

    // finalize (diskseq). The write FD's diskseq could not be read ->
    // rejected before a PreparedWrite exists; a different diskseq ->
    // rejected as a mismatch.
    #[test]
    fn finalize_prepared_write_rejects_missing_or_different_fd_diskseq() {
        let snapshot = base_device();
        let ready = || ReadyToOpen {
            plan: WritePlan::new(TEST_IMAGE_SIZE, snapshot.size, DEFAULT_CHUNK_SIZE).unwrap(),
            current: snapshot.clone(),
            verify_mode: VerifyMode::None,
            image_generation: ImageSelection::new(TEST_IMAGE_SIZE).image_generation(),
        };

        let mut missing = matching_fd_metadata(&snapshot);
        missing.diskseq = None;
        let (_path, handle) = test_handle_with_temp_file("no-fd-diskseq");
        let result = finalize_prepared_write(ready(), Some(handle), Some(&missing));
        assert!(matches!(result, Err(WriteGateError::FdBindingInsufficient)));

        let mut different = matching_fd_metadata(&snapshot);
        different.diskseq = snapshot.diskseq.map(|diskseq| diskseq + 1);
        let (_path, handle) = test_handle_with_temp_file("other-fd-diskseq");
        let result = finalize_prepared_write(ready(), Some(handle), Some(&different));
        assert!(matches!(result, Err(WriteGateError::FdBindingMismatch)));
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
            verify_mode: VerifyMode::None,
            image_generation: ImageSelection::new(TEST_IMAGE_SIZE).image_generation(),
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
            verify_mode: VerifyMode::None,
            image_generation: ImageSelection::new(TEST_IMAGE_SIZE).image_generation(),
        };
        let metadata = matching_fd_metadata(&snapshot);
        let (_path, handle) = test_handle_with_temp_file("begin-fields");
        let prepared = finalize_prepared_write(ready, Some(handle), Some(&metadata)).unwrap();

        let expected_block_path = prepared.target_block_path.clone();
        let expected_target_size = prepared.target_size;
        let expected_image_size = prepared.image_size;

        // `begin()` now returns `AuthorizedWrite`, not `ActiveWrite`
        // directly; `into_parts()` (the only way to take it apart, normally
        // called only from `write_job::start()`) hands back the exact
        // `ActiveWrite` this test still wants to inspect.
        let (active, _plan, _verify_mode) = prepared.begin().into_parts();

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
            verify_mode: VerifyMode::None,
            image_generation: ImageSelection::new(TEST_IMAGE_SIZE).image_generation(),
        };
        let metadata = matching_fd_metadata(&snapshot);
        let (_path, handle) = test_handle_with_temp_file("active-drop-closes-fd");
        let raw_fd = handle.raw_fd_for_test();

        let prepared = finalize_prepared_write(ready, Some(handle), Some(&metadata)).unwrap();
        assert!(
            std::path::Path::new(&format!("/proc/self/fd/{raw_fd}")).exists(),
            "fd should still be open right after finalize_prepared_write"
        );

        let (active, _plan, _verify_mode) = prepared.begin().into_parts();
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
            verify_mode: VerifyMode::None,
            image_generation: ImageSelection::new(TEST_IMAGE_SIZE).image_generation(),
        };
        let metadata = matching_fd_metadata(&snapshot);
        let (path, handle) = test_handle_with_persistent_temp_file("write-known-data");
        let prepared = finalize_prepared_write(ready, Some(handle), Some(&metadata)).unwrap();
        let (mut active, _plan, _verify_mode) = prepared.begin().into_parts();

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
            verify_mode: VerifyMode::None,
            image_generation: ImageSelection::new(TEST_IMAGE_SIZE).image_generation(),
        };
        let metadata = matching_fd_metadata(&snapshot);
        let (_path, handle) = test_handle_with_temp_file("type-compat");
        let prepared = finalize_prepared_write(ready, Some(handle), Some(&metadata)).unwrap();
        let (mut active, _plan, _verify_mode) = prepared.begin().into_parts();

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
        let confirmation = ConfirmationToken::confirm(write_intent_for_test(
            &snapshot,
            image,
            selection_generation_of(&state),
            VerifyMode::None,
        ));

        let ready = prepare_for_open(
            &state,
            SnapshotFetchOutcome::Found(snapshot.clone()),
            image,
            VerifyMode::None,
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

        // `begin()` returns `AuthorizedWrite` now; this helper still hands
        // back a plain `ActiveWrite` (via the crate-private `into_parts()`)
        // since every caller below only exercises `writer_target()`/
        // `writer::write()` directly, not `write_job::start()`.
        let (active, _plan, _verify_mode) = prepared.begin().into_parts();

        (path, active, plan)
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
        let confirmation = ConfirmationToken::confirm(write_intent_for_test(
            &snapshot,
            image,
            selection_generation_of(&state),
            VerifyMode::None,
        ));
        let ready = prepare_for_open(
            &state,
            SnapshotFetchOutcome::Found(snapshot.clone()),
            image,
            VerifyMode::None,
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
        let (mut active, _plan, _verify_mode) = prepared.begin().into_parts();

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
        let stale_token = ConfirmationToken::confirm(write_intent_for_test(
            &old_snapshot,
            image,
            selection_generation_of(&state),
            VerifyMode::None,
        ));

        let result = prepare_for_open(
            &state,
            SnapshotFetchOutcome::Found(new_snapshot),
            image,
            VerifyMode::None,
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
        let old_token = ConfirmationToken::confirm(write_intent_for_test(
            &original,
            image,
            selection_generation_of(&state),
            VerifyMode::None,
        ));

        let state = apply_event(state, &interfaces_removed(&block_path));
        assert!(matches!(state, SelectionState::Invalidated { .. }));

        let mut reselected_snapshot = base_device();
        reselected_snapshot.diskseq = Some(99);
        let state = select(reselected_snapshot.clone()).unwrap();

        let result = prepare_for_open(
            &state,
            SnapshotFetchOutcome::Found(reselected_snapshot),
            image,
            VerifyMode::None,
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
        let old_token = ConfirmationToken::confirm(write_intent_for_test(
            &snapshot,
            image,
            selection_generation_of(&state),
            VerifyMode::None,
        ));

        // Explicit reselect of the exact same device. No replug, no field on
        // `snapshot` differs at all -- only `selection_generation` changes.
        let state = select(snapshot.clone()).unwrap();

        let result = prepare_for_open(
            &state,
            SnapshotFetchOutcome::Found(snapshot),
            image,
            VerifyMode::None,
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
        let new_token = ConfirmationToken::confirm(write_intent_for_test(
            &snapshot,
            image,
            selection_generation_of(&state),
            VerifyMode::None,
        ));

        let result = prepare_for_open(
            &state,
            SnapshotFetchOutcome::Found(snapshot),
            image,
            VerifyMode::None,
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
        let old_token = ConfirmationToken::confirm(write_intent_for_test(
            &snapshot,
            image_a,
            selection_generation_of(&state),
            VerifyMode::None,
        ));

        // Explicit reselect of a different image, same size. `state` (the
        // target selection) is untouched.
        let image_b = ImageSelection::new(TEST_IMAGE_SIZE);
        assert_eq!(image_a.image_size(), image_b.image_size());
        assert_ne!(image_a.image_generation(), image_b.image_generation());

        let result = prepare_for_open(
            &state,
            SnapshotFetchOutcome::Found(snapshot),
            image_b,
            VerifyMode::None,
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
        let new_token = ConfirmationToken::confirm(write_intent_for_test(
            &snapshot,
            image_b,
            selection_generation_of(&state),
            VerifyMode::None,
        ));

        let result = prepare_for_open(
            &state,
            SnapshotFetchOutcome::Found(snapshot),
            image_b,
            VerifyMode::None,
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

    // ---------------------------------------------------------------------
    // WriteIntent::from_selection
    // ---------------------------------------------------------------------

    // WriteIntent A. A Selected SelectionState builds a WriteIntent whose
    // target/selection_generation fields match the same state's own
    // baseline/selection_generation, and whose image/verify_mode fields
    // match the caller's own arguments unchanged.
    #[test]
    fn write_intent_from_selection_succeeds_for_selected_and_matches_the_same_state() {
        let snapshot = base_device();
        let state = select(snapshot.clone()).unwrap();
        let image = ImageSelection::new(TEST_IMAGE_SIZE);

        let intent = WriteIntent::from_selection(&state, image, VerifyMode::Full)
            .expect("Selected SelectionState must build a WriteIntent");

        assert_eq!(intent.target_block_path(), snapshot.block_path);
        assert_eq!(intent.target_size(), snapshot.size);
        assert_eq!(intent.target_diskseq(), snapshot.diskseq);
        assert_eq!(
            intent.selection_generation(),
            selection_generation_of(&state)
        );
        assert_eq!(intent.image_size(), image.image_size());
        assert_eq!(intent.image_generation(), image.image_generation());
        assert_eq!(intent.verify_mode(), VerifyMode::Full);
    }

    // WriteIntent B. NoSelection can never build a WriteIntent.
    #[test]
    fn write_intent_from_selection_rejects_no_selection() {
        let result = WriteIntent::from_selection(
            &SelectionState::NoSelection,
            ImageSelection::new(TEST_IMAGE_SIZE),
            VerifyMode::None,
        );

        assert!(matches!(result, Err(IntentBuildError::NoSelection)));
    }

    // WriteIntent C. An Invalidated SelectionState can never build a
    // WriteIntent, regardless of why it was invalidated -- mirrors
    // `prepare_for_open_rejects_invalidated_selection` for the Gate itself.
    #[test]
    fn write_intent_from_selection_rejects_invalidated() {
        let snapshot = base_device();
        let block_path = snapshot.block_path.clone();
        let state = select(snapshot).unwrap();
        let state = apply_event(state, &interfaces_removed(&block_path));
        assert!(matches!(state, SelectionState::Invalidated { .. }));

        let result = WriteIntent::from_selection(
            &state,
            ImageSelection::new(TEST_IMAGE_SIZE),
            VerifyMode::None,
        );

        assert!(matches!(
            result,
            Err(IntentBuildError::SelectionInvalidated)
        ));
    }

    // WriteIntent D. `image_size`/`image_generation` are taken from the
    // caller's `ImageSelection` unchanged -- not re-derived, not minted
    // fresh inside `from_selection`.
    #[test]
    fn write_intent_preserves_the_given_image_selection() {
        let state = select(base_device()).unwrap();
        let image = ImageSelection::new(TEST_IMAGE_SIZE);

        let intent = WriteIntent::from_selection(&state, image, VerifyMode::None).unwrap();

        assert_eq!(intent.image_size(), image.image_size());
        assert_eq!(intent.image_generation(), image.image_generation());
    }

    // WriteIntent E. `verify_mode` is taken from the caller's argument
    // unchanged, for every variant.
    #[test]
    fn write_intent_preserves_the_given_verify_mode() {
        let state = select(base_device()).unwrap();
        let image = ImageSelection::new(TEST_IMAGE_SIZE);

        for mode in [VerifyMode::None, VerifyMode::Quick, VerifyMode::Full] {
            let intent = WriteIntent::from_selection(&state, image, mode).unwrap();
            assert_eq!(intent.verify_mode(), mode);
        }
    }

    // ---------------------------------------------------------------------
    // Stale confirmation: VerifyMode
    // ---------------------------------------------------------------------

    // Stale confirmation C. A confirmation made while VerifyMode::Quick was
    // selected must not authorize a write once the caller's current choice
    // has moved on to VerifyMode::Full -- even though target, image, and
    // selection_generation are all still identical.
    #[test]
    fn prepare_for_open_rejects_confirmation_after_verify_mode_change_quick_to_full() {
        let snapshot = base_device();
        let state = select(snapshot.clone()).unwrap();
        let image = ImageSelection::new(TEST_IMAGE_SIZE);
        let intent = WriteIntent::from_selection(&state, image, VerifyMode::Quick).unwrap();
        let old_token = ConfirmationToken::confirm(intent);

        let result = prepare_for_open(
            &state,
            SnapshotFetchOutcome::Found(snapshot),
            image,
            VerifyMode::Full,
            Some(&old_token),
        );

        assert!(matches!(result, Err(WriteGateError::ConfirmationMismatch)));
    }

    // Stale confirmation D. Same as above, VerifyMode::Full -> VerifyMode::None.
    #[test]
    fn prepare_for_open_rejects_confirmation_after_verify_mode_change_full_to_none() {
        let snapshot = base_device();
        let state = select(snapshot.clone()).unwrap();
        let image = ImageSelection::new(TEST_IMAGE_SIZE);
        let intent = WriteIntent::from_selection(&state, image, VerifyMode::Full).unwrap();
        let old_token = ConfirmationToken::confirm(intent);

        let result = prepare_for_open(
            &state,
            SnapshotFetchOutcome::Found(snapshot),
            image,
            VerifyMode::None,
            Some(&old_token),
        );

        assert!(matches!(result, Err(WriteGateError::ConfirmationMismatch)));
    }

    // Stale confirmation E. Nothing changed (same target, image,
    // selection_generation, and VerifyMode as the confirmation was made
    // with) -> the Gate accepts it, for every VerifyMode variant.
    #[test]
    fn prepare_for_open_succeeds_when_verify_mode_is_unchanged() {
        for mode in [VerifyMode::None, VerifyMode::Quick, VerifyMode::Full] {
            let snapshot = base_device();
            let state = select(snapshot.clone()).unwrap();
            let image = ImageSelection::new(TEST_IMAGE_SIZE);
            let intent = WriteIntent::from_selection(&state, image, mode).unwrap();
            let token = ConfirmationToken::confirm(intent);

            let result = prepare_for_open(
                &state,
                SnapshotFetchOutcome::Found(snapshot),
                image,
                mode,
                Some(&token),
            );

            assert!(result.is_ok(), "expected Ok for VerifyMode {mode:?}");
        }
    }

    // Stale confirmation F. The same VerifyMode change as test C does not
    // permanently lock the target out -- only the stale token. A freshly
    // built WriteIntent/ConfirmationToken bound to the new VerifyMode lets
    // prepare_for_open succeed against the identical target and image.
    #[test]
    fn prepare_for_open_succeeds_with_fresh_confirmation_after_verify_mode_change() {
        let snapshot = base_device();
        let state = select(snapshot.clone()).unwrap();
        let image = ImageSelection::new(TEST_IMAGE_SIZE);

        let old_intent = WriteIntent::from_selection(&state, image, VerifyMode::Quick).unwrap();
        let _old_token = ConfirmationToken::confirm(old_intent);

        let new_intent = WriteIntent::from_selection(&state, image, VerifyMode::Full).unwrap();
        let new_token = ConfirmationToken::confirm(new_intent);

        let result = prepare_for_open(
            &state,
            SnapshotFetchOutcome::Found(snapshot),
            image,
            VerifyMode::Full,
            Some(&new_token),
        );

        assert!(result.is_ok());
    }

    // ---------------------------------------------------------------------
    // image_generation transport: prepare_for_open -> ReadyToOpen ->
    // PreparedWrite -> AuthorizedWrite
    // ---------------------------------------------------------------------

    // Gate generation transport. The confirmed `image_generation` (and,
    // via `AuthorizedWrite::image_size()`, the confirmed `image_size`)
    // travels unchanged all the way from `prepare_for_open` through
    // `ReadyToOpen`/`PreparedWrite` to `AuthorizedWrite`, readable only via
    // `AuthorizedWrite`'s own `pub(crate)` getters -- proving the value a
    // future `write_job::AuthorizedExecution::bind()` compares against is
    // exactly the one the Gate verified, never a fresh or re-derived one.
    #[test]
    fn authorized_write_carries_the_confirmed_image_generation_and_size() {
        let snapshot = base_device();
        let state = select(snapshot.clone()).unwrap();
        let image = ImageSelection::new(TEST_IMAGE_SIZE);
        let intent = WriteIntent::from_selection(&state, image, VerifyMode::None).unwrap();
        let confirmation = ConfirmationToken::confirm(intent);

        let ready = prepare_for_open(
            &state,
            SnapshotFetchOutcome::Found(snapshot.clone()),
            image,
            VerifyMode::None,
            Some(&confirmation),
        )
        .unwrap();

        let metadata = matching_fd_metadata(&snapshot);
        let (_path, handle) = test_handle_with_temp_file("generation-transport");
        let prepared = finalize_prepared_write(ready, Some(handle), Some(&metadata)).unwrap();
        let authorized = prepared.begin();

        assert_eq!(authorized.image_generation(), image.image_generation());
        assert_eq!(authorized.image_size(), image.image_size());
    }

    // ---------------------------------------------------------------------
    // check_identity_instance_for_verify (Built-in Verify implementation
    // step 3)
    // ---------------------------------------------------------------------

    // V1. Identical baseline/current, no hazard: Verify is allowed.
    #[test]
    fn verify_target_check_succeeds_for_identical_snapshot() {
        let baseline = base_device();
        let current = base_device();

        assert_eq!(
            check_identity_instance_for_verify(&baseline, &current),
            Ok(())
        );
    }

    // V2. A changed serial is rejected, exactly as strictly as write time.
    #[test]
    fn verify_target_check_rejects_identity_changed() {
        let baseline = base_device();
        let mut current = base_device();
        current.serial = "DIFFERENT-SERIAL".to_string();

        assert_eq!(
            check_identity_instance_for_verify(&baseline, &current),
            Err(VerifyTargetCheckError::IdentityChanged)
        );
    }

    // V3. Neither snapshot reports a usable serial: Identity cannot be
    // proven, so Verify is rejected rather than assumed safe.
    #[test]
    fn verify_target_check_rejects_identity_insufficient() {
        let mut baseline = base_device();
        baseline.serial = String::new();
        let mut current = base_device();
        current.serial = String::new();

        assert_eq!(
            check_identity_instance_for_verify(&baseline, &current),
            Err(VerifyTargetCheckError::IdentityInsufficient)
        );
    }

    // V4. A changed diskseq (unplug/replug, or device re-enumeration) is
    // rejected, exactly as strictly as write time.
    #[test]
    fn verify_target_check_rejects_instance_recreated() {
        let baseline = base_device();
        let mut current = base_device();
        current.diskseq = Some(999);

        assert_eq!(
            check_identity_instance_for_verify(&baseline, &current),
            Err(VerifyTargetCheckError::InstanceRecreated)
        );
    }

    // V5. Missing diskseq information cannot prove Instance sameness, so
    // Verify is rejected rather than assumed safe.
    #[test]
    fn verify_target_check_rejects_instance_insufficient() {
        let mut baseline = base_device();
        baseline.diskseq = None;
        let current = base_device();

        assert_eq!(
            check_identity_instance_for_verify(&baseline, &current),
            Err(VerifyTargetCheckError::InstanceInsufficient)
        );
    }

    // V6 (the key regression test this step exists for). A device that
    // gained mount points since the baseline -- exactly what happens when
    // the OS/desktop auto-mounts a newly-written filesystem, as observed on
    // real hardware after the MyPocketOS Hybrid ISO write -- must NOT block
    // Verify. Reusing `check_identity_instance_safety` here would have
    // rejected this via `assess_device`'s `MountedFilesystem` -> `Caution`.
    #[test]
    fn verify_target_check_allows_newly_mounted_filesystem() {
        let baseline = base_device();
        let mut current = base_device();
        current.mount_points = vec!["/media/example".to_string()];

        assert_eq!(
            check_identity_instance_for_verify(&baseline, &current),
            Ok(())
        );
    }

    // V7. A device that is no longer reported as partitionable (some hybrid
    // images legitimately change this) does not block Verify on its own.
    #[test]
    fn verify_target_check_allows_not_partitionable_change() {
        let baseline = base_device();
        let mut current = base_device();
        current.hint_partitionable = false;

        assert_eq!(
            check_identity_instance_for_verify(&baseline, &current),
            Ok(())
        );
    }

    // V8. A removable/connection_bus reclassification alone -- with Identity
    // and Instance both unchanged -- does not block Verify; an actual device
    // swap is caught by the Identity/Instance checks above instead.
    #[test]
    fn verify_target_check_allows_removable_and_bus_reclassification() {
        let baseline = base_device();
        let mut current = base_device();
        current.removable = false;
        current.connection_bus = "unknown".to_string();

        assert_eq!(
            check_identity_instance_for_verify(&baseline, &current),
            Ok(())
        );
    }

    // V9. A device the system now considers a system disk is rejected.
    #[test]
    fn verify_target_check_rejects_system_device() {
        let baseline = base_device();
        let mut current = base_device();
        current.hint_system = true;

        assert_eq!(
            check_identity_instance_for_verify(&baseline, &current),
            Err(VerifyTargetCheckError::UnsafeTargetState)
        );
    }

    // V10. Newly-active swap on the target is rejected.
    #[test]
    fn verify_target_check_rejects_active_swap() {
        let baseline = base_device();
        let mut current = base_device();
        current.active_swap = true;

        assert_eq!(
            check_identity_instance_for_verify(&baseline, &current),
            Err(VerifyTargetCheckError::UnsafeTargetState)
        );
    }

    // V11. A newly-detected LUKS/LVM/RAID signature is rejected.
    #[test]
    fn verify_target_check_rejects_complex_storage() {
        let baseline = base_device();
        let mut current = base_device();
        current.complex_storage = true;

        assert_eq!(
            check_identity_instance_for_verify(&baseline, &current),
            Err(VerifyTargetCheckError::UnsafeTargetState)
        );
    }

    // V12. A device the system now says to ignore is rejected.
    #[test]
    fn verify_target_check_rejects_hint_ignore() {
        let baseline = base_device();
        let mut current = base_device();
        current.hint_ignore = true;

        assert_eq!(
            check_identity_instance_for_verify(&baseline, &current),
            Err(VerifyTargetCheckError::UnsafeTargetState)
        );
    }

    // V13. Media no longer available (nothing to read) is rejected.
    #[test]
    fn verify_target_check_rejects_media_unavailable() {
        let baseline = base_device();
        let mut current = base_device();
        current.media_available = false;

        assert_eq!(
            check_identity_instance_for_verify(&baseline, &current),
            Err(VerifyTargetCheckError::UnsafeTargetState)
        );
    }

    // V14. `read_only` becoming `true` is deliberately NOT a hard hazard for
    // Verify -- see `verify_target_has_hard_hazard`'s doc comment for the
    // full rationale (it is a write-restriction signal, irrelevant to a
    // read-only Verify, and blocking on it would work against Verify's own
    // diagnostic purpose). This test pins that deliberate design decision.
    #[test]
    fn verify_target_check_allows_read_only_becoming_true() {
        let baseline = base_device();
        let mut current = base_device();
        current.read_only = true;

        assert_eq!(
            check_identity_instance_for_verify(&baseline, &current),
            Ok(())
        );
    }

    // ---------------------------------------------------------------------
    // diagnose_identity_instance_for_verify / VerifyTargetDiagnostics /
    // HardHazardReason (Verify Pre-flight Diagnostics Design, implementation
    // step 1+2)
    //
    // Every test below checks both the diagnostics value itself and the
    // `check_identity_instance_for_verify` result together, so a future
    // change that made the two diverge (diagnostics saying one thing, the
    // check deciding another) would fail here immediately.
    // ---------------------------------------------------------------------

    // D1. Identical baseline/current: Identity Same, Instance SameInstance,
    // no hazards, and the check still allows Verify.
    #[test]
    fn diagnostics_for_identical_snapshot_are_clean_and_check_allows() {
        let baseline = base_device();
        let current = base_device();

        let diagnostics = diagnose_identity_instance_for_verify(&baseline, &current);

        assert_eq!(diagnostics.identity, IdentityComparison::Same);
        assert_eq!(diagnostics.instance, InstanceComparison::SameInstance);
        assert!(diagnostics.hazards.is_empty());
        assert_eq!(
            check_identity_instance_for_verify(&baseline, &current),
            Ok(())
        );
    }

    // D2. mount_points going from empty to non-empty: the diagnostics'
    // `current` snapshot preserves the new value (observable for a future
    // log line), no hazard is raised, and the check still allows Verify --
    // this is the same real-hardware scenario `verify_target_check_allows_newly_mounted_filesystem`
    // above pins, now also checked at the diagnostics level.
    #[test]
    fn diagnostics_preserve_newly_mounted_filesystem_without_hazard() {
        let baseline = base_device();
        let mut current = base_device();
        current.mount_points = vec!["/media/example".to_string()];

        let diagnostics = diagnose_identity_instance_for_verify(&baseline, &current);

        assert_eq!(diagnostics.current.mount_points, vec!["/media/example"]);
        assert!(diagnostics.baseline.mount_points.is_empty());
        assert!(diagnostics.hazards.is_empty());
        assert_eq!(
            check_identity_instance_for_verify(&baseline, &current),
            Ok(())
        );
    }

    // D3. read_only going from false to true: the diagnostics' `current`
    // snapshot preserves the change, no hazard is raised, and the check
    // still allows Verify (mirrors `verify_target_check_allows_read_only_becoming_true`
    // above at the diagnostics level).
    #[test]
    fn diagnostics_preserve_read_only_change_without_hazard() {
        let baseline = base_device();
        let mut current = base_device();
        current.read_only = true;

        let diagnostics = diagnose_identity_instance_for_verify(&baseline, &current);

        assert!(!diagnostics.baseline.read_only);
        assert!(diagnostics.current.read_only);
        assert!(diagnostics.hazards.is_empty());
        assert_eq!(
            check_identity_instance_for_verify(&baseline, &current),
            Ok(())
        );
    }

    // D4. hint_system alone: hazards contains exactly SystemDevice, and the
    // check rejects with UnsafeTargetState.
    #[test]
    fn diagnostics_report_system_device_hazard() {
        let baseline = base_device();
        let mut current = base_device();
        current.hint_system = true;

        let diagnostics = diagnose_identity_instance_for_verify(&baseline, &current);

        assert_eq!(diagnostics.hazards, vec![HardHazardReason::SystemDevice]);
        assert_eq!(
            check_identity_instance_for_verify(&baseline, &current),
            Err(VerifyTargetCheckError::UnsafeTargetState)
        );
    }

    // D5. active_swap and complex_storage both true: both reasons are
    // reported, in the fixed, documented order (ActiveSwap before
    // ComplexStorage), regardless of which field was set first in the test.
    #[test]
    fn diagnostics_report_multiple_hazards_in_deterministic_order() {
        let baseline = base_device();
        let mut current = base_device();
        current.complex_storage = true;
        current.active_swap = true;

        let diagnostics = diagnose_identity_instance_for_verify(&baseline, &current);

        assert_eq!(
            diagnostics.hazards,
            vec![
                HardHazardReason::ActiveSwap,
                HardHazardReason::ComplexStorage
            ]
        );
        assert_eq!(
            check_identity_instance_for_verify(&baseline, &current),
            Err(VerifyTargetCheckError::UnsafeTargetState)
        );
    }

    // D6. hint_ignore alone: hazards contains exactly HintIgnore.
    #[test]
    fn diagnostics_report_hint_ignore_hazard() {
        let baseline = base_device();
        let mut current = base_device();
        current.hint_ignore = true;

        let diagnostics = diagnose_identity_instance_for_verify(&baseline, &current);

        assert_eq!(diagnostics.hazards, vec![HardHazardReason::HintIgnore]);
        assert_eq!(
            check_identity_instance_for_verify(&baseline, &current),
            Err(VerifyTargetCheckError::UnsafeTargetState)
        );
    }

    // D7. media_available false: hazards contains exactly MediaUnavailable.
    #[test]
    fn diagnostics_report_media_unavailable_hazard() {
        let baseline = base_device();
        let mut current = base_device();
        current.media_available = false;

        let diagnostics = diagnose_identity_instance_for_verify(&baseline, &current);

        assert_eq!(
            diagnostics.hazards,
            vec![HardHazardReason::MediaUnavailable]
        );
        assert_eq!(
            check_identity_instance_for_verify(&baseline, &current),
            Err(VerifyTargetCheckError::UnsafeTargetState)
        );
    }

    // D8. Identity changed: diagnostics.identity reports Changed, and the
    // check still rejects with the same IdentityChanged error as before this
    // refactor (Instance/hazards are not even reached).
    #[test]
    fn diagnostics_report_identity_changed_and_check_still_rejects() {
        let baseline = base_device();
        let mut current = base_device();
        current.serial = "DIFFERENT-SERIAL".to_string();

        let diagnostics = diagnose_identity_instance_for_verify(&baseline, &current);

        assert_eq!(diagnostics.identity, IdentityComparison::Changed);
        assert_eq!(
            check_identity_instance_for_verify(&baseline, &current),
            Err(VerifyTargetCheckError::IdentityChanged)
        );
    }

    // D9. Identity insufficient (no usable serial on either side): diagnostics
    // and check behavior both preserved from before this refactor.
    #[test]
    fn diagnostics_report_identity_insufficient_and_check_still_rejects() {
        let mut baseline = base_device();
        baseline.serial = String::new();
        let mut current = base_device();
        current.serial = String::new();

        let diagnostics = diagnose_identity_instance_for_verify(&baseline, &current);

        assert_eq!(
            diagnostics.identity,
            IdentityComparison::InsufficientIdentity
        );
        assert_eq!(
            check_identity_instance_for_verify(&baseline, &current),
            Err(VerifyTargetCheckError::IdentityInsufficient)
        );
    }

    // D10. Instance recreated (diskseq changed): diagnostics.instance reports
    // Recreated, and the check still rejects with InstanceRecreated.
    #[test]
    fn diagnostics_report_instance_recreated_and_check_still_rejects() {
        let baseline = base_device();
        let mut current = base_device();
        current.diskseq = Some(999);

        let diagnostics = diagnose_identity_instance_for_verify(&baseline, &current);

        assert_eq!(diagnostics.instance, InstanceComparison::Recreated);
        assert_eq!(
            check_identity_instance_for_verify(&baseline, &current),
            Err(VerifyTargetCheckError::InstanceRecreated)
        );
    }

    // D11. Instance insufficient (diskseq missing on one side): diagnostics
    // and check behavior both preserved from before this refactor.
    #[test]
    fn diagnostics_report_instance_insufficient_and_check_still_rejects() {
        let mut baseline = base_device();
        baseline.diskseq = None;
        let current = base_device();

        let diagnostics = diagnose_identity_instance_for_verify(&baseline, &current);

        assert_eq!(
            diagnostics.instance,
            InstanceComparison::InsufficientInformation
        );
        assert_eq!(
            check_identity_instance_for_verify(&baseline, &current),
            Err(VerifyTargetCheckError::InstanceInsufficient)
        );
    }

    // ---------------------------------------------------------------------
    // verify_target_check_from_diagnostics (Verify Pre-flight Diagnostics,
    // implementation step 3+4): the shared Identity -> Instance -> hazards
    // priority order, now the single place both this module's own
    // `check_identity_instance_for_verify` and `write_job::PendingVerify::
    // check_target()` reach their allow/reject decision from. Exercised
    // here directly against hand-built `VerifyTargetDiagnostics` values
    // (independent of `diagnose_identity_instance_for_verify`'s own
    // comparison logic, already covered by the D1-D11 tests above), so the
    // priority order itself is pinned regardless of how the diagnostics
    // were produced.
    // ---------------------------------------------------------------------

    fn diagnostics_for_test(
        identity: IdentityComparison,
        instance: InstanceComparison,
        hazards: Vec<HardHazardReason>,
    ) -> VerifyTargetDiagnostics {
        VerifyTargetDiagnostics {
            baseline: base_device(),
            current: base_device(),
            identity,
            instance,
            hazards,
        }
    }

    // P1. Clean diagnostics (Same/SameInstance/no hazards) are allowed.
    #[test]
    fn verify_target_check_from_diagnostics_allows_clean_diagnostics() {
        let diagnostics = diagnostics_for_test(
            IdentityComparison::Same,
            InstanceComparison::SameInstance,
            Vec::new(),
        );

        assert_eq!(verify_target_check_from_diagnostics(&diagnostics), Ok(()));
    }

    // P2. Identity::Changed takes priority even when Instance and hazards
    // are both also wrong at the same time.
    #[test]
    fn verify_target_check_from_diagnostics_identity_changed_takes_priority() {
        let diagnostics = diagnostics_for_test(
            IdentityComparison::Changed,
            InstanceComparison::Recreated,
            vec![HardHazardReason::SystemDevice],
        );

        assert_eq!(
            verify_target_check_from_diagnostics(&diagnostics),
            Err(VerifyTargetCheckError::IdentityChanged)
        );
    }

    // P3. Identity::InsufficientIdentity also takes priority over Instance
    // and hazards.
    #[test]
    fn verify_target_check_from_diagnostics_identity_insufficient_takes_priority() {
        let diagnostics = diagnostics_for_test(
            IdentityComparison::InsufficientIdentity,
            InstanceComparison::Recreated,
            vec![HardHazardReason::SystemDevice],
        );

        assert_eq!(
            verify_target_check_from_diagnostics(&diagnostics),
            Err(VerifyTargetCheckError::IdentityInsufficient)
        );
    }

    // P4. With Identity Same, Instance::Recreated takes priority over a
    // simultaneous hazard.
    #[test]
    fn verify_target_check_from_diagnostics_instance_recreated_takes_priority_over_hazards() {
        let diagnostics = diagnostics_for_test(
            IdentityComparison::Same,
            InstanceComparison::Recreated,
            vec![HardHazardReason::ActiveSwap],
        );

        assert_eq!(
            verify_target_check_from_diagnostics(&diagnostics),
            Err(VerifyTargetCheckError::InstanceRecreated)
        );
    }

    // P5. With Identity Same, Instance::InsufficientInformation also takes
    // priority over a simultaneous hazard.
    #[test]
    fn verify_target_check_from_diagnostics_instance_insufficient_takes_priority_over_hazards() {
        let diagnostics = diagnostics_for_test(
            IdentityComparison::Same,
            InstanceComparison::InsufficientInformation,
            vec![HardHazardReason::ActiveSwap],
        );

        assert_eq!(
            verify_target_check_from_diagnostics(&diagnostics),
            Err(VerifyTargetCheckError::InstanceInsufficient)
        );
    }

    // P6. With Identity Same and Instance SameInstance, a single hazard is
    // reported as UnsafeTargetState.
    #[test]
    fn verify_target_check_from_diagnostics_reports_unsafe_target_state_for_a_hazard() {
        let diagnostics = diagnostics_for_test(
            IdentityComparison::Same,
            InstanceComparison::SameInstance,
            vec![HardHazardReason::MediaUnavailable],
        );

        assert_eq!(
            verify_target_check_from_diagnostics(&diagnostics),
            Err(VerifyTargetCheckError::UnsafeTargetState)
        );
    }

    // P7. Multiple simultaneous hazards still collapse to a single
    // UnsafeTargetState -- the flat error type is unchanged by this step.
    #[test]
    fn verify_target_check_from_diagnostics_collapses_multiple_hazards_to_unsafe_target_state() {
        let diagnostics = diagnostics_for_test(
            IdentityComparison::Same,
            InstanceComparison::SameInstance,
            vec![
                HardHazardReason::ActiveSwap,
                HardHazardReason::ComplexStorage,
            ],
        );

        assert_eq!(
            verify_target_check_from_diagnostics(&diagnostics),
            Err(VerifyTargetCheckError::UnsafeTargetState)
        );
    }
}
