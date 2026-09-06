// Core layer (Selection Continuity). This module never talks to UDisks2,
// D-Bus, or /sys directly — it only receives already-collected data
// (`DeviceSnapshot`, `SnapshotFetchOutcome`, `DeviceEvent`) and already-computed
// judgements (`SafetyAssessment`, `IdentityComparison`, `InstanceComparison`)
// from the Linux Backend / Safety Engine / Identity modules, and decides what
// they mean for the user's current Selection.

use crate::device::{DeviceSnapshot, SnapshotFetchOutcome};
use crate::identity::{compare_identity, compare_instance, IdentityComparison, InstanceComparison};
use crate::linux_access::FdMetadata;
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

#[derive(Debug)]
pub enum SelectionState {
    NoSelection,
    Selected {
        baseline: DeviceSnapshot,
        baseline_assessment: SafetyAssessment,
    },
    Invalidated {
        baseline: DeviceSnapshot,
        baseline_assessment: SafetyAssessment,
        reason: InvalidationReason,
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

    Ok(SelectionState::Selected {
        baseline,
        baseline_assessment,
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
        };
    }

    match event {
        DeviceEvent::InterfacesRemoved { .. } => SelectionState::Invalidated {
            baseline,
            baseline_assessment,
            reason: InvalidationReason::TargetRemoved,
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
                }
            } else {
                SelectionState::Selected {
                    baseline,
                    baseline_assessment,
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
            };
        }
        SnapshotFetchOutcome::Error(_) => {
            return SelectionState::Invalidated {
                baseline,
                baseline_assessment,
                reason: InvalidationReason::SnapshotRefreshFailed,
            };
        }
    };

    if let Err(reason) = check_identity_instance_safety(&baseline, &current) {
        return SelectionState::Invalidated {
            baseline,
            baseline_assessment,
            reason,
        };
    }

    SelectionState::Selected {
        baseline,
        baseline_assessment,
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
// connecting a `PreparedWrite` to the Writer is explicitly a later step.
// ---------------------------------------------------------------------

// Binds a single "yes, write this image to this target" confirmation to the
// exact target (by block_path), its exact size, the exact image size, and
// the target's block-device generation (diskseq) at confirmation time. A
// token is data only — there is no UI in this codebase yet, so (for now) the
// only way to obtain one is to construct it directly from the snapshot the
// user was actually looking at when they confirmed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfirmationToken {
    pub target_block_path: String,
    pub target_size: u64,
    pub image_size: u64,
    pub target_diskseq: Option<u64>,
}

impl ConfirmationToken {
    pub fn new(target: &DeviceSnapshot, image_size: u64) -> Self {
        ConfirmationToken {
            target_block_path: target.block_path.clone(),
            target_size: target.size,
            image_size,
            target_diskseq: target.diskseq,
        }
    }
}

// A token only ever authorizes the exact (target, size, image_size,
// generation) it was made for. Any difference — a different target, a
// resized/different image, or the target having been replugged (a new
// diskseq, whether via a plain reconnect or a full reselect) since the token
// was made — is a mismatch, not a "close enough".
fn confirmation_matches(
    token: &ConfirmationToken,
    current: &DeviceSnapshot,
    image_size: u64,
) -> bool {
    token.target_block_path == current.block_path
        && token.target_size == current.size
        && token.image_size == image_size
        && token.target_diskseq == current.diskseq
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
// confirmation) held at the moment this value was constructed. Deliberately
// does not hold the FD itself (see module docs) and has no method that could
// perform a write — obtaining a `PreparedWrite` is not, by itself, capable
// of writing anything. Connecting it to `writer::write()` is a distinct,
// later step this module does not implement.
#[derive(Debug)]
pub struct PreparedWrite {
    pub target_block_path: String,
    pub target_size: u64,
    pub image_size: u64,
}

// The pure half of the gate: conditions A-I plus the confirmation check.
// Takes the current `SelectionState` (by reference — this does not mutate
// ongoing Selection Continuity monitoring) and a target-specific re-fetch
// the caller already performed (condition B). Reuses `writer::WritePlan` for
// F/G/H/I instead of re-implementing size validation here.
pub fn prepare_for_open(
    state: &SelectionState,
    refreshed: SnapshotFetchOutcome,
    image_size: u64,
    confirmation: Option<&ConfirmationToken>,
) -> Result<ReadyToOpen, WriteGateError> {
    let (baseline, _baseline_assessment) = match state {
        SelectionState::NoSelection => return Err(WriteGateError::NoSelection),
        SelectionState::Invalidated { .. } => return Err(WriteGateError::SelectionInvalidated),
        SelectionState::Selected {
            baseline,
            baseline_assessment,
        } => (baseline, baseline_assessment),
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
    let plan = match WritePlan::new(image_size, current.size, DEFAULT_CHUNK_SIZE) {
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

    if !confirmation_matches(token, &current, image_size) {
        return Err(WriteGateError::ConfirmationMismatch);
    }

    Ok(ReadyToOpen { current, plan })
}

// The second half of the gate (conditions J and K), run after the caller has
// used `ReadyToOpen` to actually call OpenDevice (Linux I/O, outside this
// module) and read back the FD's metadata. Consumes `ReadyToOpen` and
// produces a `PreparedWrite` only if OpenDevice succeeded and the resulting
// FD is bound to the exact device node just re-verified.
pub fn finalize_prepared_write(
    ready: ReadyToOpen,
    open_device_succeeded: bool,
    fd_metadata: Option<&FdMetadata>,
) -> Result<PreparedWrite, WriteGateError> {
    if !open_device_succeeded {
        return Err(WriteGateError::OpenDeviceFailed);
    }

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
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::linux_monitor::PropertyChange;

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
        let token = ConfirmationToken::new(&snapshot, TEST_IMAGE_SIZE);

        let ready = prepare_for_open(
            &state,
            SnapshotFetchOutcome::Found(base_device()),
            TEST_IMAGE_SIZE,
            Some(&token),
        )
        .unwrap();

        let metadata = matching_fd_metadata(&snapshot);
        let prepared = finalize_prepared_write(ready, true, Some(&metadata)).unwrap();

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
            TEST_IMAGE_SIZE,
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
            TEST_IMAGE_SIZE,
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
        let token = ConfirmationToken::new(&other_target, TEST_IMAGE_SIZE);

        let result = prepare_for_open(
            &state,
            SnapshotFetchOutcome::Found(snapshot),
            TEST_IMAGE_SIZE,
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
        let token = ConfirmationToken::new(&snapshot, TEST_IMAGE_SIZE);

        let result = prepare_for_open(
            &state,
            SnapshotFetchOutcome::Found(snapshot),
            TEST_IMAGE_SIZE * 5,
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
        let token = ConfirmationToken::new(&snapshot, TEST_IMAGE_SIZE);

        let result = prepare_for_open(
            &state,
            SnapshotFetchOutcome::Found(snapshot),
            TEST_IMAGE_SIZE,
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
        let token = ConfirmationToken::new(&snapshot, TEST_IMAGE_SIZE);

        let result = prepare_for_open(
            &state,
            SnapshotFetchOutcome::Error("simulated D-Bus failure".to_string()),
            TEST_IMAGE_SIZE,
            Some(&token),
        );

        assert!(matches!(result, Err(WriteGateError::SnapshotRefreshFailed)));
    }

    // Gate F. Identity Changed on the re-fetched current -> IdentityChanged.
    #[test]
    fn prepare_for_open_rejects_identity_changed() {
        let snapshot = base_device();
        let state = select(snapshot.clone()).unwrap();
        let token = ConfirmationToken::new(&snapshot, TEST_IMAGE_SIZE);

        let mut current = snapshot;
        current.serial = "OTHER-SERIAL-0002".to_string();

        let result = prepare_for_open(
            &state,
            SnapshotFetchOutcome::Found(current),
            TEST_IMAGE_SIZE,
            Some(&token),
        );

        assert!(matches!(result, Err(WriteGateError::IdentityChanged)));
    }

    // Gate: Identity InsufficientIdentity -> IdentityInsufficient.
    #[test]
    fn prepare_for_open_rejects_identity_insufficient() {
        let snapshot = base_device();
        let state = select(snapshot.clone()).unwrap();
        let token = ConfirmationToken::new(&snapshot, TEST_IMAGE_SIZE);

        let mut current = snapshot;
        current.serial = String::new();

        let result = prepare_for_open(
            &state,
            SnapshotFetchOutcome::Found(current),
            TEST_IMAGE_SIZE,
            Some(&token),
        );

        assert!(matches!(result, Err(WriteGateError::IdentityInsufficient)));
    }

    // Gate G. Instance Recreated (diskseq changed) -> InstanceRecreated.
    #[test]
    fn prepare_for_open_rejects_instance_recreated() {
        let snapshot = base_device();
        let state = select(snapshot.clone()).unwrap();
        let token = ConfirmationToken::new(&snapshot, TEST_IMAGE_SIZE);

        let mut current = snapshot;
        current.diskseq = Some(19);

        let result = prepare_for_open(
            &state,
            SnapshotFetchOutcome::Found(current),
            TEST_IMAGE_SIZE,
            Some(&token),
        );

        assert!(matches!(result, Err(WriteGateError::InstanceRecreated)));
    }

    // Gate: Instance InsufficientInformation -> InstanceInsufficient.
    #[test]
    fn prepare_for_open_rejects_instance_insufficient() {
        let snapshot = base_device();
        let state = select(snapshot.clone()).unwrap();
        let token = ConfirmationToken::new(&snapshot, TEST_IMAGE_SIZE);

        let mut current = snapshot;
        current.diskseq = None;

        let result = prepare_for_open(
            &state,
            SnapshotFetchOutcome::Found(current),
            TEST_IMAGE_SIZE,
            Some(&token),
        );

        assert!(matches!(result, Err(WriteGateError::InstanceInsufficient)));
    }

    // Gate H. Safety re-evaluation on current now Blocked -> SafetyRejected.
    #[test]
    fn prepare_for_open_rejects_safety_blocked() {
        let snapshot = base_device();
        let state = select(snapshot.clone()).unwrap();
        let token = ConfirmationToken::new(&snapshot, TEST_IMAGE_SIZE);

        let mut current = snapshot;
        current.hint_system = true;

        let result = prepare_for_open(
            &state,
            SnapshotFetchOutcome::Found(current),
            TEST_IMAGE_SIZE,
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
        let token = ConfirmationToken::new(&snapshot, too_large);

        let result = prepare_for_open(
            &state,
            SnapshotFetchOutcome::Found(snapshot),
            too_large,
            Some(&token),
        );

        assert!(matches!(result, Err(WriteGateError::ImageTooLarge)));
    }

    // finalize J. OpenDevice itself failing -> OpenDeviceFailed, regardless
    // of FD metadata (there is none to check yet).
    #[test]
    fn finalize_prepared_write_rejects_open_device_failure() {
        let snapshot = base_device();
        let ready = ReadyToOpen {
            plan: WritePlan::new(TEST_IMAGE_SIZE, snapshot.size, DEFAULT_CHUNK_SIZE).unwrap(),
            current: snapshot,
        };

        let result = finalize_prepared_write(ready, false, None);

        assert!(matches!(result, Err(WriteGateError::OpenDeviceFailed)));
    }

    // finalize K (Mismatch). OpenDevice succeeded but the FD's own
    // major/minor don't match the just-verified snapshot -> FdBindingMismatch.
    #[test]
    fn finalize_prepared_write_rejects_fd_binding_mismatch() {
        let snapshot = base_device();
        let metadata = fd_metadata(snapshot.major + 1, snapshot.minor, Some(snapshot.size));
        let ready = ReadyToOpen {
            plan: WritePlan::new(TEST_IMAGE_SIZE, snapshot.size, DEFAULT_CHUNK_SIZE).unwrap(),
            current: snapshot,
        };

        let result = finalize_prepared_write(ready, true, Some(&metadata));

        assert!(matches!(result, Err(WriteGateError::FdBindingMismatch)));
    }

    // finalize K (InsufficientInformation). OpenDevice succeeded but FD
    // metadata could not be obtained -> FdBindingInsufficient, never assumed
    // to be a Match.
    #[test]
    fn finalize_prepared_write_rejects_fd_binding_insufficient_information() {
        let snapshot = base_device();
        let ready = ReadyToOpen {
            plan: WritePlan::new(TEST_IMAGE_SIZE, snapshot.size, DEFAULT_CHUNK_SIZE).unwrap(),
            current: snapshot,
        };

        let result = finalize_prepared_write(ready, true, None);

        assert!(matches!(result, Err(WriteGateError::FdBindingInsufficient)));
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
        let stale_token = ConfirmationToken::new(&old_snapshot, TEST_IMAGE_SIZE);

        let mut new_snapshot = base_device();
        new_snapshot.diskseq = Some(99);
        let state = select(new_snapshot.clone()).unwrap();

        let result = prepare_for_open(
            &state,
            SnapshotFetchOutcome::Found(new_snapshot),
            TEST_IMAGE_SIZE,
            Some(&stale_token),
        );

        assert!(matches!(result, Err(WriteGateError::ConfirmationMismatch)));
    }

    // Gate M / Confirmation-mismatch D. After a Selection is Invalidated and
    // the user explicitly re-selects (a fresh baseline, new diskseq), a
    // confirmation obtained before that re-selection must not carry over.
    #[test]
    fn prepare_for_open_rejects_confirmation_after_reselect() {
        let original = base_device();
        let block_path = original.block_path.clone();
        let old_token = ConfirmationToken::new(&original, TEST_IMAGE_SIZE);

        let state = select(original).unwrap();
        let state = apply_event(state, &interfaces_removed(&block_path));
        assert!(matches!(state, SelectionState::Invalidated { .. }));

        let mut reselected_snapshot = base_device();
        reselected_snapshot.diskseq = Some(99);
        let state = select(reselected_snapshot.clone()).unwrap();

        let result = prepare_for_open(
            &state,
            SnapshotFetchOutcome::Found(reselected_snapshot),
            TEST_IMAGE_SIZE,
            Some(&old_token),
        );

        assert!(matches!(result, Err(WriteGateError::ConfirmationMismatch)));
    }
}
