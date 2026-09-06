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

    match compare_identity(&baseline, &current) {
        IdentityComparison::Changed => {
            return SelectionState::Invalidated {
                baseline,
                baseline_assessment,
                reason: InvalidationReason::IdentityChanged,
            };
        }
        IdentityComparison::InsufficientIdentity => {
            return SelectionState::Invalidated {
                baseline,
                baseline_assessment,
                reason: InvalidationReason::IdentityInsufficient,
            };
        }
        IdentityComparison::Same => {}
    }

    match compare_instance(&baseline, &current) {
        InstanceComparison::Recreated => {
            return SelectionState::Invalidated {
                baseline,
                baseline_assessment,
                reason: InvalidationReason::InstanceRecreated,
            };
        }
        InstanceComparison::InsufficientInformation => {
            return SelectionState::Invalidated {
                baseline,
                baseline_assessment,
                reason: InvalidationReason::InstanceInformationInsufficient,
            };
        }
        InstanceComparison::SameInstance => {}
    }

    // Baseline was safe, but the Safety Engine's verdict can change
    // independently of Identity/Instance (e.g. the target got mounted, or an
    // active swap appeared) — so it must be re-run on `current`, not assumed.
    let current_assessment = assess_device(&current);

    if !current_assessment.writable || !matches!(current_assessment.risk_level, RiskLevel::Normal)
    {
        return SelectionState::Invalidated {
            baseline,
            baseline_assessment,
            reason: InvalidationReason::SafetyChanged,
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
}
