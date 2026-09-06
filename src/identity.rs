use crate::device::DeviceSnapshot;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityComparison {
    Same,
    Changed,
    InsufficientIdentity,
}

// Kernel-assigned device nodes and major/minor numbers can be reassigned across
// replugs even for the same physical device (observed directly during SD-reader
// investigation), so they are intentionally excluded from this comparison.
// Only serial/size/vendor/model act as identity evidence; a positive `Same`
// requires a matching, non-empty serial on both sides.
pub fn compare_identity(
    baseline: &DeviceSnapshot,
    current: &DeviceSnapshot,
) -> IdentityComparison {
    let serial_known =
        !baseline.serial.is_empty() && !current.serial.is_empty();

    if serial_known && baseline.serial != current.serial {
        return IdentityComparison::Changed;
    }

    if baseline.size != current.size {
        return IdentityComparison::Changed;
    }

    let vendor_conflicts = !baseline.vendor.is_empty()
        && !current.vendor.is_empty()
        && baseline.vendor != current.vendor;

    let model_conflicts = !baseline.model.is_empty()
        && !current.model.is_empty()
        && baseline.model != current.model;

    if vendor_conflicts || model_conflicts {
        return IdentityComparison::Changed;
    }

    if serial_known {
        return IdentityComparison::Same;
    }

    IdentityComparison::InsufficientIdentity
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstanceComparison {
    SameInstance,
    Recreated,
    InsufficientInformation,
}

// `diskseq` answers a different question than `compare_identity`: not "is this
// the same physical drive?" but "is this the very same Linux block device
// instance the user selected, with no disconnect/re-creation in between?".
// A physical device that is unplugged and replugged (even the exact same USB
// stick or SD card) gets a new, larger diskseq from the kernel, while
// compare_identity would still correctly call it the same physical device.
// Mixing the two would defeat that distinction, so diskseq is intentionally
// kept out of compare_identity and only used here.
pub fn compare_instance(
    baseline: &DeviceSnapshot,
    current: &DeviceSnapshot,
) -> InstanceComparison {
    match (baseline.diskseq, current.diskseq) {
        (Some(a), Some(b)) if a == b => InstanceComparison::SameInstance,
        (Some(_), Some(_)) => InstanceComparison::Recreated,
        _ => InstanceComparison::InsufficientInformation,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_device() -> DeviceSnapshot {
        DeviceSnapshot {
            device: "/dev/sda".to_string(),
            block_path: "/org/freedesktop/UDisks2/block_devices/sda"
                .to_string(),
            drive_path:
                "/org/freedesktop/UDisks2/drives/Test_Model_TEST-SERIAL-0001"
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

    // A. Full match (including serial) -> Same.
    #[test]
    fn identical_snapshots_are_same() {
        let baseline = base_device();
        let current = base_device();

        assert_eq!(
            compare_identity(&baseline, &current),
            IdentityComparison::Same
        );
    }

    // B. Device node (and its UDisks2 block path) changed alone, all other
    // stable identity fields unchanged -> still Same.
    #[test]
    fn device_node_change_alone_is_still_same() {
        let baseline = base_device();
        let mut current = base_device();
        current.device = "/dev/sdb".to_string();
        current.block_path =
            "/org/freedesktop/UDisks2/block_devices/sdb".to_string();

        assert_eq!(
            compare_identity(&baseline, &current),
            IdentityComparison::Same
        );
    }

    // C. Device node unchanged, serial changed -> Changed.
    #[test]
    fn serial_change_is_changed() {
        let baseline = base_device();
        let mut current = base_device();
        current.serial = "TEST-SERIAL-9999".to_string();

        assert_eq!(
            compare_identity(&baseline, &current),
            IdentityComparison::Changed
        );
    }

    // D. Device node unchanged, size changed -> Changed.
    #[test]
    fn size_change_is_changed() {
        let baseline = base_device();
        let mut current = base_device();
        current.size = 16_000_000_000;

        assert_eq!(
            compare_identity(&baseline, &current),
            IdentityComparison::Changed
        );
    }

    // E. Serial empty on both sides, nothing else to contradict -> do not
    // claim Same; fall back to the safe InsufficientIdentity result.
    #[test]
    fn missing_serial_is_insufficient_identity() {
        let mut baseline = base_device();
        baseline.serial = String::new();
        let mut current = base_device();
        current.serial = String::new();

        assert_eq!(
            compare_identity(&baseline, &current),
            IdentityComparison::InsufficientIdentity
        );
    }

    // F. major/minor changed alone (kernel re-enumeration), all stable
    // identity fields unchanged -> still Same. major/minor are collected for
    // diagnostics but are never authoritative for this decision, by design.
    #[test]
    fn major_minor_change_alone_is_still_same() {
        let baseline = base_device();
        let mut current = base_device();
        current.major = 259;
        current.minor = 3;

        assert_eq!(
            compare_identity(&baseline, &current),
            IdentityComparison::Same
        );
    }

    // G. vendor/model alone matching a different device (different serial and
    // size) must not be treated as Same.
    #[test]
    fn matching_vendor_and_model_does_not_imply_same_device() {
        let baseline = base_device();
        let mut current = base_device();
        current.serial = "OTHER-SERIAL-0002".to_string();
        current.size = 4_000_000_000;

        assert_eq!(
            compare_identity(&baseline, &current),
            IdentityComparison::Changed
        );
    }

    // Instance A. Same diskseq -> SameInstance.
    #[test]
    fn same_diskseq_is_same_instance() {
        let baseline = base_device();
        let current = base_device();

        assert_eq!(
            compare_instance(&baseline, &current),
            InstanceComparison::SameInstance
        );
    }

    // Instance B. diskseq changed (observed for real during replug testing:
    // 12 -> 19 -> 24 across successive reinsertions) -> Recreated.
    #[test]
    fn diskseq_change_is_recreated() {
        let baseline = base_device();
        let mut current = base_device();
        current.diskseq = Some(19);

        assert_eq!(
            compare_instance(&baseline, &current),
            InstanceComparison::Recreated
        );
    }

    // Instance C. diskseq unavailable on at least one side -> do not guess;
    // report InsufficientInformation instead of SameInstance or Recreated.
    #[test]
    fn missing_diskseq_is_insufficient_information() {
        let mut baseline = base_device();
        baseline.diskseq = None;
        let current = base_device();

        assert_eq!(
            compare_instance(&baseline, &current),
            InstanceComparison::InsufficientInformation
        );
    }

    // Instance D. Identity and Instance are deliberately independent
    // concepts: a matching serial/size/vendor/model (Same physical device)
    // does not imply the same block device generation. After an unplug and
    // replug of the very same physical drive, diskseq changes even though
    // nothing about the device's identity changed.
    #[test]
    fn identity_same_but_instance_recreated_after_replug() {
        let baseline = base_device();
        let mut current = base_device();
        current.diskseq = Some(19);

        assert_eq!(
            compare_identity(&baseline, &current),
            IdentityComparison::Same
        );
        assert_eq!(
            compare_instance(&baseline, &current),
            InstanceComparison::Recreated
        );
    }

    // Instance E. device node and major/minor unchanged (as observed for real:
    // the same USB port can keep reassigning the same major/minor across
    // replugs) -> diskseq is still the deciding factor, not device node or
    // major/minor.
    #[test]
    fn diskseq_alone_change_is_recreated_even_with_stable_device_node() {
        let baseline = base_device();
        let mut current = base_device();
        current.diskseq = Some(24);
        // device, block_path, major, minor intentionally left unchanged.

        assert_eq!(current.device, baseline.device);
        assert_eq!(current.major, baseline.major);
        assert_eq!(current.minor, baseline.minor);
        assert_eq!(
            compare_instance(&baseline, &current),
            InstanceComparison::Recreated
        );
    }
}
