use crate::device::DeviceSnapshot;

#[derive(Debug)]
pub enum RiskLevel {
    Normal,
    Caution,
    Blocked,
}

#[derive(Debug)]
pub enum RiskReason {
    SystemDevice,
    CriticalMount,
    ActiveSwap,
    ComplexStorage,
    MountedFilesystem,
    ReadOnly,
    IgnoredBySystem,
    NotPartitionable,
    UsbRemovable,
    UnknownOrNonRemovable,
    MediaUnavailable,
}

#[derive(Debug)]
pub struct SafetyAssessment {
    pub risk_level: RiskLevel,
    pub writable: bool,
    pub reasons: Vec<RiskReason>,
}

pub fn assess_device(device: &DeviceSnapshot) -> SafetyAssessment {
    let mut reasons = Vec::new();

    let has_critical_mount = device.mount_points.iter().any(|mount| {
        mount == "/"
            || mount == "/boot"
            || mount == "/boot/efi"
    });

    if has_critical_mount {
        reasons.push(RiskReason::CriticalMount);

        if device.hint_system {
            reasons.push(RiskReason::SystemDevice);
        }

        if device.active_swap {
            reasons.push(RiskReason::ActiveSwap);
        }

        if device.complex_storage {
            reasons.push(RiskReason::ComplexStorage);
        }

        return SafetyAssessment {
            risk_level: RiskLevel::Blocked,
            writable: false,
            reasons,
        };
    }

    if device.active_swap {
        reasons.push(RiskReason::ActiveSwap);

        return SafetyAssessment {
            risk_level: RiskLevel::Blocked,
            writable: false,
            reasons,
        };
    }

    if device.complex_storage {
        reasons.push(RiskReason::ComplexStorage);

        return SafetyAssessment {
            risk_level: RiskLevel::Blocked,
            writable: false,
            reasons,
        };
    }

    if device.hint_system {
        reasons.push(RiskReason::SystemDevice);

        return SafetyAssessment {
            risk_level: RiskLevel::Blocked,
            writable: false,
            reasons,
        };
    }

    if device.read_only {
        reasons.push(RiskReason::ReadOnly);

        return SafetyAssessment {
            risk_level: RiskLevel::Blocked,
            writable: false,
            reasons,
        };
    }

    if device.hint_ignore {
        reasons.push(RiskReason::IgnoredBySystem);

        return SafetyAssessment {
            risk_level: RiskLevel::Blocked,
            writable: false,
            reasons,
        };
    }

    if !device.media_available || device.size == 0 {
        reasons.push(RiskReason::MediaUnavailable);

        return SafetyAssessment {
            risk_level: RiskLevel::Blocked,
            writable: false,
            reasons,
        };
    }

    if !device.hint_partitionable {
        reasons.push(RiskReason::NotPartitionable);

        return SafetyAssessment {
            risk_level: RiskLevel::Caution,
            writable: false,
            reasons,
        };
    }

    if !device.mount_points.is_empty() {
        reasons.push(RiskReason::MountedFilesystem);

        return SafetyAssessment {
            risk_level: RiskLevel::Caution,
            writable: false,
            reasons,
        };
    }

    if device.connection_bus == "usb" && device.removable {
        reasons.push(RiskReason::UsbRemovable);

        return SafetyAssessment {
            risk_level: RiskLevel::Normal,
            writable: true,
            reasons,
        };
    }

    reasons.push(RiskReason::UnknownOrNonRemovable);

    SafetyAssessment {
        risk_level: RiskLevel::Caution,
        writable: false,
        reasons,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_device() -> DeviceSnapshot {
        DeviceSnapshot {
            device: "/dev/sdx".to_string(),
            block_path: "/org/freedesktop/UDisks2/block_devices/sdx"
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

    fn has_reason(reasons: &[RiskReason], target: &RiskReason) -> bool {
        reasons
            .iter()
            .any(|reason| std::mem::discriminant(reason) == std::mem::discriminant(target))
    }

    #[test]
    fn removable_usb_is_normal_and_writable() {
        let device = base_device();

        let assessment = assess_device(&device);

        assert!(matches!(assessment.risk_level, RiskLevel::Normal));
        assert!(assessment.writable);
        assert!(has_reason(&assessment.reasons, &RiskReason::UsbRemovable));
    }

    #[test]
    fn system_device_is_blocked() {
        let mut device = base_device();
        device.hint_system = true;

        let assessment = assess_device(&device);

        assert!(matches!(assessment.risk_level, RiskLevel::Blocked));
        assert!(!assessment.writable);
        assert!(has_reason(&assessment.reasons, &RiskReason::SystemDevice));
    }

    #[test]
    fn critical_mount_is_blocked() {
        let mut device = base_device();
        device.mount_points = vec!["/".to_string()];

        let assessment = assess_device(&device);

        assert!(matches!(assessment.risk_level, RiskLevel::Blocked));
        assert!(!assessment.writable);
        assert!(has_reason(&assessment.reasons, &RiskReason::CriticalMount));
    }

    #[test]
    fn read_only_device_is_blocked() {
        let mut device = base_device();
        device.read_only = true;

        let assessment = assess_device(&device);

        assert!(matches!(assessment.risk_level, RiskLevel::Blocked));
        assert!(!assessment.writable);
        assert!(has_reason(&assessment.reasons, &RiskReason::ReadOnly));
    }

    #[test]
    fn mounted_non_critical_filesystem_is_caution() {
        let mut device = base_device();
        device.mount_points = vec!["/mnt/test".to_string()];

        let assessment = assess_device(&device);

        assert!(matches!(assessment.risk_level, RiskLevel::Caution));
        assert!(!assessment.writable);
        assert!(has_reason(
            &assessment.reasons,
            &RiskReason::MountedFilesystem
        ));
    }

    #[test]
    fn active_swap_is_blocked() {
        let mut device = base_device();
        device.active_swap = true;

        let assessment = assess_device(&device);

        assert!(matches!(assessment.risk_level, RiskLevel::Blocked));
        assert!(!assessment.writable);
        assert!(has_reason(&assessment.reasons, &RiskReason::ActiveSwap));
    }

    #[test]
    fn complex_storage_is_blocked() {
        let mut device = base_device();
        device.complex_storage = true;

        let assessment = assess_device(&device);

        assert!(matches!(assessment.risk_level, RiskLevel::Blocked));
        assert!(!assessment.writable);
        assert!(has_reason(
            &assessment.reasons,
            &RiskReason::ComplexStorage
        ));
    }

    #[test]
    fn unknown_non_removable_device_is_caution() {
        let mut device = base_device();
        device.connection_bus = "sata".to_string();
        device.removable = false;

        let assessment = assess_device(&device);

        assert!(matches!(assessment.risk_level, RiskLevel::Caution));
        assert!(!assessment.writable);
        assert!(has_reason(
            &assessment.reasons,
            &RiskReason::UnknownOrNonRemovable
        ));
    }

    #[test]
    fn ignored_device_is_blocked() {
        let mut device = base_device();
        device.hint_ignore = true;

        let assessment = assess_device(&device);

        assert!(matches!(assessment.risk_level, RiskLevel::Blocked));
        assert!(!assessment.writable);
        assert!(has_reason(
            &assessment.reasons,
            &RiskReason::IgnoredBySystem
        ));
    }

    #[test]
    fn not_partitionable_device_is_caution() {
        let mut device = base_device();
        device.hint_partitionable = false;

        let assessment = assess_device(&device);

        assert!(matches!(assessment.risk_level, RiskLevel::Caution));
        assert!(!assessment.writable);
        assert!(has_reason(
            &assessment.reasons,
            &RiskReason::NotPartitionable
        ));
    }

    #[test]
    fn boot_critical_mount_is_blocked() {
        let mut device = base_device();
        device.mount_points = vec!["/boot".to_string()];

        let assessment = assess_device(&device);

        assert!(matches!(assessment.risk_level, RiskLevel::Blocked));
        assert!(!assessment.writable);
        assert!(has_reason(&assessment.reasons, &RiskReason::CriticalMount));
    }

    #[test]
    fn boot_efi_critical_mount_is_blocked() {
        let mut device = base_device();
        device.mount_points = vec!["/boot/efi".to_string()];

        let assessment = assess_device(&device);

        assert!(matches!(assessment.risk_level, RiskLevel::Blocked));
        assert!(!assessment.writable);
        assert!(has_reason(&assessment.reasons, &RiskReason::CriticalMount));
    }

    #[test]
    fn combined_critical_conditions_are_all_reported() {
        let mut device = base_device();
        device.mount_points = vec!["/".to_string()];
        device.hint_system = true;
        device.active_swap = true;
        device.complex_storage = true;

        let assessment = assess_device(&device);

        assert!(matches!(assessment.risk_level, RiskLevel::Blocked));
        assert!(!assessment.writable);
        assert!(has_reason(&assessment.reasons, &RiskReason::CriticalMount));
        assert!(has_reason(&assessment.reasons, &RiskReason::SystemDevice));
        assert!(has_reason(&assessment.reasons, &RiskReason::ActiveSwap));
        assert!(has_reason(
            &assessment.reasons,
            &RiskReason::ComplexStorage
        ));
    }

    #[test]
    fn media_unavailable_is_blocked() {
        let mut device = base_device();
        device.media_available = false;

        let assessment = assess_device(&device);

        assert!(matches!(assessment.risk_level, RiskLevel::Blocked));
        assert!(!assessment.writable);
        assert!(has_reason(
            &assessment.reasons,
            &RiskReason::MediaUnavailable
        ));
    }

    #[test]
    fn zero_size_media_is_blocked() {
        let mut device = base_device();
        device.size = 0;

        let assessment = assess_device(&device);

        assert!(matches!(assessment.risk_level, RiskLevel::Blocked));
        assert!(!assessment.writable);
        assert!(has_reason(
            &assessment.reasons,
            &RiskReason::MediaUnavailable
        ));
    }

    #[test]
    fn read_only_takes_priority_over_mounted_filesystem() {
        let mut device = base_device();
        device.read_only = true;
        device.mount_points = vec!["/mnt/test".to_string()];

        let assessment = assess_device(&device);

        assert!(matches!(assessment.risk_level, RiskLevel::Blocked));
        assert!(!assessment.writable);
        assert!(has_reason(&assessment.reasons, &RiskReason::ReadOnly));
    }
}