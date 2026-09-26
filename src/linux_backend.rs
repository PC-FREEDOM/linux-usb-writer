use std::{
    collections::HashMap,
    fs,
};

use zbus::{
    blocking::{Connection, Proxy},
    zvariant::{OwnedObjectPath, OwnedValue},
};

use crate::device::{DeviceSnapshot, SnapshotFetchOutcome};

fn bytes_to_string(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes)
        .trim_end_matches('\0')
        .to_string()
}

// Decodes a Linux dev_t into (major, minor) using the same encoding as
// glibc's gnu_dev_major/gnu_dev_minor. Used both for UDisks2's
// Block.DeviceNumber and for a raw fstat() st_rdev value (linux_access.rs) —
// both are the same dev_t encoding.
pub(crate) fn decode_device_number(device_number: u64) -> (u32, u32) {
    let major = (((device_number >> 8) & 0xfff) as u32)
        | ((device_number >> 32) as u32 & !0xfff);

    let minor = ((device_number & 0xff) as u32)
        | ((device_number >> 12) as u32 & !0xff);

    (major, minor)
}

// Reads the kernel's block device generation counter from sysfs
// (/sys/block/<name>/diskseq). Works for any whole-disk device node
// (sdX, nvme0n1, mmcblk0, ...) since the sysfs name is just the device
// node's basename. Returns None if unavailable rather than guessing a
// sentinel value, since 0 is not a reserved "unknown" diskseq.
fn read_diskseq(device_node: &str) -> Option<u64> {
    let device_name = device_node.strip_prefix("/dev/")?;
    let path = format!("/sys/block/{device_name}/diskseq");

    fs::read_to_string(path).ok()?.trim().parse().ok()
}

fn get_partition_paths(
    connection: &Connection,
    disk_path: &OwnedObjectPath,
) -> Vec<OwnedObjectPath> {
    let partition_table = match Proxy::new(
        connection,
        "org.freedesktop.UDisks2",
        disk_path.as_str(),
        "org.freedesktop.UDisks2.PartitionTable",
    ) {
        Ok(proxy) => proxy,
        Err(_) => return Vec::new(),
    };

    partition_table
        .get_property("Partitions")
        .unwrap_or_default()
}

// Every mount point of the disk: its own filesystem's (a disk with no
// partition table can carry a filesystem directly, e.g. a superfloppy or
// some written ISO images) and each of its partitions'.
fn collect_mount_points(
    connection: &Connection,
    disk_path: &OwnedObjectPath,
    partition_paths: &[OwnedObjectPath],
) -> Vec<String> {
    merge_mount_points(
        std::iter::once(disk_path)
            .chain(partition_paths)
            .map(|path| filesystem_mount_points(connection, path)),
    )
}

// The raw Filesystem.MountPoints of one Block object. An object without a
// Filesystem interface (no filesystem on it) has none; that, like a failed
// property read, is not an error here.
fn filesystem_mount_points(connection: &Connection, object_path: &OwnedObjectPath) -> Vec<Vec<u8>> {
    let filesystem = match Proxy::new(
        connection,
        "org.freedesktop.UDisks2",
        object_path.as_str(),
        "org.freedesktop.UDisks2.Filesystem",
    ) {
        Ok(proxy) => proxy,
        Err(_) => return Vec::new(),
    };

    filesystem.get_property("MountPoints").unwrap_or_default()
}

// Decodes and merges raw MountPoints lists into one sorted list without
// empty entries or duplicates (the same path can be reported more than
// once, e.g. by filesystems stacked on one mount point).
fn merge_mount_points(lists: impl IntoIterator<Item = Vec<Vec<u8>>>) -> Vec<String> {
    let mut mount_points = Vec::new();

    for points in lists {
        for point in points {
            let point = bytes_to_string(&point);

            if !point.is_empty() && !mount_points.contains(&point) {
                mount_points.push(point);
            }
        }
    }

    mount_points.sort();
    mount_points
}

fn block_device_name(
    connection: &Connection,
    object_path: &OwnedObjectPath,
) -> Option<String> {
    let block = Proxy::new(
        connection,
        "org.freedesktop.UDisks2",
        object_path.as_str(),
        "org.freedesktop.UDisks2.Block",
    )
    .ok()?;

    let device: Vec<u8> = block.get_property("Device").ok()?;

    Some(bytes_to_string(&device))
}

fn read_active_swaps() -> Vec<String> {
    let contents = match fs::read_to_string("/proc/swaps") {
        Ok(contents) => contents,
        Err(_) => return Vec::new(),
    };

    contents
        .lines()
        .skip(1)
        .filter_map(|line| line.split_whitespace().next())
        .map(str::to_string)
        .collect()
}

fn collect_swap_devices(
    connection: &Connection,
    disk_device: &str,
    partition_paths: &[OwnedObjectPath],
    active_swaps: &[String],
) -> Vec<String> {
    let mut related_devices = vec![disk_device.to_string()];

    for partition_path in partition_paths {
        if let Some(device) =
            block_device_name(connection, partition_path)
        {
            related_devices.push(device);
        }
    }

    active_swaps
        .iter()
        .filter(|swap| related_devices.contains(swap))
        .cloned()
        .collect()
}

fn inspect_complex_storage(
    connection: &Connection,
    object_path: &OwnedObjectPath,
) -> Vec<String> {
    let block = match Proxy::new(
        connection,
        "org.freedesktop.UDisks2",
        object_path.as_str(),
        "org.freedesktop.UDisks2.Block",
    ) {
        Ok(proxy) => proxy,
        Err(_) => return Vec::new(),
    };

    let device: Vec<u8> =
        block.get_property("Device").unwrap_or_default();

    let device_name = bytes_to_string(&device);

    let id_usage: String =
        block.get_property("IdUsage").unwrap_or_default();

    let id_type: String =
        block.get_property("IdType").unwrap_or_default();

    let mdraid_path: OwnedObjectPath =
        block.get_property("MDRaid")
            .unwrap_or_else(|_| OwnedObjectPath::try_from("/").unwrap());

    let mdraid_member_path: OwnedObjectPath =
        block.get_property("MDRaidMember")
            .unwrap_or_else(|_| OwnedObjectPath::try_from("/").unwrap());

    let crypto_backing_path: OwnedObjectPath =
        block.get_property("CryptoBackingDevice")
            .unwrap_or_else(|_| OwnedObjectPath::try_from("/").unwrap());

    let mut details = Vec::new();

    if id_usage == "crypto" {
        details.push(format!("{device_name}: IdUsage=crypto"));
    }

    if matches!(
        id_type.as_str(),
        "crypto_LUKS"
            | "LVM2_member"
            | "linux_raid_member"
    ) {
        details.push(format!("{device_name}: IdType={id_type}"));
    }

    if mdraid_path.as_str() != "/" {
        details.push(format!(
            "{device_name}: MD RAID={mdraid_path}"
        ));
    }

    if mdraid_member_path.as_str() != "/" {
        details.push(format!(
            "{device_name}: RAID member={mdraid_member_path}"
        ));
    }

    if crypto_backing_path.as_str() != "/" {
        details.push(format!(
            "{device_name}: Crypto backing={crypto_backing_path}"
        ));
    }

    details
}

fn collect_complex_storage_details(
    connection: &Connection,
    disk_path: &OwnedObjectPath,
    partition_paths: &[OwnedObjectPath],
) -> Vec<String> {
    let mut details =
        inspect_complex_storage(connection, disk_path);

    for partition_path in partition_paths {
        details.extend(
            inspect_complex_storage(connection, partition_path)
        );
    }

    details
}

// Builds a single DeviceSnapshot for one Block object path, or Ok(None) if
// that object is a partition (not a whole disk) or has no Drive. Shared by
// both the full-fleet collection and the single-target refresh so the two
// never drift apart.
fn build_snapshot_for_path(
    connection: &Connection,
    device_path: &OwnedObjectPath,
    active_swaps: &[String],
) -> zbus::Result<Option<DeviceSnapshot>> {
    let block = Proxy::new(
        connection,
        "org.freedesktop.UDisks2",
        device_path.as_str(),
        "org.freedesktop.UDisks2.Block",
    )?;

    let device: Vec<u8> = block.get_property("Device")?;
    let size: u64 = block.get_property("Size")?;
    let read_only: bool = block.get_property("ReadOnly")?;
    let drive_path: OwnedObjectPath =
        block.get_property("Drive")?;
    let device_number: u64 =
        block.get_property("DeviceNumber")?;
    let (major, minor) = decode_device_number(device_number);

    let hint_system: bool =
        block.get_property("HintSystem")?;
    let hint_ignore: bool =
        block.get_property("HintIgnore")?;
    let hint_partitionable: bool =
        block.get_property("HintPartitionable")?;

    let device_name = bytes_to_string(&device);
    let diskseq = read_diskseq(&device_name);

    let partition = Proxy::new(
        connection,
        "org.freedesktop.UDisks2",
        device_path.as_str(),
        "org.freedesktop.UDisks2.Partition",
    )?;

    let partition_number: Option<u32> =
        partition.get_property("Number").ok();

    if partition_number.is_some() || drive_path.as_str() == "/" {
        return Ok(None);
    }

    let drive = Proxy::new(
        connection,
        "org.freedesktop.UDisks2",
        drive_path.as_str(),
        "org.freedesktop.UDisks2.Drive",
    )?;

    let model: String = drive.get_property("Model")?;
    let vendor: String = drive.get_property("Vendor")?;
    let serial: String = drive.get_property("Serial")?;
    let connection_bus: String =
        drive.get_property("ConnectionBus")?;
    let removable: bool =
        drive.get_property("Removable")?;
    let media_available: bool =
        drive.get_property("MediaAvailable")?;

    let partition_paths =
        get_partition_paths(connection, device_path);

    let mount_points =
        collect_mount_points(connection, device_path, &partition_paths);

    let swap_devices = collect_swap_devices(
        connection,
        &device_name,
        &partition_paths,
        active_swaps,
    );

    let active_swap = !swap_devices.is_empty();

    let complex_storage_details =
        collect_complex_storage_details(
            connection,
            device_path,
            &partition_paths,
        );

    let complex_storage =
        !complex_storage_details.is_empty();

    Ok(Some(DeviceSnapshot {
        device: device_name,
        block_path: device_path.as_str().to_string(),
        drive_path: drive_path.as_str().to_string(),
        major,
        minor,
        diskseq,
        size,
        read_only,
        media_available,
        model,
        vendor,
        serial,
        connection_bus,
        removable,
        hint_system,
        hint_ignore,
        hint_partitionable,
        mount_points,
        active_swap,
        swap_devices,
        complex_storage,
        complex_storage_details,
    }))
}

// Returns true if a zbus error indicates the D-Bus object simply doesn't
// exist (rather than some other, unexpected failure). UDisks2's GDBus-based
// service has been observed (see reports/latest.md) to report a missing
// object as `org.freedesktop.DBus.Error.UnknownMethod` with a "does not
// exist" description, in addition to the more conventional UnknownObject.
fn is_object_missing_error(error: &zbus::Error) -> bool {
    let zbus::Error::MethodError(name, description, _) = error else {
        return false;
    };

    let description = description.as_deref().unwrap_or("");

    name.as_str() == "org.freedesktop.DBus.Error.UnknownObject"
        || (name.as_str() == "org.freedesktop.DBus.Error.UnknownMethod"
            && description.contains("does not exist"))
}

pub fn collect_device_snapshots() -> zbus::Result<Vec<DeviceSnapshot>> {
    let connection = Connection::system()?;

    let manager = Proxy::new(
        &connection,
        "org.freedesktop.UDisks2",
        "/org/freedesktop/UDisks2/Manager",
        "org.freedesktop.UDisks2.Manager",
    )?;

    let options: HashMap<String, OwnedValue> = HashMap::new();

    let devices: Vec<OwnedObjectPath> =
        manager.call("GetBlockDevices", &(options,))?;

    let active_swaps = read_active_swaps();
    let mut snapshots = Vec::new();

    for device_path in devices {
        if let Some(snapshot) =
            build_snapshot_for_path(&connection, &device_path, &active_swaps)?
        {
            snapshots.push(snapshot);
        }
    }

    Ok(snapshots)
}

// Re-fetches exactly one target's DeviceSnapshot by its UDisks2 Block object
// path, without touching or being affected by any other device. Intended for
// Selection Continuity's targeted re-verification (Core layer), so a race or
// failure on an unrelated device can never disturb the selected target's
// re-check. Collection only: this function makes no Selection judgement — it
// just reports whether the target was found, is gone, or the query failed.
pub fn collect_device_snapshot(block_path: &str) -> SnapshotFetchOutcome {
    let connection = match Connection::system() {
        Ok(connection) => connection,
        Err(error) => return SnapshotFetchOutcome::Error(error.to_string()),
    };

    let device_path = match OwnedObjectPath::try_from(block_path) {
        Ok(path) => path,
        Err(error) => return SnapshotFetchOutcome::Error(error.to_string()),
    };

    let active_swaps = read_active_swaps();

    match build_snapshot_for_path(&connection, &device_path, &active_swaps) {
        Ok(Some(snapshot)) => SnapshotFetchOutcome::Found(snapshot),
        Ok(None) => SnapshotFetchOutcome::NotFound,
        Err(error) if is_object_missing_error(&error) => {
            SnapshotFetchOutcome::NotFound
        }
        Err(error) => SnapshotFetchOutcome::Error(error.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::safety::{RiskLevel, RiskReason, assess_device};

    // Filesystem.MountPoints entries as UDisks2 reports them: NUL-terminated
    // byte strings.
    fn points(paths: &[&str]) -> Vec<Vec<u8>> {
        paths
            .iter()
            .map(|path| {
                let mut bytes = path.as_bytes().to_vec();
                bytes.push(0);
                bytes
            })
            .collect()
    }

    // A removable USB disk the Safety Engine would allow writing to, apart
    // from the mount points under test.
    fn usb_disk_with_mounts(mount_points: Vec<String>) -> DeviceSnapshot {
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
            mount_points,
            active_swap: false,
            swap_devices: Vec::new(),
            complex_storage: false,
            complex_storage_details: Vec::new(),
        }
    }

    fn refused_as_mounted(mount_points: Vec<String>) -> bool {
        let assessment = assess_device(&usb_disk_with_mounts(mount_points));
        !assessment.writable
            && matches!(assessment.risk_level, RiskLevel::Caution)
            && assessment
                .reasons
                .iter()
                .any(|reason| matches!(reason, RiskReason::MountedFilesystem))
    }

    // The lists `collect_mount_points` merges, in its order: the disk's own
    // first, then each partition's.
    fn merged(disk: Vec<Vec<u8>>, partitions: Vec<Vec<Vec<u8>>>) -> Vec<String> {
        merge_mount_points(std::iter::once(disk).chain(partitions))
    }

    // 1. A filesystem on the disk itself, no partitions: its mount is
    // collected, and the Safety Engine refuses the disk as mounted.
    #[test]
    fn a_mount_of_the_disk_itself_is_collected() {
        let mount_points = merged(points(&["/media/test"]), Vec::new());

        assert_eq!(mount_points, ["/media/test"]);
        assert!(refused_as_mounted(mount_points));
    }

    // 2. A mounted partition, the disk itself unmounted: collected as before.
    #[test]
    fn a_mount_of_a_partition_is_collected() {
        let mount_points = merged(Vec::new(), vec![points(&["/media/partition"]), Vec::new()]);

        assert_eq!(mount_points, ["/media/partition"]);
        assert!(refused_as_mounted(mount_points));
    }

    // 3. Both the disk and a partition mounted: both are collected.
    #[test]
    fn mounts_of_the_disk_and_its_partitions_are_all_collected() {
        let mount_points = merged(
            points(&["/media/disk"]),
            vec![points(&["/media/partition", "/mnt/second"])],
        );

        assert_eq!(
            mount_points,
            ["/media/disk", "/media/partition", "/mnt/second"]
        );
        assert!(refused_as_mounted(mount_points));
    }

    // 4. No filesystem anywhere (no Filesystem interface on the disk, no
    // partitions): no mount points, and nothing is refused for being mounted.
    #[test]
    fn no_filesystem_means_no_mount_points() {
        let mount_points = merged(Vec::new(), Vec::new());

        assert!(mount_points.is_empty());
        assert!(!refused_as_mounted(mount_points.clone()));
        assert!(assess_device(&usb_disk_with_mounts(mount_points)).writable);
    }

    // 5. The same path reported more than once (by the disk and a partition,
    // or twice by one object) appears once; empty entries are dropped; the
    // result is sorted.
    #[test]
    fn duplicate_and_empty_mount_points_are_merged_away() {
        let mount_points = merged(
            points(&["/media/same", ""]),
            vec![points(&["/media/same", "/media/other", "/media/other"])],
        );

        assert_eq!(mount_points, ["/media/other", "/media/same"]);
    }
}
