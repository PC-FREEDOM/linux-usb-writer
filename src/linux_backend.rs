use std::{collections::HashMap, fmt, fs, io};

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

// UDisks2's object tree as ObjectManager.GetManagedObjects returns it:
// object path -> interface name -> property name -> value. Every snapshot is
// built from one such tree, fetched in one call, so whether an object has an
// interface is read from the tree itself -- a missing key means the object
// really has no such interface -- instead of being inferred from a failed
// D-Bus call.
type Properties = HashMap<String, OwnedValue>;
type Interfaces = HashMap<String, Properties>;
type ManagedObjects = HashMap<String, Interfaces>;

const BLOCK: &str = "org.freedesktop.UDisks2.Block";
const DRIVE: &str = "org.freedesktop.UDisks2.Drive";
const FILESYSTEM: &str = "org.freedesktop.UDisks2.Filesystem";
const PARTITION: &str = "org.freedesktop.UDisks2.Partition";
const PARTITION_TABLE: &str = "org.freedesktop.UDisks2.PartitionTable";

// Why a snapshot could not be built. Each of these means information the
// Safety Engine needs could not be obtained, so no snapshot is produced:
// a failure is never turned into "no mounts", "no swap", or "no RAID".
#[derive(Debug)]
enum CollectionError {
    // GetManagedObjects itself failed.
    DBus(zbus::Error),
    // /proc/swaps could not be read.
    Swaps(io::Error),
    // An object the disk refers to (its drive, one of its partitions) is
    // not in the tree.
    MissingObject {
        path: String,
    },
    // An object lacks an interface it must have (a partition without Block,
    // a drive without Drive).
    MissingInterface {
        path: String,
        interface: &'static str,
    },
    // An interface the object has lacks a property it must carry.
    MissingProperty {
        path: String,
        interface: &'static str,
        property: &'static str,
    },
    // A property has a value of an unexpected type.
    InvalidProperty {
        path: String,
        interface: &'static str,
        property: &'static str,
    },
}

impl fmt::Display for CollectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CollectionError::DBus(error) => {
                write!(f, "could not read the UDisks2 object tree: {error}")
            }
            CollectionError::Swaps(error) => write!(f, "could not read /proc/swaps: {error}"),
            CollectionError::MissingObject { path } => {
                write!(f, "UDisks2 object {path} is missing")
            }
            CollectionError::MissingInterface { path, interface } => {
                write!(f, "UDisks2 object {path} has no {interface} interface")
            }
            CollectionError::MissingProperty {
                path,
                interface,
                property,
            } => write!(f, "UDisks2 object {path} has no {interface}.{property}"),
            CollectionError::InvalidProperty {
                path,
                interface,
                property,
            } => write!(
                f,
                "UDisks2 object {path} has an unexpected value for {interface}.{property}"
            ),
        }
    }
}

// One object of the tree, with the checked property accessors every read
// below goes through.
#[derive(Clone, Copy)]
struct Object<'a> {
    path: &'a str,
    interfaces: &'a Interfaces,
}

impl<'a> Object<'a> {
    fn find(objects: &'a ManagedObjects, path: &str) -> Result<Self, CollectionError> {
        objects
            .get_key_value(path)
            .map(|(path, interfaces)| Object { path, interfaces })
            .ok_or_else(|| CollectionError::MissingObject {
                path: path.to_string(),
            })
    }

    fn has(&self, interface: &str) -> bool {
        self.interfaces.contains_key(interface)
    }

    // A property of an interface the object must have.
    fn get<T: TryFrom<OwnedValue>>(
        &self,
        interface: &'static str,
        property: &'static str,
    ) -> Result<T, CollectionError> {
        let properties =
            self.interfaces
                .get(interface)
                .ok_or_else(|| CollectionError::MissingInterface {
                    path: self.path.to_string(),
                    interface,
                })?;

        let value = properties
            .get(property)
            .ok_or_else(|| CollectionError::MissingProperty {
                path: self.path.to_string(),
                interface,
                property,
            })?;

        let invalid = || CollectionError::InvalidProperty {
            path: self.path.to_string(),
            interface,
            property,
        };

        T::try_from(value.try_clone().map_err(|_| invalid())?).map_err(|_| invalid())
    }

    // A property of an interface the object may lack: None when the object
    // has no such interface, the property's value when it has.
    fn get_if_present<T: TryFrom<OwnedValue>>(
        &self,
        interface: &'static str,
        property: &'static str,
    ) -> Result<Option<T>, CollectionError> {
        if self.has(interface) {
            self.get(interface, property).map(Some)
        } else {
            Ok(None)
        }
    }
}

// The disk's children, from its PartitionTable. A disk without a partition
// table has none.
fn partition_objects<'a>(
    objects: &'a ManagedObjects,
    disk: Object<'a>,
) -> Result<Vec<Object<'a>>, CollectionError> {
    let paths: Vec<OwnedObjectPath> = disk
        .get_if_present(PARTITION_TABLE, "Partitions")?
        .unwrap_or_default();

    paths
        .iter()
        .map(|path| {
            let partition = Object::find(objects, path.as_str())?;

            if !partition.has(BLOCK) {
                return Err(CollectionError::MissingInterface {
                    path: partition.path.to_string(),
                    interface: BLOCK,
                });
            }

            Ok(partition)
        })
        .collect()
}

// The raw Filesystem.MountPoints of one Block object. An object without a
// Filesystem interface (no filesystem on it) has none.
fn filesystem_mount_points(object: Object<'_>) -> Result<Vec<Vec<u8>>, CollectionError> {
    Ok(object
        .get_if_present(FILESYSTEM, "MountPoints")?
        .unwrap_or_default())
}

// Every mount point of the disk: its own filesystem's (a disk with no
// partition table can carry a filesystem directly, e.g. a superfloppy or
// some written ISO images) and each of its partitions'.
fn collect_mount_points(
    disk: Object<'_>,
    partitions: &[Object<'_>],
) -> Result<Vec<String>, CollectionError> {
    let lists = std::iter::once(disk)
        .chain(partitions.iter().copied())
        .map(filesystem_mount_points)
        .collect::<Result<Vec<_>, _>>()?;

    Ok(merge_mount_points(lists))
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

fn block_device_name(object: Object<'_>) -> Result<String, CollectionError> {
    let device: Vec<u8> = object.get(BLOCK, "Device")?;

    Ok(bytes_to_string(&device))
}

// The device column of /proc/swaps (the header line skipped).
fn parse_active_swaps(contents: &str) -> Vec<String> {
    contents
        .lines()
        .skip(1)
        .filter_map(|line| line.split_whitespace().next())
        .map(str::to_string)
        .collect()
}

// Any failure to read /proc/swaps -- including its absence -- is an error,
// never "no active swap".
fn read_active_swaps() -> io::Result<Vec<String>> {
    fs::read_to_string("/proc/swaps").map(|contents| parse_active_swaps(&contents))
}

fn collect_swap_devices(
    disk: Object<'_>,
    partitions: &[Object<'_>],
    active_swaps: &[String],
) -> Result<Vec<String>, CollectionError> {
    let related_devices = std::iter::once(disk)
        .chain(partitions.iter().copied())
        .map(block_device_name)
        .collect::<Result<Vec<_>, _>>()?;

    Ok(active_swaps
        .iter()
        .filter(|swap| related_devices.contains(swap))
        .cloned()
        .collect())
}

fn inspect_complex_storage(object: Object<'_>) -> Result<Vec<String>, CollectionError> {
    let device_name = block_device_name(object)?;
    let id_usage: String = object.get(BLOCK, "IdUsage")?;
    let id_type: String = object.get(BLOCK, "IdType")?;
    let mdraid_path: OwnedObjectPath = object.get(BLOCK, "MDRaid")?;
    let mdraid_member_path: OwnedObjectPath = object.get(BLOCK, "MDRaidMember")?;
    let crypto_backing_path: OwnedObjectPath = object.get(BLOCK, "CryptoBackingDevice")?;

    let mut details = Vec::new();

    if id_usage == "crypto" {
        details.push(format!("{device_name}: IdUsage=crypto"));
    }

    if matches!(
        id_type.as_str(),
        "crypto_LUKS" | "LVM2_member" | "linux_raid_member"
    ) {
        details.push(format!("{device_name}: IdType={id_type}"));
    }

    // "/" is UDisks2's own value for "none" on these object-path properties.
    if mdraid_path.as_str() != "/" {
        details.push(format!("{device_name}: MD RAID={mdraid_path}"));
    }

    if mdraid_member_path.as_str() != "/" {
        details.push(format!("{device_name}: RAID member={mdraid_member_path}"));
    }

    if crypto_backing_path.as_str() != "/" {
        details.push(format!(
            "{device_name}: Crypto backing={crypto_backing_path}"
        ));
    }

    Ok(details)
}

fn collect_complex_storage_details(
    disk: Object<'_>,
    partitions: &[Object<'_>],
) -> Result<Vec<String>, CollectionError> {
    let mut details = Vec::new();

    for object in std::iter::once(disk).chain(partitions.iter().copied()) {
        details.extend(inspect_complex_storage(object)?);
    }

    Ok(details)
}

// Builds a single DeviceSnapshot for one Block object path, or Ok(None) if
// the path is not a whole disk with a Drive: not in the tree, not a Block
// object, a partition, or a block device without a drive. Shared by both
// the full-fleet collection and the single-target refresh so the two never
// drift apart. Pure apart from `read_diskseq`, which is passed in so tests
// need neither D-Bus nor sysfs.
fn snapshot_from_objects(
    objects: &ManagedObjects,
    device_path: &str,
    active_swaps: &[String],
    read_diskseq: &dyn Fn(&str) -> Option<u64>,
) -> Result<Option<DeviceSnapshot>, CollectionError> {
    let Ok(disk) = Object::find(objects, device_path) else {
        return Ok(None);
    };

    if !disk.has(BLOCK) {
        return Ok(None);
    }

    // A partition is recognised by its Partition interface. Its Number is
    // still checked, so a malformed Partition interface is an error rather
    // than something passed over.
    if disk.has(PARTITION) {
        let _number: u32 = disk.get(PARTITION, "Number")?;
        return Ok(None);
    }

    let drive_path: OwnedObjectPath = disk.get(BLOCK, "Drive")?;

    if drive_path.as_str() == "/" {
        return Ok(None);
    }

    let device: Vec<u8> = disk.get(BLOCK, "Device")?;
    let size: u64 = disk.get(BLOCK, "Size")?;
    let read_only: bool = disk.get(BLOCK, "ReadOnly")?;
    let device_number: u64 = disk.get(BLOCK, "DeviceNumber")?;
    let (major, minor) = decode_device_number(device_number);

    let hint_system: bool = disk.get(BLOCK, "HintSystem")?;
    let hint_ignore: bool = disk.get(BLOCK, "HintIgnore")?;
    let hint_partitionable: bool = disk.get(BLOCK, "HintPartitionable")?;

    let device_name = bytes_to_string(&device);
    let diskseq = read_diskseq(&device_name);

    let drive = Object::find(objects, drive_path.as_str())?;

    let model: String = drive.get(DRIVE, "Model")?;
    let vendor: String = drive.get(DRIVE, "Vendor")?;
    let serial: String = drive.get(DRIVE, "Serial")?;
    let connection_bus: String = drive.get(DRIVE, "ConnectionBus")?;
    let removable: bool = drive.get(DRIVE, "Removable")?;
    let media_available: bool = drive.get(DRIVE, "MediaAvailable")?;

    let partitions = partition_objects(objects, disk)?;

    let mount_points = collect_mount_points(disk, &partitions)?;

    let swap_devices = collect_swap_devices(disk, &partitions, active_swaps)?;

    let active_swap = !swap_devices.is_empty();

    let complex_storage_details = collect_complex_storage_details(disk, &partitions)?;

    let complex_storage = !complex_storage_details.is_empty();

    Ok(Some(DeviceSnapshot {
        device: device_name,
        block_path: device_path.to_string(),
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

// Every whole disk with a Drive in the tree, in object-path order. Any
// device whose information cannot be read fails the whole collection, as
// does an unreadable /proc/swaps.
fn snapshots_from_objects(
    objects: &ManagedObjects,
    active_swaps: io::Result<Vec<String>>,
    read_diskseq: &dyn Fn(&str) -> Option<u64>,
) -> Result<Vec<DeviceSnapshot>, CollectionError> {
    let active_swaps = active_swaps.map_err(CollectionError::Swaps)?;

    let mut paths: Vec<&String> = objects.keys().collect();
    paths.sort();

    let mut snapshots = Vec::new();

    for path in paths {
        if let Some(snapshot) = snapshot_from_objects(objects, path, &active_swaps, read_diskseq)? {
            snapshots.push(snapshot);
        }
    }

    Ok(snapshots)
}

// The outcome of a single-target refresh, from one fetched tree and one
// read of /proc/swaps. Either failing is an Error, never a snapshot built
// from partial information.
fn snapshot_outcome(
    objects: Result<ManagedObjects, CollectionError>,
    active_swaps: io::Result<Vec<String>>,
    device_path: &str,
    read_diskseq: &dyn Fn(&str) -> Option<u64>,
) -> SnapshotFetchOutcome {
    let result = objects.and_then(|objects| {
        let active_swaps = active_swaps.map_err(CollectionError::Swaps)?;
        snapshot_from_objects(&objects, device_path, &active_swaps, read_diskseq)
    });

    match result {
        Ok(Some(snapshot)) => SnapshotFetchOutcome::Found(snapshot),
        Ok(None) => SnapshotFetchOutcome::NotFound,
        Err(error) => SnapshotFetchOutcome::Error(error.to_string()),
    }
}

// One GetManagedObjects call on UDisks2's ObjectManager.
fn fetch_managed_objects(connection: &Connection) -> Result<ManagedObjects, CollectionError> {
    let manager = Proxy::new(
        connection,
        "org.freedesktop.UDisks2",
        "/org/freedesktop/UDisks2",
        "org.freedesktop.DBus.ObjectManager",
    )
    .map_err(CollectionError::DBus)?;

    let objects: HashMap<OwnedObjectPath, Interfaces> = manager
        .call("GetManagedObjects", &())
        .map_err(CollectionError::DBus)?;

    Ok(objects
        .into_iter()
        .map(|(path, interfaces)| (path.as_str().to_string(), interfaces))
        .collect())
}

pub fn collect_device_snapshots() -> zbus::Result<Vec<DeviceSnapshot>> {
    let connection = Connection::system()?;

    let objects = match fetch_managed_objects(&connection) {
        Ok(objects) => objects,
        Err(CollectionError::DBus(error)) => return Err(error),
        Err(error) => return Err(zbus::Error::Failure(error.to_string())),
    };

    snapshots_from_objects(&objects, read_active_swaps(), &read_diskseq)
        .map_err(|error| zbus::Error::Failure(error.to_string()))
}

// Re-fetches exactly one target's DeviceSnapshot by its UDisks2 Block object
// path. Intended for Selection Continuity's targeted re-verification (Core
// layer): only the target and the objects it refers to (its drive and
// partitions) are read from the tree, so a problem with an unrelated device
// can never disturb the selected target's re-check. Collection only: this
// function makes no Selection judgement — it just reports whether the target
// was found, is gone, or its information could not be read.
pub fn collect_device_snapshot(block_path: &str) -> SnapshotFetchOutcome {
    let connection = match Connection::system() {
        Ok(connection) => connection,
        Err(error) => return SnapshotFetchOutcome::Error(error.to_string()),
    };

    snapshot_outcome(
        fetch_managed_objects(&connection),
        read_active_swaps(),
        block_path,
        &read_diskseq,
    )
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

    // ---------------------------------------------------------------------
    // Snapshots built from a synthetic GetManagedObjects tree (no D-Bus).

    use zbus::zvariant::{ObjectPath, Value};

    const DISK: &str = "/org/freedesktop/UDisks2/block_devices/sdx";
    const DISK_DRIVE: &str = "/org/freedesktop/UDisks2/drives/Test_Model_TEST_SERIAL";

    fn value<'a>(value: impl Into<Value<'a>>) -> OwnedValue {
        OwnedValue::try_from(value.into()).expect("test value without file descriptors")
    }

    fn object_path(path: &str) -> OwnedValue {
        value(ObjectPath::try_from(path).expect("valid object path"))
    }

    fn nul_terminated(text: &str) -> Vec<u8> {
        let mut bytes = text.as_bytes().to_vec();
        bytes.push(0);
        bytes
    }

    fn block_interface(device: &str) -> Properties {
        HashMap::from([
            ("Device".to_string(), value(nul_terminated(device))),
            ("Size".to_string(), value(8_000_000_000u64)),
            ("ReadOnly".to_string(), value(false)),
            ("Drive".to_string(), object_path(DISK_DRIVE)),
            ("DeviceNumber".to_string(), value(8u64 << 8)),
            ("HintSystem".to_string(), value(false)),
            ("HintIgnore".to_string(), value(false)),
            ("HintPartitionable".to_string(), value(true)),
            ("IdUsage".to_string(), value("")),
            ("IdType".to_string(), value("")),
            ("MDRaid".to_string(), object_path("/")),
            ("MDRaidMember".to_string(), object_path("/")),
            ("CryptoBackingDevice".to_string(), object_path("/")),
        ])
    }

    // A removable USB disk with no partition table and no filesystem: the
    // Safety Engine would allow writing to it.
    fn usb_tree() -> ManagedObjects {
        let drive = HashMap::from([
            ("Model".to_string(), value("Test Model")),
            ("Vendor".to_string(), value("Test Vendor")),
            ("Serial".to_string(), value("TEST-SERIAL")),
            ("ConnectionBus".to_string(), value("usb")),
            ("Removable".to_string(), value(true)),
            ("MediaAvailable".to_string(), value(true)),
        ]);

        HashMap::from([
            (
                DISK.to_string(),
                HashMap::from([(BLOCK.to_string(), block_interface("/dev/sdx"))]),
            ),
            (
                DISK_DRIVE.to_string(),
                HashMap::from([(DRIVE.to_string(), drive)]),
            ),
        ])
    }

    fn partition_path(number: u32) -> String {
        format!("{DISK}{number}")
    }

    // Adds partition `number` to the disk: a Block + Partition object, listed
    // in the disk's PartitionTable (created if needed).
    fn add_partition(tree: &mut ManagedObjects, number: u32) {
        let path = partition_path(number);
        let mut block = block_interface(&format!("/dev/sdx{number}"));
        block.insert("HintPartitionable".to_string(), value(false));

        tree.insert(
            path.clone(),
            HashMap::from([
                (BLOCK.to_string(), block),
                (
                    PARTITION.to_string(),
                    HashMap::from([("Number".to_string(), value(number))]),
                ),
            ]),
        );

        let disk = tree.get_mut(DISK).unwrap();
        let listed: Vec<String> = disk
            .get(PARTITION_TABLE)
            .map(|table| {
                let paths: Vec<OwnedObjectPath> =
                    table["Partitions"].try_clone().unwrap().try_into().unwrap();
                paths.iter().map(|path| path.as_str().to_string()).collect()
            })
            .unwrap_or_default();
        let paths: Vec<ObjectPath<'_>> = listed
            .iter()
            .map(String::as_str)
            .chain(std::iter::once(path.as_str()))
            .map(|path| ObjectPath::try_from(path).unwrap())
            .collect();
        disk.insert(
            PARTITION_TABLE.to_string(),
            HashMap::from([("Partitions".to_string(), value(paths))]),
        );
    }

    fn set(tree: &mut ManagedObjects, path: &str, interface: &str, property: &str, to: OwnedValue) {
        tree.get_mut(path)
            .unwrap()
            .entry(interface.to_string())
            .or_default()
            .insert(property.to_string(), to);
    }

    fn remove(tree: &mut ManagedObjects, path: &str, interface: &str, property: &str) {
        tree.get_mut(path)
            .unwrap()
            .get_mut(interface)
            .unwrap()
            .remove(property);
    }

    fn mount(tree: &mut ManagedObjects, path: &str, mount_points: &[&str]) {
        set(
            tree,
            path,
            FILESYSTEM,
            "MountPoints",
            value(points(mount_points)),
        );
    }

    fn fixed_diskseq(_device: &str) -> Option<u64> {
        Some(12)
    }

    fn build_with_swaps(
        tree: &ManagedObjects,
        active_swaps: &[&str],
    ) -> Result<Option<DeviceSnapshot>, CollectionError> {
        let active_swaps: Vec<String> = active_swaps.iter().map(|swap| swap.to_string()).collect();
        snapshot_from_objects(tree, DISK, &active_swaps, &fixed_diskseq)
    }

    fn build(tree: &ManagedObjects) -> Result<Option<DeviceSnapshot>, CollectionError> {
        build_with_swaps(tree, &[])
    }

    fn built(tree: &ManagedObjects) -> DeviceSnapshot {
        build(tree)
            .expect("snapshot should be built")
            .expect("the disk is a whole disk with a drive")
    }

    fn is_missing_property(result: Result<Option<DeviceSnapshot>, CollectionError>) -> bool {
        matches!(result, Err(CollectionError::MissingProperty { .. }))
    }

    fn is_invalid_property(result: Result<Option<DeviceSnapshot>, CollectionError>) -> bool {
        matches!(result, Err(CollectionError::InvalidProperty { .. }))
    }

    fn refused(snapshot: &DeviceSnapshot) -> bool {
        let assessment = assess_device(snapshot);
        !assessment.writable && !matches!(assessment.risk_level, RiskLevel::Normal)
    }

    // The fixture itself: a complete, well-formed tree builds a snapshot the
    // Safety Engine allows, with every field read from the tree.
    #[test]
    fn a_well_formed_tree_builds_the_expected_snapshot() {
        let snapshot = built(&usb_tree());

        assert_eq!(snapshot.device, "/dev/sdx");
        assert_eq!(snapshot.block_path, DISK);
        assert_eq!(snapshot.drive_path, DISK_DRIVE);
        assert_eq!((snapshot.major, snapshot.minor), (8, 0));
        assert_eq!(snapshot.diskseq, Some(12));
        assert_eq!(snapshot.size, 8_000_000_000);
        assert_eq!(snapshot.serial, "TEST-SERIAL");
        assert_eq!(snapshot.connection_bus, "usb");
        assert!(snapshot.removable && snapshot.media_available && snapshot.hint_partitionable);
        assert!(snapshot.mount_points.is_empty());
        assert!(!snapshot.active_swap && !snapshot.complex_storage);
        assert!(assess_device(&snapshot).writable);
    }

    // T1 (A). No Filesystem interface anywhere: no mount points, and that is
    // not an error.
    #[test]
    fn tree_without_filesystem_interface_has_no_mount_points() {
        let snapshot = built(&usb_tree());

        assert!(snapshot.mount_points.is_empty());
    }

    // T2 (B). A Filesystem interface with an empty MountPoints: unmounted.
    #[test]
    fn tree_filesystem_with_empty_mount_points_is_unmounted() {
        let mut tree = usb_tree();
        mount(&mut tree, DISK, &[]);

        let snapshot = built(&tree);

        assert!(snapshot.mount_points.is_empty());
        assert!(assess_device(&snapshot).writable);
    }

    // T3 / T13. The disk's own filesystem mounted (whole-disk mount): the
    // mount is collected and the disk is refused.
    #[test]
    fn tree_whole_disk_mount_is_collected_and_refused() {
        let mut tree = usb_tree();
        mount(&mut tree, DISK, &["/media/disk"]);

        let snapshot = built(&tree);

        assert_eq!(snapshot.mount_points, ["/media/disk"]);
        assert!(refused_as_mounted(snapshot.mount_points));
    }

    // T4 (C). A Filesystem interface without MountPoints is an error, not
    // "unmounted" -- on the disk or on a partition.
    #[test]
    fn tree_filesystem_without_mount_points_is_an_error() {
        let mut tree = usb_tree();
        set(&mut tree, DISK, FILESYSTEM, "Size", value(1u64));
        assert!(is_missing_property(build(&tree)));

        let mut tree = usb_tree();
        add_partition(&mut tree, 1);
        set(
            &mut tree,
            &partition_path(1),
            FILESYSTEM,
            "Size",
            value(1u64),
        );
        assert!(is_missing_property(build(&tree)));
    }

    // T5 (C). MountPoints of the wrong type is an error.
    #[test]
    fn tree_mount_points_of_the_wrong_type_are_an_error() {
        let mut tree = usb_tree();
        set(
            &mut tree,
            DISK,
            FILESYSTEM,
            "MountPoints",
            value("/media/disk"),
        );

        assert!(is_invalid_property(build(&tree)));
    }

    // T6 (A). No PartitionTable interface: no partitions, and that is not an
    // error.
    #[test]
    fn tree_without_partition_table_has_no_partitions() {
        let snapshot = built(&usb_tree());

        assert!(snapshot.mount_points.is_empty());
        assert!(snapshot.complex_storage_details.is_empty());
    }

    // T7 (B). A PartitionTable with an empty Partitions list is fine.
    #[test]
    fn tree_partition_table_with_no_partitions_is_fine() {
        let mut tree = usb_tree();
        set(
            &mut tree,
            DISK,
            PARTITION_TABLE,
            "Partitions",
            value(Vec::<ObjectPath<'_>>::new()),
        );

        let snapshot = built(&tree);

        assert!(snapshot.mount_points.is_empty());
        assert!(assess_device(&snapshot).writable);
    }

    // T8 (C). A PartitionTable whose Partitions is missing or of the wrong
    // type, or that lists a partition missing from the tree or lacking a
    // Block interface, is an error: the partitions' mounts could not be
    // checked.
    #[test]
    fn tree_unreadable_partition_list_is_an_error() {
        let mut tree = usb_tree();
        set(&mut tree, DISK, PARTITION_TABLE, "Type", value("gpt"));
        assert!(is_missing_property(build(&tree)));

        let mut tree = usb_tree();
        set(
            &mut tree,
            DISK,
            PARTITION_TABLE,
            "Partitions",
            value("not a list"),
        );
        assert!(is_invalid_property(build(&tree)));

        let mut tree = usb_tree();
        add_partition(&mut tree, 1);
        tree.remove(&partition_path(1));
        assert!(matches!(
            build(&tree),
            Err(CollectionError::MissingObject { .. })
        ));

        let mut tree = usb_tree();
        add_partition(&mut tree, 1);
        tree.get_mut(&partition_path(1)).unwrap().remove(BLOCK);
        assert!(matches!(
            build(&tree),
            Err(CollectionError::MissingInterface { .. })
        ));
    }

    // T9. A partition is recognised by its Partition interface and is not a
    // whole disk; a Partition interface without a valid Number is an error,
    // never a whole disk.
    #[test]
    fn tree_partition_objects_are_not_whole_disks_and_must_be_well_formed() {
        let mut tree = usb_tree();
        add_partition(&mut tree, 1);
        let path = partition_path(1);
        let active_swaps = Vec::new();

        assert!(matches!(
            snapshot_from_objects(&tree, &path, &active_swaps, &fixed_diskseq),
            Ok(None)
        ));

        remove(&mut tree, &path, PARTITION, "Number");
        assert!(matches!(
            snapshot_from_objects(&tree, &path, &active_swaps, &fixed_diskseq),
            Err(CollectionError::MissingProperty { .. })
        ));

        set(&mut tree, &path, PARTITION, "Number", value("1"));
        assert!(matches!(
            snapshot_from_objects(&tree, &path, &active_swaps, &fixed_diskseq),
            Err(CollectionError::InvalidProperty { .. })
        ));
    }

    // T10 (C). IdUsage / IdType missing or of the wrong type, on the disk or
    // on a partition, is an error -- never an empty string.
    #[test]
    fn tree_unreadable_id_usage_or_id_type_is_an_error() {
        for property in ["IdUsage", "IdType"] {
            for path in [DISK.to_string(), partition_path(1)] {
                let mut tree = usb_tree();
                add_partition(&mut tree, 1);
                remove(&mut tree, &path, BLOCK, property);
                assert!(is_missing_property(build(&tree)), "{property} on {path}");

                let mut tree = usb_tree();
                add_partition(&mut tree, 1);
                set(&mut tree, &path, BLOCK, property, value(true));
                assert!(is_invalid_property(build(&tree)), "{property} on {path}");
            }
        }
    }

    // T11 (C). MDRaid / MDRaidMember / CryptoBackingDevice missing or of the
    // wrong type is an error -- never "/".
    #[test]
    fn tree_unreadable_raid_or_crypto_links_are_an_error() {
        for property in ["MDRaid", "MDRaidMember", "CryptoBackingDevice"] {
            for path in [DISK.to_string(), partition_path(1)] {
                let mut tree = usb_tree();
                add_partition(&mut tree, 1);
                remove(&mut tree, &path, BLOCK, property);
                assert!(is_missing_property(build(&tree)), "{property} on {path}");

                let mut tree = usb_tree();
                add_partition(&mut tree, 1);
                set(&mut tree, &path, BLOCK, property, value("/"));
                assert!(is_invalid_property(build(&tree)), "{property} on {path}");
            }
        }
    }

    // Other required Block / Drive properties: missing -> error, and a
    // drive object missing from the tree -> error.
    #[test]
    fn tree_unreadable_block_or_drive_information_is_an_error() {
        for property in [
            "Device",
            "Size",
            "ReadOnly",
            "Drive",
            "DeviceNumber",
            "HintSystem",
            "HintIgnore",
            "HintPartitionable",
        ] {
            let mut tree = usb_tree();
            remove(&mut tree, DISK, BLOCK, property);
            assert!(is_missing_property(build(&tree)), "Block.{property}");
        }

        for property in [
            "Model",
            "Vendor",
            "Serial",
            "ConnectionBus",
            "Removable",
            "MediaAvailable",
        ] {
            let mut tree = usb_tree();
            remove(&mut tree, DISK_DRIVE, DRIVE, property);
            assert!(is_missing_property(build(&tree)), "Drive.{property}");
        }

        let mut tree = usb_tree();
        tree.remove(DISK_DRIVE);
        assert!(matches!(
            build(&tree),
            Err(CollectionError::MissingObject { .. })
        ));

        // A partition's Device (needed to match it against /proc/swaps).
        let mut tree = usb_tree();
        add_partition(&mut tree, 1);
        remove(&mut tree, &partition_path(1), BLOCK, "Device");
        assert!(is_missing_property(build(&tree)));
    }

    // Paths that are not a whole disk with a drive are passed over: not in
    // the tree, not a Block object, or a block device without a drive.
    #[test]
    fn tree_paths_that_are_not_whole_disks_are_passed_over() {
        let tree = usb_tree();
        let active_swaps = Vec::new();

        assert!(matches!(
            snapshot_from_objects(
                &tree,
                "/org/freedesktop/UDisks2/block_devices/nope",
                &active_swaps,
                &fixed_diskseq
            ),
            Ok(None)
        ));
        assert!(matches!(
            snapshot_from_objects(&tree, DISK_DRIVE, &active_swaps, &fixed_diskseq),
            Ok(None)
        ));

        let mut tree = usb_tree();
        set(&mut tree, DISK, BLOCK, "Drive", object_path("/"));
        assert!(matches!(build(&tree), Ok(None)));
    }

    // T12 (C). /proc/swaps unreadable -> Error for a single target and for
    // the whole list, never "no active swap".
    #[test]
    fn unreadable_swaps_is_an_error() {
        let tree = usb_tree();
        let unreadable = || Err(io::Error::from(io::ErrorKind::NotFound));

        assert!(matches!(
            snapshot_outcome(Ok(tree.clone()), unreadable(), DISK, &fixed_diskseq),
            SnapshotFetchOutcome::Error(_)
        ));
        assert!(matches!(
            snapshots_from_objects(&tree, unreadable(), &fixed_diskseq),
            Err(CollectionError::Swaps(_))
        ));
    }

    // The outcome of a single-target refresh: found, not found, or -- when
    // the object tree could not be fetched or is malformed -- an Error.
    #[test]
    fn snapshot_outcome_reports_found_not_found_and_errors() {
        let tree = usb_tree();

        assert!(matches!(
            snapshot_outcome(Ok(tree.clone()), Ok(Vec::new()), DISK, &fixed_diskseq),
            SnapshotFetchOutcome::Found(_)
        ));
        assert!(matches!(
            snapshot_outcome(
                Ok(tree.clone()),
                Ok(Vec::new()),
                "/org/freedesktop/UDisks2/block_devices/nope",
                &fixed_diskseq
            ),
            SnapshotFetchOutcome::NotFound
        ));
        assert!(matches!(
            snapshot_outcome(
                Err(CollectionError::DBus(zbus::Error::Failure(
                    "simulated".to_string()
                ))),
                Ok(Vec::new()),
                DISK,
                &fixed_diskseq
            ),
            SnapshotFetchOutcome::Error(_)
        ));

        let mut malformed = usb_tree();
        set(&mut malformed, DISK, FILESYSTEM, "Size", value(1u64));
        assert!(matches!(
            snapshot_outcome(Ok(malformed), Ok(Vec::new()), DISK, &fixed_diskseq),
            SnapshotFetchOutcome::Error(_)
        ));
    }

    // The full list fails as a whole when any device cannot be read; a
    // well-formed tree yields its whole disks only (partitions and devices
    // without a drive are passed over).
    #[test]
    fn device_list_is_whole_disks_only_and_fails_as_a_whole() {
        let mut tree = usb_tree();
        add_partition(&mut tree, 1);

        let snapshots = snapshots_from_objects(&tree, Ok(Vec::new()), &fixed_diskseq).unwrap();
        assert_eq!(snapshots.len(), 1);
        assert_eq!(snapshots[0].block_path, DISK);

        set(
            &mut tree,
            &partition_path(1),
            FILESYSTEM,
            "Size",
            value(1u64),
        );
        assert!(snapshots_from_objects(&tree, Ok(Vec::new()), &fixed_diskseq).is_err());
    }

    // T14. A mounted partition, the disk itself unmounted: collected.
    #[test]
    fn tree_partition_mount_is_collected_and_refused() {
        let mut tree = usb_tree();
        add_partition(&mut tree, 1);
        add_partition(&mut tree, 2);
        mount(&mut tree, &partition_path(2), &["/media/partition"]);

        let snapshot = built(&tree);

        assert_eq!(snapshot.mount_points, ["/media/partition"]);
        assert!(refused_as_mounted(snapshot.mount_points));
    }

    // T15. The disk and a partition both mounted: both collected.
    #[test]
    fn tree_disk_and_partition_mounts_are_all_collected() {
        let mut tree = usb_tree();
        add_partition(&mut tree, 1);
        mount(&mut tree, DISK, &["/media/disk"]);
        mount(
            &mut tree,
            &partition_path(1),
            &["/media/partition", "/mnt/second"],
        );

        let snapshot = built(&tree);

        assert_eq!(
            snapshot.mount_points,
            ["/media/disk", "/media/partition", "/mnt/second"]
        );
        assert!(refused_as_mounted(snapshot.mount_points));
    }

    // T16. Duplicate and empty entries are merged away, sorted.
    #[test]
    fn tree_duplicate_and_empty_mount_points_are_merged_away() {
        let mut tree = usb_tree();
        add_partition(&mut tree, 1);
        mount(&mut tree, DISK, &["/media/same", ""]);
        mount(
            &mut tree,
            &partition_path(1),
            &["/media/same", "/media/other", "/media/other"],
        );

        let snapshot = built(&tree);

        assert_eq!(snapshot.mount_points, ["/media/other", "/media/same"]);
    }

    // T17. Every complex-storage hazard is still detected, on the disk or on
    // a partition, and the disk is refused.
    #[test]
    fn tree_complex_storage_is_still_detected() {
        let hazards: [(&str, OwnedValue, &str); 7] = [
            ("IdUsage", value("crypto"), "IdUsage=crypto"),
            ("IdType", value("crypto_LUKS"), "IdType=crypto_LUKS"),
            ("IdType", value("LVM2_member"), "IdType=LVM2_member"),
            (
                "IdType",
                value("linux_raid_member"),
                "IdType=linux_raid_member",
            ),
            (
                "MDRaid",
                object_path("/org/freedesktop/UDisks2/mdraid/md0"),
                "MD RAID=",
            ),
            (
                "MDRaidMember",
                object_path("/org/freedesktop/UDisks2/mdraid/md0"),
                "RAID member=",
            ),
            (
                "CryptoBackingDevice",
                object_path("/org/freedesktop/UDisks2/block_devices/sdy1"),
                "Crypto backing=",
            ),
        ];

        for (property, hazard, detail) in hazards {
            for path in [DISK.to_string(), partition_path(1)] {
                let mut tree = usb_tree();
                add_partition(&mut tree, 1);
                set(
                    &mut tree,
                    &path,
                    BLOCK,
                    property,
                    hazard.try_clone().unwrap(),
                );

                let snapshot = built(&tree);

                assert!(snapshot.complex_storage, "{property} on {path}");
                assert!(
                    snapshot
                        .complex_storage_details
                        .iter()
                        .any(|found| found.contains(detail)),
                    "{property} on {path}: {:?}",
                    snapshot.complex_storage_details
                );
                assert!(refused(&snapshot), "{property} on {path}");
            }
        }
    }

    // Swap on the disk or on a partition is still detected (by matching the
    // Block.Device of each against /proc/swaps), and the disk is refused.
    #[test]
    fn tree_active_swap_is_still_detected() {
        for swap in ["/dev/sdx", "/dev/sdx1"] {
            let mut tree = usb_tree();
            add_partition(&mut tree, 1);

            let snapshot = build_with_swaps(&tree, &["/dev/other", swap])
                .unwrap()
                .unwrap();

            assert!(snapshot.active_swap, "{swap}");
            assert_eq!(snapshot.swap_devices, [swap]);
            assert!(refused(&snapshot), "{swap}");
        }

        let mut tree = usb_tree();
        add_partition(&mut tree, 1);
        let snapshot = build_with_swaps(&tree, &["/dev/other"]).unwrap().unwrap();
        assert!(!snapshot.active_swap);
    }

    // /proc/swaps parsing: the header is skipped, the device column kept.
    #[test]
    fn active_swaps_are_parsed_from_the_device_column() {
        let contents = "Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n\
                        /dev/zram0                              partition\t8388604\t\t0\t\t100\n\
                        /swapfile                               file\t\t1048572\t\t0\t\t-2\n";

        assert_eq!(parse_active_swaps(contents), ["/dev/zram0", "/swapfile"]);
        assert!(parse_active_swaps("Filename Type Size Used Priority\n").is_empty());
    }

    // T18. A refresh that fails to read the target's information reaches the
    // Core layer as an Error: the Selection is invalidated and the write gate
    // refuses to open -- no stale snapshot is used in its place.
    #[test]
    fn unreadable_refresh_invalidates_the_selection_and_blocks_the_gate() {
        use crate::execution::core::{
            self, ConfirmationToken, ImageSelection, InvalidationReason, SelectionState,
            VerifyMode, WriteGateError, WriteIntent,
        };

        let mut malformed = usb_tree();
        set(&mut malformed, DISK, FILESYSTEM, "Size", value(1u64));
        let failed_refresh =
            || snapshot_outcome(Ok(malformed.clone()), Ok(Vec::new()), DISK, &fixed_diskseq);

        let state = core::select(built(&usb_tree())).expect("selectable");
        let image = ImageSelection::new(1_000_000);
        let token = ConfirmationToken::confirm(
            WriteIntent::from_selection(&state, image, VerifyMode::None).unwrap(),
        );

        let gate = core::prepare_for_open(
            &state,
            failed_refresh(),
            image,
            VerifyMode::None,
            Some(&token),
        );
        assert!(matches!(gate, Err(WriteGateError::SnapshotRefreshFailed)));

        let state = core::revalidate(state, failed_refresh());
        assert!(matches!(
            state,
            SelectionState::Invalidated {
                reason: InvalidationReason::SnapshotRefreshFailed,
                ..
            }
        ));
    }
}
