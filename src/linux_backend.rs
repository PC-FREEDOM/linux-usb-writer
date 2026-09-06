use std::{
    collections::HashMap,
    fs,
};

use zbus::{
    blocking::{Connection, Proxy},
    zvariant::{OwnedObjectPath, OwnedValue},
};

use crate::device::DeviceSnapshot;

fn bytes_to_string(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes)
        .trim_end_matches('\0')
        .to_string()
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

fn collect_mount_points(
    connection: &Connection,
    partition_paths: &[OwnedObjectPath],
) -> Vec<String> {
    let mut mount_points = Vec::new();

    for partition_path in partition_paths {
        let filesystem = match Proxy::new(
            connection,
            "org.freedesktop.UDisks2",
            partition_path.as_str(),
            "org.freedesktop.UDisks2.Filesystem",
        ) {
            Ok(proxy) => proxy,
            Err(_) => continue,
        };

        let points: Vec<Vec<u8>> =
            match filesystem.get_property("MountPoints") {
                Ok(points) => points,
                Err(_) => continue,
            };

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
        let block = Proxy::new(
            &connection,
            "org.freedesktop.UDisks2",
            device_path.as_str(),
            "org.freedesktop.UDisks2.Block",
        )?;

        let device: Vec<u8> = block.get_property("Device")?;
        let size: u64 = block.get_property("Size")?;
        let read_only: bool = block.get_property("ReadOnly")?;
        let drive_path: OwnedObjectPath =
            block.get_property("Drive")?;

        let hint_system: bool =
            block.get_property("HintSystem")?;
        let hint_ignore: bool =
            block.get_property("HintIgnore")?;
        let hint_partitionable: bool =
            block.get_property("HintPartitionable")?;

        let device_name = bytes_to_string(&device);

        let partition = Proxy::new(
            &connection,
            "org.freedesktop.UDisks2",
            device_path.as_str(),
            "org.freedesktop.UDisks2.Partition",
        )?;

        let partition_number: Option<u32> =
            partition.get_property("Number").ok();

        if partition_number.is_some() || drive_path.as_str() == "/" {
            continue;
        }

        let drive = Proxy::new(
            &connection,
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
            get_partition_paths(&connection, &device_path);

        let mount_points =
            collect_mount_points(&connection, &partition_paths);

        let swap_devices = collect_swap_devices(
            &connection,
            &device_name,
            &partition_paths,
            &active_swaps,
        );

        let active_swap = !swap_devices.is_empty();

        let complex_storage_details =
            collect_complex_storage_details(
                &connection,
                &device_path,
                &partition_paths,
            );

        let complex_storage =
            !complex_storage_details.is_empty();

        snapshots.push(DeviceSnapshot {
            device: device_name,
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
        });
    }

    Ok(snapshots)
}