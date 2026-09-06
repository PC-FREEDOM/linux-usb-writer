mod device;
mod identity;
mod linux_backend;
mod linux_monitor;
mod safety;

use identity::{compare_identity, compare_instance};
use linux_backend::collect_device_snapshots;
use linux_monitor::{start_monitoring, DeviceEvent};
use safety::assess_device;

fn main() -> zbus::Result<()> {
    if std::env::args().nth(1).as_deref() == Some("monitor") {
        return run_monitor();
    }

    let snapshots = collect_device_snapshots()?;

    println!("Safety assessments:");

    for snapshot in snapshots {
        let assessment = assess_device(&snapshot);

        println!();
        println!("Device:      {}", snapshot.device);
        println!(
            "Model:       {} {}",
            snapshot.vendor,
            snapshot.model
        );
        println!("Size:        {} bytes", snapshot.size);
        println!("Bus:         {}", snapshot.connection_bus);
        println!("Removable:   {}", snapshot.removable);
        println!("Media avail: {}", snapshot.media_available);
        println!("Serial:      {}", snapshot.serial);
        println!("Major:minor: {}:{}", snapshot.major, snapshot.minor);
        println!("Diskseq:     {:?}", snapshot.diskseq);
        println!("Block path:  {}", snapshot.block_path);
        println!("Drive path:  {}", snapshot.drive_path);

        if snapshot.mount_points.is_empty() {
            println!("Mounts:      none");
        } else {
            println!("Mounts:");

            for mount in &snapshot.mount_points {
                println!("  {mount}");
            }
        }

        if snapshot.active_swap {
            println!("Active swap:");

            for swap in &snapshot.swap_devices {
                println!("  {swap}");
            }
        } else {
            println!("Active swap: none");
        }

        if snapshot.complex_storage {
            println!("Complex storage:");

            for detail in &snapshot.complex_storage_details {
                println!("  {detail}");
            }
        } else {
            println!("Complex storage: none");
        }

        println!("Risk:        {:?}", assessment.risk_level);
        println!("Writable:    {}", assessment.writable);
        println!("Reasons:     {:?}", assessment.reasons);

        let identity_self_check = compare_identity(&snapshot, &snapshot);
        println!("Identity self-check: {identity_self_check:?}");

        let instance_self_check = compare_instance(&snapshot, &snapshot);
        println!("Instance self-check: {instance_self_check:?}");
    }

    Ok(())
}

// PoC mode: read-only observation of UDisks2 D-Bus signals (`cargo run --
// monitor`). Prints raw structured events and, on each event, a fresh
// DeviceSnapshot re-read so diskseq changes (not carried by any signal) can
// be observed as they happen. Runs until interrupted with Ctrl+C.
fn run_monitor() -> zbus::Result<()> {
    println!("Monitoring UDisks2 D-Bus signals (read-only). Press Ctrl+C to stop.");

    let events = start_monitoring()?;

    for event in events {
        match &event {
            DeviceEvent::InterfacesAdded {
                object_path,
                interfaces,
            } => {
                println!("\n[InterfacesAdded] {object_path}");
                println!("  interfaces: {interfaces:?}");
            }
            DeviceEvent::InterfacesRemoved {
                object_path,
                interfaces,
            } => {
                println!("\n[InterfacesRemoved] {object_path}");
                println!("  interfaces: {interfaces:?}");
            }
            DeviceEvent::PropertiesChanged {
                object_path,
                interface,
                changed,
                invalidated,
            } => {
                println!("\n[PropertiesChanged] {object_path} ({interface})");

                for change in changed {
                    println!("  {} = {}", change.name, change.value);
                }

                if !invalidated.is_empty() {
                    println!("  invalidated: {invalidated:?}");
                }
            }
            DeviceEvent::WatcherFailed {
                object_path,
                reason,
            } => {
                eprintln!("\n[WatcherFailed] {object_path}: {reason}");
            }
        }

        println!("  -- current diskseq (re-fetched DeviceSnapshot) --");

        match collect_device_snapshots() {
            Ok(snapshots) => {
                for snapshot in &snapshots {
                    println!(
                        "  {} diskseq={:?} media_available={} size={}",
                        snapshot.device,
                        snapshot.diskseq,
                        snapshot.media_available,
                        snapshot.size
                    );
                }
            }
            Err(error) => eprintln!("  snapshot refresh failed: {error}"),
        }
    }

    Ok(())
}