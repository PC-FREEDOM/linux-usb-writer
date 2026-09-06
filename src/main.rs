mod device;
mod linux_backend;
mod safety;

use linux_backend::collect_device_snapshots;
use safety::assess_device;

fn main() -> zbus::Result<()> {
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
    }

    Ok(())
}