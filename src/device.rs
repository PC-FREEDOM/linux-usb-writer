#[derive(Debug)]
pub struct DeviceSnapshot {
    pub device: String,
    pub block_path: String,
    pub drive_path: String,
    pub major: u32,
    pub minor: u32,
    pub diskseq: Option<u64>,
    pub size: u64,
    pub read_only: bool,
    pub media_available: bool,
    pub model: String,
    pub vendor: String,
    pub serial: String,
    pub connection_bus: String,
    pub removable: bool,
    pub hint_system: bool,
    pub hint_ignore: bool,
    pub hint_partitionable: bool,
    pub mount_points: Vec<String>,
    pub active_swap: bool,
    pub swap_devices: Vec<String>,
    pub complex_storage: bool,
    pub complex_storage_details: Vec<String>,
}

// Outcome of a targeted, single-device re-fetch (see
// `linux_backend::collect_device_snapshot`). Kept here as a plain data type so
// the Core layer can consume it without depending on how it was collected.
#[derive(Debug)]
pub enum SnapshotFetchOutcome {
    Found(DeviceSnapshot),
    NotFound,
    Error(String),
}