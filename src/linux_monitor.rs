use std::{
    collections::{HashMap, HashSet},
    sync::mpsc::{self, Receiver, Sender},
    thread,
};

use zbus::{
    blocking::{Connection, Proxy},
    zvariant::{OwnedObjectPath, OwnedValue},
};

use crate::linux_backend::collect_device_snapshots;

#[derive(Debug, Clone)]
pub struct PropertyChange {
    pub name: String,
    pub value: String,
    pub as_bool: Option<bool>,
}

#[derive(Debug, Clone)]
pub enum DeviceEvent {
    InterfacesAdded {
        object_path: String,
        interfaces: Vec<String>,
    },
    InterfacesRemoved {
        object_path: String,
        interfaces: Vec<String>,
    },
    PropertiesChanged {
        object_path: String,
        interface: String,
        changed: Vec<PropertyChange>,
        invalidated: Vec<String>,
    },
    WatcherFailed {
        object_path: String,
        reason: String,
    },
}

impl DeviceEvent {
    // The UDisks2 object path this event is about. Used by the Core layer to
    // decide whether an event is relevant to the currently selected target.
    pub fn object_path(&self) -> &str {
        match self {
            DeviceEvent::InterfacesAdded { object_path, .. }
            | DeviceEvent::InterfacesRemoved { object_path, .. }
            | DeviceEvent::PropertiesChanged { object_path, .. }
            | DeviceEvent::WatcherFailed { object_path, .. } => object_path,
        }
    }
}

fn build_property_changes(
    changed_properties: HashMap<String, OwnedValue>,
) -> Vec<PropertyChange> {
    changed_properties
        .into_iter()
        .map(|(name, value)| {
            let as_bool = bool::try_from(&*value).ok();

            PropertyChange {
                name,
                value: format!("{value:?}"),
                as_bool,
            }
        })
        .collect()
}

fn spawn_object_manager_watcher(
    connection: &Connection,
    signal_name: &'static str,
    sender: Sender<DeviceEvent>,
) {
    let connection = connection.clone();

    thread::spawn(move || {
        let proxy = match Proxy::new(
            &connection,
            "org.freedesktop.UDisks2",
            "/org/freedesktop/UDisks2",
            "org.freedesktop.DBus.ObjectManager",
        ) {
            Ok(proxy) => proxy,
            Err(error) => {
                let _ = sender.send(DeviceEvent::WatcherFailed {
                    object_path: "/org/freedesktop/UDisks2".to_string(),
                    reason: format!("{signal_name} proxy setup failed: {error}"),
                });
                return;
            }
        };

        let signals = match proxy.receive_signal(signal_name) {
            Ok(signals) => signals,
            Err(error) => {
                let _ = sender.send(DeviceEvent::WatcherFailed {
                    object_path: "/org/freedesktop/UDisks2".to_string(),
                    reason: format!("{signal_name} subscription failed: {error}"),
                });
                return;
            }
        };

        for message in signals {
            let event = if signal_name == "InterfacesAdded" {
                message
                    .body()
                    .deserialize::<(
                        OwnedObjectPath,
                        HashMap<String, HashMap<String, OwnedValue>>,
                    )>()
                    .ok()
                    .map(|(path, interfaces)| DeviceEvent::InterfacesAdded {
                        object_path: path.as_str().to_string(),
                        interfaces: interfaces.into_keys().collect(),
                    })
            } else {
                message
                    .body()
                    .deserialize::<(OwnedObjectPath, Vec<String>)>()
                    .ok()
                    .map(|(path, interfaces)| DeviceEvent::InterfacesRemoved {
                        object_path: path.as_str().to_string(),
                        interfaces,
                    })
            };

            if let Some(event) = event {
                if sender.send(event).is_err() {
                    break;
                }
            }
        }
    });
}

fn spawn_properties_watcher(
    connection: &Connection,
    object_path: String,
    sender: Sender<DeviceEvent>,
) {
    let connection = connection.clone();

    thread::spawn(move || {
        let proxy = match Proxy::new(
            &connection,
            "org.freedesktop.UDisks2",
            object_path.as_str(),
            "org.freedesktop.DBus.Properties",
        ) {
            Ok(proxy) => proxy,
            Err(error) => {
                let _ = sender.send(DeviceEvent::WatcherFailed {
                    object_path: object_path.clone(),
                    reason: format!("properties proxy setup failed: {error}"),
                });
                return;
            }
        };

        let signals = match proxy.receive_signal("PropertiesChanged") {
            Ok(signals) => signals,
            Err(error) => {
                let _ = sender.send(DeviceEvent::WatcherFailed {
                    object_path: object_path.clone(),
                    reason: format!("PropertiesChanged subscription failed: {error}"),
                });
                return;
            }
        };

        for message in signals {
            let parsed = message
                .body()
                .deserialize::<(String, HashMap<String, OwnedValue>, Vec<String>)>();

            let Ok((interface, changed_properties, invalidated)) = parsed else {
                continue;
            };

            let event = DeviceEvent::PropertiesChanged {
                object_path: object_path.clone(),
                interface,
                changed: build_property_changes(changed_properties),
                invalidated,
            };

            if sender.send(event).is_err() {
                break;
            }
        }
    });
}

// Starts a read-only, best-effort watch of UDisks2's ObjectManager
// (InterfacesAdded/InterfacesRemoved) and of PropertiesChanged on every
// Drive/Block object known at start time. This module only observes and
// structures D-Bus signals into `DeviceEvent`s; it makes no Identity,
// Instance, or Selection judgement — that stays in `identity.rs` / the
// (future) Core layer.
pub fn start_monitoring() -> zbus::Result<Receiver<DeviceEvent>> {
    let connection = Connection::system()?;
    let snapshots = collect_device_snapshots()?;

    let mut watch_paths: HashSet<String> = HashSet::new();

    for snapshot in &snapshots {
        watch_paths.insert(snapshot.block_path.clone());

        if snapshot.drive_path != "/" {
            watch_paths.insert(snapshot.drive_path.clone());
        }
    }

    let (sender, receiver) = mpsc::channel();

    spawn_object_manager_watcher(&connection, "InterfacesAdded", sender.clone());
    spawn_object_manager_watcher(&connection, "InterfacesRemoved", sender.clone());

    for path in watch_paths {
        spawn_properties_watcher(&connection, path, sender.clone());
    }

    Ok(receiver)
}

#[cfg(test)]
mod tests {
    use super::*;
    use zbus::zvariant::Value;

    #[test]
    fn build_property_changes_formats_every_entry() {
        let mut properties = HashMap::new();
        properties.insert(
            "MediaAvailable".to_string(),
            OwnedValue::try_from(Value::from(false)).unwrap(),
        );
        properties.insert(
            "Size".to_string(),
            OwnedValue::try_from(Value::from(0u64)).unwrap(),
        );

        let mut changes = build_property_changes(properties);
        changes.sort_by(|a, b| a.name.cmp(&b.name));

        assert_eq!(changes.len(), 2);
        assert_eq!(changes[0].name, "MediaAvailable");
        assert_eq!(changes[0].value, "OwnedValue(Bool(false))");
        assert_eq!(changes[0].as_bool, Some(false));
        assert_eq!(changes[1].name, "Size");
        assert_eq!(changes[1].value, "OwnedValue(U64(0))");
        assert_eq!(changes[1].as_bool, None);
    }

    #[test]
    fn build_property_changes_on_empty_map_is_empty() {
        let changes = build_property_changes(HashMap::new());

        assert!(changes.is_empty());
    }
}
