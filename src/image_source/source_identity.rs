// Source identity: detecting that a selected image file was changed after
// it was opened.
//
// When an image is opened, a snapshot of the open file's metadata is taken
// (device, inode, size, modification time, status-change time). At later
// checkpoints -- in particular immediately before the first byte is written
// to the target -- the same open file's metadata is read again and must
// still match exactly; otherwise the source is treated as changed and the
// operation stops.
//
// What this is for: ordinary changes made after selection by other
// processes -- a download still in progress, a re-download or copy
// overwriting the file, an editor or sync tool, a plain write, truncate or
// append. Any of those advance the status-change time (`ctime`), which an
// unprivileged process cannot set back, and most also change the size or
// modification time.
//
// What this is not: a content hash, a file snapshot, or tamper protection.
// It does not detect changes that leave this metadata untouched -- further
// writes through an already-dirty shared memory mapping (these do not
// advance `ctime`), privileged manipulation (clock changes, writing to the
// underlying block device), or filesystems whose timestamps are unreliable
// (e.g. cached network attributes, some FUSE filesystems). Nor can it stop a
// change: a change made after one checkpoint is only seen at the next one.
//
// Everything here reads metadata from an already-open `File` (`fstat`),
// never from a path, so it always describes the very file being read.
//
// Two separate guarantees apply to a selected image, and this module only
// provides the second:
//
//   - Same open file: the image is always read from the file that was
//     opened at selection, never re-opened by path, so renaming, deleting
//     or replacing the path can never make a different file be read (see
//     `FileImageSource`).
//   - Unchanged since selection (this module): the open file's metadata
//     must still be exactly as recorded at selection. On Linux, renaming,
//     unlinking or hard-linking the file also updates its status-change
//     time, so moving, deleting or replacing the selected file is reported
//     as a change too -- even though the original content is still what
//     would be read.
//
// A reported change never claims a cause: metadata alone cannot tell a
// rename from an in-place rewrite, so no attempt is made to.

use std::fmt;
use std::fs::{File, Metadata};
use std::io;
use std::os::unix::fs::MetadataExt;

// A file timestamp exactly as the kernel reports it: whole seconds (signed,
// may be negative for dates before 1970) plus the nanosecond part. Kept as
// the two raw values rather than folded into one number, so no value is
// ever truncated, wrapped or rounded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileTimestamp {
    seconds: i64,
    nanoseconds: i64,
}

impl FileTimestamp {
    fn new(seconds: i64, nanoseconds: i64) -> Self {
        FileTimestamp {
            seconds,
            nanoseconds,
        }
    }
}

// The metadata snapshot of an open image file. Two snapshots of the same,
// unchanged file are equal; any difference in any field means the file is
// no longer in the state it was selected in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceIdentity {
    // Device and inode: fixed for an open file; compared anyway, as an
    // invariant check and for diagnostics.
    dev: u64,
    ino: u64,
    size: u64,
    modified: FileTimestamp,
    status_changed: FileTimestamp,
}

impl SourceIdentity {
    // Builds a snapshot from metadata already obtained from an open file.
    pub(super) fn from_metadata(metadata: &Metadata) -> Self {
        SourceIdentity {
            dev: metadata.dev(),
            ino: metadata.ino(),
            size: metadata.size(),
            modified: FileTimestamp::new(metadata.mtime(), metadata.mtime_nsec()),
            status_changed: FileTimestamp::new(metadata.ctime(), metadata.ctime_nsec()),
        }
    }

    // Reads the open file's metadata again and confirms it still matches
    // this snapshot. One `fstat`; no path, no data read, no allocation.
    pub(super) fn revalidate(&self, file: &File) -> Result<(), SourceChanged> {
        let current = file.metadata().map_err(SourceChanged::Unverifiable)?;
        compare(*self, SourceIdentity::from_metadata(&current))
    }
}

fn compare(expected: SourceIdentity, actual: SourceIdentity) -> Result<(), SourceChanged> {
    if expected == actual {
        Ok(())
    } else {
        Err(SourceChanged::Metadata { expected, actual })
    }
}

// The source can no longer be treated as the file that was selected. This
// does not mean its content is necessarily different -- only that its
// metadata changed since it was opened (or could not be read again), so it
// is not safe to keep treating it as the same source. Selecting the image
// again starts over with a fresh snapshot.
#[derive(Debug)]
pub enum SourceChanged {
    // The metadata differs from the snapshot taken when the image was
    // opened.
    Metadata {
        expected: SourceIdentity,
        actual: SourceIdentity,
    },
    // The open file's metadata could not be read again, so the source
    // cannot be confirmed unchanged.
    Unverifiable(io::Error),
}

impl fmt::Display for SourceChanged {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SourceChanged::Metadata { expected, actual } => write!(
                f,
                "the image file changed after it was selected (expected {expected:?}, found {actual:?})"
            ),
            SourceChanged::Unverifiable(error) => write!(
                f,
                "the image file could not be confirmed unchanged since it was selected: {error}"
            ),
        }
    }
}

impl std::error::Error for SourceChanged {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;
    use std::os::unix::fs::FileExt as _;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;

    fn identity(ino: u64, size: u64, mtime: (i64, i64), ctime: (i64, i64)) -> SourceIdentity {
        SourceIdentity {
            dev: 7,
            ino,
            size,
            modified: FileTimestamp::new(mtime.0, mtime.1),
            status_changed: FileTimestamp::new(ctime.0, ctime.1),
        }
    }

    fn temp_file(tag: &str, contents: &[u8]) -> PathBuf {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "linux-usb-writer-source-identity-{tag}-{}-{id}.img",
            std::process::id()
        ));
        std::fs::write(&path, contents).unwrap();
        path
    }

    // Opens `path` read-only (as `open_image` does) and snapshots it.
    fn open_and_snapshot(path: &PathBuf) -> (File, SourceIdentity) {
        let file = File::open(path).unwrap();
        let snapshot = SourceIdentity::from_metadata(&file.metadata().unwrap());
        (file, snapshot)
    }

    // Filesystems without fine-grained timestamps only advance them once per
    // clock tick; waiting a little before a change keeps these tests from
    // depending on that granularity.
    fn let_the_clock_tick() {
        std::thread::sleep(Duration::from_millis(20));
    }

    fn assert_changed(result: Result<(), SourceChanged>) -> (SourceIdentity, SourceIdentity) {
        match result {
            Err(SourceChanged::Metadata { expected, actual }) => (expected, actual),
            other => panic!("expected SourceChanged::Metadata, got {other:?}"),
        }
    }

    #[test]
    fn identical_snapshots_compare_equal() {
        let a = identity(1, 100, (10, 5), (10, 6));
        assert!(compare(a, a).is_ok());
    }

    #[test]
    fn every_field_takes_part_in_the_comparison() {
        let base = identity(1, 100, (10, 5), (10, 6));
        let variants = [
            SourceIdentity { dev: 8, ..base },
            SourceIdentity { ino: 2, ..base },
            SourceIdentity { size: 101, ..base },
            SourceIdentity { size: 99, ..base },
            SourceIdentity {
                modified: FileTimestamp::new(10, 7),
                ..base
            },
            SourceIdentity {
                modified: FileTimestamp::new(11, 5),
                ..base
            },
            SourceIdentity {
                status_changed: FileTimestamp::new(10, 7),
                ..base
            },
            SourceIdentity {
                status_changed: FileTimestamp::new(9, 6),
                ..base
            },
        ];

        for actual in variants {
            let (expected, got) = assert_changed(compare(base, actual));
            assert_eq!(expected, base);
            assert_eq!(got, actual);
        }
    }

    // Raw kernel values are kept verbatim, including negative and extreme
    // ones; a difference in the nanosecond part alone is still a difference.
    #[test]
    fn timestamps_keep_extreme_and_negative_values_exactly() {
        for (seconds, nanoseconds) in [
            (i64::MIN, 0),
            (-1, 999_999_999),
            (0, 0),
            (i64::MAX, 999_999_999),
        ] {
            let stamp = FileTimestamp::new(seconds, nanoseconds);
            assert_eq!(stamp.seconds, seconds);
            assert_eq!(stamp.nanoseconds, nanoseconds);
        }
        assert_ne!(
            FileTimestamp::new(i64::MAX, 999_999_998),
            FileTimestamp::new(i64::MAX, 999_999_999)
        );
        assert_ne!(FileTimestamp::new(-1, 0), FileTimestamp::new(1, 0));
    }

    // Revalidating an untouched file succeeds every time, and revalidating
    // does not itself change the metadata.
    #[test]
    fn unchanged_file_revalidates_repeatedly() {
        let path = temp_file("unchanged", b"image bytes");
        let (file, snapshot) = open_and_snapshot(&path);

        for _ in 0..5 {
            snapshot.revalidate(&file).unwrap();
        }
        assert_eq!(
            SourceIdentity::from_metadata(&file.metadata().unwrap()),
            snapshot
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn append_is_a_change() {
        let path = temp_file("append", b"image bytes");
        let (file, snapshot) = open_and_snapshot(&path);

        let_the_clock_tick();
        let mut appender = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        appender.write_all(b"more").unwrap();

        let (expected, actual) = assert_changed(snapshot.revalidate(&file));
        assert_eq!(actual.size, expected.size + 4);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn truncation_is_a_change() {
        let path = temp_file("truncate", b"image bytes");
        let (file, snapshot) = open_and_snapshot(&path);

        let_the_clock_tick();
        std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(3)
            .unwrap();

        let (_, actual) = assert_changed(snapshot.revalidate(&file));
        assert_eq!(actual.size, 3);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn same_size_overwrite_is_a_change() {
        let path = temp_file("overwrite", b"image bytes");
        let (file, snapshot) = open_and_snapshot(&path);

        let_the_clock_tick();
        let writer = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        writer.write_all_at(b"IMAGE", 0).unwrap();

        let (expected, actual) = assert_changed(snapshot.revalidate(&file));
        assert_eq!(actual.size, expected.size);
        assert_ne!(actual.status_changed, expected.status_changed);
        let _ = std::fs::remove_file(&path);
    }

    // Setting the modification time back after an overwrite does not hide
    // it: the status-change time still moved (and cannot be set back
    // without privileges).
    #[test]
    fn restoring_the_modification_time_does_not_hide_an_overwrite() {
        let path = temp_file("mtime-restore", b"image bytes");
        let (file, snapshot) = open_and_snapshot(&path);
        let original_mtime = file.metadata().unwrap().modified().unwrap();

        let_the_clock_tick();
        let writer = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        writer.write_all_at(b"IMAGE", 0).unwrap();
        writer.set_modified(original_mtime).unwrap();

        let (expected, actual) = assert_changed(snapshot.revalidate(&file));
        assert_eq!(actual.modified, expected.modified, "mtime was restored");
        assert_ne!(actual.status_changed, expected.status_changed);
        let _ = std::fs::remove_file(&path);
    }

    // Changing only the modification time (no content change) is still a
    // change: the snapshot is compared as a whole.
    #[test]
    fn modification_time_change_alone_is_a_change() {
        let path = temp_file("mtime-only", b"image bytes");
        let (file, snapshot) = open_and_snapshot(&path);

        let writer = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        writer
            .set_modified(std::time::SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000))
            .unwrap();

        let (expected, actual) = assert_changed(snapshot.revalidate(&file));
        assert_ne!(actual.modified, expected.modified);
        let _ = std::fs::remove_file(&path);
    }

    // Path operations on the selected file (rename, unlink, rename plus a
    // replacement at the old path, an extra hard link) update the open
    // file's status-change time on Linux, so each is reported as a change
    // -- without any attempt to say which operation it was.
    #[test]
    fn path_operations_on_the_selected_file_are_reported_as_changes() {
        type PathOperation = fn(&PathBuf);
        let operations: [(&str, PathOperation); 4] = [
            ("rename", |path| {
                std::fs::rename(path, path.with_extension("moved")).unwrap();
            }),
            ("unlink", |path| {
                std::fs::remove_file(path).unwrap();
            }),
            ("replace", |path| {
                std::fs::rename(path, path.with_extension("moved")).unwrap();
                std::fs::write(path, b"another file entirely").unwrap();
            }),
            ("hard-link", |path| {
                std::fs::hard_link(path, path.with_extension("link")).unwrap();
            }),
        ];

        for (name, operation) in operations {
            let path = temp_file(name, b"image bytes");
            let (file, snapshot) = open_and_snapshot(&path);

            let_the_clock_tick();
            operation(&path);

            let (expected, actual) = assert_changed(snapshot.revalidate(&file));
            assert_eq!(actual.ino, expected.ino, "{name}: still the same open file");
            assert_ne!(actual.status_changed, expected.status_changed, "{name}");

            for leftover in [
                path.clone(),
                path.with_extension("moved"),
                path.with_extension("link"),
            ] {
                let _ = std::fs::remove_file(leftover);
            }
        }
    }
}
