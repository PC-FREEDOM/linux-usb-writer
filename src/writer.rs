// Writer Core. Deliberately Linux/UDisks2-agnostic: this module knows
// nothing about `DeviceSnapshot`, D-Bus, or the Safety Engine, and never
// decides *whether* a write should happen — only *how* to copy bytes from a
// readable source to a writable target once something else has already
// decided it's safe to do so. Connecting this to a real block device (via
// `linux_access.rs`'s OpenDevice FD) is a separate, later step.
//
// The source/target abstractions are deliberately just `std::io::Read` /
// `std::io::Write` rather than bespoke traits: a plain file and an in-memory
// `Cursor<Vec<u8>>` already implement them, and so will future decompressing
// readers (gzip/xz) and a block-device-backed writer — they only need to
// wrap or implement `Read`/`Write`, not conform to a writer-specific trait.

use std::io::{self, Read, Write};

// 1 MiB. Chosen as a reasonable default for chunked copying; not tuned for
// throughput (performance is explicitly out of scope for this PoC).
pub const DEFAULT_CHUNK_SIZE: usize = 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WritePlan {
    pub image_size: u64,
    pub target_size: u64,
    pub chunk_size: usize,
}

impl WritePlan {
    // Pure validation: no I/O, no side effects. `image_size`/`target_size`
    // must be supplied by the caller (e.g. from a source file's metadata and
    // a freshly re-verified DeviceSnapshot.size) — this function only checks
    // that the numbers make sense together.
    pub fn new(image_size: u64, target_size: u64, chunk_size: usize) -> Result<Self, WriteError> {
        if image_size == 0 || target_size == 0 {
            return Err(WriteError::InvalidSize);
        }

        if chunk_size == 0 {
            return Err(WriteError::InvalidChunkSize);
        }

        if image_size > target_size {
            return Err(WriteError::ImageTooLarge);
        }

        Ok(WritePlan {
            image_size,
            target_size,
            chunk_size,
        })
    }
}

#[derive(Debug, Clone, Copy)]
pub struct WriteProgress {
    pub bytes_written: u64,
    pub total_bytes: u64,
}

// Fields here are read via the derived Debug impl (for error reporting) and,
// for `Cancelled`, via destructuring in tests — rustc's dead-code lint
// doesn't count either as a use outside of a plain `cargo check` build.
#[allow(dead_code)]
#[derive(Debug)]
pub enum WriteError {
    InvalidSize,
    InvalidChunkSize,
    ImageTooLarge,
    SourceRead(io::Error),
    TargetWrite(io::Error),
    FlushFailed(io::Error),
    // The source ran out of data before `plan.image_size` bytes were read —
    // distinct from `SourceRead`, which is for an actual I/O error. This is
    // never treated as a successful, if-shorter-than-planned write.
    SourceTooShort { bytes_written: u64 },
    // Carries how much had already been written when cancellation was
    // observed, so the caller always knows the target is left partially
    // written rather than having to guess.
    Cancelled { bytes_written: u64 },
}

// Reads until `buf` is full or the source is exhausted, retrying on
// `Interrupted`. Unlike `Read::read_exact`, running out of input early is not
// an error here — it's reported as a short read (fewer bytes than `buf.len()`)
// so the caller can decide what that means.
fn read_fully<R: Read>(reader: &mut R, buf: &mut [u8]) -> io::Result<usize> {
    let mut total = 0;

    while total < buf.len() {
        match reader.read(&mut buf[total..]) {
            Ok(0) => break,
            Ok(n) => total += n,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }

    Ok(total)
}

// Copies exactly `plan.image_size` bytes from `source` to `target` in
// `plan.chunk_size` chunks, reporting progress after each chunk and checking
// `is_cancelled` before each one. Always flushes `target` on a full,
// uncancelled completion — but flushing here only means
// `std::io::Write::flush()` (pushing the writer's own buffers out), which is
// a different guarantee from an OS-level sync/fsync of a block device to
// physical media. A future block-device Writer must add its own explicit
// sync step; this function does not perform (or claim to perform) one, since
// today it is only ever used against plain files in tests/PoC code.
pub fn write<R: Read, W: Write>(
    plan: &WritePlan,
    mut source: R,
    mut target: W,
    mut on_progress: impl FnMut(WriteProgress),
    mut is_cancelled: impl FnMut() -> bool,
) -> Result<u64, WriteError> {
    // Defense in depth: even if a `WritePlan` were constructed some other
    // way than `WritePlan::new` (bypassing its validation), a zero-byte
    // image or a zero-sized chunk must never be silently accepted.
    if plan.image_size == 0 {
        return Err(WriteError::InvalidSize);
    }

    if plan.chunk_size == 0 {
        return Err(WriteError::InvalidChunkSize);
    }

    let mut buffer = vec![0u8; plan.chunk_size];
    let mut bytes_written: u64 = 0;

    while bytes_written < plan.image_size {
        if is_cancelled() {
            return Err(WriteError::Cancelled { bytes_written });
        }

        let remaining = plan.image_size - bytes_written;
        // Bounded by `remaining`, so this never asks to read (and therefore
        // never writes) past `plan.image_size`, no matter how much more data
        // `source` actually has available.
        let to_read = remaining.min(buffer.len() as u64) as usize;

        let read_bytes =
            read_fully(&mut source, &mut buffer[..to_read]).map_err(WriteError::SourceRead)?;

        if read_bytes == 0 {
            // The source ran out before reaching `plan.image_size`. Reporting
            // `Ok(bytes_written)` here would silently claim success for a
            // shorter-than-planned write, so this is an explicit error
            // instead — the caller still learns exactly how much was
            // written via `bytes_written`.
            return Err(WriteError::SourceTooShort { bytes_written });
        }

        target
            .write_all(&buffer[..read_bytes])
            .map_err(WriteError::TargetWrite)?;

        bytes_written += read_bytes as u64;

        on_progress(WriteProgress {
            bytes_written,
            total_bytes: plan.image_size,
        });
    }

    target.flush().map_err(WriteError::FlushFailed)?;

    Ok(bytes_written)
}

// Minimal verification primitive: compares two readers byte-for-byte.
// Intended to grow into distinct Quick Verify (e.g. sampled chunks or a
// hash) / Full Verify (this, exhaustive) / None policies later; today it
// only implements the exhaustive comparison.
pub fn verify_equal<A: Read, B: Read>(mut a: A, mut b: B) -> io::Result<bool> {
    let mut buf_a = [0u8; 8192];
    let mut buf_b = [0u8; 8192];

    loop {
        let n_a = read_fully(&mut a, &mut buf_a)?;
        let n_b = read_fully(&mut b, &mut buf_b)?;

        if n_a != n_b || buf_a[..n_a] != buf_b[..n_b] {
            return Ok(false);
        }

        if n_a == 0 {
            return Ok(true);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    struct FailingReader;

    impl Read for FailingReader {
        fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::other("simulated source read failure"))
        }
    }

    struct FailingWriter;

    impl Write for FailingWriter {
        fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
            Err(io::Error::other("simulated target write failure"))
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    struct FlushFailingWriter {
        inner: Vec<u8>,
    }

    impl Write for FlushFailingWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.inner.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::other("simulated flush failure"))
        }
    }

    // A. image < target -> plan created successfully.
    #[test]
    fn plan_allows_image_smaller_than_target() {
        assert!(WritePlan::new(10, 20, DEFAULT_CHUNK_SIZE).is_ok());
    }

    // B. image == target -> success.
    #[test]
    fn plan_allows_image_equal_to_target() {
        assert!(WritePlan::new(10, 10, DEFAULT_CHUNK_SIZE).is_ok());
    }

    // C. image > target -> ImageTooLarge.
    #[test]
    fn plan_rejects_image_larger_than_target() {
        assert!(matches!(
            WritePlan::new(20, 10, DEFAULT_CHUNK_SIZE),
            Err(WriteError::ImageTooLarge)
        ));
    }

    // D. image size 0 -> InvalidSize.
    #[test]
    fn plan_rejects_zero_image_size() {
        assert!(matches!(
            WritePlan::new(0, 10, DEFAULT_CHUNK_SIZE),
            Err(WriteError::InvalidSize)
        ));
    }

    // E. target size 0 -> InvalidSize.
    #[test]
    fn plan_rejects_zero_target_size() {
        assert!(matches!(
            WritePlan::new(10, 0, DEFAULT_CHUNK_SIZE),
            Err(WriteError::InvalidSize)
        ));
    }

    // F. small data -> all bytes written correctly.
    #[test]
    fn small_data_is_written_completely() {
        let data = b"hello world".to_vec();
        let plan = WritePlan::new(data.len() as u64, data.len() as u64, DEFAULT_CHUNK_SIZE)
            .unwrap();
        let source = Cursor::new(data.clone());
        let mut target = Vec::new();

        let written = write(&plan, source, &mut target, |_| {}, || false).unwrap();

        assert_eq!(written, data.len() as u64);
        assert_eq!(target, data);
    }

    // G. chunk size smaller than the data -> multiple chunks reconstruct it exactly.
    #[test]
    fn multiple_chunks_reconstruct_exact_data() {
        let data: Vec<u8> = (0..10_000u32).map(|i| (i % 256) as u8).collect();
        let plan = WritePlan::new(data.len() as u64, data.len() as u64, 1024).unwrap();
        let source = Cursor::new(data.clone());
        let mut target = Vec::new();

        let written = write(&plan, source, &mut target, |_| {}, || false).unwrap();

        assert_eq!(written, data.len() as u64);
        assert_eq!(target, data);
    }

    // H. progress -> bytes_written is monotonically increasing and ends at image_size.
    #[test]
    fn progress_is_monotonic_and_ends_at_image_size() {
        let data = vec![7u8; 5000];
        let plan = WritePlan::new(data.len() as u64, data.len() as u64, 1024).unwrap();
        let source = Cursor::new(data.clone());
        let mut target = Vec::new();
        let mut progress_log = Vec::new();

        write(
            &plan,
            source,
            &mut target,
            |progress| progress_log.push(progress.bytes_written),
            || false,
        )
        .unwrap();

        assert!(!progress_log.is_empty());
        assert!(progress_log.windows(2).all(|pair| pair[0] < pair[1]));
        assert_eq!(*progress_log.last().unwrap(), data.len() as u64);
    }

    // I. cancel -> stops early with Cancelled, fewer than image_size bytes written.
    #[test]
    fn cancellation_stops_before_completion() {
        let data = vec![1u8; 10_000];
        let plan = WritePlan::new(data.len() as u64, data.len() as u64, 1024).unwrap();
        let source = Cursor::new(data);
        let mut target = Vec::new();
        let mut checks = 0;

        let result = write(&plan, source, &mut target, |_| {}, || {
            checks += 1;
            checks > 2
        });

        match result {
            Err(WriteError::Cancelled { bytes_written }) => {
                assert!(bytes_written > 0);
                assert!(bytes_written < 10_000);
            }
            other => panic!("expected Cancelled, got {other:?}"),
        }
    }

    // J. source read error -> SourceRead.
    #[test]
    fn source_read_error_is_reported() {
        let plan = WritePlan::new(100, 100, 1024).unwrap();
        let mut target = Vec::new();

        let result = write(&plan, FailingReader, &mut target, |_| {}, || false);

        assert!(matches!(result, Err(WriteError::SourceRead(_))));
    }

    // K. target write error -> TargetWrite.
    #[test]
    fn target_write_error_is_reported() {
        let data = vec![1u8; 100];
        let plan = WritePlan::new(data.len() as u64, data.len() as u64, 1024).unwrap();
        let source = Cursor::new(data);

        let result = write(&plan, source, FailingWriter, |_| {}, || false);

        assert!(matches!(result, Err(WriteError::TargetWrite(_))));
    }

    // L. flush error -> FlushFailed.
    #[test]
    fn flush_error_is_reported() {
        let data = vec![1u8; 100];
        let plan = WritePlan::new(data.len() as u64, data.len() as u64, 1024).unwrap();
        let source = Cursor::new(data);
        let target = FlushFailingWriter { inner: Vec::new() };

        let result = write(&plan, source, target, |_| {}, || false);

        assert!(matches!(result, Err(WriteError::FlushFailed(_))));
    }

    // M. write then read-back matches the original exactly (via verify_equal).
    #[test]
    fn written_data_round_trips_via_verify_equal() {
        let data: Vec<u8> = (0..3000u32).map(|i| (i % 250) as u8).collect();
        let plan = WritePlan::new(data.len() as u64, data.len() as u64, 512).unwrap();
        let source = Cursor::new(data.clone());
        let mut target = Vec::new();

        write(&plan, source, &mut target, |_| {}, || false).unwrap();

        let matches = verify_equal(Cursor::new(data), Cursor::new(target)).unwrap();
        assert!(matches);
    }

    // N. A zero-byte plan must never be treated as a successful write, even
    // if something bypassed `WritePlan::new`'s own validation.
    #[test]
    fn zero_byte_plan_is_never_treated_as_a_successful_write() {
        let plan = WritePlan {
            image_size: 0,
            target_size: 10,
            chunk_size: DEFAULT_CHUNK_SIZE,
        };
        let source = Cursor::new(Vec::<u8>::new());
        let mut target = Vec::new();

        let result = write(&plan, source, &mut target, |_| {}, || false);

        assert!(matches!(result, Err(WriteError::InvalidSize)));
    }

    // O. chunk_size == 0 must never be accepted by WritePlan::new, and
    // write() itself refuses it defensively too (in case a plan bypassed
    // `new`), rather than silently coercing it to some fallback chunk size.
    #[test]
    fn chunk_size_zero_is_rejected() {
        assert!(matches!(
            WritePlan::new(10, 10, 0),
            Err(WriteError::InvalidChunkSize)
        ));

        let plan = WritePlan {
            image_size: 10,
            target_size: 10,
            chunk_size: 0,
        };
        let source = Cursor::new(vec![1u8; 10]);
        let mut target = Vec::new();

        let result = write(&plan, source, &mut target, |_| {}, || false);

        assert!(matches!(result, Err(WriteError::InvalidChunkSize)));
    }

    // P. A source that runs out before `image_size` bytes are read must be
    // reported as an explicit error, never as a successful, shorter write.
    // `bytes_written` in the error still tells the caller how far it got.
    #[test]
    fn source_shorter_than_planned_image_is_error() {
        let plan = WritePlan::new(8192, 8192, 1024).unwrap();
        let short_source = Cursor::new(vec![1u8; 4096]);
        let mut target = Vec::new();

        let result = write(&plan, short_source, &mut target, |_| {}, || false);

        match result {
            Err(WriteError::SourceTooShort { bytes_written }) => {
                assert_eq!(bytes_written, 4096);
            }
            other => panic!("expected SourceTooShort, got {other:?}"),
        }
    }

    // Q. A source longer than the plan's image_size must not cause the
    // writer to write past image_size — only the first `image_size` bytes
    // ever reach the target, regardless of how much more `source` has.
    #[test]
    fn source_longer_than_plan_does_not_write_past_image_size() {
        let full_data: Vec<u8> = (0..8192u32).map(|i| (i % 256) as u8).collect();
        let plan = WritePlan::new(4096, 4096, 1024).unwrap();
        let source = Cursor::new(full_data.clone());
        let mut target = Vec::new();

        let written = write(&plan, source, &mut target, |_| {}, || false).unwrap();

        assert_eq!(written, 4096);
        assert_eq!(target.len(), 4096);
        assert_eq!(target, full_data[..4096]);
    }
}
