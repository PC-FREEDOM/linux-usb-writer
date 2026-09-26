// Compressed image validation (Preflight). A `CompressedImageFile` (gzip or
// xz content, detected by `open_image`) is turned into a
// `PreflightedCompressedImage` only by decoding the whole compressed stream
// once, end to end: every member/stream, every integrity check, and every
// compressed byte must be accounted for, and the exact decompressed size is
// measured on the way. Nothing here writes anywhere or knows about targets;
// the decoded bytes are counted and discarded.
//
// Layering of the gzip decode pipeline (bottom to top):
//
//   source cursor    positional reads (`pread`) over the one `File` that
//                    `open_image` opened, starting at byte 0, clamped to the
//                    compressed size recorded at open time
//   BufReader        buffering for the syscalls
//   CountingBufRead  counts what the decoder actually `consume()`s, polls
//                    for cancellation before every `fill_buf()`, and tags any
//                    error from below as a source I/O error
//   MultiGzDecoder   every member, CRC32 + ISIZE per member, and any trailing
//                    bytes rejected (behavior pinned by `gzip_behavior` tests)
//
// Errors are classified by type, never by message text: cancellation and
// source I/O failures travel through the decoder as typed payloads
// (`PreflightCancelled` / `SourceReadError`), which `flate2` passes through
// unchanged (see `gzip_behavior::errors_from_below_the_decoder_propagate_
// unchanged`); anything else came from the decoder itself.

use std::cell::Cell;
use std::fmt;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use flate2::bufread::MultiGzDecoder;

use super::{CompressedImageFile, CompressionFormat, FileImageReader};

// Capacity of the `BufReader` above the source cursor: how much compressed
// data one positional read fetches.
const INPUT_BUFFER_LEN: usize = 256 * 1024;
// Size of the scratch buffer decoded output is read into and discarded.
const OUTPUT_BUFFER_LEN: usize = 1024 * 1024;
// Progress is reported whenever compressed input or decoded output has
// advanced by at least this much since the last report (and once more on
// success), so a huge image produces a bounded, steady stream of reports.
const PROGRESS_STEP: u64 = 1024 * 1024;

// Limits applied while validating. Chosen by the caller (e.g. from the
// selected target's capacity); this module never looks at targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PreflightOptions {
    // Decoding stops with `LogicalSizeLimitExceeded` as soon as the decoded
    // size would exceed this. A decoded size exactly equal to it is allowed.
    pub max_logical_size: u64,
}

// A snapshot of Preflight's progress.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PreflightProgress {
    // Compressed bytes the decoder has actually consumed (not merely read
    // ahead by a buffer).
    pub compressed_consumed: u64,
    // The compressed file's size, as recorded when it was opened.
    pub compressed_total: u64,
    // Decoded bytes produced so far.
    pub logical_produced: u64,
}

// Why Preflight rejected a compressed image.
#[derive(Debug)]
pub enum PreflightError {
    // The caller's cancellation check returned `true`.
    Cancelled,
    // The compressed data is damaged: an invalid header, corrupt compressed
    // data, a checksum/size mismatch, or bytes after the last valid member
    // (the decoder's own error is kept for diagnostics).
    Corrupt(io::Error),
    // The compressed data ended before a complete stream (the decoder's own
    // error is kept). Short trailing garbage after a valid member also
    // surfaces here: the decoder cannot tell it apart from a truncated next
    // member, and either way the image is rejected.
    Incomplete(io::Error),
    // The decoded size does not fit in a `u64`.
    LogicalSizeOverflow,
    // The decoded size exceeds `PreflightOptions::max_logical_size`.
    LogicalSizeLimitExceeded { limit: u64 },
    // The decoder reported a clean end of stream without having consumed
    // exactly the compressed file's size. Not expected from a correct
    // decoder; checked so a clean end is never trusted on its own.
    InputConsumptionMismatch { consumed: u64, compressed_size: u64 },
    // Reading the compressed file itself failed.
    Io(io::Error),
    // Validation for this compression format is not implemented yet.
    UnsupportedFormat(CompressionFormat),
}

// A compressed image whose whole stream has been decoded and validated.
// The only way to obtain one is `CompressedImageFile::preflight`, so holding
// one means validation succeeded -- there is no "not yet validated" state to
// confuse it with. Keeps the very file `open_image` opened (never re-opened
// by path) so later replays decode exactly the bytes that were validated.
#[derive(Debug)]
pub struct PreflightedCompressedImage {
    file: Arc<File>,
    path: PathBuf,
    format: CompressionFormat,
    compressed_size: u64,
    logical_size: u64,
}

impl PreflightedCompressedImage {
    pub fn format(&self) -> CompressionFormat {
        self.format
    }

    // For display only, like `FileImageSource::path()`.
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn compressed_size(&self) -> u64 {
        self.compressed_size
    }

    // The exact number of bytes the validated stream decodes to.
    pub fn logical_size(&self) -> u64 {
        self.logical_size
    }
}

impl CompressedImageFile {
    // Decodes the whole compressed stream once to validate it and measure
    // its decoded size, consuming this file handle into a
    // `PreflightedCompressedImage` on success.
    //
    // `is_cancelled` is polled before every read of compressed input -- so
    // cancellation works even while the input produces no output (e.g. a run
    // of empty gzip members). `on_progress` receives periodic snapshots and a
    // final one on success. Both are plain closures, borrowed for the
    // duration of this call only.
    //
    // Reads the file that `open_image` opened, from byte 0, with positional
    // reads: the path is never re-opened and the file's shared offset is
    // never used.
    pub fn preflight(
        self,
        options: PreflightOptions,
        mut is_cancelled: impl FnMut() -> bool,
        mut on_progress: impl FnMut(PreflightProgress),
    ) -> Result<PreflightedCompressedImage, PreflightError> {
        if self.format != CompressionFormat::Gzip {
            return Err(PreflightError::UnsupportedFormat(self.format));
        }

        let file = Arc::new(self.file);
        let input =
            BufReader::with_capacity(INPUT_BUFFER_LEN, source_cursor(&file, self.compressed_size));

        let logical_size = preflight_gzip(
            input,
            self.compressed_size,
            options,
            &mut is_cancelled,
            &mut on_progress,
        )?;

        Ok(PreflightedCompressedImage {
            file,
            path: self.path,
            format: self.format,
            compressed_size: self.compressed_size,
            logical_size,
        })
    }
}

// A fresh reader over `file` from byte 0 to `end` (the compressed size
// recorded at open time), using positional reads only. This is the same
// reader plain images use (`FileImageReader`): each call starts its own
// independent position, bytes past `end` are never read even if the file
// has since grown, and a shrunken file simply ends early.
fn source_cursor(file: &Arc<File>, end: u64) -> FileImageReader {
    FileImageReader {
        file: Arc::clone(file),
        position: 0,
        logical_size: end,
    }
}

// Validates a gzip stream read from `input` and returns its decoded size.
// Generic over the input so tests can inject source failures; production
// passes the buffered source cursor.
fn preflight_gzip(
    input: impl BufRead,
    compressed_size: u64,
    options: PreflightOptions,
    is_cancelled: &mut dyn FnMut() -> bool,
    on_progress: &mut dyn FnMut(PreflightProgress),
) -> Result<u64, PreflightError> {
    if is_cancelled() {
        return Err(PreflightError::Cancelled);
    }

    // Shared between the decode loop (which advances it) and the hook below
    // the decoder (which reports it).
    let logical_produced = Cell::new(0u64);

    let (decoded, consumed) = {
        let mut reporter = ProgressReporter::new(compressed_size);
        let hook = |consumed: u64| {
            reporter.maybe_report(consumed, logical_produced.get(), &mut *on_progress);
            is_cancelled()
        };

        let mut decoder = MultiGzDecoder::new(CountingBufRead::new(input, hook));
        let decoded = decode_to_end(&mut decoder, options, &logical_produced);
        (decoded, decoder.get_ref().consumed())
    };

    let logical_size = decoded?;

    if consumed != compressed_size {
        return Err(PreflightError::InputConsumptionMismatch {
            consumed,
            compressed_size,
        });
    }

    on_progress(PreflightProgress {
        compressed_consumed: consumed,
        compressed_total: compressed_size,
        logical_produced: logical_size,
    });

    Ok(logical_size)
}

// Reads `decoder` to its end, discarding the output while counting it into
// `logical_produced`. Returns the total on a clean end of stream.
fn decode_to_end(
    decoder: &mut impl Read,
    options: PreflightOptions,
    logical_produced: &Cell<u64>,
) -> Result<u64, PreflightError> {
    let mut buf = vec![0u8; OUTPUT_BUFFER_LEN];

    loop {
        let n = match decoder.read(&mut buf) {
            Ok(0) => return Ok(logical_produced.get()),
            Ok(n) => n,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(classify_error(error)),
        };

        let total = add_logical_bytes(logical_produced.get(), n, options.max_logical_size)?;
        logical_produced.set(total);
    }
}

// Adds `n` freshly decoded bytes to `current`, enforcing the `u64` range and
// the caller's limit (`== limit` allowed, `> limit` rejected).
fn add_logical_bytes(current: u64, n: usize, limit: u64) -> Result<u64, PreflightError> {
    let n = u64::try_from(n).map_err(|_| PreflightError::LogicalSizeOverflow)?;
    let total = current
        .checked_add(n)
        .ok_or(PreflightError::LogicalSizeOverflow)?;

    if total > limit {
        return Err(PreflightError::LogicalSizeLimitExceeded { limit });
    }

    Ok(total)
}

// Maps an error that came out of the decoder to a `PreflightError`: typed
// payloads injected below the decoder first (cancellation, source I/O),
// then the decoder's own errors by kind. Message text is never inspected.
fn classify_error(error: io::Error) -> PreflightError {
    if error
        .get_ref()
        .is_some_and(|inner| inner.is::<PreflightCancelled>())
    {
        return PreflightError::Cancelled;
    }

    if error
        .get_ref()
        .is_some_and(|inner| inner.is::<SourceReadError>())
    {
        let inner = error
            .into_inner()
            .expect("checked above: the error carries a payload");
        return match inner.downcast::<SourceReadError>() {
            Ok(source) => PreflightError::Io(source.0),
            Err(other) => PreflightError::Io(io::Error::other(other)),
        };
    }

    match error.kind() {
        io::ErrorKind::UnexpectedEof => PreflightError::Incomplete(error),
        _ => PreflightError::Corrupt(error),
    }
}

// Throttles progress reports: reports when input or output has advanced by
// `PROGRESS_STEP` since the previous report.
struct ProgressReporter {
    compressed_total: u64,
    last_consumed: u64,
    last_logical: u64,
}

impl ProgressReporter {
    fn new(compressed_total: u64) -> Self {
        ProgressReporter {
            compressed_total,
            last_consumed: 0,
            last_logical: 0,
        }
    }

    fn maybe_report(
        &mut self,
        consumed: u64,
        logical: u64,
        on_progress: &mut dyn FnMut(PreflightProgress),
    ) {
        let input_advanced = consumed.saturating_sub(self.last_consumed) >= PROGRESS_STEP;
        let output_advanced = logical.saturating_sub(self.last_logical) >= PROGRESS_STEP;

        if input_advanced || output_advanced {
            self.last_consumed = consumed;
            self.last_logical = logical;
            on_progress(PreflightProgress {
                compressed_consumed: consumed,
                compressed_total: self.compressed_total,
                logical_produced: logical,
            });
        }
    }
}

// Payload of the error `CountingBufRead` raises when the hook requests
// cancellation. Recognized by type after it has passed through the decoder.
#[derive(Debug)]
struct PreflightCancelled;

impl fmt::Display for PreflightCancelled {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("preflight cancelled")
    }
}

impl std::error::Error for PreflightCancelled {}

// Payload wrapping any error from the source below `CountingBufRead`, so it
// can never be mistaken for a decoder (format) error, whatever its kind.
#[derive(Debug)]
struct SourceReadError(io::Error);

impl fmt::Display for SourceReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "reading the compressed image failed: {}", self.0)
    }
}

impl std::error::Error for SourceReadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
    }
}

// The `BufRead` placed directly below the decoder. Counts the compressed
// bytes the decoder actually consumes (via `consume()`, never what a buffer
// below has read ahead), calls `before_fill` with that count before every
// `fill_buf()` -- a `true` return cancels -- and tags every error from below
// as `SourceReadError`. Retries `Interrupted` from below itself, so that kind
// never reaches the decoder (which treats it specially in places).
pub(super) struct CountingBufRead<R, F> {
    inner: R,
    consumed: u64,
    before_fill: F,
}

impl<R: BufRead, F: FnMut(u64) -> bool> CountingBufRead<R, F> {
    pub(super) fn new(inner: R, before_fill: F) -> Self {
        CountingBufRead {
            inner,
            consumed: 0,
            before_fill,
        }
    }

    // Compressed bytes consumed so far.
    pub(super) fn consumed(&self) -> u64 {
        self.consumed
    }
}

impl<R: BufRead, F: FnMut(u64) -> bool> BufRead for CountingBufRead<R, F> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        if (self.before_fill)(self.consumed) {
            return Err(io::Error::other(PreflightCancelled));
        }

        // Retry `Interrupted` from below; a plain loop around `fill_buf`
        // cannot return the borrowed slice from inside it, so probe first.
        loop {
            match self.inner.fill_buf() {
                Ok(_) => break,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(io::Error::other(SourceReadError(error))),
            }
        }

        self.inner
            .fill_buf()
            .map_err(|error| io::Error::other(SourceReadError(error)))
    }

    fn consume(&mut self, amount: usize) {
        self.inner.consume(amount);
        // Cannot overflow for any real file (the count never exceeds the
        // bytes the source handed out); saturate rather than wrap so an
        // impossible overflow can only make the final equality check fail.
        self.consumed = self.consumed.saturating_add(amount as u64);
    }
}

impl<R: BufRead, F: FnMut(u64) -> bool> Read for CountingBufRead<R, F> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let available = self.fill_buf()?;
        let n = available.len().min(buf.len());
        buf[..n].copy_from_slice(&available[..n]);
        self.consume(n);
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::image_source::{OpenedImage, open_image};
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use std::io::Write as _;
    use std::sync::atomic::{AtomicU64, Ordering};

    const NO_LIMIT: PreflightOptions = PreflightOptions {
        max_logical_size: u64::MAX,
    };

    fn gzip_member(payload: &[u8]) -> Vec<u8> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(payload).unwrap();
        encoder.finish().unwrap()
    }

    fn payload_a() -> Vec<u8> {
        (0..65_536u32)
            .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
            .collect()
    }

    fn payload_b() -> Vec<u8> {
        b"hello gzip member B ".repeat(500)
    }

    fn flip(bytes: &[u8], offset_from_end: usize) -> Vec<u8> {
        let mut flipped = bytes.to_vec();
        let index = flipped.len() - offset_from_end;
        flipped[index] ^= 0xFF;
        flipped
    }

    fn write_gz_file(tag: &str, contents: &[u8]) -> PathBuf {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "linux-usb-writer-preflight-test-{tag}-{}-{id}.img.gz",
            std::process::id()
        ));
        std::fs::write(&path, contents).expect("write temp gzip file");
        path
    }

    fn open_compressed(path: &Path) -> CompressedImageFile {
        match open_image(path) {
            Ok(OpenedImage::Compressed(file)) => file,
            other => panic!("expected OpenedImage::Compressed, got {other:?}"),
        }
    }

    // Runs the real production entry point on `contents` written to a temp
    // `.gz` file, with no cancellation, collecting progress reports.
    fn preflight_contents(
        tag: &str,
        contents: &[u8],
        options: PreflightOptions,
    ) -> (
        Result<PreflightedCompressedImage, PreflightError>,
        Vec<PreflightProgress>,
    ) {
        let path = write_gz_file(tag, contents);
        let file = open_compressed(&path);
        let mut reports = Vec::new();
        let result = file.preflight(options, || false, |progress| reports.push(progress));
        let _ = std::fs::remove_file(&path);
        (result, reports)
    }

    // A `BufRead` over a byte slice that exposes a small window per
    // `fill_buf()` and can fail with a chosen error once a given number of
    // bytes has been consumed -- a stand-in for a failing disk.
    struct ScriptedInput<'a> {
        data: &'a [u8],
        position: usize,
        window: usize,
        fail_at: Option<(usize, io::ErrorKind)>,
    }

    impl Read for ScriptedInput<'_> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let available = self.fill_buf()?;
            let n = available.len().min(buf.len());
            buf[..n].copy_from_slice(&available[..n]);
            self.consume(n);
            Ok(n)
        }
    }

    impl BufRead for ScriptedInput<'_> {
        fn fill_buf(&mut self) -> io::Result<&[u8]> {
            if let Some((at, kind)) = self.fail_at {
                if self.position >= at {
                    return Err(io::Error::new(kind, "injected source failure"));
                }
            }
            let end = (self.position + self.window).min(self.data.len());
            Ok(&self.data[self.position..end])
        }

        fn consume(&mut self, amount: usize) {
            self.position += amount;
        }
    }

    fn scripted(data: &[u8], fail_at: Option<(usize, io::ErrorKind)>) -> ScriptedInput<'_> {
        ScriptedInput {
            data,
            position: 0,
            window: 64,
            fail_at,
        }
    }

    // ---------------------------------------------------------------------
    // Valid streams.
    // ---------------------------------------------------------------------

    #[test]
    fn single_member_is_validated_with_its_exact_decoded_size() {
        let a = payload_a();
        let contents = gzip_member(&a);
        let (result, _) = preflight_contents("single", &contents, NO_LIMIT);

        let image = result.unwrap();
        assert_eq!(image.format(), CompressionFormat::Gzip);
        assert_eq!(image.logical_size(), a.len() as u64);
        assert_eq!(image.compressed_size(), contents.len() as u64);
    }

    #[test]
    fn multi_member_size_is_the_sum_of_all_members() {
        let (a, b) = (payload_a(), payload_b());
        let contents = [gzip_member(&a), gzip_member(&[]), gzip_member(&b)].concat();
        let (result, _) = preflight_contents("multi", &contents, NO_LIMIT);

        assert_eq!(result.unwrap().logical_size(), (a.len() + b.len()) as u64);
    }

    // A valid gzip that decodes to nothing passes Preflight with size 0:
    // Preflight validates the format; refusing an empty image stays the
    // Write Gate's job, exactly as for a 0-byte plain image.
    #[test]
    fn valid_empty_gzip_is_validated_with_size_zero() {
        let (result, _) = preflight_contents("empty", &gzip_member(&[]), NO_LIMIT);
        assert_eq!(result.unwrap().logical_size(), 0);
    }

    // The final progress report on success is exact: all compressed input
    // consumed, the full decoded size produced.
    #[test]
    fn final_progress_report_is_exact() {
        let a = payload_a();
        let contents = gzip_member(&a);
        let (result, reports) = preflight_contents("progress", &contents, NO_LIMIT);

        result.unwrap();
        assert_eq!(
            reports.last(),
            Some(&PreflightProgress {
                compressed_consumed: contents.len() as u64,
                compressed_total: contents.len() as u64,
                logical_produced: a.len() as u64,
            })
        );
    }

    // Progress reports during a larger decode are monotonic and report the
    // same compressed total throughout.
    #[test]
    fn progress_reports_are_monotonic() {
        // Stored (uncompressed) deflate blocks keep this multi-MiB fixture
        // fast to build in debug test builds.
        let big: Vec<u8> = (0..6 * 1024 * 1024u32)
            .map(|i| (i.wrapping_mul(2_654_435_761) >> 11) as u8)
            .collect();
        let mut encoder = GzEncoder::new(Vec::new(), Compression::none());
        encoder.write_all(&big).unwrap();
        let contents = encoder.finish().unwrap();
        let (result, reports) = preflight_contents("progress-big", &contents, NO_LIMIT);

        result.unwrap();
        assert!(reports.len() >= 2, "expected intermediate reports");
        for pair in reports.windows(2) {
            assert!(pair[0].compressed_consumed <= pair[1].compressed_consumed);
            assert!(pair[0].logical_produced <= pair[1].logical_produced);
        }
        assert!(
            reports
                .iter()
                .all(|report| report.compressed_total == contents.len() as u64)
        );
    }

    // Same-handle guarantee: after `open_image`, the path is renamed away, a
    // different file is put at the original path, and everything is
    // deleted -- Preflight still validates the file that was opened.
    #[test]
    fn preflight_reads_the_file_open_image_opened_not_the_path() {
        let a = payload_a();
        let path = write_gz_file("swap", &gzip_member(&a));
        let moved = path.with_extension("moved");

        let file = open_compressed(&path);

        std::fs::rename(&path, &moved).unwrap();
        std::fs::write(&path, gzip_member(b"a different, much shorter image")).unwrap();
        std::fs::remove_file(&moved).unwrap();
        std::fs::remove_file(&path).unwrap();

        let image = file.preflight(NO_LIMIT, || false, |_| {}).unwrap();
        assert_eq!(image.logical_size(), a.len() as u64);
    }

    // ---------------------------------------------------------------------
    // Damaged streams.
    // ---------------------------------------------------------------------

    fn assert_corrupt(tag: &str, contents: &[u8]) {
        let (result, _) = preflight_contents(tag, contents, NO_LIMIT);
        assert!(
            matches!(result, Err(PreflightError::Corrupt(_))),
            "{tag}: {result:?}"
        );
    }

    fn assert_incomplete(tag: &str, contents: &[u8]) {
        let (result, _) = preflight_contents(tag, contents, NO_LIMIT);
        assert!(
            matches!(result, Err(PreflightError::Incomplete(_))),
            "{tag}: {result:?}"
        );
    }

    #[test]
    fn checksum_and_size_mismatches_are_corrupt() {
        let member = gzip_member(&payload_a());
        assert_corrupt("crc", &flip(&member, 8));
        assert_corrupt("isize", &flip(&member, 4));
    }

    #[test]
    fn truncation_is_incomplete() {
        let member = gzip_member(&payload_a());
        assert_incomplete("trunc-footer", &member[..member.len() - 3]);
        assert_incomplete("trunc-body", &member[..member.len() / 2]);
        assert_incomplete("header-only", &member[..10]);
    }

    #[test]
    fn invalid_header_is_corrupt() {
        let mut member = gzip_member(&payload_a());
        member[2] = 7; // compression method must be 8
        assert_corrupt("bad-header", &member);
    }

    // Trailing bytes are always rejected; which of the two kinds depends on
    // their length (see `gzip_behavior`), but never success.
    #[test]
    fn trailing_bytes_are_rejected() {
        let member = gzip_member(&payload_a());

        assert_incomplete(
            "garbage-short",
            &[member.clone(), vec![0xDE, 0xAD]].concat(),
        );
        assert_corrupt("garbage-long", &[member.clone(), vec![0xDE; 16]].concat());
        assert_incomplete("zeros-short", &[member.clone(), vec![0u8; 4]].concat());
        assert_corrupt("zeros-long", &[member.clone(), vec![0u8; 512]].concat());
    }

    #[test]
    fn damage_in_a_later_member_is_rejected() {
        let (a, b) = (payload_a(), payload_b());
        let member_b = gzip_member(&b);

        assert_corrupt(
            "second-crc",
            &[gzip_member(&a), flip(&member_b, 8)].concat(),
        );
        assert_incomplete(
            "second-trunc",
            &[gzip_member(&a), member_b[..member_b.len() / 2].to_vec()].concat(),
        );
    }

    // ---------------------------------------------------------------------
    // Limits.
    // ---------------------------------------------------------------------

    #[test]
    fn decoded_size_exactly_at_the_limit_is_allowed() {
        let a = payload_a();
        let options = PreflightOptions {
            max_logical_size: a.len() as u64,
        };
        let (result, _) = preflight_contents("at-limit", &gzip_member(&a), options);
        assert_eq!(result.unwrap().logical_size(), a.len() as u64);
    }

    #[test]
    fn decoded_size_over_the_limit_is_rejected() {
        let a = payload_a();
        let limit = a.len() as u64 - 1;
        let options = PreflightOptions {
            max_logical_size: limit,
        };
        let (result, _) = preflight_contents("over-limit", &gzip_member(&a), options);
        assert!(matches!(
            result,
            Err(PreflightError::LogicalSizeLimitExceeded { limit: got }) if got == limit
        ));
    }

    #[test]
    fn zero_limit_allows_only_empty_images() {
        let zero = PreflightOptions {
            max_logical_size: 0,
        };

        let (empty, _) = preflight_contents("zero-empty", &gzip_member(&[]), zero);
        assert_eq!(empty.unwrap().logical_size(), 0);

        let (non_empty, _) = preflight_contents("zero-nonempty", &gzip_member(b"x"), zero);
        assert!(matches!(
            non_empty,
            Err(PreflightError::LogicalSizeLimitExceeded { limit: 0 })
        ));
    }

    #[test]
    fn logical_size_arithmetic_is_checked() {
        assert_eq!(add_logical_bytes(10, 5, 15).unwrap(), 15);
        assert!(matches!(
            add_logical_bytes(10, 6, 15),
            Err(PreflightError::LogicalSizeLimitExceeded { limit: 15 })
        ));
        assert!(matches!(
            add_logical_bytes(u64::MAX - 1, 2, u64::MAX),
            Err(PreflightError::LogicalSizeOverflow)
        ));
        assert_eq!(
            add_logical_bytes(u64::MAX - 1, 1, u64::MAX).unwrap(),
            u64::MAX
        );
        assert_eq!(add_logical_bytes(0, 0, 0).unwrap(), 0);
    }

    // ---------------------------------------------------------------------
    // Cancellation.
    // ---------------------------------------------------------------------

    #[test]
    fn cancellation_before_start_reads_nothing() {
        let path = write_gz_file("cancel-before", &gzip_member(&payload_a()));
        let file = open_compressed(&path);
        let mut reports = 0;

        let result = file.preflight(NO_LIMIT, || true, |_| reports += 1);
        let _ = std::fs::remove_file(&path);

        assert!(matches!(result, Err(PreflightError::Cancelled)));
        assert_eq!(reports, 0);
    }

    #[test]
    fn cancellation_during_decode_is_reported_as_cancelled() {
        let path = write_gz_file("cancel-during", &gzip_member(&payload_a()));
        let file = open_compressed(&path);
        let checks = Cell::new(0u32);

        let result = file.preflight(
            NO_LIMIT,
            || {
                checks.set(checks.get() + 1);
                checks.get() > 3
            },
            |_| {},
        );
        let _ = std::fs::remove_file(&path);

        assert!(matches!(result, Err(PreflightError::Cancelled)));
    }

    // Thousands of empty members produce no output at all, but consume
    // input: cancellation is polled on input, so it still takes effect
    // mid-stream (checked through a small input window so many polls happen).
    #[test]
    fn cancellation_works_while_input_produces_no_output() {
        let contents = gzip_member(&[]).repeat(5_000);
        let checks = Cell::new(0u32);
        let mut is_cancelled = || {
            checks.set(checks.get() + 1);
            checks.get() > 100
        };

        let result = preflight_gzip(
            scripted(&contents, None),
            contents.len() as u64,
            NO_LIMIT,
            &mut is_cancelled,
            &mut |_| {},
        );

        assert!(matches!(result, Err(PreflightError::Cancelled)));
        assert_eq!(checks.get(), 101, "stopped at the first cancelled poll");
    }

    // ---------------------------------------------------------------------
    // Error classification.
    // ---------------------------------------------------------------------

    // A failure of the source below the decoder is `Io` -- whatever its
    // kind, including kinds the decoder itself uses for format errors.
    #[test]
    fn source_failures_are_io_not_corrupt_or_incomplete() {
        let contents = gzip_member(&payload_a());

        for kind in [
            io::ErrorKind::InvalidData,
            io::ErrorKind::InvalidInput,
            io::ErrorKind::UnexpectedEof,
            io::ErrorKind::Other,
        ] {
            for fail_at in [0, 5, 500] {
                let result = preflight_gzip(
                    scripted(&contents, Some((fail_at, kind))),
                    contents.len() as u64,
                    NO_LIMIT,
                    &mut || false,
                    &mut |_| {},
                );
                match result {
                    Err(PreflightError::Io(error)) => assert_eq!(error.kind(), kind),
                    other => panic!("{kind:?} at {fail_at}: expected Io, got {other:?}"),
                }
            }
        }
    }

    // Cancellation is `Cancelled` -- never `Io` or `Corrupt` -- wherever in
    // the stream it lands.
    #[test]
    fn cancellation_is_never_misclassified() {
        let contents = [gzip_member(&payload_a()), gzip_member(&payload_b())].concat();

        // Count how many polls a full, uncancelled run makes, then cancel at
        // points spread across that range (first poll through the last one).
        let total_polls = Cell::new(0u32);
        preflight_gzip(
            scripted(&contents, None),
            contents.len() as u64,
            NO_LIMIT,
            &mut || {
                total_polls.set(total_polls.get() + 1);
                false
            },
            &mut |_| {},
        )
        .unwrap();
        let total = total_polls.get();
        assert!(total > 4, "expected many polls, got {total}");

        for cancel_after in [0, 1, total / 2, total - 1] {
            let checks = Cell::new(0u32);
            let result = preflight_gzip(
                scripted(&contents, None),
                contents.len() as u64,
                NO_LIMIT,
                &mut || {
                    checks.set(checks.get() + 1);
                    checks.get() > cancel_after
                },
                &mut |_| {},
            );
            assert!(
                matches!(result, Err(PreflightError::Cancelled)),
                "cancel_after={cancel_after}: {result:?}"
            );
        }
    }

    // A decoder format error is never reported as `Io`.
    #[test]
    fn decoder_errors_are_never_io() {
        let member = gzip_member(&payload_a());
        for contents in [flip(&member, 8), member[..member.len() - 3].to_vec()] {
            let result = preflight_gzip(
                scripted(&contents, None),
                contents.len() as u64,
                NO_LIMIT,
                &mut || false,
                &mut |_| {},
            );
            assert!(
                matches!(
                    result,
                    Err(PreflightError::Corrupt(_) | PreflightError::Incomplete(_))
                ),
                "{result:?}"
            );
        }
    }

    // A clean end of stream is not trusted unless every compressed byte was
    // consumed: claiming a larger compressed size than the stream occupies
    // is rejected.
    #[test]
    fn clean_end_without_consuming_the_whole_input_is_rejected() {
        let contents = gzip_member(&payload_a());
        let result = preflight_gzip(
            scripted(&contents, None),
            contents.len() as u64 + 1,
            NO_LIMIT,
            &mut || false,
            &mut |_| {},
        );

        assert!(matches!(
            result,
            Err(PreflightError::InputConsumptionMismatch { consumed, compressed_size })
                if consumed == contents.len() as u64 && compressed_size == consumed + 1
        ));
    }

    // Consumption is counted from `consume()` only: a buffer below that
    // reads ahead does not inflate the count.
    #[test]
    fn counting_follows_consume_not_read_ahead() {
        let data = [7u8; 100];
        let mut reader = CountingBufRead::new(&data[..], |_| false);

        assert_eq!(reader.fill_buf().unwrap().len(), 100);
        assert_eq!(reader.consumed(), 0);
        reader.consume(30);
        assert_eq!(reader.consumed(), 30);
        let mut two = [0u8; 2];
        reader.read_exact(&mut two).unwrap();
        assert_eq!(reader.consumed(), 32);
    }

    // ---------------------------------------------------------------------
    // Formats not implemented yet.
    // ---------------------------------------------------------------------

    #[test]
    fn xz_is_not_validated_yet() {
        let path = std::env::temp_dir().join(format!(
            "linux-usb-writer-preflight-test-xz-{}.img.xz",
            std::process::id()
        ));
        std::fs::write(&path, [0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00, 0x00, 0x04]).unwrap();
        let file = match open_image(&path) {
            Ok(OpenedImage::Compressed(file)) => file,
            other => panic!("expected Compressed, got {other:?}"),
        };
        let _ = std::fs::remove_file(&path);

        let result = file.preflight(NO_LIMIT, || false, |_| {});
        assert!(matches!(
            result,
            Err(PreflightError::UnsupportedFormat(CompressionFormat::Xz))
        ));
    }
}
