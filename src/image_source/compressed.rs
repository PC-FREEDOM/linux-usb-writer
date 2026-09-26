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
//   CountingBufRead  counts what the decoder actually `consume()`s, runs a
//                    check before every `fill_buf()` (cancellation, then the
//                    Compressed Input Budget below), and tags any error from
//                    below as a source I/O error
//   MultiGzDecoder   every member, CRC32 + ISIZE per member, and any trailing
//                    bytes rejected (behavior pinned by `gzip_behavior` tests)
//
// Errors are classified by type, never by message text: cancellation, budget
// exhaustion and source I/O failures travel through the decoder as typed
// payloads (`PreflightCancelled` / `InputBudgetExceeded` /
// `SourceReadError`), which `flate2` passes through unchanged (see
// `gzip_behavior::errors_from_below_the_decoder_propagate_unchanged`);
// anything else came from the decoder itself.
//
// Compressed Input Budget (a resource / responsiveness policy -- not a
// corruption check and not a decompression-bomb check): a valid gzip stream
// can make the decoder process a great deal of compressed input while
// producing almost no output (thousands of empty members, empty stored
// blocks, large header fields). A single `read()` would then stay inside the
// decoder for a long time, and nothing above it could react (e.g. to a
// cancellation) until it returned. The budget bounds that work locally:
//
//   - every decoded output byte earns 65/64 bytes of compressed-input
//     budget (integer arithmetic; the fractional remainder is carried, so
//     the total earned never depends on how output was split into reads);
//   - the balance starts at, and can never exceed, 1 MiB -- output earned in
//     the past cannot be banked for later;
//   - compressed bytes the decoder consumes are charged against the
//     balance, and consuming more than the balance is refused.
//
// The balance is checked in `fill_buf()`, before the decoder can consume the
// next buffer, so the decoder may consume up to one buffer (the 256 KiB
// `BufReader` capacity) beyond it before the next check. Output is credited
// every `DECODE_QUANTUM` (64 KiB) of decoding. Together, for any stretch of
// decoding that produces `dL` bytes of output, the compressed input
// processed is at most `1 MiB + dL * 65/64 + 256 KiB` -- about 2.27 MiB per
// 1 MiB of output. That bound is what keeps every read short enough for the
// caller to stay responsive.
//
// This policy can refuse gzip files that are well-formed: very long runs of
// tiny members (each with ~20 bytes of member overhead for a byte or so of
// output -- about 50,000+ consecutive 1-byte members), runs of members with
// very large header fields, or runs of empty members / empty stored blocks.
// Ordinary disk-image gzip files (single member, pigz, a few concatenated
// files, `--rsyncable`) stay far below the limit.

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
// How much decoded output one decoder read may produce before it is counted
// and credited to the Compressed Input Budget. Part of the budget's
// responsiveness contract, not just a buffer size: a smaller quantum keeps
// the credit current; a larger one could let honest, incompressible input
// run ahead of its credit.
const DECODE_QUANTUM: usize = 64 * 1024;
// Compressed Input Budget: the balance's starting value and ceiling.
const INPUT_BUDGET_CAP: u64 = 1024 * 1024;
// Compressed Input Budget: each output byte earns `1 + 1/64` input bytes.
const INPUT_BUDGET_RATE_DENOMINATOR: u64 = 64;
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
    LogicalSizeLimitExceeded {
        limit: u64,
    },
    // The decoder reported a clean end of stream without having consumed
    // exactly the compressed file's size. Not expected from a correct
    // decoder; checked so a clean end is never trusted on its own.
    InputConsumptionMismatch {
        consumed: u64,
        compressed_size: u64,
    },
    // The decoder needed more compressed input than the Compressed Input
    // Budget allows for the output produced so far (see the module
    // comment). The stream is not necessarily damaged -- it may be valid
    // gzip -- but processing it would take unreasonably long per byte of
    // image, so it is refused as a resource policy.
    CompressedInputBudgetExceeded {
        compressed_consumed: u64,
        logical_produced: u64,
    },
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
        let mut budget = InputBudgetMeter::new();
        let hook = |consumed: u64| {
            let logical = logical_produced.get();
            preflight_check(is_cancelled(), &mut budget, consumed, logical)?;
            reporter.maybe_report(consumed, logical, &mut *on_progress);
            Ok(())
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
    let mut buf = vec![0u8; DECODE_QUANTUM];

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

// The check run before every `fill_buf()` during Preflight. Cancellation is
// checked first and wins: if the caller has asked to stop, the result is
// `Cancelled` even when the budget is also exhausted at that moment.
fn preflight_check(
    cancelled: bool,
    budget: &mut InputBudgetMeter,
    consumed: u64,
    logical: u64,
) -> io::Result<()> {
    if cancelled {
        return Err(io::Error::other(PreflightCancelled));
    }
    budget.update(consumed, logical)
}

// The Compressed Input Budget's balance (see the module comment). Pure
// integer arithmetic, no I/O.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CompressedInputBudget {
    // Compressed bytes that may still be consumed. Never above
    // `INPUT_BUDGET_CAP`.
    tokens: u64,
    // Output bytes not yet worth a whole extra token: the running total of
    // credited output modulo `INPUT_BUDGET_RATE_DENOMINATOR`. Carrying it
    // makes the credit for N output bytes exactly `N + floor(N / 64)` no
    // matter how N was split across calls.
    credit_remainder: u64,
}

impl CompressedInputBudget {
    fn new() -> Self {
        CompressedInputBudget {
            tokens: INPUT_BUDGET_CAP,
            credit_remainder: 0,
        }
    }

    // Credits `produced` output bytes at 65/64, never raising the balance
    // above the cap (so past output cannot be banked).
    fn credit_output(&mut self, produced: u64) {
        let denominator = INPUT_BUDGET_RATE_DENOMINATOR;
        // Both terms are below `denominator`, so this cannot overflow.
        let carried = self.credit_remainder + produced % denominator;
        let extra = produced / denominator + carried / denominator;
        self.credit_remainder = carried % denominator;

        let credit = produced.saturating_add(extra);
        self.tokens = self.tokens.saturating_add(credit).min(INPUT_BUDGET_CAP);
    }

    // Charges `consumed` input bytes. Returns `false` -- leaving the balance
    // unchanged -- when the balance does not cover them.
    fn try_charge_input(&mut self, consumed: u64) -> bool {
        if consumed > self.tokens {
            return false;
        }
        self.tokens -= consumed;
        true
    }
}

// Applies the budget to a running decode: credits output and charges input
// as the totals advance between checks.
struct InputBudgetMeter {
    budget: CompressedInputBudget,
    credited_logical: u64,
    charged_consumed: u64,
}

impl InputBudgetMeter {
    fn new() -> Self {
        InputBudgetMeter {
            budget: CompressedInputBudget::new(),
            credited_logical: 0,
            charged_consumed: 0,
        }
    }

    // `consumed` / `logical` are the running totals (both only ever grow).
    // Output is credited before input is charged, so the output produced up
    // to this point always counts.
    fn update(&mut self, consumed: u64, logical: u64) -> io::Result<()> {
        self.budget
            .credit_output(logical.saturating_sub(self.credited_logical));
        self.credited_logical = logical;

        let delta = consumed.saturating_sub(self.charged_consumed);
        if !self.budget.try_charge_input(delta) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                InputBudgetExceeded {
                    compressed_consumed: consumed,
                    logical_produced: logical,
                },
            ));
        }
        self.charged_consumed = consumed;

        Ok(())
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

    if let Some(exceeded) = error
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<InputBudgetExceeded>())
    {
        return PreflightError::CompressedInputBudgetExceeded {
            compressed_consumed: exceeded.compressed_consumed,
            logical_produced: exceeded.logical_produced,
        };
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

// Payload of the error raised when the Compressed Input Budget is exhausted.
// Recognized by type after it has passed through the decoder.
#[derive(Debug)]
struct InputBudgetExceeded {
    compressed_consumed: u64,
    logical_produced: u64,
}

impl fmt::Display for InputBudgetExceeded {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "compressed input budget exceeded after {} compressed bytes for {} decoded bytes",
            self.compressed_consumed, self.logical_produced
        )
    }
}

impl std::error::Error for InputBudgetExceeded {}

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
// `fill_buf()` -- an `Err` from it is returned as-is (the caller's typed
// payload, e.g. cancellation or budget exhaustion) -- and tags every error
// from below as `SourceReadError`. Retries `Interrupted` from below itself, so that kind
// never reaches the decoder (which treats it specially in places).
pub(super) struct CountingBufRead<R, F> {
    inner: R,
    consumed: u64,
    before_fill: F,
}

impl<R: BufRead, F: FnMut(u64) -> io::Result<()>> CountingBufRead<R, F> {
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

impl<R: BufRead, F: FnMut(u64) -> io::Result<()>> BufRead for CountingBufRead<R, F> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        (self.before_fill)(self.consumed)?;

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

impl<R: BufRead, F: FnMut(u64) -> io::Result<()>> Read for CountingBufRead<R, F> {
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
        let mut reader = CountingBufRead::new(&data[..], |_| Ok(()));

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

    // ---------------------------------------------------------------------
    // Compressed Input Budget: arithmetic.
    // ---------------------------------------------------------------------

    fn drained_budget() -> CompressedInputBudget {
        let mut budget = CompressedInputBudget::new();
        assert!(budget.try_charge_input(INPUT_BUDGET_CAP));
        assert_eq!(budget.tokens, 0);
        budget
    }

    #[test]
    fn budget_starts_full_at_the_cap() {
        let budget = CompressedInputBudget::new();
        assert_eq!(budget.tokens, INPUT_BUDGET_CAP);
        assert_eq!(budget.credit_remainder, 0);
    }

    // 64 one-byte credits earn exactly 65, like one 64-byte credit; the
    // fraction is carried, not rounded away per call.
    #[test]
    fn budget_credit_carries_the_fraction() {
        let mut budget = drained_budget();
        for _ in 0..63 {
            budget.credit_output(1);
        }
        assert_eq!(budget.tokens, 63);
        budget.credit_output(1);
        assert_eq!(budget.tokens, 65);

        let mut whole = drained_budget();
        whole.credit_output(64);
        assert_eq!(whole.tokens, 65);
    }

    // The total credit for N output bytes is `N + floor(N / 64)` however the
    // N bytes are split into calls.
    #[test]
    fn budget_credit_does_not_depend_on_read_splitting() {
        for total in [1u64, 63, 64, 65, 1000, 12_345, 64 * 1024 + 17] {
            let expected = total + total / 64;
            for chunk in [1u64, 7, 64, 4096, 64 * 1024, total] {
                let mut budget = drained_budget();
                let mut left = total;
                while left > 0 {
                    let step = chunk.min(left);
                    budget.credit_output(step);
                    left -= step;
                }
                assert_eq!(budget.tokens, expected, "total={total} chunk={chunk}");
            }
        }
    }

    #[test]
    fn budget_credit_never_exceeds_the_cap() {
        let mut budget = CompressedInputBudget::new();
        budget.credit_output(1);
        assert_eq!(budget.tokens, INPUT_BUDGET_CAP);

        let mut budget = drained_budget();
        budget.credit_output(INPUT_BUDGET_CAP);
        assert_eq!(budget.tokens, INPUT_BUDGET_CAP);

        // Huge output, repeatedly: still exactly the cap (no banking).
        for _ in 0..3 {
            budget.credit_output(1 << 40);
            assert_eq!(budget.tokens, INPUT_BUDGET_CAP);
        }
    }

    #[test]
    fn budget_credit_is_overflow_safe() {
        let mut budget = drained_budget();
        budget.credit_output(u64::MAX);
        assert_eq!(budget.tokens, INPUT_BUDGET_CAP);
        assert_eq!(budget.credit_remainder, u64::MAX % 64);

        budget.credit_output(u64::MAX);
        assert_eq!(budget.tokens, INPUT_BUDGET_CAP);
        assert!(budget.credit_remainder < 64);

        let mut zero = drained_budget();
        zero.credit_output(0);
        assert_eq!(zero, drained_budget());
    }

    #[test]
    fn budget_charge_is_exact_and_never_wraps() {
        let mut exact = CompressedInputBudget::new();
        assert!(exact.try_charge_input(INPUT_BUDGET_CAP));
        assert_eq!(exact.tokens, 0);
        assert!(exact.try_charge_input(0));

        let mut over = CompressedInputBudget::new();
        assert!(!over.try_charge_input(INPUT_BUDGET_CAP + 1));
        assert_eq!(
            over.tokens, INPUT_BUDGET_CAP,
            "a refused charge changes nothing"
        );

        let mut huge = CompressedInputBudget::new();
        assert!(!huge.try_charge_input(u64::MAX));
        assert_eq!(huge.tokens, INPUT_BUDGET_CAP);
    }

    fn budget_error(result: io::Result<()>) -> PreflightError {
        classify_error(result.unwrap_err())
    }

    // Exactly the balance is allowed; one byte more is refused, and reported
    // as the typed budget error with the totals at that point.
    #[test]
    fn meter_allows_exactly_the_balance_and_refuses_one_more_byte() {
        let mut meter = InputBudgetMeter::new();
        meter.update(INPUT_BUDGET_CAP, 0).unwrap();

        let mut meter = InputBudgetMeter::new();
        let error = budget_error(meter.update(INPUT_BUDGET_CAP + 1, 0));
        assert!(matches!(
            error,
            PreflightError::CompressedInputBudgetExceeded {
                compressed_consumed,
                logical_produced: 0,
            } if compressed_consumed == INPUT_BUDGET_CAP + 1
        ));

        // With output: 64 KiB of output earns 65 KiB on top of the cap.
        let mut meter = InputBudgetMeter::new();
        let allowed = INPUT_BUDGET_CAP + 65 * 1024;
        meter.update(INPUT_BUDGET_CAP, 0).unwrap();
        meter.update(allowed, 64 * 1024).unwrap();
        assert!(meter.update(allowed + 1, 64 * 1024).is_err());
    }

    // The core of the policy: a gigabyte of earlier output does not buy more
    // than the cap of later input.
    #[test]
    fn meter_does_not_bank_past_output() {
        // The 1 GiB of output is credited, but the balance stays capped, so
        // the total input allowed is still exactly the cap.
        let mut meter = InputBudgetMeter::new();
        meter.update(1_000, 1 << 30).unwrap();
        meter.update(INPUT_BUDGET_CAP, 1 << 30).unwrap();
        assert!(meter.update(INPUT_BUDGET_CAP + 1, 1 << 30).is_err());
    }

    // When cancellation and budget exhaustion coincide, cancellation wins.
    #[test]
    fn cancellation_takes_priority_over_budget_exhaustion() {
        let mut meter = InputBudgetMeter::new();
        let cancelled = preflight_check(true, &mut meter, INPUT_BUDGET_CAP + 1, 0);
        assert!(matches!(budget_error(cancelled), PreflightError::Cancelled));

        let mut meter = InputBudgetMeter::new();
        let exceeded = preflight_check(false, &mut meter, INPUT_BUDGET_CAP + 1, 0);
        assert!(matches!(
            budget_error(exceeded),
            PreflightError::CompressedInputBudgetExceeded { .. }
        ));
    }

    // ---------------------------------------------------------------------
    // Compressed Input Budget: real gzip streams through the production path.
    // ---------------------------------------------------------------------

    fn gzip_at(payload: &[u8], level: u32) -> Vec<u8> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::new(level));
        encoder.write_all(payload).unwrap();
        encoder.finish().unwrap()
    }

    fn pseudo_random(len: usize, seed: u64) -> Vec<u8> {
        let mut x = seed | 1;
        (0..len)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                x as u8
            })
            .collect()
    }

    fn assert_budget_exceeded(tag: &str, contents: &[u8]) -> (u64, u64) {
        let (result, reports) = preflight_contents(tag, contents, NO_LIMIT);
        let (consumed, logical) = match result {
            Err(PreflightError::CompressedInputBudgetExceeded {
                compressed_consumed,
                logical_produced,
            }) => (compressed_consumed, logical_produced),
            other => panic!("{tag}: expected CompressedInputBudgetExceeded, got {other:?}"),
        };
        // A refused image never gets the final "complete" progress report.
        assert!(
            reports
                .iter()
                .all(|report| report.compressed_consumed < contents.len() as u64),
            "{tag}: a success-looking final report was emitted"
        );
        (consumed, logical)
    }

    #[test]
    fn budget_accepts_ordinary_gzip_at_every_level() {
        let random = pseudo_random(1 << 20, 11);
        let zeros = vec![0u8; 4 << 20];
        let text = payload_b().repeat(100);

        for level in [0, 1, 6, 9] {
            for (name, payload) in [("random", &random), ("zeros", &zeros), ("text", &text)] {
                let (result, _) = preflight_contents(
                    &format!("budget-{name}-{level}"),
                    &gzip_at(payload, level),
                    NO_LIMIT,
                );
                assert_eq!(
                    result.unwrap().logical_size(),
                    payload.len() as u64,
                    "{name} level {level}"
                );
            }
        }
    }

    #[test]
    fn budget_accepts_small_gzip_files() {
        for size in [0usize, 1, 100, 1024, 64 * 1024] {
            let payload = pseudo_random(size, 3);
            let (result, _) = preflight_contents(
                &format!("budget-small-{size}"),
                &gzip_at(&payload, 6),
                NO_LIMIT,
            );
            assert_eq!(result.unwrap().logical_size(), size as u64);
        }
    }

    #[test]
    fn budget_accepts_realistic_multi_member_files() {
        let text_member = gzip_at(&payload_b()[..4096], 6);
        let random_member = gzip_at(&pseudo_random(4096, 9), 6);
        let empty = gzip_at(&[], 6);

        let mut mixed = Vec::new();
        for _ in 0..1000 {
            mixed.extend_from_slice(&text_member);
            mixed.extend_from_slice(&empty);
            mixed.extend_from_slice(&random_member);
        }
        let (result, _) = preflight_contents("budget-multi", &mixed, NO_LIMIT);
        assert_eq!(result.unwrap().logical_size(), 1000 * 2 * 4096);
    }

    // Consecutive 1-byte members: each costs ~21 compressed bytes for one
    // output byte, so a long enough run exhausts the budget (a documented
    // false rejection of valid gzip). 10,000 and 50,000 pass; 100,000 is
    // refused after roughly 50,000 members.
    #[test]
    fn budget_tiny_member_runs_pass_up_to_the_documented_boundary() {
        let one = gzip_at(b"x", 6);

        for count in [10_000usize, 50_000] {
            let (result, _) = preflight_contents(
                &format!("budget-tiny-{count}"),
                &one.repeat(count),
                NO_LIMIT,
            );
            assert_eq!(result.unwrap().logical_size(), count as u64);
        }

        let (consumed, logical) = assert_budget_exceeded("budget-tiny-100k", &one.repeat(100_000));
        assert!(
            (50_000..60_000).contains(&logical),
            "refused after {logical} members"
        );
        assert!(consumed <= INPUT_BUDGET_CAP + logical + logical / 64 + INPUT_BUFFER_LEN as u64);
    }

    // P1: a long run of empty members is refused within the cap plus one
    // input buffer, before any output.
    #[test]
    fn budget_refuses_a_run_of_empty_members() {
        let mut contents = gzip_at(&[], 6).repeat(80_000);
        contents.extend_from_slice(&gzip_at(b"x", 6));

        let (consumed, logical) = assert_budget_exceeded("budget-p1", &contents);
        assert_eq!(logical, 0);
        assert!(consumed > INPUT_BUDGET_CAP);
        assert!(consumed <= INPUT_BUDGET_CAP + INPUT_BUFFER_LEN as u64);
    }

    // P2: one member made of empty stored blocks is refused the same way.
    #[test]
    fn budget_refuses_a_run_of_empty_stored_blocks() {
        let mut member = vec![0x1F, 0x8B, 8, 0, 0, 0, 0, 0, 0, 0xFF];
        for _ in 0..400_000 {
            member.extend_from_slice(&[0x00, 0x00, 0x00, 0xFF, 0xFF]);
        }
        member.extend_from_slice(&[0x01, 0x01, 0x00, 0xFE, 0xFF, b'x']);
        let mut crc = flate2::Crc::new();
        crc.update(b"x");
        member.extend_from_slice(&crc.sum().to_le_bytes());
        member.extend_from_slice(&1u32.to_le_bytes());

        let (consumed, logical) = assert_budget_exceeded("budget-p2", &member);
        assert_eq!(logical, 0);
        assert!(consumed <= INPUT_BUDGET_CAP + INPUT_BUFFER_LEN as u64);
    }

    // P3: sprinkling single output bytes between runs of empty members earns
    // almost nothing and does not keep the stream alive.
    #[test]
    fn budget_refuses_empty_member_runs_interleaved_with_output() {
        let one = gzip_at(b"x", 6);
        let empty_run = gzip_at(&[], 6).repeat(3_000);
        let mut contents = Vec::new();
        for _ in 0..100 {
            contents.extend_from_slice(&one);
            contents.extend_from_slice(&empty_run);
        }

        let (consumed, logical) = assert_budget_exceeded("budget-p3", &contents);
        assert!(logical < 100);
        assert!(consumed <= INPUT_BUDGET_CAP + logical * 2 + INPUT_BUFFER_LEN as u64);
    }

    // BANK: many megabytes of highly compressible output first (earning far
    // more than the cap), then a long run of empty members. Because the
    // balance is capped, the run is refused within the cap -- the earlier
    // output was not banked.
    #[test]
    fn budget_refuses_empty_members_after_banking_attempt() {
        let zeros = vec![0u8; 16 << 20];
        let bank = gzip_at(&zeros, 9);
        let mut contents = bank.clone();
        contents.extend_from_slice(&gzip_at(&[], 6).repeat(80_000));
        contents.extend_from_slice(&gzip_at(b"x", 6));

        let (consumed, logical) = assert_budget_exceeded("budget-bank", &contents);
        assert_eq!(
            logical,
            zeros.len() as u64,
            "all banked output was produced first"
        );
        let spent_after_bank = consumed - bank.len() as u64;
        assert!(
            spent_after_bank <= INPUT_BUDGET_CAP + INPUT_BUFFER_LEN as u64,
            "spent {spent_after_bank} after the bank: earlier output was banked"
        );
    }

    // Cancellation still works with the budget in place, and wins when it
    // lands on the very check where the budget would have been exceeded.
    #[test]
    fn cancellation_wins_at_the_poll_where_the_budget_runs_out() {
        let contents = gzip_at(&[], 6).repeat(60_000);

        let polls = Cell::new(0u32);
        let exceeded = preflight_gzip(
            scripted(&contents, None),
            contents.len() as u64,
            NO_LIMIT,
            &mut || {
                polls.set(polls.get() + 1);
                false
            },
            &mut |_| {},
        );
        assert!(matches!(
            exceeded,
            Err(PreflightError::CompressedInputBudgetExceeded { .. })
        ));
        let failing_poll = polls.get();

        let polls = Cell::new(0u32);
        let cancelled = preflight_gzip(
            scripted(&contents, None),
            contents.len() as u64,
            NO_LIMIT,
            &mut || {
                polls.set(polls.get() + 1);
                polls.get() >= failing_poll
            },
            &mut |_| {},
        );
        assert!(matches!(cancelled, Err(PreflightError::Cancelled)));
    }

    // The logical-size limit is a separate check and keeps its own error.
    #[test]
    fn logical_size_limit_is_independent_of_the_budget() {
        let zeros = vec![0u8; 4 << 20];
        let options = PreflightOptions {
            max_logical_size: (1 << 20) - 1,
        };
        let (result, _) = preflight_contents("budget-vs-limit", &gzip_at(&zeros, 9), options);
        assert!(matches!(
            result,
            Err(PreflightError::LogicalSizeLimitExceeded { limit }) if limit == (1 << 20) - 1
        ));
    }
}
