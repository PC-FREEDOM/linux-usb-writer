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
use std::sync::atomic::{AtomicU64, Ordering};

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

    // Starts a fresh decode of the validated stream: a new reader over the
    // same open file (never re-opened by path), from compressed byte 0, with
    // its own independent position -- so this can be called any number of
    // times (e.g. once to write, once more to verify), and no replay affects
    // another. The reader enforces everything Preflight established; see
    // `StrictReplayReader`. Infallible: nothing is read until the first
    // `read()` (any error surfaces there).
    pub fn replay(&self) -> StrictReplayReader {
        StrictReplayReader::new(&self.file, self.compressed_size, self.logical_size)
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

// ---------------------------------------------------------------------
// Replay: decoding a validated stream again, strictly.
// ---------------------------------------------------------------------

// The check run before every `fill_buf()` during a replay: the Compressed
// Input Budget only (a replay has no cancellation hook of its own; the
// budget keeps each `read()` short enough for the caller's own checks).
type ReplayHook = Box<dyn FnMut(u64) -> io::Result<()> + Send>;
type ReplayDecoder = MultiGzDecoder<CountingBufRead<BufReader<FileImageReader>, ReplayHook>>;

// Why a replay failed, as a category that survives the first error (an
// `io::Error` cannot be cloned). Determined by type, never by message text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReplayFailure {
    // The stream ended cleanly before producing `logical_size` bytes.
    EndedEarly,
    // The stream produced more than `logical_size` bytes.
    LogicalSizeExceeded,
    // The stream ended cleanly without consuming the whole compressed file.
    InputNotFullyConsumed,
    // The Compressed Input Budget was exhausted.
    InputBudgetExceeded,
    // Reading the compressed file failed.
    SourceIo,
    // The decoder reported damaged data (header, compressed data, checksum
    // or size mismatch, trailing bytes).
    Corrupt,
    // The decoder reported that the compressed data ended too soon.
    Incomplete,
}

impl ReplayFailure {
    // Categorizes an error that came out of the decoder or this module:
    // typed payloads first, then the decoder's own errors by kind.
    fn of(error: &io::Error) -> ReplayFailure {
        if let Some(inner) = error.get_ref() {
            if let Some(failed) = inner.downcast_ref::<ReplayFailed>() {
                return failed.0;
            }
            if inner.is::<InputBudgetExceeded>() {
                return ReplayFailure::InputBudgetExceeded;
            }
            if inner.is::<SourceReadError>() {
                return ReplayFailure::SourceIo;
            }
        }
        match error.kind() {
            io::ErrorKind::UnexpectedEof => ReplayFailure::Incomplete,
            _ => ReplayFailure::Corrupt,
        }
    }
}

// Payload of the errors this module raises itself during a replay (end /
// size mismatches), and of every error returned after the first failure.
#[derive(Debug)]
struct ReplayFailed(ReplayFailure);

impl fmt::Display for ReplayFailed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "compressed image replay failed: {:?}", self.0)
    }
}

impl std::error::Error for ReplayFailed {}

fn replay_failed(failure: ReplayFailure) -> io::Error {
    let kind = match failure {
        ReplayFailure::EndedEarly => io::ErrorKind::UnexpectedEof,
        _ => io::ErrorKind::InvalidData,
    };
    io::Error::new(kind, ReplayFailed(failure))
}

enum ReplayState {
    // Still decoding. `produced` never exceeds `logical_size`; `credited` is
    // the same count, shared with the budget hook below the decoder.
    Active {
        decoder: Box<ReplayDecoder>,
        produced: u64,
        credited: Arc<AtomicU64>,
    },
    // Every byte was delivered and the end of the stream was verified.
    Succeeded,
    // A failure was reported; every later read reports it again.
    Failed {
        kind: io::ErrorKind,
        failure: ReplayFailure,
    },
}

// A strict, sequential re-decode of a validated compressed image. As a
// `Read`, it yields exactly the `logical_size` bytes Preflight measured and
// then `Ok(0)` -- or an error, never anything in between:
//
//   - Output is capped at `logical_size`; producing more is an error
//     (`InvalidData`), and so is ending before it (`UnexpectedEof`).
//   - The read that would deliver the final bytes first drives the decoder
//     to its verified end (so trailing checksums/sizes, trailing bytes and
//     any extra output are checked) and returns those bytes only if the end
//     is valid; otherwise that read fails and the bytes are not delivered.
//     With `logical_size == 0`, the first non-empty read does the same.
//   - Each read hands the decoder at most `DECODE_QUANTUM` bytes of room,
//     and the Compressed Input Budget applies exactly as in Preflight, so
//     a single read stays within the documented work bound.
//   - After success every read returns `Ok(0)`; after a failure every read
//     returns an error of the same kind (never data). `Interrupted` is never
//     returned.
//   - A zero-length read returns `Ok(0)` without advancing anything.
pub struct StrictReplayReader {
    logical_size: u64,
    compressed_size: u64,
    state: ReplayState,
}

impl StrictReplayReader {
    fn new(file: &Arc<File>, compressed_size: u64, logical_size: u64) -> Self {
        let credited = Arc::new(AtomicU64::new(0));
        let mut budget = InputBudgetMeter::new();
        let hook_credited = Arc::clone(&credited);
        let hook: ReplayHook = Box::new(move |consumed: u64| {
            budget.update(consumed, hook_credited.load(Ordering::Relaxed))
        });

        let input =
            BufReader::with_capacity(INPUT_BUFFER_LEN, source_cursor(file, compressed_size));
        let decoder = Box::new(MultiGzDecoder::new(CountingBufRead::new(input, hook)));

        StrictReplayReader {
            logical_size,
            compressed_size,
            state: ReplayState::Active {
                decoder,
                produced: 0,
                credited,
            },
        }
    }

    // Records `error` as this reader's terminal failure and returns it.
    fn fail(&mut self, error: io::Error) -> io::Error {
        let failure = ReplayFailure::of(&error);
        // Never report `Interrupted` (callers retry it); `read_decoder`
        // already absorbs it, so this is only a guard.
        let error = if error.kind() == io::ErrorKind::Interrupted {
            io::Error::other(ReplayFailed(failure))
        } else {
            error
        };
        self.state = ReplayState::Failed {
            kind: error.kind(),
            failure,
        };
        error
    }

    // Compressed bytes consumed so far (test instrumentation).
    #[cfg(test)]
    fn compressed_consumed(&self) -> Option<u64> {
        match &self.state {
            ReplayState::Active { decoder, .. } => Some(decoder.get_ref().consumed()),
            _ => None,
        }
    }
}

// Reads from `decoder`, retrying `Interrupted` (so it can never escape).
fn read_decoder(decoder: &mut ReplayDecoder, buf: &mut [u8]) -> io::Result<usize> {
    loop {
        match decoder.read(buf) {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            result => return result,
        }
    }
}

// Verifies the end of a replayed stream once all `logical_size` bytes have
// been produced: the decoder must reach a clean end (which checks every
// remaining footer, and rejects trailing bytes) without producing a single
// further byte, having consumed exactly the whole compressed file. Stops at
// the first extra output byte -- the size mismatch is already certain.
fn verify_end_of_stream(decoder: &mut ReplayDecoder, compressed_size: u64) -> io::Result<()> {
    let mut probe = [0u8; 64];

    if read_decoder(decoder, &mut probe)? != 0 {
        return Err(replay_failed(ReplayFailure::LogicalSizeExceeded));
    }
    if decoder.get_ref().consumed() != compressed_size {
        return Err(replay_failed(ReplayFailure::InputNotFullyConsumed));
    }

    Ok(())
}

impl Read for StrictReplayReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let (decoder, produced, credited) = match &mut self.state {
            ReplayState::Succeeded => return Ok(0),
            ReplayState::Failed { kind, failure } => {
                return Err(io::Error::new(*kind, ReplayFailed(*failure)));
            }
            ReplayState::Active { .. } if buf.is_empty() => return Ok(0),
            ReplayState::Active {
                decoder,
                produced,
                credited,
            } => (decoder, produced, credited),
        };

        let remaining = self.logical_size - *produced;

        if remaining == 0 {
            // Only reachable with `logical_size == 0`: nothing to deliver,
            // but the stream's end is still verified before reporting EOF.
            return match verify_end_of_stream(decoder, self.compressed_size) {
                Ok(()) => {
                    self.state = ReplayState::Succeeded;
                    Ok(0)
                }
                Err(error) => Err(self.fail(error)),
            };
        }

        let want = (buf.len() as u64).min(remaining).min(DECODE_QUANTUM as u64) as usize;
        let n = match read_decoder(decoder, &mut buf[..want]) {
            Ok(0) => return Err(self.fail(replay_failed(ReplayFailure::EndedEarly))),
            Ok(n) => n,
            Err(error) => return Err(self.fail(error)),
        };

        *produced += n as u64;
        credited.store(*produced, Ordering::Relaxed);

        if *produced == self.logical_size {
            // The final bytes are in `buf`, but are only reported (as
            // `Ok(n)`) if the stream's end verifies; on failure this read
            // returns an error and they are not delivered.
            if let Err(error) = verify_end_of_stream(decoder, self.compressed_size) {
                return Err(self.fail(error));
            }
            self.state = ReplayState::Succeeded;
        }

        Ok(n)
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

    // ---------------------------------------------------------------------
    // Replay (StrictReplayReader).
    // ---------------------------------------------------------------------

    const REPLAY_BUFFER_SIZES: [usize; 6] = [1, 7, 64, 4096, 64 * 1024, 1024 * 1024];

    // Writes `contents` to a temp `.gz` file, opens and preflights it, and
    // returns the validated image together with the (still existing) path,
    // so tests can mutate the same inode afterwards.
    fn preflighted(tag: &str, contents: &[u8]) -> (PreflightedCompressedImage, PathBuf) {
        let path = write_gz_file(tag, contents);
        let image = open_compressed(&path)
            .preflight(NO_LIMIT, || false, |_| {})
            .unwrap_or_else(|error| panic!("{tag}: preflight failed: {error:?}"));
        (image, path)
    }

    // Overwrites the file in place from offset 0 (same inode, no truncation).
    fn rewrite_in_place(path: &Path, bytes: &[u8]) {
        use std::os::unix::fs::FileExt as _;
        let file = std::fs::OpenOptions::new().write(true).open(path).unwrap();
        file.write_all_at(bytes, 0).unwrap();
    }

    fn flip_byte_in_place(path: &Path, offset_from_end: u64) {
        use std::os::unix::fs::FileExt as _;
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .unwrap();
        let offset = file.metadata().unwrap().len() - offset_from_end;
        let mut byte = [0u8; 1];
        file.read_exact_at(&mut byte, offset).unwrap();
        file.write_all_at(&[byte[0] ^ 0xFF], offset).unwrap();
    }

    // An empty gzip member of exactly `len` bytes (>= 20): the FNAME field
    // absorbs any length above the 20-byte minimum.
    fn empty_member_of_len(len: usize) -> Vec<u8> {
        if len == 20 {
            return gzip_at(&[], 6);
        }
        assert!(len >= 21);
        let mut member = vec![0x1F, 0x8B, 8, 0x08, 0, 0, 0, 0, 0, 0xFF];
        member.extend(std::iter::repeat_n(b'n', len - 21));
        member.push(0);
        member.extend_from_slice(&[0x03, 0x00]); // empty final fixed block
        member.extend_from_slice(&[0; 8]); // CRC32 0, ISIZE 0
        member
    }

    // Valid gzip data of exactly `gap` bytes that decodes to nothing.
    fn empty_members_filling(gap: usize) -> Vec<u8> {
        if gap == 0 {
            return Vec::new();
        }
        assert!(gap >= 20, "gap {gap} too small to fill");
        let plain = gzip_at(&[], 6);
        let (count, rest) = (gap / 20, gap % 20);
        if rest == 0 {
            return plain.repeat(count);
        }
        let mut filled = plain.repeat(count - 1);
        filled.extend_from_slice(&empty_member_of_len(20 + rest));
        filled
    }

    fn padded_to(mut contents: Vec<u8>, len: usize) -> Vec<u8> {
        let gap = len - contents.len();
        contents.extend_from_slice(&empty_members_filling(gap));
        assert_eq!(contents.len(), len);
        contents
    }

    #[derive(Debug)]
    struct ReplayRun {
        delivered: Vec<u8>,
        end: Result<(), (io::ErrorKind, ReplayFailure)>,
    }

    // Reads `reader` to its end with `buf_size` reads, keeping only bytes
    // reported by `Ok(n)`; never sees `Interrupted`.
    fn replay_all(reader: &mut StrictReplayReader, buf_size: usize) -> ReplayRun {
        let mut buf = vec![0u8; buf_size];
        let mut delivered = Vec::new();
        let end = loop {
            match reader.read(&mut buf) {
                Ok(0) => break Ok(()),
                Ok(n) => {
                    assert!(n <= DECODE_QUANTUM, "a read returned {n} > quantum");
                    delivered.extend_from_slice(&buf[..n]);
                }
                Err(error) => {
                    assert_ne!(error.kind(), io::ErrorKind::Interrupted);
                    break Err((error.kind(), ReplayFailure::of(&error)));
                }
            }
        };
        ReplayRun { delivered, end }
    }

    // After a failure: every read -- empty or not -- fails again with the
    // same kind and category and never returns data.
    fn assert_stays_failed(
        reader: &mut StrictReplayReader,
        expected: (io::ErrorKind, ReplayFailure),
    ) {
        for size in [0usize, 1, 4096] {
            let mut buf = vec![0u8; size];
            let error = reader.read(&mut buf).unwrap_err();
            assert_eq!((error.kind(), ReplayFailure::of(&error)), expected);
        }
    }

    #[test]
    fn replay_delivers_the_exact_content_for_every_buffer_size() {
        let a = payload_a();
        let (image, path) = preflighted("replay-single", &gzip_member(&a));

        for size in REPLAY_BUFFER_SIZES {
            let run = replay_all(&mut image.replay(), size);
            assert_eq!(run.end, Ok(()), "buffer {size}");
            assert_eq!(run.delivered, a, "buffer {size}");
        }
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn replay_handles_multi_member_streams_with_empty_members() {
        let (a, b) = (payload_a(), payload_b());
        let contents = [gzip_member(&a), gzip_member(&[]), gzip_member(&b)].concat();
        let (image, path) = preflighted("replay-multi", &contents);

        for size in REPLAY_BUFFER_SIZES {
            let run = replay_all(&mut image.replay(), size);
            assert_eq!(run.end, Ok(()));
            assert_eq!(
                run.delivered,
                [a.clone(), b.clone()].concat(),
                "buffer {size}"
            );
        }
        let _ = std::fs::remove_file(&path);
    }

    // Each replay starts from compressed byte 0 with its own position:
    // readers created from the same image, even read interleaved, all
    // deliver the full content.
    #[test]
    fn replays_are_independent_and_repeatable() {
        let a = payload_a();
        let (image, path) = preflighted("replay-repeat", &gzip_member(&a));

        let mut first = image.replay();
        let mut second = image.replay();
        let mut buf = vec![0u8; 1000];
        let n = first.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], &a[..n]);

        let second_run = replay_all(&mut second, 4096);
        let rest_of_first = replay_all(&mut first, 4096);
        let third_run = replay_all(&mut image.replay(), 64 * 1024);

        assert_eq!(second_run.delivered, a);
        assert_eq!([&a[..n], &rest_of_first.delivered[..]].concat(), a);
        assert_eq!(third_run.delivered, a);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn replay_reads_the_opened_file_not_the_path() {
        let a = payload_a();
        let (image, path) = preflighted("replay-swap", &gzip_member(&a));
        let moved = path.with_extension("moved");

        std::fs::rename(&path, &moved).unwrap();
        std::fs::write(&path, gzip_member(b"a different image")).unwrap();
        std::fs::remove_file(&moved).unwrap();
        std::fs::remove_file(&path).unwrap();

        let run = replay_all(&mut image.replay(), 4096);
        assert_eq!(run.end, Ok(()));
        assert_eq!(run.delivered, a);
    }

    // A zero-length read changes nothing; success is sticky.
    #[test]
    fn replay_zero_length_reads_and_success_are_stable() {
        let a = payload_a();
        let (image, path) = preflighted("replay-empty-reads", &gzip_member(&a));
        let mut reader = image.replay();

        for _ in 0..3 {
            assert_eq!(reader.read(&mut []).unwrap(), 0);
        }
        assert!(reader.compressed_consumed().is_some(), "still active");

        let run = replay_all(&mut reader, 4096);
        assert_eq!(run.delivered, a);

        let mut buf = vec![0u8; 4096];
        for _ in 0..3 {
            assert_eq!(reader.read(&mut buf).unwrap(), 0);
            assert_eq!(reader.read(&mut []).unwrap(), 0);
        }
        assert!(reader.compressed_consumed().is_none(), "decoder released");
        let _ = std::fs::remove_file(&path);
    }

    // `logical_size == 0` still verifies the stream on the first non-empty
    // read -- and a zero-length read does not trigger that verification.
    #[test]
    fn replay_of_an_empty_image_still_verifies_the_stream() {
        let (image, path) = preflighted("replay-zero", &gzip_member(&[]));
        assert_eq!(image.logical_size(), 0);

        let mut reader = image.replay();
        assert_eq!(reader.read(&mut []).unwrap(), 0);
        assert!(
            reader.compressed_consumed().is_some(),
            "empty read verified nothing"
        );
        let run = replay_all(&mut reader, 64);
        assert_eq!(run.end, Ok(()));
        assert!(run.delivered.is_empty());

        // The same empty image, altered after Preflight: now it decodes to
        // data (same size), which the replay refuses.
        let len = gzip_member(b"z").len() + 40;
        let (image, path2) = preflighted("replay-zero-mut", &padded_to(gzip_member(&[]), len));
        rewrite_in_place(&path2, &padded_to(gzip_member(b"z"), len));
        let mut reader = image.replay();
        let run = replay_all(&mut reader, 64);
        assert!(run.delivered.is_empty());
        assert_eq!(
            run.end,
            Err((
                io::ErrorKind::InvalidData,
                ReplayFailure::LogicalSizeExceeded
            ))
        );
        assert_stays_failed(
            &mut reader,
            (
                io::ErrorKind::InvalidData,
                ReplayFailure::LogicalSizeExceeded,
            ),
        );

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&path2);
    }

    // The decoder is never asked for more than one quantum per read, even
    // with a large caller buffer.
    #[test]
    fn replay_reads_are_limited_to_the_decode_quantum() {
        let random = pseudo_random(3 << 20, 5);
        let (image, path) = preflighted("replay-quantum", &gzip_at(&random, 0));
        let mut reader = image.replay();
        let mut buf = vec![0u8; 1 << 20];
        let mut total = 0usize;
        loop {
            let n = reader.read(&mut buf).unwrap();
            if n == 0 {
                break;
            }
            assert!(n <= DECODE_QUANTUM);
            assert_eq!(&buf[..n], &random[total..total + n]);
            total += n;
        }
        assert_eq!(total, random.len());
        let _ = std::fs::remove_file(&path);
    }

    // Damage placed after the payload (footer) is only detectable at the
    // end: the read that would deliver the final bytes fails instead, so
    // those bytes are never delivered -- for every buffer size.
    #[test]
    fn replay_withholds_the_final_bytes_when_the_footer_is_damaged_after_preflight() {
        let a = payload_a();
        let logical = a.len();

        for (label, offset_from_end) in [("crc", 8u64), ("isize", 4u64)] {
            for size in REPLAY_BUFFER_SIZES {
                let (image, path) =
                    preflighted(&format!("replay-{label}-{size}"), &gzip_member(&a));
                flip_byte_in_place(&path, offset_from_end);

                let mut reader = image.replay();
                let run = replay_all(&mut reader, size);
                let piece = size.min(DECODE_QUANTUM);

                assert!(
                    run.delivered.len() < logical,
                    "{label}/{size}: final bytes delivered"
                );
                assert!(
                    run.delivered.len() >= logical - piece,
                    "{label}/{size}: stopped early"
                );
                assert_eq!(run.delivered, a[..run.delivered.len()]);
                assert_eq!(
                    run.end,
                    Err((io::ErrorKind::InvalidInput, ReplayFailure::Corrupt))
                );
                assert_stays_failed(
                    &mut reader,
                    (io::ErrorKind::InvalidInput, ReplayFailure::Corrupt),
                );
                let _ = std::fs::remove_file(&path);
            }
        }
    }

    #[test]
    fn replay_fails_on_body_damage_after_preflight_and_stays_failed() {
        let a = payload_a();
        let member = gzip_member(&a);
        let (image, path) = preflighted("replay-body", &member);
        flip_byte_in_place(&path, (member.len() / 2) as u64);

        let mut reader = image.replay();
        let run = replay_all(&mut reader, 4096);
        let (kind, failure) = run.end.unwrap_err();
        assert!(matches!(
            failure,
            ReplayFailure::Corrupt | ReplayFailure::Incomplete
        ));
        assert!(run.delivered.len() < a.len());
        assert_stays_failed(&mut reader, (kind, failure));
        let _ = std::fs::remove_file(&path);
    }

    // Truncating the file after Preflight (footer or body) is detected: the
    // cursor stops at the real end and the decoder reports it.
    #[test]
    fn replay_fails_when_the_file_is_truncated_after_preflight() {
        let a = payload_a();
        let member = gzip_member(&a);

        for cut in [3usize, member.len() / 2] {
            let (image, path) = preflighted(&format!("replay-trunc-{cut}"), &member);
            let file = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
            file.set_len((member.len() - cut) as u64).unwrap();

            let mut reader = image.replay();
            let run = replay_all(&mut reader, 4096);
            assert!(run.delivered.len() < a.len());
            assert_eq!(
                run.end,
                Err((io::ErrorKind::UnexpectedEof, ReplayFailure::Incomplete))
            );
            assert_stays_failed(
                &mut reader,
                (io::ErrorKind::UnexpectedEof, ReplayFailure::Incomplete),
            );
            let _ = std::fs::remove_file(&path);
        }
    }

    #[test]
    fn replay_fails_on_damage_in_a_later_member_after_preflight() {
        let (a, b) = (payload_a(), payload_b());
        let member_b = gzip_member(&b);
        let contents = [gzip_member(&a), member_b.clone()].concat();

        let (image, path) = preflighted("replay-second-crc", &contents);
        flip_byte_in_place(&path, 8);
        let run = replay_all(&mut image.replay(), 4096);
        assert!(run.delivered.len() < a.len() + b.len());
        assert_eq!(
            run.end,
            Err((io::ErrorKind::InvalidInput, ReplayFailure::Corrupt))
        );
        let _ = std::fs::remove_file(&path);

        let (image, path) = preflighted("replay-second-trunc", &contents);
        let file = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        file.set_len((contents.len() - member_b.len() / 2) as u64)
            .unwrap();
        let run = replay_all(&mut image.replay(), 4096);
        assert!(run.delivered.len() < a.len() + b.len());
        assert_eq!(
            run.end,
            Err((io::ErrorKind::UnexpectedEof, ReplayFailure::Incomplete))
        );
        let _ = std::fs::remove_file(&path);
    }

    // Same-size rewrite that decodes to less than Preflight measured: a
    // clean end before `logical_size` is an error, not an EOF.
    #[test]
    fn replay_reports_an_early_end_as_an_error() {
        let long = gzip_at(&vec![0u8; 2 << 20], 9);
        let short = gzip_at(&vec![0u8; 1 << 20], 9);
        let len = long.len().max(short.len()) + 200;

        let (image, path) = preflighted("replay-early", &padded_to(long, len));
        rewrite_in_place(&path, &padded_to(short, len));

        let mut reader = image.replay();
        let run = replay_all(&mut reader, 64 * 1024);
        assert_eq!(run.delivered.len(), 1 << 20);
        assert_eq!(
            run.end,
            Err((io::ErrorKind::UnexpectedEof, ReplayFailure::EndedEarly))
        );
        assert_stays_failed(
            &mut reader,
            (io::ErrorKind::UnexpectedEof, ReplayFailure::EndedEarly),
        );
        let _ = std::fs::remove_file(&path);
    }

    // Same-size rewrite that decodes to more than Preflight measured: the
    // extra output is refused at the logical size, and the final bytes up
    // to it are withheld.
    #[test]
    fn replay_refuses_output_beyond_the_logical_size() {
        let short = gzip_at(&vec![0u8; 1 << 20], 9);
        let long = gzip_at(&vec![0u8; 2 << 20], 9);
        let len = long.len().max(short.len()) + 200;

        let (image, path) = preflighted("replay-longer", &padded_to(short, len));
        rewrite_in_place(&path, &padded_to(long, len));

        let mut reader = image.replay();
        let run = replay_all(&mut reader, 64 * 1024);
        assert!(run.delivered.len() < 1 << 20, "final bytes withheld");
        assert_eq!(
            run.end,
            Err((
                io::ErrorKind::InvalidData,
                ReplayFailure::LogicalSizeExceeded
            ))
        );
        assert_stays_failed(
            &mut reader,
            (
                io::ErrorKind::InvalidData,
                ReplayFailure::LogicalSizeExceeded,
            ),
        );
        let _ = std::fs::remove_file(&path);
    }

    // The source cursor is clamped to the compressed size recorded at open
    // time: bytes appended after Preflight are never read (by design).
    #[test]
    fn replay_ignores_bytes_appended_after_open() {
        let a = payload_a();
        let (image, path) = preflighted("replay-append", &gzip_member(&a));
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        file.write_all(&[0xDE; 4096]).unwrap();

        let run = replay_all(&mut image.replay(), 4096);
        assert_eq!(run.end, Ok(()));
        assert_eq!(run.delivered, a);
        let _ = std::fs::remove_file(&path);
    }

    // The budget applies to replays too: a same-size rewrite into a run of
    // empty members is refused with `InvalidData` carrying the typed budget
    // payload -- not `Interrupted`, not a corruption.
    #[test]
    fn replay_enforces_the_input_budget() {
        let random = pseudo_random(2 << 20, 21);
        let original = gzip_at(&random, 0);
        let len = original.len();
        let (image, path) = preflighted("replay-budget", &original);
        rewrite_in_place(&path, &padded_to(gzip_at(b"x", 6), len));

        let mut reader = image.replay();
        let mut buf = vec![0u8; 64 * 1024];
        let first_error = loop {
            match reader.read(&mut buf) {
                Ok(0) => panic!("unexpected end"),
                Ok(_) => continue,
                Err(error) => break error,
            }
        };
        assert_eq!(first_error.kind(), io::ErrorKind::InvalidData);
        let exceeded = first_error
            .get_ref()
            .and_then(|inner| inner.downcast_ref::<InputBudgetExceeded>())
            .expect("typed budget payload");
        assert!(exceeded.compressed_consumed <= INPUT_BUDGET_CAP + INPUT_BUFFER_LEN as u64 + 64);
        assert_stays_failed(
            &mut reader,
            (
                io::ErrorKind::InvalidData,
                ReplayFailure::InputBudgetExceeded,
            ),
        );
        let _ = std::fs::remove_file(&path);
    }

    // BANK on replay: all the compressible output first, then a run of
    // empty members -- refused within the cap, earlier output not banked.
    #[test]
    fn replay_refuses_empty_members_after_banking_attempt() {
        let zeros = vec![0u8; 16 << 20];
        let bank = gzip_at(&zeros, 9);
        let original = [bank.clone(), gzip_at(&pseudo_random(2 << 20, 3), 0)].concat();
        let len = original.len();
        let (image, path) = preflighted("replay-bank", &original);
        rewrite_in_place(&path, &padded_to(bank.clone(), len));

        let mut reader = image.replay();
        let mut buf = vec![0u8; 64 * 1024];
        let mut delivered = 0usize;
        let error = loop {
            match reader.read(&mut buf) {
                Ok(0) => panic!("unexpected end"),
                Ok(n) => delivered += n,
                Err(error) => break error,
            }
        };
        assert_eq!(delivered, zeros.len());
        let exceeded = error
            .get_ref()
            .and_then(|inner| inner.downcast_ref::<InputBudgetExceeded>())
            .expect("typed budget payload");
        let spent_after_bank = exceeded.compressed_consumed - bank.len() as u64;
        assert!(spent_after_bank <= INPUT_BUDGET_CAP + INPUT_BUFFER_LEN as u64);
        let _ = std::fs::remove_file(&path);
    }

    // The documented work bound holds for a replay reading 1 MiB chunks the
    // way the writer does: per 1 MiB of output, at most
    // cap + 1 MiB * 65/64 + one input buffer of compressed input -- even for
    // a valid file built to use the budget as fully as it allows.
    #[test]
    fn replay_keeps_the_per_chunk_work_bound() {
        let zeros_step = gzip_at(&vec![0u8; 128 * 1024], 9);
        let mut contents = gzip_at(&[], 6).repeat(45_000);
        for _ in 0..8 {
            contents.extend_from_slice(&zeros_step);
            contents.extend_from_slice(&gzip_at(&[], 6).repeat(6_600));
        }
        contents.extend_from_slice(&gzip_at(b"x", 6));
        let (image, path) = preflighted("replay-bound", &contents);

        let chunk = 1usize << 20;
        let bound = INPUT_BUDGET_CAP + (1 << 20) + (1 << 20) / 64 + INPUT_BUFFER_LEN as u64;
        let mut reader = image.replay();
        let mut buf = vec![0u8; chunk];
        let mut delivered = 0usize;
        let mut chunk_start = 0u64;
        loop {
            // Fill one chunk the way `writer::write` does.
            let mut filled = 0;
            while filled < chunk {
                match reader.read(&mut buf[filled..]).unwrap() {
                    0 => break,
                    n => filled += n,
                }
            }
            if let Some(consumed) = reader.compressed_consumed() {
                assert!(
                    consumed - chunk_start <= bound,
                    "chunk used {}",
                    consumed - chunk_start
                );
                chunk_start = consumed;
            }
            delivered += filled;
            if filled < chunk {
                break;
            }
        }
        assert_eq!(delivered as u64, image.logical_size());
        let _ = std::fs::remove_file(&path);
    }
}
