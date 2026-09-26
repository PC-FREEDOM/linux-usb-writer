// Compressed image validation (Preflight). A `CompressedImageFile` (gzip or
// xz content, detected by `open_image`) is turned into a
// `PreflightedCompressedImage` only by decoding the whole compressed stream
// once, end to end: every member/stream, every integrity check, and every
// compressed byte must be accounted for, and the exact decompressed size is
// measured on the way. Nothing here writes anywhere or knows about targets;
// the decoded bytes are counted and discarded.
//
// Layering of the decode pipeline (bottom to top):
//
//   source cursor    positional reads (`pread`) over the one `File` that
//                    `open_image` opened, starting at byte 0, clamped to the
//                    compressed size recorded at open time
//   BufReader        buffering for the syscalls
//   CountingBufRead  counts what the decoder actually `consume()`s, runs a
//                    check before every `fill_buf()` (cancellation, then the
//                    Compressed Input Budget below), and tags any error from
//                    below as a source I/O error
//   FormatDecoder    the format's decoder, which the decode loops use:
//     gzip           `MultiGzDecoder`: every member, CRC32 + ISIZE per
//                    member, and any trailing bytes rejected (behavior pinned
//                    by `gzip_behavior` tests)
//     xz             liblzma's .xz stream decoder (never the auto decoder, so
//                    legacy .lzma / .lz data is refused): every concatenated
//                    stream, Stream Padding accepted only in multiples of
//                    four zero bytes (the .xz format's own rule -- unlike
//                    gzip, where trailing zeros are refused), every Block
//                    Check, Index and Stream Footer verified; a stream
//                    without an integrity check (Check=None) or with a check
//                    type liblzma cannot verify is refused, and so is a Block
//                    needing more than `XZ_DECODER_MEMLIMIT` of decoder
//                    memory (behavior pinned by `xz_behavior` tests)
//
// Errors are classified by type, never by message text: cancellation, budget
// exhaustion and source I/O failures travel through the decoder as typed
// payloads (`PreflightCancelled` / `InputBudgetExceeded` /
// `SourceReadError`), which both decoders pass through unchanged (see
// `gzip_behavior::errors_from_below_the_decoder_propagate_unchanged` and
// `xz_behavior::x23_errors_from_below_the_decoder_propagate_unchanged`);
// liblzma's own errors carry a typed `liblzma::stream::Error`; anything else
// came from the decoder itself.
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
use liblzma::bufread::XzDecoder;
use liblzma::stream::{CONCATENATED, Stream, TELL_NO_CHECK, TELL_UNSUPPORTED_CHECK};

use super::source_identity::{SourceChanged, SourceIdentity};
use super::{
    CompressedImageFile, CompressionFormat, FileImageReader, ImageSource, ImageSourceAccess,
};

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
// XZ decoder memory limit: the most memory liblzma may estimate a Block's
// filter chain needs (essentially its dictionary) -- checked when each Block
// Header is read, before that memory is allocated. Not a limit on the
// process's own memory use. Covers every standard preset (`xz -9` needs
// about 65 MiB); a Block declaring more is refused with
// `DecoderMemoryLimitExceeded`. Fixed for v0.1.
const XZ_DECODER_MEMLIMIT: u64 = 512 * 1024 * 1024;
// XZ decoder flags: report Check=None and unsupported check types (without
// these liblzma decodes such streams without verifying anything), and decode
// every concatenated stream and the Stream Padding between them (without it
// the decoder ends after the first stream).
const XZ_DECODER_FLAGS: u32 = TELL_NO_CHECK | TELL_UNSUPPORTED_CHECK | CONCATENATED;

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
    // or stream -- for xz also invalid Stream Padding and options liblzma
    // cannot decode (unknown filters, reserved bits) (the decoder's own error
    // is kept for diagnostics).
    Corrupt(io::Error),
    // The compressed data ended before a complete stream (the decoder's own
    // error is kept). Short trailing garbage after a valid member also
    // surfaces here: the decoder cannot tell it apart from a truncated next
    // member, and either way the image is rejected.
    Incomplete(io::Error),
    // xz only: a stream carries no integrity check (Check=None), so its
    // content could not be verified. Refused in every stream of the file.
    IntegrityCheckMissing,
    // xz only: a stream's integrity check type is not one liblzma can verify
    // (a reserved or unknown Check ID). Refused in every stream of the file.
    UnsupportedIntegrityCheck,
    // xz only: a Block needs more decoder memory than `limit` (see
    // `XZ_DECODER_MEMLIMIT`). The data is not necessarily damaged; decoding
    // it is refused as a resource policy.
    DecoderMemoryLimitExceeded {
        limit: u64,
    },
    // The decoder itself could not start or continue (e.g. it could not
    // allocate memory, or reported an internal error) -- not attributed to
    // the compressed data. The decoder's own error is kept.
    DecoderFailure(io::Error),
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
    // Validation for this compression format is not implemented. Every
    // `CompressionFormat` is validated now, so Preflight no longer returns
    // this; kept until the callers that display it are updated.
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
    // The snapshot taken when `open_image` opened the file -- deliberately
    // not refreshed by Preflight, so a change at any point after selection
    // (including during Preflight) is still detected.
    identity: SourceIdentity,
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

    // Confirms the file is still in the state it was selected in (see
    // `source_identity`): the reference is the snapshot from `open_image`,
    // not from the end of Preflight.
    pub fn revalidate_identity(&self) -> Result<(), SourceChanged> {
        self.identity.revalidate(&self.file)
    }

    // Starts a fresh decode of the validated stream: a new reader over the
    // same open file (never re-opened by path), from compressed byte 0, with
    // its own independent position -- so this can be called any number of
    // times (e.g. once to write, once more to verify), and no replay affects
    // another. The reader enforces everything Preflight established; see
    // `StrictReplayReader`. It decodes with the format Preflight validated
    // (`self.format`, never re-detected). Nothing is read here: the only
    // error is the decoder failing to set up (xz only, e.g. out of memory),
    // reported as a `ReplayFailure::DecoderFailure` whose source is
    // liblzma's own error; every other error surfaces from `read()`.
    pub fn replay(&self) -> io::Result<StrictReplayReader> {
        StrictReplayReader::new(
            &self.file,
            self.format,
            self.compressed_size,
            self.logical_size,
        )
    }
}

// A validated compressed image as an `ImageSource`: what the write and Verify
// paths read from. A thin wrapper -- everything it provides comes from the
// `PreflightedCompressedImage` it owns:
//
//   - `logical_size()` is the decoded size Preflight measured, never the
//     compressed file's size;
//   - `open_reader()` is a fresh `replay()` (a `StrictReplayReader` from
//     logical byte 0, over the same open file, with its own position), so
//     the write and a later Full Verify each decode independently;
//   - `access()` is `SequentialReplay`: a gzip or xz stream cannot be read
//     at an arbitrary offset without decoding everything before it, so `read_at`
//     keeps the trait's `Unsupported` default and Quick Verify refuses this
//     source;
//   - `revalidate_identity()` checks against the snapshot `open_image` took,
//     which Preflight did not refresh.
//
// Not `Clone`, like the value it wraps.
#[derive(Debug)]
pub struct CompressedImageSource {
    preflighted: PreflightedCompressedImage,
}

impl CompressedImageSource {
    pub fn new(preflighted: PreflightedCompressedImage) -> Self {
        CompressedImageSource { preflighted }
    }

    // For display only, like `FileImageSource::path()`.
    pub fn path(&self) -> &Path {
        self.preflighted.path()
    }
}

impl ImageSource for CompressedImageSource {
    fn logical_size(&self) -> u64 {
        self.preflighted.logical_size()
    }

    fn access(&self) -> ImageSourceAccess {
        ImageSourceAccess::SequentialReplay
    }

    // Replay errors keep their typed payloads inside the `io::Error` (see
    // `StrictReplayReader`); nothing here re-wraps them.
    fn open_reader(&self) -> io::Result<Box<dyn Read>> {
        Ok(Box::new(self.preflighted.replay()?))
    }

    fn revalidate_identity(&self) -> Result<(), SourceChanged> {
        self.preflighted.revalidate_identity()
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
        let file = Arc::new(self.file);
        let input =
            BufReader::with_capacity(INPUT_BUFFER_LEN, source_cursor(&file, self.compressed_size));

        let logical_size = preflight_stream(
            self.format,
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
            identity: self.identity,
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

// Validates a `format` stream read from `input` and returns its decoded
// size. The same decode loop, checks and success conditions serve every
// format; only the decoder differs. Generic over the input so tests can
// inject source failures; production passes the buffered source cursor.
//
// Success needs all of: the decoder's own clean end of stream (for xz,
// after every concatenated stream and the Stream Padding), a decoded size
// within `options`, and exactly the whole compressed size consumed. Output
// that merely reaches some size is never taken as success: a damaged
// footer, Index or check can still be reported after all of it.
fn preflight_stream(
    format: CompressionFormat,
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

        let counted = CountingBufRead::new(input, hook);
        let mut decoder = match format {
            CompressionFormat::Gzip => FormatDecoder::gzip(counted),
            CompressionFormat::Xz => {
                FormatDecoder::xz(counted).map_err(PreflightError::DecoderFailure)?
            }
        };
        let decoded = decode_to_end(&mut decoder, options, &logical_produced);
        (decoded, decoder.input().consumed())
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
// then liblzma's typed errors, then the decoder's own errors by kind.
// Message text is never inspected.
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

    // liblzma's own errors (xz only; gzip errors never carry this payload).
    if let Some(lzma) = error
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<liblzma::stream::Error>())
        .copied()
    {
        use liblzma::stream::Error as Lzma;
        return match lzma {
            Lzma::NoCheck => PreflightError::IntegrityCheckMissing,
            Lzma::UnsupportedCheck => PreflightError::UnsupportedIntegrityCheck,
            Lzma::MemLimit => PreflightError::DecoderMemoryLimitExceeded {
                limit: XZ_DECODER_MEMLIMIT,
            },
            Lzma::Mem | Lzma::Program => PreflightError::DecoderFailure(error),
            Lzma::Data | Lzma::Format | Lzma::Options => PreflightError::Corrupt(error),
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
// Format decoders.
// ---------------------------------------------------------------------

// The decoder for one compression format, reading compressed bytes from
// `R` (the counted input below it). Everything above -- Preflight's decode
// loop and `StrictReplayReader`'s strict end-of-stream state machine -- is
// written once against this type; only the construction and the per-format
// decoder differ. A plain enum: `read()` delegates straight to the wrapped
// decoder (no extra buffering or copying), and `input()` reaches the
// counted input for the exact-consumption checks.
enum FormatDecoder<R: BufRead> {
    Gzip(MultiGzDecoder<R>),
    Xz(XzDecoder<R>),
}

impl<R: BufRead> FormatDecoder<R> {
    // Every member, CRC32 + ISIZE per member, trailing bytes rejected (see
    // the module comment and `gzip_behavior`).
    fn gzip(input: R) -> Self {
        FormatDecoder::Gzip(MultiGzDecoder::new(input))
    }

    // liblzma's .xz stream decoder with `XZ_DECODER_MEMLIMIT` and
    // `XZ_DECODER_FLAGS` (see the module comment and `xz_behavior`).
    // Fails only if liblzma cannot set the decoder up (e.g. out of memory);
    // the error carries liblzma's typed `Error`.
    fn xz(input: R) -> io::Result<Self> {
        let stream = Stream::new_stream_decoder(XZ_DECODER_MEMLIMIT, XZ_DECODER_FLAGS)?;
        Ok(FormatDecoder::Xz(XzDecoder::new_stream(input, stream)))
    }

    // The input the decoder reads from, never the decoder's own buffering.
    fn input(&self) -> &R {
        match self {
            FormatDecoder::Gzip(decoder) => decoder.get_ref(),
            FormatDecoder::Xz(decoder) => decoder.get_ref(),
        }
    }
}

impl<R: BufRead> Read for FormatDecoder<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            FormatDecoder::Gzip(decoder) => decoder.read(buf),
            FormatDecoder::Xz(decoder) => decoder.read(buf),
        }
    }
}

// ---------------------------------------------------------------------
// Replay: decoding a validated stream again, strictly.
// ---------------------------------------------------------------------

// The check run before every `fill_buf()` during a replay: the Compressed
// Input Budget only (a replay has no cancellation hook of its own; the
// budget keeps each `read()` short enough for the caller's own checks).
type ReplayHook = Box<dyn FnMut(u64) -> io::Result<()> + Send>;
type ReplayDecoder = FormatDecoder<CountingBufRead<BufReader<FileImageReader>, ReplayHook>>;

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
    // xz: a stream carries no integrity check (Check=None).
    IntegrityCheckMissing,
    // xz: a stream's integrity check type cannot be verified.
    UnsupportedIntegrityCheck,
    // xz: a Block needs more decoder memory than `limit`.
    DecoderMemoryLimitExceeded { limit: u64 },
    // The decoder could not be set up or could not continue, not attributed
    // to the data (the first error returned keeps the decoder's own error).
    DecoderFailure,
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
            if inner.is::<DecoderSetupFailed>() {
                return ReplayFailure::DecoderFailure;
            }
            // liblzma's own errors (xz only), classified as in Preflight.
            if let Some(lzma) = inner.downcast_ref::<liblzma::stream::Error>() {
                use liblzma::stream::Error as Lzma;
                return match lzma {
                    Lzma::NoCheck => ReplayFailure::IntegrityCheckMissing,
                    Lzma::UnsupportedCheck => ReplayFailure::UnsupportedIntegrityCheck,
                    Lzma::MemLimit => ReplayFailure::DecoderMemoryLimitExceeded {
                        limit: XZ_DECODER_MEMLIMIT,
                    },
                    Lzma::Mem | Lzma::Program => ReplayFailure::DecoderFailure,
                    Lzma::Data | Lzma::Format | Lzma::Options => ReplayFailure::Corrupt,
                };
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

// Payload of the error `replay()` returns when the decoder cannot be set up;
// keeps the decoder's own error as its source.
#[derive(Debug)]
struct DecoderSetupFailed(io::Error);

impl fmt::Display for DecoderSetupFailed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "the decompressor could not be set up: {}", self.0)
    }
}

impl std::error::Error for DecoderSetupFailed {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
    }
}

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
    // A reader over `file` (the one Preflight validated, shared -- never
    // re-opened) decoding `format`. Only the decoder's construction depends
    // on the format; the state machine below is the same for every format.
    fn new(
        file: &Arc<File>,
        format: CompressionFormat,
        compressed_size: u64,
        logical_size: u64,
    ) -> io::Result<Self> {
        let credited = Arc::new(AtomicU64::new(0));
        let mut budget = InputBudgetMeter::new();
        let hook_credited = Arc::clone(&credited);
        let hook: ReplayHook = Box::new(move |consumed: u64| {
            budget.update(consumed, hook_credited.load(Ordering::Relaxed))
        });

        let input =
            BufReader::with_capacity(INPUT_BUFFER_LEN, source_cursor(file, compressed_size));
        let counted = CountingBufRead::new(input, hook);
        let decoder = Box::new(match format {
            CompressionFormat::Gzip => FormatDecoder::gzip(counted),
            CompressionFormat::Xz => FormatDecoder::xz(counted)
                .map_err(|error| io::Error::other(DecoderSetupFailed(error)))?,
        });

        Ok(StrictReplayReader {
            logical_size,
            compressed_size,
            state: ReplayState::Active {
                decoder,
                produced: 0,
                credited,
            },
        })
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
            ReplayState::Active { decoder, .. } => Some(decoder.input().consumed()),
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
    if decoder.input().consumed() != compressed_size {
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

        let result = preflight_stream(
            CompressionFormat::Gzip,
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
                let result = preflight_stream(
                    CompressionFormat::Gzip,
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
        preflight_stream(
            CompressionFormat::Gzip,
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
            let result = preflight_stream(
                CompressionFormat::Gzip,
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
            let result = preflight_stream(
                CompressionFormat::Gzip,
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
        let result = preflight_stream(
            CompressionFormat::Gzip,
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
    // xz Preflight: the same entry point, loop and success conditions as
    // gzip, with liblzma's .xz stream decoder (behavior pinned in detail by
    // `xz_behavior`; these tests go through `CompressedImageFile::preflight`
    // or `preflight_stream`).
    // ---------------------------------------------------------------------

    // One .xz stream with one Block (preset 0: a 256 KiB dictionary).
    fn xz_stream(payload: &[u8], check: liblzma::stream::Check) -> Vec<u8> {
        let stream = Stream::new_easy_encoder(0, check).unwrap();
        let mut encoder = liblzma::write::XzEncoder::new_stream(Vec::new(), stream);
        encoder.write_all(payload).unwrap();
        encoder.finish().unwrap()
    }

    fn crc64_stream(payload: &[u8]) -> Vec<u8> {
        xz_stream(payload, liblzma::stream::Check::Crc64)
    }

    fn write_xz_file(tag: &str, contents: &[u8]) -> PathBuf {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "linux-usb-writer-preflight-test-{tag}-{}-{id}.img.xz",
            std::process::id()
        ));
        std::fs::write(&path, contents).expect("write temp xz file");
        path
    }

    // `preflight_contents` for `.xz` files.
    fn preflight_xz(
        tag: &str,
        contents: &[u8],
        options: PreflightOptions,
    ) -> (
        Result<PreflightedCompressedImage, PreflightError>,
        Vec<PreflightProgress>,
    ) {
        let path = write_xz_file(tag, contents);
        let file = open_compressed(&path);
        assert_eq!(file.format(), CompressionFormat::Xz);
        let mut reports = Vec::new();
        let result = file.preflight(options, || false, |progress| reports.push(progress));
        let _ = std::fs::remove_file(&path);
        (result, reports)
    }

    // Asserts `contents` validates to exactly `expected_size` decoded bytes,
    // with the whole compressed file consumed (the final progress report is
    // exact).
    fn assert_xz_validated(tag: &str, contents: &[u8], expected_size: u64) {
        let (result, reports) = preflight_xz(tag, contents, NO_LIMIT);
        let preflighted = result.unwrap_or_else(|error| panic!("{tag}: {error:?}"));
        assert_eq!(preflighted.format(), CompressionFormat::Xz);
        assert_eq!(preflighted.logical_size(), expected_size, "{tag}");
        assert_eq!(preflighted.compressed_size(), contents.len() as u64);
        assert_eq!(
            reports.last(),
            Some(&PreflightProgress {
                compressed_consumed: contents.len() as u64,
                compressed_total: contents.len() as u64,
                logical_produced: expected_size,
            }),
            "{tag}"
        );
    }

    fn xz_error(tag: &str, contents: &[u8]) -> PreflightError {
        match preflight_xz(tag, contents, NO_LIMIT).0 {
            Err(error) => error,
            Ok(preflighted) => panic!(
                "{tag}: expected a rejection, validated {} bytes",
                preflighted.logical_size()
            ),
        }
    }

    fn crc32(bytes: &[u8]) -> u32 {
        let mut crc = flate2::Crc::new();
        crc.update(bytes);
        crc.sum()
    }

    // Offsets inside a single .xz stream, located from the Stream Footer's
    // Backward Size: where the Index starts, and where the footer starts.
    fn xz_index_start(stream: &[u8]) -> usize {
        let footer = stream.len() - 12;
        let backward = u32::from_le_bytes(stream[footer + 4..footer + 8].try_into().unwrap());
        footer - (backward as usize + 1) * 4
    }

    // Rewrites the Check ID in a single stream's Stream Header and Footer,
    // recomputing both CRC32s (IDs must share a check-field size). See
    // `xz_behavior::with_check_id`.
    fn with_check_id(stream: &[u8], check_id: u8) -> Vec<u8> {
        let mut patched = stream.to_vec();
        patched[7] = check_id;
        let header_crc = crc32(&patched[6..8]);
        patched[8..12].copy_from_slice(&header_crc.to_le_bytes());
        let footer = patched.len() - 12;
        patched[footer + 9] = check_id;
        let footer_crc = crc32(&patched[footer + 4..footer + 10]);
        patched[footer..footer + 4].copy_from_slice(&footer_crc.to_le_bytes());
        patched
    }

    // Rewrites the LZMA2 dictionary byte of a single stream's first Block
    // Header and recomputes its CRC32. See
    // `xz_behavior::with_declared_dictionary`.
    fn with_declared_dictionary(stream: &[u8], dictionary_byte: u8) -> Vec<u8> {
        let mut patched = stream.to_vec();
        let header_len = (patched[12] as usize + 1) * 4;
        assert_eq!(&patched[13..16], &[0x00, 0x21, 0x01], "one LZMA2 filter");
        patched[16] = dictionary_byte;
        let crc_at = 12 + header_len - 4;
        let crc = crc32(&patched[12..crc_at]);
        patched[crc_at..crc_at + 4].copy_from_slice(&crc.to_le_bytes());
        patched
    }

    // X1-X3: every check type liblzma can verify is accepted, with the
    // exact decoded size and the whole file consumed.
    #[test]
    fn xz_with_every_supported_check_is_validated_with_its_exact_size() {
        use liblzma::stream::Check;
        let a = payload_a();

        for (name, check) in [
            ("crc32", Check::Crc32),
            ("crc64", Check::Crc64),
            ("sha256", Check::Sha256),
        ] {
            assert_xz_validated(&format!("xz-{name}"), &xz_stream(&a, check), a.len() as u64);
        }
    }

    // X4-X5: concatenated streams are one image; its size is the sum.
    #[test]
    fn xz_concatenated_streams_are_validated_as_one_image() {
        use liblzma::stream::Check;
        let (a, b) = (payload_a(), payload_b());
        let sa = xz_stream(&a, Check::Crc32);
        let sb = xz_stream(&b, Check::Sha256);
        let empty = crc64_stream(&[]);
        let ab = (a.len() + b.len()) as u64;

        assert_xz_validated("xz-concat-2", &[sa.clone(), sb.clone()].concat(), ab);
        assert_xz_validated("xz-concat-3", &[sa, empty, sb].concat(), ab);
    }

    // X6-X7: Stream Padding (multiples of four zero bytes) is accepted
    // between streams and after the last one -- the .xz format's own rule,
    // unlike gzip's refusal of trailing zeros.
    #[test]
    fn xz_stream_padding_between_and_after_streams_is_accepted() {
        let (a, b) = (payload_a(), payload_b());
        let (sa, sb) = (crc64_stream(&a), crc64_stream(&b));
        let ab = (a.len() + b.len()) as u64;
        let zeros = |len: usize| vec![0u8; len];

        assert_xz_validated(
            "xz-pad-between",
            &[sa.clone(), zeros(8), sb.clone()].concat(),
            ab,
        );
        assert_xz_validated(
            "xz-pad-final-4",
            &[sa.clone(), zeros(4)].concat(),
            a.len() as u64,
        );
        assert_xz_validated("xz-pad-both", &[sa, zeros(4), sb, zeros(12)].concat(), ab);
    }

    // X16: padding of any other length is corrupt.
    #[test]
    fn xz_invalid_stream_padding_is_corrupt() {
        let a = payload_a();
        let (sa, sb) = (crc64_stream(&a), crc64_stream(&payload_b()));

        for len in [1, 2, 3, 5, 6, 7] {
            let tail = [sa.clone(), vec![0u8; len]].concat();
            let error = xz_error("xz-pad-bad-tail", &tail);
            assert!(
                matches!(error, PreflightError::Corrupt(_)),
                "{len}: {error:?}"
            );

            let between = [sa.clone(), vec![0u8; len], sb.clone()].concat();
            let error = xz_error("xz-pad-bad-between", &between);
            assert!(
                matches!(error, PreflightError::Corrupt(_)),
                "{len}: {error:?}"
            );
        }
    }

    // X8-X9: Check=None is refused, in the first stream and in a later one.
    #[test]
    fn xz_without_an_integrity_check_is_refused_in_any_stream() {
        use liblzma::stream::Check;
        let a = payload_a();
        let none = xz_stream(&payload_b(), Check::None);

        let error = xz_error("xz-none-first", &none);
        assert!(
            matches!(error, PreflightError::IntegrityCheckMissing),
            "{error:?}"
        );

        let later = [crc64_stream(&a), vec![0u8; 4], none].concat();
        let error = xz_error("xz-none-second", &later);
        assert!(
            matches!(error, PreflightError::IntegrityCheckMissing),
            "{error:?}"
        );
    }

    // X10: a reserved Check ID is refused, in the first stream and in a
    // later one.
    #[test]
    fn xz_with_an_unsupported_check_is_refused_in_any_stream() {
        let reserved = with_check_id(&crc64_stream(&payload_b()), 5);

        let error = xz_error("xz-reserved-first", &reserved);
        assert!(
            matches!(error, PreflightError::UnsupportedIntegrityCheck),
            "{error:?}"
        );

        let later = [crc64_stream(&payload_a()), reserved].concat();
        let error = xz_error("xz-reserved-second", &later);
        assert!(
            matches!(error, PreflightError::UnsupportedIntegrityCheck),
            "{error:?}"
        );
    }

    // X11: a Block declaring a 1.5 GiB dictionary exceeds the 512 MiB decoder
    // memory limit (refused before that memory is allocated); a 64 MiB
    // dictionary (`xz -9`) is within it.
    #[test]
    fn xz_over_the_decoder_memory_limit_is_refused() {
        let a = payload_a();
        let stream = crc64_stream(&a);

        let error = xz_error("xz-memlimit", &with_declared_dictionary(&stream, 40));
        assert!(
            matches!(
                error,
                PreflightError::DecoderMemoryLimitExceeded { limit } if limit == XZ_DECODER_MEMLIMIT
            ),
            "{error:?}"
        );
        assert_eq!(XZ_DECODER_MEMLIMIT, 512 * 1024 * 1024);

        assert_xz_validated(
            "xz-memlimit-64m",
            &with_declared_dictionary(&stream, 28),
            a.len() as u64,
        );
    }

    // X12-X13: damage found only after the whole payload was decoded -- a
    // Block Check, the Index, the Stream Footer -- is corrupt: reaching the
    // payload's size is never taken as success.
    #[test]
    fn xz_damage_after_the_payload_is_corrupt() {
        let stream = crc64_stream(&payload_a());
        let index = xz_index_start(&stream);
        let footer = stream.len() - 12;

        for (name, position) in [
            ("block-check", index - 1),
            ("index-count", index + 1),
            ("index-crc", footer - 1),
            ("footer-crc", footer),
            ("footer-backward-size", footer + 4),
            ("footer-magic", footer + 11),
        ] {
            let error = xz_error(
                &format!("xz-{name}"),
                &flip(&stream, stream.len() - position),
            );
            assert!(
                matches!(error, PreflightError::Corrupt(_)),
                "{name}: {error:?}"
            );
        }
    }

    // X14: a truncated file is incomplete, wherever it is cut -- in the
    // header, the Block, the Index or the footer. A bare header fragment (the
    // old "xz is not validated yet" fixture) is incomplete too.
    #[test]
    fn truncated_xz_is_incomplete() {
        let stream = crc64_stream(&payload_b());
        let mut cuts: Vec<usize> = (7..stream.len()).step_by(97).collect();
        cuts.extend([12, stream.len() - 12, stream.len() - 1]);

        for cut in cuts {
            let error = xz_error("xz-truncated", &stream[..cut]);
            assert!(
                matches!(error, PreflightError::Incomplete(_)),
                "{cut}: {error:?}"
            );
        }

        let fragment = [0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00, 0x00, 0x04];
        let error = xz_error("xz-fragment", &fragment);
        assert!(matches!(error, PreflightError::Incomplete(_)), "{error:?}");
    }

    // X15: trailing garbage is never accepted -- incomplete when shorter
    // than a Stream Header (12 bytes), corrupt otherwise.
    #[test]
    fn xz_trailing_garbage_is_refused() {
        let stream = crc64_stream(&payload_a());

        for len in [1, 5, 11] {
            let error = xz_error(
                "xz-garbage-short",
                &[stream.clone(), vec![0xAA; len]].concat(),
            );
            assert!(
                matches!(error, PreflightError::Incomplete(_)),
                "{len}: {error:?}"
            );
        }
        for len in [12, 64] {
            let error = xz_error(
                "xz-garbage-long",
                &[stream.clone(), vec![0xAA; len]].concat(),
            );
            assert!(
                matches!(error, PreflightError::Corrupt(_)),
                "{len}: {error:?}"
            );
        }
    }

    // X17: the logical size limit applies as for gzip: exactly at the limit
    // is allowed, one byte over is refused.
    #[test]
    fn xz_logical_size_limit_is_enforced() {
        let a = payload_a();
        let contents = [crc64_stream(&a), crc64_stream(&a)].concat();
        let size = 2 * a.len() as u64;

        let (at_limit, _) = preflight_xz(
            "xz-limit-at",
            &contents,
            PreflightOptions {
                max_logical_size: size,
            },
        );
        assert_eq!(at_limit.unwrap().logical_size(), size);

        let (over, _) = preflight_xz(
            "xz-limit-over",
            &contents,
            PreflightOptions {
                max_logical_size: size - 1,
            },
        );
        assert!(
            matches!(over, Err(PreflightError::LogicalSizeLimitExceeded { limit }) if limit == size - 1),
            "{over:?}"
        );
    }

    // X18: cancellation -- before anything is read, during decoding, and
    // while the decoder is only consuming Stream Padding (no output).
    #[test]
    fn xz_preflight_can_be_cancelled() {
        let contents = crc64_stream(&payload_a());

        let path = write_xz_file("xz-cancel-before", &contents);
        let mut reports = 0;
        let result = open_compressed(&path).preflight(NO_LIMIT, || true, |_| reports += 1);
        let _ = std::fs::remove_file(&path);
        assert!(matches!(result, Err(PreflightError::Cancelled)));
        assert_eq!(reports, 0);

        // Large enough for many decoder reads (the xz decoder polls its input
        // once per read, so a 64 KiB image finishes within three checks).
        let path = write_xz_file(
            "xz-cancel-during",
            &crc64_stream(&pseudo_random(1 << 20, 5)),
        );
        let checks = Cell::new(0u32);
        let result = open_compressed(&path).preflight(
            NO_LIMIT,
            || {
                checks.set(checks.get() + 1);
                checks.get() > 3
            },
            |_| {},
        );
        let _ = std::fs::remove_file(&path);
        assert!(matches!(result, Err(PreflightError::Cancelled)));

        let padded = [contents, vec![0u8; 256 * 1024]].concat();
        let checks = Cell::new(0u32);
        let mut is_cancelled = || {
            checks.set(checks.get() + 1);
            checks.get() > 2_000
        };
        let result = preflight_stream(
            CompressionFormat::Xz,
            scripted(&padded, None),
            padded.len() as u64,
            NO_LIMIT,
            &mut is_cancelled,
            &mut |_| {},
        );
        assert!(
            matches!(result, Err(PreflightError::Cancelled)),
            "{result:?}"
        );
    }

    // X19: the Compressed Input Budget applies unchanged: ordinary xz is
    // accepted within the documented bound; a run of empty streams, or a
    // very long Stream Padding, is refused within the cap plus one input
    // buffer -- as a resource policy, though the data is valid.
    #[test]
    fn xz_compressed_input_budget_applies_unchanged() {
        let random = pseudo_random(1 << 20, 23);
        let contents = crc64_stream(&random);
        let (result, reports) = preflight_xz("xz-budget-ok", &contents, NO_LIMIT);
        assert_eq!(result.unwrap().logical_size(), random.len() as u64);
        for report in reports {
            let logical = report.logical_produced;
            assert!(
                report.compressed_consumed
                    <= INPUT_BUDGET_CAP + logical + logical / 64 + INPUT_BUFFER_LEN as u64
            );
        }

        let empty_run = crc64_stream(&[]).repeat(80_000);
        let (consumed, logical) = match xz_error("xz-budget-empty", &empty_run) {
            PreflightError::CompressedInputBudgetExceeded {
                compressed_consumed,
                logical_produced,
            } => (compressed_consumed, logical_produced),
            other => panic!("expected CompressedInputBudgetExceeded, got {other:?}"),
        };
        assert_eq!(logical, 0);
        assert!(consumed > INPUT_BUDGET_CAP);
        assert!(consumed <= INPUT_BUDGET_CAP + INPUT_BUFFER_LEN as u64);

        let long_padding = [crc64_stream(b"x"), vec![0u8; 4 << 20]].concat();
        let error = xz_error("xz-budget-padding", &long_padding);
        assert!(
            matches!(error, PreflightError::CompressedInputBudgetExceeded { .. }),
            "{error:?}"
        );
    }

    // X20: a failing source is `Io`, never corrupt or incomplete -- at every
    // point of the stream, including inside the Stream Padding.
    #[test]
    fn xz_source_failures_are_io() {
        let contents = [crc64_stream(&payload_b()), vec![0u8; 256]].concat();

        for fail_at in [0, 13, contents.len() / 2, contents.len() - 100] {
            for kind in [io::ErrorKind::UnexpectedEof, io::ErrorKind::InvalidData] {
                let result = preflight_stream(
                    CompressionFormat::Xz,
                    scripted(&contents, Some((fail_at, kind))),
                    contents.len() as u64,
                    NO_LIMIT,
                    &mut || false,
                    &mut |_| {},
                );
                match result {
                    Err(PreflightError::Io(error)) => assert_eq!(error.kind(), kind),
                    other => panic!("fail_at={fail_at} {kind:?}: expected Io, got {other:?}"),
                }
            }
        }
    }

    // X20: a clean end is only success with the whole compressed size
    // consumed: a stream followed by bytes the cursor never reaches (the
    // size given is larger than the data) is not success.
    #[test]
    fn xz_success_requires_exact_input_consumption() {
        let contents = crc64_stream(&payload_a());

        let exact = preflight_stream(
            CompressionFormat::Xz,
            scripted(&contents, None),
            contents.len() as u64,
            NO_LIMIT,
            &mut || false,
            &mut |_| {},
        );
        assert_eq!(exact.unwrap(), payload_a().len() as u64);

        let result = preflight_stream(
            CompressionFormat::Xz,
            scripted(&contents, None),
            contents.len() as u64 + 4,
            NO_LIMIT,
            &mut || false,
            &mut |_| {},
        );
        assert!(
            matches!(
                result,
                Err(PreflightError::InputConsumptionMismatch { consumed, compressed_size })
                    if consumed == contents.len() as u64 && compressed_size == consumed + 4
            ),
            "{result:?}"
        );
    }

    // Every typed liblzma error maps to its Preflight category; the crate's
    // untyped end-of-input error is incomplete. (Mem / Program / decoder
    // setup failures cannot be provoked from data, so the mapping itself is
    // checked here.)
    #[test]
    fn liblzma_errors_are_classified_by_type() {
        use liblzma::stream::Error as Lzma;
        let classify = |lzma: Lzma| classify_error(io::Error::from(lzma));

        assert!(matches!(
            classify(Lzma::NoCheck),
            PreflightError::IntegrityCheckMissing
        ));
        assert!(matches!(
            classify(Lzma::UnsupportedCheck),
            PreflightError::UnsupportedIntegrityCheck
        ));
        assert!(matches!(
            classify(Lzma::MemLimit),
            PreflightError::DecoderMemoryLimitExceeded { limit } if limit == XZ_DECODER_MEMLIMIT
        ));
        for lzma in [Lzma::Mem, Lzma::Program] {
            assert!(
                matches!(classify(lzma), PreflightError::DecoderFailure(_)),
                "{lzma:?}"
            );
        }
        for lzma in [Lzma::Data, Lzma::Format, Lzma::Options] {
            assert!(
                matches!(classify(lzma), PreflightError::Corrupt(_)),
                "{lzma:?}"
            );
        }

        let premature = io::Error::new(io::ErrorKind::UnexpectedEof, "premature eof");
        assert!(matches!(
            classify_error(premature),
            PreflightError::Incomplete(_)
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
        let exceeded = preflight_stream(
            CompressionFormat::Gzip,
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
        let cancelled = preflight_stream(
            CompressionFormat::Gzip,
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
            let run = replay_all(&mut image.replay().unwrap(), size);
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
            let run = replay_all(&mut image.replay().unwrap(), size);
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

        let mut first = image.replay().unwrap();
        let mut second = image.replay().unwrap();
        let mut buf = vec![0u8; 1000];
        let n = first.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], &a[..n]);

        let second_run = replay_all(&mut second, 4096);
        let rest_of_first = replay_all(&mut first, 4096);
        let third_run = replay_all(&mut image.replay().unwrap(), 64 * 1024);

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

        let run = replay_all(&mut image.replay().unwrap(), 4096);
        assert_eq!(run.end, Ok(()));
        assert_eq!(run.delivered, a);
    }

    // A zero-length read changes nothing; success is sticky.
    #[test]
    fn replay_zero_length_reads_and_success_are_stable() {
        let a = payload_a();
        let (image, path) = preflighted("replay-empty-reads", &gzip_member(&a));
        let mut reader = image.replay().unwrap();

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

        let mut reader = image.replay().unwrap();
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
        let mut reader = image.replay().unwrap();
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
        let mut reader = image.replay().unwrap();
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

                let mut reader = image.replay().unwrap();
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

        let mut reader = image.replay().unwrap();
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

            let mut reader = image.replay().unwrap();
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
        let run = replay_all(&mut image.replay().unwrap(), 4096);
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
        let run = replay_all(&mut image.replay().unwrap(), 4096);
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

        let mut reader = image.replay().unwrap();
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

        let mut reader = image.replay().unwrap();
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

        let run = replay_all(&mut image.replay().unwrap(), 4096);
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

        let mut reader = image.replay().unwrap();
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

        let mut reader = image.replay().unwrap();
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
        let mut reader = image.replay().unwrap();
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

    // The replay reader can move to the thread that writes (`Send`), but is
    // neither shared (`!Sync`) nor duplicated (`!Clone`) -- whatever decoder
    // `FormatDecoder` holds. Checked at compile time: a type implementing
    // `Sync` (or `Clone`) would make the trait selection below ambiguous.
    #[test]
    fn replay_reader_is_send_but_neither_sync_nor_clone() {
        fn assert_send<T: Send>() {}
        assert_send::<StrictReplayReader>();

        trait AmbiguousIfSync<A> {
            fn check() {}
        }
        impl<T: ?Sized> AmbiguousIfSync<()> for T {}
        struct IsSync;
        impl<T: ?Sized + Sync> AmbiguousIfSync<IsSync> for T {}
        <StrictReplayReader as AmbiguousIfSync<_>>::check();

        trait AmbiguousIfClone<A> {
            fn check() {}
        }
        impl<T: ?Sized> AmbiguousIfClone<()> for T {}
        struct IsClone;
        impl<T: ?Sized + Clone> AmbiguousIfClone<IsClone> for T {}
        <StrictReplayReader as AmbiguousIfClone<_>>::check();
    }

    // ---------------------------------------------------------------------
    // Replay (xz): the same `StrictReplayReader`, with liblzma's decoder.
    // Damage is introduced after Preflight, in the same inode, the way a
    // change between Preflight and the write would appear.
    // ---------------------------------------------------------------------

    // `preflighted` for `.xz` files.
    fn preflighted_xz(tag: &str, contents: &[u8]) -> (PreflightedCompressedImage, PathBuf) {
        let path = write_xz_file(tag, contents);
        let image = open_compressed(&path)
            .preflight(NO_LIMIT, || false, |_| {})
            .unwrap_or_else(|error| panic!("{tag}: preflight failed: {error:?}"));
        assert_eq!(image.format(), CompressionFormat::Xz);
        (image, path)
    }

    // Preflights `contents`, lets `damage` change the file in place, then
    // replays it once with `buf_size` reads; checks the failure is sticky.
    fn xz_replay_after(
        tag: &str,
        contents: &[u8],
        damage: impl FnOnce(&Path),
        buf_size: usize,
    ) -> ReplayRun {
        let (image, path) = preflighted_xz(tag, contents);
        damage(&path);
        let mut reader = image.replay().unwrap();
        let run = replay_all(&mut reader, buf_size);
        if let Err(expected) = run.end {
            assert_stays_failed(&mut reader, expected);
        }
        let _ = std::fs::remove_file(&path);
        run
    }

    // R1-R3, R27: every supported check replays the exact payload for every
    // buffer size; after success every read (empty or not) is `Ok(0)`.
    #[test]
    fn xz_replay_delivers_the_exact_content_for_every_check_and_buffer_size() {
        use liblzma::stream::Check;
        let a = payload_a();

        for check in [Check::Crc32, Check::Crc64, Check::Sha256] {
            let (image, path) = preflighted_xz("xz-replay-check", &xz_stream(&a, check));
            for size in REPLAY_BUFFER_SIZES {
                let mut reader = image.replay().unwrap();
                let run = replay_all(&mut reader, size);
                assert_eq!(run.end, Ok(()), "{check:?}/{size}");
                assert!(run.delivered == a, "{check:?}/{size}");
                for len in [0usize, 1, 4096] {
                    assert_eq!(reader.read(&mut vec![0u8; len]).unwrap(), 0);
                }
            }
            let _ = std::fs::remove_file(&path);
        }
    }

    // R4-R7: concatenated streams and Stream Padding replay as one image,
    // to the very end.
    #[test]
    fn xz_replay_reads_every_concatenated_stream_and_padding() {
        use liblzma::stream::Check;
        let (a, b) = (payload_a(), payload_b());
        let c = b"xyz".to_vec();
        let sa = xz_stream(&a, Check::Crc32);
        let sb = xz_stream(&b, Check::Crc64);
        let sc = xz_stream(&c, Check::Sha256);
        let pad = |len: usize| vec![0u8; len];

        for (name, contents, expected) in [
            (
                "2",
                [sa.clone(), sb.clone()].concat(),
                [&a[..], &b].concat(),
            ),
            (
                "3",
                [sa.clone(), sb.clone(), sc.clone()].concat(),
                [&a[..], &b, &c].concat(),
            ),
            (
                "pad-between",
                [sa.clone(), pad(8), sb.clone()].concat(),
                [&a[..], &b].concat(),
            ),
            ("pad-final", [sa.clone(), pad(4)].concat(), a.clone()),
        ] {
            for size in [7, 64 * 1024, 1024 * 1024] {
                let run = xz_replay_after(&format!("xz-replay-{name}"), &contents, |_| {}, size);
                assert_eq!(run.end, Ok(()), "{name}/{size}");
                assert!(run.delivered == expected, "{name}/{size}");
            }
        }
    }

    // R8-R9: a stream without an integrity check appearing after Preflight
    // (first or later stream) is refused before any of its payload.
    #[test]
    fn xz_replay_refuses_a_missing_integrity_check_in_any_stream() {
        use liblzma::stream::Check;
        let (a, b) = (payload_a(), payload_b());
        let (sa, sb) = (crc64_stream(&a), crc64_stream(&b));
        let expected = (
            io::ErrorKind::InvalidInput,
            ReplayFailure::IntegrityCheckMissing,
        );

        let none = xz_stream(&b, Check::None);
        let run = xz_replay_after("xz-replay-none", &sb, |p| rewrite_in_place(p, &none), 4096);
        assert_eq!(run.end, Err(expected));
        assert!(run.delivered.is_empty());

        let later = [sa.clone(), none].concat();
        let run = xz_replay_after(
            "xz-replay-none-later",
            &[sa, sb].concat(),
            |p| rewrite_in_place(p, &later),
            4096,
        );
        assert_eq!(run.end, Err(expected));
        assert!(a.starts_with(&run.delivered));
    }

    // R10-R11: a reserved Check ID appearing after Preflight (first or later
    // stream; same size, so only the ID differs) is refused.
    #[test]
    fn xz_replay_refuses_an_unsupported_integrity_check_in_any_stream() {
        let (a, b) = (payload_a(), payload_b());
        let (sa, sb) = (crc64_stream(&a), crc64_stream(&b));
        let expected = (
            io::ErrorKind::Other,
            ReplayFailure::UnsupportedIntegrityCheck,
        );

        let reserved = with_check_id(&sb, 5);
        let run = xz_replay_after(
            "xz-replay-reserved",
            &sb,
            |p| rewrite_in_place(p, &reserved),
            4096,
        );
        assert_eq!(run.end, Err(expected));
        assert!(run.delivered.is_empty());

        let later = [sa.clone(), reserved].concat();
        let run = xz_replay_after(
            "xz-replay-reserved-later",
            &[sa, sb].concat(),
            |p| rewrite_in_place(p, &later),
            4096,
        );
        assert_eq!(run.end, Err(expected));
        assert!(a.starts_with(&run.delivered));
    }

    // R12: a Block declaring a dictionary over the decoder memory limit
    // (same size, only the dictionary byte differs) is refused, typed.
    #[test]
    fn xz_replay_refuses_a_block_over_the_decoder_memory_limit() {
        let stream = crc64_stream(&payload_a());
        let over = with_declared_dictionary(&stream, 40);
        let run = xz_replay_after(
            "xz-replay-memlimit",
            &stream,
            |p| rewrite_in_place(p, &over),
            4096,
        );
        assert_eq!(
            run.end,
            Err((
                io::ErrorKind::Other,
                ReplayFailure::DecoderMemoryLimitExceeded {
                    limit: XZ_DECODER_MEMLIMIT
                }
            ))
        );
        assert!(run.delivered.is_empty());
    }

    // R13-R14, R25: damage found after the payload (Block Check, Index,
    // Stream Footer) fails the read that would deliver the final bytes --
    // those bytes are never delivered, for every buffer size.
    #[test]
    fn xz_replay_withholds_the_final_bytes_when_the_end_is_damaged() {
        let a = payload_a();
        let stream = crc64_stream(&a);
        let index = xz_index_start(&stream);
        let footer = stream.len() - 12;
        let expected = (io::ErrorKind::InvalidData, ReplayFailure::Corrupt);

        for (name, position) in [
            ("block-check", index - 1),
            ("index-crc", footer - 1),
            ("footer-crc", footer),
            ("footer-magic", footer + 11),
        ] {
            for size in REPLAY_BUFFER_SIZES {
                let run = xz_replay_after(
                    &format!("xz-replay-{name}"),
                    &stream,
                    |p| flip_byte_in_place(p, (stream.len() - position) as u64),
                    size,
                );
                let piece = size.min(DECODE_QUANTUM);
                assert_eq!(run.end, Err(expected), "{name}/{size}");
                assert!(
                    run.delivered.len() < a.len(),
                    "{name}/{size}: final bytes delivered"
                );
                assert!(
                    run.delivered.len() >= a.len() - piece,
                    "{name}/{size}: stopped early"
                );
                assert!(a.starts_with(&run.delivered));
            }
        }
    }

    // R25: the case the strict end exists for. The payload's stream ends in
    // the first 256 KiB input buffer, and the damage (a later, empty
    // stream's footer) lies in the next one -- so the decoder itself hands
    // back every payload byte through `Ok(n)` before reporting it (checked
    // directly below). The replay still withholds the final bytes.
    #[test]
    fn xz_replay_withholds_the_final_bytes_when_the_decoder_errs_only_after_them() {
        let payload = pseudo_random(200 * 1024, 17);
        let first = crc64_stream(&payload);
        assert!(first.len() < INPUT_BUFFER_LEN);
        let padding = vec![0u8; (INPUT_BUFFER_LEN - first.len()).next_multiple_of(4) + 64];
        let contents = [first, padding, crc64_stream(&[])].concat();
        let footer_crc_from_end = 12u64;

        let mut damaged = contents.clone();
        let at = damaged.len() - footer_crc_from_end as usize;
        damaged[at] ^= 0xFF;
        let mut decoder =
            FormatDecoder::xz(BufReader::with_capacity(INPUT_BUFFER_LEN, &damaged[..])).unwrap();
        let mut buf = vec![0u8; DECODE_QUANTUM];
        let mut decoded = 0;
        let error = loop {
            match decoder.read(&mut buf) {
                Ok(0) => panic!("damaged stream ended cleanly"),
                Ok(n) => decoded += n,
                Err(error) => break error,
            }
        };
        assert_eq!(
            decoded,
            payload.len(),
            "the decoder returned all bytes first"
        );
        assert_eq!(ReplayFailure::of(&error), ReplayFailure::Corrupt);

        for size in [4096, 64 * 1024, 1024 * 1024] {
            let run = xz_replay_after(
                "xz-replay-late",
                &contents,
                |p| flip_byte_in_place(p, footer_crc_from_end),
                size,
            );
            assert_eq!(
                run.end,
                Err((io::ErrorKind::InvalidData, ReplayFailure::Corrupt))
            );
            assert!(
                run.delivered.len() < payload.len(),
                "{size}: final bytes delivered"
            );
            assert!(payload.starts_with(&run.delivered));
        }
    }

    // R15-R17: truncation, short trailing garbage and invalid Stream Padding
    // appearing after Preflight are refused.
    #[test]
    fn xz_replay_refuses_truncation_trailing_garbage_and_bad_padding() {
        let (a, b) = (payload_a(), payload_b());
        let (sa, sb) = (crc64_stream(&a), crc64_stream(&b));
        let incomplete = (io::ErrorKind::UnexpectedEof, ReplayFailure::Incomplete);
        let corrupt = (io::ErrorKind::InvalidData, ReplayFailure::Corrupt);
        let set_len = |len: usize| {
            move |p: &Path| {
                let file = std::fs::OpenOptions::new().write(true).open(p).unwrap();
                file.set_len(len as u64).unwrap();
            }
        };

        for cut in [3usize, 13, sa.len() / 2] {
            let run = xz_replay_after("xz-replay-trunc", &sa, set_len(sa.len() - cut), 4096);
            assert_eq!(run.end, Err(incomplete), "cut {cut}");
            assert!(run.delivered.len() < a.len());
        }

        // Valid padding replaced by the same number of non-zero bytes.
        let padded = [sa.clone(), vec![0u8; 4]].concat();
        let garbage = [sa.clone(), vec![0xAA; 4]].concat();
        let run = xz_replay_after(
            "xz-replay-garbage",
            &padded,
            |p| rewrite_in_place(p, &garbage),
            4096,
        );
        assert_eq!(run.end, Err(incomplete));

        // Final padding cut to 3 bytes; padding between streams shifted to 3.
        let run = xz_replay_after("xz-replay-pad3", &padded, set_len(sa.len() + 3), 4096);
        assert_eq!(run.end, Err(corrupt));
        let between = [sa.clone(), vec![0u8; 4], sb.clone()].concat();
        let shifted = [sa.clone(), vec![0u8; 3], sb.clone(), vec![0u8; 1]].concat();
        let run = xz_replay_after(
            "xz-replay-pad-between",
            &between,
            |p| rewrite_in_place(p, &shifted),
            4096,
        );
        assert_eq!(run.end, Err(corrupt));
        assert!(a.starts_with(&run.delivered));
    }

    // R18-R20: exactly the measured size replays; a stream that now decodes
    // to fewer bytes ends early, one that decodes to more is refused at the
    // measured size (same compressed length in both cases).
    #[test]
    fn xz_replay_enforces_the_logical_size_exactly() {
        let long = crc64_stream(&vec![7u8; 300 * 1024]);
        let short = crc64_stream(&vec![7u8; 200 * 1024]);
        let len = long.len().max(short.len()) + 64;
        let pad_to = |stream: &[u8]| [stream, &vec![0u8; len - stream.len()]].concat();

        let run = xz_replay_after("xz-replay-size-exact", &pad_to(&long), |_| {}, 64 * 1024);
        assert_eq!(run.end, Ok(()));
        assert_eq!(run.delivered.len(), 300 * 1024);

        let shorter = pad_to(&short);
        let run = xz_replay_after(
            "xz-replay-size-short",
            &pad_to(&long),
            |p| rewrite_in_place(p, &shorter),
            64 * 1024,
        );
        assert_eq!(
            run.end,
            Err((io::ErrorKind::UnexpectedEof, ReplayFailure::EndedEarly))
        );
        assert_eq!(run.delivered.len(), 200 * 1024);

        let longer = pad_to(&long);
        let run = xz_replay_after(
            "xz-replay-size-long",
            &pad_to(&short),
            |p| rewrite_in_place(p, &longer),
            64 * 1024,
        );
        assert_eq!(
            run.end,
            Err((
                io::ErrorKind::InvalidData,
                ReplayFailure::LogicalSizeExceeded
            ))
        );
        assert!(run.delivered.len() < 200 * 1024);
    }

    // R22: the Compressed Input Budget applies to xz replays unchanged: a
    // file rewritten (same length) into a tiny stream followed by megabytes
    // of valid Stream Padding is refused within the cap plus one buffer.
    #[test]
    fn xz_replay_enforces_the_input_budget() {
        let original = crc64_stream(&pseudo_random(2 << 20, 21));
        let tiny = crc64_stream(b"x");
        let rewritten = [tiny.clone(), vec![0u8; original.len() - tiny.len()]].concat();
        let (image, path) = preflighted_xz("xz-replay-budget", &original);
        rewrite_in_place(&path, &rewritten);

        let mut reader = image.replay().unwrap();
        let mut buf = vec![0u8; 64 * 1024];
        let error = loop {
            match reader.read(&mut buf) {
                Ok(0) => panic!("unexpected end"),
                Ok(_) => continue,
                Err(error) => break error,
            }
        };
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        let exceeded = error
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

    // R21: a replay has no cancellation hook of its own; the caller (writer
    // / Verify) checks between reads. What makes that responsive is that
    // every read is bounded: at most `DECODE_QUANTUM` of output
    // (`replay_all` asserts it) and, per 1 MiB chunk, at most the documented
    // compressed-input bound. A reader abandoned mid-stream (a cancelled
    // write) does not affect a fresh replay of the same image.
    #[test]
    fn xz_replay_reads_are_bounded_and_an_abandoned_reader_is_harmless() {
        let payload = pseudo_random(3 << 20, 9);
        let (image, path) = preflighted_xz("xz-replay-bounded", &crc64_stream(&payload));

        let chunk = 1usize << 20;
        let bound = INPUT_BUDGET_CAP + (1 << 20) + (1 << 20) / 64 + INPUT_BUFFER_LEN as u64;
        let mut reader = image.replay().unwrap();
        let mut buf = vec![0u8; chunk];
        let mut chunk_start = 0u64;
        let mut filled = 0;
        while filled < chunk {
            let n = reader.read(&mut buf[filled..]).unwrap();
            assert!(n > 0 && n <= DECODE_QUANTUM);
            filled += n;
        }
        let consumed = reader.compressed_consumed().unwrap();
        assert!(consumed - chunk_start <= bound);
        chunk_start = consumed;
        assert!(chunk_start > 0);
        drop(reader);

        let run = replay_all(&mut image.replay().unwrap(), 64 * 1024);
        assert_eq!(run.end, Ok(()));
        assert!(run.delivered == payload);
        let _ = std::fs::remove_file(&path);
    }

    // R24: a clean end is only success with the whole compressed size
    // consumed: a reader told the file is 4 bytes longer than it is (so its
    // input ends early, after a complete stream) fails, never succeeds.
    #[test]
    fn xz_replay_requires_exact_input_consumption() {
        let a = payload_a();
        let (image, path) = preflighted_xz("xz-replay-consumed", &crc64_stream(&a));

        let mut reader = StrictReplayReader::new(
            &image.file,
            CompressionFormat::Xz,
            image.compressed_size() + 4,
            image.logical_size(),
        )
        .unwrap();
        let run = replay_all(&mut reader, 4096);
        assert_eq!(
            run.end,
            Err((
                io::ErrorKind::InvalidData,
                ReplayFailure::InputNotFullyConsumed
            ))
        );
        assert!(run.delivered.len() < a.len());
        assert_stays_failed(
            &mut reader,
            (
                io::ErrorKind::InvalidData,
                ReplayFailure::InputNotFullyConsumed,
            ),
        );
        let _ = std::fs::remove_file(&path);
    }

    // R26, R28: zero-length reads change nothing (before any data and
    // mid-stream), and success and failure are both sticky.
    #[test]
    fn xz_replay_zero_length_reads_and_terminal_states_are_stable() {
        let a = payload_a();
        let (image, path) = preflighted_xz("xz-replay-empty-reads", &crc64_stream(&a));
        let mut reader = image.replay().unwrap();

        for _ in 0..3 {
            assert_eq!(reader.read(&mut []).unwrap(), 0);
        }
        assert_eq!(reader.compressed_consumed(), Some(0), "nothing read yet");

        let mut buf = vec![0u8; 4096];
        assert_eq!(reader.read(&mut buf).unwrap(), 4096);
        let consumed = reader.compressed_consumed();
        assert_eq!(reader.read(&mut []).unwrap(), 0);
        assert_eq!(reader.compressed_consumed(), consumed);

        let run = replay_all(&mut reader, 4096);
        assert_eq!(run.end, Ok(()));
        assert!(run.delivered == a[4096..]);
        assert!(reader.compressed_consumed().is_none(), "decoder released");
        let _ = std::fs::remove_file(&path);
    }

    // R29: the replay reads the file Preflight read -- renaming, replacing
    // and deleting the path change nothing -- and `CompressedImageSource`
    // hands out independent xz replays with sequential access only.
    #[test]
    fn xz_replay_reads_the_opened_file_and_serves_independent_readers() {
        let a = payload_a();
        let (image, path) = preflighted_xz("xz-replay-swap", &crc64_stream(&a));
        let moved = path.with_extension("moved");
        std::fs::rename(&path, &moved).unwrap();
        std::fs::write(&path, crc64_stream(b"a different image")).unwrap();
        std::fs::remove_file(&moved).unwrap();
        std::fs::remove_file(&path).unwrap();

        let source = CompressedImageSource::new(image);
        assert_eq!(source.access(), ImageSourceAccess::SequentialReplay);
        assert_eq!(source.logical_size(), a.len() as u64);
        let mut first = source.open_reader().unwrap();
        let mut second = source.open_reader().unwrap();
        let (from_second, end) = read_boxed(&mut *second);
        assert_eq!(end, Ok(()));
        assert!(from_second == a);
        let (from_first, end) = read_boxed(&mut *first);
        assert_eq!(end, Ok(()));
        assert!(from_first == a);
        assert_eq!(
            source.read_at(0, &mut [0u8; 16]).unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
    }

    // Replay classification: liblzma's errors map exactly as in Preflight,
    // and a decoder that could not be set up is `DecoderFailure` (never
    // `Corrupt`, whatever liblzma reported), keeping liblzma's error as its
    // source. (Setup and Mem / Program failures cannot be provoked from
    // data, so the mapping itself is checked.)
    #[test]
    fn replay_failures_from_liblzma_are_classified_by_type() {
        use liblzma::stream::Error as Lzma;
        let of = |lzma: Lzma| ReplayFailure::of(&io::Error::from(lzma));

        assert_eq!(of(Lzma::NoCheck), ReplayFailure::IntegrityCheckMissing);
        assert_eq!(
            of(Lzma::UnsupportedCheck),
            ReplayFailure::UnsupportedIntegrityCheck
        );
        assert_eq!(
            of(Lzma::MemLimit),
            ReplayFailure::DecoderMemoryLimitExceeded {
                limit: XZ_DECODER_MEMLIMIT
            }
        );
        for lzma in [Lzma::Mem, Lzma::Program] {
            assert_eq!(of(lzma), ReplayFailure::DecoderFailure, "{lzma:?}");
        }
        for lzma in [Lzma::Data, Lzma::Format, Lzma::Options] {
            assert_eq!(of(lzma), ReplayFailure::Corrupt, "{lzma:?}");
        }

        for lzma in [Lzma::Mem, Lzma::Options, Lzma::Program] {
            let setup = io::Error::other(DecoderSetupFailed(io::Error::from(lzma)));
            assert_eq!(ReplayFailure::of(&setup), ReplayFailure::DecoderFailure);
            let source = std::error::Error::source(setup.get_ref().unwrap()).unwrap();
            assert_eq!(
                source.downcast_ref::<io::Error>().unwrap().kind(),
                io::Error::from(lzma).kind()
            );
        }

        let source_io = io::Error::other(SourceReadError(io::Error::other("disk")));
        assert_eq!(ReplayFailure::of(&source_io), ReplayFailure::SourceIo);
        let premature = io::Error::new(io::ErrorKind::UnexpectedEof, "premature eof");
        assert_eq!(ReplayFailure::of(&premature), ReplayFailure::Incomplete);
    }

    // ---------------------------------------------------------------------
    // Source identity (gzip): same contracts as raw, with the snapshot taken
    // when `open_image` opened the file and never refreshed by Preflight.
    // ---------------------------------------------------------------------

    fn source_changed(result: Result<(), SourceChanged>) -> bool {
        matches!(result, Err(SourceChanged::Metadata { .. }))
    }

    fn let_the_clock_tick() {
        std::thread::sleep(std::time::Duration::from_millis(20));
    }

    #[test]
    fn preflighted_image_unchanged_revalidates() {
        let (image, path) = preflighted("identity-gz-unchanged", &gzip_member(&payload_a()));
        for _ in 0..3 {
            image.revalidate_identity().unwrap();
        }
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn preflighted_image_detects_append_and_overwrite() {
        let member = gzip_member(&payload_a());

        let (image, path) = preflighted("identity-gz-append", &member);
        let_the_clock_tick();
        let mut appender = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        appender.write_all(&[0u8; 16]).unwrap();
        assert!(source_changed(image.revalidate_identity()));
        let _ = std::fs::remove_file(&path);

        let (image, path) = preflighted("identity-gz-overwrite", &member);
        let_the_clock_tick();
        rewrite_in_place(&path, &member); // same bytes, same size: still a write
        assert!(source_changed(image.revalidate_identity()));
        let _ = std::fs::remove_file(&path);
    }

    // The reference point is selection (`open_image`), not the end of
    // Preflight: a change between opening and Preflight -- here rewriting
    // the very same valid bytes, so Preflight itself succeeds -- is still
    // reported afterwards.
    #[test]
    fn preflight_keeps_the_open_time_snapshot() {
        let member = gzip_member(&payload_a());
        let path = write_gz_file("identity-gz-before-preflight", &member);
        let file = open_compressed(&path);

        let_the_clock_tick();
        rewrite_in_place(&path, &member);

        let image = file.preflight(NO_LIMIT, || false, |_| {}).unwrap();
        assert_eq!(image.logical_size(), payload_a().len() as u64);
        assert!(source_changed(image.revalidate_identity()));
        let _ = std::fs::remove_file(&path);
    }

    // Path operations after Preflight: replays keep decoding the opened
    // file, while revalidation reports the change.
    #[test]
    fn preflighted_image_path_operations_keep_the_open_file_but_are_reported() {
        let a = payload_a();
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
                std::fs::write(path, gzip_member(b"a different image")).unwrap();
            }),
            ("hard-link", |path| {
                std::fs::hard_link(path, path.with_extension("link")).unwrap();
            }),
        ];

        for (name, operate) in operations {
            let (image, path) = preflighted(&format!("identity-gz-{name}"), &gzip_member(&a));

            let_the_clock_tick();
            operate(&path);

            let run = replay_all(&mut image.replay().unwrap(), 64 * 1024);
            assert_eq!(run.end, Ok(()), "{name}");
            assert_eq!(run.delivered, a, "{name}: still the opened file");
            assert!(source_changed(image.revalidate_identity()), "{name}");

            for leftover in [
                path.clone(),
                path.with_extension("moved"),
                path.with_extension("link"),
            ] {
                let _ = std::fs::remove_file(leftover);
            }
        }
    }

    // ---------------------------------------------------------------------
    // CompressedImageSource: a validated gzip image through `ImageSource`.
    // ---------------------------------------------------------------------

    fn compressed_source(tag: &str, contents: &[u8]) -> (CompressedImageSource, PathBuf) {
        let (image, path) = preflighted(tag, contents);
        (CompressedImageSource::new(image), path)
    }

    // Reads a boxed reader to its end, the way `writer::write` and Full
    // Verify consume `open_reader()`.
    fn read_boxed(reader: &mut dyn Read) -> (Vec<u8>, Result<(), (io::ErrorKind, ReplayFailure)>) {
        let mut delivered = Vec::new();
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            match reader.read(&mut buf) {
                Ok(0) => return (delivered, Ok(())),
                Ok(n) => delivered.extend_from_slice(&buf[..n]),
                Err(error) => {
                    assert_ne!(error.kind(), io::ErrorKind::Interrupted);
                    return (delivered, Err((error.kind(), ReplayFailure::of(&error))));
                }
            }
        }
    }

    // A, B, C: built from a Preflighted image; reports the decoded size (not
    // the compressed size); a reader yields the whole payload.
    #[test]
    fn compressed_source_reports_the_logical_size_and_reads_the_payload() {
        let a = payload_a();
        let member = gzip_member(&a);
        let (source, path) = compressed_source("source-basic", &member);

        assert_eq!(source.logical_size(), a.len() as u64);
        assert_ne!(source.logical_size(), member.len() as u64);
        assert_eq!(source.path(), path.as_path());

        let (delivered, end) = read_boxed(&mut *source.open_reader().unwrap());
        assert_eq!(end, Ok(()));
        assert_eq!(delivered, a);
        let _ = std::fs::remove_file(&path);
    }

    // D, E: every `open_reader()` starts at logical byte 0 with its own
    // position -- a reader left half-read does not affect the next one, and
    // a second full read (as Full Verify would do after the write) decodes
    // the same payload again.
    #[test]
    fn compressed_source_readers_are_independent() {
        let (a, b) = (payload_a(), payload_b());
        let expected = [a.clone(), b.clone()].concat();
        let (source, path) = compressed_source(
            "source-independent",
            &[gzip_member(&a), gzip_member(&b)].concat(),
        );

        let mut first = source.open_reader().unwrap();
        let mut head = vec![0u8; 1000];
        first.read_exact(&mut head).unwrap();
        assert_eq!(head, expected[..1000]);

        let (write_pass, end) = read_boxed(&mut *source.open_reader().unwrap());
        assert_eq!(end, Ok(()));
        assert_eq!(write_pass, expected);

        let (verify_pass, end) = read_boxed(&mut *source.open_reader().unwrap());
        assert_eq!(end, Ok(()));
        assert_eq!(verify_pass, expected);

        let (rest, end) = read_boxed(&mut *first);
        assert_eq!(end, Ok(()));
        assert_eq!(rest, expected[1000..]);
        let _ = std::fs::remove_file(&path);
    }

    // F, G, H: after rename or path replacement, readers still decode the
    // opened file (never the replacement), and the source reports the change.
    #[test]
    fn compressed_source_keeps_the_opened_file_and_reports_path_operations() {
        type Operation = fn(&Path);
        let operations: [(&str, Operation); 2] = [
            ("rename", |path| {
                std::fs::rename(path, path.with_extension("moved")).unwrap();
            }),
            ("replace", |path| {
                std::fs::rename(path, path.with_extension("moved")).unwrap();
                std::fs::write(path, gzip_member(b"a different image")).unwrap();
            }),
        ];
        let a = payload_a();

        for (name, operate) in operations {
            let (source, path) = compressed_source(&format!("source-{name}"), &gzip_member(&a));

            let_the_clock_tick();
            operate(&path);

            let (delivered, end) = read_boxed(&mut *source.open_reader().unwrap());
            assert_eq!(end, Ok(()), "{name}");
            assert_eq!(delivered, a, "{name}: still the opened file");
            assert!(source_changed(source.revalidate_identity()), "{name}");

            let _ = std::fs::remove_file(&path);
            let _ = std::fs::remove_file(path.with_extension("moved"));
        }
    }

    // I: unchanged, the source revalidates; changed after Preflight, it
    // reports the change against the open-time snapshot.
    #[test]
    fn compressed_source_revalidates_against_the_open_time_snapshot() {
        let member = gzip_member(&payload_a());
        let (source, path) = compressed_source("source-identity", &member);
        for _ in 0..3 {
            source.revalidate_identity().unwrap();
        }

        let_the_clock_tick();
        rewrite_in_place(&path, &member);
        assert!(source_changed(source.revalidate_identity()));
        let _ = std::fs::remove_file(&path);
    }

    // J: the strict end-of-stream contract holds through `open_reader()`: a
    // damaged CRC or ISIZE withholds the final bytes and fails with the typed
    // category, as with `replay()` directly.
    #[test]
    fn compressed_source_readers_keep_the_strict_end_of_stream() {
        let a = payload_a();
        for (label, offset_from_end) in [("crc", 8u64), ("isize", 4u64)] {
            let (source, path) = compressed_source(&format!("source-{label}"), &gzip_member(&a));
            flip_byte_in_place(&path, offset_from_end);

            let mut reader = source.open_reader().unwrap();
            let (delivered, end) = read_boxed(&mut *reader);
            assert!(delivered.len() < a.len(), "{label}: final bytes withheld");
            assert_eq!(
                end,
                Err((io::ErrorKind::InvalidInput, ReplayFailure::Corrupt)),
                "{label}"
            );
            let error = reader.read(&mut [0u8; 16]).unwrap_err();
            assert_eq!(ReplayFailure::of(&error), ReplayFailure::Corrupt, "{label}");
            let _ = std::fs::remove_file(&path);
        }
    }

    // K (known limitation, not solved here): a same-size rewrite into a
    // different valid gzip stream of the same decoded size replays cleanly --
    // replay alone cannot tell. Only the Source Identity checkpoints report
    // it.
    #[test]
    fn compressed_source_same_size_valid_rewrite_is_caught_only_by_identity() {
        let original = gzip_at(&vec![0x11u8; 4096], 0);
        let rewritten = gzip_at(&vec![0x22u8; 4096], 0);
        assert_eq!(original.len(), rewritten.len());
        let (source, path) = compressed_source("source-same-size", &original);

        let_the_clock_tick();
        rewrite_in_place(&path, &rewritten);

        let (delivered, end) = read_boxed(&mut *source.open_reader().unwrap());
        assert_eq!(end, Ok(()));
        assert_eq!(
            delivered,
            vec![0x22u8; 4096],
            "the replay reads the new bytes"
        );
        assert!(source_changed(source.revalidate_identity()));
        let _ = std::fs::remove_file(&path);
    }

    // L: sequential replay only -- no random access.
    #[test]
    fn compressed_source_is_sequential_replay_only() {
        let (source, path) = compressed_source("source-access", &gzip_member(&payload_a()));
        assert_eq!(source.access(), ImageSourceAccess::SequentialReplay);
        let error = source.read_at(0, &mut [0u8; 16]).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
        let _ = std::fs::remove_file(&path);
    }
}
