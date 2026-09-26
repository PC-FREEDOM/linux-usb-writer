// Behavior pinning for liblzma's `.xz` stream decoder, driven through
// `liblzma::bufread::XzDecoder` (XZ Phase 2D-3a).
//
// Test-only. These tests do not exercise any production code path: they
// record, as executable assertions, how the decoder configuration the
// future XZ `ImageSource` is planned to use behaves at the boundaries that
// matter for Preflight and strict end-of-stream validation -- stream
// boundaries, Stream Padding, integrity checks, the Index and Stream
// Footer, truncation, trailing bytes, the memory limit -- and that the
// behavior is identical for every read size and input window. If a future
// liblzma upgrade changes any of this, these tests fail before production
// code relies on it.
//
// The planned configuration (see `planned_decoder`):
//
//   Stream::new_stream_decoder(512 MiB,
//       TELL_NO_CHECK | TELL_UNSUPPORTED_CHECK | CONCATENATED)
//   bufread::XzDecoder::new_stream(input, stream)
//
// Never the crate's `XzDecoder::new` (no memory limit, no concatenation, no
// check reporting) or `new_multi_decoder` (liblzma's auto decoder, which
// also accepts legacy .lzma and .lz data).
//
// Fixtures are built in memory with liblzma's own encoder, then damaged or
// patched byte-by-byte at offsets fixed by the .xz file format (Stream
// Header / Block Header / Index / Stream Footer), so the rejection cases do
// not depend on the encoder being correct. Fixture layout produced by the
// single-threaded stream encoder with one LZMA2 filter:
//
//   Stream Header (12): magic (6), Stream Flags (2: 0x00, Check ID), CRC32
//   Block Header: size byte, flags 0x00 (one filter, no size fields),
//                 LZMA2 filter (0x21, 0x01, dictionary byte), padding, CRC32
//   compressed data, Block Padding, Check (0/4/8/32 bytes)
//   Index: 0x00 indicator, record count, records, padding, CRC32
//   Stream Footer (12): CRC32, Backward Size (4), Stream Flags (2), "YZ"

use std::io::{self, BufRead, Read};
use std::ops::Range;

use flate2::Crc;
use liblzma::bufread::XzDecoder;
use liblzma::stream::{
    Action, CONCATENATED, Check, Error, Filters, LzmaOptions, Status, Stream, TELL_NO_CHECK,
    TELL_UNSUPPORTED_CHECK,
};

// The memory limit and flags the production XZ decoder is planned to use.
const PLANNED_MEMLIMIT: u64 = 512 * 1024 * 1024;
const PLANNED_FLAGS: u32 = TELL_NO_CHECK | TELL_UNSUPPORTED_CHECK | CONCATENATED;

// Every read size the tests drive the decoder with (production readers are
// chunked; 1 MiB is the writer's chunk size) ...
const READ_SIZES: [usize; 5] = [1, 7, 64, 4096, 1 << 20];
// ... and every input window the underlying `BufRead` exposes per
// `fill_buf()` call, so stream boundaries, padding, footers and trailing
// bytes fall across `fill_buf` boundaries in every possible way.
const INPUT_WINDOWS: [usize; 3] = [1, 3, 8192];

const STREAM_HEADER_LEN: usize = 12;
const STREAM_FOOTER_LEN: usize = 12;
const XZ_MAGIC: [u8; 6] = [0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00];

// ---------------------------------------------------------------------
// Fixtures.
// ---------------------------------------------------------------------

fn payload_a() -> Vec<u8> {
    // 64 KiB of poorly-compressible bytes, so the compressed body spans many
    // input windows and several output reads.
    (0..65_536u32)
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
        .collect()
}

fn payload_b() -> Vec<u8> {
    b"hello xz stream B ".repeat(500)
}

fn payload_c() -> Vec<u8> {
    b"xyz".to_vec()
}

// A small poorly-compressible payload, for tests that decode once per byte
// of the compressed file.
fn payload_small() -> Vec<u8> {
    (0..2_000u32)
        .map(|i| (i.wrapping_mul(2_246_822_519) >> 11) as u8)
        .collect()
}

// Runs `stream` (an encoder) over `blocks`: each block but the last is
// ended with a full flush, which makes the stream encoder close the current
// .xz Block and start a new one; the last is ended with `Finish`.
fn encode_with(mut stream: Stream, blocks: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();

    for (i, block) in blocks.iter().enumerate() {
        let action = if i + 1 == blocks.len() {
            Action::Finish
        } else {
            Action::FullFlush
        };
        let mut input = *block;

        loop {
            out.reserve(64 * 1024);
            let before = stream.total_in();
            let status = stream.process_vec(input, &mut out, action).unwrap();
            input = &input[(stream.total_in() - before) as usize..];
            if status == Status::StreamEnd {
                break;
            }
        }
    }

    out
}

// One .xz stream with one Block (preset 0: a 256 KiB dictionary).
fn xz(payload: &[u8], check: Check) -> Vec<u8> {
    encode_with(Stream::new_easy_encoder(0, check).unwrap(), &[payload])
}

// One .xz stream with one Block per element of `blocks`.
fn xz_blocks(blocks: &[&[u8]], check: Check) -> Vec<u8> {
    encode_with(Stream::new_easy_encoder(0, check).unwrap(), blocks)
}

// One .xz stream whose LZMA2 filter uses a `dict_size`-byte dictionary.
fn xz_with_dictionary(payload: &[u8], dict_size: u32) -> Vec<u8> {
    let mut options = LzmaOptions::new_preset(0).unwrap();
    options.dict_size(dict_size);
    let mut filters = Filters::new();
    filters.lzma2(&options);
    encode_with(
        Stream::new_stream_encoder(&filters, Check::Crc64).unwrap(),
        &[payload],
    )
}

fn concat(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
}

fn zeros(len: usize) -> Vec<u8> {
    vec![0u8; len]
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = Crc::new();
    crc.update(bytes);
    crc.sum()
}

fn flipped(bytes: &[u8], index: usize) -> Vec<u8> {
    let mut corrupted = bytes.to_vec();
    corrupted[index] ^= 0xFF;
    corrupted
}

// Offsets inside a single .xz stream (no padding after it), located from
// the Stream Footer's Backward Size, as a decoder would.
fn footer_start(stream: &[u8]) -> usize {
    stream.len() - STREAM_FOOTER_LEN
}

fn index_range(stream: &[u8]) -> Range<usize> {
    let footer = footer_start(stream);
    let backward = u32::from_le_bytes(stream[footer + 4..footer + 8].try_into().unwrap());
    let index_len = (backward as usize + 1) * 4;
    footer - index_len..footer
}

// Rewrites the Check ID in both the Stream Header and the Stream Footer of a
// single stream, recomputing both CRC32s, so the file stays structurally
// valid and only the Check ID differs. Only valid between Check IDs with the
// same check-field size (the Blocks' check fields are left as they are).
fn with_check_id(stream: &[u8], check_id: u8) -> Vec<u8> {
    let mut patched = stream.to_vec();
    assert_eq!(patched[..6], XZ_MAGIC, "not a Stream Header");
    assert_eq!(patched[6], 0x00, "unexpected Stream Flags");
    patched[7] = check_id;
    let header_crc = crc32(&patched[6..8]);
    patched[8..12].copy_from_slice(&header_crc.to_le_bytes());

    let footer = footer_start(&patched);
    assert_eq!(&patched[footer + 10..], b"YZ", "not a Stream Footer");
    assert_eq!(patched[footer + 8], 0x00, "unexpected Stream Flags");
    patched[footer + 9] = check_id;
    let footer_crc = crc32(&patched[footer + 4..footer + 10]);
    patched[footer..footer + 4].copy_from_slice(&footer_crc.to_le_bytes());

    patched
}

// Rewrites the LZMA2 dictionary-size byte in the first Block Header of a
// single stream and recomputes the Block Header's CRC32. The data still
// decodes correctly (a larger dictionary is only a larger window); what
// changes is the memory the decoder must reserve for the Block.
fn with_declared_dictionary(stream: &[u8], dictionary_byte: u8) -> Vec<u8> {
    let mut patched = stream.to_vec();
    let start = STREAM_HEADER_LEN;
    let header_len = (patched[start] as usize + 1) * 4;
    assert_eq!(patched[start + 1], 0x00, "Block Header flags");
    assert_eq!(patched[start + 2], 0x21, "LZMA2 filter ID");
    assert_eq!(patched[start + 3], 0x01, "LZMA2 properties size");
    patched[start + 4] = dictionary_byte;
    let crc_at = start + header_len - 4;
    let crc = crc32(&patched[start..crc_at]);
    patched[crc_at..crc_at + 4].copy_from_slice(&crc.to_le_bytes());
    patched
}

// ---------------------------------------------------------------------
// Decoding harness.
// ---------------------------------------------------------------------

// A `BufRead` over a byte slice that exposes at most `window` bytes per
// `fill_buf()` and counts exactly what the decoder `consume()`s -- which is
// what "compressed bytes the decoder actually consumed" means, as opposed to
// what an underlying buffer may have prefetched.
struct CountingSliceReader<'a> {
    data: &'a [u8],
    consumed: usize,
    window: usize,
}

impl<'a> CountingSliceReader<'a> {
    fn new(data: &'a [u8], window: usize) -> Self {
        CountingSliceReader {
            data,
            consumed: 0,
            window,
        }
    }
}

impl Read for CountingSliceReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let available = self.fill_buf()?;
        let n = available.len().min(buf.len());
        buf[..n].copy_from_slice(&available[..n]);
        self.consume(n);
        Ok(n)
    }
}

impl BufRead for CountingSliceReader<'_> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        let end = (self.consumed + self.window).min(self.data.len());
        Ok(&self.data[self.consumed..end])
    }

    fn consume(&mut self, amount: usize) {
        self.consumed += amount;
        assert!(self.consumed <= self.data.len(), "consumed past the input");
    }
}

// How a decode ended. `Lzma` is a typed liblzma error recovered from the
// `io::Error` by downcasting (never by message text); `Untyped` is an error
// the crate's `XzDecoder` raised itself with only a kind and a message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum End {
    Clean,
    Lzma(Error),
    Untyped(io::ErrorKind),
}

fn end_of(error: &io::Error) -> End {
    match error
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<Error>())
    {
        Some(lzma) => End::Lzma(*lzma),
        None => End::Untyped(error.kind()),
    }
}

// The observable result of decoding `input` to the end: every byte the
// decoder handed back, how the decoding ended (and the `io::ErrorKind` of
// the error, if any), and how many input bytes the decoder had consumed.
#[derive(Debug)]
struct DecodeRun {
    output: Vec<u8>,
    end: End,
    kind: Option<io::ErrorKind>,
    consumed: usize,
}

fn planned_decoder(memlimit: u64) -> Stream {
    Stream::new_stream_decoder(memlimit, PLANNED_FLAGS).unwrap()
}

fn decode_with(input: &[u8], read_size: usize, window: usize, stream: Stream) -> DecodeRun {
    let mut decoder = XzDecoder::new_stream(CountingSliceReader::new(input, window), stream);
    let mut buf = vec![0u8; read_size];
    let mut output = Vec::new();

    let (end, kind) = loop {
        match decoder.read(&mut buf) {
            Ok(0) => break (End::Clean, None),
            Ok(n) => output.extend_from_slice(&buf[..n]),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => break (end_of(&error), Some(error.kind())),
        }
    };

    // The wrapper hands the reader below exactly what liblzma consumed, so
    // counting `consume()` below the decoder measures liblzma's own input
    // position -- the property the production counting layer relies on.
    let consumed = decoder.get_ref().consumed;
    assert_eq!(consumed as u64, decoder.total_in());

    DecodeRun {
        output,
        end,
        kind,
        consumed,
    }
}

fn decode(input: &[u8], read_size: usize, window: usize) -> DecodeRun {
    decode_with(input, read_size, window, planned_decoder(PLANNED_MEMLIMIT))
}

// Decodes `input` with every read size x input window, calling `check` on
// each run.
fn for_all_shapes(input: &[u8], mut check: impl FnMut(&DecodeRun, usize, usize)) {
    for read_size in READ_SIZES {
        for window in INPUT_WINDOWS {
            check(&decode(input, read_size, window), read_size, window);
        }
    }
}

// Every shape decodes `input` completely to `expected`, ends cleanly and
// has consumed the whole input when it does.
fn assert_valid(input: &[u8], expected: &[u8]) {
    for_all_shapes(input, |run, read_size, window| {
        let shape = format!("read_size={read_size} window={window}");
        assert_eq!(run.end, End::Clean, "{shape}");
        assert!(run.output == expected, "output differs at {shape}");
        assert_eq!(
            run.consumed,
            input.len(),
            "a clean end consumes all input ({shape})"
        );
    });
}

// Every shape fails with exactly `end`, having handed back only a prefix of
// `valid_before` (the payload of the streams before the defect): never a
// clean end, never a byte that is not part of the valid data. How much of
// that prefix arrives before the error depends on the read shape -- see
// `the_whole_payload_can_be_returned_before_a_block_check_error`.
fn assert_rejected(input: &[u8], end: End, valid_before: &[u8]) {
    for_all_shapes(input, |run, read_size, window| {
        let shape = format!("read_size={read_size} window={window}");
        assert_eq!(run.end, end, "{shape}");
        assert!(
            valid_before.starts_with(&run.output),
            "output is not a prefix of the valid data at {shape} ({} bytes)",
            run.output.len()
        );
    });
}

// Input windows small enough that the damaged bytes arrive in a later
// `fill_buf()` than the payload's last bytes -- the situation production
// hits whenever the damage lies past a 256 KiB input-buffer boundary.
const SMALL_INPUT_WINDOWS: [usize; 2] = [1, 3];

// When the damage arrives in a later `fill_buf()` than the payload's last
// bytes, the decoder has handed back every byte of `payload` through
// `Ok(n)` -- whatever the read size -- by the time the error surfaces. (If
// the damage arrives in the same `fill_buf()`, liblzma may detect it in the
// same call that decoded the last bytes; the crate then returns the error
// and drops those bytes. Which case happens depends only on where input
// buffer boundaries fall, so production must be safe in both.)
fn assert_whole_payload_returned_before(input: &[u8], end: End, payload: &[u8]) {
    for read_size in READ_SIZES {
        for window in SMALL_INPUT_WINDOWS {
            let run = decode(input, read_size, window);
            assert_eq!(run.end, end, "read_size={read_size} window={window}");
            assert!(
                run.output == payload,
                "expected all {} payload bytes before the error, got {} (read_size={read_size} window={window})",
                payload.len(),
                run.output.len()
            );
        }
    }
}

// ---------------------------------------------------------------------
// X1-X4: valid streams.
// ---------------------------------------------------------------------

#[test]
fn x1_single_stream_decodes_completely_with_every_supported_check() {
    let a = payload_a();

    for (check, check_id) in [(Check::Crc32, 1), (Check::Crc64, 4), (Check::Sha256, 10)] {
        let stream = xz(&a, check);
        assert_eq!(stream[7], check_id, "fixture carries {check:?}");
        assert_valid(&stream, &a);
    }
}

#[test]
fn x2_concatenated_streams_decode_as_one() {
    let (a, b, c) = (payload_a(), payload_b(), payload_c());
    let sa = xz(&a, Check::Crc32);
    let sb = xz(&b, Check::Crc64);
    let sc = xz(&c, Check::Sha256);

    assert_valid(&concat(&[&sa, &sb]), &concat(&[&a, &b]));
    assert_valid(&concat(&[&sa, &sb, &sc]), &concat(&[&a, &b, &c]));
}

#[test]
fn x3_multi_block_stream_decodes_completely() {
    let a = payload_a();
    let stream = xz_blocks(
        &[&a[..20_000], &a[20_000..40_000], &a[40_000..]],
        Check::Crc64,
    );

    // The Index lists three Blocks (indicator 0x00, then the record count).
    let index = index_range(&stream);
    assert_eq!(stream[index.start], 0x00);
    assert_eq!(stream[index.start + 1], 3);

    assert_valid(&stream, &a);
}

#[test]
fn x4_empty_streams_decode_to_nothing() {
    let a = payload_a();
    let empty = xz(&[], Check::Crc64);

    assert_valid(&empty, &[]);
    assert_valid(&concat(&[&empty, &xz(&a, Check::Crc64), &empty]), &a);
}

// ---------------------------------------------------------------------
// X5-X6: Stream Padding (only multiples of four bytes are valid).
// ---------------------------------------------------------------------

#[test]
fn x5_stream_padding_of_a_multiple_of_four_bytes_is_accepted() {
    let (a, b) = (payload_a(), payload_b());
    let sa = xz(&a, Check::Crc64);
    let sb = xz(&b, Check::Crc32);

    for len in [4, 8, 12, 1024] {
        assert_valid(&concat(&[&sa, &zeros(len)]), &a);
    }
    assert_valid(&concat(&[&sa, &zeros(4), &sb]), &concat(&[&a, &b]));
    assert_valid(
        &concat(&[&sa, &zeros(8), &sb, &zeros(4)]),
        &concat(&[&a, &b]),
    );
}

// Padding whose length is not a multiple of four is a data error (liblzma
// LZMA_DATA_ERROR), both after the last stream and between streams. The
// streams before it were complete and valid, so their payload may already
// have been returned.
#[test]
fn x6_stream_padding_of_other_lengths_is_a_data_error() {
    let (a, b) = (payload_a(), payload_b());
    let sa = xz(&a, Check::Crc64);
    let sb = xz(&b, Check::Crc32);

    for len in [1, 2, 3, 5, 6, 7] {
        let input = concat(&[&sa, &zeros(len)]);
        assert_rejected(&input, End::Lzma(Error::Data), &a);
        assert_whole_payload_returned_before(&input, End::Lzma(Error::Data), &a);
    }
    for len in [1, 3, 5] {
        assert_rejected(
            &concat(&[&sa, &zeros(len), &sb]),
            End::Lzma(Error::Data),
            &a,
        );
    }
}

// ---------------------------------------------------------------------
// X7-X8: trailing garbage.
// ---------------------------------------------------------------------

// 12 or more non-padding bytes after a stream are read as the next Stream
// Header; a later stream with the wrong magic is LZMA_DATA_ERROR (liblzma
// reports LZMA_FORMAT_ERROR only for the first stream).
#[test]
fn x7_trailing_garbage_of_twelve_bytes_or_more_is_a_data_error() {
    let a = payload_a();
    let sa = xz(&a, Check::Crc64);
    let gzip_like = concat(&[&[0x1F, 0x8B, 0x08, 0x00], &[0xAA; 16]]);

    for garbage in [
        vec![0xAA; 12],
        vec![0xAA; 16],
        vec![0xAA; 64],
        concat(&[&zeros(4), &[0xAA; 12]]),
        gzip_like,
    ] {
        assert_rejected(&concat(&[&sa, &garbage]), End::Lzma(Error::Data), &a);
    }
}

// Fewer than 12 bytes after a stream are an incomplete next Stream Header:
// liblzma never reports an end, and the crate's `XzDecoder` raises its own
// untyped `UnexpectedEof` ("premature eof") at the end of input. The same
// happens for a complete, valid next Stream Header with nothing after it.
#[test]
fn x8_trailing_garbage_shorter_than_twelve_bytes_is_an_untyped_unexpected_eof() {
    let a = payload_a();
    let sa = xz(&a, Check::Crc64);
    let next_header_only = xz(&[], Check::Crc64)[..STREAM_HEADER_LEN].to_vec();

    for len in 1..12 {
        assert_rejected(
            &concat(&[&sa, &vec![0xAA; len]]),
            End::Untyped(io::ErrorKind::UnexpectedEof),
            &a,
        );
    }
    assert_rejected(
        &concat(&[&sa, &zeros(4), &[0xAA, 0xBB]]),
        End::Untyped(io::ErrorKind::UnexpectedEof),
        &a,
    );
    assert_rejected(
        &concat(&[&sa, &next_header_only]),
        End::Untyped(io::ErrorKind::UnexpectedEof),
        &a,
    );
}

// ---------------------------------------------------------------------
// X9: truncation.
// ---------------------------------------------------------------------

// Cutting a single stream anywhere -- including inside the Block, the
// Check, the Index and the Stream Footer, and to zero bytes -- never ends
// cleanly: every cut is an untyped `UnexpectedEof`, and nothing but a
// prefix of the payload is ever returned.
#[test]
fn x9_truncation_at_every_offset_never_ends_cleanly() {
    let payload = payload_small();
    let stream = xz(&payload, Check::Crc64);

    for cut in 0..stream.len() {
        for (read_size, window) in [(4096, 8192), (7, 3)] {
            let run = decode(&stream[..cut], read_size, window);
            assert_eq!(
                run.end,
                End::Untyped(io::ErrorKind::UnexpectedEof),
                "cut={cut} read_size={read_size} window={window}"
            );
            assert!(payload.starts_with(&run.output), "cut={cut}");
        }
    }
}

// A cut exactly at a stream boundary (with valid padding) is a complete,
// shorter file and decodes cleanly -- the decoder cannot know more was
// intended. Detecting that needs something outside the stream (e.g. the
// file's size at open time). Every cut inside the second stream fails.
#[test]
fn x9b_truncation_exactly_at_a_stream_boundary_is_a_valid_shorter_file() {
    let (a, b) = (payload_small(), payload_c());
    let sa = xz(&a, Check::Crc64);
    let sb = xz(&b, Check::Crc32);
    let whole = concat(&[&sa, &zeros(4), &sb]);

    assert_valid(&whole[..sa.len()], &a);
    assert_valid(&whole[..sa.len() + 4], &a);

    for cut in sa.len() + 5..whole.len() {
        let run = decode(&whole[..cut], 4096, 8192);
        assert_ne!(run.end, End::Clean, "cut={cut}");
        assert!(concat(&[&a, &b]).starts_with(&run.output), "cut={cut}");
    }
}

// ---------------------------------------------------------------------
// X10-X11: Check=None (must be refused in every stream).
// ---------------------------------------------------------------------

// TELL_NO_CHECK makes liblzma stop right after the Stream Header of a
// stream without an integrity check, before any of its Blocks is decoded:
// no output at all, and a typed `NoCheck`.
#[test]
fn x10_check_none_in_the_first_stream_is_reported_before_any_output() {
    let a = payload_a();
    let none = xz(&a, Check::None);
    assert_eq!(none[7], 0x00, "fixture carries Check=None");

    assert_rejected(&none, End::Lzma(Error::NoCheck), &[]);
}

// The check is re-evaluated at every Stream Header, so a stream without a
// check after valid ones is caught too, before any of its own payload is
// returned -- whatever the read shape.
#[test]
fn x11_check_none_in_a_later_stream_is_reported_before_its_payload() {
    let (a, b, c) = (payload_a(), payload_b(), payload_c());
    let sa = xz(&a, Check::Crc64);
    let sb = xz(&b, Check::Crc32);
    let none = xz(&c, Check::None);

    assert_rejected(&concat(&[&sa, &none]), End::Lzma(Error::NoCheck), &a);
    assert_rejected(
        &concat(&[&sa, &zeros(8), &none]),
        End::Lzma(Error::NoCheck),
        &a,
    );
    assert_rejected(
        &concat(&[&sa, &sb, &none]),
        End::Lzma(Error::NoCheck),
        &concat(&[&a, &b]),
    );
    assert_whole_payload_returned_before(&concat(&[&sa, &none]), End::Lzma(Error::NoCheck), &a);
}

// Without TELL_NO_CHECK the very same inputs decode cleanly: nothing else
// in liblzma refuses Check=None, which is why the flag is mandatory.
#[test]
fn x11b_without_tell_no_check_check_none_is_accepted_silently() {
    let (a, c) = (payload_a(), payload_c());
    let input = concat(&[&xz(&a, Check::Crc64), &xz(&c, Check::None)]);

    let stream = Stream::new_stream_decoder(PLANNED_MEMLIMIT, CONCATENATED).unwrap();
    let run = decode_with(&input, 4096, 8192, stream);
    assert_eq!(run.end, End::Clean);
    assert!(run.output == concat(&[&a, &c]));
}

// ---------------------------------------------------------------------
// X12: reserved / unknown Check IDs.
// ---------------------------------------------------------------------

// Sanity for the patcher: rewriting a stream's own Check ID changes
// nothing, and changing the ID without fixing the CRC32s is caught by the
// Stream Header's CRC32 (LZMA_DATA_ERROR) before any output.
#[test]
fn x12a_check_id_patching_keeps_the_stream_valid() {
    let a = payload_a();
    let stream = xz(&a, Check::Crc64);

    assert_valid(&with_check_id(&stream, 4), &a);

    let mut unfixed = stream.clone();
    unfixed[7] = 5;
    assert_rejected(&unfixed, End::Lzma(Error::Data), &[]);
}

// Reserved Check IDs (the format defines only 0, 1, 4 and 10) are reported
// by TELL_UNSUPPORTED_CHECK as a typed `UnsupportedCheck`, right after the
// Stream Header, in any stream. IDs are swapped only within the same
// check-field size (4, 8 or 32 bytes), so the rest of the file is valid.
#[test]
fn x12_reserved_check_ids_are_reported_as_unsupported() {
    let a = payload_a();

    for (check, reserved_ids) in [
        (Check::Crc32, [2, 3]),
        (Check::Crc64, [5, 6]),
        (Check::Sha256, [11, 12]),
    ] {
        let stream = xz(&a, check);
        for id in reserved_ids {
            let patched = with_check_id(&stream, id);
            assert_rejected(&patched, End::Lzma(Error::UnsupportedCheck), &[]);

            let later = concat(&[&xz(&payload_b(), Check::Crc32), &patched]);
            assert_rejected(&later, End::Lzma(Error::UnsupportedCheck), &payload_b());
        }
    }
}

// Without TELL_UNSUPPORTED_CHECK liblzma decodes such a stream without
// verifying any integrity check at all -- which is why the flag is
// mandatory.
#[test]
fn x12b_without_tell_unsupported_check_reserved_ids_are_decoded_unverified() {
    let a = payload_a();
    let patched = with_check_id(&xz(&a, Check::Crc64), 5);

    let stream =
        Stream::new_stream_decoder(PLANNED_MEMLIMIT, TELL_NO_CHECK | CONCATENATED).unwrap();
    let run = decode_with(&patched, 4096, 8192, stream);
    assert_eq!(run.end, End::Clean);
    assert!(run.output == a);
}

// ---------------------------------------------------------------------
// X13-X16: integrity damage after the payload.
// ---------------------------------------------------------------------

// A wrong Block Check is found only after the whole Block has been decoded:
// the decoder can hand back every payload byte through `Ok(n)` -- i.e.
// produce exactly the image's logical size -- and only report the damage on
// a later read. A decoder reaching the logical size therefore proves
// nothing about the stream; the end of the stream must be verified before
// the final bytes are released (StrictReplayReader's contract). See
// `assert_whole_payload_returned_before` for when the last bytes are
// dropped instead.
#[test]
fn x13_the_whole_payload_can_be_returned_before_a_block_check_error() {
    let a = payload_a();

    for check in [Check::Crc32, Check::Crc64, Check::Sha256] {
        let stream = xz(&a, check);
        // The Check field is the last thing before the Index.
        let damaged = flipped(&stream, index_range(&stream).start - 1);

        assert_rejected(&damaged, End::Lzma(Error::Data), &a);
        assert_whole_payload_returned_before(&damaged, End::Lzma(Error::Data), &a);
    }
}

// Damage in the Index (its record count or its CRC32) is found after the
// whole payload, as LZMA_DATA_ERROR.
#[test]
fn x14_index_damage_is_a_data_error_after_the_payload() {
    let a = payload_a();
    let stream = xz(&a, Check::Crc64);
    let index = index_range(&stream);

    for position in [index.start + 1, index.end - 1] {
        let damaged = flipped(&stream, position);
        assert_rejected(&damaged, End::Lzma(Error::Data), &a);
        assert_whole_payload_returned_before(&damaged, End::Lzma(Error::Data), &a);
    }
}

// Damage anywhere in the Stream Footer -- CRC32, Backward Size, Stream
// Flags, or the "YZ" magic (liblzma turns a footer LZMA_FORMAT_ERROR into
// LZMA_DATA_ERROR) -- is found after the whole payload.
#[test]
fn x15_stream_footer_damage_is_a_data_error_after_the_payload() {
    let a = payload_a();
    let stream = xz(&a, Check::Crc64);
    let footer = footer_start(&stream);

    for offset in [0, 3, 4, 8, 9, 10, 11] {
        let damaged = flipped(&stream, footer + offset);
        assert_rejected(&damaged, End::Lzma(Error::Data), &a);
        assert_whole_payload_returned_before(&damaged, End::Lzma(Error::Data), &a);
    }
}

// Damage in the first Stream Header is found before any output: a bad
// CRC32 is LZMA_DATA_ERROR, a bad magic is LZMA_FORMAT_ERROR (first stream
// only; in a later stream it would be LZMA_DATA_ERROR, see X7).
#[test]
fn x15b_stream_header_damage_is_reported_before_any_output() {
    let a = payload_a();
    let stream = xz(&a, Check::Crc64);

    assert_rejected(&flipped(&stream, 8), End::Lzma(Error::Data), &[]);
    assert_rejected(&flipped(&stream, 0), End::Lzma(Error::Format), &[]);
}

// Flipping any single byte of a small stream never produces a clean end:
// whatever the decoder hands back before noticing, the damage is always
// reported.
#[test]
fn x16_damage_anywhere_always_ends_in_an_error() {
    let payload = payload_small();
    let stream = xz(&payload, Check::Crc64);

    for position in 0..stream.len() {
        let run = decode(&flipped(&stream, position), 4096, 8192);
        assert_ne!(
            run.end,
            End::Clean,
            "flipping byte {position} ended cleanly"
        );
    }
}

// ---------------------------------------------------------------------
// X17-X18: memory limit.
// ---------------------------------------------------------------------

// A Block whose filter chain needs more memory than the decoder's limit is
// refused with a typed `MemLimit` before any of that Block is decoded --
// in the first stream, or in a later one after the earlier streams'
// payload.
#[test]
fn x17_a_small_memory_limit_is_reported_as_mem_limit() {
    let (a, b) = (payload_a(), payload_b());
    let small_dictionary = xz(&a, Check::Crc64); // preset 0: 256 KiB
    let large_dictionary = xz_with_dictionary(&b, 4 * 1024 * 1024);

    let run = decode_with(&small_dictionary, 4096, 8192, planned_decoder(64 * 1024));
    assert_eq!(run.end, End::Lzma(Error::MemLimit));
    assert!(run.output.is_empty());

    let input = concat(&[&small_dictionary, &large_dictionary]);
    for (read_size, window) in [(1, 8192), (4096, 8192), (1 << 20, 8192)] {
        let run = decode_with(&input, read_size, window, planned_decoder(2 * 1024 * 1024));
        assert_eq!(run.end, End::Lzma(Error::MemLimit));
        assert!(a.starts_with(&run.output));
    }

    assert_valid(&input, &concat(&[&a, &b]));
}

// Under the planned 512 MiB limit, a Block declaring a 64 MiB dictionary
// (what `xz -9` uses) decodes, while one declaring a 512 MiB or 1.5 GiB
// dictionary is refused with `MemLimit` before any output. The limit is
// checked against the declared dictionary before it is allocated.
//
// LZMA2 dictionary byte `p`: 2^(p/2 + 12) for even `p`, 3 * 2^((p-1)/2 +
// 11) for odd `p`; 28 -> 64 MiB, 34 -> 512 MiB, 40 -> 1.5 GiB.
#[test]
fn x18_the_planned_limit_accepts_xz_9_dictionaries_and_refuses_larger_ones() {
    let a = payload_a();
    let stream = xz(&a, Check::Crc64);

    let run = decode(&with_declared_dictionary(&stream, 28), 4096, 8192);
    assert_eq!(run.end, End::Clean);
    assert!(run.output == a);

    for dictionary_byte in [34, 40] {
        let run = decode(
            &with_declared_dictionary(&stream, dictionary_byte),
            4096,
            8192,
        );
        assert_eq!(
            run.end,
            End::Lzma(Error::MemLimit),
            "byte {dictionary_byte}"
        );
        assert!(run.output.is_empty());
    }
}

// ---------------------------------------------------------------------
// X19-X20: concatenation and the end of the stream.
// ---------------------------------------------------------------------

// Without CONCATENATED the decoder ends cleanly after the first stream,
// leaving what follows (padding, or further streams) unconsumed. A clean
// end alone therefore does not prove the whole file was read: the planned
// decoder uses CONCATENATED, and production still checks that the
// consumed count equals the file's size.
#[test]
fn x19_without_concatenated_the_decoder_stops_after_the_first_stream() {
    let (a, b) = (payload_a(), payload_b());
    let sa = xz(&a, Check::Crc64);

    for rest in [xz(&b, Check::Crc32), zeros(4)] {
        let input = concat(&[&sa, &rest]);
        let stream =
            Stream::new_stream_decoder(PLANNED_MEMLIMIT, TELL_NO_CHECK | TELL_UNSUPPORTED_CHECK)
                .unwrap();
        let run = decode_with(&input, 4096, 8192, stream);
        assert_eq!(run.end, End::Clean);
        assert!(run.output == a);
        assert_eq!(run.consumed, sa.len());
        assert!(run.consumed < input.len());
    }
}

// Once the planned decoder has ended cleanly, it stays ended: later reads
// return `Ok(0)` and consume nothing.
#[test]
fn x20_a_clean_end_is_stable() {
    let a = payload_a();
    let input = concat(&[&xz(&a, Check::Crc64), &zeros(4)]);
    let mut decoder = XzDecoder::new_stream(
        CountingSliceReader::new(&input, 8192),
        planned_decoder(PLANNED_MEMLIMIT),
    );

    let mut output = Vec::new();
    decoder.read_to_end(&mut output).unwrap();
    assert!(output == a);

    let mut buf = [0u8; 64];
    for _ in 0..3 {
        assert_eq!(decoder.read(&mut buf).unwrap(), 0);
        assert_eq!(decoder.get_ref().consumed, input.len());
    }
}

// ---------------------------------------------------------------------
// X21: the stream decoder accepts .xz only.
// ---------------------------------------------------------------------

// The planned stream decoder (unlike liblzma's auto decoder) refuses legacy
// .lzma data, .lz (lzip) data and other formats as a typed `Format` error
// before any output. After a valid .xz stream, .lzma data is a `Data`
// error like any other garbage.
#[test]
fn x21_legacy_lzma_lzip_and_other_formats_are_not_accepted() {
    let a = payload_a();
    let lzma_alone = encode_with(
        Stream::new_lzma_encoder(&LzmaOptions::new_preset(0).unwrap()).unwrap(),
        &[&a],
    );
    let lzip_like = concat(&[b"LZIP", &[0x01, 0x0C], &zeros(32)]);
    let gzip_like = concat(&[&[0x1F, 0x8B, 0x08, 0x00], &zeros(32)]);

    for input in [&lzma_alone, &lzip_like, &gzip_like, &zeros(32)] {
        assert_rejected(input, End::Lzma(Error::Format), &[]);
    }

    assert_rejected(
        &concat(&[&xz(&a, Check::Crc64), &lzma_alone]),
        End::Lzma(Error::Data),
        &a,
    );
}

// ---------------------------------------------------------------------
// X22-X24: error typing and propagation.
// ---------------------------------------------------------------------

// The liblzma errors production must tell apart come out of the decoder as
// `io::Error`s whose payload downcasts to `liblzma::stream::Error` -- no
// message text involved -- with these kinds (the crate's `From` mapping).
// The crate's own end-of-input error carries no typed payload.
#[test]
fn x22_liblzma_errors_are_typed_and_have_stable_kinds() {
    let a = payload_a();
    let sa = xz(&a, Check::Crc64);
    let cases = [
        (
            xz(&a, Check::None),
            PLANNED_MEMLIMIT,
            Error::NoCheck,
            io::ErrorKind::InvalidInput,
        ),
        (
            with_check_id(&sa, 5),
            PLANNED_MEMLIMIT,
            Error::UnsupportedCheck,
            io::ErrorKind::Other,
        ),
        (sa.clone(), 64 * 1024, Error::MemLimit, io::ErrorKind::Other),
        (
            flipped(&sa, footer_start(&sa)),
            PLANNED_MEMLIMIT,
            Error::Data,
            io::ErrorKind::InvalidData,
        ),
        (
            zeros(32),
            PLANNED_MEMLIMIT,
            Error::Format,
            io::ErrorKind::InvalidData,
        ),
    ];

    for (input, memlimit, error, kind) in cases {
        let run = decode_with(&input, 4096, 8192, planned_decoder(memlimit));
        assert_eq!(run.end, End::Lzma(error));
        assert_eq!(run.kind, Some(kind), "{error:?}");
    }

    let truncated = decode(&sa[..sa.len() - 1], 4096, 8192);
    assert_eq!(truncated.end, End::Untyped(io::ErrorKind::UnexpectedEof));
}

#[derive(Debug)]
struct StopRequested;

impl std::fmt::Display for StopRequested {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("stop requested")
    }
}

impl std::error::Error for StopRequested {}

// A `BufRead` below the decoder that fails its `fill_buf()` after a given
// number of calls -- the shape the production cancellation / budget check
// takes.
struct FailingAfterFills<'a> {
    inner: CountingSliceReader<'a>,
    fills_left: usize,
}

impl Read for FailingAfterFills<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let available = self.fill_buf()?;
        let n = available.len().min(buf.len());
        buf[..n].copy_from_slice(&available[..n]);
        self.consume(n);
        Ok(n)
    }
}

impl BufRead for FailingAfterFills<'_> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        if self.fills_left == 0 {
            return Err(io::Error::other(StopRequested));
        }
        self.fills_left -= 1;
        self.inner.fill_buf()
    }

    fn consume(&mut self, amount: usize) {
        self.inner.consume(amount);
    }
}

// An error raised by the reader below the decoder comes back out of the
// decoder unchanged (same kind, original payload recoverable by
// downcasting), exactly as with the gzip decoder -- including while the
// decoder is only consuming Stream Padding and producing nothing.
#[test]
fn x23_errors_from_below_the_decoder_propagate_unchanged() {
    let a = payload_a();
    let sa = xz(&a, Check::Crc64);
    let padded = concat(&[&sa, &zeros(4096)]);

    for (input, fills) in [(&sa, 5), (&padded, sa.len() + 100)] {
        let mut decoder = XzDecoder::new_stream(
            FailingAfterFills {
                inner: CountingSliceReader::new(input, 1),
                fills_left: fills,
            },
            planned_decoder(PLANNED_MEMLIMIT),
        );

        let mut sink = Vec::new();
        let error = decoder.read_to_end(&mut sink).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::Other);
        assert!(
            error
                .get_ref()
                .is_some_and(|inner| inner.is::<StopRequested>())
        );
    }
}

// The production replay reader must stay `Send`; the decoder it will wrap
// is `Send` as long as its input is.
#[test]
fn x24_the_decoder_is_send() {
    fn assert_send<T: Send>() {}
    assert_send::<XzDecoder<CountingSliceReader<'static>>>();
    assert_send::<Stream>();
}
