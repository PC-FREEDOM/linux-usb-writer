// Behavior pinning for `flate2::bufread::MultiGzDecoder` (XZ/GZIP Phase 2A).
//
// Test-only. These tests do not exercise any production code path: they
// record, as executable assertions, how the gzip decoder chosen for the
// future compressed `ImageSource` behaves at the boundaries that matter for
// Preflight and strict end-of-stream validation -- member boundaries,
// footers, truncation, trailing bytes -- and that the behavior is identical
// for every read size and input window. If a future flate2 upgrade changes
// any of this, these tests fail before the production code relies on it.
//
// Fixtures are built in memory with `flate2::write::GzEncoder` and then
// corrupted byte-by-byte (footer CRC32/ISIZE, header fields, truncation,
// appended bytes), so the corruption cases do not depend on the encoder
// being correct. Member layout produced by `GzEncoder` with default
// settings: a 10-byte header, the DEFLATE body, then an 8-byte footer
// (CRC32 little-endian, then ISIZE little-endian).

use std::io::{self, BufRead, Read, Write};

use flate2::Compression;
use flate2::bufread::MultiGzDecoder;
use flate2::write::GzEncoder;

const HEADER_LEN: usize = 10;
const FOOTER_LEN: usize = 8;

// Every read size the tests drive the decoder with (production readers are
// chunked; 1 MiB is the writer's chunk size) ...
const READ_SIZES: [usize; 5] = [1, 7, 64, 4096, 1 << 20];
// ... and every input window the underlying `BufRead` exposes per
// `fill_buf()` call, so member boundaries, footers and trailing bytes fall
// across `fill_buf` boundaries in every possible way for small fixtures.
const INPUT_WINDOWS: [usize; 3] = [1, 3, 8192];

fn gzip_member(payload: &[u8]) -> Vec<u8> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(payload).unwrap();
    encoder.finish().unwrap()
}

fn payload_a() -> Vec<u8> {
    // 64 KiB of poorly-compressible bytes, so the DEFLATE body spans many
    // input windows and several output reads.
    (0..65_536u32)
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
        .collect()
}

fn payload_b() -> Vec<u8> {
    b"hello gzip member B ".repeat(500)
}

fn payload_c() -> Vec<u8> {
    b"xyz".to_vec()
}

fn with_footer_byte_flipped(member: &[u8], offset_from_end: usize) -> Vec<u8> {
    let mut corrupted = member.to_vec();
    let index = corrupted.len() - offset_from_end;
    corrupted[index] ^= 0xFF;
    corrupted
}

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

// The observable result of decoding `input` to the end: every byte the
// decoder handed back, how the decoding ended, and how many input bytes the
// decoder had consumed at that point.
#[derive(Debug)]
struct DecodeRun {
    output: Vec<u8>,
    end: Result<(), io::ErrorKind>,
    consumed: usize,
}

fn decode(input: &[u8], read_size: usize, window: usize) -> DecodeRun {
    let mut decoder = MultiGzDecoder::new(CountingSliceReader::new(input, window));
    let mut buf = vec![0u8; read_size];
    let mut output = Vec::new();

    let end = loop {
        match decoder.read(&mut buf) {
            Ok(0) => break Ok(()),
            Ok(n) => output.extend_from_slice(&buf[..n]),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => break Err(error.kind()),
        }
    };

    DecodeRun {
        output,
        end,
        consumed: decoder.get_ref().consumed,
    }
}

// Decodes `input` with every read size x input window and asserts they all
// agree, returning the common result. This is the "chunk boundaries do not
// matter" guarantee every other test builds on.
fn decode_all_shapes(input: &[u8]) -> DecodeRun {
    let reference = decode(input, 4096, 8192);

    for read_size in READ_SIZES {
        for window in INPUT_WINDOWS {
            let run = decode(input, read_size, window);
            assert_eq!(
                run.output, reference.output,
                "output differs at read_size={read_size} window={window}"
            );
            assert_eq!(
                run.end, reference.end,
                "end differs at read_size={read_size} window={window}"
            );
            assert_eq!(
                run.consumed, reference.consumed,
                "consumed differs at read_size={read_size} window={window}"
            );
        }
    }

    reference
}

fn assert_valid(input: &[u8], expected: &[u8]) {
    let run = decode_all_shapes(input);
    assert_eq!(run.end, Ok(()));
    assert_eq!(run.output, expected);
    assert_eq!(
        run.consumed,
        input.len(),
        "a valid stream consumes all input"
    );
}

// Asserts decoding fails with `kind`, and that every valid payload byte
// before the defect had already been returned to the caller when the error
// surfaced (`returned_before_error`).
fn assert_rejected(input: &[u8], kind: io::ErrorKind, returned_before_error: &[u8]) {
    let run = decode_all_shapes(input);
    assert_eq!(run.end, Err(kind));
    assert_eq!(run.output, returned_before_error);
}

// ---------------------------------------------------------------------
// G1-G4: valid streams.
// ---------------------------------------------------------------------

#[test]
fn g1_single_member_decodes_completely() {
    let a = payload_a();
    assert_valid(&gzip_member(&a), &a);
}

#[test]
fn g2_two_members_decode_as_one_concatenated_stream() {
    let (a, b) = (payload_a(), payload_b());
    let input = [gzip_member(&a), gzip_member(&b)].concat();
    assert_valid(&input, &[a, b].concat());
}

#[test]
fn g3_three_members_decode_as_one_concatenated_stream() {
    let (a, b, c) = (payload_a(), payload_b(), payload_c());
    let input = [gzip_member(&a), gzip_member(&b), gzip_member(&c)].concat();
    assert_valid(&input, &[a, b, c].concat());
}

#[test]
fn g4_empty_member_between_members_is_accepted() {
    let (a, b) = (payload_a(), payload_b());
    let input = [gzip_member(&a), gzip_member(&[]), gzip_member(&b)].concat();
    assert_valid(&input, &[a, b].concat());
}

// ---------------------------------------------------------------------
// G5-G9, G13-G14: integrity and truncation. In every case the decoder hands
// back all payload bytes it could decode *before* reporting the defect.
// ---------------------------------------------------------------------

#[test]
fn g5_crc32_mismatch_is_rejected_after_the_whole_payload_was_returned() {
    let a = payload_a();
    let member = with_footer_byte_flipped(&gzip_member(&a), FOOTER_LEN); // CRC32 byte 0
    assert_rejected(&member, io::ErrorKind::InvalidInput, &a);
}

#[test]
fn g6_isize_mismatch_is_rejected_the_same_way_as_crc() {
    let a = payload_a();
    let member = with_footer_byte_flipped(&gzip_member(&a), 4); // ISIZE byte 0
    // Same kind as a CRC mismatch: flate2 checks both in one comparison.
    assert_rejected(&member, io::ErrorKind::InvalidInput, &a);
}

#[test]
fn g7_truncated_footer_is_rejected() {
    let a = payload_a();
    let member = gzip_member(&a);
    assert_rejected(
        &member[..member.len() - 3],
        io::ErrorKind::UnexpectedEof,
        &a,
    );
}

#[test]
fn g8_truncated_deflate_body_is_rejected() {
    let a = payload_a();
    let member = gzip_member(&a);
    let body_len = member.len() - HEADER_LEN - FOOTER_LEN;
    let truncated = &member[..HEADER_LEN + body_len / 2];

    let run = decode_all_shapes(truncated);
    assert_eq!(run.end, Err(io::ErrorKind::UnexpectedEof));
    assert!(run.output.len() < a.len());
    assert_eq!(run.output, a[..run.output.len()]);
}

#[test]
fn g9_header_only_is_rejected() {
    let member = gzip_member(&payload_a());
    assert_rejected(&member[..HEADER_LEN], io::ErrorKind::UnexpectedEof, &[]);
}

#[test]
fn g13_crc_mismatch_in_second_member_is_rejected() {
    let (a, b) = (payload_a(), payload_b());
    let input = [
        gzip_member(&a),
        with_footer_byte_flipped(&gzip_member(&b), FOOTER_LEN),
    ]
    .concat();
    assert_rejected(&input, io::ErrorKind::InvalidInput, &[a, b].concat());
}

#[test]
fn g14_truncated_second_member_is_rejected() {
    let (a, b) = (payload_a(), payload_b());
    let member_b = gzip_member(&b);
    let input = [gzip_member(&a), member_b[..member_b.len() / 2].to_vec()].concat();

    let run = decode_all_shapes(&input);
    assert_eq!(run.end, Err(io::ErrorKind::UnexpectedEof));
    // All of A, plus whatever part of B could be decoded, was returned.
    assert!(run.output.len() > a.len());
    assert_eq!(run.output[..a.len()], a[..]);
}

// ---------------------------------------------------------------------
// G10-G12, G15: bytes after the last valid member are always an error,
// never silently ignored -- but the error *kind* depends on how many bytes
// follow: fewer than a gzip header (10 bytes) -> UnexpectedEof (the decoder
// tried to read a next header and ran out); 10+ non-gzip bytes ->
// InvalidInput ("invalid gzip header"). Callers therefore cannot tell
// "trailing data" from "truncation" by kind alone.
// ---------------------------------------------------------------------

#[test]
fn g10_short_trailing_garbage_is_rejected() {
    let a = payload_a();
    let input = [gzip_member(&a), vec![0xDE, 0xAD, 0xBE, 0xEF]].concat();
    assert_rejected(&input, io::ErrorKind::UnexpectedEof, &a);
}

#[test]
fn g10b_long_trailing_garbage_is_rejected_as_an_invalid_header() {
    let a = payload_a();
    let member = gzip_member(&a);
    let input = [member.clone(), vec![0xDE; 16]].concat();

    let run = decode_all_shapes(&input);
    assert_eq!(run.end, Err(io::ErrorKind::InvalidInput));
    assert_eq!(run.output, a);
    // The decoder stopped after reading one would-be header, leaving the
    // rest of the garbage unconsumed.
    assert_eq!(run.consumed, member.len() + HEADER_LEN);
}

#[test]
fn g11_trailing_zero_padding_is_rejected() {
    let a = payload_a();
    let member = gzip_member(&a);

    for padding in [1usize, 2, 8] {
        let input = [member.clone(), vec![0u8; padding]].concat();
        assert_rejected(&input, io::ErrorKind::UnexpectedEof, &a);
    }

    let input = [member.clone(), vec![0u8; 512]].concat();
    assert_rejected(&input, io::ErrorKind::InvalidInput, &a);
}

#[test]
fn g12_trailing_garbage_after_multiple_members_is_rejected() {
    let (a, b) = (payload_a(), payload_b());
    let input = [
        gzip_member(&a),
        gzip_member(&b),
        vec![0xDE, 0xAD, 0xBE, 0xEF],
    ]
    .concat();
    assert_rejected(&input, io::ErrorKind::UnexpectedEof, &[a, b].concat());
}

#[test]
fn g15_another_formats_magic_after_a_member_is_rejected() {
    let a = payload_a();
    let member = gzip_member(&a);

    let xz_magic = vec![0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00];
    let zstd_magic = vec![0x28, 0xB5, 0x2F, 0xFD];
    for trailer in [xz_magic, zstd_magic] {
        let input = [member.clone(), trailer].concat();
        assert_rejected(&input, io::ErrorKind::UnexpectedEof, &a);
    }
}

#[test]
fn incomplete_next_member_header_is_rejected() {
    let a = payload_a();
    let member = gzip_member(&a);

    for partial in [vec![0x1F], vec![0x1F, 0x8B, 0x08]] {
        let input = [member.clone(), partial].concat();
        assert_rejected(&input, io::ErrorKind::UnexpectedEof, &a);
    }

    // A complete next header with no body.
    let input = [
        member.clone(),
        gzip_member(&payload_b())[..HEADER_LEN].to_vec(),
    ]
    .concat();
    assert_rejected(&input, io::ErrorKind::UnexpectedEof, &a);
}

// Known gzip format limitation (not a decoder bug): a multi-member file cut
// exactly at a member boundary is itself a valid, shorter gzip file. Nothing
// in the gzip format records the total, so Preflight cannot detect it; the
// logical size measured by Preflight is the only defense afterwards (a
// replay that ends early is caught by the size check).
#[test]
fn truncation_exactly_at_a_member_boundary_is_indistinguishable_from_a_shorter_file() {
    let (a, b) = (payload_a(), payload_b());
    let first_member_only = gzip_member(&a);
    let _full = [first_member_only.clone(), gzip_member(&b)].concat();

    assert_valid(&first_member_only, &a);
}

// ---------------------------------------------------------------------
// Input consumption: what the decoder consumed vs. what a buffer prefetched.
// ---------------------------------------------------------------------

// A plain `Read` that counts every byte handed out, standing in for a file
// whose OS position advances on every read.
struct CountingRead<'a> {
    data: &'a [u8],
    position: usize,
}

impl Read for CountingRead<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = (self.data.len() - self.position).min(buf.len());
        buf[..n].copy_from_slice(&self.data[self.position..self.position + n]);
        self.position += n;
        Ok(n)
    }
}

// With a real `std::io::BufReader` in between, the underlying reader's
// position is how much was *prefetched*, not how much the decoder
// consumed: after rejecting long trailing garbage, the underlying reader
// has handed out the whole input while the decoder consumed only up to the
// would-be header -- the rest still sits in the `BufReader`'s buffer. So
// "file position == compressed size" does not prove the decoder consumed
// everything; only `consume()`-based counting (below the decoder, above any
// buffer) does.
#[test]
fn underlying_position_measures_prefetch_not_decoder_consumption() {
    let a = payload_a();
    let member = gzip_member(&a);
    let input = [member.clone(), vec![0u8; 512]].concat();

    let buffered = io::BufReader::with_capacity(
        8192,
        CountingRead {
            data: &input,
            position: 0,
        },
    );
    let mut decoder = MultiGzDecoder::new(buffered);
    let mut sink = Vec::new();
    let error = decoder.read_to_end(&mut sink).unwrap_err();

    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    let buffered = decoder.get_ref();
    assert_eq!(
        buffered.get_ref().position,
        input.len(),
        "all input prefetched"
    );
    let consumed = input.len() - buffered.buffer().len();
    assert_eq!(consumed, member.len() + HEADER_LEN, "decoder consumed less");
}

// On a valid stream the decoder only reports end-of-stream (`Ok(0)`) after
// its input reported end-of-input, and by then it has consumed every byte:
// `consume()`-counting equals the compressed size (also asserted for every
// shape by `assert_valid`).
#[test]
fn valid_stream_end_implies_all_input_consumed() {
    let (a, b) = (payload_a(), payload_b());
    let input = [gzip_member(&a), gzip_member(&b)].concat();

    for window in INPUT_WINDOWS {
        let mut decoder = MultiGzDecoder::new(CountingSliceReader::new(&input, window));
        let mut sink = Vec::new();
        decoder.read_to_end(&mut sink).unwrap();
        assert_eq!(decoder.get_ref().consumed, input.len());
        assert!(decoder.get_mut().fill_buf().unwrap().is_empty());
    }
}

// ---------------------------------------------------------------------
// Strict end-of-stream: the decoder returns the last payload bytes *before*
// it validates the footer (G5/G6/G10...). A reader that knows the logical
// size from Preflight can still keep the final bytes from ever reaching its
// caller: when the next read would complete the logical size, it first
// drives the decoder to the end and only then returns those bytes. This
// test-local prototype validates that approach against the real decoder; it
// is not production code.
// ---------------------------------------------------------------------

struct StrictEndPrototype<R: BufRead> {
    decoder: MultiGzDecoder<R>,
    produced: u64,
    logical_size: u64,
}

impl<R: BufRead> Read for StrictEndPrototype<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let remaining = self.logical_size - self.produced;
        let want = (buf.len() as u64).min(remaining) as usize;
        if want == 0 {
            return Ok(0);
        }

        let n = self.decoder.read(&mut buf[..want])?;
        if n == 0 {
            return Ok(0); // ended early: the caller's size check reports it
        }
        self.produced += n as u64;

        if self.produced == self.logical_size {
            let mut scratch = [0u8; 64];
            loop {
                match self.decoder.read(&mut scratch)? {
                    0 => break,
                    _ => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "more output than the validated logical size",
                        ));
                    }
                }
            }
        }

        Ok(n)
    }
}

// Reads `input` through the prototype with `read_size` chunks, returning
// the bytes a writer would have received (only `Ok(n)` data counts) and how
// the read ended.
fn read_strictly(
    input: &[u8],
    logical_size: u64,
    read_size: usize,
    window: usize,
) -> (Vec<u8>, Result<(), io::ErrorKind>) {
    let mut reader = StrictEndPrototype {
        decoder: MultiGzDecoder::new(CountingSliceReader::new(input, window)),
        produced: 0,
        logical_size,
    };
    let mut buf = vec![0u8; read_size];
    let mut delivered = Vec::new();

    let end = loop {
        match reader.read(&mut buf) {
            Ok(0) => break Ok(()),
            Ok(n) => delivered.extend_from_slice(&buf[..n]),
            Err(error) => break Err(error.kind()),
        }
    };

    (delivered, end)
}

#[test]
fn strict_end_prototype_withholds_the_final_bytes_when_the_end_is_invalid() {
    let a = payload_a();
    let member = gzip_member(&a);
    let logical_size = a.len() as u64;

    let invalid_ends = [
        with_footer_byte_flipped(&member, FOOTER_LEN), // CRC
        with_footer_byte_flipped(&member, 4),          // ISIZE
        [member.clone(), vec![0xDE, 0xAD, 0xBE, 0xEF]].concat(),
        [member.clone(), vec![0u8; 512]].concat(),
    ];

    for input in &invalid_ends {
        for read_size in READ_SIZES {
            for window in INPUT_WINDOWS {
                let (delivered, end) = read_strictly(input, logical_size, read_size, window);
                assert!(end.is_err(), "read_size={read_size} window={window}");
                assert!(
                    (delivered.len() as u64) < logical_size,
                    "the final payload bytes must not be delivered \
                     (read_size={read_size} window={window})"
                );
                assert_eq!(delivered, a[..delivered.len()]);
            }
        }
    }
}

#[test]
fn strict_end_prototype_delivers_everything_when_the_end_is_valid() {
    let (a, b) = (payload_a(), payload_b());
    let input = [gzip_member(&a), gzip_member(&[]), gzip_member(&b)].concat();
    let expected = [a, b].concat();

    for read_size in READ_SIZES {
        for window in INPUT_WINDOWS {
            let (delivered, end) = read_strictly(&input, expected.len() as u64, read_size, window);
            assert_eq!(end, Ok(()), "read_size={read_size} window={window}");
            assert_eq!(delivered, expected);
        }
    }
}

#[test]
fn strict_end_prototype_rejects_more_output_than_the_logical_size() {
    let (a, b) = (payload_a(), payload_b());
    let input = [gzip_member(&a), gzip_member(&b)].concat();

    // As if the file had been replaced after Preflight measured only A.
    let (delivered, end) = read_strictly(&input, a.len() as u64, 4096, 8192);
    assert_eq!(end, Err(io::ErrorKind::InvalidData));
    assert!(delivered.len() < a.len());
}

// ---------------------------------------------------------------------
// Malformed headers and many empty members: errors, never panics.
// ---------------------------------------------------------------------

#[test]
fn malformed_headers_are_errors_not_panics() {
    let member = gzip_member(&payload_a());

    let mut wrong_method = member.clone();
    wrong_method[2] = 7; // CM must be 8 (deflate)
    let mut reserved_flags = member.clone();
    reserved_flags[3] = 0xE0; // FLG reserved bits set

    assert_eq!(
        decode_all_shapes(&wrong_method).end,
        Err(io::ErrorKind::InvalidInput)
    );
    assert_eq!(
        decode_all_shapes(&reserved_flags).end,
        Err(io::ErrorKind::InvalidInput)
    );

    // FEXTRA announcing 65535 extra bytes, followed by only 3.
    let huge_extra = [
        0x1F, 0x8B, 8, 0x04, 0, 0, 0, 0, 0, 0xFF, 0xFF, 0xFF, 1, 2, 3,
    ];
    assert_eq!(
        decode_all_shapes(&huge_extra).end,
        Err(io::ErrorKind::UnexpectedEof)
    );

    // FNAME without its terminating NUL.
    let unterminated_name = [0x1F, 0x8B, 8, 0x08, 0, 0, 0, 0, 0, 0xFF, b'a', b'b', b'c'];
    assert_eq!(
        decode_all_shapes(&unterminated_name).end,
        Err(io::ErrorKind::UnexpectedEof)
    );
}

#[test]
fn many_empty_members_decode_to_nothing() {
    let input = gzip_member(&[]).repeat(1000);
    assert_valid(&input, &[]);
}

// ---------------------------------------------------------------------
// Corruption inside the DEFLATE body, and errors raised below the decoder.
// ---------------------------------------------------------------------

// A flipped byte inside the compressed body always ends in an error -- but
// depending on where it lands, the decoder may first emit *wrong* bytes,
// possibly more of them than the original payload, before the footer check
// fails. Anything that streams decoder output onward (a replay feeding the
// writer) must therefore treat every byte as unconfirmed until the stream's
// end has been validated, and must cap output at the validated logical size.
#[test]
fn corrupted_deflate_body_always_ends_in_an_error() {
    let a = payload_a();
    let member = gzip_member(&a);
    let mut saw_more_output_than_payload = false;

    for offset in [
        HEADER_LEN,
        HEADER_LEN + 1,
        50,
        500,
        1000,
        member.len() / 2,
        member.len() - 20,
    ] {
        let mut corrupted = member.clone();
        corrupted[offset] ^= 0x55;

        let run = decode_all_shapes(&corrupted);
        assert!(
            matches!(
                run.end,
                Err(io::ErrorKind::InvalidInput | io::ErrorKind::UnexpectedEof)
            ),
            "offset {offset}: {:?}",
            run.end
        );
        saw_more_output_than_payload |= run.output.len() > a.len();
    }

    assert!(
        saw_more_output_than_payload,
        "expected at least one corruption to over-produce before failing"
    );
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
// number of calls -- the shape a future cancellation check would take.
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
// decoder unchanged: same kind, and the original error value is still
// recoverable by downcasting -- so a cancellation (or any other signal)
// injected below the decoder can be recognized precisely, without matching
// message strings.
#[test]
fn errors_from_below_the_decoder_propagate_unchanged() {
    let member = gzip_member(&payload_a());
    let mut decoder = MultiGzDecoder::new(FailingAfterFills {
        inner: CountingSliceReader::new(&member, 64),
        fills_left: 5,
    });

    let mut sink = Vec::new();
    let error = decoder.read_to_end(&mut sink).unwrap_err();

    assert_eq!(error.kind(), io::ErrorKind::Other);
    assert!(
        error
            .get_ref()
            .is_some_and(|inner| inner.is::<StopRequested>())
    );
}
