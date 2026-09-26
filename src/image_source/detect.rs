// Image format detection: pure functions over bytes and file names, no I/O.
// `open_image` (in the parent module) reads the leading bytes from the one
// already-open `File` and hands them here; nothing in this module ever opens
// a path, so detection can never look at a different file than the one that
// is later read as the image.
//
// Content (magic bytes) is the only thing that decides the format. The file
// name is consulted for exactly one purpose: refusing a file whose name
// promises gzip/xz while its content is something else, so a misnamed or
// damaged download is never silently written as a raw image.

use std::path::Path;

use super::{CompressionFormat, ImageSourceError, UnsupportedCompression};

// Enough leading bytes to recognize every signature below (xz and 7z are the
// longest, at 6 bytes). A file shorter than this is still classified -- a
// signature that does not fit simply cannot match.
pub(super) const DETECTION_HEAD_LEN: usize = 6;

// What the leading bytes say the file is. `Raw` means "no known compressed
// or archive signature" -- the existing plain-image path, unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum DetectedFormat {
    Raw,
    Compressed(CompressionFormat),
    Unsupported(UnsupportedCompression),
}

const GZIP_MAGIC: &[u8] = &[0x1F, 0x8B];
const XZ_MAGIC: &[u8] = &[0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00];
const ZSTD_MAGIC: &[u8] = &[0x28, 0xB5, 0x2F, 0xFD];
const BZIP2_MAGIC: &[u8] = &[0x42, 0x5A, 0x68]; // "BZh"
const SEVEN_ZIP_MAGIC: &[u8] = &[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C];
const LZ4_FRAME_MAGIC: &[u8] = &[0x04, 0x22, 0x4D, 0x18];
// PKZIP signatures a ZIP file can start with (APPNOTE.TXT): a local file
// header (the usual case), the end-of-central-directory record (an empty
// archive), and the spanning/split marker. All are 4 bytes starting "PK".
const ZIP_MAGICS: &[&[u8]] = &[
    &[0x50, 0x4B, 0x03, 0x04],
    &[0x50, 0x4B, 0x05, 0x06],
    &[0x50, 0x4B, 0x07, 0x08],
];

// Classifies an image by its leading bytes. `head` may be shorter than
// `DETECTION_HEAD_LEN` (a short or empty file); a signature longer than
// `head` never matches, so a truncated prefix of a signature is `Raw`.
// lzma-alone is deliberately not detected: its "magic" is only a properties
// byte plus dictionary size, too weak to tell apart from raw data.
pub(super) fn detect_format(head: &[u8]) -> DetectedFormat {
    if head.starts_with(XZ_MAGIC) {
        return DetectedFormat::Compressed(CompressionFormat::Xz);
    }
    if head.starts_with(GZIP_MAGIC) {
        return DetectedFormat::Compressed(CompressionFormat::Gzip);
    }
    if head.starts_with(ZSTD_MAGIC) {
        return DetectedFormat::Unsupported(UnsupportedCompression::Zstd);
    }
    if head.starts_with(BZIP2_MAGIC) {
        return DetectedFormat::Unsupported(UnsupportedCompression::Bzip2);
    }
    if ZIP_MAGICS.iter().any(|magic| head.starts_with(magic)) {
        return DetectedFormat::Unsupported(UnsupportedCompression::Zip);
    }
    if head.starts_with(SEVEN_ZIP_MAGIC) {
        return DetectedFormat::Unsupported(UnsupportedCompression::SevenZip);
    }
    if head.starts_with(LZ4_FRAME_MAGIC) {
        return DetectedFormat::Unsupported(UnsupportedCompression::Lz4);
    }
    DetectedFormat::Raw
}

// The compression format the file name promises, if any: only the final
// extension counts (`image.iso.gz` -> gzip), compared case-insensitively
// (`IMAGE.XZ` -> xz). A name without a UTF-8 extension promises nothing.
pub(super) fn format_promised_by_name(path: &Path) -> Option<CompressionFormat> {
    let extension = path.extension()?.to_str()?;

    if extension.eq_ignore_ascii_case("gz") {
        Some(CompressionFormat::Gzip)
    } else if extension.eq_ignore_ascii_case("xz") {
        Some(CompressionFormat::Xz)
    } else {
        None
    }
}

// Rejects a file whose name promises gzip/xz while its content is not that
// format -- including content that is raw or the *other* compression
// format. Content that is compressed under a name that promises nothing
// (e.g. `image.iso` holding xz data) is accepted: content decides.
pub(super) fn check_name_matches_content(
    path: &Path,
    detected: DetectedFormat,
) -> Result<(), ImageSourceError> {
    match format_promised_by_name(path) {
        Some(expected) if detected != DetectedFormat::Compressed(expected) => {
            Err(ImageSourceError::ExtensionMismatch { expected })
        }
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_gzip_and_xz() {
        assert_eq!(
            detect_format(&[0x1F, 0x8B, 0x08, 0x00, 0x00, 0x00]),
            DetectedFormat::Compressed(CompressionFormat::Gzip)
        );
        assert_eq!(
            detect_format(&[0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00]),
            DetectedFormat::Compressed(CompressionFormat::Xz)
        );
    }

    #[test]
    fn detects_known_unsupported_formats() {
        let cases: &[(&[u8], UnsupportedCompression)] = &[
            (
                &[0x28, 0xB5, 0x2F, 0xFD, 0x00, 0x00],
                UnsupportedCompression::Zstd,
            ),
            (b"BZh91A", UnsupportedCompression::Bzip2),
            (
                &[0x50, 0x4B, 0x03, 0x04, 0x14, 0x00],
                UnsupportedCompression::Zip,
            ),
            (
                &[0x50, 0x4B, 0x05, 0x06, 0x00, 0x00],
                UnsupportedCompression::Zip,
            ),
            (
                &[0x50, 0x4B, 0x07, 0x08, 0x00, 0x00],
                UnsupportedCompression::Zip,
            ),
            (
                &[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C],
                UnsupportedCompression::SevenZip,
            ),
            (
                &[0x04, 0x22, 0x4D, 0x18, 0x64, 0x40],
                UnsupportedCompression::Lz4,
            ),
        ];

        for (head, expected) in cases {
            assert_eq!(
                detect_format(head),
                DetectedFormat::Unsupported(*expected),
                "head {head:02X?}"
            );
        }
    }

    #[test]
    fn ordinary_image_starts_are_raw() {
        // MBR boot code, an all-zero ISO system area, and ASCII text.
        assert_eq!(
            detect_format(&[0xEB, 0x63, 0x90, 0x10, 0x8E, 0xD0]),
            DetectedFormat::Raw
        );
        assert_eq!(detect_format(&[0u8; 6]), DetectedFormat::Raw);
        assert_eq!(detect_format(b"hello!"), DetectedFormat::Raw);
    }

    #[test]
    fn empty_and_short_heads_are_raw_unless_a_whole_signature_fits() {
        assert_eq!(detect_format(&[]), DetectedFormat::Raw);
        assert_eq!(detect_format(&[0x1F]), DetectedFormat::Raw);
        assert_eq!(detect_format(&[0xFD, 0x37]), DetectedFormat::Raw);
        assert_eq!(detect_format(&[0x42, 0x5A]), DetectedFormat::Raw);
        assert_eq!(detect_format(&[0x28, 0xB5, 0x2F]), DetectedFormat::Raw);
        assert_eq!(
            detect_format(&[0xFD, 0x37, 0x7A, 0x58, 0x5A]),
            DetectedFormat::Raw
        );
        // A 2-byte file holding exactly the gzip magic is gzip (a signature
        // that fits entirely always matches, whatever the file length).
        assert_eq!(
            detect_format(&[0x1F, 0x8B]),
            DetectedFormat::Compressed(CompressionFormat::Gzip)
        );
        assert_eq!(
            detect_format(b"BZh"),
            DetectedFormat::Unsupported(UnsupportedCompression::Bzip2)
        );
    }

    #[test]
    fn near_miss_signatures_are_raw() {
        // xz magic with a wrong last byte, 7z with a wrong last byte, "PK"
        // without a known record type, and a reversed gzip magic.
        assert_eq!(
            detect_format(&[0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x01]),
            DetectedFormat::Raw
        );
        assert_eq!(
            detect_format(&[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1D]),
            DetectedFormat::Raw
        );
        assert_eq!(
            detect_format(&[0x50, 0x4B, 0x01, 0x02, 0x00, 0x00]),
            DetectedFormat::Raw
        );
        assert_eq!(
            detect_format(&[0x8B, 0x1F, 0x00, 0x00, 0x00, 0x00]),
            DetectedFormat::Raw
        );
    }

    #[test]
    fn name_promises_follow_the_final_extension_case_insensitively() {
        let gzip = Some(CompressionFormat::Gzip);
        let xz = Some(CompressionFormat::Xz);

        assert_eq!(format_promised_by_name(Path::new("a.gz")), gzip);
        assert_eq!(format_promised_by_name(Path::new("a.GZ")), gzip);
        assert_eq!(format_promised_by_name(Path::new("a.iso.gz")), gzip);
        assert_eq!(format_promised_by_name(Path::new("a.xz")), xz);
        assert_eq!(format_promised_by_name(Path::new("a.XZ")), xz);
        assert_eq!(format_promised_by_name(Path::new("a.img.xz")), xz);
        assert_eq!(format_promised_by_name(Path::new("a.iso")), None);
        assert_eq!(format_promised_by_name(Path::new("download")), None);
        assert_eq!(format_promised_by_name(Path::new("a.gz.iso")), None);
    }

    #[test]
    fn matching_name_and_content_is_accepted() {
        let gzip = DetectedFormat::Compressed(CompressionFormat::Gzip);
        let xz = DetectedFormat::Compressed(CompressionFormat::Xz);

        assert!(check_name_matches_content(Path::new("a.gz"), gzip).is_ok());
        assert!(check_name_matches_content(Path::new("a.iso.gz"), gzip).is_ok());
        assert!(check_name_matches_content(Path::new("a.XZ"), xz).is_ok());
        assert!(check_name_matches_content(Path::new("a.img.xz"), xz).is_ok());
    }

    #[test]
    fn content_decides_when_the_name_promises_nothing() {
        let gzip = DetectedFormat::Compressed(CompressionFormat::Gzip);
        let xz = DetectedFormat::Compressed(CompressionFormat::Xz);

        assert!(check_name_matches_content(Path::new("download"), gzip).is_ok());
        assert!(check_name_matches_content(Path::new("image.iso"), xz).is_ok());
        assert!(check_name_matches_content(Path::new("image.iso"), DetectedFormat::Raw).is_ok());
    }

    #[test]
    fn name_promising_compression_without_matching_content_is_rejected() {
        let cases = [
            ("a.gz", DetectedFormat::Raw, CompressionFormat::Gzip),
            ("a.GZ", DetectedFormat::Raw, CompressionFormat::Gzip),
            ("a.xz", DetectedFormat::Raw, CompressionFormat::Xz),
            ("a.img.XZ", DetectedFormat::Raw, CompressionFormat::Xz),
            (
                "a.gz",
                DetectedFormat::Compressed(CompressionFormat::Xz),
                CompressionFormat::Gzip,
            ),
            (
                "a.xz",
                DetectedFormat::Compressed(CompressionFormat::Gzip),
                CompressionFormat::Xz,
            ),
        ];

        for (name, detected, expected) in cases {
            match check_name_matches_content(Path::new(name), detected) {
                Err(ImageSourceError::ExtensionMismatch { expected: got }) => {
                    assert_eq!(got, expected, "{name}")
                }
                other => panic!("{name}: expected ExtensionMismatch, got {other:?}"),
            }
        }
    }
}
