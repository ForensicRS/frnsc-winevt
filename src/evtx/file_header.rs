//! The 4096-byte EVTX file header.
//!
//! Layout (verified against the `libyal/libevtx` format documentation and
//! cross-checked against the `omerbenamram/evtx` parser's field offsets):
//!
//! | Offset | Size | Field                              |
//! |--------|------|-------------------------------------|
//! | 0      | 8    | Signature `"ElfFile\0"`              |
//! | 8      | 8    | First chunk number (u64 LE)          |
//! | 16     | 8    | Last chunk number (u64 LE)           |
//! | 24     | 8    | Next record identifier (u64 LE)      |
//! | 32     | 4    | Header size (u32 LE, normally 128)   |
//! | 36     | 2    | Minor format version (u16 LE)        |
//! | 38     | 2    | Major format version (u16 LE)        |
//! | 40     | 2    | Header block size (u16 LE, = 4096)   |
//! | 42     | 2    | Number of chunks (u16 LE)             |
//! | 44     | 76   | Unused                                |
//! | 120    | 4    | File flags (u32 LE)                   |
//! | 124    | 4    | Checksum: CRC-32 of bytes `0..120`    |
//! | 128    | 3968 | Unused (padding to the 4096 block)    |

use forensic_rs::prelude::*;
use forensic_rs::{ensure_buffer_size, ensure_format};

use crate::crc32::crc32;

pub const EVTX_FILE_MAGIC: [u8; 8] = *b"ElfFile\0";
pub const EVTX_FILE_HEADER_BLOCK_SIZE: usize = 4096;
const CHECKSUM_RANGE: usize = 120;

/// Bits of [`EvtxFileHeader::flags`].
pub const EVTX_FILE_FLAG_DIRTY: u32 = 0x1;
pub const EVTX_FILE_FLAG_FULL: u32 = 0x2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EvtxFileHeader {
    pub first_chunk_number: u64,
    pub last_chunk_number: u64,
    pub next_record_id: u64,
    pub header_size: u32,
    pub minor_version: u16,
    pub major_version: u16,
    pub header_block_size: u16,
    pub chunk_count: u16,
    pub flags: u32,
    pub checksum: u32,
    /// Whether the stored CRC-32 matches the recomputed one. A mismatch does
    /// not fail the parse: a dirty/incompletely-flushed EVTX file (crash,
    /// live acquisition mid-write) is forensically meaningful, not just
    /// "corrupt" — callers can inspect this flag and record it as evidence
    /// rather than the parser silently hiding it or refusing the whole file.
    pub checksum_valid: bool,
}

impl EvtxFileHeader {
    pub fn is_dirty(&self) -> bool {
        self.flags & EVTX_FILE_FLAG_DIRTY != 0
    }

    pub fn is_full(&self) -> bool {
        self.flags & EVTX_FILE_FLAG_FULL != 0
    }

    /// Parses the header from the first [`EVTX_FILE_HEADER_BLOCK_SIZE`] bytes
    /// of an EVTX file. A magic mismatch is a hard error (this isn't an EVTX
    /// file at all); a checksum mismatch is reported via `checksum_valid`
    /// instead of failing.
    pub fn parse(buf: &[u8]) -> ForensicResult<Self> {
        ensure_buffer_size!(buf, 0usize, EVTX_FILE_HEADER_BLOCK_SIZE, "evtx file header");
        let mut r = ByteReader::new(buf);
        let magic: [u8; 8] = r.read_fixed()?;
        ensure_format!(
            magic == EVTX_FILE_MAGIC,
            "evtx_file_header",
            "invalid EVTX file signature"
        );
        let first_chunk_number = r.read_u64_le()?;
        let last_chunk_number = r.read_u64_le()?;
        let next_record_id = r.read_u64_le()?;
        let header_size = r.read_u32_le()?;
        let minor_version = r.read_u16_le()?;
        let major_version = r.read_u16_le()?;
        let header_block_size = r.read_u16_le()?;
        let chunk_count = r.read_u16_le()?;
        r.seek_to(120)?;
        let flags = r.read_u32_le()?;
        let checksum = r.read_u32_le()?;
        let computed = crc32(&buf[0..CHECKSUM_RANGE]);
        Ok(Self {
            first_chunk_number,
            last_chunk_number,
            next_record_id,
            header_size,
            minor_version,
            major_version,
            header_block_size,
            chunk_count,
            flags,
            checksum,
            checksum_valid: computed == checksum,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_valid_header() -> Vec<u8> {
        let mut buf = vec![0u8; EVTX_FILE_HEADER_BLOCK_SIZE];
        buf[0..8].copy_from_slice(&EVTX_FILE_MAGIC);
        buf[8..16].copy_from_slice(&7u64.to_le_bytes()); // first_chunk_number
        buf[16..24].copy_from_slice(&9u64.to_le_bytes()); // last_chunk_number
        buf[24..32].copy_from_slice(&123u64.to_le_bytes()); // next_record_id
        buf[32..36].copy_from_slice(&128u32.to_le_bytes()); // header_size
        buf[36..38].copy_from_slice(&1u16.to_le_bytes()); // minor_version
        buf[38..40].copy_from_slice(&3u16.to_le_bytes()); // major_version
        buf[40..42].copy_from_slice(&4096u16.to_le_bytes()); // header_block_size
        buf[42..44].copy_from_slice(&3u16.to_le_bytes()); // chunk_count
        buf[120..124].copy_from_slice(&0u32.to_le_bytes()); // flags
        let checksum = crc32(&buf[0..120]);
        buf[124..128].copy_from_slice(&checksum.to_le_bytes());
        buf
    }

    #[test]
    fn parses_valid_header() {
        let buf = build_valid_header();
        let header = EvtxFileHeader::parse(&buf).unwrap();
        assert_eq!(header.first_chunk_number, 7);
        assert_eq!(header.last_chunk_number, 9);
        assert_eq!(header.next_record_id, 123);
        assert_eq!(header.major_version, 3);
        assert_eq!(header.minor_version, 1);
        assert_eq!(header.header_block_size, 4096);
        assert_eq!(header.chunk_count, 3);
        assert!(header.checksum_valid);
        assert!(!header.is_dirty());
        assert!(!header.is_full());
    }

    #[test]
    fn rejects_bad_magic() {
        let mut buf = build_valid_header();
        buf[0] = b'X';
        assert!(EvtxFileHeader::parse(&buf).is_err());
    }

    #[test]
    fn flags_a_bad_checksum_without_failing() {
        let mut buf = build_valid_header();
        buf[124] ^= 0xFF; // corrupt the stored checksum
        let header = EvtxFileHeader::parse(&buf).unwrap();
        assert!(!header.checksum_valid);
    }

    #[test]
    fn rejects_truncated_buffer() {
        let buf = vec![0u8; 100];
        assert!(EvtxFileHeader::parse(&buf).is_err());
    }
}
