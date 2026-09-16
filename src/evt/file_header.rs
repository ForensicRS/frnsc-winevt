//! The 48-byte legacy `.evt` file header (`ELF_LOGFILE_HEADER`).
//!
//! Layout (verified against the `libyal/libevt` format documentation):
//!
//! | Offset | Size | Field                                          |
//! |--------|------|-------------------------------------------------|
//! | 0      | 4    | Size, including this field (u32 LE, = 48)       |
//! | 4      | 4    | Signature `"LfLe"` / `0x654c664c` (u32 LE)      |
//! | 8      | 4    | Major format version (u32 LE, = 1)              |
//! | 12     | 4    | Minor format version (u32 LE, = 1)              |
//! | 16     | 4    | First (oldest) record offset (u32 LE)           |
//! | 20     | 4    | End-of-file / next-write record offset (u32 LE) |
//! | 24     | 4    | Last (newest) record number (u32 LE)            |
//! | 28     | 4    | First (oldest) record number (u32 LE)           |
//! | 32     | 4    | Maximum file size (u32 LE)                      |
//! | 36     | 4    | File flags (u32 LE)                             |
//! | 40     | 4    | Retention (u32 LE)                              |
//! | 44     | 4    | Copy of size (u32 LE, = 48)                     |

use forensic_rs::prelude::*;
use forensic_rs::{ensure_buffer_size, ensure_format};

pub const EVT_HEADER_SIZE: usize = 48;
pub const EVT_SIGNATURE: u32 = 0x654c_664c; // "LfLe"

/// Bits of [`EvtFileHeader::flags`].
pub const EVT_FILE_FLAG_DIRTY: u32 = 0x1;
pub const EVT_FILE_FLAG_WRAP: u32 = 0x2;
pub const EVT_FILE_FLAG_ARCHIVED: u32 = 0x8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EvtFileHeader {
    pub major_version: u32,
    pub minor_version: u32,
    pub start_offset: u32,
    pub end_offset: u32,
    pub last_record_number: u32,
    pub first_record_number: u32,
    pub max_size: u32,
    pub flags: u32,
    pub retention: u32,
}

impl EvtFileHeader {
    pub fn is_dirty(&self) -> bool {
        self.flags & EVT_FILE_FLAG_DIRTY != 0
    }

    /// Parses the 48-byte header from the start of a `.evt` file.
    pub fn parse(buf: &[u8]) -> ForensicResult<Self> {
        ensure_buffer_size!(buf, 0usize, EVT_HEADER_SIZE, "evt file header");
        let mut r = ByteReader::new(buf);
        let size = r.read_u32_le()?;
        ensure_format!(
            size as usize == EVT_HEADER_SIZE,
            "evt_file_header",
            "unexpected evt file header size"
        );
        let signature = r.read_u32_le()?;
        ensure_format!(
            signature == EVT_SIGNATURE,
            "evt_file_header",
            "invalid EVT file signature"
        );
        let major_version = r.read_u32_le()?;
        let minor_version = r.read_u32_le()?;
        let start_offset = r.read_u32_le()?;
        let end_offset = r.read_u32_le()?;
        let last_record_number = r.read_u32_le()?;
        let first_record_number = r.read_u32_le()?;
        let max_size = r.read_u32_le()?;
        let flags = r.read_u32_le()?;
        let retention = r.read_u32_le()?;
        let end_size = r.read_u32_le()?;
        ensure_format!(
            end_size as usize == EVT_HEADER_SIZE,
            "evt_file_header",
            "evt file header trailing size copy mismatch"
        );
        Ok(Self {
            major_version,
            minor_version,
            start_offset,
            end_offset,
            last_record_number,
            first_record_number,
            max_size,
            flags,
            retention,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_valid_header() -> Vec<u8> {
        let mut buf = vec![0u8; EVT_HEADER_SIZE];
        buf[0..4].copy_from_slice(&(EVT_HEADER_SIZE as u32).to_le_bytes());
        buf[4..8].copy_from_slice(&EVT_SIGNATURE.to_le_bytes());
        buf[8..12].copy_from_slice(&1u32.to_le_bytes());
        buf[12..16].copy_from_slice(&1u32.to_le_bytes());
        buf[16..20].copy_from_slice(&48u32.to_le_bytes()); // start_offset
        buf[20..24].copy_from_slice(&1000u32.to_le_bytes()); // end_offset
        buf[24..28].copy_from_slice(&10u32.to_le_bytes()); // last_record_number
        buf[28..32].copy_from_slice(&1u32.to_le_bytes()); // first_record_number
        buf[32..36].copy_from_slice(&0x10000u32.to_le_bytes()); // max_size
        buf[36..40].copy_from_slice(&0u32.to_le_bytes()); // flags
        buf[40..44].copy_from_slice(&0u32.to_le_bytes()); // retention
        buf[44..48].copy_from_slice(&(EVT_HEADER_SIZE as u32).to_le_bytes());
        buf
    }

    #[test]
    fn parses_valid_header() {
        let buf = build_valid_header();
        let header = EvtFileHeader::parse(&buf).unwrap();
        assert_eq!(header.major_version, 1);
        assert_eq!(header.last_record_number, 10);
        assert_eq!(header.first_record_number, 1);
        assert!(!header.is_dirty());
    }

    #[test]
    fn rejects_bad_signature() {
        let mut buf = build_valid_header();
        buf[4] = 0;
        assert!(EvtFileHeader::parse(&buf).is_err());
    }

    #[test]
    fn rejects_bad_trailing_size_copy() {
        let mut buf = build_valid_header();
        buf[44..48].copy_from_slice(&0u32.to_le_bytes());
        assert!(EvtFileHeader::parse(&buf).is_err());
    }

    #[test]
    fn rejects_truncated_buffer() {
        let buf = vec![0u8; 10];
        assert!(EvtFileHeader::parse(&buf).is_err());
    }
}
