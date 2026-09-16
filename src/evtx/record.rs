//! A single EVTX event record: a 24-byte header, a BinXML fragment, and a
//! trailing 4-byte copy of the record's size (verified against
//! `libyal/libevtx` and cross-checked against `omerbenamram/evtx`).
//!
//! | Offset | Size | Field                                              |
//! |--------|------|------------------------------------------------------|
//! | 0      | 4    | Signature `\x2a\x2a\x00\x00`                        |
//! | 4      | 4    | Size, including the signature and this field (u32) |
//! | 8      | 8    | Event record identifier (u64 LE)                   |
//! | 16     | 8    | Written date/time: a Windows FILETIME (u64 LE)     |
//! | 24     | ...  | Event data (a BinXML fragment)                     |
//! | end-4  | 4    | Copy of size (u32 LE)                              |

use forensic_rs::prelude::*;
use forensic_rs::{ensure_buffer_size, ensure_format};

pub const EVTX_RECORD_MAGIC: [u8; 4] = [0x2a, 0x2a, 0x00, 0x00];
const FIXED_HEADER_SIZE: usize = 24;

#[derive(Debug, Clone, Copy)]
pub struct EvtxRecordHeader {
    pub size: u32,
    pub record_id: u64,
    pub filetime: u64,
}

impl EvtxRecordHeader {
    /// Parses one record's header and BinXML fragment starting at
    /// `chunk[offset..]`.
    ///
    /// Returns the header, a slice borrowing the record's raw BinXML
    /// fragment bytes, and the offset of the record immediately following it
    /// (`offset + size`).
    pub fn parse_at(chunk: &[u8], offset: usize) -> ForensicResult<(Self, &[u8], usize)> {
        ensure_buffer_size!(chunk, offset, FIXED_HEADER_SIZE, "evtx record header");
        let mut r = ByteReader::new(chunk);
        r.seek_to(offset)?;
        let magic: [u8; 4] = r.read_fixed()?;
        ensure_format!(
            magic == EVTX_RECORD_MAGIC,
            "evtx_record",
            "invalid event record signature"
        );
        let size = r.read_u32_le()?;
        ensure_format!(
            size as usize >= FIXED_HEADER_SIZE + 4,
            "evtx_record",
            "event record smaller than its fixed header"
        );
        ensure_buffer_size!(chunk, offset, size as usize, "evtx record body");

        let record_id = r.read_u64_le()?;
        let filetime = r.read_u64_le()?;
        let binxml_len = size as usize - FIXED_HEADER_SIZE - 4;
        let binxml = r.read_bytes(binxml_len)?;
        let trailing_size = r.read_u32_le()?;
        ensure_format!(
            trailing_size == size,
            "evtx_record",
            "event record trailing size copy mismatch"
        );

        Ok((
            EvtxRecordHeader {
                size,
                record_id,
                filetime,
            },
            binxml,
            offset + size as usize,
        ))
    }

    pub fn timestamp(&self) -> ForensicTimestamp {
        ForensicTimestamp::from_win_filetime(self.filetime)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_record(record_id: u64, binxml: &[u8]) -> Vec<u8> {
        let total_size = FIXED_HEADER_SIZE + binxml.len() + 4;
        let mut buf = vec![0u8; total_size];
        buf[0..4].copy_from_slice(&EVTX_RECORD_MAGIC);
        buf[4..8].copy_from_slice(&(total_size as u32).to_le_bytes());
        buf[8..16].copy_from_slice(&record_id.to_le_bytes());
        buf[16..24].copy_from_slice(&133_514_430_235_959_706u64.to_le_bytes());
        buf[24..24 + binxml.len()].copy_from_slice(binxml);
        buf[total_size - 4..].copy_from_slice(&(total_size as u32).to_le_bytes());
        buf
    }

    #[test]
    fn parses_valid_record() {
        let payload = [1u8, 2, 3, 4];
        let buf = build_record(7, &payload);
        let (header, binxml, next) = EvtxRecordHeader::parse_at(&buf, 0).unwrap();
        assert_eq!(header.record_id, 7);
        assert_eq!(binxml, &payload);
        assert_eq!(next, buf.len());
    }

    #[test]
    fn rejects_bad_magic() {
        let mut buf = build_record(1, &[]);
        buf[0] = 0;
        assert!(EvtxRecordHeader::parse_at(&buf, 0).is_err());
    }

    #[test]
    fn rejects_bad_trailing_size() {
        let mut buf = build_record(1, &[1, 2, 3]);
        let len = buf.len();
        buf[len - 4..].copy_from_slice(&0u32.to_le_bytes());
        assert!(EvtxRecordHeader::parse_at(&buf, 0).is_err());
    }
}
