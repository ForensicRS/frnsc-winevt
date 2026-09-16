//! A single legacy `EVENTLOGRECORD`.
//!
//! Fixed 56-byte header (verified against the `libyal/libevt` format
//! documentation), followed by variable-length fields addressed by
//! record-relative offsets, followed by a trailing 4-byte copy of the
//! record's total size:
//!
//! | Offset | Size | Field                                            |
//! |--------|------|----------------------------------------------------|
//! | 0      | 4    | Size, including this field (u32 LE)               |
//! | 4      | 4    | Signature `"LfLe"` / `0x654c664c` (u32 LE)         |
//! | 8      | 4    | Record number (u32 LE)                            |
//! | 12     | 4    | Time generated (u32 LE, Unix epoch seconds, UTC)  |
//! | 16     | 4    | Time written (u32 LE, Unix epoch seconds, UTC)    |
//! | 20     | 4    | Event identifier (u32 LE)                         |
//! | 24     | 2    | Event type (u16 LE)                               |
//! | 26     | 2    | Number of strings (u16 LE)                        |
//! | 28     | 2    | Event category (u16 LE)                           |
//! | 30     | 2    | Reserved flags (u16 LE)                           |
//! | 32     | 4    | Closing record number (u32 LE)                    |
//! | 36     | 4    | Event strings offset, record-relative (u32 LE)    |
//! | 40     | 4    | User SID size (u32 LE)                            |
//! | 44     | 4    | User SID offset, record-relative (u32 LE)         |
//! | 48     | 4    | Event data size (u32 LE)                          |
//! | 52     | 4    | Event data offset, record-relative (u32 LE)       |
//! | 56     | ...  | Source name (NUL-terminated UTF-16LE)             |
//! | ...    | ...  | Computer name (NUL-terminated UTF-16LE)           |
//! | ...    | ...  | User SID, event strings, event data, padding      |
//! | end-4  | 4    | Copy of size (u32 LE)                             |

use forensic_rs::prelude::*;
use forensic_rs::utils::win::to_string_sid;
use forensic_rs::{ensure_buffer_size, ensure_format};

pub const EVT_RECORD_SIGNATURE: u32 = 0x654c_664c; // "LfLe"
const FIXED_HEADER_SIZE: usize = 56;

/// Classic `EVENTLOG_*_TYPE` bit values (`winnt.h`).
const EVENTLOG_ERROR_TYPE: u16 = 0x0001;
const EVENTLOG_WARNING_TYPE: u16 = 0x0002;

#[derive(Debug, Clone)]
pub struct EvtRecord {
    pub record_number: u32,
    pub time_generated: u32,
    pub time_written: u32,
    pub event_id_raw: u32,
    pub event_type: u16,
    pub event_category: u16,
    pub source_name: String,
    pub computer_name: String,
    pub user_sid: Option<String>,
    pub strings: Vec<String>,
    pub data: Vec<u8>,
}

impl EvtRecord {
    /// The low 16 bits of the raw event identifier — what Event Viewer shows
    /// as "Event ID" for classic logs (the high bits pack facility/severity
    /// codes in the style of an `NTSTATUS`, per `winnt.h`'s `EVENTLOG_*`
    /// layout, and aren't part of the displayed ID).
    pub fn event_id(&self) -> u32 {
        self.event_id_raw & 0xFFFF
    }

    /// Maps the classic `EVENTLOG_*_TYPE` bit value to the framework's
    /// [`EventLevel`]. There is no legacy equivalent of `Critical`/`Verbose`;
    /// audit success/failure and plain "success" all surface as
    /// `Information`, matching how Event Viewer displays them for logs
    /// migrated from the classic API.
    pub fn level(&self) -> EventLevel {
        match self.event_type {
            EVENTLOG_ERROR_TYPE => EventLevel::Error,
            EVENTLOG_WARNING_TYPE => EventLevel::Warning,
            _ => EventLevel::Information,
        }
    }

    /// Parses one `EVENTLOGRECORD` starting at `buf[offset..]`.
    ///
    /// Returns the parsed record and the offset immediately following it
    /// (`offset + size`), so callers can walk the file sequentially.
    pub fn parse_at(buf: &[u8], offset: usize) -> ForensicResult<(Self, usize)> {
        ensure_buffer_size!(buf, offset, FIXED_HEADER_SIZE, "evt record header");
        let mut r = ByteReader::new(buf);
        r.seek_to(offset)?;
        let size = r.read_u32_le()?;
        ensure_format!(
            size as usize >= FIXED_HEADER_SIZE + 4,
            "evt_record",
            "event record smaller than its fixed header"
        );
        ensure_buffer_size!(buf, offset, size as usize, "evt record body");

        let signature = r.read_u32_le()?;
        ensure_format!(
            signature == EVT_RECORD_SIGNATURE,
            "evt_record",
            "invalid event record signature"
        );
        let record_number = r.read_u32_le()?;
        let time_generated = r.read_u32_le()?;
        let time_written = r.read_u32_le()?;
        let event_id_raw = r.read_u32_le()?;
        let event_type = r.read_u16_le()?;
        let num_strings = r.read_u16_le()?;
        let event_category = r.read_u16_le()?;
        let _reserved_flags = r.read_u16_le()?;
        let _closing_record_number = r.read_u32_le()?;
        let strings_offset = r.read_u32_le()?;
        let user_sid_length = r.read_u32_le()?;
        let user_sid_offset = r.read_u32_le()?;
        let data_length = r.read_u32_le()?;
        let data_offset = r.read_u32_le()?;

        // The remaining fields are addressed by offsets relative to the
        // start of this record, not the reader's current position.
        let source_name = r.read_utf16le_cstring()?;
        let computer_name = r.read_utf16le_cstring()?;

        let user_sid = if user_sid_length > 0 {
            let start = offset + user_sid_offset as usize;
            ensure_buffer_size!(buf, start, user_sid_length as usize, "evt record user sid");
            to_string_sid(&buf[start..start + user_sid_length as usize]).ok()
        } else {
            None
        };

        let mut strings = Vec::with_capacity(num_strings as usize);
        if num_strings > 0 {
            let start = offset + strings_offset as usize;
            let mut sr = ByteReader::new(buf);
            sr.seek_to(start)?;
            for _ in 0..num_strings {
                strings.push(sr.read_utf16le_cstring()?);
            }
        }

        let data = if data_length > 0 {
            let start = offset + data_offset as usize;
            ensure_buffer_size!(buf, start, data_length as usize, "evt record data");
            buf[start..start + data_length as usize].to_vec()
        } else {
            Vec::new()
        };

        let trailing_offset = offset + size as usize - 4;
        let mut tr = ByteReader::new(buf);
        tr.seek_to(trailing_offset)?;
        let trailing_size = tr.read_u32_le()?;
        ensure_format!(
            trailing_size == size,
            "evt_record",
            "event record trailing size copy mismatch"
        );

        Ok((
            EvtRecord {
                record_number,
                time_generated,
                time_written,
                event_id_raw,
                event_type,
                event_category,
                source_name,
                computer_name,
                user_sid,
                strings,
                data,
            },
            offset + size as usize,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utf16le_z(s: &str) -> Vec<u8> {
        let mut out: Vec<u8> = s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        out.extend_from_slice(&0u16.to_le_bytes());
        out
    }

    /// Builds a single valid `EVENTLOGRECORD` at offset 0: source "App",
    /// computer "HOST", no SID, one string, no data.
    fn build_record() -> Vec<u8> {
        let source = utf16le_z("App");
        let computer = utf16le_z("HOST");
        let strings = utf16le_z("something happened");

        let strings_offset = FIXED_HEADER_SIZE + source.len() + computer.len();
        let data_offset = strings_offset + strings.len();
        let total_size = data_offset + 4; // + trailing size copy, no data

        let mut buf = vec![0u8; total_size];
        buf[0..4].copy_from_slice(&(total_size as u32).to_le_bytes());
        buf[4..8].copy_from_slice(&EVT_RECORD_SIGNATURE.to_le_bytes());
        buf[8..12].copy_from_slice(&42u32.to_le_bytes()); // record_number
        buf[12..16].copy_from_slice(&1_700_000_000u32.to_le_bytes()); // time_generated
        buf[16..20].copy_from_slice(&1_700_000_001u32.to_le_bytes()); // time_written
        buf[20..24].copy_from_slice(&0x4000_1000u32.to_le_bytes()); // event_id_raw
        buf[24..26].copy_from_slice(&EVENTLOG_ERROR_TYPE.to_le_bytes()); // event_type
        buf[26..28].copy_from_slice(&1u16.to_le_bytes()); // num_strings
        buf[28..30].copy_from_slice(&0u16.to_le_bytes()); // event_category
        buf[30..32].copy_from_slice(&0u16.to_le_bytes()); // reserved flags
        buf[32..36].copy_from_slice(&0u32.to_le_bytes()); // closing_record_number
        buf[36..40].copy_from_slice(&(strings_offset as u32).to_le_bytes());
        buf[40..44].copy_from_slice(&0u32.to_le_bytes()); // user_sid_length
        buf[44..48].copy_from_slice(&0u32.to_le_bytes()); // user_sid_offset
        buf[48..52].copy_from_slice(&0u32.to_le_bytes()); // data_length
        buf[52..56].copy_from_slice(&(data_offset as u32).to_le_bytes());

        let mut pos = FIXED_HEADER_SIZE;
        buf[pos..pos + source.len()].copy_from_slice(&source);
        pos += source.len();
        buf[pos..pos + computer.len()].copy_from_slice(&computer);
        pos += computer.len();
        buf[pos..pos + strings.len()].copy_from_slice(&strings);

        buf[total_size - 4..].copy_from_slice(&(total_size as u32).to_le_bytes());
        buf
    }

    #[test]
    fn parses_valid_record() {
        let buf = build_record();
        let (record, next) = EvtRecord::parse_at(&buf, 0).unwrap();
        assert_eq!(next, buf.len());
        assert_eq!(record.record_number, 42);
        assert_eq!(record.source_name, "App");
        assert_eq!(record.computer_name, "HOST");
        assert_eq!(record.strings, vec!["something happened".to_string()]);
        assert_eq!(record.event_id(), 0x1000);
        assert_eq!(record.level(), EventLevel::Error);
        assert!(record.user_sid.is_none());
        assert!(record.data.is_empty());
    }

    #[test]
    fn rejects_bad_signature() {
        let mut buf = build_record();
        buf[4] = 0;
        assert!(EvtRecord::parse_at(&buf, 0).is_err());
    }

    #[test]
    fn rejects_bad_trailing_size_copy() {
        let mut buf = build_record();
        let len = buf.len();
        buf[len - 4..].copy_from_slice(&0u32.to_le_bytes());
        assert!(EvtRecord::parse_at(&buf, 0).is_err());
    }

    #[test]
    fn parses_two_sequential_records() {
        let one = build_record();
        let mut buf = one.clone();
        buf.extend_from_slice(&one);
        let (first, next) = EvtRecord::parse_at(&buf, 0).unwrap();
        assert_eq!(first.record_number, 42);
        let (second, next2) = EvtRecord::parse_at(&buf, next).unwrap();
        assert_eq!(second.record_number, 42);
        assert_eq!(next2, buf.len());
    }
}
