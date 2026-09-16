//! [`EventLogReader`] over a parsed legacy `.evt` file.

use std::collections::BTreeMap;

use forensic_rs::prelude::*;

use crate::evt::file_header::{EvtFileHeader, EVT_HEADER_SIZE};
use crate::evt::record::EvtRecord;
use crate::query_iter::RecordIter;

/// Turns one parsed [`EvtRecord`] into the framework's [`EventRecord`] shape.
///
/// Legacy `.evt` has no structured `EventData`/`UserData` — insertion
/// strings and the raw data blob are the closest equivalent, so they're
/// carried through under `event.strings` (an array) and `event.data` (the
/// binary blob, hex-encoded — [`Field`] has no dedicated binary variant).
fn map_record(record: EvtRecord, channel: &str) -> EventRecord {
    let mut data = BTreeMap::new();
    if !record.strings.is_empty() {
        data.insert(
            text_owned("event.strings".to_string()),
            Field::Array(record.strings.iter().cloned().map(text_owned).collect()),
        );
    }
    if !record.data.is_empty() {
        data.insert(
            text_owned("event.data".to_string()),
            Field::from(hex_encode(&record.data)),
        );
    }
    data.insert(
        text_owned("event.time_written".to_string()),
        Field::Date(ForensicTimestamp::from_unix_secs(record.time_written as i64)),
    );
    data.insert(
        text_owned("event.category".to_string()),
        Field::U64(record.event_category as u64),
    );

    let event_id = record.event_id();
    let level = record.level();
    EventRecord {
        record_id: record.record_number as u64,
        event_id,
        timestamp: ForensicTimestamp::from_unix_secs(record.time_generated as i64),
        provider: record.source_name,
        channel: channel.to_string(),
        level,
        computer: record.computer_name,
        user_sid: record.user_sid,
        data,
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// Reads a legacy `.evt` file, eagerly parsing every record between the
/// header's `start_offset` and `end_offset` into memory.
///
/// `.evt` has no embedded channel name (unlike `.evtx`'s `Channel` element)
/// — it's implicit in which file was opened (`AppEvent.evt` -> "Application",
/// etc.), so the caller supplies it.
///
/// This covers the common non-wrapped case. A `.evt` log that has wrapped
/// (wraps its circular buffer back to the start) or contains corrupted
/// records recoverable only by scanning for trailing size copies is not
/// handled yet — parsing stops at the first record that fails to parse.
pub struct EvtEventLogReader {
    channel: String,
    records: Vec<EventRecord>,
}

impl EvtEventLogReader {
    pub fn from_bytes(bytes: &[u8], channel: impl Into<String>) -> ForensicResult<Self> {
        let header = EvtFileHeader::parse(bytes)?;
        let channel = channel.into();
        let mut records = Vec::new();

        let start = header.start_offset.max(EVT_HEADER_SIZE as u32) as usize;
        let end = (header.end_offset as usize).min(bytes.len());
        let mut offset = start;
        while offset + 4 <= end {
            match EvtRecord::parse_at(bytes, offset) {
                Ok((record, next)) => {
                    records.push(map_record(record, &channel));
                    offset = next;
                }
                Err(_) => break,
            }
        }

        Ok(Self { channel, records })
    }
}

impl EventLogReader for EvtEventLogReader {
    fn channels(&self) -> ForensicResult<Vec<String>> {
        Ok(vec![self.channel.clone()])
    }

    fn query(&self, query: &EventLogQuery) -> ForensicResult<Box<dyn EventLogIterator + '_>> {
        Ok(Box::new(RecordIter::new(&self.records, query.clone())))
    }

    fn event_count(&self, channel: &str) -> ForensicResult<u64> {
        if channel == self.channel {
            Ok(self.records.len() as u64)
        } else {
            Ok(0)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evt::file_header::{EVT_SIGNATURE, EVT_HEADER_SIZE as HDR};
    use crate::evt::record::EVT_RECORD_SIGNATURE;

    /// `EvtRecord`'s fixed 56-byte header size (see `record.rs`'s private
    /// `FIXED_HEADER_SIZE` — not `EVT_HEADER_SIZE`, which is the *file*
    /// header's 48-byte size and unrelated to a record's own layout).
    const RECORD_HEADER: usize = 56;

    fn utf16le_z(s: &str) -> Vec<u8> {
        let mut out: Vec<u8> = s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        out.extend_from_slice(&0u16.to_le_bytes());
        out
    }

    fn build_record(record_number: u32, event_id: u32) -> Vec<u8> {
        let source = utf16le_z("App");
        let computer = utf16le_z("HOST");
        let strings_offset = RECORD_HEADER + source.len() + computer.len();
        let total_size = strings_offset + 4;

        let mut buf = vec![0u8; total_size];
        buf[0..4].copy_from_slice(&(total_size as u32).to_le_bytes());
        buf[4..8].copy_from_slice(&EVT_RECORD_SIGNATURE.to_le_bytes());
        buf[8..12].copy_from_slice(&record_number.to_le_bytes());
        buf[12..16].copy_from_slice(&1_700_000_000u32.to_le_bytes());
        buf[16..20].copy_from_slice(&1_700_000_001u32.to_le_bytes());
        buf[20..24].copy_from_slice(&event_id.to_le_bytes());
        buf[24..26].copy_from_slice(&1u16.to_le_bytes()); // EVENTLOG_ERROR_TYPE
        buf[26..28].copy_from_slice(&0u16.to_le_bytes()); // num_strings
        buf[28..30].copy_from_slice(&0u16.to_le_bytes());
        buf[30..32].copy_from_slice(&0u16.to_le_bytes());
        buf[32..36].copy_from_slice(&0u32.to_le_bytes());
        buf[36..40].copy_from_slice(&(strings_offset as u32).to_le_bytes());
        buf[40..44].copy_from_slice(&0u32.to_le_bytes());
        buf[44..48].copy_from_slice(&0u32.to_le_bytes());
        buf[48..52].copy_from_slice(&0u32.to_le_bytes());
        buf[52..56].copy_from_slice(&(strings_offset as u32).to_le_bytes());

        let mut pos = RECORD_HEADER;
        buf[pos..pos + source.len()].copy_from_slice(&source);
        pos += source.len();
        buf[pos..pos + computer.len()].copy_from_slice(&computer);

        buf[total_size - 4..].copy_from_slice(&(total_size as u32).to_le_bytes());
        buf
    }

    fn build_file(records: &[Vec<u8>]) -> Vec<u8> {
        let mut body = Vec::new();
        for r in records {
            body.extend_from_slice(r);
        }
        let end_offset = HDR + body.len();

        let mut buf = vec![0u8; HDR];
        buf[0..4].copy_from_slice(&(HDR as u32).to_le_bytes());
        buf[4..8].copy_from_slice(&EVT_SIGNATURE.to_le_bytes());
        buf[8..12].copy_from_slice(&1u32.to_le_bytes());
        buf[12..16].copy_from_slice(&1u32.to_le_bytes());
        buf[16..20].copy_from_slice(&(HDR as u32).to_le_bytes()); // start_offset
        buf[20..24].copy_from_slice(&(end_offset as u32).to_le_bytes()); // end_offset
        buf[24..28].copy_from_slice(&(records.len() as u32).to_le_bytes());
        buf[28..32].copy_from_slice(&1u32.to_le_bytes());
        buf[32..36].copy_from_slice(&0x10000u32.to_le_bytes());
        buf[36..40].copy_from_slice(&0u32.to_le_bytes());
        buf[40..44].copy_from_slice(&0u32.to_le_bytes());
        buf[44..48].copy_from_slice(&(HDR as u32).to_le_bytes());

        buf.extend_from_slice(&body);
        buf
    }

    #[test]
    fn reads_and_queries_records() {
        let file = build_file(&[build_record(1, 100), build_record(2, 200)]);
        let reader = EvtEventLogReader::from_bytes(&file, "Application").unwrap();

        assert_eq!(reader.channels().unwrap(), vec!["Application".to_string()]);
        assert_eq!(reader.event_count("Application").unwrap(), 2);
        assert_eq!(reader.event_count("Security").unwrap(), 0);

        let mut iter = reader.query(&EventLogQuery::new().with_event_ids(&[200])).unwrap();
        let record = iter.next().unwrap().unwrap();
        assert_eq!(record.event_id, 200);
        assert_eq!(record.record_id, 2);
        assert_eq!(record.channel, "Application");
        assert!(iter.next().unwrap().is_none());
    }

    #[test]
    fn query_all_returns_every_record() {
        let file = build_file(&[build_record(1, 100), build_record(2, 200)]);
        let reader: Box<dyn EventLogReader> =
            Box::new(EvtEventLogReader::from_bytes(&file, "Application").unwrap());
        let mut iter = reader.query_all().unwrap();
        let mut count = 0;
        while iter.next().unwrap().is_some() {
            count += 1;
        }
        assert_eq!(count, 2);
    }
}
