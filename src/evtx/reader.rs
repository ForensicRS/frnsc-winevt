//! [`EventLogReader`] over a parsed `.evtx` file.

use forensic_rs::prelude::*;

use crate::evtx::binxml::{decode_record_fragment, ChunkContext};
use crate::evtx::chunk::{EvtxChunkHeader, EVTX_CHUNK_HEADER_SIZE, EVTX_CHUNK_SIZE};
use crate::evtx::file_header::{EvtxFileHeader, EVTX_FILE_HEADER_BLOCK_SIZE};
use crate::evtx::mapping::map_event;
use crate::evtx::record::EvtxRecordHeader;
use crate::evtx::xml::XmlNode;
use crate::query_iter::RecordIter;

/// Set on a record's `data` map when the *chunk* it came from failed its
/// CRC-32 self-check (see `evtx::chunk`) — only ever inserted when `false`,
/// since an always-present `true` on every ordinary record would just be
/// noise; its absence means the chunk's checksum was valid.
const CHUNK_CHECKSUM_VALID_FIELD: &str = "evtx.chunk.checksum_valid";
/// Same, for the file-level header checksum (see `evtx::file_header`).
const FILE_CHECKSUM_VALID_FIELD: &str = "evtx.file.checksum_valid";
/// Set when a record's physical header parsed but its BinXML content did
/// not decode into a recognizable `Event` element — the record still
/// appears (with only `record_id`/`timestamp` from its header reliable),
/// rather than vanishing with no trace, per the "never silently lose
/// evidence a record existed" rule.
const DECODE_ERROR_FIELD: &str = "evtx.record.decode_error";

/// Reads a `.evtx` file, eagerly decoding every record in every chunk into
/// memory at construction time.
///
/// Chunks are located by dividing the file into fixed `EVTX_CHUNK_SIZE`
/// slices after the file header, not by trusting the header's `chunk_count`
/// — a chunk slot that was pre-allocated but never written (no valid
/// `ElfChnk\0` magic) is silently skipped rather than treated as a hard
/// error, since that's routine for a live or recently-created event log
/// file. A structurally corrupt record stops that chunk's scan (there is no
/// reliable way to find the next record boundary once one record's declared
/// size can't be trusted), but every record successfully framed before that
/// point is kept — including one whose BinXML failed to decode, which still
/// surfaces (see [`DECODE_ERROR_FIELD`]) rather than disappearing.
///
/// File- and chunk-level CRC-32 mismatches (see `evtx::file_header`,
/// `evtx::chunk`) don't fail the read either — a dirty/partially-flushed log
/// is real evidence, not corruption to reject — but they *are* propagated
/// onto every affected record via [`FILE_CHECKSUM_VALID_FIELD`]/
/// [`CHUNK_CHECKSUM_VALID_FIELD`] so the anomaly reaches the caller instead
/// of being silently discarded after the check runs.
pub struct EvtxEventLogReader {
    records: Vec<EventRecord>,
}

impl EvtxEventLogReader {
    pub fn from_bytes(bytes: Vec<u8>) -> ForensicResult<Self> {
        let file_header = EvtxFileHeader::parse(&bytes)?;
        let mut records = Vec::new();

        let total_chunks = bytes.len().saturating_sub(EVTX_FILE_HEADER_BLOCK_SIZE) / EVTX_CHUNK_SIZE;
        for chunk_index in 0..total_chunks {
            let chunk_start = EVTX_FILE_HEADER_BLOCK_SIZE + chunk_index * EVTX_CHUNK_SIZE;
            let chunk_bytes = &bytes[chunk_start..chunk_start + EVTX_CHUNK_SIZE];
            let Ok(chunk_header) = EvtxChunkHeader::parse(chunk_bytes) else {
                continue; // never-written / unallocated chunk slot
            };
            let chunk_checksum_valid = chunk_header.events_checksum_valid && chunk_header.header_checksum_valid;

            let ctx = ChunkContext::new(chunk_bytes);
            let scan_limit = (chunk_header.free_space_offset as usize).min(chunk_bytes.len());
            let mut offset = EVTX_CHUNK_HEADER_SIZE;
            while offset + 4 <= scan_limit {
                let Ok((record_header, _binxml, next_offset)) = EvtxRecordHeader::parse_at(chunk_bytes, offset) else {
                    break; // structural corruption — stop scanning this chunk
                };
                let binxml_start = offset + 24;
                let binxml_end = offset + record_header.size as usize - 4;

                let mut record = match decode_record_fragment(&ctx, binxml_start, binxml_end) {
                    Ok(nodes) => match nodes.into_iter().find_map(|node| match node {
                        XmlNode::Element(e) if e.name == "Event" => Some(e),
                        _ => None,
                    }) {
                        Some(event) => map_event(&event, record_header.record_id, record_header.timestamp()),
                        None => empty_record_with_decode_error(
                            &record_header,
                            "BinXML fragment decoded but contained no Event root element",
                        ),
                    },
                    Err(e) => empty_record_with_decode_error(&record_header, &e.to_string()),
                };

                if !file_header.checksum_valid {
                    record.data.insert(text_owned(FILE_CHECKSUM_VALID_FIELD.to_string()), Field::from(false));
                }
                if !chunk_checksum_valid {
                    record.data.insert(text_owned(CHUNK_CHECKSUM_VALID_FIELD.to_string()), Field::from(false));
                }
                records.push(record);

                offset = next_offset;
            }
        }

        Ok(Self { records })
    }
}

fn empty_record_with_decode_error(header: &EvtxRecordHeader, error: &str) -> EventRecord {
    let mut data = std::collections::BTreeMap::new();
    data.insert(text_owned(DECODE_ERROR_FIELD.to_string()), Field::from(error.to_string()));
    EventRecord {
        record_id: header.record_id,
        event_id: 0,
        timestamp: header.timestamp(),
        provider: String::new(),
        channel: String::new(),
        level: EventLevel::Information,
        computer: String::new(),
        user_sid: None,
        data,
    }
}

impl EventLogReader for EvtxEventLogReader {
    fn channels(&self) -> ForensicResult<Vec<String>> {
        let mut channels = Vec::new();
        for record in &self.records {
            if !channels.contains(&record.channel) {
                channels.push(record.channel.clone());
            }
        }
        Ok(channels)
    }

    fn query(&self, query: &EventLogQuery) -> ForensicResult<Box<dyn EventLogIterator + '_>> {
        Ok(Box::new(RecordIter::new(&self.records, query.clone())))
    }

    fn event_count(&self, channel: &str) -> ForensicResult<u64> {
        Ok(self.records.iter().filter(|r| r.channel == channel).count() as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crc32::crc32;
    use crate::evtx::binxml::values;
    use crate::evtx::chunk::EVTX_CHUNK_MAGIC;
    use crate::evtx::file_header::EVTX_FILE_MAGIC;
    use crate::evtx::record::EVTX_RECORD_MAGIC;

    fn utf16le(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect()
    }

    fn push_name_def(buf: &mut Vec<u8>, name: &str) -> u32 {
        let offset = buf.len() as u32;
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.extend_from_slice(&(name.encode_utf16().count() as u16).to_le_bytes());
        buf.extend_from_slice(&utf16le(name));
        buf.extend_from_slice(&0u16.to_le_bytes());
        offset
    }

    /// Appends a record's BinXML fragment directly onto the chunk buffer
    /// `b` (name-table offsets are chunk-absolute, so this must be built
    /// in place rather than in a standalone buffer and copied in later): a
    /// non-templated `<Event><System><Provider Name="P"/><EventID>7</EventID>
    /// <Channel>Application</Channel><Computer>HOST</Computer><Level>4</Level>
    /// </System></Event>`.
    fn push_event_binxml(b: &mut Vec<u8>) {
        b.push(0x0F); // fragment header
        b.extend_from_slice(&[1, 1, 0]);

        // <Event>
        b.push(0x01);
        b.extend_from_slice(&0u32.to_le_bytes());
        let ph = b.len();
        b.extend_from_slice(&0u32.to_le_bytes());
        let off = push_name_def(b, "Event");
        b[ph..ph + 4].copy_from_slice(&off.to_le_bytes());
        b.push(0x02); // close start element

        // <System>
        b.push(0x01);
        b.extend_from_slice(&0u32.to_le_bytes());
        let ph = b.len();
        b.extend_from_slice(&0u32.to_le_bytes());
        let off = push_name_def(b, "System");
        b[ph..ph + 4].copy_from_slice(&off.to_le_bytes());
        b.push(0x02);

        // <Provider Name="P" /> (empty element with one attribute)
        b.push(0x01 | 0x40); // has attributes
        b.extend_from_slice(&0u32.to_le_bytes());
        let ph = b.len();
        b.extend_from_slice(&0u32.to_le_bytes());
        let off = push_name_def(b, "Provider");
        b[ph..ph + 4].copy_from_slice(&off.to_le_bytes());
        let attr_list_len_pos = b.len();
        b.extend_from_slice(&0u32.to_le_bytes());
        let attr_list_start = b.len();
        b.push(0x06); // attribute
        let ph = b.len();
        b.extend_from_slice(&0u32.to_le_bytes());
        let off = push_name_def(b, "Name");
        b[ph..ph + 4].copy_from_slice(&off.to_le_bytes());
        b.push(0x05); // value
        b.push(values::VALUE_WSTRING);
        b.extend_from_slice(&("P".encode_utf16().count() as u16).to_le_bytes());
        b.extend_from_slice(&utf16le("P"));
        let attr_list_len = (b.len() - attr_list_start) as u32;
        b[attr_list_len_pos..attr_list_len_pos + 4].copy_from_slice(&attr_list_len.to_le_bytes());
        b.push(0x03); // close empty element

        // <EventID>7</EventID>
        push_text_element(b, "EventID", "7");
        // <Channel>Application</Channel>
        push_text_element(b, "Channel", "Application");
        // <Computer>HOST</Computer>
        push_text_element(b, "Computer", "HOST");
        // <Level>4</Level>
        push_text_element(b, "Level", "4");

        b.push(0x04); // end </System>
        b.push(0x04); // end </Event>
        b.push(0x00); // eof
    }

    fn push_text_element(b: &mut Vec<u8>, name: &str, text: &str) {
        b.push(0x01);
        b.extend_from_slice(&0u32.to_le_bytes());
        let ph = b.len();
        b.extend_from_slice(&0u32.to_le_bytes());
        let off = push_name_def(b, name);
        b[ph..ph + 4].copy_from_slice(&off.to_le_bytes());
        b.push(0x02);
        b.push(0x05);
        b.push(values::VALUE_WSTRING);
        b.extend_from_slice(&(text.encode_utf16().count() as u16).to_le_bytes());
        b.extend_from_slice(&utf16le(text));
        b.push(0x04);
    }

    fn build_evtx_file() -> Vec<u8> {
        // Built as one growing buffer (not a fixed-size chunk with BinXML
        // spliced in from a standalone buffer) because BinXML name-table
        // offsets are chunk-absolute: `push_name_def`/`push_event_binxml`
        // must see the real position each byte lands at within the chunk.
        let mut chunk = vec![0u8; EVTX_CHUNK_HEADER_SIZE];
        chunk[0..8].copy_from_slice(&EVTX_CHUNK_MAGIC);
        chunk[24..32].copy_from_slice(&1u64.to_le_bytes()); // first_event_record_id
        chunk[32..40].copy_from_slice(&1u64.to_le_bytes()); // last_event_record_id
        chunk[40..44].copy_from_slice(&128u32.to_le_bytes());

        let record_offset = EVTX_CHUNK_HEADER_SIZE;
        chunk.extend_from_slice(&EVTX_RECORD_MAGIC);
        let size_field_pos = chunk.len();
        chunk.extend_from_slice(&0u32.to_le_bytes()); // size, patched below
        chunk.extend_from_slice(&1u64.to_le_bytes()); // record_id
        chunk.extend_from_slice(&133_514_430_235_959_706u64.to_le_bytes());
        push_event_binxml(&mut chunk);
        let record_total_size = chunk.len() - record_offset + 4;
        chunk[size_field_pos..size_field_pos + 4].copy_from_slice(&(record_total_size as u32).to_le_bytes());
        chunk.extend_from_slice(&(record_total_size as u32).to_le_bytes()); // trailing size copy

        chunk.resize(EVTX_CHUNK_SIZE, 0);

        let free_space_offset = (record_offset + record_total_size) as u32;
        chunk[44..48].copy_from_slice(&(record_offset as u32).to_le_bytes());
        chunk[48..52].copy_from_slice(&free_space_offset.to_le_bytes());
        let events_checksum = crc32(&chunk[EVTX_CHUNK_HEADER_SIZE..free_space_offset as usize]);
        chunk[52..56].copy_from_slice(&events_checksum.to_le_bytes());

        let mut header_bytes_for_checksum = Vec::new();
        header_bytes_for_checksum.extend_from_slice(&chunk[0..120]);
        header_bytes_for_checksum.extend_from_slice(&chunk[128..EVTX_CHUNK_HEADER_SIZE]);
        let header_checksum = crc32(&header_bytes_for_checksum);
        chunk[124..128].copy_from_slice(&header_checksum.to_le_bytes());

        let mut file = vec![0u8; EVTX_FILE_HEADER_BLOCK_SIZE];
        file[0..8].copy_from_slice(&EVTX_FILE_MAGIC);
        file[16..24].copy_from_slice(&0u64.to_le_bytes()); // last_chunk_number
        file[32..36].copy_from_slice(&128u32.to_le_bytes());
        file[36..38].copy_from_slice(&1u16.to_le_bytes());
        file[38..40].copy_from_slice(&3u16.to_le_bytes());
        file[40..42].copy_from_slice(&4096u16.to_le_bytes());
        file[42..44].copy_from_slice(&1u16.to_le_bytes());
        let file_checksum = crc32(&file[0..120]);
        file[124..128].copy_from_slice(&file_checksum.to_le_bytes());

        file.extend_from_slice(&chunk);
        file
    }

    #[test]
    fn reads_and_queries_synthetic_evtx() {
        let bytes = build_evtx_file();
        let reader = EvtxEventLogReader::from_bytes(bytes).unwrap();

        assert_eq!(reader.channels().unwrap(), vec!["Application".to_string()]);
        assert_eq!(reader.event_count("Application").unwrap(), 1);

        let mut iter = reader.query(&EventLogQuery::new().with_event_ids(&[7])).unwrap();
        let record = iter.next().unwrap().unwrap();
        assert_eq!(record.event_id, 7);
        assert_eq!(record.record_id, 1);
        assert_eq!(record.channel, "Application");
        assert_eq!(record.computer, "HOST");
        assert_eq!(record.level, EventLevel::Information);
        assert_eq!(record.provider, "P");
        assert!(iter.next().unwrap().is_none());

        assert!(reader
            .query(&EventLogQuery::new().with_event_ids(&[999]))
            .unwrap()
            .next()
            .unwrap()
            .is_none());
    }

    #[test]
    fn a_bad_chunk_checksum_is_flagged_on_every_record_from_it_not_dropped() {
        let mut bytes = build_evtx_file();
        // Corrupt one byte of record data covered by the chunk's events
        // checksum, without touching any structural field (magic, offsets,
        // trailing size copy) — the record must still parse and appear.
        let corrupt_at = EVTX_FILE_HEADER_BLOCK_SIZE + EVTX_CHUNK_HEADER_SIZE + 40;
        bytes[corrupt_at] ^= 0xFF;

        let reader = EvtxEventLogReader::from_bytes(bytes).unwrap();
        let mut iter = reader.query(&EventLogQuery::new()).unwrap();
        let record = iter.next().unwrap().expect("record still present despite bad checksum");
        assert_eq!(
            record.data.get(&text_owned(CHUNK_CHECKSUM_VALID_FIELD.to_string())),
            Some(&Field::from(false))
        );
    }

    #[test]
    fn a_record_with_undecodable_binxml_surfaces_instead_of_vanishing() {
        // A record whose BinXML immediately violates the token grammar
        // (a bare EndElement with no matching open element) still frames
        // correctly at the header level and must still appear, carrying the
        // decode failure rather than disappearing.
        let mut chunk = vec![0u8; EVTX_CHUNK_HEADER_SIZE];
        chunk[0..8].copy_from_slice(&EVTX_CHUNK_MAGIC);
        chunk[24..32].copy_from_slice(&1u64.to_le_bytes());
        chunk[32..40].copy_from_slice(&1u64.to_le_bytes());
        chunk[40..44].copy_from_slice(&128u32.to_le_bytes());

        let record_offset = EVTX_CHUNK_HEADER_SIZE;
        chunk.extend_from_slice(&EVTX_RECORD_MAGIC);
        let size_field_pos = chunk.len();
        chunk.extend_from_slice(&0u32.to_le_bytes());
        chunk.extend_from_slice(&42u64.to_le_bytes()); // record_id
        chunk.extend_from_slice(&133_514_430_235_959_706u64.to_le_bytes());
        chunk.push(0x0F); // fragment header
        chunk.extend_from_slice(&[1, 1, 0]);
        chunk.push(0x04); // EndElement with nothing open — invalid grammar
        chunk.push(0x00); // eof
        let record_total_size = chunk.len() - record_offset + 4;
        chunk[size_field_pos..size_field_pos + 4].copy_from_slice(&(record_total_size as u32).to_le_bytes());
        chunk.extend_from_slice(&(record_total_size as u32).to_le_bytes());
        chunk.resize(EVTX_CHUNK_SIZE, 0);

        let free_space_offset = (record_offset + record_total_size) as u32;
        chunk[44..48].copy_from_slice(&(record_offset as u32).to_le_bytes());
        chunk[48..52].copy_from_slice(&free_space_offset.to_le_bytes());

        let mut file = vec![0u8; EVTX_FILE_HEADER_BLOCK_SIZE];
        file[0..8].copy_from_slice(&EVTX_FILE_MAGIC);
        file[40..42].copy_from_slice(&4096u16.to_le_bytes());
        file[42..44].copy_from_slice(&1u16.to_le_bytes());
        file.extend_from_slice(&chunk);

        let reader = EvtxEventLogReader::from_bytes(file).unwrap();
        let mut iter = reader.query(&EventLogQuery::new()).unwrap();
        let record = iter.next().unwrap().expect("record still present despite undecodable BinXML");
        assert_eq!(record.record_id, 42);
        assert!(record.data.contains_key(&text_owned(DECODE_ERROR_FIELD.to_string())));
        assert!(iter.next().unwrap().is_none());
    }
}
