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
    use crate::evtx::testdata::{build_evtx_file, build_evtx_file_with_undecodable_record};

    #[test]
    fn reads_and_queries_synthetic_evtx() {
        let bytes = build_evtx_file("Application");
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
        let mut bytes = build_evtx_file("Application");
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
        // A record whose BinXML immediately violates the token grammar (a bare EndElement with
        // no matching open element) still frames correctly at the header level and must still
        // appear, carrying the decode failure rather than disappearing.
        let file = build_evtx_file_with_undecodable_record(42);

        let reader = EvtxEventLogReader::from_bytes(file).unwrap();
        let mut iter = reader.query(&EventLogQuery::new()).unwrap();
        let record = iter.next().unwrap().expect("record still present despite undecodable BinXML");
        assert_eq!(record.record_id, 42);
        assert!(record.data.contains_key(&text_owned(DECODE_ERROR_FIELD.to_string())));
        assert!(iter.next().unwrap().is_none());
    }
}
