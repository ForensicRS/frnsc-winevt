//! One 64KiB (`0x10000`-byte) EVTX chunk: a 512-byte header (verified against
//! `libyal/libevtx` and cross-checked against `omerbenamram/evtx`'s field
//! offsets and checksum ranges) followed by record data.
//!
//! | Offset    | Size | Field                                            |
//! |-----------|------|----------------------------------------------------|
//! | 0         | 8    | Signature `"ElfChnk\0"`                          |
//! | 8         | 8    | First event record number (u64 LE)               |
//! | 16        | 8    | Last event record number (u64 LE)                |
//! | 24        | 8    | First event record identifier (u64 LE)            |
//! | 32        | 8    | Last event record identifier (u64 LE)             |
//! | 40        | 4    | Header size (u32 LE, = 128)                       |
//! | 44        | 4    | Last event record data offset (u32 LE)            |
//! | 48        | 4    | Free space offset (u32 LE)                        |
//! | 52        | 4    | Event records checksum (CRC-32 of `512..free_space_offset`) |
//! | 56        | 64   | Unused                                            |
//! | 120       | 4    | Flags (u32 LE)                                    |
//! | 124       | 4    | Header checksum (CRC-32 of `0..120` ++ `128..512`) |
//! | 128       | 256  | Common string offset table (64 x u32 bucket heads) |
//! | 384       | 128  | Template offset table (32 x u32 bucket heads)      |
//!
//! Both checksums are validated but never treated as fatal: a chunk with a
//! bad checksum is still parsed (its records are real bytes on disk either
//! way) and the mismatch is surfaced via `*_checksum_valid` for the caller to
//! weigh as evidence of a partially-flushed or tampered log.

use forensic_rs::prelude::*;
use forensic_rs::{ensure_buffer_size, ensure_format};

use crate::crc32::crc32;

pub const EVTX_CHUNK_MAGIC: [u8; 8] = *b"ElfChnk\0";
pub const EVTX_CHUNK_SIZE: usize = 0x10000;
pub const EVTX_CHUNK_HEADER_SIZE: usize = 512;
const STRING_TABLE_BUCKETS: usize = 64;
const TEMPLATE_TABLE_BUCKETS: usize = 32;

#[derive(Debug, Clone)]
pub struct EvtxChunkHeader {
    pub first_event_record_number: u64,
    pub last_event_record_number: u64,
    pub first_event_record_id: u64,
    pub last_event_record_id: u64,
    pub last_event_record_data_offset: u32,
    pub free_space_offset: u32,
    pub events_checksum: u32,
    pub events_checksum_valid: bool,
    pub flags: u32,
    pub header_checksum: u32,
    pub header_checksum_valid: bool,
    /// Chunk-relative offsets to the head of each string-table hash bucket
    /// (`0` means the bucket is empty). Each entry chains to the next entry
    /// in the same bucket via that entry's own `next_string` field.
    pub string_bucket_offsets: [u32; STRING_TABLE_BUCKETS],
    /// Chunk-relative offsets to the head of each template-table hash
    /// bucket, same chaining convention as `string_bucket_offsets`.
    pub template_bucket_offsets: [u32; TEMPLATE_TABLE_BUCKETS],
}

impl EvtxChunkHeader {
    /// Parses the 512-byte header from the start of one chunk's bytes
    /// (`chunk` is expected to be the chunk's full `EVTX_CHUNK_SIZE` slice,
    /// though only the header portion is required to be present).
    pub fn parse(chunk: &[u8]) -> ForensicResult<Self> {
        ensure_buffer_size!(chunk, 0usize, EVTX_CHUNK_HEADER_SIZE, "evtx chunk header");
        let mut r = ByteReader::new(chunk);
        let magic: [u8; 8] = r.read_fixed()?;
        ensure_format!(
            magic == EVTX_CHUNK_MAGIC,
            "evtx_chunk_header",
            "invalid EVTX chunk signature"
        );
        let first_event_record_number = r.read_u64_le()?;
        let last_event_record_number = r.read_u64_le()?;
        let first_event_record_id = r.read_u64_le()?;
        let last_event_record_id = r.read_u64_le()?;
        let _header_size = r.read_u32_le()?;
        let last_event_record_data_offset = r.read_u32_le()?;
        let free_space_offset = r.read_u32_le()?;
        let events_checksum = r.read_u32_le()?;

        r.seek_to(120)?;
        let flags = r.read_u32_le()?;
        let header_checksum = r.read_u32_le()?;

        let mut string_bucket_offsets = [0u32; STRING_TABLE_BUCKETS];
        r.seek_to(128)?;
        for slot in string_bucket_offsets.iter_mut() {
            *slot = r.read_u32_le()?;
        }
        let mut template_bucket_offsets = [0u32; TEMPLATE_TABLE_BUCKETS];
        for slot in template_bucket_offsets.iter_mut() {
            *slot = r.read_u32_le()?;
        }

        let free_space_offset_usize = free_space_offset as usize;
        let events_checksum_valid = free_space_offset_usize >= EVTX_CHUNK_HEADER_SIZE
            && chunk.len() >= free_space_offset_usize
            && crc32(&chunk[EVTX_CHUNK_HEADER_SIZE..free_space_offset_usize]) == events_checksum;

        let header_checksum_valid = {
            let mut bytes_for_checksum = Vec::with_capacity(120 + (EVTX_CHUNK_HEADER_SIZE - 128));
            bytes_for_checksum.extend_from_slice(&chunk[0..120]);
            bytes_for_checksum.extend_from_slice(&chunk[128..EVTX_CHUNK_HEADER_SIZE]);
            crc32(&bytes_for_checksum) == header_checksum
        };

        Ok(Self {
            first_event_record_number,
            last_event_record_number,
            first_event_record_id,
            last_event_record_id,
            last_event_record_data_offset,
            free_space_offset,
            events_checksum,
            events_checksum_valid,
            flags,
            header_checksum,
            header_checksum_valid,
            string_bucket_offsets,
            template_bucket_offsets,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_valid_chunk() -> Vec<u8> {
        let mut chunk = vec![0u8; EVTX_CHUNK_SIZE];
        chunk[0..8].copy_from_slice(&EVTX_CHUNK_MAGIC);
        chunk[8..16].copy_from_slice(&0u64.to_le_bytes());
        chunk[16..24].copy_from_slice(&1u64.to_le_bytes());
        chunk[24..32].copy_from_slice(&100u64.to_le_bytes());
        chunk[32..40].copy_from_slice(&101u64.to_le_bytes());
        chunk[40..44].copy_from_slice(&128u32.to_le_bytes());
        let free_space_offset = EVTX_CHUNK_HEADER_SIZE as u32 + 16;
        chunk[44..48].copy_from_slice(&(EVTX_CHUNK_HEADER_SIZE as u32).to_le_bytes());
        chunk[48..52].copy_from_slice(&free_space_offset.to_le_bytes());

        // Fill some fake record bytes so the events checksum has content.
        for (i, b) in chunk[EVTX_CHUNK_HEADER_SIZE..free_space_offset as usize]
            .iter_mut()
            .enumerate()
        {
            *b = i as u8;
        }
        let events_checksum = crc32(&chunk[EVTX_CHUNK_HEADER_SIZE..free_space_offset as usize]);
        chunk[52..56].copy_from_slice(&events_checksum.to_le_bytes());

        chunk[120..124].copy_from_slice(&0u32.to_le_bytes()); // flags

        let mut bytes_for_checksum = Vec::new();
        bytes_for_checksum.extend_from_slice(&chunk[0..120]);
        bytes_for_checksum.extend_from_slice(&chunk[128..EVTX_CHUNK_HEADER_SIZE]);
        let header_checksum = crc32(&bytes_for_checksum);
        chunk[124..128].copy_from_slice(&header_checksum.to_le_bytes());

        chunk
    }

    #[test]
    fn parses_valid_chunk_header() {
        let chunk = build_valid_chunk();
        let header = EvtxChunkHeader::parse(&chunk).unwrap();
        assert_eq!(header.first_event_record_id, 100);
        assert_eq!(header.last_event_record_id, 101);
        assert!(header.events_checksum_valid);
        assert!(header.header_checksum_valid);
    }

    #[test]
    fn rejects_bad_magic() {
        let mut chunk = build_valid_chunk();
        chunk[0] = b'X';
        assert!(EvtxChunkHeader::parse(&chunk).is_err());
    }

    #[test]
    fn flags_bad_checksums_without_failing() {
        let mut chunk = build_valid_chunk();
        chunk[EVTX_CHUNK_HEADER_SIZE] ^= 0xFF; // corrupt one record-data byte
        let header = EvtxChunkHeader::parse(&chunk).unwrap();
        assert!(!header.events_checksum_valid);
        // Header checksum (over the header + string/template tables) is
        // unaffected by corruption in the record-data region.
        assert!(header.header_checksum_valid);
    }
}
