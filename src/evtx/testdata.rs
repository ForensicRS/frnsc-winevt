//! Synthetic `.evtx` bytes for this crate's own tests and, through [`crate::fixtures`], for
//! downstream readiness checks.
//!
//! `pub(crate)`: a hand-built EVTX file is expensive enough to get right that two test modules
//! should not each own a copy, but it is a test fixture, not stable API — [`crate::fixtures`] is
//! the public seam for that. Not `#[cfg(test)]`: [`crate::fixtures::evtx_file`] needs
//! [`build_evtx_file`] in ordinary (non-test) builds too.
//!
//! Everything here is built as one growing buffer rather than a fixed-size chunk with the
//! BinXML spliced in afterwards, because BinXML name-table offsets are *chunk-absolute*:
//! [`push_name_def`] must see the real position each byte lands at inside the chunk.

use crate::crc32::crc32;
use crate::evtx::binxml::values;
use crate::evtx::chunk::{EVTX_CHUNK_HEADER_SIZE, EVTX_CHUNK_MAGIC, EVTX_CHUNK_SIZE};
use crate::evtx::file_header::{EVTX_FILE_HEADER_BLOCK_SIZE, EVTX_FILE_MAGIC};
use crate::evtx::record::EVTX_RECORD_MAGIC;

/// The `TimeCreated` written into every record [`build_evtx_file`] produces, as a raw
/// FILETIME. 2023-12-20T11:57:03.5959706Z.
pub(crate) const RECORD_FILETIME: u64 = 133_514_430_235_959_706;

pub(crate) fn utf16le(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect()
}

pub(crate) fn push_name_def(buf: &mut Vec<u8>, name: &str) -> u32 {
    let offset = buf.len() as u32;
    buf.extend_from_slice(&0u32.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&(name.encode_utf16().count() as u16).to_le_bytes());
    buf.extend_from_slice(&utf16le(name));
    buf.extend_from_slice(&0u16.to_le_bytes());
    offset
}

pub(crate) fn push_text_element(b: &mut Vec<u8>, name: &str, text: &str) {
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

/// Appends a record's BinXML fragment directly onto the chunk buffer `b`: a non-templated
/// `<Event><System><Provider Name="P"/><EventID>7</EventID><Channel>{channel}</Channel>
/// <Computer>HOST</Computer><Level>4</Level></System></Event>`.
pub(crate) fn push_event_binxml(b: &mut Vec<u8>, channel: &str) {
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

    push_text_element(b, "EventID", "7");
    push_text_element(b, "Channel", channel);
    push_text_element(b, "Computer", "HOST");
    push_text_element(b, "Level", "4");

    b.push(0x04); // end </System>
    b.push(0x04); // end </Event>
    b.push(0x00); // eof
}

/// A complete, checksum-valid one-chunk, one-record `.evtx` file whose single record is on
/// `channel`.
pub(crate) fn build_evtx_file(channel: &str) -> Vec<u8> {
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
    chunk.extend_from_slice(&RECORD_FILETIME.to_le_bytes());
    push_event_binxml(&mut chunk, channel);
    let record_total_size = chunk.len() - record_offset + 4;
    chunk[size_field_pos..size_field_pos + 4]
        .copy_from_slice(&(record_total_size as u32).to_le_bytes());
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

/// A one-chunk `.evtx` whose single record frames correctly at the header level but whose BinXML
/// immediately violates the token grammar (a bare EndElement with nothing open).
///
/// The record must still surface — carrying the decode failure — rather than vanishing, which is
/// what both the reader and the parser above it are on the hook for.
///
/// Only ever called from `#[cfg(test)]` code (unlike [`build_evtx_file`], which
/// [`crate::fixtures`] also calls): a corrupt fixture has no readiness-benchmark use.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn build_evtx_file_with_undecodable_record(record_id: u64) -> Vec<u8> {
    let mut chunk = vec![0u8; EVTX_CHUNK_HEADER_SIZE];
    chunk[0..8].copy_from_slice(&EVTX_CHUNK_MAGIC);
    chunk[24..32].copy_from_slice(&record_id.to_le_bytes());
    chunk[32..40].copy_from_slice(&record_id.to_le_bytes());
    chunk[40..44].copy_from_slice(&128u32.to_le_bytes());

    let record_offset = EVTX_CHUNK_HEADER_SIZE;
    chunk.extend_from_slice(&EVTX_RECORD_MAGIC);
    let size_field_pos = chunk.len();
    chunk.extend_from_slice(&0u32.to_le_bytes());
    chunk.extend_from_slice(&record_id.to_le_bytes());
    chunk.extend_from_slice(&RECORD_FILETIME.to_le_bytes());
    chunk.push(0x0F); // fragment header
    chunk.extend_from_slice(&[1, 1, 0]);
    chunk.push(0x04); // EndElement with nothing open — invalid grammar
    chunk.push(0x00); // eof
    let record_total_size = chunk.len() - record_offset + 4;
    chunk[size_field_pos..size_field_pos + 4]
        .copy_from_slice(&(record_total_size as u32).to_le_bytes());
    chunk.extend_from_slice(&(record_total_size as u32).to_le_bytes());
    chunk.resize(EVTX_CHUNK_SIZE, 0);

    let free_space_offset = (record_offset + record_total_size) as u32;
    chunk[44..48].copy_from_slice(&(record_offset as u32).to_le_bytes());
    chunk[48..52].copy_from_slice(&free_space_offset.to_le_bytes());

    // Checksums left unset: they are informational, and the reader flags rather than rejects a
    // mismatch — which this fixture also exercises.
    let mut file = vec![0u8; EVTX_FILE_HEADER_BLOCK_SIZE];
    file[0..8].copy_from_slice(&EVTX_FILE_MAGIC);
    file[40..42].copy_from_slice(&4096u16.to_le_bytes());
    file[42..44].copy_from_slice(&1u16.to_le_bytes());
    file.extend_from_slice(&chunk);
    file
}
