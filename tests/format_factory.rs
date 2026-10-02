//! End-to-end check of `EvtFormatFactory`/`EvtxFormatFactory` through a real
//! `MountResolver` — the same probe -> pick-winner -> mount -> query path a
//! downstream analyzer actually uses, per `forensic-rs`'s own
//! `EventLogReader` example.
//!
//! EVTX's CRC-32 checksums are intentionally left unset/mismatched here
//! (they're informational, not load-bearing — see `evtx::file_header` and
//! `evtx::chunk`), which keeps this test independent of `frnsc_winevt`'s
//! private `crc32` module and focused on what it's actually meant to check:
//! factory dispatch and mount plumbing, not BinXML/record decoding
//! correctness (covered by the crate's unit tests).

use std::sync::Arc;

use forensic_rs::prelude::*;
use forensic_rs::utils::testing::InMemoryVirtualFileSystem;

use frnsc_winevt::evt::file_header::{EVT_HEADER_SIZE, EVT_SIGNATURE};
use frnsc_winevt::evt::record::EVT_RECORD_SIGNATURE;
use frnsc_winevt::evtx::chunk::{EVTX_CHUNK_HEADER_SIZE, EVTX_CHUNK_MAGIC, EVTX_CHUNK_SIZE};
use frnsc_winevt::evtx::file_header::{EVTX_FILE_HEADER_BLOCK_SIZE, EVTX_FILE_MAGIC};
use frnsc_winevt::{EvtFormatFactory, EvtxFormatFactory};

fn utf16le_z(s: &str) -> Vec<u8> {
    let mut out: Vec<u8> = s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
    out.extend_from_slice(&0u16.to_le_bytes());
    out
}

/// A minimal but fully valid `.evt` file: header + one record, no SID, no
/// strings, no data.
fn build_evt_bytes() -> Vec<u8> {
    let source = utf16le_z("App");
    let computer = utf16le_z("HOST");

    const RECORD_FIXED_HEADER: usize = 56;
    let record_total = RECORD_FIXED_HEADER + source.len() + computer.len() + 4;

    let mut record = vec![0u8; record_total];
    record[0..4].copy_from_slice(&(record_total as u32).to_le_bytes());
    record[4..8].copy_from_slice(&EVT_RECORD_SIGNATURE.to_le_bytes());
    record[8..12].copy_from_slice(&1u32.to_le_bytes()); // record_number
    record[12..16].copy_from_slice(&1_700_000_000u32.to_le_bytes());
    record[16..20].copy_from_slice(&1_700_000_001u32.to_le_bytes());
    record[20..24].copy_from_slice(&4625u32.to_le_bytes()); // event_id
    record[24..26].copy_from_slice(&1u16.to_le_bytes()); // EVENTLOG_ERROR_TYPE
    let mut pos = RECORD_FIXED_HEADER;
    record[pos..pos + source.len()].copy_from_slice(&source);
    pos += source.len();
    record[pos..pos + computer.len()].copy_from_slice(&computer);
    record[record_total - 4..].copy_from_slice(&(record_total as u32).to_le_bytes());

    let end_offset = EVT_HEADER_SIZE + record.len();
    let mut file = vec![0u8; EVT_HEADER_SIZE];
    file[0..4].copy_from_slice(&(EVT_HEADER_SIZE as u32).to_le_bytes());
    file[4..8].copy_from_slice(&EVT_SIGNATURE.to_le_bytes());
    file[8..12].copy_from_slice(&1u32.to_le_bytes());
    file[12..16].copy_from_slice(&1u32.to_le_bytes());
    file[16..20].copy_from_slice(&(EVT_HEADER_SIZE as u32).to_le_bytes()); // start_offset
    file[20..24].copy_from_slice(&(end_offset as u32).to_le_bytes()); // end_offset
    file[24..28].copy_from_slice(&1u32.to_le_bytes()); // last_record_number
    file[28..32].copy_from_slice(&1u32.to_le_bytes()); // first_record_number
    file[32..36].copy_from_slice(&0x10000u32.to_le_bytes());
    file[44..48].copy_from_slice(&(EVT_HEADER_SIZE as u32).to_le_bytes());
    file.extend_from_slice(&record);
    file
}

/// A minimal valid (structurally, not checksum-valid) `.evtx` file with a
/// single empty chunk and no records.
fn build_evtx_bytes() -> Vec<u8> {
    let mut file = vec![0u8; EVTX_FILE_HEADER_BLOCK_SIZE];
    file[0..8].copy_from_slice(&EVTX_FILE_MAGIC);
    file[40..42].copy_from_slice(&4096u16.to_le_bytes());
    file[42..44].copy_from_slice(&1u16.to_le_bytes()); // chunk_count

    let mut chunk = vec![0u8; EVTX_CHUNK_SIZE];
    chunk[0..8].copy_from_slice(&EVTX_CHUNK_MAGIC);
    chunk[44..48].copy_from_slice(&(EVTX_CHUNK_HEADER_SIZE as u32).to_le_bytes());
    chunk[48..52].copy_from_slice(&(EVTX_CHUNK_HEADER_SIZE as u32).to_le_bytes()); // free_space_offset, no records

    file.extend_from_slice(&chunk);
    file
}

fn build_resolver() -> MountResolver {
    MountResolver::builder()
        .factory(Arc::new(EvtxFormatFactory))
        .factory(Arc::new(EvtFormatFactory::new("Application")))
        .build()
}

fn resolve_bytes(resolver: &MountResolver, path: &str, bytes: Vec<u8>) -> ForensicResult<Mounted> {
    let vfs = InMemoryVirtualFileSystem::new().with_file(path, bytes);
    let fs: Arc<dyn FileSystem> = Arc::new(vfs);
    let locator = EvidenceLocator::root().push(LocatorSegment::Path(FPathBuf::from(path)));
    let file = fs.open(FPath::new(path))?;
    resolver.resolve(
        &fs,
        &locator,
        file,
        Some(MountKind::EventLog),
        &CancellationToken::new(),
    )
}

#[test]
fn mounts_evt_and_queries_it() {
    let resolver = build_resolver();
    let mounted = resolve_bytes(&resolver, "AppEvent.evt", build_evt_bytes())
        .expect("should mount as an event log");
    let reader = mounted.as_event_log().expect("Mounted::EventLog");

    assert_eq!(reader.channels().unwrap(), vec!["Application".to_string()]);
    let mut iter = reader.query_all().unwrap();
    let record = iter.next().unwrap().expect("one record");
    assert_eq!(record.event_id, 4625);
    assert_eq!(record.provider, "App");
    assert!(iter.next().unwrap().is_none());
}

#[test]
fn mounts_empty_evtx() {
    let resolver = build_resolver();
    let mounted = resolve_bytes(&resolver, "Application.evtx", build_evtx_bytes())
        .expect("should mount as an event log");
    let reader = mounted.as_event_log().expect("Mounted::EventLog");
    assert!(reader.channels().unwrap().is_empty());
    assert!(reader.query_all().unwrap().next().unwrap().is_none());
}

#[test]
fn rejects_garbage_bytes() {
    let resolver = build_resolver();
    let err = resolve_bytes(&resolver, "not_a_log.bin", vec![0xAAu8; 256]);
    assert!(err.is_err());
}

#[test]
fn each_factory_only_claims_its_own_format() {
    // .evtx bytes probed with only EvtFormatFactory registered (and vice
    // versa) must not be misidentified as the other format.
    let evt_only = MountResolver::builder()
        .factory(Arc::new(EvtFormatFactory::new("Application")))
        .build();
    assert!(resolve_bytes(&evt_only, "Application.evtx", build_evtx_bytes()).is_err());

    let evtx_only = MountResolver::builder()
        .factory(Arc::new(EvtxFormatFactory))
        .build();
    assert!(resolve_bytes(&evtx_only, "AppEvent.evt", build_evt_bytes()).is_err());
}
