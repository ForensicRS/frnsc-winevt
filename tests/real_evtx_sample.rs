//! Reads a real `.evtx` sample checked in as a test fixture, mimicking its
//! live-system path (`artifacts/C/Windows/System32/winevt/Logs/...`).
//!
//! Unlike the crate's hand-built synthetic fixtures, this file exercises the
//! parser against genuine on-disk BinXML — heavy template/substitution use
//! and a nested BinXml `EventData` payload — which is exactly what surfaced
//! three real decoding bugs during development (see `AGENTS.md` and the
//! module doc comments on `evtx::binxml::tokens::read_template_instance`,
//! `evtx::binxml::values`'s `VALUE_NULL` handling, and `NestedBinXml`).
//! Keeping this file as a regression test is the whole point: a synthetic
//! fixture can't accidentally encode the same bug twice, but a bug in the
//! decoder reappearing here would be caught immediately.

use forensic_rs::prelude::*;
use frnsc_winevt::evtx::reader::EvtxEventLogReader;

const SAMPLE_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/artifacts/C/Windows/System32/winevt/Logs/Microsoft-Windows-Dhcp-Client%4Admin.evtx"
);

fn load_reader() -> EvtxEventLogReader {
    let bytes = std::fs::read(SAMPLE_PATH).expect("real .evtx test fixture should be present");
    EvtxEventLogReader::from_bytes(bytes).expect("well-formed real-world .evtx should parse")
}

fn field_str<'a>(record: &'a EventRecord, key: &str) -> Option<&'a str> {
    match record.data.get(&text_owned(key.to_string())) {
        Some(Field::Text(t)) => Some(&t[..]),
        _ => None,
    }
}

#[test]
fn reports_the_single_channel() {
    let reader = load_reader();
    assert_eq!(
        reader.channels().unwrap(),
        vec!["Microsoft-Windows-Dhcp-Client/Admin".to_string()]
    );
    assert_eq!(
        reader
            .event_count("Microsoft-Windows-Dhcp-Client/Admin")
            .unwrap(),
        4
    );
}

#[test]
fn every_record_decodes_with_no_anomalies() {
    let reader = load_reader();
    let mut iter = reader.query(&EventLogQuery::new()).unwrap();
    let mut seen = 0;
    while let Some(record) = iter.next().unwrap() {
        seen += 1;
        assert_eq!(record.provider, "Microsoft-Windows-Dhcp-Client");
        assert_eq!(record.channel, "Microsoft-Windows-Dhcp-Client/Admin");
        assert_eq!(record.user_sid.as_deref(), Some("S-1-5-19"));
        assert!(
            !record
                .data
                .contains_key(&text_owned("evtx.record.decode_error".to_string())),
            "record {} should not have failed to decode",
            record.record_id
        );
        assert!(
            !record
                .data
                .contains_key(&text_owned("evtx.chunk.checksum_valid".to_string())),
            "this fixture's chunk checksum should be valid"
        );
        assert!(
            !record
                .data
                .contains_key(&text_owned("evtx.file.checksum_valid".to_string())),
            "this fixture's file checksum should be valid"
        );
    }
    assert_eq!(seen, 4);
}

#[test]
fn decodes_informational_lease_events() {
    let reader = load_reader();
    let mut iter = reader
        .query(&EventLogQuery::new().with_event_ids(&[50041]))
        .unwrap();

    let first = iter.next().unwrap().expect("record 1");
    assert_eq!(first.record_id, 1);
    assert_eq!(first.computer, "ADMINCO-ETLBRJR");
    assert_eq!(first.level, EventLevel::Information);

    let second = iter.next().unwrap().expect("record 2");
    assert_eq!(second.record_id, 2);
    assert_eq!(second.computer, "CompW2019x64");
    assert_eq!(second.level, EventLevel::Information);

    assert!(iter.next().unwrap().is_none());
}

#[test]
fn decodes_warning_and_error_events_with_event_data() {
    let reader = load_reader();

    let mut warnings = reader
        .query(&EventLogQuery::new().with_event_ids(&[1003]))
        .unwrap();
    let record3 = warnings.next().unwrap().expect("record 3");
    assert_eq!(record3.record_id, 3);
    assert_eq!(record3.computer, "CompW2019x64.cancamusa.com");
    assert_eq!(record3.level, EventLevel::Warning);
    assert_eq!(
        field_str(&record3, "winlog.event_data.HWAddress"),
        Some("0x000063c37a46")
    );
    assert_eq!(field_str(&record3, "winlog.event_data.HWLength"), Some("6"));
    assert_eq!(
        field_str(&record3, "winlog.event_data.StatusCode"),
        Some("121")
    );
    assert!(warnings.next().unwrap().is_none());

    let mut errors = reader
        .query(&EventLogQuery::new().with_event_ids(&[1001]))
        .unwrap();
    let record4 = errors.next().unwrap().expect("record 4");
    assert_eq!(record4.record_id, 4);
    assert_eq!(record4.computer, "CompW2019x64.cancamusa.com");
    assert_eq!(record4.level, EventLevel::Error);
    assert_eq!(
        field_str(&record4, "winlog.event_data.HWAddress"),
        Some("0x000063c37a46")
    );
    assert_eq!(field_str(&record4, "winlog.event_data.HWLength"), Some("6"));
    assert_eq!(
        field_str(&record4, "winlog.event_data.StatusCode"),
        Some("121")
    );
    assert!(errors.next().unwrap().is_none());
}
