# frnsc-winevt

A [`forensic-rs`](https://github.com/ForensicRS/forensic-rs) `FormatFactory`/`EventLogReader` implementation for Windows Event Log files: both the legacy binary `.evt` format and the modern binary-XML `.evtx` format.

**Implements:** `FormatFactory` (`EvtFormatFactory`, `EvtxFormatFactory`) and `EventLogReader` (`EvtEventLogReader`, `EvtxEventLogReader`).

Built on `forensic-rs`, which decouples forensic analysis logic from data access: an analyzer written against `forensic_rs::traits::events::EventLogReader` runs unmodified whether the underlying evidence is a live Windows Event Log API, a parsed `.evt`/`.evtx` file (this crate), or an in-memory test double (`forensic_rs::utils::testing::TestingEventLogReader`).

## Usage

```rust
use std::sync::Arc;
use forensic_rs::prelude::*;
use frnsc_winevt::{EvtFormatFactory, EvtxFormatFactory};

let resolver = MountResolver::builder()
    .factory(Arc::new(EvtxFormatFactory))
    .factory(Arc::new(EvtFormatFactory::new("Application"))) // .evt has no embedded channel name
    .build();

// `resolver.resolve(&fs, &locator, file, Some(MountKind::EventLog), &cancellation)`
// returns `Mounted::EventLog(Arc<dyn EventLogReader>)` for a recognized file.
// From there, query it exactly like any other EventLogReader:
fn count_failed_logons(reader: &dyn EventLogReader) -> ForensicResult<u32> {
    let query = EventLogQuery::new()
        .with_channels(&["Security"])
        .with_event_ids(&[4625]);
    let mut iter = reader.query(&query)?;
    let mut count = 0u32;
    while let Some(_record) = iter.next()? {
        count += 1;
    }
    Ok(count)
}
```

## Coverage and limitations

Both readers parse eagerly (the whole file is decoded into memory at mount time) and are read-only — there is no live/write path.

**`.evtx`**
- Full BinXML decoding: elements, attributes, templates with substitution arrays (including conditional substitutions — a null-valued conditional substitution omits its attribute/text node), value-type arrays, nested templates, and nested BinXml values (`EventData`'s actual content arrives this way — decoded recursively, not dropped).
- `System/*`, `EventData/Data[@Name]`, and `UserData/*` (flattened to dotted keys, e.g. `winlog.user_data.EventXML.ProcessId`) are mapped into `EventRecord`.
- File/chunk CRC-32 checksums are validated but **not** treated as fatal — a dirty or partially-flushed EVTX file (a live acquisition mid-write, a crash) is still parsed. The mismatch isn't just discarded after the check either: every record from an affected file/chunk carries `evtx.file.checksum_valid`/`evtx.chunk.checksum_valid` (`false`) in its `data` map. A record whose physical header parses but whose BinXML fails to decode into a recognizable `Event` element still appears too (with only `record_id`/`timestamp` reliable), carrying `evtx.record.decode_error`, rather than silently vanishing.
- Not implemented: message-table/manifest resolution (so `EventData` values are the raw typed values, not a formatted message string — the same limitation `EventRecord`'s own documentation describes), processing instructions, and the full dependency-identifier gating mechanism for template-conditional *subtrees* (a conditional substitution's own null value is still correctly omitted; omitting an entire gated element subtree is not).

**`.evt`**
- `.evt` has no embedded channel name — `EvtFormatFactory::new(channel)` takes the channel to attribute records to (typically derived from the source file name: `AppEvent.evt` -> `"Application"`, `SecEvent.evt` -> `"System"`, etc.).
- Insertion strings and the raw data blob (there's no structured `EventData` in this format) surface as `event.strings` and `event.data` (hex-encoded — `Field` has no dedicated binary variant) in `EventRecord::data`.
- Covers the common non-wrapped case: parsing walks sequentially from the header's `start_offset` to `end_offset` and stops at the first record that fails to parse. A `.evt` log whose circular buffer has wrapped, or one recoverable only by scanning for trailing per-record size copies (a realistic scenario for a log pulled from unallocated space), is not handled.

## Testing

Tests use hand-built, byte-correct synthetic `.evt`/`.evtx` fixtures (see the `tests` modules alongside each parser, and `tests/format_factory.rs` for the end-to-end `MountResolver` path) rather than a mocking library, plus one real-world fixture: `tests/real_evtx_sample.rs` reads a genuine `.evtx` sample checked in at `artifacts/C/Windows/System32/winevt/Logs/` (mimicking its live-system path). Real on-disk BinXML exercises template/substitution/nested-fragment code paths a hand-built fixture is unlikely to hit by construction — it's what caught three real decoding bugs during development (see `AGENTS.md`).

## License

MIT
