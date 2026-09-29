# frnsc-winevt Agent Guide

## Project Overview

frnsc-winevt implements the `forensic-rs` `FormatFactory` and `EventLogReader` traits for Windows Event Log files: the legacy binary `.evt` format and the modern binary-XML `.evtx` format.

**Depends on:** [`forensic-rs`](https://github.com/ForensicRS/forensic-rs) 0.14 (path-patched to a local `../forensic-rs` checkout in `.cargo/config.toml` for co-development — see that file before assuming `Cargo.toml`'s `"0.14"` version requirement is what actually gets built).

## Review discipline

Apply the `forensic-rs-tool-review` skill (copied into `.claude/skills/`) to every change here: it covers the trait-layering contract (Core vs. `Ext`), forensic soundness (never fabricate a missing timestamp, source divergence is evidence not noise, the Finding/log/error three-way split), and adversarial-input robustness (no panics on evidence bytes, bounds-checked parsing). Don't restate that content in this file.

## Module structure

- `src/crc32.rs` — CRC-32/ISO-HDLC, used by EVTX's (non-fatal) file/chunk checksums.
- `src/query_iter.rs` — the shared `EventLogIterator` over an already-parsed `Vec<EventRecord>`, used by both readers.
- `src/factory.rs` — `EvtFormatFactory`, `EvtxFormatFactory` (the `FormatFactory` impls; probe by magic bytes, mount by reading the whole file and delegating to the matching reader's `from_bytes`).
- `src/parser.rs` — `EvtxParserFactory` (the `ArtifactParserFactory` impl). Locates logs **only** through `ParseContext::resolve_artifact` over the `WindowsXMLEventLog*` definitions in `DEFINITIONS`; there is deliberately no local glob list here, and `can_parse` returns `false` when a run configured no `ArtifactCatalog` rather than guessing paths. `ParserRun::Push`, because `EventLogReader::query` hands back a borrowed cursor. `artifact_for_channel` classifies the channel into a `WindowsEvents` variant (recognizing PowerShell/Sysmon/TerminalServices, which `EventRecord::into_forensic_data` leaves as `Other`) — the raw channel always stays in `event.channel`.
- `src/evtx/testdata.rs` — `#[cfg(test)]`, `pub(crate)`: the hand-built synthetic `.evtx` fixtures (`build_evtx_file`, `build_evtx_file_with_undecodable_record`), shared by `evtx::reader`'s and `parser`'s test modules. **Build BinXML in place on the chunk buffer**: name-table offsets are chunk-absolute, so a fragment built in a standalone buffer and copied in later has wrong offsets.
- `src/evt/` — legacy format: `file_header.rs` (`ELF_LOGFILE_HEADER`), `record.rs` (`EVENTLOGRECORD`), `reader.rs` (`EvtEventLogReader` + record -> `EventRecord` mapping).
- `src/evtx/` — modern format:
  - `file_header.rs`, `chunk.rs`, `record.rs` — the three binary header layers (file -> 64KiB chunk -> record), each with byte-offset tables in their module doc comments citing the spec.
  - `binxml/values.rs` — BinXML variant-type value decoding (the `0x00`-`0x21`/array-flag type table).
  - `binxml/tokens.rs` — the token-stream walker: name-table resolution, template-instance expansion, and the recursive-descent decoder producing an `XmlElement` tree. `ChunkContext` holds the per-chunk name/template caches (offsets are chunk-absolute, so caches are keyed by chunk offset, not per-record).
  - `xml.rs` — the minimal generic XML tree type BinXML decodes into.
  - `mapping.rs` — `XmlElement` (the decoded `Event` root) -> `EventRecord`.
  - `reader.rs` — `EvtxEventLogReader`: iterates chunks by fixed-size slicing (not by trusting the file header's `chunk_count`), decodes every record, skips unparsable chunks/records rather than failing the whole file.

Byte-level layouts throughout are cited against the `libyal/libevt`/`libevtx` format documentation and cross-checked against the `omerbenamram/evtx` and `python-evtx` implementations — see the module-level doc comments for the specific tables. Known, deliberate gaps (message-table resolution, `.evt` wrap-around recovery, template dependency-identifier subtree gating) are listed in `README.md`'s "Coverage and limitations" section — check there before assuming something unhandled is a bug rather than a documented scope boundary.

## Error handling

Use `ForensicResult<T>`/`ForensicError` from `forensic-rs`, and its `ensure_buffer_size!`/`ensure_format!` macros for structural validation (imported explicitly per file — they're `#[macro_export]`ed at the crate root, not covered by `forensic_rs::prelude::*`). Binary parsing uses `forensic_rs::parsing::ByteReader`, not the older `utils::unpack` free functions.

A magic/signature mismatch is a hard `ForensicError` (this isn't the claimed format at all). A checksum mismatch (EVTX file/chunk CRC-32) is not — it's recorded as a `*_checksum_valid` flag on the parsed header instead, since a dirty/partially-flushed log is forensically meaningful evidence, not just "corrupt input" to reject.

**Know the limit of "one unreadable log is one `Err` item".** That granularity is real for whole logs and false for truncation *within* one. `EvtxEventLogReader::from_bytes` decodes eagerly and derives `total_chunks` from the file *length*, while the header needs only the first 4096 bytes — so a `.evtx` cut anywhere in `4096..=69631` parses its header, reports zero chunks, and yields zero records with no error, identical to an empty log. An unparsable chunk slot `continue`s and a corrupt record `break`s, neither logging anything. Because `query()` walks an already-built `Vec`, it cannot yield `Err`, so `EvtxParserFactory`'s record-cursor `Err` arm is unreachable and marked as such; keep it as defensive structure for a future streaming reader. `parser::tests::a_log_truncated_mid_chunk_is_silently_empty` pins the current silence deliberately — if you fix the reader (compare the header's own `chunk_count`/`last_chunk_number` against `total_chunks`), update that test and the workspace `FINDINGS.md` rather than restoring the silence. Do not write a doc claim about failure granularity that no test can exercise.

## Testing

Every parser module builds its own hand-crafted byte fixtures in a `#[cfg(test)] mod tests` block. When adding a fixture that spans multiple layers (e.g. a full chunk containing a record's BinXML), build it as one growing `Vec<u8>` from offset 0 rather than assembling sub-buffers separately and splicing them in at a nonzero offset — BinXML name/template-table offsets are chunk-absolute, and a sub-buffer built starting at its own offset 0 silently breaks the "is this the definition or a reference" position check (`reader.position() == name_offset`) once spliced in elsewhere. This exact bug hit `evtx::reader`'s first fixture draft; see its `tests` module for the corrected pattern (also watch for reusing the wrong header-size constant across layers — a distinct bug that hit `evt::reader`'s first draft, confusing the *file* header's size with the *record* header's size).

`tests/real_evtx_sample.rs` reads a real `.evtx` file checked in at `artifacts/C/Windows/System32/winevt/Logs/Microsoft-Windows-Dhcp-Client%4Admin.evtx` (kept as a tracked fixture, not gitignored — a real sample is small and catches what hand-built fixtures can't by construction). It caught three real bugs the synthetic fixtures never exercised, all now fixed and covered by dedicated unit tests too:

1. `read_template_instance` was missing a byte real EVTX always has immediately after the `TOK_TEMPLATE_INSTANCE` token, before `template_id` — not documented in any spec I found, only found by tracing real bytes against a known-good template-bucket-table offset.
2. `read_scalar`'s `VALUE_NULL` arm consumed zero bytes regardless of `explicit_size`. A null-typed template substitution still reserves its declared byte span in the values blob as padding — skipping it silently misaligned every substitution after it for the rest of the record (this is what corrupted `Provider`/`Channel`/`Sid` in the real file, since they came later in that template).
3. Nested BinXml values (`VALUE_BINXML`, type `0x21` — how `EventData`'s actual content arrives) were stored as raw bytes and never decoded at all. Fixing this required storing a chunk-absolute `(start, end)` span rather than an owned byte copy in `BinXmlValue::NestedBinXml`: a recursive decode over an isolated copy breaks the "is this the definition" position check the moment the nested content happens to contain an inline name/template definition (which real `EventData` does). Its own top-level elements decode with `in_template = false` — they're per-record value data, not template-definition bytes, even though the substitution referencing them lives inside a template body.

If a future change to this decoder needs deeper verification, the pattern that found these bugs was: dump raw bytes at the point of failure, cross-check candidate field values against independently-known-good markers already present in the file (a chunk's string/template bucket-table offsets, a byte that should land exactly on a known token type), rather than trusting any single secondary source's documented byte layout — the extra byte in (1) isn't in any spec I could find, only in real files.
