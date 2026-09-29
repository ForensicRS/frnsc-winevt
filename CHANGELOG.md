# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `parser::EvtxParserFactory` (re-exported as `frnsc_winevt::EvtxParserFactory`) — an
  `ArtifactParserFactory` that locates every Windows XML Event Log in the evidence through the
  run's `ArtifactCatalog` (the `WindowsXMLEventLogApplication`/`PowerShell`/`Security`/`Sysmon`/
  `System`/`TerminalServices` definitions) and emits one `ForensicData` per event, built on
  `EvtxEventLogReader`. `FormatFactory` answers "these bytes are an event log"; this answers
  "find every event log this evidence has" — a pipeline registers both.
  - One registered provenance source per real `.evtx` file, never one wildcard covering several;
    emission order is keyed by path so a run is reproducible.
  - Requires an `ArtifactCatalog`: `can_parse` returns `false` without one rather than falling
    back to a local glob list that would drift from the knowledge base.
  - `parser::ARTIFACT_DEFINITION` (`artifact.definition`) carries the *path-derived* attribution
    beside the log's own `event.channel`, so a renamed or planted log is visible in the record
    rather than silently reconciled.
  - Channel classification recognizes the PowerShell, Sysmon and TerminalServices channels that
    `EventRecord::into_forensic_data`'s own mapping leaves as `WindowsEvents::Other`; the raw
    channel string is always kept verbatim in `event.channel`.
  - Failure granularity: one unreadable log is one `Err` item and the other logs are still read;
    a record whose BinXML does not decode still arrives as a record carrying
    `evtx.record.decode_error`.
- Initial implementation of `FormatFactory` and `EventLogReader` for legacy `.evt` and modern `.evtx` Windows Event Log files, including a from-scratch BinXML decoder (templates, substitutions, value-type arrays) for `.evtx`.
- Nested BinXml value decoding (`VALUE_BINXML`), so `EventData`'s content is recursively decoded and populated instead of dropped.
- `tests/real_evtx_sample.rs`: a real `.evtx` sample checked in as a regression fixture.

### Fixed

- `read_template_instance` now consumes an extra byte real EVTX always writes immediately after the `TOK_TEMPLATE_INSTANCE` token, before `template_id` — previously misaligned every read for the rest of the record.
- Null-typed template substitutions (`VALUE_NULL`) now consume their declared byte span (reserved padding) instead of zero bytes — previously misaligned every substitution after them in the same record.
