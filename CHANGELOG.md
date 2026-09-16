# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Initial implementation of `FormatFactory` and `EventLogReader` for legacy `.evt` and modern `.evtx` Windows Event Log files, including a from-scratch BinXML decoder (templates, substitutions, value-type arrays) for `.evtx`.
- Nested BinXml value decoding (`VALUE_BINXML`), so `EventData`'s content is recursively decoded and populated instead of dropped.
- `tests/real_evtx_sample.rs`: a real `.evtx` sample checked in as a regression fixture.

### Fixed

- `read_template_instance` now consumes an extra byte real EVTX always writes immediately after the `TOK_TEMPLATE_INSTANCE` token, before `template_id` — previously misaligned every read for the rest of the record.
- Null-typed template substitutions (`VALUE_NULL`) now consume their declared byte span (reserved padding) instead of zero bytes — previously misaligned every substitution after them in the same record.
