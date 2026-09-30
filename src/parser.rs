//! [`ArtifactParserFactory`] over the `WindowsXMLEventLog*` artifact-catalog definitions.
//!
//! Where [`crate::EvtxFormatFactory`] answers "these bytes are an event log, mount them",
//! this answers "find every Windows XML Event Log this evidence has, and emit its records".
//! The two are complementary, not alternatives: a pipeline registers both.

use std::collections::BTreeMap;
use std::io::Read;

use forensic_rs::prelude::*;

use crate::evtx::reader::EvtxEventLogReader;

/// Registration id of [`EvtxParserFactory`], in the `ParserRegistry`/`AccessRequirements`
/// namespace.
pub const PARSER_ID: &str = "windows.evtx";

/// The ForensicArtifacts definitions this parser reads, in the order it reads them.
///
/// The catalog is the source of truth for *where* these logs live; there is deliberately no
/// local glob list here to drift from it. Sorted, so a run's output order is deterministic.
pub const DEFINITIONS: &[&str] = &[
    "WindowsXMLEventLogApplication",
    "WindowsXMLEventLogPowerShell",
    "WindowsXMLEventLogSecurity",
    "WindowsXMLEventLogSysmon",
    "WindowsXMLEventLogSystem",
    "WindowsXMLEventLogTerminalServices",
];

/// Channel carried by the log `WindowsXMLEventLogSysmon` names.
const SYSMON_CHANNEL: &str = "Microsoft-Windows-Sysmon/Operational";
/// Channels carried by the logs `WindowsXMLEventLogPowerShell` names.
const POWERSHELL_CHANNELS: &[&str] = &[
    "Microsoft-Windows-PowerShell/Admin",
    "Microsoft-Windows-PowerShell/Operational",
    "PowerShellCore/Operational",
    "Windows PowerShell",
];
/// Channel carried by the log `WindowsXMLEventLogTerminalServices` names. `WindowsEvents` has
/// no variant for it, so its records are `WindowsEvents::Other(_)`.
const TERMINAL_SERVICES_CHANNEL: &str =
    "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational";

/// The [`Artifact`] for a record read from `channel`.
///
/// Classification only: the channel string itself is kept verbatim in the record's
/// `event.channel` field, so nothing here can lose what was read. Recognizes the channels the
/// [`DEFINITIONS`] name, which is more than
/// [`EventRecord::into_forensic_data`]'s own mapping does (it knows only the four classic
/// channels and leaves PowerShell, Sysmon and TerminalServices as `Other`).
fn artifact_for_channel(channel: &str) -> Artifact {
    let event = match channel {
        "Application" => WindowsEvents::Application,
        "Security" => WindowsEvents::Security,
        "Setup" => WindowsEvents::Setup,
        "System" => WindowsEvents::System,
        SYSMON_CHANNEL => WindowsEvents::Sysmon,
        other if POWERSHELL_CHANNELS.contains(&other) => WindowsEvents::PowerShell,
        other => WindowsEvents::Other(other.to_string()),
    };
    Artifact::from(event)
}

/// Emits one [`ForensicData`] per event record of every Windows XML Event Log the run's
/// [`ArtifactCatalog`] locates, built on [`EvtxEventLogReader`].
///
/// Stateless (`&self`): the open readers, the byte buffers and the registered sources all live
/// inside [`Self::open`] and the [`ParserRun::Push`] closure it returns, never in `self`, so one
/// instance behind an `Arc` serves the serial pipeline and every parallel worker.
///
/// # Requires an artifact catalog
///
/// Files are located exclusively through [`ParseContext::resolve_artifact`] over
/// [`DEFINITIONS`]. A run with no catalog configured on its `TriageSources` cannot be served,
/// and [`Self::can_parse`] returns `false` rather than falling back to a hand-maintained glob
/// list that would silently diverge from the knowledge base.
///
/// # Failure granularity
///
/// One unreadable log is one `Err` item and the other logs are still read: this is the granularity
/// the parser itself controls, and it holds. Within a log, a record whose BinXML does not decode
/// still appears (carrying `evtx.record.decode_error` — see [`EvtxEventLogReader`]) rather than
/// vanishing.
///
/// ## What is *not* reported, and why the cursor's `Err` arm is still here
///
/// The record cursor's `Err` arm below is **unreachable today**.
/// [`EvtxEventLogReader::from_bytes`] decodes the whole file eagerly and returns `Ok` as soon as
/// the 4096-byte file header parses; `query()` then iterates an already-built `Vec<EventRecord>`,
/// which cannot fail. So the parser never sees a mid-log read error, and the "ends that log's
/// scan" behaviour it implements has no input that triggers it. The arm is kept as defensive
/// structure — it goes live if the reader ever becomes streaming — and the no-resynchronization
/// reasoning stays correct for that day.
///
/// The consequence is a real blind spot, recorded in the workspace `FINDINGS.md` and pinned by
/// `a_log_truncated_mid_chunk_is_silently_empty`:
///
/// * the reader derives `total_chunks` from the file *length*
///   (`(len - 4096) / EVTX_CHUNK_SIZE`), so a `.evtx` truncated to any length in `4096..=69631`
///   parses its header, yields `total_chunks == 0`, and produces **zero records and zero `Err`
///   items** — output indistinguishable from a chunk slot that was allocated but never written;
/// * an unparsable chunk slot is skipped (`continue`) and a structurally corrupt record ends the
///   chunk scan (`break`), in both cases without so much as a `debug!`;
/// * the header's own `chunk_count` and `last_chunk_number` — the evidence that records *were*
///   expected — are parsed into [`EvtxFileHeader`] and then ignored, so nothing compares them
///   against `total_chunks`.
///
/// Fixing that means changing [`EvtxEventLogReader`], whose non-test code this parser
/// deliberately does not touch; it is a separate change. Until then, do not read "one `Err` per
/// unreadable log" as covering truncation *within* a log.
pub struct EvtxParserFactory {
    descriptor: ParserDescriptor,
}

impl Default for EvtxParserFactory {
    fn default() -> Self {
        let artifacts: Vec<Artifact> = vec![
            Artifact::from(WindowsEvents::Application),
            Artifact::from(WindowsEvents::PowerShell),
            Artifact::from(WindowsEvents::Security),
            Artifact::from(WindowsEvents::Sysmon),
            Artifact::from(WindowsEvents::System),
            // Declared explicitly because `WindowsEvents` has no TerminalServices variant:
            // without it, every record of the log `WindowsXMLEventLogTerminalServices` names
            // would fail `ParserDescriptor::handles` and go unmatched by every auto-matched
            // `AnalysisModule`. Never left empty — empty means "every artifact".
            Artifact::from(WindowsEvents::Other(TERMINAL_SERVICES_CHANNEL.to_string())),
        ];
        let requirements: Vec<Requirement> = DEFINITIONS
            .iter()
            .copied()
            .map(|name| Requirement::Artifact(ArtifactRef::from_static(name)))
            .collect();
        Self {
            descriptor: ParserDescriptor::new(
                PARSER_ID,
                "Windows XML Event Log",
                "Emits one record per event of every Windows XML Event Log (.evtx) the artifact \
                 catalog locates: Application, Security, System, PowerShell, Sysmon and \
                 TerminalServices",
                env!("CARGO_PKG_VERSION"),
            )
            .with_artifacts(artifacts)
            .with_requirements(requirements),
        }
    }
}

impl EvtxParserFactory {
    pub fn new() -> Self {
        Self::default()
    }
}

impl ArtifactParserFactory for EvtxParserFactory {
    fn descriptor(&self) -> &ParserDescriptor {
        &self.descriptor
    }

    /// Both a filesystem to read and a catalog to locate the logs with. Deliberately does not
    /// resolve the definitions here: that walks the evidence, and [`Self::open`] would only
    /// have to walk it again.
    fn can_parse(&self, ctx: &ParseContext<'_>) -> bool {
        ctx.vfs().is_some() && ctx.sources().catalog().is_some()
    }

    fn open(&self, ctx: &ParseContext<'_>) -> ForensicResult<ParserRun> {
        let fs = ctx.vfs().cloned().ok_or_else(|| {
            ForensicError::missing_data(
                "FileSystem source required",
                CompactString::const_new(PARSER_ID),
            )
        })?;
        if ctx.sources().catalog().is_none() {
            return Err(ForensicError::missing_data(
                "ArtifactCatalog required: this parser locates event logs by artifact \
                 definition name, never by a local glob list",
                CompactString::const_new(PARSER_ID),
            ));
        }
        let host = ctx.host().to_string();
        let acquisition = ctx.acquisition();
        let cancellation = ctx.cancellation().clone();

        // Problems first, so they are not buried after thousands of records.
        let mut head: Vec<ForensicResult<ForensicData>> = Vec::new();
        // Keyed by path so a file two definitions both name is read once, and so emission
        // order does not depend on the filesystem's walk order.
        let mut targets: BTreeMap<FPathBuf, &'static str> = BTreeMap::new();
        for definition in DEFINITIONS.iter().copied() {
            let resolution = match ctx.resolve_artifact(definition) {
                Ok(resolution) => resolution,
                Err(e) => {
                    head.push(Err(e));
                    continue;
                }
            };
            // A directory that could not be listed is not the same as "the log is absent":
            // it is a hole in the evidence and stays visible as its own item.
            head.extend(resolution.errors.into_iter().map(Err));
            // Likewise a source of the definition that never became a search pattern at all:
            // that part of the definition was not examined, which is not the same as "not
            // found". `notes` below are only how the patterns were built (which fallback was
            // used, ...) — the path each record ends up carrying already tells the analyst
            // where it really came from, so those are for the engineer.
            head.extend(resolution.unresolved.into_iter().map(|u| {
                Err(ForensicError::other(
                    "catalog",
                    format!(
                        "{definition}: source {:?} was not searched: {}",
                        u.source, u.reason
                    ),
                ))
            }));
            for note in &resolution.notes {
                debug!("{PARSER_ID}: {definition}: {note}");
            }
            for file in resolution.files {
                // Every `WindowsXMLEventLog*` source names files, never directories; a
                // directory match would be a catalog change, not an event log.
                if file.directory {
                    debug!("{PARSER_ID}: {definition}: ignoring directory {}", file.path);
                    continue;
                }
                if let Some(first) = targets.get(&file.path) {
                    debug!(
                        "{PARSER_ID}: {} matched both {first} and {definition}; attributed to {first}",
                        file.path
                    );
                    continue;
                }
                targets.insert(file.path, definition);
            }
        }

        // One registered source per real file — never one wildcard standing in for several.
        let targets: Vec<(FPathBuf, &'static str, SourceHandle)> = targets
            .into_iter()
            .map(|(path, definition)| {
                let source = ctx.register_source(SourceKey::Path(path.as_str().to_string()));
                (path, definition, source)
            })
            .collect();

        Ok(ParserRun::push(move |out| {
            for item in head {
                if out.emit(item).is_stop() {
                    return Ok(());
                }
            }
            for (path, definition, source) in targets {
                if cancellation.is_cancelled() {
                    return Ok(());
                }
                // A plain local: the reader, and the borrowed record cursor below, live and
                // die inside this frame. This is exactly why the run is `Push`.
                let reader = match read_log(fs.as_ref(), path.as_path()) {
                    Ok(reader) => reader,
                    Err(e) => {
                        if out.emit(Err(e)).is_stop() {
                            return Ok(());
                        }
                        continue;
                    }
                };
                let mut records = match reader.query(&EventLogQuery::new()) {
                    Ok(records) => records,
                    Err(e) => {
                        if out.emit(Err(e.with_path(path.clone()))).is_stop() {
                            return Ok(());
                        }
                        continue;
                    }
                };
                loop {
                    if cancellation.is_cancelled() {
                        return Ok(());
                    }
                    match records.next() {
                        Ok(Some(record)) => {
                            let data = to_forensic_data(
                                &host,
                                definition,
                                path.as_path(),
                                &source,
                                acquisition,
                                record,
                            );
                            if out.emit(Ok(data)).is_stop() {
                                return Ok(());
                            }
                        }
                        Ok(None) => break,
                        Err(e) => {
                            // UNREACHABLE TODAY, deliberately kept — see this type's docs.
                            // `EvtxEventLogReader` decodes eagerly in `from_bytes`, so `query()`
                            // walks a `Vec<EventRecord>` that cannot yield `Err`. This arm goes
                            // live only if the reader becomes streaming; the reasoning below is
                            // what it should do when it does.
                            if out.emit(Err(e.with_path(path.clone()))).is_stop() {
                                return Ok(());
                            }
                            // No resynchronization is possible mid-log; the next log goes on.
                            break;
                        }
                    }
                }
            }
            Ok(())
        }))
    }
}

/// Reads the whole log at `path` and parses it. Every failure carries the path, so an `Err`
/// item names the log it came from.
fn read_log(fs: &dyn FileSystem, path: &FPath) -> ForensicResult<EvtxEventLogReader> {
    let mut file = fs
        .open(path)
        .map_err(|e| e.with_path(FPathBuf::from(path.as_str())))?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).map_err(|e| {
        ForensicError::io_error_with_source(e, format!("{PARSER_ID}: reading {path}"))
    })?;
    EvtxEventLogReader::from_bytes(bytes).map_err(|e| e.with_path(FPathBuf::from(path.as_str())))
}

fn to_forensic_data(
    host: &str,
    definition: &'static str,
    path: &FPath,
    source: &SourceHandle,
    acquisition: Acquisition,
    record: EventRecord,
) -> ForensicData {
    let provenance = source.mint(acquisition, Recovery::Allocated);
    let artifact = artifact_for_channel(&record.channel);
    let mut data = ForensicData::new(host, artifact.clone(), provenance);
    // `EventRecord::into_forensic_data` owns the record -> ECS field mapping; reuse it rather
    // than restating it here, then put back the two fields it cannot get right for a
    // file-backed log: `artifact.host` (it has no run host and writes an empty one) and
    // `artifact.name` (its channel mapping does not know the PowerShell, Sysmon and
    // TerminalServices channels — see `artifact_for_channel`). `data.artifact()` itself is
    // already the classification above; these two keep the serialized fields agreeing with it.
    data.extend_from(record.into_forensic_data(provenance));
    data.insert(
        Text::Borrowed(ARTIFACT_HOST),
        Field::Text(Text::Owned(host.to_string())),
    );
    data.insert(
        Text::Borrowed(ARTIFACT_NAME),
        Field::Text(Text::Owned(artifact.to_string())),
    );
    data.set(ARTIFACT_PATH, path.as_str().to_string());
    data.set(ARTIFACT_DEFINITION, definition);
    data
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;
    use std::sync::Arc;

    use forensic_rs::prelude::testing::{
        collect_run, InMemoryVirtualFileSystem, TestingRegistry,
    };
    use forensic_rs::traits::registry::RegValue;

    use super::*;
    use crate::evtx::testdata::{build_evtx_file, build_evtx_file_with_undecodable_record};

    const NT: &str = r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion";
    const LOGS: &str = r"Windows/System32/winevt/Logs";

    /// The real `WindowsXMLEventLog*` sources, restated as an in-test catalog: the crate
    /// cannot depend on `frnsc-artifacts` (that would invert the dependency — the catalog crate
    /// is downstream), and a pinned copy here also fails loudly if a definition's paths change.
    fn definition(name: &'static str, paths: &'static [Text]) -> ArtifactDefinition {
        ArtifactDefinition {
            name: Cow::Borrowed(name),
            aliases: Cow::Borrowed(&[]),
            doc: Cow::Borrowed(""),
            sources: Cow::Owned(vec![SourceEntry {
                source: ArtifactSource::File {
                    paths: Cow::Borrowed(paths),
                    separator: Separator::Backslash,
                },
                supported_os: Cow::Borrowed(&[]),
            }]),
            supported_os: Cow::Borrowed(&[Os::Windows]),
            urls: Cow::Borrowed(&[]),
        }
    }

    fn catalog() -> Arc<dyn ArtifactCatalog> {
        let defs = vec![
            definition(
                "WindowsXMLEventLogApplication",
                &[Cow::Borrowed(
                    r"%%environ_systemroot%%\System32\winevt\Logs\Application.evtx",
                )],
            ),
            definition(
                "WindowsXMLEventLogPowerShell",
                &[
                    Cow::Borrowed(
                        r"%%environ_systemroot%%\System32\winevt\Logs\Microsoft-Windows-PowerShell%4Operational.evtx",
                    ),
                    Cow::Borrowed(
                        r"%%environ_systemroot%%\System32\winevt\Logs\Windows PowerShell.evtx",
                    ),
                ],
            ),
            definition(
                "WindowsXMLEventLogSecurity",
                &[Cow::Borrowed(
                    r"%%environ_systemroot%%\System32\winevt\Logs\Security.evtx",
                )],
            ),
            definition(
                "WindowsXMLEventLogSysmon",
                &[Cow::Borrowed(
                    r"%%environ_systemroot%%\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx",
                )],
            ),
            definition(
                "WindowsXMLEventLogSystem",
                &[Cow::Borrowed(
                    r"%%environ_systemroot%%\System32\winevt\Logs\System.evtx",
                )],
            ),
            definition(
                "WindowsXMLEventLogTerminalServices",
                &[Cow::Borrowed(
                    r"%%environ_systemroot%%\System32\winevt\Logs\Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx",
                )],
            ),
        ];
        Arc::new(SliceCatalog::new(defs).unwrap())
    }

    /// `%%environ_systemroot%%` resolves through the host profile, so the registry has to
    /// carry a `SystemRoot`; without one every glob degrades to a `\*` search.
    fn registry() -> Arc<dyn Registry> {
        let mut reg = TestingRegistry::empty();
        reg.add_value(NT, "SystemRoot", RegValue::new_sz(r"C:\Windows"));
        Arc::new(reg)
    }

    fn sources(vfs: InMemoryVirtualFileSystem, with_catalog: bool) -> TriageSources {
        let mut builder = TriageSources::builder()
            .vfs(Arc::new(vfs))
            .registry(registry())
            .acquisition(Acquisition::ImageRead);
        if with_catalog {
            builder = builder.catalog(catalog());
        }
        builder.build()
    }

    fn run(sources: &TriageSources) -> Vec<ForensicResult<ForensicData>> {
        let triage = TriageContext::new("TEST-HOST", "default");
        let cancellation = CancellationToken::new();
        let ctx = ParseContext::new(sources, &triage, &cancellation);
        let parser = EvtxParserFactory::new();
        assert!(parser.can_parse(&ctx));
        collect_run(parser.open(&ctx).unwrap()).unwrap()
    }

    fn field<'a>(data: &'a ForensicData, key: &str) -> Option<&'a str> {
        data.field_as_str(key)
    }

    #[test]
    fn declares_every_definition_as_a_requirement() {
        let parser = EvtxParserFactory::new();
        let declared: Vec<&str> = parser
            .descriptor()
            .requirements
            .iter()
            .filter_map(|r| match r {
                Requirement::Artifact(a) => Some(a.name.as_ref()),
                _ => None,
            })
            .collect();
        assert_eq!(declared, DEFINITIONS.to_vec());
        assert!(
            !parser.descriptor().artifacts.is_empty(),
            "an empty artifact list would mean 'every artifact'"
        );
    }

    #[test]
    fn emits_one_record_per_event_with_per_file_provenance() {
        let vfs = InMemoryVirtualFileSystem::new()
            .with_file(
                format!("{LOGS}/Security.evtx"),
                build_evtx_file("Security"),
            )
            .with_file(
                format!("{LOGS}/Microsoft-Windows-Sysmon%4Operational.evtx"),
                build_evtx_file(SYSMON_CHANNEL),
            );
        let sources = sources(vfs, true);
        let items = run(&sources);

        let records: Vec<&ForensicData> = items.iter().filter_map(|i| i.as_ref().ok()).collect();
        assert!(
            items.iter().all(|i| i.is_ok()),
            "unexpected error items: {:?}",
            items.iter().filter_map(|i| i.as_ref().err()).collect::<Vec<_>>()
        );
        assert_eq!(records.len(), 2);

        // Deterministic order: by path, so Microsoft-... sorts before Security.evtx.
        let paths: Vec<Option<&str>> = records.iter().map(|d| field(d, ARTIFACT_PATH)).collect();
        assert_eq!(
            paths,
            vec![
                Some(
                    format!("{LOGS}/Microsoft-Windows-Sysmon%4Operational.evtx").as_str()
                ),
                Some(format!("{LOGS}/Security.evtx").as_str()),
            ]
        );

        let sysmon = records[0];
        assert_eq!(field(sysmon, "event.channel"), Some(SYSMON_CHANNEL));
        assert_eq!(
            field(sysmon, ARTIFACT_DEFINITION),
            Some("WindowsXMLEventLogSysmon")
        );
        // The channel is classified, not invented: `event.channel` above still holds it
        // verbatim, and `WindowsEvents::Other` would be the un-classified answer.
        assert_eq!(
            sysmon.artifact(),
            &Artifact::from(WindowsEvents::Sysmon),
            "the Sysmon channel must classify as WindowsEvents::Sysmon"
        );
        assert_eq!(field(sysmon, ARTIFACT_NAME), Some("Windows::WinEvt::Sysmon"));
        assert_eq!(field(sysmon, ARTIFACT_HOST), Some("TEST-HOST"));
        // The record's own Computer stays separate from the run's host.
        assert_eq!(field(sysmon, "host.name"), Some("HOST"));
        assert_eq!(sysmon.field_as_u64("event.code"), Some(7));
        assert!(
            sysmon.field_as_date(TIMESTAMP).is_some(),
            "@timestamp must carry the record's own TimeCreated"
        );

        let security = records[1];
        assert_eq!(
            security.artifact(),
            &Artifact::from(WindowsEvents::Security)
        );
        assert_eq!(
            field(security, ARTIFACT_DEFINITION),
            Some("WindowsXMLEventLogSecurity")
        );

        // One registered source per real file, so the two records do not share provenance.
        assert_ne!(
            sysmon.provenance(),
            security.provenance(),
            "each log must mint against its own registered source"
        );
    }

    #[test]
    fn a_truncated_log_is_one_err_item_and_the_other_logs_still_parse() {
        let mut truncated = build_evtx_file("System");
        truncated.truncate(16); // below the EVTX file header: cannot be framed at all
        let vfs = InMemoryVirtualFileSystem::new()
            .with_file(format!("{LOGS}/System.evtx"), truncated)
            .with_file(
                format!("{LOGS}/Security.evtx"),
                build_evtx_file("Security"),
            );
        let items = run(&sources(vfs, true));

        let errors: Vec<&ForensicError> = items.iter().filter_map(|i| i.as_ref().err()).collect();
        let records: Vec<&ForensicData> = items.iter().filter_map(|i| i.as_ref().ok()).collect();
        assert_eq!(errors.len(), 1, "the truncated log is exactly one Err item");
        assert!(
            errors[0].to_string().contains("System.evtx"),
            "the error must name the log it came from: {}",
            errors[0]
        );
        assert_eq!(
            records.len(),
            1,
            "the stream must continue past the truncated log"
        );
        assert_eq!(
            field(records[0], ARTIFACT_PATH),
            Some(format!("{LOGS}/Security.evtx").as_str())
        );
    }

    #[test]
    fn a_log_truncated_mid_chunk_is_silently_empty() {
        // REGRESSION PIN, NOT AN ENDORSEMENT. This asserts a known blind spot so that it is
        // recorded rather than merely unknown — see this module's `EvtxParserFactory` docs and
        // the workspace `FINDINGS.md`.
        //
        // `a_truncated_log_is_one_err_item_…` above uses truncate(16), which is the *only* class
        // of truncation the reader catches: below 4096 the file header itself cannot be framed.
        // Cut anywhere inside the first chunk instead and the header parses fine, while
        // `total_chunks = (len - 4096) / 65536` rounds down to zero — so the log reports as
        // empty, with no error, even though its own header says records were written.
        let full = build_evtx_file("System");
        assert_eq!(full.len(), 69632, "one header block plus one 64 KiB chunk");
        let mut truncated = full.clone();
        truncated.truncate(40000); // header intact, chunk cut in half
        let vfs = InMemoryVirtualFileSystem::new()
            .with_file(format!("{LOGS}/System.evtx"), truncated)
            .with_file(
                format!("{LOGS}/Security.evtx"),
                build_evtx_file("Security"),
            );
        let items = run(&sources(vfs, true));

        let errors: Vec<&ForensicError> = items.iter().filter_map(|i| i.as_ref().err()).collect();
        let records: Vec<&ForensicData> = items.iter().filter_map(|i| i.as_ref().ok()).collect();

        // The blind spot itself: no record, and nothing says so.
        assert!(
            errors.is_empty(),
            "PINNED CURRENT BEHAVIOUR: mid-chunk truncation raises no error. This pin fires on \
             the header's own chunk_count (file[42..44], written as 1 by build_evtx_file) versus \
             total_chunks computed from the file length — not on last_chunk_number, which is 0 \
             for a single-chunk log either way and would not trip. If this now fails, the reader \
             learned to compare chunk_count against the file length — that is the desired fix; \
             update this test and the FINDINGS.md entry rather than restoring the silence. \
             Got: {errors:?}"
        );
        assert_eq!(
            records.len(),
            1,
            "PINNED CURRENT BEHAVIOUR: the truncated log contributes no records at all, so only \
             the intact Security.evtx is represented"
        );
        assert_eq!(
            field(records[0], ARTIFACT_PATH),
            Some(format!("{LOGS}/Security.evtx").as_str()),
            "the one surviving record must be the intact log's"
        );

        // And the point of the pin: that output is indistinguishable from a chunk slot that was
        // allocated but never written — a valid header, full file length, and a zeroed chunk
        // area, which is what "genuinely empty" means on disk. This is deliberately NOT a second
        // short file: truncating to 4096 bytes gives total_chunks == 0 and skips the chunk loop
        // entirely, while a full-length zeroed chunk gives total_chunks == 1 and exercises
        // `EvtxChunkHeader::parse` failing on the zeroed magic, taking the `continue` path at
        // reader.rs — the actual code path a never-written chunk slot takes.
        let mut never_written = full;
        never_written[4096..].fill(0); // zero the chunk area, keep the 4096-byte file header
        let empty_vfs = InMemoryVirtualFileSystem::new()
            .with_file(format!("{LOGS}/System.evtx"), never_written)
            .with_file(
                format!("{LOGS}/Security.evtx"),
                build_evtx_file("Security"),
            );
        let empty_items = run(&sources(empty_vfs, true));
        assert_eq!(
            empty_items.len(),
            items.len(),
            "a log truncated mid-chunk and a log with a never-written chunk slot are \
             indistinguishable"
        );
    }

    #[test]
    fn a_record_with_undecodable_binxml_still_reaches_the_pipeline() {
        // The complement of the truncated-file case: the *file* is readable, one *record* is
        // not. It must arrive as a record carrying the decode failure — not be dropped, and not
        // turn into an error that hides the fact that a record existed there at all.
        let vfs = InMemoryVirtualFileSystem::new()
            .with_file(
                format!("{LOGS}/System.evtx"),
                build_evtx_file_with_undecodable_record(42),
            )
            .with_file(format!("{LOGS}/Security.evtx"), build_evtx_file("Security"));
        let items = run(&sources(vfs, true));

        assert!(
            items.iter().all(|i| i.is_ok()),
            "an undecodable record is a record, not an error: {:?}",
            items.iter().filter_map(|i| i.as_ref().err()).collect::<Vec<_>>()
        );
        let records: Vec<&ForensicData> = items.iter().filter_map(|i| i.as_ref().ok()).collect();
        assert_eq!(records.len(), 2, "both logs contribute their record");

        let broken = records
            .iter()
            .find(|d| field(d, ARTIFACT_PATH) == Some(format!("{LOGS}/System.evtx").as_str()))
            .expect("the log with the undecodable record still produced one");
        assert_eq!(broken.field_as_u64("event.record_id"), Some(42));
        assert!(
            field(broken, "evtx.record.decode_error").is_some(),
            "the decode failure must travel with the record"
        );
        // Nothing was invented to fill the gap: no channel was decoded, so the record falls to
        // the un-classified artifact rather than being attributed to a channel it never named.
        assert_eq!(
            broken.artifact(),
            &Artifact::from(WindowsEvents::Other(String::new()))
        );
        assert!(
            broken.field_as_date(TIMESTAMP).is_some(),
            "the record header's own TimeCreated survived even though its BinXML did not"
        );
    }

    #[test]
    fn a_log_that_is_not_an_evtx_file_at_all_is_one_err_item() {
        let vfs = InMemoryVirtualFileSystem::new()
            .with_file(format!("{LOGS}/Application.evtx"), vec![0xAAu8; 4096]);
        let items = run(&sources(vfs, true));
        assert_eq!(items.len(), 1);
        assert!(items[0].is_err());
    }

    #[test]
    fn a_missing_log_is_not_an_error() {
        let items = run(&sources(InMemoryVirtualFileSystem::new(), true));
        assert!(
            items.is_empty(),
            "logs that are simply absent produce neither records nor errors: {items:?}"
        );
    }

    #[test]
    fn without_a_catalog_the_parser_declines_instead_of_guessing_paths() {
        let vfs = InMemoryVirtualFileSystem::new().with_file(
            format!("{LOGS}/Security.evtx"),
            build_evtx_file("Security"),
        );
        let sources = sources(vfs, false);
        let triage = TriageContext::new("TEST-HOST", "default");
        let cancellation = CancellationToken::new();
        let ctx = ParseContext::new(&sources, &triage, &cancellation);
        let parser = EvtxParserFactory::new();
        assert!(!parser.can_parse(&ctx));
        assert!(parser.open(&ctx).is_err());
    }

    #[test]
    fn cancellation_stops_before_any_log_is_read() {
        let vfs = InMemoryVirtualFileSystem::new().with_file(
            format!("{LOGS}/Security.evtx"),
            build_evtx_file("Security"),
        );
        let sources = sources(vfs, true);
        let triage = TriageContext::new("TEST-HOST", "default");
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        let ctx = ParseContext::new(&sources, &triage, &cancellation);
        let items = collect_run(EvtxParserFactory::new().open(&ctx).unwrap()).unwrap();
        assert!(items.is_empty());
    }

    #[test]
    fn classifies_every_channel_the_definitions_name() {
        assert_eq!(
            artifact_for_channel("Application"),
            Artifact::from(WindowsEvents::Application)
        );
        assert_eq!(
            artifact_for_channel("Security"),
            Artifact::from(WindowsEvents::Security)
        );
        assert_eq!(
            artifact_for_channel("System"),
            Artifact::from(WindowsEvents::System)
        );
        assert_eq!(
            artifact_for_channel("Setup"),
            Artifact::from(WindowsEvents::Setup)
        );
        assert_eq!(
            artifact_for_channel(SYSMON_CHANNEL),
            Artifact::from(WindowsEvents::Sysmon)
        );
        for channel in POWERSHELL_CHANNELS {
            assert_eq!(
                artifact_for_channel(channel),
                Artifact::from(WindowsEvents::PowerShell),
                "{channel}"
            );
        }
        // An unknown channel keeps its own name rather than being forced into a variant.
        assert_eq!(
            artifact_for_channel("Some-Vendor/Operational"),
            Artifact::from(WindowsEvents::Other("Some-Vendor/Operational".to_string()))
        );
        // The declared artifact list must actually cover the TerminalServices records.
        assert!(
            EvtxParserFactory::new()
                .descriptor()
                .handles(&artifact_for_channel(TERMINAL_SERVICES_CHANNEL))
        );
    }
}
