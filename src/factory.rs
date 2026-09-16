//! [`FormatFactory`] implementations that recognize and mount `.evt`/`.evtx`
//! byte streams as [`Mounted::EventLog`].

use std::io::{Read, SeekFrom};
use std::sync::Arc;

use forensic_rs::prelude::*;

use crate::evt::file_header::{EVT_HEADER_SIZE, EVT_SIGNATURE};
use crate::evt::reader::EvtEventLogReader;
use crate::evtx::file_header::EVTX_FILE_MAGIC;

/// Recognizes and mounts the legacy binary `.evt` format.
///
/// `.evt` has no embedded channel name, so the factory is constructed with
/// the channel to attribute records to (typically derived from the source
/// file's name — `AppEvent.evt` -> `"Application"`, `SecEvent.evt` ->
/// `"Security"`, `SysEvent.evt` -> `"System"`).
pub struct EvtFormatFactory {
    channel: String,
}

impl EvtFormatFactory {
    pub fn new(channel: impl Into<String>) -> Self {
        Self {
            channel: channel.into(),
        }
    }
}

impl FormatFactory for EvtFormatFactory {
    fn name(&self) -> &'static str {
        "evt"
    }

    fn yields(&self) -> MountKind {
        MountKind::EventLog
    }

    fn probe(&self, file: &mut dyn VirtualFile, _ctx: &MountContext<'_>) -> ForensicResult<ProbeScore> {
        let start = file.stream_position()?;
        let mut header = [0u8; EVT_HEADER_SIZE];
        let matches = file.read_exact(&mut header).is_ok()
            && u32::from_le_bytes([header[0], header[1], header[2], header[3]]) as usize
                == EVT_HEADER_SIZE
            && u32::from_le_bytes([header[4], header[5], header[6], header[7]]) == EVT_SIGNATURE;
        file.seek(SeekFrom::Start(start))?;
        Ok(if matches { ProbeScore::Exact } else { ProbeScore::No })
    }

    fn mount(&self, mut file: Box<dyn VirtualFile>, _ctx: &MountContext<'_>) -> ForensicResult<Mounted> {
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        let reader = EvtEventLogReader::from_bytes(&bytes, self.channel.clone())?;
        Ok(Mounted::EventLog(Arc::new(reader)))
    }
}

/// Recognizes and mounts the modern binary-XML `.evtx` format.
pub struct EvtxFormatFactory;

impl FormatFactory for EvtxFormatFactory {
    fn name(&self) -> &'static str {
        "evtx"
    }

    fn yields(&self) -> MountKind {
        MountKind::EventLog
    }

    fn probe(&self, file: &mut dyn VirtualFile, _ctx: &MountContext<'_>) -> ForensicResult<ProbeScore> {
        let start = file.stream_position()?;
        let mut magic = [0u8; EVTX_FILE_MAGIC.len()];
        let matches = file.read_exact(&mut magic).is_ok() && magic == EVTX_FILE_MAGIC;
        file.seek(SeekFrom::Start(start))?;
        Ok(if matches { ProbeScore::Exact } else { ProbeScore::No })
    }

    fn mount(&self, mut file: Box<dyn VirtualFile>, _ctx: &MountContext<'_>) -> ForensicResult<Mounted> {
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        let reader = crate::evtx::reader::EvtxEventLogReader::from_bytes(bytes)?;
        Ok(Mounted::EventLog(Arc::new(reader)))
    }
}
