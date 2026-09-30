//! Modern binary-XML `.evtx` Windows Event Log format.

pub mod binxml;
pub mod chunk;
pub mod file_header;
pub mod mapping;
pub mod reader;
pub mod record;
pub(crate) mod testdata;
pub mod xml;

pub use file_header::EvtxFileHeader;
pub use reader::EvtxEventLogReader;
