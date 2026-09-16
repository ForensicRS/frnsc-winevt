//! Legacy binary `.evt` Windows Event Log format.

pub mod file_header;
pub mod reader;
pub mod record;

pub use file_header::EvtFileHeader;
pub use reader::EvtEventLogReader;
