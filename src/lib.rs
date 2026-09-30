//! `frnsc-winevt`: a [`forensic_rs`] [`FormatFactory`](forensic_rs::traits::format::FormatFactory)
//! and [`EventLogReader`](forensic_rs::traits::events::EventLogReader) implementation for
//! Windows Event Log files — both the legacy binary `.evt` format and the
//! modern binary-XML `.evtx` format.
//!
//! Built on `forensic-rs`, which decouples forensic analysis logic from data
//! access: an analyzer written against `EventLogReader` runs unmodified
//! whether the underlying evidence is a live Windows Event Log API, a parsed
//! `.evt`/`.evtx` file (this crate), or an in-memory test double
//! (`forensic_rs::utils::testing::TestingEventLogReader`).
//!
//! # Usage
//!
//! ```no_run
//! use std::sync::Arc;
//! use forensic_rs::prelude::*;
//! use frnsc_winevt::{EvtFormatFactory, EvtxFormatFactory};
//!
//! let resolver = MountResolver::builder()
//!     .factory(Arc::new(EvtxFormatFactory))
//!     .factory(Arc::new(EvtFormatFactory::new("Application")))
//!     .build();
//! ```

mod crc32;
pub mod evt;
pub mod evtx;
mod factory;
/// Synthetic `.evtx` bytes built from the on-disk layout, for tests and readiness checks.
/// Hidden from docs and not part of the stable API.
#[doc(hidden)]
pub mod fixtures;
pub mod parser;
mod query_iter;

pub use factory::{EvtFormatFactory, EvtxFormatFactory};
pub use parser::EvtxParserFactory;
