//! Synthetic `.evtx` bytes, for tests and pipeline readiness checks that need a well-formed log
//! without the gitignored real evidence. Hidden from docs and not part of the stable API.
//!
//! Wraps this crate's own test fixture builder rather than duplicating it, so downstream crates
//! (`frnsc-pipeline`'s readiness benchmark) exercise the exact same bytes this crate's own tests
//! do.

use crate::evtx::testdata::build_evtx_file;

/// A complete, checksum-valid one-chunk, one-record `.evtx` file whose single record is on
/// `channel` (e.g. `"Security"`, `"System"`).
pub fn evtx_file(channel: &str) -> Vec<u8> {
    build_evtx_file(channel)
}
