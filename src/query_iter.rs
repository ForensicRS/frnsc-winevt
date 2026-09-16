//! Shared [`EventLogIterator`] over an in-memory, already-parsed record set.
//!
//! Both the `.evt` and `.evtx` readers parse eagerly into a `Vec<EventRecord>`
//! at mount time (see `evt::reader`/`evtx::reader`), so querying is just a
//! filtered walk over that vector — implemented once here instead of twice.

use forensic_rs::prelude::*;

pub(crate) struct RecordIter<'a> {
    records: &'a [EventRecord],
    query: EventLogQuery,
    pos: usize,
}

impl<'a> RecordIter<'a> {
    pub(crate) fn new(records: &'a [EventRecord], query: EventLogQuery) -> Self {
        Self {
            records,
            query,
            pos: 0,
        }
    }
}

impl<'a> EventLogIterator for RecordIter<'a> {
    fn next(&mut self) -> ForensicResult<Option<EventRecord>> {
        while self.pos < self.records.len() {
            let record = &self.records[self.pos];
            self.pos += 1;
            if self.query.matches(record) {
                return Ok(Some(record.clone()));
            }
        }
        Ok(None)
    }
}
