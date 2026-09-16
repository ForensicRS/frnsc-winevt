//! BinXML decoding: per-chunk shared state ([`ChunkContext`]), variant-type
//! value decoding ([`values`]), and the token stream walker ([`tokens`]).

pub mod tokens;
pub mod values;

pub use tokens::{decode_record_fragment, ChunkContext};
pub use values::BinXmlValue;
