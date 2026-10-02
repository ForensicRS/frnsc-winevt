//! BinXML decoding: per-chunk shared state ([`ChunkContext`]), variant-type
//! value decoding ([`values`]), and the token stream walker ([`tokens`]).

pub mod tokens;
pub mod values;

pub use tokens::{ChunkContext, decode_record_fragment};
pub use values::BinXmlValue;
