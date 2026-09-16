//! BinXML "variant type" value decoding.
//!
//! Type codes verified against `python-evtx`'s `Nodes.py` node-type table and
//! cross-checked against `omerbenamram/evtx`'s `value_variant.rs` decode
//! logic (in particular: which types use their template-substitution
//! `size:u16` directly vs. read a self-describing length prefix when no size
//! is given, and the on-disk SID/GUID byte layouts).
//!
//! | Code | Type          | Code | Type          |
//! |------|---------------|------|---------------|
//! | 0x00 | Null          | 0x0B | Real32 (f32)  |
//! | 0x01 | WString       | 0x0C | Real64 (f64)  |
//! | 0x02 | String (ANSI) | 0x0D | Boolean       |
//! | 0x03 | Int8          | 0x0E | Binary        |
//! | 0x04 | UInt8         | 0x0F | Guid          |
//! | 0x05 | Int16         | 0x10 | Size (SizeT)  |
//! | 0x06 | UInt16        | 0x11 | FileTime      |
//! | 0x07 | Int32         | 0x12 | SysTime       |
//! | 0x08 | UInt32        | 0x13 | Sid           |
//! | 0x09 | Int64         | 0x14 | HexInt32      |
//! | 0x0A | UInt64        | 0x15 | HexInt64      |
//! |      |               | 0x21 | BinXml (nested fragment) |
//!
//! Array variants OR the type code with [`ARRAY_FLAG`] (`0x80`).

use forensic_rs::prelude::*;
use forensic_rs::utils::win::to_string_sid;
use forensic_rs::{ensure_buffer_size, ensure_format};

pub const VALUE_NULL: u8 = 0x00;
pub const VALUE_WSTRING: u8 = 0x01;
pub const VALUE_STRING: u8 = 0x02;
pub const VALUE_INT8: u8 = 0x03;
pub const VALUE_UINT8: u8 = 0x04;
pub const VALUE_INT16: u8 = 0x05;
pub const VALUE_UINT16: u8 = 0x06;
pub const VALUE_INT32: u8 = 0x07;
pub const VALUE_UINT32: u8 = 0x08;
pub const VALUE_INT64: u8 = 0x09;
pub const VALUE_UINT64: u8 = 0x0A;
pub const VALUE_REAL32: u8 = 0x0B;
pub const VALUE_REAL64: u8 = 0x0C;
pub const VALUE_BOOL: u8 = 0x0D;
pub const VALUE_BINARY: u8 = 0x0E;
pub const VALUE_GUID: u8 = 0x0F;
pub const VALUE_SIZE: u8 = 0x10;
pub const VALUE_FILETIME: u8 = 0x11;
pub const VALUE_SYSTIME: u8 = 0x12;
pub const VALUE_SID: u8 = 0x13;
pub const VALUE_HEX32: u8 = 0x14;
pub const VALUE_HEX64: u8 = 0x15;
pub const VALUE_BINXML: u8 = 0x21;
pub const ARRAY_FLAG: u8 = 0x80;

#[derive(Debug, Clone, Default)]
pub enum BinXmlValue {
    #[default]
    Null,
    Text(String),
    I64(i64),
    U64(u64),
    F64(f64),
    Bool(bool),
    Binary(Vec<u8>),
    Date(ForensicTimestamp),
    /// A nested BinXML fragment: its chunk-absolute `(start, end)` byte
    /// span, recursively decoded by the caller (`tokens::decode_node`) —
    /// stored as a span rather than owned bytes so the recursive decode
    /// stays in the same absolute coordinate space the containing decode
    /// used, which name/template "is this the definition" checks depend on.
    NestedBinXml(usize, usize),
    Array(Vec<BinXmlValue>),
}

impl BinXmlValue {
    /// Renders the value the way it would appear as XML attribute/text
    /// content (arrays are comma-joined, matching common EVTX viewer
    /// convention for manifest-typed array fields).
    pub fn to_display_string(&self) -> String {
        match self {
            BinXmlValue::Null => String::new(),
            BinXmlValue::Text(s) => s.clone(),
            BinXmlValue::I64(v) => v.to_string(),
            BinXmlValue::U64(v) => v.to_string(),
            BinXmlValue::F64(v) => v.to_string(),
            BinXmlValue::Bool(v) => v.to_string(),
            BinXmlValue::Binary(b) => hex_encode(b),
            BinXmlValue::Date(t) => t.to_string(),
            BinXmlValue::NestedBinXml(..) => String::new(),
            BinXmlValue::Array(items) => items
                .iter()
                .map(BinXmlValue::to_display_string)
                .collect::<Vec<_>>()
                .join(","),
        }
    }

    /// Converts to the framework's [`Field`] for direct insertion into an
    /// [`EventRecord`]'s `data` map.
    pub fn to_field(&self) -> Field {
        match self {
            BinXmlValue::Null => Field::Null,
            BinXmlValue::Text(s) => Field::from(s.clone()),
            BinXmlValue::I64(v) => Field::I64(*v),
            BinXmlValue::U64(v) => Field::U64(*v),
            BinXmlValue::F64(v) => Field::F64(*v),
            BinXmlValue::Bool(v) => Field::from(*v),
            BinXmlValue::Binary(b) => Field::from(hex_encode(b)),
            BinXmlValue::Date(t) => Field::Date(*t),
            BinXmlValue::NestedBinXml(..) => Field::Null,
            BinXmlValue::Array(items) => {
                Field::Array(items.iter().map(|v| text_owned(v.to_display_string())).collect())
            }
        }
    }
}

pub fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(2 + bytes.len() * 2);
    out.push_str("0x");
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

fn format_guid(bytes: &[u8; 16]) -> String {
    let data1 = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let data2 = u16::from_le_bytes([bytes[4], bytes[5]]);
    let data3 = u16::from_le_bytes([bytes[6], bytes[7]]);
    format!(
        "{{{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}}}",
        data1,
        data2,
        data3,
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15]
    )
}

/// The number of bytes a `SidType` value occupies, computed from its
/// sub-authority count byte at relative offset 1 (revision(1) +
/// sub_authority_count(1) + authority(6) + sub_authority_count * 4).
fn sid_byte_length(bytes: &[u8]) -> ForensicResult<usize> {
    ensure_buffer_size!(bytes, 0usize, 2, "sid");
    let sub_authority_count = bytes[1] as usize;
    Ok(8 + sub_authority_count * 4)
}

fn read_systime(reader: &mut ByteReader) -> ForensicResult<ForensicTimestamp> {
    let year = reader.read_u16_le()?;
    let month = reader.read_u16_le()?;
    let _day_of_week = reader.read_u16_le()?;
    let day = reader.read_u16_le()?;
    let hour = reader.read_u16_le()?;
    let minute = reader.read_u16_le()?;
    let second = reader.read_u16_le()?;
    let milliseconds = reader.read_u16_le()?;
    ForensicTimestamp::with_ymd_and_hms(
        year,
        month as u8,
        day as u8,
        hour as u8,
        minute as u8,
        second as u8,
        milliseconds as u32 * 1000,
    )
}

/// Reads one value of `value_type` (its `ARRAY_FLAG` bit stripped by the
/// caller — see [`read_value`]) from `reader`.
///
/// `explicit_size` is `Some(byte_len)` for a template substitution (the
/// substitution descriptor states the value's exact byte length up front,
/// so variable-length types are read as exactly that many bytes with no
/// internal length prefix) and `None` for a standalone `Value` token (where
/// variable-length types instead carry their own length prefix).
fn read_scalar(reader: &mut ByteReader, value_type: u8, explicit_size: Option<usize>) -> ForensicResult<BinXmlValue> {
    Ok(match value_type {
        VALUE_NULL => {
            // A null-typed template substitution still reserves its full
            // declared byte span in the values blob (as padding) rather
            // than contributing zero bytes — confirmed against real EVTX
            // data, where skipping this padding misaligned every
            // substitution after it for the rest of the record.
            if let Some(byte_len) = explicit_size {
                reader.read_bytes(byte_len)?;
            }
            BinXmlValue::Null
        }
        VALUE_WSTRING => {
            let text = match explicit_size {
                Some(byte_len) => {
                    if byte_len == 0 {
                        String::new()
                    } else {
                        ensure_format!(byte_len % 2 == 0, "binxml_value", "odd byte length for a wstring value");
                        reader.read_utf16le_string(byte_len)?
                    }
                }
                None => {
                    let char_count = reader.read_u16_le()? as usize;
                    reader.read_utf16le_string(char_count * 2)?
                }
            };
            BinXmlValue::Text(text)
        }
        VALUE_STRING => {
            let bytes = match explicit_size {
                Some(byte_len) => reader.read_bytes(byte_len)?,
                None => {
                    let len = reader.read_u16_le()? as usize;
                    reader.read_bytes(len)?
                }
            };
            BinXmlValue::Text(String::from_utf8_lossy(bytes).into_owned())
        }
        VALUE_INT8 => BinXmlValue::I64(reader.read_i8()? as i64),
        VALUE_UINT8 => BinXmlValue::U64(reader.read_u8()? as u64),
        VALUE_INT16 => BinXmlValue::I64(reader.read_i16_le()? as i64),
        VALUE_UINT16 => BinXmlValue::U64(reader.read_u16_le()? as u64),
        VALUE_INT32 => BinXmlValue::I64(reader.read_i32_le()? as i64),
        VALUE_UINT32 => BinXmlValue::U64(reader.read_u32_le()? as u64),
        VALUE_INT64 => BinXmlValue::I64(reader.read_i64_le()?),
        VALUE_UINT64 => BinXmlValue::U64(reader.read_u64_le()?),
        VALUE_REAL32 => BinXmlValue::F64(reader.read_f32_le()? as f64),
        VALUE_REAL64 => BinXmlValue::F64(reader.read_f64_le()?),
        VALUE_BOOL => BinXmlValue::Bool(reader.read_u32_le()? != 0),
        VALUE_BINARY => {
            let bytes = match explicit_size {
                Some(byte_len) => reader.read_bytes(byte_len)?,
                None => {
                    let len = reader.read_u32_le()? as usize;
                    reader.read_bytes(len)?
                }
            };
            BinXmlValue::Binary(bytes.to_vec())
        }
        VALUE_GUID => {
            let bytes: [u8; 16] = reader.read_fixed()?;
            BinXmlValue::Text(format_guid(&bytes))
        }
        VALUE_SIZE => match explicit_size {
            Some(4) => BinXmlValue::U64(reader.read_u32_le()? as u64),
            _ => BinXmlValue::U64(reader.read_u64_le()?),
        },
        VALUE_FILETIME => BinXmlValue::Date(ForensicTimestamp::from_win_filetime(reader.read_u64_le()?)),
        VALUE_SYSTIME => BinXmlValue::Date(read_systime(reader)?),
        VALUE_SID => {
            let byte_len = match explicit_size {
                Some(byte_len) => byte_len,
                None => sid_byte_length(reader.remaining_slice())?,
            };
            let bytes = reader.read_bytes(byte_len)?;
            match to_string_sid(bytes) {
                Ok(sid) => BinXmlValue::Text(sid),
                Err(_) => BinXmlValue::Binary(bytes.to_vec()),
            }
        }
        VALUE_HEX32 => BinXmlValue::Text(format!("0x{:08x}", reader.read_u32_le()?)),
        VALUE_HEX64 => BinXmlValue::Text(format!("0x{:016x}", reader.read_u64_le()?)),
        VALUE_BINXML => {
            let byte_len = match explicit_size {
                Some(byte_len) => byte_len,
                None => reader.read_u16_le()? as usize,
            };
            // Record the chunk-absolute span rather than copying bytes out
            // — see the `NestedBinXml` doc comment for why this matters.
            let start = reader.position();
            reader.skip(byte_len)?;
            BinXmlValue::NestedBinXml(start, start + byte_len)
        }
        other => {
            return Err(ForensicError::invalid_format(
                "binxml_value",
                format!("unsupported BinXML value type 0x{other:02x}"),
            ))
        }
    })
}

/// Reads one BinXML value, honoring the array flag (`0x80`).
///
/// For an array, `explicit_size` (always present for arrays, which only
/// occur as template substitutions) bounds the whole array's bytes: numeric
/// element types are read as a fixed-width repeat until the byte budget is
/// exhausted, and `WString`/`String` arrays are NUL-terminated entries packed
/// back-to-back filling the same budget.
pub fn read_value(reader: &mut ByteReader, raw_type: u8, explicit_size: Option<usize>) -> ForensicResult<BinXmlValue> {
    let is_array = raw_type & ARRAY_FLAG != 0;
    let value_type = raw_type & !ARRAY_FLAG;
    if !is_array {
        return read_scalar(reader, value_type, explicit_size);
    }

    let byte_len = explicit_size.ok_or_else(|| {
        ForensicError::invalid_format("binxml_value", "array value without an explicit byte size")
    })?;
    let end = reader.position() + byte_len;
    let mut items = Vec::new();
    match value_type {
        VALUE_WSTRING | VALUE_STRING => {
            while reader.position() < end {
                let s = if value_type == VALUE_WSTRING {
                    reader.read_utf16le_cstring()?
                } else {
                    reader.read_cstring()?
                };
                items.push(BinXmlValue::Text(s));
            }
        }
        _ => {
            while reader.position() < end {
                items.push(read_scalar(reader, value_type, None)?);
            }
        }
    }
    // Element-level reads (fixed-width numerics via `read_scalar(.., None)`)
    // are self-contained, so the loop naturally lands exactly on `end` for
    // well-formed input; a mismatch surfaces as a bounds error on the next
    // read rather than silently misaligning the caller's cursor.
    Ok(BinXmlValue::Array(items))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_wstring_with_explicit_size() {
        let bytes: Vec<u8> = "hi".encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        let mut r = ByteReader::new(&bytes);
        let v = read_value(&mut r, VALUE_WSTRING, Some(4)).unwrap();
        assert_eq!(v.to_display_string(), "hi");
    }

    #[test]
    fn reads_wstring_with_length_prefix() {
        let mut bytes = vec![2u8, 0]; // char count = 2
        bytes.extend("hi".encode_utf16().flat_map(|u| u.to_le_bytes()));
        let mut r = ByteReader::new(&bytes);
        let v = read_value(&mut r, VALUE_WSTRING, None).unwrap();
        assert_eq!(v.to_display_string(), "hi");
    }

    #[test]
    fn reads_uint32() {
        let bytes = 0xDEAD_BEEFu32.to_le_bytes();
        let mut r = ByteReader::new(&bytes);
        let v = read_value(&mut r, VALUE_UINT32, Some(4)).unwrap();
        assert_eq!(v.to_display_string(), "3735928559");
    }

    #[test]
    fn reads_guid() {
        let bytes: [u8; 16] = [
            0x33, 0x22, 0x11, 0x00, 0x55, 0x44, 0x77, 0x66, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        ];
        let mut r = ByteReader::new(&bytes);
        let v = read_value(&mut r, VALUE_GUID, Some(16)).unwrap();
        assert_eq!(v.to_display_string(), "{00112233-4455-6677-8899-aabbccddeeff}");
    }

    #[test]
    fn reads_filetime() {
        let bytes = 133_514_430_235_959_706u64.to_le_bytes();
        let mut r = ByteReader::new(&bytes);
        let v = read_value(&mut r, VALUE_FILETIME, Some(8)).unwrap();
        assert!(matches!(v, BinXmlValue::Date(_)));
    }

    #[test]
    fn null_with_explicit_size_consumes_its_declared_padding() {
        // A null-typed template substitution still reserves its declared
        // byte span in the values blob — skipping it (consuming 0 bytes
        // regardless of declared_size) would misalign every substitution
        // that follows it in the same record.
        let mut bytes = vec![0xAAu8; 16];
        bytes.extend(0xDEAD_BEEFu32.to_le_bytes()); // the next substitution's data
        let mut r = ByteReader::new(&bytes);
        let v = read_value(&mut r, VALUE_NULL, Some(16)).unwrap();
        assert!(matches!(v, BinXmlValue::Null));
        assert_eq!(r.position(), 16);
        let next = read_value(&mut r, VALUE_UINT32, Some(4)).unwrap();
        assert_eq!(next.to_display_string(), "3735928559");
    }

    #[test]
    fn null_without_explicit_size_consumes_nothing() {
        // A standalone Value token (no template substitution context) has
        // no declared size to honor for a null value.
        let bytes = [0xAAu8; 4];
        let mut r = ByteReader::new(&bytes);
        let v = read_value(&mut r, VALUE_NULL, None).unwrap();
        assert!(matches!(v, BinXmlValue::Null));
        assert_eq!(r.position(), 0);
    }

    #[test]
    fn reads_uint32_array() {
        let mut bytes = Vec::new();
        bytes.extend(1u32.to_le_bytes());
        bytes.extend(2u32.to_le_bytes());
        bytes.extend(3u32.to_le_bytes());
        let mut r = ByteReader::new(&bytes);
        let v = read_value(&mut r, VALUE_UINT32 | ARRAY_FLAG, Some(12)).unwrap();
        assert_eq!(v.to_display_string(), "1,2,3");
    }

    #[test]
    fn reads_wstring_array() {
        let mut bytes = Vec::new();
        for s in ["ab", "cd"] {
            bytes.extend(s.encode_utf16().flat_map(|u| u.to_le_bytes()));
            bytes.extend(0u16.to_le_bytes());
        }
        let len = bytes.len();
        let mut r = ByteReader::new(&bytes);
        let v = read_value(&mut r, VALUE_WSTRING | ARRAY_FLAG, Some(len)).unwrap();
        assert_eq!(v.to_display_string(), "ab,cd");
    }

    #[test]
    fn rejects_unsupported_type() {
        let bytes = [0u8; 8];
        let mut r = ByteReader::new(&bytes);
        assert!(read_value(&mut r, 0x7E, Some(1)).is_err());
    }
}
