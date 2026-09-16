//! The BinXML token stream walker: name-table resolution, template-instance
//! expansion, and the recursive-descent decoder that turns a token stream
//! into an [`XmlElement`] tree.
//!
//! Token type codes verified against `python-evtx`'s `Nodes.py` node-type
//! table. A token byte's low nibble is its type; bit `0x40` on
//! [`TOK_OPEN_START_ELEMENT`] means "this element has an attribute list"
//! (`has_attributes`, confirmed against `omerbenamram/evtx`'s
//! `read_open_start_element_cursor`, where it and `has_dependency_identifier`
//! are ambient parameters the caller derives, not bits read from data). The
//! "dependency identifier" field is present only while decoding a *template
//! definition's* body (`in_template = true`) — it's how a template marks an
//! element as gated by a [`TOK_CONDITIONAL_SUBSTITUTION`], but fully
//! resolving that gating (omitting the whole subtree when the referenced
//! substitution is null, rather than just the one substituted value) is not
//! implemented; the field is read (to keep the cursor aligned) and ignored.
//! This is a known, documented simplification — see the crate README.

use std::cell::RefCell;
use std::collections::BTreeMap;

use forensic_rs::ensure_format;
use forensic_rs::prelude::*;

use super::values::{self, BinXmlValue};
use crate::evtx::xml::{XmlElement, XmlNode};

pub const TOK_EOF: u8 = 0x00;
pub const TOK_OPEN_START_ELEMENT: u8 = 0x01;
pub const TOK_CLOSE_START_ELEMENT: u8 = 0x02;
pub const TOK_CLOSE_EMPTY_ELEMENT: u8 = 0x03;
pub const TOK_END_ELEMENT: u8 = 0x04;
pub const TOK_VALUE: u8 = 0x05;
pub const TOK_ATTRIBUTE: u8 = 0x06;
pub const TOK_CDATA: u8 = 0x07;
pub const TOK_CHAR_REF: u8 = 0x08;
pub const TOK_ENTITY_REF: u8 = 0x09;
pub const TOK_PI_TARGET: u8 = 0x0A;
pub const TOK_PI_DATA: u8 = 0x0B;
pub const TOK_TEMPLATE_INSTANCE: u8 = 0x0C;
pub const TOK_NORMAL_SUBSTITUTION: u8 = 0x0D;
pub const TOK_CONDITIONAL_SUBSTITUTION: u8 = 0x0E;
pub const TOK_FRAGMENT_HEADER: u8 = 0x0F;

const HAS_ATTRIBUTES_FLAG: u8 = 0x40;
const TOKEN_TYPE_MASK: u8 = 0x0F;

/// Per-chunk decode state shared across every record in the chunk: the raw
/// chunk bytes (name/template offsets are chunk-absolute) plus caches so a
/// name or template definition that's physically written once (by the first
/// record that uses it) is parsed once, not on every reference.
pub struct ChunkContext<'a> {
    pub chunk: &'a [u8],
    names: RefCell<BTreeMap<u32, String>>,
    /// offset -> (body start offset, body byte length), the template's
    /// BinXML fragment location. Bodies are re-decoded per use (against that
    /// use's own substitution values) rather than cached as a parsed tree —
    /// templates are small, and this avoids a separate placeholder-tree IR.
    templates: RefCell<BTreeMap<u32, (usize, usize)>>,
}

impl<'a> ChunkContext<'a> {
    pub fn new(chunk: &'a [u8]) -> Self {
        Self {
            chunk,
            names: RefCell::new(BTreeMap::new()),
            templates: RefCell::new(BTreeMap::new()),
        }
    }
}

/// Decodes one record's top-level BinXML fragment (`chunk[start..end]`,
/// absolute chunk offsets) into its XML nodes (normally exactly one root
/// `Event` element).
pub fn decode_record_fragment(ctx: &ChunkContext, start: usize, end: usize) -> ForensicResult<Vec<XmlNode>> {
    let mut reader = ByteReader::new(ctx.chunk);
    reader.seek_to(start)?;
    decode_fragment(ctx, &mut reader, end, None, false)
}

/// Decodes a sequence of top-level BinXML nodes up to `end`: a leading
/// [`TOK_FRAGMENT_HEADER`] is consumed if present, and decoding stops at
/// [`TOK_EOF`] or `end`, whichever comes first.
fn decode_fragment(
    ctx: &ChunkContext,
    reader: &mut ByteReader,
    end: usize,
    substitutions: Option<&[BinXmlValue]>,
    in_template: bool,
) -> ForensicResult<Vec<XmlNode>> {
    let mut nodes = Vec::new();
    while reader.position() < end {
        let token = reader.read_u8()?;
        match token & TOKEN_TYPE_MASK {
            TOK_FRAGMENT_HEADER => {
                let _major_version = reader.read_u8()?;
                let _minor_version = reader.read_u8()?;
                let _flags = reader.read_u8()?;
            }
            TOK_EOF => break,
            _ => nodes.extend(decode_node(ctx, reader, token, substitutions, in_template)?),
        }
    }
    Ok(nodes)
}

/// Decodes one non-header, non-EOF token into zero or more XML nodes: zero
/// for a token that carries no output of its own (a processing instruction)
/// or a conditional substitution resolving to null, one for almost
/// everything else, or more than one when a nested [`TOK_TEMPLATE_INSTANCE`]
/// or a nested BinXml value ([`BinXmlValue::NestedBinXml`] — this is how
/// `EventData`'s actual content arrives) expands to multiple sibling nodes.
fn decode_node(
    ctx: &ChunkContext,
    reader: &mut ByteReader,
    token: u8,
    substitutions: Option<&[BinXmlValue]>,
    in_template: bool,
) -> ForensicResult<Vec<XmlNode>> {
    Ok(match token & TOKEN_TYPE_MASK {
        TOK_OPEN_START_ELEMENT => vec![XmlNode::Element(decode_element(
            ctx,
            reader,
            token,
            substitutions,
            in_template,
        )?)],
        TOK_VALUE | TOK_NORMAL_SUBSTITUTION | TOK_CONDITIONAL_SUBSTITUTION => {
            match decode_value_bearing_token(reader, token, substitutions)? {
                // A nested BinXml value is itself a fragment sharing this
                // chunk's name/template tables — decode it recursively,
                // staying in `ctx.chunk`'s coordinate space (not an
                // isolated copy) so "is this the definition" position
                // checks inside it keep working. Its own top-level elements
                // are always non-template (`in_template = false`): this is
                // dynamic per-record value data, not template-definition
                // bytes, regardless of whether the substitution token that
                // referenced it happened to live inside a template body. If
                // it in turn contains its own `TOK_TEMPLATE_INSTANCE`, that
                // template's body still gets `in_template = true` — decided
                // independently by `read_template_instance`.
                Some(BinXmlValue::NestedBinXml(start, end)) => {
                    let mut nested = ByteReader::new(ctx.chunk);
                    nested.seek_to(start)?;
                    decode_fragment(ctx, &mut nested, end, substitutions, false)?
                }
                Some(value) => vec![XmlNode::Text(value.to_display_string())],
                None => vec![],
            }
        }
        TOK_CDATA => {
            let char_count = reader.read_u16_le()? as usize;
            vec![XmlNode::Text(reader.read_utf16le_string(char_count * 2)?)]
        }
        TOK_ENTITY_REF => {
            let name = resolve_name(ctx, reader)?;
            vec![XmlNode::Text(format!("&{name};"))]
        }
        TOK_CHAR_REF => {
            let code = reader.read_u16_le()?;
            char::from_u32(code as u32)
                .map(|c| vec![XmlNode::Text(c.to_string())])
                .unwrap_or_default()
        }
        TOK_PI_TARGET => {
            let _name = resolve_name(ctx, reader)?;
            vec![]
        }
        TOK_PI_DATA => {
            let char_count = reader.read_u16_le()? as usize;
            reader.read_utf16le_string(char_count * 2)?;
            vec![]
        }
        TOK_TEMPLATE_INSTANCE => read_template_instance(ctx, reader)?,
        other => {
            return Err(ForensicError::invalid_format(
                "binxml_token",
                format!("unexpected BinXML token 0x{other:02x}"),
            ))
        }
    })
}

/// Decodes an [`TOK_OPEN_START_ELEMENT`] token's body: an optional
/// (template-only) dependency identifier, a data-size hint (ignored — it
/// exists to let a writer skip an element without full parsing, which this
/// decoder never needs to do), the element's name, its attribute list if
/// `HAS_ATTRIBUTES_FLAG` is set, and its children up to the matching
/// [`TOK_END_ELEMENT`] (or none, for [`TOK_CLOSE_EMPTY_ELEMENT`]).
fn decode_element(
    ctx: &ChunkContext,
    reader: &mut ByteReader,
    token: u8,
    substitutions: Option<&[BinXmlValue]>,
    in_template: bool,
) -> ForensicResult<XmlElement> {
    let has_attributes = token & HAS_ATTRIBUTES_FLAG != 0;
    if in_template {
        let _dependency_identifier = reader.read_u16_le()?;
    }
    let _data_size = reader.read_u32_le()?;
    let name = resolve_name(ctx, reader)?;

    let mut attributes = Vec::new();
    if has_attributes {
        let attribute_list_data_size = reader.read_u32_le()?;
        let attribute_list_end = reader.position() + attribute_list_data_size as usize;
        while reader.position() < attribute_list_end {
            let attr_token = reader.read_u8()?;
            ensure_format!(
                attr_token & TOKEN_TYPE_MASK == TOK_ATTRIBUTE,
                "binxml_token",
                "expected an Attribute token inside an element's attribute list"
            );
            let attr_name = resolve_name(ctx, reader)?;
            let value_token = reader.read_u8()?;
            if let Some(value) = decode_value_bearing_token(reader, value_token, substitutions)? {
                attributes.push((attr_name, value.to_display_string()));
            }
        }
    }

    let close_token = reader.read_u8()?;
    let mut children = Vec::new();
    match close_token & TOKEN_TYPE_MASK {
        TOK_CLOSE_START_ELEMENT => loop {
            let child_token = reader.read_u8()?;
            if child_token & TOKEN_TYPE_MASK == TOK_END_ELEMENT {
                break;
            }
            children.extend(decode_node(ctx, reader, child_token, substitutions, in_template)?);
        },
        TOK_CLOSE_EMPTY_ELEMENT => {}
        other => {
            return Err(ForensicError::invalid_format(
                "binxml_token",
                format!("expected CloseStartElement or CloseEmptyElement, found 0x{other:02x}"),
            ))
        }
    }

    Ok(XmlElement {
        name,
        attributes,
        children,
    })
}

/// Decodes a [`TOK_VALUE`], [`TOK_NORMAL_SUBSTITUTION`], or
/// [`TOK_CONDITIONAL_SUBSTITUTION`] token's body into its value. Returns
/// `None` only for a conditional substitution whose resolved value is null —
/// the framework's signal to omit this attribute/text node entirely rather
/// than render it as an empty string.
fn decode_value_bearing_token(
    reader: &mut ByteReader,
    token: u8,
    substitutions: Option<&[BinXmlValue]>,
) -> ForensicResult<Option<BinXmlValue>> {
    match token & TOKEN_TYPE_MASK {
        TOK_VALUE => {
            let value_type = reader.read_u8()?;
            Ok(Some(values::read_value(reader, value_type, None)?))
        }
        TOK_NORMAL_SUBSTITUTION | TOK_CONDITIONAL_SUBSTITUTION => {
            let substitution_id = reader.read_u16_le()?;
            let _declared_value_type = reader.read_u8()?;
            let is_conditional = token & TOKEN_TYPE_MASK == TOK_CONDITIONAL_SUBSTITUTION;
            let subs = substitutions.ok_or_else(|| {
                ForensicError::invalid_format("binxml_token", "substitution token outside of a template")
            })?;
            let value = subs
                .get(substitution_id as usize)
                .cloned()
                .unwrap_or(BinXmlValue::Null);
            if is_conditional && matches!(value, BinXmlValue::Null) {
                Ok(None)
            } else {
                Ok(Some(value))
            }
        }
        other => Err(ForensicError::invalid_format(
            "binxml_token",
            format!("expected a value-bearing token, found 0x{other:02x}"),
        )),
    }
}

/// Resolves a `NameRef`: a 4-byte chunk-absolute offset, immediately
/// followed by the name's inline definition (`next_string: u32`,
/// `hash: u16`, `char_count: u16`, UTF-16LE chars, NUL terminator) *only*
/// the first time that offset is written — i.e. only when the reader's
/// current position equals the offset just read. Every later occurrence
/// (from this record or a later one in the same chunk) is a bare 4-byte
/// reference to that already-written entry, resolved from the cache or, for
/// a forward reference, by parsing directly at that chunk offset.
fn resolve_name(ctx: &ChunkContext, reader: &mut ByteReader) -> ForensicResult<String> {
    let name_offset = reader.read_u32_le()?;
    if reader.position() == name_offset as usize {
        let entry_offset = reader.position() as u32;
        let _next_string = reader.read_u32_le()?;
        let _hash = reader.read_u16_le()?;
        let char_count = reader.read_u16_le()? as usize;
        let name = reader.read_utf16le_string(char_count * 2)?;
        let _terminator = reader.read_u16_le()?;
        ctx.names.borrow_mut().insert(entry_offset, name.clone());
        Ok(name)
    } else if let Some(name) = ctx.names.borrow().get(&name_offset) {
        Ok(name.clone())
    } else {
        let mut side = ByteReader::new(ctx.chunk);
        side.seek_to(name_offset as usize)?;
        let _next_string = side.read_u32_le()?;
        let _hash = side.read_u16_le()?;
        let char_count = side.read_u16_le()? as usize;
        let name = side.read_utf16le_string(char_count * 2)?;
        ctx.names.borrow_mut().insert(name_offset, name.clone());
        Ok(name)
    }
}

/// Decodes a [`TOK_TEMPLATE_INSTANCE`] token's body: a version/unknown byte
/// (present on real EVTX data between the token and `template_id` — absent
/// from every published field-offset table I could find, so verified
/// directly by tracing a real file's bytes rather than a spec), then
/// `template_id` (unused — it identifies the template for the writer's own
/// cache, not needed for reading), `template_definition_data_offset`, then
/// (only the first time that offset is reached — same definition/reference
/// convention as [`resolve_name`]) the template definition header
/// (`next_template_offset: u32`, `guid: [u8; 16]`, `data_size: u32`) and its
/// BinXML body, then this instance's own substitution count, descriptor
/// array (`size: u16, value_type: u8, unknown: u8` each), and values.
///
/// The template body is re-decoded fresh against these substitution values
/// (rather than cached as a parsed tree) — only its byte range is cached.
fn read_template_instance(ctx: &ChunkContext, reader: &mut ByteReader) -> ForensicResult<Vec<XmlNode>> {
    let _unknown = reader.read_u8()?;
    let _template_id = reader.read_u32_le()?;
    let definition_offset = reader.read_u32_le()?;

    let (body_start, body_len) = if reader.position() == definition_offset as usize {
        let _next_template_offset = reader.read_u32_le()?;
        let _guid: [u8; 16] = reader.read_fixed()?;
        let data_size = reader.read_u32_le()?;
        let body_start = reader.position();
        reader.skip(data_size as usize)?;
        ctx.templates
            .borrow_mut()
            .insert(definition_offset, (body_start, data_size as usize));
        (body_start, data_size as usize)
    } else if let Some(&cached) = ctx.templates.borrow().get(&definition_offset) {
        cached
    } else {
        let mut side = ByteReader::new(ctx.chunk);
        side.seek_to(definition_offset as usize)?;
        let _next_template_offset = side.read_u32_le()?;
        let _guid: [u8; 16] = side.read_fixed()?;
        let data_size = side.read_u32_le()?;
        let body_start = side.position();
        ctx.templates
            .borrow_mut()
            .insert(definition_offset, (body_start, data_size as usize));
        (body_start, data_size as usize)
    };

    let num_substitutions = reader.read_u32_le()?;
    struct Descriptor {
        size: u16,
        value_type: u8,
    }
    let mut descriptors = Vec::with_capacity(num_substitutions as usize);
    for _ in 0..num_substitutions {
        let size = reader.read_u16_le()?;
        let value_type = reader.read_u8()?;
        let _unknown = reader.read_u8()?;
        descriptors.push(Descriptor { size, value_type });
    }
    let mut substitution_values = Vec::with_capacity(descriptors.len());
    for descriptor in &descriptors {
        substitution_values.push(values::read_value(
            reader,
            descriptor.value_type,
            Some(descriptor.size as usize),
        )?);
    }

    let mut body_reader = ByteReader::new(ctx.chunk);
    body_reader.seek_to(body_start)?;
    decode_fragment(
        ctx,
        &mut body_reader,
        body_start + body_len,
        Some(&substitution_values),
        true,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utf16le(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect()
    }

    /// Writes an inline name definition at the current position and returns
    /// its (chunk-absolute) offset. Layout: next_string(u32)=0, hash(u16)=0,
    /// char_count(u16), chars, NUL terminator.
    fn push_name_def(buf: &mut Vec<u8>, name: &str) -> u32 {
        let offset = buf.len() as u32;
        buf.extend_from_slice(&0u32.to_le_bytes()); // next_string
        buf.extend_from_slice(&0u16.to_le_bytes()); // hash
        buf.extend_from_slice(&(name.encode_utf16().count() as u16).to_le_bytes());
        buf.extend_from_slice(&utf16le(name));
        buf.extend_from_slice(&0u16.to_le_bytes()); // terminator
        offset
    }

    /// Builds a minimal non-templated fragment:
    /// `<Event><System>hello</System></Event>`
    #[test]
    fn decodes_simple_non_templated_fragment() {
        let mut chunk = Vec::new();
        // Fragment header.
        chunk.push(TOK_FRAGMENT_HEADER);
        chunk.extend_from_slice(&[1, 1, 0]);

        // <Event ...> open start element, no attributes.
        chunk.push(TOK_OPEN_START_ELEMENT);
        chunk.extend_from_slice(&0u32.to_le_bytes()); // data_size, unused
        let event_name_offset = 0; // filled in after we know the position
        let _ = event_name_offset;
        let name_pos_placeholder = chunk.len();
        chunk.extend_from_slice(&0u32.to_le_bytes()); // name ref placeholder
        let event_name_offset = push_name_def(&mut chunk, "Event");
        chunk[name_pos_placeholder..name_pos_placeholder + 4]
            .copy_from_slice(&event_name_offset.to_le_bytes());

        chunk.push(TOK_CLOSE_START_ELEMENT);

        // <System> child element containing text "hello".
        chunk.push(TOK_OPEN_START_ELEMENT);
        chunk.extend_from_slice(&0u32.to_le_bytes());
        let name_pos_placeholder = chunk.len();
        chunk.extend_from_slice(&0u32.to_le_bytes());
        let system_name_offset = push_name_def(&mut chunk, "System");
        chunk[name_pos_placeholder..name_pos_placeholder + 4]
            .copy_from_slice(&system_name_offset.to_le_bytes());
        chunk.push(TOK_CLOSE_START_ELEMENT);

        // Text value "hello" (standalone Value token, length-prefixed wstring).
        chunk.push(TOK_VALUE);
        chunk.push(values::VALUE_WSTRING);
        chunk.extend_from_slice(&("hello".encode_utf16().count() as u16).to_le_bytes());
        chunk.extend_from_slice(&utf16le("hello"));

        chunk.push(TOK_END_ELEMENT); // closes <System>
        chunk.push(TOK_END_ELEMENT); // closes <Event>
        chunk.push(TOK_EOF);

        let end = chunk.len();
        let ctx = ChunkContext::new(&chunk);
        let nodes = decode_record_fragment(&ctx, 0, end).unwrap();
        assert_eq!(nodes.len(), 1);
        let XmlNode::Element(event) = &nodes[0] else {
            panic!("expected root element")
        };
        assert_eq!(event.name, "Event");
        let system = event.child("System").unwrap();
        assert_eq!(system.text(), "hello");
    }

    /// Builds a record that references a template already cached from a
    /// prior "record" in the same chunk, exercising the reference (as
    /// opposed to definition) path of both name and template resolution.
    #[test]
    fn decodes_templated_record_with_substitution() {
        let mut chunk = Vec::new();

        // --- Template definition, referenced later ---
        // The definition's own header lives inline at the point a
        // TemplateInstance token first reaches it; we build it directly here
        // to isolate template-body decoding from TemplateInstance framing.
        let template_body_start_marker = chunk.len() as u32 + 4 + 16 + 4; // after header fields
        let definition_offset = chunk.len() as u32;
        chunk.extend_from_slice(&0u32.to_le_bytes()); // next_template_offset
        chunk.extend_from_slice(&[0u8; 16]); // guid
        let data_size_pos = chunk.len();
        chunk.extend_from_slice(&0u32.to_le_bytes()); // data_size placeholder

        assert_eq!(chunk.len() as u32, template_body_start_marker);

        // Template body: <Event><Data>SUBST</Data></Event>, where SUBST is a
        // NormalSubstitution referencing index 0.
        chunk.push(TOK_FRAGMENT_HEADER);
        chunk.extend_from_slice(&[1, 1, 0]);
        chunk.push(TOK_OPEN_START_ELEMENT);
        chunk.extend_from_slice(&0u16.to_le_bytes()); // dependency identifier (in_template)
        chunk.extend_from_slice(&0u32.to_le_bytes()); // data_size
        let name_pos_placeholder = chunk.len();
        chunk.extend_from_slice(&0u32.to_le_bytes());
        let event_name_offset = push_name_def(&mut chunk, "Event");
        chunk[name_pos_placeholder..name_pos_placeholder + 4]
            .copy_from_slice(&event_name_offset.to_le_bytes());
        chunk.push(TOK_CLOSE_START_ELEMENT);

        chunk.push(TOK_OPEN_START_ELEMENT);
        chunk.extend_from_slice(&0u16.to_le_bytes());
        chunk.extend_from_slice(&0u32.to_le_bytes());
        let name_pos_placeholder = chunk.len();
        chunk.extend_from_slice(&0u32.to_le_bytes());
        let data_name_offset = push_name_def(&mut chunk, "Data");
        chunk[name_pos_placeholder..name_pos_placeholder + 4]
            .copy_from_slice(&data_name_offset.to_le_bytes());
        chunk.push(TOK_CLOSE_START_ELEMENT);

        chunk.push(TOK_NORMAL_SUBSTITUTION);
        chunk.extend_from_slice(&0u16.to_le_bytes()); // substitution id 0
        chunk.push(values::VALUE_WSTRING); // declared type, unused by the decoder

        chunk.push(TOK_END_ELEMENT); // closes <Data>
        chunk.push(TOK_END_ELEMENT); // closes <Event>
        chunk.push(TOK_EOF);

        let data_size = chunk.len() as u32 - template_body_start_marker;
        chunk[data_size_pos..data_size_pos + 4].copy_from_slice(&data_size.to_le_bytes());

        // --- Record fragment: FragmentHeader + TemplateInstance + EOF ---
        let record_start = chunk.len();
        chunk.push(TOK_FRAGMENT_HEADER);
        chunk.extend_from_slice(&[1, 1, 0]);
        chunk.push(TOK_TEMPLATE_INSTANCE);
        chunk.push(0x01); // unknown/version byte, present on real EVTX data
        chunk.extend_from_slice(&1u32.to_le_bytes()); // template_id, unused
        chunk.extend_from_slice(&definition_offset.to_le_bytes());
        // This is a *reference* (position != definition_offset), so no
        // inline header/body follows — straight to the substitution array.
        chunk.extend_from_slice(&1u32.to_le_bytes()); // num_substitutions
        let value_text = "hello-from-substitution";
        chunk.extend_from_slice(&((value_text.encode_utf16().count() * 2) as u16).to_le_bytes());
        chunk.push(values::VALUE_WSTRING);
        chunk.push(0); // unknown/reserved
        chunk.extend_from_slice(&utf16le(value_text));
        chunk.push(TOK_EOF);
        let record_end = chunk.len();

        let ctx = ChunkContext::new(&chunk);
        let nodes = decode_record_fragment(&ctx, record_start, record_end).unwrap();
        assert_eq!(nodes.len(), 1);
        let XmlNode::Element(event) = &nodes[0] else {
            panic!("expected root element")
        };
        assert_eq!(event.name, "Event");
        let data = event.child("Data").unwrap();
        assert_eq!(data.text(), value_text);
    }

    /// A `VALUE_BINXML` substitution (real EVTX's mechanism for `EventData`'s
    /// content) must be recursively decoded and its nodes spliced in, not
    /// dropped.
    #[test]
    fn decodes_nested_binxml_substitution() {
        let mut chunk = Vec::new();

        let template_body_start_marker = chunk.len() as u32 + 4 + 16 + 4;
        let definition_offset = chunk.len() as u32;
        chunk.extend_from_slice(&0u32.to_le_bytes());
        chunk.extend_from_slice(&[0u8; 16]);
        let data_size_pos = chunk.len();
        chunk.extend_from_slice(&0u32.to_le_bytes());
        assert_eq!(chunk.len() as u32, template_body_start_marker);

        // Template body: <Event><EventData>SUBST</EventData></Event>, where
        // SUBST (index 0) is declared as a nested BinXml value.
        chunk.push(TOK_FRAGMENT_HEADER);
        chunk.extend_from_slice(&[1, 1, 0]);
        chunk.push(TOK_OPEN_START_ELEMENT);
        chunk.extend_from_slice(&0u16.to_le_bytes());
        chunk.extend_from_slice(&0u32.to_le_bytes());
        let ph = chunk.len();
        chunk.extend_from_slice(&0u32.to_le_bytes());
        let off = push_name_def(&mut chunk, "Event");
        chunk[ph..ph + 4].copy_from_slice(&off.to_le_bytes());
        chunk.push(TOK_CLOSE_START_ELEMENT);

        chunk.push(TOK_OPEN_START_ELEMENT);
        chunk.extend_from_slice(&0u16.to_le_bytes());
        chunk.extend_from_slice(&0u32.to_le_bytes());
        let ph = chunk.len();
        chunk.extend_from_slice(&0u32.to_le_bytes());
        let off = push_name_def(&mut chunk, "EventData");
        chunk[ph..ph + 4].copy_from_slice(&off.to_le_bytes());
        chunk.push(TOK_CLOSE_START_ELEMENT);

        chunk.push(TOK_NORMAL_SUBSTITUTION);
        chunk.extend_from_slice(&0u16.to_le_bytes());
        chunk.push(values::VALUE_BINXML);

        chunk.push(TOK_END_ELEMENT); // closes <EventData>
        chunk.push(TOK_END_ELEMENT); // closes <Event>
        chunk.push(TOK_EOF);

        let data_size = chunk.len() as u32 - template_body_start_marker;
        chunk[data_size_pos..data_size_pos + 4].copy_from_slice(&data_size.to_le_bytes());

        // --- Record fragment: FragmentHeader + TemplateInstance + EOF ---
        let record_start = chunk.len();
        chunk.push(TOK_FRAGMENT_HEADER);
        chunk.extend_from_slice(&[1, 1, 0]);
        chunk.push(TOK_TEMPLATE_INSTANCE);
        chunk.push(0x01);
        chunk.extend_from_slice(&1u32.to_le_bytes());
        chunk.extend_from_slice(&definition_offset.to_le_bytes());
        chunk.extend_from_slice(&1u32.to_le_bytes()); // num_substitutions

        // Build the nested fragment (`<Data>hello</Data>`) separately to
        // know its size up front, then splice it directly into the chunk at
        // its real position so its own name definitions land at real
        // chunk-absolute offsets (required for the recursive decode's
        // "is this the definition" check to work).
        let nested_size_pos = chunk.len();
        chunk.extend_from_slice(&0u16.to_le_bytes()); // size, patched below
        chunk.push(values::VALUE_BINXML);
        chunk.push(0);
        let nested_start = chunk.len();
        chunk.push(TOK_FRAGMENT_HEADER);
        chunk.extend_from_slice(&[1, 1, 0]);
        chunk.push(TOK_OPEN_START_ELEMENT);
        chunk.extend_from_slice(&0u32.to_le_bytes());
        let ph = chunk.len();
        chunk.extend_from_slice(&0u32.to_le_bytes());
        let off = push_name_def(&mut chunk, "Data");
        chunk[ph..ph + 4].copy_from_slice(&off.to_le_bytes());
        chunk.push(TOK_CLOSE_START_ELEMENT);
        chunk.push(TOK_VALUE);
        chunk.push(values::VALUE_WSTRING);
        chunk.extend_from_slice(&("hello".encode_utf16().count() as u16).to_le_bytes());
        chunk.extend_from_slice(&utf16le("hello"));
        chunk.push(TOK_END_ELEMENT);
        chunk.push(TOK_EOF);
        let nested_size = (chunk.len() - nested_start) as u16;
        chunk[nested_size_pos..nested_size_pos + 2].copy_from_slice(&nested_size.to_le_bytes());

        chunk.push(TOK_EOF);
        let record_end = chunk.len();

        let ctx = ChunkContext::new(&chunk);
        let nodes = decode_record_fragment(&ctx, record_start, record_end).unwrap();
        let XmlNode::Element(event) = &nodes[0] else {
            panic!("expected root element")
        };
        let event_data = event.child("EventData").unwrap();
        let data = event_data.child("Data").unwrap();
        assert_eq!(data.text(), "hello");
    }
}
