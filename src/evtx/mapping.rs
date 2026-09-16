//! Maps a decoded `Event` [`XmlElement`] tree to the framework's
//! [`EventRecord`] shape.
//!
//! `record_id` and `timestamp` are taken from the physical EVTX record
//! header (see [`crate::evtx::record::EvtxRecordHeader`]) rather than
//! re-parsed from the rendered `System/EventRecordID` and
//! `System/TimeCreated/@SystemTime` text — the header's binary FILETIME and
//! record identifier are the authoritative on-disk values these XML fields
//! merely mirror, and using them directly avoids a fragile round-trip
//! through string formatting/parsing.

use std::collections::BTreeMap;

use forensic_rs::prelude::*;

use crate::evtx::xml::{XmlElement, XmlNode};

pub fn map_event(event: &XmlElement, record_id: u64, timestamp: ForensicTimestamp) -> EventRecord {
    let system = event.child("System");

    let provider = system
        .and_then(|s| s.child("Provider"))
        .and_then(|p| p.attr("Name"))
        .unwrap_or_default()
        .to_string();
    let event_id = system
        .and_then(|s| s.child("EventID"))
        .map(|e| e.text())
        .and_then(|t| t.trim().parse::<u32>().ok())
        .unwrap_or(0);
    let channel = system
        .and_then(|s| s.child("Channel"))
        .map(|e| e.text())
        .unwrap_or_default();
    let computer = system
        .and_then(|s| s.child("Computer"))
        .map(|e| e.text())
        .unwrap_or_default();
    // Windows Level values: 0 (LogAlways) has no EventLevel equivalent and
    // conventionally renders as Information, same as an absent/unparsable
    // Level element.
    let level = system
        .and_then(|s| s.child("Level"))
        .map(|e| e.text())
        .and_then(|t| t.trim().parse::<u8>().ok())
        .and_then(EventLevel::from_id)
        .unwrap_or(EventLevel::Information);
    let user_sid = system
        .and_then(|s| s.child("Security"))
        .and_then(|sec| sec.attr("UserID"))
        .map(|s| s.to_string());

    let mut data = BTreeMap::new();
    if let Some(event_data) = event.child("EventData") {
        for (index, entry) in event_data.children_named("Data").enumerate() {
            let key = entry
                .attr("Name")
                .map(|name| format!("winlog.event_data.{name}"))
                .unwrap_or_else(|| format!("winlog.event_data.{index}"));
            data.insert(text_owned(key), Field::from(entry.text()));
        }
        if let Some(binary) = event_data.child("Binary") {
            data.insert(text_owned("winlog.event_data.binary".to_string()), Field::from(binary.text()));
        }
    }
    if let Some(user_data) = event.child("UserData") {
        for child in element_children(user_data) {
            flatten_into(child, format!("winlog.user_data.{}", child.name), &mut data);
        }
    }

    EventRecord {
        record_id,
        event_id,
        timestamp,
        provider,
        channel,
        level,
        computer,
        user_sid,
        data,
    }
}

fn element_children(element: &XmlElement) -> impl Iterator<Item = &XmlElement> {
    element.children.iter().filter_map(|node| match node {
        XmlNode::Element(e) => Some(e),
        XmlNode::Text(_) => None,
    })
}

/// Recursively flattens an arbitrary (provider-defined) element tree into
/// dotted-path keys, e.g. `winlog.user_data.EventXML.ProcessId`. Leaf
/// elements (no element children) become one field; elements with element
/// children recurse without emitting a field of their own.
fn flatten_into(element: &XmlElement, prefix: String, out: &mut BTreeMap<Text, Field>) {
    let mut children = element_children(element).peekable();
    if children.peek().is_none() {
        let text = element.text();
        if !text.trim().is_empty() {
            out.insert(text_owned(prefix), Field::from(text));
        }
        return;
    }
    for child in children {
        flatten_into(child, format!("{prefix}.{}", child.name), out);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn el(name: &str, children: Vec<XmlNode>) -> XmlElement {
        XmlElement {
            name: name.to_string(),
            attributes: Vec::new(),
            children,
        }
    }

    fn attr_el(name: &str, attrs: Vec<(&str, &str)>) -> XmlElement {
        XmlElement {
            name: name.to_string(),
            attributes: attrs.into_iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
            children: Vec::new(),
        }
    }

    #[test]
    fn maps_system_and_event_data_fields() {
        let system = el(
            "System",
            vec![
                XmlNode::Element(attr_el("Provider", vec![("Name", "Microsoft-Windows-Security-Auditing")])),
                XmlNode::Element(el("EventID", vec![XmlNode::Text("4624".to_string())])),
                XmlNode::Element(el("Channel", vec![XmlNode::Text("Security".to_string())])),
                XmlNode::Element(el("Computer", vec![XmlNode::Text("HOST1".to_string())])),
                XmlNode::Element(el("Level", vec![XmlNode::Text("4".to_string())])),
                XmlNode::Element(attr_el("Security", vec![("UserID", "S-1-5-18")])),
            ],
        );
        let mut logon_type = el("Data", vec![XmlNode::Text("3".to_string())]);
        logon_type.attributes.push(("Name".to_string(), "LogonType".to_string()));
        let event_data = el("EventData", vec![XmlNode::Element(logon_type)]);
        let event = el("Event", vec![XmlNode::Element(system), XmlNode::Element(event_data)]);

        let timestamp = ForensicTimestamp::from_unix_secs(1_700_000_000);
        let record = map_event(&event, 42, timestamp);

        assert_eq!(record.record_id, 42);
        assert_eq!(record.event_id, 4624);
        assert_eq!(record.channel, "Security");
        assert_eq!(record.computer, "HOST1");
        assert_eq!(record.level, EventLevel::Information);
        assert_eq!(record.provider, "Microsoft-Windows-Security-Auditing");
        assert_eq!(record.user_sid.as_deref(), Some("S-1-5-18"));
        assert_eq!(
            record.data.get(&text_owned("winlog.event_data.LogonType".to_string())),
            Some(&Field::from("3".to_string()))
        );
    }

    #[test]
    fn flattens_nested_user_data() {
        let inner = el("ProcessId", vec![XmlNode::Text("1234".to_string())]);
        let event_xml = el("EventXML", vec![XmlNode::Element(inner)]);
        let user_data = el("UserData", vec![XmlNode::Element(event_xml)]);
        let event = el("Event", vec![XmlNode::Element(user_data)]);

        let record = map_event(&event, 1, ForensicTimestamp::from_unix_secs(0));
        assert_eq!(
            record.data.get(&text_owned("winlog.user_data.EventXML.ProcessId".to_string())),
            Some(&Field::from("1234".to_string()))
        );
    }
}
