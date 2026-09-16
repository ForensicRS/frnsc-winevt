//! A minimal, generic XML element tree — the target shape BinXML is decoded
//! into, before [`crate::evtx::mapping`] interprets the well-known
//! `Event/System/*`, `Event/EventData/*`, and `Event/UserData/*` elements.

#[derive(Debug, Clone, Default)]
pub struct XmlElement {
    pub name: String,
    pub attributes: Vec<(String, String)>,
    pub children: Vec<XmlNode>,
}

#[derive(Debug, Clone)]
pub enum XmlNode {
    Element(XmlElement),
    Text(String),
}

impl XmlElement {
    pub fn attr(&self, name: &str) -> Option<&str> {
        self.attributes
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    pub fn child(&self, name: &str) -> Option<&XmlElement> {
        self.children.iter().find_map(|node| match node {
            XmlNode::Element(e) if e.name == name => Some(e),
            _ => None,
        })
    }

    pub fn children_named<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a XmlElement> {
        self.children.iter().filter_map(move |node| match node {
            XmlNode::Element(e) if e.name == name => Some(e),
            _ => None,
        })
    }

    /// Concatenation of this element's direct text children (BinXML rarely
    /// mixes text and element children, so this covers the common case of a
    /// leaf element whose value is its text content).
    pub fn text(&self) -> String {
        self.children
            .iter()
            .filter_map(|node| match node {
                XmlNode::Text(t) => Some(t.as_str()),
                _ => None,
            })
            .collect::<Vec<_>>()
            .join("")
    }
}
