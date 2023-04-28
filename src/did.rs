use crate::{
    string::{method_id_encoded, url_encoded, validate_method_name},
    url::{URLParameters, URL},
};
use anyhow::anyhow;
use serde::{de::Visitor, Deserialize, Serialize};
use std::fmt::Display;

/// A DID is a decentralized identity according to https://www.w3.org/TR/did-core/#did-syntax. A
/// DID internally is represented as a byte array that is percent-encoded on demand according to
/// the rules defined in that document, as well as validated in some instances with regards to
/// encoding requirements. DIDs are not required to be UTF-8 compliant in the ID portion, and all
/// bytes that fall outside of a normal alphanumeric ASCII range are percent-encoded, with a few
/// exceptions. The internal types are Vec<u8> for malleability but this may change to \[u8] in the
/// future.
///
/// DIDs must have both a non-empty name and ID portion according to this interpretation of the
/// spec. They must start with `did:` and will be generated as such both in string conversion and
/// serialization steps. De-serialization also runs through the same checks and conversions.
///
/// ```
/// use did_toolkit::prelude::*;
///
/// let did = DID::parse("did:mymethod:alice").unwrap();
/// assert_eq!(String::from_utf8(did.name).unwrap(), "mymethod");
/// assert_eq!(String::from_utf8(did.id).unwrap(), "alice");
///
/// let did = DID {
///     name: "mymethod".as_bytes().to_vec(),
///     id: "alice".as_bytes().to_vec(),
/// };
/// assert_eq!(did.to_string(), "did:mymethod:alice");
/// ```
#[derive(Clone, Hash, Default, Debug, PartialOrd, Ord, Eq, PartialEq)]
pub struct DID {
    pub name: Vec<u8>,
    pub id: Vec<u8>,
}

impl Serialize for DID {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

struct DIDVisitor;
impl Visitor<'_> for DIDVisitor {
    type Value = DID;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("Expecting a decentralized identity")
    }

    fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        match DID::parse(&v) {
            Ok(did) => Ok(did),
            Err(e) => Err(E::custom(e)),
        }
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        match DID::parse(v) {
            Ok(did) => Ok(did),
            Err(e) => Err(E::custom(e)),
        }
    }
}

impl<'de> Deserialize<'de> for DID {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(DIDVisitor)
    }
}

impl Display for DID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut ret = String::from("did:");

        ret += &url_encoded(&self.name);
        ret += &(":".to_string() + &method_id_encoded(&self.id));
        f.write_str(&ret)
    }
}

impl DID {
    /// Parse a DID from a string. See top-level type documentation for information on formats.
    pub fn parse(s: &str) -> Result<Self, anyhow::Error> {
        match s.strip_prefix("did:") {
            Some(s) => match s.split_once(':') {
                Some((method_name, method_id)) => {
                    if method_id.is_empty() {
                        return Err(anyhow!("Method ID cannot be empty"));
                    }

                    if method_name.is_empty() {
                        return Err(anyhow!("Method name cannot be empty"));
                    }

                    validate_method_name(method_name.as_bytes())?;
                    Ok(DID {
                        name: method_name.into(),
                        id: method_id.into(),
                    })
                }
                None => Err(anyhow!("DID is missing method_id")),
            },
            None => Err(anyhow!("DID is missing method_name, method_id")),
        }
    }

    /// When provided with URL parameters, generates a DID URL. These are different from hypertext
    /// URLs and should be handled differently.
    ///
    /// ```
    /// use did_toolkit::prelude::*;
    ///
    /// let did = DID::parse("did:mymethod:alice").unwrap();
    /// let url = did.join(URLParameters{
    ///     fragment: Some("key-1".as_bytes().to_vec()),
    ///     ..Default::default()
    /// });
    /// assert_eq!(url.to_string(), "did:mymethod:alice#key-1");
    /// ```
    pub fn join(&self, parameters: URLParameters) -> URL {
        URL {
            did: self.clone(),
            parameters: Some(parameters),
        }
    }
}

mod tests {
    #[test]
    fn test_to_string() {
        use super::DID;

        let did = DID {
            name: "abcdef".into(),
            id: "123456".into(),
            ..Default::default()
        };

        assert_eq!(did.to_string(), "did:abcdef:123456");

        let did = DID {
            name: "abcdef".into(),
            id: "123456:u:alice".into(),
            ..Default::default()
        };

        assert_eq!(did.to_string(), "did:abcdef:123456:u:alice");
    }

    #[test]
    fn test_parse() {
        use super::DID;

        assert!(DID::parse("").is_err());
        assert!(DID::parse("did::").is_err());
        assert!(DID::parse("did:a:").is_err());
        assert!(DID::parse("frobnik").is_err());
        assert!(DID::parse("did").is_err());
        assert!(DID::parse("frobnik:").is_err());
        assert!(DID::parse("did:").is_err());
        assert!(DID::parse("did:abcdef").is_err());

        let did = DID::parse("did:abcdef:123456").unwrap();
        assert_eq!(
            did,
            DID {
                name: "abcdef".into(),
                id: "123456".into(),
                ..Default::default()
            }
        );

        let did = DID::parse("did:abcdef:123456:u:alice").unwrap();
        assert_eq!(
            did,
            DID {
                name: "abcdef".into(),
                id: "123456:u:alice".into(),
                ..Default::default()
            }
        );
    }

    #[test]
    fn test_serde() {
        use super::DID;

        let did: [DID; 1] = serde_json::from_str(r#"["did:123456:123"]"#).unwrap();
        assert_eq!(
            did[0],
            DID {
                name: "123456".into(),
                id: "123".into(),
                ..Default::default()
            }
        );

        assert_eq!(
            serde_json::to_string(&did).unwrap(),
            r#"["did:123456:123"]"#
        );
    }
}
