use crate::{
    string::{method_id_encoded, url_encoded, validate_method_name},
    url::{URLParameters, URL},
};
use anyhow::anyhow;
use serde::{de::Visitor, Deserialize, Serialize};
use std::fmt::Display;

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
    pub fn parse(s: &str) -> Result<Self, anyhow::Error> {
        match s.strip_prefix("did:") {
            Some(s) => match s.split_once(':') {
                Some((method_name, method_id)) => {
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
