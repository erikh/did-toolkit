use crate::string::{method_id_encoded, url_encoded, validate_method_name};
use anyhow::anyhow;

#[derive(Default, Debug, Hash, Eq, PartialEq)]
pub struct DID {
    pub name: Vec<u8>,
    pub method: Vec<u8>,
}

impl ToString for DID {
    fn to_string(&self) -> String {
        let mut ret = String::from("did:");

        ret += &url_encoded(&self.name);
        ret += &(":".to_string() + &method_id_encoded(&self.method));
        ret
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
                        method: method_id.into(),
                    })
                }
                None => Err(anyhow!("DID is missing method_id")),
            },
            None => Err(anyhow!("DID is missing method_name, method_id")),
        }
    }
}

mod tests {
    #[test]
    fn test_to_string() {
        use super::DID;

        let did = DID {
            name: "abcdef".into(),
            method: "123456".into(),
            ..Default::default()
        };

        assert_eq!(did.to_string(), "did:abcdef:123456");

        let did = DID {
            name: "abcdef".into(),
            method: "123456:u:alice".into(),
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
                method: "123456".into(),
                ..Default::default()
            }
        );

        let did = DID::parse("did:abcdef:123456:u:alice").unwrap();
        assert_eq!(
            did,
            DID {
                name: "abcdef".into(),
                method: "123456:u:alice".into(),
                ..Default::default()
            }
        );
    }
}
