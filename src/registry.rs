#![allow(dead_code)]
use crate::{did::DID, document::Document, url::URL};
use anyhow::anyhow;
use std::collections::BTreeMap;

#[derive(Default)]
pub struct Registry(BTreeMap<DID, Document>);

impl Registry {
    fn insert(&mut self, doc: Document) -> Result<(), anyhow::Error> {
        if self.0.contains_key(&doc.id()) {
            return Err(anyhow!("DID {} already exists in registry", doc.id()));
        }

        self.0.insert(doc.id(), doc);
        Ok(())
    }

    fn remove(&mut self, did: DID) -> Option<Document> {
        self.0.remove(&did)
    }

    fn get(&self, did: DID) -> Option<Document> {
        self.0.get(&did).cloned()
    }

    fn follow(&self, url: URL) -> Option<Document> {
        self.get(url.to_did())
    }
}

mod tests {
    #[test]
    fn test_basic() {
        use super::Registry;
        use crate::{did::DID, document::Document};

        let mut reg: Registry = Default::default();
        let did = DID::parse("did:testing:u:alice").unwrap();
        let doc = Document {
            id: did.clone(),
            ..Default::default()
        };

        let did2 = DID::parse("did:testing:u:bob").unwrap();
        let doc2 = Document {
            id: did2.clone(),
            ..Default::default()
        };

        let did3 = DID::parse("did:testing:u:charlie").unwrap();

        assert!(reg.insert(doc.clone()).is_ok());
        assert!(reg.insert(doc.clone()).is_err());
        assert_eq!(reg.get(did.clone()), Some(doc));
        assert!(reg.insert(doc2.clone()).is_ok());
        assert_eq!(reg.get(did2), Some(doc2));
        assert!(reg.get(did3).is_none());
        assert!(reg.remove(did.clone()).is_some());
        assert!(reg.get(did).is_none());
    }

    #[test]
    fn test_follow() {
        use super::Registry;
        use crate::{did::DID, document::Document, url::URL};

        let mut reg: Registry = Default::default();
        let did = DID::parse("did:testing:u:alice").unwrap();
        let doc = Document {
            id: did.clone(),
            ..Default::default()
        };

        let did2 = DID::parse("did:testing:u:bob").unwrap();
        let doc2 = Document {
            id: did2.clone(),
            ..Default::default()
        };

        assert!(reg.insert(doc.clone()).is_ok());
        assert!(reg.insert(doc2.clone()).is_ok());

        let url = URL::parse("did:testing:u:alice/path#fragment").unwrap();
        let url2 = URL::parse("did:testing:u:bob/path#fragment").unwrap();
        let url3 = URL::parse("did:testing:u:charlie/path#fragment").unwrap();

        assert_eq!(reg.follow(url).unwrap(), doc);
        assert_eq!(reg.follow(url2).unwrap(), doc2);
        assert!(reg.follow(url3).is_none());
    }
}
