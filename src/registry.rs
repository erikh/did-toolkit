#![allow(dead_code)]
use crate::{
    did::DID,
    document::{Document, VerificationMethod},
    url::URL,
};
use anyhow::anyhow;
use either::Either;
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

    fn remove(&mut self, did: &DID) -> Option<Document> {
        self.0.remove(did)
    }

    fn get(&self, did: &DID) -> Option<Document> {
        self.0.get(did).cloned()
    }

    fn follow(&self, url: URL) -> Option<Document> {
        self.get(&url.to_did())
    }

    fn verification_method_for_url(&self, did: &DID, url: URL) -> Option<VerificationMethod> {
        if let Some(doc) = self.get(&did) {
            if let Some(vm) = doc.verification_method() {
                for method in vm {
                    if url == method.id() {
                        return Some(method);
                    }
                }
            }
        }

        None
    }

    pub fn controls(&self, did: &DID, controller: &DID) -> Result<bool, anyhow::Error> {
        if let Some(did_doc) = self.get(did) {
            if did == controller {
                return Ok(true);
            }

            if self.get(controller).is_some() {
                match did_doc.controller() {
                    Some(Either::Left(did)) => return Ok(&did == controller),
                    Some(Either::Right(did_list)) => {
                        for did in did_list {
                            if &did == controller {
                                return Ok(true);
                            }
                        }
                    }
                    None => return Ok(false),
                }
            } else {
                return Err(anyhow!("DID {} did not exist in the registry", did));
            }
        } else {
            return Err(anyhow!("DID {} did not exist in the registry", did));
        }

        Ok(false)
    }

    pub fn equivalent_to_did(&self, did: &DID, other: &DID) -> Result<bool, anyhow::Error> {
        // there is probably a better way to represent this stew with Iterator methods, but I
        // cannot be fucked to deal with that right now.
        if let Some(doc) = self.get(did) {
            if let Some(other_doc) = self.get(other) {
                if let Some(this_aka) = doc.also_known_as() {
                    for this_aka_each in this_aka {
                        match this_aka_each {
                            Either::Left(this_did) => {
                                if let Some(other_aka) = other_doc.also_known_as() {
                                    for other_aka_each in other_aka {
                                        match other_aka_each {
                                            Either::Left(other_did) => {
                                                if &other_did == did && &this_did == other {
                                                    return Ok(true);
                                                }
                                            }
                                            Either::Right(_url) => todo!(),
                                        }
                                    }
                                } else {
                                    return Ok(false);
                                }
                            }
                            Either::Right(_url) => todo!(),
                        }
                    }
                } else {
                    return Ok(false);
                }
            } else {
                return Err(anyhow!("DID {} did not exist in the registry", other));
            }
        } else {
            return Err(anyhow!("DID {} did not exist in the registry", did));
        }

        Ok(false)
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
        assert_eq!(reg.get(&did), Some(doc));
        assert!(reg.insert(doc2.clone()).is_ok());
        assert_eq!(reg.get(&did2), Some(doc2));
        assert!(reg.get(&did3).is_none());
        assert!(reg.remove(&did).is_some());
        assert!(reg.get(&did).is_none());
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

    #[test]
    fn test_controls() {
        use super::Registry;
        use crate::{did::DID, document::Document};
        use either::Either;
        use std::collections::BTreeSet;

        let mut reg: Registry = Default::default();
        let did = DID::parse("did:testing:u:alice").unwrap();
        let did2 = DID::parse("did:testing:u:bob").unwrap();
        let did3 = DID::parse("did:testing:u:charlie").unwrap();

        let doc = Document {
            id: did.clone(),
            controller: Some(Either::Left(did2.clone())),
            ..Default::default()
        };

        let doc2 = Document {
            id: did2.clone(),
            ..Default::default()
        };

        assert!(reg.insert(doc.clone()).is_ok());
        assert!(reg.insert(doc2.clone()).is_ok());
        assert!(reg.controls(&did, &did2).is_ok());
        assert!(reg.controls(&did2, &did3).is_err());
        assert!(reg.controls(&did, &did2).unwrap());
        assert!(!reg.controls(&did2, &did).unwrap());

        assert!(reg.remove(&did).is_some());
        assert!(reg.remove(&did2).is_some());

        let mut set = BTreeSet::new();
        set.insert(did2.clone());

        let doc = Document {
            id: did.clone(),
            controller: Some(Either::Right(set)),
            ..Default::default()
        };

        let doc2 = Document {
            id: did2.clone(),
            ..Default::default()
        };

        let doc3 = Document {
            id: did3.clone(),
            controller: Some(Either::Left(did2.clone())),
            ..Default::default()
        };

        assert!(reg.insert(doc.clone()).is_ok());
        assert!(reg.insert(doc2.clone()).is_ok());
        assert!(reg.insert(doc3.clone()).is_ok());
        assert!(reg.controls(&did, &did2).is_ok());
        assert!(reg.controls(&did, &did2).unwrap());
        assert!(!reg.controls(&did2, &did).unwrap());
        assert!(!reg.controls(&did, &did3).unwrap());
    }

    #[test]
    fn test_equivalent_to_did() {
        use super::Registry;
        use crate::{did::DID, document::Document};
        use either::Either;
        use std::collections::BTreeSet;

        let mut reg: Registry = Default::default();
        let did = DID::parse("did:testing:u:alice").unwrap();
        let did2 = DID::parse("did:testing:u:bob").unwrap();
        let did3 = DID::parse("did:testing:u:charlie").unwrap();

        let mut set = BTreeSet::new();
        set.insert(Either::Left(did2.clone()));

        let mut set2 = BTreeSet::new();
        set2.insert(Either::Left(did.clone()));

        let doc = Document {
            id: did.clone(),
            also_known_as: Some(set.clone()),
            ..Default::default()
        };

        let doc2 = Document {
            id: did2.clone(),
            also_known_as: Some(set2),
            ..Default::default()
        };

        assert!(reg.insert(doc.clone()).is_ok());
        assert!(reg.insert(doc2.clone()).is_ok());
        assert!(reg.equivalent_to_did(&did, &did3).is_err());
        assert!(reg.equivalent_to_did(&did, &did2).unwrap());
        assert!(reg.equivalent_to_did(&did2, &did).unwrap());

        let doc3 = Document {
            id: did3.clone(),
            ..Default::default()
        };

        assert!(reg.insert(doc3.clone()).is_ok());
        assert!(!reg.equivalent_to_did(&did2, &did3).unwrap());
        assert!(!reg.equivalent_to_did(&did, &did3).unwrap());

        assert!(reg.remove(&did).is_some());
        assert!(reg.remove(&did2).is_some());

        let doc = Document {
            id: did.clone(),
            also_known_as: Some(set),
            ..Default::default()
        };

        let doc2 = Document {
            id: did2.clone(),
            ..Default::default()
        };

        assert!(reg.insert(doc).is_ok());
        assert!(reg.insert(doc2).is_ok());
        assert!(!reg.equivalent_to_did(&did, &did2).unwrap());
    }
}
