use crate::{
    did::DID,
    document::{Document, VerificationMethod},
    url::URL,
};
use anyhow::anyhow;
use either::Either;
use std::{
    collections::BTreeMap,
    ops::{Index, IndexMut},
    path::PathBuf,
};
use url::Url;

/// Registry is a basic, in-memory [Document] registry that is able to load documents directly as well as
/// cross-reference them in some ways. It can also optionally fetch remote documents and cache them
/// as a part of its implementation. Documents can be loaded via the JSON or CBOR formats. JSON
/// loading is provided by [serde_json] and CBOR is provided by [ciborium].
///
/// [Document] validity checks (via [Document::valid]) are not performed at loading time. [DID]
/// keying is automatically performed based on the [Document] `id` property.
///
/// Accessing the registry is provided by a few methods in the implementation, but can also be
/// indexed by [DID] reference or [usize]. Iterators are provided as ordered pairs via
/// [Registry::iter]. The underlying storage is a [BTreeMap] and awareness of the performance
/// characteristics of this implementation may be important for larger registries.
///
/// There are examples in the apporpriate part of this crate which go into loading documents from
/// disk.
///
/// ```
/// use did_toolkit::prelude::*;
/// use either::Either;
///
/// let mut reg = Registry::default();
/// let did = DID::parse("did:mymethod:alice").unwrap();
/// let did2 = DID::parse("did:mymethod:bob").unwrap();
/// let doc = Document{
///   id: did.clone(),
///   controller: Some(Controller(Either::Left(did2.clone()))),
///   ..Default::default()
/// };
///
/// reg.insert(doc.clone());
///
/// reg.insert(Document{
///   id: did2.clone(),
///   ..Default::default()
/// });
///
/// assert!(reg.controls(&did, &did2).unwrap());
/// assert_eq!(reg[0], doc);
/// assert_eq!(reg[&did], doc);
/// ```
///
#[derive(Default)]
pub struct Registry {
    r: BTreeMap<DID, Document>,
    remote_cache: bool,
}

impl<'a> Index<&'a DID> for Registry {
    type Output = Document;

    fn index(&self, index: &'a DID) -> &Self::Output {
        self.r.index(index)
    }
}

impl<'a> IndexMut<&'a DID> for Registry {
    fn index_mut(&mut self, index: &'a DID) -> &mut Document {
        self.r.get_mut(index).unwrap()
    }
}

impl Index<usize> for Registry {
    type Output = Document;

    fn index(&self, index: usize) -> &Self::Output {
        self.r
            .iter()
            .nth(index)
            .expect("invalid index dereferencing document in registry")
            .1
    }
}

impl IndexMut<usize> for Registry {
    fn index_mut(&mut self, index: usize) -> &mut Document {
        self.r
            .iter_mut()
            .nth(index)
            .expect("invalid index dereferencing document in registry")
            .1
    }
}

impl Registry {
    /// Create a [Registry] with the remote cache enabled. Use [Registry::default] for one that
    /// does not use the remote cache.
    pub fn new_with_remote_cache() -> Self {
        Self {
            r: BTreeMap::new(),
            remote_cache: true,
        }
    }

    /// Load a document from the filesystem as JSON.
    pub fn load_document(&mut self, filename: PathBuf) -> Result<(), anyhow::Error> {
        let mut file = std::fs::OpenOptions::new();
        file.read(true);
        let io = file.open(filename)?;
        let doc: Document = serde_json::from_reader(io)?;
        self.insert(doc)
    }

    /// Load a document from the filesystem as CBOR.
    pub fn load_document_cbor(&mut self, filename: PathBuf) -> Result<(), anyhow::Error> {
        let mut file = std::fs::OpenOptions::new();
        file.read(true);
        let io = file.open(filename)?;
        let doc: Document = ciborium::de::from_reader(io)?;
        self.insert(doc)
    }

    /// Get an iterator into the ordered pairs of the registry.
    pub fn iter<'a>(&'a self) -> impl Iterator<Item = (&'a DID, &'a Document)> + 'a {
        self.r.iter()
    }

    /// Compute the size of the registry.
    pub fn len(&self) -> usize {
        self.r.len()
    }

    /// Insert a document into the registry. The registry will automatically be keyed by the
    /// [Document]'s `id` property. Will fail if the document already exists.
    pub fn insert(&mut self, doc: Document) -> Result<(), anyhow::Error> {
        if self.r.contains_key(&doc.id) {
            return Err(anyhow!("DID {} already exists in registry", doc.id));
        }

        self.r.insert(doc.id.clone(), doc);
        Ok(())
    }

    /// Remove a document by [DID].
    pub fn remove(&mut self, did: &DID) -> Option<Document> {
        self.r.remove(did)
    }

    /// Retreive a document by [DID].
    pub fn get(&self, did: &DID) -> Option<Document> {
        self.r.get(did).cloned()
    }

    /// Retrieve a document by DID [URL].
    pub fn follow(&self, url: URL) -> Option<Document> {
        self.get(&url.to_did())
    }

    /// Looks up a [VerificationMethod] by [URL] for the [DID]. There must be a
    /// [VerificationMethod] in the [DID]'s document, otherwise this will return [None].
    pub fn verification_method_for_url(&self, did: &DID, url: URL) -> Option<VerificationMethod> {
        if let Some(doc) = self.get(did) {
            if let Some(vm) = doc.verification_method {
                for method in vm {
                    if url == method.id {
                        return Some(method);
                    }
                }
            }
        }

        None
    }

    /// For a given [DID], determine if another [DID] is designated as a controller. Follows the
    /// rules specified in <https://www.w3.org/TR/did-core/#did-controller>. Will fail if either
    /// [DID] is missing from the registry.
    pub fn controls(&self, did: &DID, controller: &DID) -> Result<bool, anyhow::Error> {
        if let Some(did_doc) = self.get(did) {
            if did == controller {
                return Ok(true);
            }

            if self.get(controller).is_some() {
                if did_doc.controller.is_some() {
                    match did_doc.controller.unwrap().0 {
                        Either::Left(did) => return Ok(&did == controller),
                        Either::Right(did_list) => {
                            for did in did_list {
                                if &did == controller {
                                    return Ok(true);
                                }
                            }
                        }
                    }
                } else {
                    return Ok(false);
                }
            } else {
                return Err(anyhow!("DID {} did not exist in the registry", did));
            }
        } else {
            return Err(anyhow!("DID {} did not exist in the registry", did));
        }

        Ok(false)
    }

    /// For two given [DID]s, determine if they can be treated the same according to the rules for
    /// the `alsoKnownAs` property, which you can read here:
    /// <https://www.w3.org/TR/did-core/#also-known-as>
    ///
    /// Both [DID]s must exist in the registry, otherwise an error will be returned.
    pub fn equivalent_to_did(&mut self, did: &DID, other: &DID) -> Result<bool, anyhow::Error> {
        // there is probably a better way to represent this stew with Iterator methods, but I
        // cannot be fucked to deal with that right now.
        if let Some(doc) = self.get(did) {
            if let Some(other_doc) = self.get(other) {
                if let Some(this_aka) = doc.also_known_as {
                    for this_aka_each in this_aka.0 {
                        match this_aka_each.0 {
                            Either::Left(this_did) => {
                                if self.compare_aka(did, &this_did, &other_doc)? {
                                    return Ok(true);
                                }
                            }
                            Either::Right(url) => {
                                let this_doc = self.cache_document(url)?;
                                if self.compare_aka(did, &this_doc.id, &other_doc)? {
                                    return Ok(true);
                                }
                            }
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

    fn compare_aka(
        &mut self,
        did: &DID,
        this_did: &DID,
        other_doc: &Document,
    ) -> Result<bool, anyhow::Error> {
        if let Some(other_aka) = &other_doc.also_known_as {
            for other_aka_each in &other_aka.0 {
                let other_did = &match &other_aka_each.0 {
                    Either::Left(other_did) => other_did.clone(),
                    Either::Right(url) => self.cache_document(url.clone())?.id,
                };

                if other_did == did && this_did == &other_doc.id {
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }

    fn cache_document(&mut self, url: Url) -> Result<Document, anyhow::Error> {
        if self.remote_cache {
            let doc = reqwest::blocking::get(url)?.json::<Document>()?;
            self.insert(doc.clone())?;
            Ok(doc)
        } else {
            Err(anyhow!("Remote caching of documents is disabled"))
        }
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
        use crate::{
            did::DID,
            document::{Controller, Document},
        };
        use either::Either;
        use std::collections::BTreeSet;

        let mut reg: Registry = Default::default();
        let did = DID::parse("did:testing:u:alice").unwrap();
        let did2 = DID::parse("did:testing:u:bob").unwrap();
        let did3 = DID::parse("did:testing:u:charlie").unwrap();

        let doc = Document {
            id: did.clone(),
            controller: Some(Controller(Either::Left(did2.clone()))),
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
            controller: Some(Controller(Either::Right(set))),
            ..Default::default()
        };

        let doc2 = Document {
            id: did2.clone(),
            ..Default::default()
        };

        let doc3 = Document {
            id: did3.clone(),
            controller: Some(Controller(Either::Left(did2.clone()))),
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
        use crate::{
            did::DID,
            document::{AlsoKnownAs, AlsoKnownAsEither, Document},
        };
        use either::Either;
        use std::collections::BTreeSet;

        let mut reg: Registry = Default::default();
        let did = DID::parse("did:testing:u:alice").unwrap();
        let did2 = DID::parse("did:testing:u:bob").unwrap();
        let did3 = DID::parse("did:testing:u:charlie").unwrap();

        let mut set = BTreeSet::new();
        set.insert(AlsoKnownAsEither(Either::Left(did2.clone())));

        let mut set2 = BTreeSet::new();
        set2.insert(AlsoKnownAsEither(Either::Left(did.clone())));

        let doc = Document {
            id: did.clone(),
            also_known_as: Some(AlsoKnownAs(set.clone())),
            ..Default::default()
        };

        let doc2 = Document {
            id: did2.clone(),
            also_known_as: Some(AlsoKnownAs(set2)),
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
            also_known_as: Some(AlsoKnownAs(set)),
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
