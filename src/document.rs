use crate::{did::DID, jwk::JWK, multibase::MultiBase, registry::Registry, url::URL};
use anyhow::anyhow;
use either::Either;
use serde::{ser::SerializeSeq, Deserialize, Serialize, Serializer};
use std::{collections::BTreeSet, fmt::Display, hash::Hash};
use url::Url;

#[derive(Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum VerificationMethodType {
    JWK2020,
    ECDSASECP256K12019,
    Ed255192018,
    Bls12381G12020,
    Bls12381G22020,
    PGP2021,
    ECDSASECP256K1Recovery2020,
    VerifiableCondition2021,
}

impl Display for VerificationMethodType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::JWK2020 => "JsonWebKey2020",
            Self::ECDSASECP256K12019 => "EcdsaSecp256k1VerificationKey2019",
            Self::Ed255192018 => "Ed25519VerificationKey2018",
            Self::Bls12381G12020 => "Bls12381G1Key2020",
            Self::Bls12381G22020 => "Bls12381G2Key2020",
            Self::PGP2021 => "PgpVerificationKey2021",
            Self::ECDSASECP256K1Recovery2020 => "EcdsaSecp256k1RecoveryMethod2020",
            Self::VerifiableCondition2021 => "VerifiableCondition2021",
        })
    }
}

#[derive(Clone, Debug, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct VerificationMethod {
    pub id: URL,
    pub controller: DID,
    #[serde(rename = "type")]
    pub typ: VerificationMethodType,
    #[serde(rename = "publicKeyJwk", skip_serializing_if = "Option::is_none")]
    pub public_key_jwk: Option<JWK>,
    #[serde(rename = "publicKeyMultibase", skip_serializing_if = "Option::is_none")]
    pub public_key_multibase: Option<MultiBase>,
}

impl PartialEq for VerificationMethod {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
            && self.controller == other.controller
            && self.typ == other.typ
            && self.public_key_jwk == other.public_key_jwk
            && self.public_key_multibase == other.public_key_multibase
    }
}

// fixate the "key" for the hash on the verification method id. We don't want the rest considered,
// so we can constrain uniqueness on the id, not, say, the key material.
impl Hash for VerificationMethod {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.id.hash(state)
    }
}

impl VerificationMethod {
    pub fn valid(&self) -> Result<(), anyhow::Error> {
        if self.public_key_jwk.is_some() && self.public_key_multibase.is_some() {
            return Err(anyhow!(
                "Verification method {} provided both JWK and multibase keys",
                self.id
            ));
        }

        Ok(())
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
// it's important to note here that the document that describes these is not very well formed.
// https://www.w3.org/TR/did-spec-registries/#service-types
pub enum ServiceType {
    // https://www.w3.org/TR/did-spec-registries/#credentialregistry
    CredentialRegistry,
    // https://identity.foundation/.well-known/resources/did-configuration/#linked-domain-service-endpoint
    LinkedDomains,
    // there are others (such as DIDCommMessaging) that I did not supply here because they don't
    // appear to be finished.
}

impl Display for ServiceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::CredentialRegistry => "CredentialRegistry",
            Self::LinkedDomains => "LinkedDomains",
        })
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
// a lumping of all the one off garbage in this part of the spec.
// seriously, I think someone at the w3c thinks JSON is a programming language
pub struct ServiceEndpointProperties {
    // only used for LinkedDomains
    #[serde(skip_serializing_if = "Option::is_none")]
    origins: Option<BTreeSet<Url>>,

    // only used for CredentialRegistry
    #[serde(skip_serializing_if = "Option::is_none")]
    registries: Option<BTreeSet<Url>>,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ServiceEndpoint {
    pub id: Url,
    #[serde(rename = "type")]
    pub typ: Either<ServiceType, BTreeSet<ServiceType>>,
    #[serde(rename = "serviceEndpoint")]
    pub endpoint: Either<Url, ServiceEndpointProperties>,
}

impl ServiceEndpoint {
    pub fn id(&self) -> Url {
        self.id.clone()
    }

    pub fn service_type(&self) -> Either<ServiceType, BTreeSet<ServiceType>> {
        self.typ.clone()
    }

    pub fn endpoint(&self) -> Either<Url, ServiceEndpointProperties> {
        self.endpoint.clone()
    }
}

#[derive(Clone, Debug, Default, Hash, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
pub struct VerificationMethods(BTreeSet<Either<VerificationMethod, URL>>);

impl Serialize for VerificationMethods {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(self.0.len()))?;
        for item in &self.0 {
            match item {
                Either::Left(vm) => {
                    seq.serialize_element(&vm)?;
                }
                Either::Right(url) => {
                    seq.serialize_element(&url)?;
                }
            }
        }
        seq.end()
    }
}

impl VerificationMethods {
    // Takes an optional registry to lookup by URL
    pub fn valid(&self, registry: Option<&Registry>) -> Result<(), anyhow::Error> {
        for v in self.0.iter() {
            match v {
                Either::Left(vm) => vm.valid()?,
                Either::Right(url) => {
                    if let Some(registry) = &registry {
                        if let Some(doc) = registry.get(&url.to_did()) {
                            if let Some(vms) = doc.verification_method {
                                if vms.iter().any(|vm| &(*vm).id == url) {
                                    return Ok(());
                                } else {
                                    return Err(anyhow!("Could not locate verification method prescribed by {} in registry", url));
                                }
                            }
                        } else {
                            return Err(anyhow!(
                                "Could not retrieve DID from DID URL {} in registry",
                                url
                            ));
                        }
                    } else {
                        return Err(anyhow!("DID URL {} provided as verification method, but could not look up in registry because none was provided", url));
                    }
                }
            }
        }

        Ok(())
    }
}

#[derive(Clone, Debug, Default, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Document {
    #[serde(rename = "@context", skip_serializing_if = "Option::is_none")]
    pub context: Option<Either<Url, BTreeSet<Url>>>,
    pub id: DID,
    #[serde(
        rename = "alsoKnownAs",
        skip_serializing_if = "Option::is_none",
        serialize_with = "crate::document::serde_support::serialize_aka"
    )]
    pub also_known_as: Option<BTreeSet<Either<DID, Url>>>,
    #[serde(
        skip_serializing_if = "Option::is_none",
        serialize_with = "crate::document::serde_support::serialize_controller"
    )]
    pub controller: Option<Either<DID, BTreeSet<DID>>>,
    #[serde(rename = "verificationMethod", skip_serializing_if = "Option::is_none")]
    pub verification_method: Option<BTreeSet<VerificationMethod>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authentication: Option<VerificationMethods>,
    #[serde(rename = "assertionMethod", skip_serializing_if = "Option::is_none")]
    pub assertion_method: Option<VerificationMethods>,
    #[serde(rename = "keyAgreement", skip_serializing_if = "Option::is_none")]
    pub key_agreement: Option<VerificationMethods>,
    #[serde(
        rename = "capabilityInvocation",
        skip_serializing_if = "Option::is_none"
    )]
    pub capability_invocation: Option<VerificationMethods>,
    #[serde(
        rename = "capabilityDelegation",
        skip_serializing_if = "Option::is_none"
    )]
    pub capability_delegation: Option<VerificationMethods>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service: Option<BTreeSet<ServiceEndpoint>>,
}

impl Document {
    // takes an optional registry to resolve URLs
    pub fn valid(&self, registry: Option<&Registry>) -> Result<(), anyhow::Error> {
        if let Some(vm) = &self.verification_method {
            for v in vm.iter() {
                v.valid()?;
            }
        }

        // these are all basically the same, call the inner verification method, or do something
        // with the DID URL.
        for field in [
            &self.authentication,
            &self.assertion_method,
            &self.key_agreement,
            &self.capability_invocation,
            &self.capability_delegation,
        ] {
            if let Some(field) = field {
                field.valid(registry)?
            }
        }

        Ok(())
    }
}

mod serde_support {
    use crate::did::DID;
    use either::Either;
    use serde::{ser::SerializeSeq, Serializer};
    use std::collections::BTreeSet;
    use url::Url;

    pub fn serialize_controller<S>(
        target: &Option<Either<DID, BTreeSet<DID>>>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match target {
            None => serializer.serialize_none(),
            Some(Either::Left(did)) => serializer.serialize_str(&did.to_string()),
            Some(Either::Right(set)) => {
                let mut seq = serializer.serialize_seq(Some(set.len()))?;
                for item in set {
                    seq.serialize_element(&item.to_string())?;
                }
                seq.end()
            }
        }
    }

    pub fn serialize_aka<S>(
        target: &Option<BTreeSet<Either<DID, Url>>>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match target {
            None => serializer.serialize_none(),
            Some(set) => {
                let mut seq = serializer.serialize_seq(Some(set.len()))?;
                for item in set {
                    seq.serialize_element(&match item {
                        Either::Left(did) => did.to_string(),
                        Either::Right(url) => url.to_string(),
                    })?;
                }
                seq.end()
            }
        }
    }
}
