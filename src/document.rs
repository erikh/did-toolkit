use crate::{did::DID, jwk::JWK, multibase::MultiBase, registry::Registry, url::URL};
use anyhow::anyhow;
use either::Either;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, fmt::Display, hash::Hash, str::FromStr};
use url::Url;

#[derive(Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
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

impl Default for VerificationMethodType {
    fn default() -> Self {
        VerificationMethodType::JWK2020
    }
}

impl FromStr for VerificationMethodType {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "JsonWebKey2020" => Ok(Self::JWK2020),
            "EcdsaSecp256k1VerificationKey2019" => Ok(Self::ECDSASECP256K12019),
            "Ed25519VerificationKey2018" => Ok(Self::Ed255192018),
            "Bls12381G1Key2020" => Ok(Self::Bls12381G12020),
            "Bls12381G2Key2020" => Ok(Self::Bls12381G22020),
            "PgpVerificationKey2021" => Ok(Self::PGP2021),
            "EcdsaSecp256k1RecoveryMethod2020" => Ok(Self::ECDSASECP256K1Recovery2020),
            "VerifiableCondition2021" => Ok(Self::VerifiableCondition2021),
            _ => Err(anyhow!("Property does not match")),
        }
    }
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

#[derive(Clone, Default, Debug, Eq, PartialOrd, Ord, Serialize, Deserialize)]
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
    /// Determines if a verification method is valid. To be valid, it must only contain one public
    /// key.
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

#[derive(Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
/// It's important to note here that the document that describes these is not very well formed.
/// https://www.w3.org/TR/did-spec-registries/#service-types
pub enum ServiceType {
    /// https://www.w3.org/TR/did-spec-registries/#credentialregistry
    CredentialRegistry,
    /// https://identity.foundation/.well-known/resources/did-configuration/#linked-domain-service-endpoint
    LinkedDomains,
    // there are others (such as DIDCommMessaging) that I did not supply here because they don't
    // appear to be finished.
}

impl Display for ServiceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::LinkedDomains => "LinkedDomains",
            Self::CredentialRegistry => "CredentialRegistry",
        })
    }
}

impl FromStr for ServiceType {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "LinkedDomains" => Ok(Self::LinkedDomains),
            "CredentialRegistry" => Ok(Self::CredentialRegistry),
            _ => Err(anyhow!("Property does not match")),
        }
    }
}

#[derive(Clone, Default, Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ServiceEndpointProperties {
    // only used for LinkedDomains
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origins: Option<BTreeSet<Url>>,

    // only used for CredentialRegistry
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registries: Option<BTreeSet<Url>>,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct ServiceTypes(pub Either<ServiceType, BTreeSet<ServiceType>>);

#[derive(Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct ServiceEndpoints(pub Either<Url, ServiceEndpointProperties>);

#[derive(Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ServiceEndpoint {
    pub id: Url,
    #[serde(rename = "type")]
    pub typ: ServiceTypes,
    #[serde(rename = "serviceEndpoint")]
    pub endpoint: ServiceEndpoints,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct VerificationMethodEither(pub Either<VerificationMethod, URL>);

#[derive(Clone, Debug, Default, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct VerificationMethods(pub BTreeSet<VerificationMethodEither>);

impl VerificationMethods {
    /// Determines if the set of verification methods is valid. Takes an optional registry to
    /// lookup by [URL].
    pub fn valid(&self, registry: Option<&Registry>) -> Result<(), anyhow::Error> {
        for v in self.0.iter() {
            match &v.0 {
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

#[derive(Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct AlsoKnownAsEither(pub Either<DID, Url>);

#[derive(Clone, Debug, Default, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct AlsoKnownAs(pub BTreeSet<AlsoKnownAsEither>);

#[derive(Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct Controller(pub Either<DID, BTreeSet<DID>>);

impl Default for Controller {
    fn default() -> Self {
        Controller(Either::Right(BTreeSet::default()))
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct Context(pub Either<Url, BTreeSet<Url>>);

impl Default for Context {
    fn default() -> Self {
        Context(Either::Right(BTreeSet::default()))
    }
}

/// The encapsulation of a decentralized identity document, or DID. This conforms to the did-core
/// spec in totality, according to the rules defined in
/// https://www.w3.org/TR/did-core/#core-properties. Divergence from the spec will be considered a
/// bug, unless otherwise noted.
///
/// Please see the individual properties regarding their use. Types in this module will remain
/// undocumented for brevity's sake, with the exception of methods that live on those types.
///
/// One notable thing in this implementation is use of the [either] crate with wrapping types. This
/// is used to aid in the (de)-serialization of documents properties that can consume multiple
/// switched types. Unfortunately, the spec is not very kind to users of statically-typed
/// languages, so we must take extra precautions to ensure all valid documents can be parsed. To
/// utilize most of these types, there may be an "either wrapper" as well as the [either::Either]
/// enum itself to encapsulate a type. For example, [AlsoKnownAs] encapsulates [AlsoKnownAsEither]
/// as a [BTreeSet] which then encapsulates [either::Either] types depending on which style of
/// attribute was used, as [DID]s and hypertext [url::Url]s can be used interchangeably. This
/// approach reduces memory usage and computation time by storing structs instead of raw strings
/// and "figuring it out later".
///
/// JSON-LD attributes (`@context`, specifically), are accounted for but not used by this
/// implementation. This allows you to generate documents and consume ones that follow the JSON-LD
/// specification but does not attempt to validate the document using the JSON-LD schema. See the
/// crate's README for more information regarding this decision.
///
/// [serde] crate implementations are available for all types, to ensure valid [serde_json] and
/// [ciborium] I/O, but other formats that [serde] supports should be technically possible to
/// support without issue.
///
#[derive(Clone, Debug, Default, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Document {
    /// JSON-LD @context support
    #[serde(rename = "@context", skip_serializing_if = "Option::is_none")]
    pub context: Option<Context>,
    /// The DID that this document corresponds to. Will be used as the key when storing in a
    /// [Registry]. This is called the "DID Subject" in the specification.
    pub id: DID,
    /// alsoKnownAs determines equivalence for two documents for all purposes. See
    /// https://www.w3.org/TR/did-core/#also-known-as for more.
    #[serde(rename = "alsoKnownAs", skip_serializing_if = "Option::is_none")]
    pub also_known_as: Option<AlsoKnownAs>,
    // controller determines if another [DID] is capable of taking actions for this [DID]. See
    // https://www.w3.org/TR/did-core/#did-controller for more.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub controller: Option<Controller>,
    /// [VerificationMethod]s are used to verify the identity claiming this document. See
    /// https://www.w3.org/TR/did-core/#verification-methods for more. Most following properties
    /// that use [VerificationMethods] may refer to this portion of the document by [URL] to add
    /// additional capabilities to a specific [VerificationMethod].
    #[serde(rename = "verificationMethod", skip_serializing_if = "Option::is_none")]
    pub verification_method: Option<BTreeSet<VerificationMethod>>,
    /// This set of [VerificationMethods] corresponds to authentication.
    /// https://www.w3.org/TR/did-core/#authentication
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authentication: Option<VerificationMethods>,
    /// This set of [VerificationMethods] corresponds to assertions.
    /// https://www.w3.org/TR/did-core/#assertion
    #[serde(rename = "assertionMethod", skip_serializing_if = "Option::is_none")]
    pub assertion_method: Option<VerificationMethods>,
    /// This set of [VerificationMethods] refers to key agreement.
    /// https://www.w3.org/TR/did-core/#key-agreement
    #[serde(rename = "keyAgreement", skip_serializing_if = "Option::is_none")]
    pub key_agreement: Option<VerificationMethods>,
    /// This set of [VerificationMethods] refers to capability invocation.
    /// https://www.w3.org/TR/did-core/#capability-invocation
    #[serde(
        rename = "capabilityInvocation",
        skip_serializing_if = "Option::is_none"
    )]
    /// This set of [VerificationMethods] refers to capability delegation.
    /// https://www.w3.org/TR/did-core/#capability-delegation
    pub capability_invocation: Option<VerificationMethods>,
    #[serde(
        rename = "capabilityDelegation",
        skip_serializing_if = "Option::is_none"
    )]
    pub capability_delegation: Option<VerificationMethods>,
    /// This portion of the document refers to affected services. Services are specially provided
    /// by the "DID registry": https://www.w3.org/TR/did-spec-registries/ and rely on enums to
    /// determine how the service is treated.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service: Option<BTreeSet<ServiceEndpoint>>,
}

impl Document {
    /// Determines if a document is valid. Takes an optional registry to resolve [URL]s
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
    use super::{
        AlsoKnownAsEither, Context, Controller, ServiceEndpointProperties, ServiceEndpoints,
        ServiceType, ServiceTypes, VerificationMethod, VerificationMethodEither,
        VerificationMethodType,
    };
    use crate::{did::DID, url::URL};
    use either::Either;
    use serde::{de::Visitor, ser::SerializeSeq, Deserialize, Serialize, Serializer};
    use std::{collections::BTreeSet, str::FromStr};
    use url::Url;

    struct ControllerVisitor;

    impl<'de> Visitor<'de> for ControllerVisitor {
        type Value = Controller;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("Expecting a DID or set of DIDs")
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            match DID::parse(v) {
                Ok(did) => Ok(Controller(Either::Left(did))),
                Err(e) => Err(E::custom(e)),
            }
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: serde::de::SeqAccess<'de>,
        {
            let mut set = BTreeSet::default();

            while let Some(elem) = seq.next_element::<String>()? {
                match DID::parse(&elem) {
                    Ok(did) => {
                        set.insert(did);
                    }
                    Err(e) => return Err(serde::de::Error::custom(e)),
                }
            }

            Ok(Controller(Either::Right(set)))
        }
    }

    impl<'de> Deserialize<'de> for Controller {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            deserializer.deserialize_any(ControllerVisitor)
        }
    }

    impl Serialize for Controller {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            match &self.0 {
                Either::Left(did) => serializer.serialize_str(&did.to_string()),
                Either::Right(set) => {
                    let mut seq = serializer.serialize_seq(Some(set.len()))?;
                    for item in set {
                        seq.serialize_element(&item.to_string())?;
                    }
                    seq.end()
                }
            }
        }
    }

    struct AlsoKnownAsVisitor;

    impl<'de> Visitor<'de> for AlsoKnownAsVisitor {
        type Value = AlsoKnownAsEither;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("Expecting a set of inter-mixed DIDs and URLs")
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            let res = match DID::parse(v) {
                Ok(did) => Either::Left(did),
                Err(_) => match Url::parse(v) {
                    Ok(url) => Either::Right(url),
                    Err(e) => return Err(serde::de::Error::custom(e)),
                },
            };

            Ok(AlsoKnownAsEither(res))
        }
    }

    impl<'de> Deserialize<'de> for AlsoKnownAsEither {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            deserializer.deserialize_str(AlsoKnownAsVisitor)
        }
    }

    impl Serialize for AlsoKnownAsEither {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            serializer.serialize_str(&match &self.0 {
                Either::Left(did) => did.to_string(),
                Either::Right(url) => url.to_string(),
            })
        }
    }

    struct VerificationMethodVisitor;
    impl<'de> Visitor<'de> for VerificationMethodVisitor {
        type Value = VerificationMethodEither;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("Expecting a set of verification methods or DID URLs")
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            match URL::parse(v) {
                Ok(url) => Ok(VerificationMethodEither(Either::Right(url))),
                Err(e) => Err(serde::de::Error::custom(e)),
            }
        }

        fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
        where
            A: serde::de::MapAccess<'de>,
        {
            let mut vm = VerificationMethod::default();

            while let Some(key) = map.next_key::<String>()? {
                match key.as_str() {
                    "id" => vm.id = map.next_value()?,
                    "controller" => vm.controller = map.next_value()?,
                    "type" => vm.typ = map.next_value()?,
                    "publicKeyJwk" => vm.public_key_jwk = map.next_value()?,
                    "publicKeyMultibase" => vm.public_key_multibase = map.next_value()?,
                    _ => {
                        return Err(serde::de::Error::unknown_field(
                            &key,
                            &[
                                "id",
                                "controller",
                                "type",
                                "publicKeyJwk",
                                "publicKeyMultibase",
                            ],
                        ))
                    }
                }
            }

            Ok(VerificationMethodEither(Either::Left(vm)))
        }
    }

    impl<'de> Deserialize<'de> for VerificationMethodEither {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            deserializer.deserialize_any(VerificationMethodVisitor)
        }
    }

    impl Serialize for VerificationMethodEither {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            match &self.0 {
                Either::Left(vm) => vm.serialize(serializer),
                Either::Right(url) => url.serialize(serializer),
            }
        }
    }

    struct ServiceTypeVisitor;

    impl<'de> Visitor<'de> for ServiceTypeVisitor {
        type Value = ServiceTypes;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("Expecting set of service types or a single service type")
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: serde::de::SeqAccess<'de>,
        {
            let mut set = BTreeSet::default();

            while let Some(elem) = seq.next_element::<String>()? {
                match ServiceType::from_str(&elem) {
                    Ok(st) => {
                        set.insert(st);
                    }
                    Err(e) => return Err(serde::de::Error::custom(e)),
                }
            }

            Ok(ServiceTypes(Either::Right(set)))
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(ServiceTypes(match ServiceType::from_str(v) {
                Ok(st) => Either::Left(st),
                Err(e) => return Err(serde::de::Error::custom(e)),
            }))
        }
    }

    impl<'de> Deserialize<'de> for ServiceTypes {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            deserializer.deserialize_any(ServiceTypeVisitor)
        }
    }

    impl Serialize for ServiceTypes {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            match &self.0 {
                Either::Left(typ) => typ.serialize(serializer),
                Either::Right(set) => {
                    let mut seq = serializer.serialize_seq(Some(set.len()))?;

                    for item in set {
                        seq.serialize_element(item)?;
                    }

                    seq.end()
                }
            }
        }
    }

    struct ServiceEndpointVisitor;

    impl<'de> Visitor<'de> for ServiceEndpointVisitor {
        type Value = ServiceEndpoints;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("Expected a service URL or service endpoint definition")
        }

        fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
        where
            A: serde::de::MapAccess<'de>,
        {
            let mut se = ServiceEndpointProperties::default();

            while let Some(key) = map.next_key::<String>()? {
                match key.as_str() {
                    "origins" => se.origins = map.next_value()?,
                    "registries" => se.registries = map.next_value()?,
                    _ => {
                        return Err(serde::de::Error::unknown_field(
                            &key,
                            &["origins", "registries"],
                        ))
                    }
                }
            }

            Ok(ServiceEndpoints(Either::Right(se)))
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            match Url::parse(v) {
                Ok(url) => Ok(ServiceEndpoints(Either::Left(url))),
                Err(e) => Err(serde::de::Error::custom(e)),
            }
        }
    }

    impl<'de> Deserialize<'de> for ServiceEndpoints {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            deserializer.deserialize_any(ServiceEndpointVisitor)
        }
    }

    impl Serialize for ServiceEndpoints {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            match &self.0 {
                Either::Left(url) => serializer.serialize_str(&url.to_string()),
                Either::Right(properties) => properties.serialize(serializer),
            }
        }
    }

    struct ContextVisitor;

    impl<'de> Visitor<'de> for ContextVisitor {
        type Value = Context;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("Expecting a URL or set of URLs")
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            match Url::parse(v) {
                Ok(res) => Ok(Context(Either::Left(res))),
                Err(e) => Err(serde::de::Error::custom(e)),
            }
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: serde::de::SeqAccess<'de>,
        {
            let mut set = BTreeSet::default();

            while let Some(elem) = seq.next_element::<String>()? {
                match Url::parse(&elem) {
                    Ok(res) => {
                        set.insert(res);
                    }
                    Err(e) => return Err(serde::de::Error::custom(e)),
                }
            }

            Ok(Context(Either::Right(set)))
        }
    }

    impl<'de> Deserialize<'de> for Context {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            deserializer.deserialize_any(ContextVisitor)
        }
    }

    impl Serialize for Context {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            match &self.0 {
                Either::Left(url) => serializer.serialize_str(&url.to_string()),
                Either::Right(set) => set.serialize(serializer),
            }
        }
    }

    struct VerificationMethodTypeVisitor;

    impl<'de> Visitor<'de> for VerificationMethodTypeVisitor {
        type Value = VerificationMethodType;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("Expected a valid verification method type")
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            match VerificationMethodType::from_str(v) {
                Ok(typ) => Ok(typ),
                Err(e) => Err(serde::de::Error::custom(e)),
            }
        }
    }

    impl<'de> Deserialize<'de> for VerificationMethodType {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            deserializer.deserialize_str(VerificationMethodTypeVisitor)
        }
    }

    impl Serialize for VerificationMethodType {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            serializer.serialize_str(&self.to_string())
        }
    }

    impl Serialize for ServiceType {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            serializer.serialize_str(&self.to_string())
        }
    }
}
