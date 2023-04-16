use crate::{did::DID, hash::OrderedHashSet, jwk::JWK, multibase::MultiBase, url::URL};
use either::Either;
use serde::{Deserialize, Serialize};
use url::Url;

#[derive(Clone, Hash, PartialEq, PartialOrd, Eq, Serialize, Deserialize)]
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

impl ToString for VerificationMethodType {
    fn to_string(&self) -> String {
        match self {
            Self::JWK2020 => "JsonWebKey2020",
            Self::ECDSASECP256K12019 => "EcdsaSecp256k1VerificationKey2019",
            Self::Ed255192018 => "Ed25519VerificationKey2018",
            Self::Bls12381G12020 => "Bls12381G1Key2020",
            Self::Bls12381G22020 => "Bls12381G2Key2020",
            Self::PGP2021 => "PgpVerificationKey2021",
            Self::ECDSASECP256K1Recovery2020 => "EcdsaSecp256k1RecoveryMethod2020",
            Self::VerifiableCondition2021 => "VerifiableCondition2021",
        }
        .to_string()
    }
}

#[derive(Clone, Hash, PartialEq, PartialOrd, Eq, Serialize, Deserialize)]
pub struct VerificationMethod {
    id: URL,
    controller: DID,
    typ: VerificationMethodType,
    public_key_jwk: Option<JWK>,
    public_key_multibase: Option<MultiBase>,
}

#[derive(Clone, Hash, PartialEq, PartialOrd, Eq, Serialize, Deserialize)]
pub enum ServiceType {
    CredentialRegistry,
}

impl ToString for ServiceType {
    fn to_string(&self) -> String {
        match self {
            Self::CredentialRegistry => "CredentialRegistry",
        }
        .to_string()
    }
}

#[derive(Clone, Hash, PartialEq, PartialOrd, Eq, Serialize, Deserialize)]
pub struct ServiceEndpoint {
    id: Url,
    typ: Either<ServiceType, OrderedHashSet<ServiceType>>,
    endpoint: Either<Url, OrderedHashSet<Url>>,
}

#[allow(dead_code)]
#[derive(Hash, PartialEq, PartialOrd, Eq, Serialize, Deserialize)]
pub struct Document {
    id: DID,
    also_known_as: Option<OrderedHashSet<Url>>,
    controller: Option<Either<DID, OrderedHashSet<DID>>>,
    verification_method: Option<OrderedHashSet<VerificationMethod>>,
    authentication: Option<Either<OrderedHashSet<VerificationMethod>, URL>>,
    assertion_method: Option<Either<OrderedHashSet<VerificationMethod>, URL>>,
    key_agreeement: Option<Either<OrderedHashSet<VerificationMethod>, URL>>,
    capability_invocation: Option<Either<OrderedHashSet<VerificationMethod>, URL>>,
    capability_delegation: Option<Either<OrderedHashSet<VerificationMethod>, URL>>,
    service: Option<OrderedHashSet<ServiceEndpoint>>,
}
