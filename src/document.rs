use crate::{did::DID, hash::HashSafeHashSet, jwk::JWK, multibase::MultiBase, url::URL};
use either::Either;
use serde::{Deserialize, Serialize};
use url::Url;

#[derive(Hash, PartialEq, PartialOrd, Eq, Serialize, Deserialize)]
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

#[derive(Hash, PartialEq, PartialOrd, Eq, Serialize, Deserialize)]
pub struct VerificationMethod {
    id: URL,
    controller: DID,
    typ: VerificationMethodType,
    public_key_jwk: Option<JWK>,
    public_key_multibase: Option<MultiBase>,
}

#[derive(Hash, PartialEq, PartialOrd, Eq, Serialize, Deserialize)]
pub struct ServiceEndpoint {
    id: Url,
    typ: Either<String, HashSafeHashSet<String>>,
    endpoint: Either<Url, HashSafeHashSet<Url>>,
}

#[allow(dead_code)]
#[derive(Hash, PartialEq, PartialOrd, Eq, Serialize, Deserialize)]
pub struct Document {
    id: DID,
    also_known_as: Option<HashSafeHashSet<Url>>,
    controller: Option<Either<DID, HashSafeHashSet<DID>>>,
    verification_method: Option<Vec<VerificationMethod>>,
    authentication: Option<Either<HashSafeHashSet<VerificationMethod>, URL>>,
    assertion_method: Option<Either<HashSafeHashSet<VerificationMethod>, URL>>,
    key_agreeement: Option<Either<HashSafeHashSet<VerificationMethod>, URL>>,
    capability_invocation: Option<Either<HashSafeHashSet<VerificationMethod>, URL>>,
    capability_delegation: Option<Either<HashSafeHashSet<VerificationMethod>, URL>>,
    service: Option<HashSafeHashSet<ServiceEndpoint>>,
}
