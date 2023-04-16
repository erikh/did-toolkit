use crate::{did::DID, hash::HashSafeHashSet, jwk::JWK, multibase::MultiBase, url::URL};
use either::Either;
use serde::{Deserialize, Serialize};
use url::Url;

#[derive(Hash, PartialEq, PartialOrd, Eq, Serialize, Deserialize)]
pub struct VerificationMethod {
    id: URL,
    controller: DID,
    typ: String,
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
    also_known_as: Option<HashSafeHashSet<String>>,
    controller: Option<Either<DID, HashSafeHashSet<DID>>>,
    verification_method: Option<HashSafeHashSet<VerificationMethod>>,
    authentication: Option<Either<HashSafeHashSet<VerificationMethod>, URL>>,
    assertion_method: Option<Either<HashSafeHashSet<VerificationMethod>, URL>>,
    key_agreeement: Option<Either<HashSafeHashSet<VerificationMethod>, URL>>,
    capability_invocation: Option<Either<HashSafeHashSet<VerificationMethod>, URL>>,
    capability_delegation: Option<Either<HashSafeHashSet<VerificationMethod>, URL>>,
    service: Option<HashSafeHashSet<ServiceEndpoint>>,
}
