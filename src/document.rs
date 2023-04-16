use crate::{did::DID, hash::HashSafeHashSet, url::URL};
use either::Either;
use serde::{Deserialize, Serialize};
use url::Url;

#[derive(Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationMethod {
    id: URL,
    controller: DID,
    typ: String,
    public_key_jwk: Option<jsonwebtoken::jwk::Jwk>,
    // multibase is a format:
    // https://datatracker.ietf.org/doc/html/draft-multiformats-multibase-03
    public_key_multibase: Option<String>,
}

#[derive(Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceEndpoint {
    id: Url,
    typ: Either<String, HashSafeHashSet<String>>,
    endpoint: Either<Url, HashSafeHashSet<Url>>,
}

#[allow(dead_code)]
#[derive(Hash, PartialEq, Eq, Serialize, Deserialize)]
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
