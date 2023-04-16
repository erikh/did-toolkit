use crate::{did::DID, url::URL};
use either::Either;
use std::collections::HashSet;
use url::Url;

#[derive(PartialEq, Eq)]
pub struct VerificationMethod {
    id: URL,
    controller: DID,
    typ: String,
    public_key_jwk: Option<jsonwebkey::JsonWebKey>,
    // multibase is a format:
    // https://datatracker.ietf.org/doc/html/draft-multiformats-multibase-03
    public_key_multibase: Option<String>,
}

#[derive(PartialEq, Eq)]
pub struct ServiceEndpoint {
    id: Url,
    typ: Either<String, HashSet<String>>,
    endpoint: Either<Url, HashSet<Url>>,
}

#[allow(dead_code)]
pub struct Document {
    id: DID,
    also_known_as: Option<HashSet<String>>,
    controller: Option<Either<DID, HashSet<DID>>>,
    verification_method: Option<HashSet<VerificationMethod>>,
    authentication: Option<Either<HashSet<VerificationMethod>, URL>>,
    assertion_method: Option<Either<HashSet<VerificationMethod>, URL>>,
    key_agreeement: Option<Either<HashSet<VerificationMethod>, URL>>,
    capability_invocation: Option<Either<HashSet<VerificationMethod>, URL>>,
    capability_delegation: Option<Either<HashSet<VerificationMethod>, URL>>,
    service: Option<HashSet<ServiceEndpoint>>,
}
