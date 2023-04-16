use std::collections::HashSet;

use crate::{did::DID, either::Either, url::URL};

#[derive(Hash, PartialEq, Eq)]
struct VerificationMethod {
    id: DID,
}

#[derive(Hash, PartialEq, Eq)]
struct ServiceEndpoint {}

#[allow(dead_code)]
struct Document {
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
