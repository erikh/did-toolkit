use std::collections::HashSet;

use crate::did::DID;

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
    controller: Option<HashSet<String>>,
    verification_method: Option<HashSet<VerificationMethod>>,
    authentication: Option<HashSet<VerificationMethod>>,
    assertion_method: Option<HashSet<VerificationMethod>>,
    key_agreeement: Option<HashSet<VerificationMethod>>,
    capability_invocation: Option<HashSet<VerificationMethod>>,
    capability_delegation: Option<HashSet<VerificationMethod>>,
    service: Option<HashSet<ServiceEndpoint>>,
}
