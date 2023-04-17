use crate::{did::DID, jwk::JWK, multibase::MultiBase, url::URL};
use anyhow::anyhow;
use either::Either;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use url::Url;

#[derive(Clone, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
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

#[derive(Clone, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct VerificationMethod {
    id: URL,
    controller: DID,
    #[serde(rename = "type")]
    typ: VerificationMethodType,
    #[serde(rename = "publicKeyJwk")]
    public_key_jwk: Option<JWK>,
    #[serde(rename = "publicKeyMultibase")]
    public_key_multibase: Option<MultiBase>,
}

impl VerificationMethod {
    pub fn id(&self) -> URL {
        self.id.clone()
    }

    pub fn controller(&self) -> DID {
        self.controller.clone()
    }

    pub fn verification_type(&self) -> VerificationMethodType {
        self.typ.clone()
    }

    pub fn public_key_jwk(&self) -> Option<JWK> {
        self.public_key_jwk.clone()
    }

    pub fn public_key_multibase(&self) -> Option<MultiBase> {
        self.public_key_multibase.clone()
    }

    pub fn validate(&self) -> Result<(), anyhow::Error> {
        if self.public_key_jwk.is_some() && self.public_key_multibase.is_some() {
            return Err(anyhow!(
                "Verification method {} provided both JWK and multibase keys",
                self.id
            ));
        }

        Ok(())
    }
}

#[derive(Clone, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
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

#[derive(Clone, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ServiceEndpoint {
    id: Url,
    #[serde(rename = "type")]
    typ: Either<ServiceType, BTreeSet<ServiceType>>,
    #[serde(rename = "serviceEndpoint")]
    endpoint: Either<Url, BTreeSet<Url>>,
}

impl ServiceEndpoint {
    pub fn id(&self) -> Url {
        self.id.clone()
    }

    pub fn service_type(&self) -> Either<ServiceType, BTreeSet<ServiceType>> {
        self.typ.clone()
    }

    pub fn endpoint(&self) -> Either<Url, BTreeSet<Url>> {
        self.endpoint.clone()
    }
}

#[allow(dead_code)]
#[derive(Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Document {
    #[serde(rename = "@context")]
    context: Option<Either<Url, BTreeSet<Url>>>,
    id: DID,
    #[serde(rename = "alsoKnownAs")]
    also_known_as: Option<BTreeSet<Url>>,
    controller: Option<Either<DID, BTreeSet<DID>>>,
    #[serde(rename = "verificationMethod")]
    verification_method: Option<BTreeSet<VerificationMethod>>,
    authentication: Option<BTreeSet<Either<VerificationMethod, URL>>>,
    #[serde(rename = "assertionMethod")]
    assertion_method: Option<BTreeSet<Either<VerificationMethod, URL>>>,
    #[serde(rename = "keyAgreement")]
    key_agreement: Option<BTreeSet<Either<VerificationMethod, URL>>>,
    #[serde(rename = "capabilityInvocation")]
    capability_invocation: Option<BTreeSet<Either<VerificationMethod, URL>>>,
    #[serde(rename = "capabilityDelegation")]
    capability_delegation: Option<BTreeSet<Either<VerificationMethod, URL>>>,
    service: Option<BTreeSet<ServiceEndpoint>>,
}

impl Document {
    pub fn context(&self) -> Option<Either<Url, BTreeSet<Url>>> {
        self.context.clone()
    }

    pub fn id(&self) -> DID {
        self.id.clone()
    }

    pub fn also_known_as(&self) -> Option<BTreeSet<Url>> {
        self.also_known_as.clone()
    }

    pub fn controller(&self) -> Option<Either<DID, BTreeSet<DID>>> {
        self.controller.clone()
    }

    pub fn verification_method(&self) -> Option<BTreeSet<VerificationMethod>> {
        self.verification_method.clone()
    }

    pub fn authentication(&self) -> Option<BTreeSet<Either<VerificationMethod, URL>>> {
        self.authentication.clone()
    }

    pub fn assertion_method(&self) -> Option<BTreeSet<Either<VerificationMethod, URL>>> {
        self.assertion_method.clone()
    }

    pub fn key_agreement(&self) -> Option<BTreeSet<Either<VerificationMethod, URL>>> {
        self.key_agreement.clone()
    }

    pub fn capability_invocation(&self) -> Option<BTreeSet<Either<VerificationMethod, URL>>> {
        self.capability_invocation.clone()
    }

    pub fn capability_delegation(&self) -> Option<BTreeSet<Either<VerificationMethod, URL>>> {
        self.capability_delegation.clone()
    }

    pub fn service(&self) -> Option<BTreeSet<ServiceEndpoint>> {
        self.service.clone()
    }

    pub fn validate(&self) -> Result<(), anyhow::Error> {
        if let Some(vm) = &self.verification_method {
            for v in vm.iter() {
                v.validate()?;
            }
        }

        // these are all basically the same, call the inner verification method, or do something
        // with the DID URL.
        for field in vec![
            &self.authentication,
            &self.assertion_method,
            &self.key_agreement,
            &self.capability_invocation,
            &self.capability_delegation,
        ] {
            if let Some(vm) = &field {
                for v in vm.iter() {
                    match v {
                        Either::Left(vm) => vm.validate()?,
                        Either::Right(_url) => { /* probably need to do something here */ }
                    }
                }
            }
        }

        Ok(())
    }
}
