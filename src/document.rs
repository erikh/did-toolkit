use crate::{did::DID, hash::OrderedHashSet, jwk::JWK, multibase::MultiBase, url::URL};
use anyhow::anyhow;
use either::Either;
use serde::{Deserialize, Serialize};
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
    typ: VerificationMethodType,
    public_key_jwk: Option<JWK>,
    public_key_multibase: Option<MultiBase>,
}

impl VerificationMethod {
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
    typ: Either<ServiceType, OrderedHashSet<ServiceType>>,
    endpoint: Either<Url, OrderedHashSet<Url>>,
}

#[allow(dead_code)]
#[derive(Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Document {
    id: DID,
    also_known_as: Option<OrderedHashSet<Url>>,
    controller: Option<Either<DID, OrderedHashSet<DID>>>,
    verification_method: Option<OrderedHashSet<VerificationMethod>>,
    authentication: Option<OrderedHashSet<Either<VerificationMethod, URL>>>,
    assertion_method: Option<OrderedHashSet<Either<VerificationMethod, URL>>>,
    key_agreement: Option<OrderedHashSet<Either<VerificationMethod, URL>>>,
    capability_invocation: Option<OrderedHashSet<Either<VerificationMethod, URL>>>,
    capability_delegation: Option<OrderedHashSet<Either<VerificationMethod, URL>>>,
    service: Option<OrderedHashSet<ServiceEndpoint>>,
}

impl Document {
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
