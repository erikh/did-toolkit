use crate::{did::DID, jwk::JWK, multibase::MultiBase, url::URL};
use anyhow::anyhow;
use either::Either;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, fmt::Display, hash::Hash};
use url::Url;

#[derive(Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
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

#[derive(Clone, Debug, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct VerificationMethod {
    pub(crate) id: URL,
    pub(crate) controller: DID,
    #[serde(rename = "type")]
    pub(crate) typ: VerificationMethodType,
    #[serde(rename = "publicKeyJwk")]
    pub(crate) public_key_jwk: Option<JWK>,
    #[serde(rename = "publicKeyMultibase")]
    pub(crate) public_key_multibase: Option<MultiBase>,
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
        self.id().hash(state)
    }
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

#[derive(Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ServiceType {
    CredentialRegistry,
}

impl Display for ServiceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::CredentialRegistry => "CredentialRegistry",
        })
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ServiceEndpoint {
    pub(crate) id: Url,
    #[serde(rename = "type")]
    pub(crate) typ: Either<ServiceType, BTreeSet<ServiceType>>,
    #[serde(rename = "serviceEndpoint")]
    pub(crate) endpoint: Either<Url, BTreeSet<Url>>,
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

#[derive(Clone, Debug, Default, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct VerificationMethods(Option<BTreeSet<Either<VerificationMethod, URL>>>);

impl VerificationMethods {
    pub fn valid(&self) -> Result<(), anyhow::Error> {
        if let Some(vm) = &self.0 {
            for v in vm.iter() {
                match v {
                    Either::Left(vm) => vm.valid()?,
                    Either::Right(_url) => {
                        todo!()
                    }
                }
            }
        }

        Ok(())
    }
}

#[allow(dead_code)]
#[derive(Clone, Debug, Default, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Document {
    #[serde(rename = "@context")]
    pub(crate) context: Option<Either<Url, BTreeSet<Url>>>,
    pub(crate) id: DID,
    #[serde(rename = "alsoKnownAs")]
    pub(crate) also_known_as: Option<BTreeSet<Either<DID, Url>>>,
    pub(crate) controller: Option<Either<DID, BTreeSet<DID>>>,
    #[serde(rename = "verificationMethod")]
    pub(crate) verification_method: Option<BTreeSet<VerificationMethod>>,
    pub(crate) authentication: VerificationMethods,
    #[serde(rename = "assertionMethod")]
    pub(crate) assertion_method: VerificationMethods,
    #[serde(rename = "keyAgreement")]
    pub(crate) key_agreement: VerificationMethods,
    #[serde(rename = "capabilityInvocation")]
    pub(crate) capability_invocation: VerificationMethods,
    #[serde(rename = "capabilityDelegation")]
    pub(crate) capability_delegation: VerificationMethods,
    pub(crate) service: Option<BTreeSet<ServiceEndpoint>>,
}

impl Document {
    pub fn context(&self) -> Option<Either<Url, BTreeSet<Url>>> {
        self.context.clone()
    }

    pub fn id(&self) -> DID {
        self.id.clone()
    }

    pub fn also_known_as(&self) -> Option<BTreeSet<Either<DID, Url>>> {
        self.also_known_as.clone()
    }

    pub fn controller(&self) -> Option<Either<DID, BTreeSet<DID>>> {
        self.controller.clone()
    }

    pub fn verification_method(&self) -> Option<BTreeSet<VerificationMethod>> {
        self.verification_method.clone()
    }

    pub fn authentication(&self) -> VerificationMethods {
        self.authentication.clone()
    }

    pub fn assertion_method(&self) -> VerificationMethods {
        self.assertion_method.clone()
    }

    pub fn key_agreement(&self) -> VerificationMethods {
        self.key_agreement.clone()
    }

    pub fn capability_invocation(&self) -> VerificationMethods {
        self.capability_invocation.clone()
    }

    pub fn capability_delegation(&self) -> VerificationMethods {
        self.capability_delegation.clone()
    }

    pub fn service(&self) -> Option<BTreeSet<ServiceEndpoint>> {
        self.service.clone()
    }

    pub fn valid(&self) -> Result<(), anyhow::Error> {
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
            field.valid()?
        }

        Ok(())
    }
}
