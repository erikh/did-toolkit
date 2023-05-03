use josekit::jwk::{alg::ec::EcCurve, Jwk};
use serde::{Deserialize, Serialize};
use std::hash::{Hash, Hasher};

/// Encapsulation of JSON Web Keys, provided by the [josekit] crate underneath. Serialization
/// omits the private key fields deliberately according to DID spec, as it is assumed for these
/// purposes it will be used in a decentralized identity document.
///
/// See <https://www.w3.org/TR/did-core/#verification-material> for more information.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct JWK(pub Jwk);

impl JWK {
    /// Creates a new JWK and generates a key for it. The underlying key will have private key
    /// material.
    pub fn new() -> Result<Self, anyhow::Error> {
        Ok(JWK(Jwk::generate_ec_key(EcCurve::P256)?))
    }

    /// Creates a new JWK struct from an existing series of bytes
    pub fn new_from_bytes(bytes: &[u8]) -> Result<Self, anyhow::Error> {
        Ok(JWK(Jwk::from_bytes(bytes)?))
    }

    /// Erases the private key material and creates a new struct from the result.
    pub fn to_public_only(&self) -> Result<Self, anyhow::Error> {
        Ok(JWK(self.0.to_public_key()?))
    }
}

impl Serialize for JWK {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self.to_public_only() {
            Ok(public) => public.0.serialize(serializer),
            Err(e) => Err(serde::ser::Error::custom(e)),
        }
    }
}

impl Hash for JWK {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.key_id().hash(state)
    }
}

impl PartialOrd for JWK {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        let mut state = std::collections::hash_map::DefaultHasher::default();
        let mut other_state = std::collections::hash_map::DefaultHasher::default();
        self.hash(&mut state);
        other.hash(&mut other_state);

        state.finish().partial_cmp(&other_state.finish())
    }
}

impl Ord for JWK {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.partial_cmp(other).unwrap()
    }
}
