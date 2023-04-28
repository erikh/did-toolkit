use jsonwebkey::{JsonWebKey, Key};
use serde::{Deserialize, Serialize};
use std::hash::{Hash, Hasher};

/// Encapsulation of JSON Web Keys, provided by the [jsonwebkey] crate underneath. Serialization
/// omits the private key fields deliberately according to DID spec, as it is assumed for these
/// purposes it will be used in a decentralized identity document.
///
/// See <https://www.w3.org/TR/did-core/#verification-material> for more information.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct JWK(pub JsonWebKey);

impl JWK {
    /// Creates a new JWK and generates a key for it. The underlying key will have private key
    /// material.
    pub fn new() -> Self {
        JWK(JsonWebKey::new(Key::generate_p256()))
    }

    /// Creates a new JWK struct from an existing [jsonwebkey::Key].
    pub fn new_from_key(key: jsonwebkey::Key) -> Self {
        JWK(JsonWebKey::new(key))
    }

    /// Erases the private key material and creates a new struct from the result.
    pub fn to_public_only(&self) -> Self {
        JWK(JsonWebKey::new(
            self.0.key.to_public().unwrap().into_owned(),
        ))
    }
}

impl Serialize for JWK {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.to_public_only().0.serialize(serializer)
    }
}

impl Hash for JWK {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.key_id.hash(state)
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
