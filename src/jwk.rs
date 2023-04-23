use jsonwebkey::{JsonWebKey, Key};
use serde::{Deserialize, Serialize};
use std::hash::{Hash, Hasher};

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct JWK(pub JsonWebKey);

impl JWK {
    // Creates a new JWK and generates a key
    pub fn new() -> Self {
        JWK(JsonWebKey::new(Key::generate_p256()))
    }

    pub fn new_from_key(key: jsonwebkey::Key) -> Self {
        JWK(JsonWebKey::new(key))
    }

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
