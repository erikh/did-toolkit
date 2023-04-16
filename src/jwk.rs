use serde::{Deserialize, Serialize};
use std::hash::{Hash, Hasher};

#[derive(Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct JWK(jsonwebtoken::jwk::Jwk);

impl PartialOrd for JWK {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        let mut state = std::collections::hash_map::DefaultHasher::default();
        let mut other_state = std::collections::hash_map::DefaultHasher::default();
        self.0.hash(&mut state);
        other.0.hash(&mut other_state);

        state.finish().partial_cmp(&other_state.finish())
    }
}
