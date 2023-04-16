use serde::{Deserialize, Serialize};
use std::{collections::HashSet, hash::Hash};

#[derive(PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct HashSafeHashSet<T: Hash + Eq>(HashSet<T>);

impl<T: Eq + Hash> Hash for HashSafeHashSet<T> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H)
    where
        T: Eq + Hash,
    {
        for item in self.0.iter() {
            item.hash(state);
        }
    }
}
