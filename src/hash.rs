use serde::{Deserialize, Serialize};
use std::{collections::HashSet, hash::Hash};

#[derive(PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct HashSafeHashSet<T: Hash + Eq>(HashSet<T>);

impl<T: Eq + Hash + PartialOrd> PartialOrd for HashSafeHashSet<T> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        for item in self.0.iter() {
            for otheritem in other.0.iter() {
                match item.partial_cmp(otheritem) {
                    Some(std::cmp::Ordering::Equal) | None => {}
                    Some(y) => return Some(y),
                }
            }
        }

        None
    }
}

impl<T: Eq + Hash + PartialOrd> Hash for HashSafeHashSet<T> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H)
    where
        T: Eq + Hash,
    {
        let mut v = Vec::from_iter(self.0.iter());
        sort::quicksort(&mut v);
        for item in v {
            item.hash(state);
        }
    }
}
