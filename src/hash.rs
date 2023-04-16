#![allow(dead_code)]
use anyhow::anyhow;
use serde::{Deserialize, Serialize};
use std::{
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
};

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct OrderedHashSet<T: Hash + Eq> {
    data: Vec<T>,
    hashes: Vec<u64>,
    iter: usize,
}

impl<T: Eq + Hash + PartialOrd> PartialOrd for OrderedHashSet<T> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        for item in self.data.iter() {
            for otheritem in other.data.iter() {
                match item.partial_cmp(otheritem) {
                    None => {}
                    Some(y) => return Some(y),
                }
            }
        }

        None
    }
}

impl<T: Eq + Hash + PartialOrd + Clone> Hash for OrderedHashSet<T> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H)
    where
        T: Eq + Hash,
    {
        let mut v = self.data.clone();
        sort::quicksort(&mut v);
        for item in v {
            item.hash(state);
        }
    }
}

impl<T: Clone + Eq + Hash + PartialOrd> Iterator for OrderedHashSet<T> {
    type Item = T;

    fn next(&mut self) -> Option<Self::Item> {
        let data = self.data.get(self.iter);
        self.iter += 1;
        data.cloned()
    }
}

impl<T: Clone + Eq + Hash + PartialOrd> OrderedHashSet<T> {
    pub fn new() -> Self {
        Self {
            data: Vec::new(),
            hashes: Vec::new(),
            iter: 0,
        }
    }

    pub fn insert(&mut self, item: &T) -> Result<T, anyhow::Error> {
        let mut hasher = DefaultHasher::default();
        item.hash(&mut hasher);
        let hash = hasher.finish();

        if self.hashes.contains(&hash) {
            Err(anyhow!("hash set already has this value"))
        } else {
            self.hashes.push(hash);
            self.data.push(item.clone());

            Ok(item.clone())
        }
    }

    pub fn delete(&mut self, item: T) {
        let mut hasher = DefaultHasher::default();
        item.hash(&mut hasher);
        let hash = hasher.finish();

        self.hashes.retain(|arg| arg != &hash);
        self.data.retain(|arg| !arg.eq(&item));
    }

    pub fn to_vec(&self) -> Vec<T> {
        self.data.clone()
    }
}
