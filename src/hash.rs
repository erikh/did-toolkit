#![allow(dead_code)]
use anyhow::anyhow;
use serde::{Deserialize, Serialize};
use std::{
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
};

#[derive(Default, Clone, PartialEq, Eq, Ord, Serialize, Deserialize)]
pub(crate) struct OrderedHashSet<T: Hash + Eq> {
    data: Vec<T>,
    hashes: Vec<u64>,
}

pub(crate) struct OrderedHashSetIterator<T: Hash + Eq + 'static> {
    set: OrderedHashSet<T>,
    iter: usize,
}

impl<T: Eq + Hash + PartialOrd> PartialOrd for OrderedHashSet<T> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        for item in self.data.iter() {
            for otheritem in other.data.iter() {
                match item.partial_cmp(otheritem) {
                    Some(std::cmp::Ordering::Equal) | None => {}
                    Some(y) => return Some(y),
                }
            }
        }

        Some(std::cmp::Ordering::Equal)
    }
}

impl<T: Eq + Hash + PartialOrd + Ord + Clone> Hash for OrderedHashSet<T> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H)
    where
        T: Eq + Hash,
    {
        let mut v = self.data.clone();
        v.sort();

        for item in v {
            item.hash(state);
        }
    }
}

impl<T: Clone + Eq + Hash + PartialOrd> Iterator for OrderedHashSetIterator<T> {
    type Item = T;

    fn next(&mut self) -> Option<Self::Item> {
        let data = self.set.data.get(self.iter);
        self.iter += 1;
        data.cloned()
    }
}

impl<T: Clone + Eq + Hash + PartialOrd> OrderedHashSet<T> {
    pub fn iter(&self) -> OrderedHashSetIterator<T> {
        OrderedHashSetIterator {
            set: self.clone(),
            iter: 0,
        }
    }

    pub fn insert(&mut self, item: T) -> Result<T, anyhow::Error> {
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

mod tests {
    #[test]
    fn test_basic() {
        use super::OrderedHashSet;

        let mut set: OrderedHashSet<&str> = Default::default();
        set.insert("foo").unwrap();
        set.insert("bar").unwrap();
        assert!(set.insert("foo").is_err());
        assert_eq!(set.to_vec(), vec!["foo", "bar"]);
        set.delete("foo");
        assert_eq!(set.to_vec(), vec!["bar"]);
        assert!(set.insert("foo").is_ok());
        assert_eq!(set.to_vec(), vec!["bar", "foo"]);
    }

    #[test]
    fn test_iterator() {
        use super::OrderedHashSet;

        let mut set: OrderedHashSet<&str> = Default::default();
        set.insert("foo").unwrap();
        set.insert("bar").unwrap();
        set.insert("quux").unwrap();
        set.insert("baz").unwrap();

        let mut iter = set.iter();
        assert_eq!(iter.next(), Some("foo"));
        assert_eq!(iter.next(), Some("bar"));
        assert_eq!(iter.next(), Some("quux"));
        assert_eq!(iter.next(), Some("baz"));
        assert_eq!(iter.next(), None);

        // double iteration
        let mut iter = set.iter();
        assert_eq!(iter.next(), Some("foo"));
        assert_eq!(iter.next(), Some("bar"));
        assert_eq!(iter.next(), Some("quux"));
        assert_eq!(iter.next(), Some("baz"));
        assert_eq!(iter.next(), None);

        let iter = set.iter();
        assert_eq!(
            iter.collect::<Vec<&str>>(),
            vec!["foo", "bar", "quux", "baz"]
        );
    }

    #[test]
    fn test_hash() {
        use super::OrderedHashSet;
        use std::{
            collections::hash_map::DefaultHasher,
            hash::{Hash, Hasher},
        };

        let mut set: OrderedHashSet<&str> = Default::default();
        set.insert("foo").unwrap();
        set.insert("bar").unwrap();
        set.insert("quux").unwrap();
        set.insert("baz").unwrap();

        let mut hasher = DefaultHasher::default();
        set.hash(&mut hasher);
        let hash = hasher.finish();

        for _ in 1..10000 {
            let mut hasher = DefaultHasher::default();
            set.hash(&mut hasher);
            assert_eq!(hasher.finish(), hash);
        }

        set.delete("foo");

        let mut hasher = DefaultHasher::default();
        set.hash(&mut hasher);
        let newhash = hasher.finish();

        assert_ne!(hash, newhash);
    }
}
