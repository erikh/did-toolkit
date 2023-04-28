// serde-compatible multibase strings
// multibase is a format:
// https://datatracker.ietf.org/doc/html/draft-multiformats-multibase-03

use serde::{de::Visitor, Deserialize, Serialize};

/// Encapsulates a public key in Multibase format (see
/// https://datatracker.ietf.org/doc/html/draft-multiformats-multibase-03). Multibase is a new
/// compact, serialization-friendly format that is still a draft standard and thus, subject to
/// change. We provide multibase formatting via the [multibase] crate. Private keys are not
/// accounted for.
#[derive(Clone, Debug, Default, Hash, PartialOrd, Ord, PartialEq, Eq)]
pub struct MultiBase(Vec<u8>);

impl Serialize for MultiBase {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&multibase::encode(multibase::Base::Base64, self.0.clone()))
    }
}

impl Visitor<'_> for MultiBase {
    type Value = MultiBase;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("Expecting a multibase-formatted string representation")
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        match multibase::decode(v) {
            Ok((_, val)) => Ok(MultiBase(val)),
            Err(e) => Err(E::custom(e)),
        }
    }
}

impl<'de> Deserialize<'de> for MultiBase {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_str::<MultiBase>(Default::default())
    }
}
