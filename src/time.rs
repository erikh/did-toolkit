use anyhow::anyhow;
use serde::{de::Visitor, Deserialize, Serialize};
use std::fmt::Display;
use time::{
    format_description::FormatItem, macros::format_description, OffsetDateTime, PrimitiveDateTime,
};

static VERSION_TIME_FORMAT: &[FormatItem<'static>] =
    format_description!("[year]-[month]-[day]T[hour]:[minute]:[second]Z");

/// VersionTime is a specific section of the query string in DID [crate::url::URL]s. It is required to be a
/// certain format, based in UTC. See <https://www.w3.org/TR/did-core/#did-parameters> for more
/// information. Formatting is provided by the [time] crate.
#[derive(Clone, Debug, Hash, PartialOrd, Ord, Eq, PartialEq)]
pub struct VersionTime(pub OffsetDateTime);

impl Default for VersionTime {
    fn default() -> Self {
        VersionTime(OffsetDateTime::from_unix_timestamp(0).unwrap())
    }
}

impl Display for VersionTime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&format!(
            "{}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
            self.0.year(),
            u8::from(self.0.month()),
            self.0.day(),
            self.0.hour(),
            self.0.minute(),
            self.0.second()
        ))
    }
}

impl Serialize for VersionTime {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl Visitor<'_> for VersionTime {
    type Value = VersionTime;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("Expecting a datetime in DID specification format")
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        match Self::parse(v) {
            Ok(v) => Ok(v),
            Err(e) => Err(E::custom(e)),
        }
    }
}

impl<'de> Deserialize<'de> for VersionTime {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_str::<VersionTime>(Default::default())
    }
}

impl VersionTime {
    /// Parse a [VersionTime] from string.
    pub fn parse(s: &str) -> Result<Self, anyhow::Error> {
        match PrimitiveDateTime::parse(s, VERSION_TIME_FORMAT) {
            Ok(dt) => Ok(VersionTime(dt.assume_utc())),
            Err(e) => Err(anyhow!(e)),
        }
    }
}
