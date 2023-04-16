use anyhow::anyhow;
use serde::{de::Visitor, Deserialize, Serialize};
use time::{
    format_description::FormatItem, macros::format_description, OffsetDateTime, PrimitiveDateTime,
};

static VERSION_TIME_FORMAT: &[FormatItem<'static>] =
    format_description!("[year]-[month]-[day]T[hour]:[minute]:[second]");

#[derive(Clone, Debug, Hash, PartialOrd, Eq, PartialEq)]
pub struct VersionTime(pub OffsetDateTime);

impl Default for VersionTime {
    fn default() -> Self {
        VersionTime(OffsetDateTime::from_unix_timestamp(0).unwrap())
    }
}

impl ToString for VersionTime {
    fn to_string(&self) -> String {
        format!(
            "{}-{:02}-{:02}T{:02}:{:02}:{:02}",
            self.0.year(),
            u8::from(self.0.month()),
            self.0.day(),
            self.0.hour(),
            self.0.minute(),
            self.0.second()
        )
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
    pub fn parse(s: &str) -> Result<Self, anyhow::Error> {
        match PrimitiveDateTime::parse(s, VERSION_TIME_FORMAT) {
            Ok(dt) => Ok(VersionTime(dt.assume_utc())),
            Err(e) => Err(anyhow!(e)),
        }
    }
}
