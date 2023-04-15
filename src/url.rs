use anyhow::anyhow;
use std::collections::BTreeMap;
use time::{
    format_description::FormatItem, macros::format_description, OffsetDateTime, PrimitiveDateTime,
};

use crate::string::url_decoded;

static VERSION_TIME_FORMAT: &'static [FormatItem<'static>] =
    format_description!("[year]-[month]-[day]T[hour]:[minute]:[second]");

#[derive(Default, Debug, PartialEq)]
pub struct URL {
    pub method: Vec<u8>,
    pub name: Vec<u8>,
    pub path: Option<Vec<u8>>,
    pub fragment: Option<Vec<u8>>,
    pub service: Option<String>,
    pub relative_ref: Option<String>,
    pub version_id: Option<String>,
    pub version_time: Option<OffsetDateTime>,
    pub hash_link: Option<String>,
    pub extra_query: Option<BTreeMap<String, String>>,
}

impl URL {
    pub fn parse(s: &str) -> Result<Self, anyhow::Error> {
        match s.strip_prefix("did:") {
            Some(s) => match s.split_once(":") {
                Some((method_name, right)) => match right.split_once("/") {
                    Some((method_id, path)) => Self::match_path(method_name, method_id, path),
                    None => match right.split_once("?") {
                        Some((method_id, query)) => {
                            Self::match_query(method_name, method_id, None, query)
                        }
                        None => match right.split_once("#") {
                            Some((method_id, fragment)) => {
                                Self::match_fragment(method_name, method_id, None, None, fragment)
                            }
                            None => Ok(URL {
                                name: url_decoded(method_name),
                                method: url_decoded(right),
                                ..Default::default()
                            }),
                        },
                    },
                },
                None => return Err(anyhow!("DID did not contain method specific ID")),
            },
            None => return Err(anyhow!("DID did not start with `did:` scheme")),
        }
    }

    #[inline]
    fn match_path(method_name: &str, method_id: &str, left: &str) -> Result<Self, anyhow::Error> {
        match left.split_once("?") {
            Some((path, query)) => Self::match_query(method_name, method_id, Some(path), query),
            None => match left.split_once("#") {
                Some((path, fragment)) => {
                    Self::match_fragment(method_name, method_id, Some(path), None, fragment)
                }
                None => Ok(URL {
                    name: url_decoded(method_name),
                    method: url_decoded(method_id),
                    path: Some(url_decoded(left)),
                    ..Default::default()
                }),
            },
        }
    }

    #[inline]
    fn match_fragment(
        method_name: &str,
        method_id: &str,
        path: Option<&str>,
        query: Option<&str>,
        fragment: &str,
    ) -> Result<Self, anyhow::Error> {
        let mut url = URL {
            name: url_decoded(method_name),
            method: url_decoded(method_id),
            fragment: Some(url_decoded(fragment)),
            path: path.and_then(|path| Some(url_decoded(path))),
            ..Default::default()
        };

        if query.is_some() {
            url.parse_query(query.unwrap())?;
        }

        Ok(url)
    }

    #[inline]
    fn match_query(
        method_name: &str,
        method_id: &str,
        path: Option<&str>,
        query: &str,
    ) -> Result<Self, anyhow::Error> {
        match query.split_once("#") {
            Some((query, fragment)) => {
                Self::match_fragment(method_name, method_id, path, Some(query), fragment)
            }
            None => {
                let mut url = URL {
                    name: url_decoded(method_name),
                    method: url_decoded(method_id),
                    path: path.and_then(|path| Some(url_decoded(path))),
                    ..Default::default()
                };

                url.parse_query(query)?;
                Ok(url)
            }
        }
    }

    #[inline]
    fn match_fixed_query_params(
        &mut self,
        left: &str,
        right: &str,
        extra_query: &mut BTreeMap<String, String>,
    ) -> Result<(), anyhow::Error> {
        match left {
            "service" => self.service = Some(right.to_string()),
            "relativeRef" => {
                self.relative_ref = Some(String::from_utf8_lossy(&url_decoded(right)).to_string())
            }
            "versionId" => self.version_id = Some(right.to_string()),
            "versionTime" => {
                let dt = PrimitiveDateTime::parse(right, VERSION_TIME_FORMAT)?;
                self.version_time = Some(dt.assume_utc());
            }
            "hl" => self.hash_link = Some(right.to_string()),
            _ => {
                extra_query.insert(left.to_string(), right.to_string());
            }
        }

        Ok(())
    }

    #[inline]
    fn parse_query(&mut self, query: &str) -> Result<(), anyhow::Error> {
        let mut extra_query = BTreeMap::new();

        if !query.contains("&") {
            match query.split_once("=") {
                Some((left, right)) => {
                    self.match_fixed_query_params(left, right, &mut extra_query)?;
                }
                None => {
                    extra_query.insert(query.to_string(), Default::default());
                }
            }
        } else {
            for part in query.split("&") {
                match part.split_once("=") {
                    Some((left, right)) => {
                        self.match_fixed_query_params(left, right, &mut extra_query)?;
                    }
                    None => {
                        extra_query.insert(part.to_string(), Default::default());
                    }
                }
            }
        }

        if !extra_query.is_empty() {
            self.extra_query = Some(extra_query.clone());
        }

        Ok(())
    }
}

mod tests {

    #[test]
    fn test_parse() {
        use super::URL;
        use std::collections::BTreeMap;
        use time::OffsetDateTime;

        assert!(URL::parse("").is_err());
        assert!(URL::parse("frobnik").is_err());
        assert!(URL::parse("did").is_err());
        assert!(URL::parse("frobnik:").is_err());
        assert!(URL::parse("did:").is_err());
        assert!(URL::parse("did:abcdef").is_err());

        let url = URL::parse("did:abcdef:123456").unwrap();
        assert_eq!(
            url,
            URL {
                name: "abcdef".into(),
                method: "123456".into(),
                ..Default::default()
            }
        );

        let url = URL::parse("did:abcdef:123456/path").unwrap();
        assert_eq!(
            url,
            URL {
                name: "abcdef".into(),
                method: "123456".into(),
                path: Some("path".into()),
                ..Default::default()
            }
        );

        let url = URL::parse("did:abcdef:123456#fragment").unwrap();
        assert_eq!(
            url,
            URL {
                name: "abcdef".into(),
                method: "123456".into(),
                fragment: Some("fragment".into()),
                ..Default::default()
            }
        );

        let url = URL::parse("did:abcdef:123456/path#fragment").unwrap();
        assert_eq!(
            url,
            URL {
                name: "abcdef".into(),
                method: "123456".into(),
                path: Some("path".into()),
                fragment: Some("fragment".into()),
                ..Default::default()
            }
        );

        let url = URL::parse("did:abcdef:123456?service=frobnik").unwrap();
        assert_eq!(
            url,
            URL {
                name: "abcdef".into(),
                method: "123456".into(),
                service: Some("frobnik".into()),
                ..Default::default()
            }
        );

        let url = URL::parse("did:abcdef:123456?service=frobnik&relativeRef=%2Fref").unwrap();
        assert_eq!(
            url,
            URL {
                name: "abcdef".into(),
                method: "123456".into(),
                service: Some("frobnik".into()),
                relative_ref: Some("/ref".into()),
                ..Default::default()
            }
        );

        let url =
            URL::parse("did:abcdef:123456?service=frobnik&relativeRef=%2Fref&versionId=1").unwrap();
        assert_eq!(
            url,
            URL {
                name: "abcdef".into(),
                method: "123456".into(),
                service: Some("frobnik".into()),
                relative_ref: Some("/ref".into()),
                version_id: Some("1".into()),
                ..Default::default()
            }
        );

        let url = URL::parse(
            "did:abcdef:123456?service=frobnik&relativeRef=%2Fref&versionId=1&hl=myhash",
        )
        .unwrap();
        assert_eq!(
            url,
            URL {
                name: "abcdef".into(),
                method: "123456".into(),
                service: Some("frobnik".into()),
                relative_ref: Some("/ref".into()),
                version_id: Some("1".into()),
                hash_link: Some("myhash".into()),
                ..Default::default()
            }
        );

        let url = URL::parse(
            "did:abcdef:123456?service=frobnik&relativeRef=%2Fref&versionId=1&hl=myhash&extra=parameter",
        )
        .unwrap();

        let mut map = BTreeMap::new();
        map.insert("extra".into(), "parameter".into());

        assert_eq!(
            url,
            URL {
                name: "abcdef".into(),
                method: "123456".into(),
                service: Some("frobnik".into()),
                relative_ref: Some("/ref".into()),
                version_id: Some("1".into()),
                hash_link: Some("myhash".into()),
                extra_query: Some(map),
                ..Default::default()
            }
        );

        let url = URL::parse(
            "did:abcdef:123456?service=frobnik&relativeRef=%2Fref&versionId=1&hl=myhash&extra",
        )
        .unwrap();

        let mut map = BTreeMap::new();
        map.insert("extra".into(), "".into());

        assert_eq!(
            url,
            URL {
                name: "abcdef".into(),
                method: "123456".into(),
                service: Some("frobnik".into()),
                relative_ref: Some("/ref".into()),
                version_id: Some("1".into()),
                hash_link: Some("myhash".into()),
                extra_query: Some(map),
                ..Default::default()
            }
        );

        let url = URL::parse("did:abcdef:123456?extra=parameter").unwrap();

        let mut map = BTreeMap::new();
        map.insert("extra".into(), "parameter".into());

        assert_eq!(
            url,
            URL {
                name: "abcdef".into(),
                method: "123456".into(),
                extra_query: Some(map),
                ..Default::default()
            }
        );

        let url = URL::parse("did:abcdef:123456?extra").unwrap();

        let mut map = BTreeMap::new();
        map.insert("extra".into(), "".into());

        assert_eq!(
            url,
            URL {
                name: "abcdef".into(),
                method: "123456".into(),
                extra_query: Some(map),
                ..Default::default()
            }
        );

        let url = URL::parse(
            "did:abcdef:123456/path?service=frobnik&relativeRef=%2Fref&versionId=1&hl=myhash",
        )
        .unwrap();
        assert_eq!(
            url,
            URL {
                name: "abcdef".into(),
                method: "123456".into(),
                path: Some("path".into()),
                service: Some("frobnik".into()),
                relative_ref: Some("/ref".into()),
                version_id: Some("1".into()),
                hash_link: Some("myhash".into()),
                ..Default::default()
            }
        );

        let url = URL::parse(
            "did:abcdef:123456/path?service=frobnik&relativeRef=%2Fref&versionId=1&hl=myhash#fragment",
        )
        .unwrap();
        assert_eq!(
            url,
            URL {
                name: "abcdef".into(),
                method: "123456".into(),
                path: Some("path".into()),
                fragment: Some("fragment".into()),
                service: Some("frobnik".into()),
                relative_ref: Some("/ref".into()),
                version_id: Some("1".into()),
                hash_link: Some("myhash".into()),
                ..Default::default()
            }
        );

        assert!(URL::parse(
            "did:abcdef:123456/path?service=frobnik&relativeRef=%2Fref&versionId=1&hl=myhash&versionTime=foo#fragment",
        )
        .is_err());

        let url = URL::parse(
            "did:abcdef:123456/path?service=frobnik&relativeRef=%2Fref&versionId=1&hl=myhash&versionTime=1978-04-06T06:00:00#fragment",
        )
        .unwrap();

        assert_eq!(
            url,
            URL {
                name: "abcdef".into(),
                method: "123456".into(),
                path: Some("path".into()),
                fragment: Some("fragment".into()),
                service: Some("frobnik".into()),
                relative_ref: Some("/ref".into()),
                version_id: Some("1".into()),
                hash_link: Some("myhash".into()),
                version_time: Some(OffsetDateTime::from_unix_timestamp(260690400).unwrap()),
                ..Default::default()
            }
        );
    }
}
