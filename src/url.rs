use anyhow::anyhow;
use std::collections::BTreeMap;
use time::{
    format_description::FormatItem, macros::format_description, OffsetDateTime, PrimitiveDateTime,
};

use crate::string::{url_decoded, url_encoded, validate_method_name};

static VERSION_TIME_FORMAT: &[FormatItem<'static>] =
    format_description!("[year]-[month]-[day]T[hour]:[minute]:[second]");

#[derive(Default, Debug, PartialEq)]
pub struct URL {
    pub name: Vec<u8>,
    pub method: Vec<u8>,
    pub path: Option<Vec<u8>>,
    pub fragment: Option<Vec<u8>>,
    pub service: Option<String>,
    pub relative_ref: Option<Vec<u8>>,
    pub version_id: Option<String>,
    pub version_time: Option<OffsetDateTime>,
    pub hash_link: Option<String>,
    pub extra_query: Option<BTreeMap<Vec<u8>, Vec<u8>>>,
}

impl ToString for URL {
    fn to_string(&self) -> String {
        let mut ret = String::from("did:");

        ret += &url_encoded(&self.name);
        ret += &(":".to_string() + &url_encoded(&self.method));

        if let Some(path) = &self.path {
            ret += &("/".to_string() + &url_encoded(path));
        }

        if self.service.is_some()
            || self.relative_ref.is_some()
            || self.version_id.is_some()
            || self.version_time.is_some()
            || self.hash_link.is_some()
            || self.extra_query.is_some()
        {
            ret += "?";

            if let Some(service) = &self.service {
                ret += &("service=".to_string() + service);
                ret += "&";
            }

            if let Some(relative_ref) = &self.relative_ref {
                ret += &("relativeRef=".to_string() + &url_encoded(relative_ref));
                ret += "&";
            }

            if let Some(version_id) = &self.version_id {
                ret += &("versionId=".to_string() + version_id);
                ret += "&";
            }

            if let Some(version_time) = self.version_time {
                ret += &("versionTime=".to_string()
                    + &format!(
                        "{}-{:02}-{:02}T{:02}:{:02}:{:02}",
                        version_time.year(),
                        u8::from(version_time.month()),
                        version_time.day(),
                        version_time.hour(),
                        version_time.minute(),
                        version_time.second()
                    ));
                ret += "&";
            }

            if let Some(hash_link) = &self.hash_link {
                ret += &("hl=".to_string() + hash_link);
                ret += "&";
            }

            if let Some(extra_query) = &self.extra_query {
                for (key, value) in extra_query.iter() {
                    ret += &format!("{}={}&", url_encoded(key), url_encoded(value));
                }
            }

            ret = match ret.strip_suffix('&') {
                Some(ret) => ret.to_string(),
                None => ret,
            };
        }

        if let Some(fragment) = &self.fragment {
            ret += &("#".to_string() + &url_encoded(fragment));
        }

        ret
    }
}

impl URL {
    pub fn parse(s: &str) -> Result<Self, anyhow::Error> {
        match s.strip_prefix("did:") {
            Some(s) => match s.split_once(':') {
                Some((method_name, right)) => match right.split_once('/') {
                    Some((method_id, path)) => Self::match_path(
                        method_name.as_bytes(),
                        method_id.as_bytes(),
                        path.as_bytes(),
                    ),
                    None => match right.split_once('?') {
                        Some((method_id, query)) => Self::match_query(
                            method_name.as_bytes(),
                            method_id.as_bytes(),
                            None,
                            query.as_bytes(),
                        ),
                        None => match right.split_once('#') {
                            Some((method_id, fragment)) => Self::match_fragment(
                                method_name.as_bytes(),
                                method_id.as_bytes(),
                                None,
                                None,
                                fragment.as_bytes(),
                            ),
                            None => {
                                validate_method_name(method_name.as_bytes())?;

                                Ok(URL {
                                    name: url_decoded(method_name.as_bytes()),
                                    method: url_decoded(right.as_bytes()),
                                    ..Default::default()
                                })
                            }
                        },
                    },
                },
                None => return Err(anyhow!("DID did not contain method specific ID")),
            },
            None => return Err(anyhow!("DID did not start with `did:` scheme")),
        }
    }

    pub fn join(&self, s: &str) -> Result<Self, anyhow::Error> {
        if s.is_empty() {
            return Err(anyhow!("relative DID URL is empty"));
        }

        match s.chars().next().unwrap() {
            '/' => Self::match_path(&self.name, &self.method, &s.as_bytes()[1..]),
            '?' => Self::match_query(&self.name, &self.method, None, &s.as_bytes()[1..]),
            '#' => Self::match_fragment(&self.name, &self.method, None, None, &s.as_bytes()[1..]),
            _ => Err(anyhow!("DID URL is not relative or is malformed")),
        }
    }

    #[inline]
    fn match_path(
        method_name: &[u8],
        method_id: &[u8],
        left: &[u8],
    ) -> Result<Self, anyhow::Error> {
        let item = String::from_utf8_lossy(left);

        match item.split_once('?') {
            Some((path, query)) => Self::match_query(
                method_name,
                method_id,
                Some(path.as_bytes()),
                query.as_bytes(),
            ),
            None => match item.split_once('#') {
                Some((path, fragment)) => Self::match_fragment(
                    method_name,
                    method_id,
                    Some(path.as_bytes()),
                    None,
                    fragment.as_bytes(),
                ),
                None => {
                    validate_method_name(method_name)?;

                    Ok(URL {
                        name: url_decoded(method_name),
                        method: url_decoded(method_id),
                        path: Some(url_decoded(left)),
                        ..Default::default()
                    })
                }
            },
        }
    }

    #[inline]
    fn match_fragment(
        method_name: &[u8],
        method_id: &[u8],
        path: Option<&[u8]>,
        query: Option<&[u8]>,
        fragment: &[u8],
    ) -> Result<Self, anyhow::Error> {
        validate_method_name(method_name)?;

        let mut url = URL {
            name: url_decoded(method_name),
            method: url_decoded(method_id),
            fragment: Some(url_decoded(fragment)),
            path: path.map(url_decoded),
            ..Default::default()
        };

        if query.is_some() {
            url.parse_query(query.unwrap())?;
        }

        Ok(url)
    }

    #[inline]
    fn match_query(
        method_name: &[u8],
        method_id: &[u8],
        path: Option<&[u8]>,
        query: &[u8],
    ) -> Result<Self, anyhow::Error> {
        let item = String::from_utf8_lossy(query);

        match item.split_once('#') {
            Some((query, fragment)) => Self::match_fragment(
                method_name,
                method_id,
                path,
                Some(query.as_bytes()),
                fragment.as_bytes(),
            ),
            None => {
                validate_method_name(method_name)?;

                let mut url = URL {
                    name: url_decoded(method_name),
                    method: url_decoded(method_id),
                    path: path.map(url_decoded),
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
        left: &[u8],
        right: &[u8],
        extra_query: &mut BTreeMap<Vec<u8>, Vec<u8>>,
    ) -> Result<(), anyhow::Error> {
        let item = String::from_utf8(left.to_vec())?;

        match item.as_str() {
            "service" => self.service = Some(String::from_utf8(right.to_vec())?),
            "relativeRef" => {
                self.relative_ref = Some(url_decoded(right));
            }
            "versionId" => self.version_id = Some(String::from_utf8(right.to_vec())?),
            "versionTime" => {
                let dt = PrimitiveDateTime::parse(
                    &String::from_utf8(right.to_vec())?,
                    VERSION_TIME_FORMAT,
                )?;
                self.version_time = Some(dt.assume_utc());
            }
            "hl" => self.hash_link = Some(String::from_utf8(right.to_vec())?),
            _ => {
                extra_query.insert(url_decoded(left), url_decoded(right));
            }
        }

        Ok(())
    }

    #[inline]
    fn parse_query(&mut self, query: &[u8]) -> Result<(), anyhow::Error> {
        let mut extra_query = BTreeMap::new();

        let item = String::from_utf8(query.to_vec())?;

        if !item.contains('&') {
            match item.split_once('=') {
                Some((left, right)) => {
                    self.match_fixed_query_params(
                        left.as_bytes(),
                        right.as_bytes(),
                        &mut extra_query,
                    )?;
                }
                None => {
                    extra_query.insert(url_decoded(query), Default::default());
                }
            }
        } else {
            for part in item.split('&') {
                match part.split_once('=') {
                    Some((left, right)) => {
                        self.match_fixed_query_params(
                            left.as_bytes(),
                            right.as_bytes(),
                            &mut extra_query,
                        )?;
                    }
                    None => {
                        extra_query.insert(url_decoded(part.as_bytes()), Default::default());
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
    fn test_join() {
        use super::URL;

        let url = URL {
            name: "abcdef".into(),
            method: "123456".into(),
            ..Default::default()
        };

        assert!(url.join("").is_err());

        assert_eq!(
            url.join("#fragment").unwrap().to_string(),
            "did:abcdef:123456#fragment"
        );

        assert_eq!(
            url.join("?service=frobnik").unwrap().to_string(),
            "did:abcdef:123456?service=frobnik"
        );

        assert_eq!(
            url.join("?service=frobnik#fragment").unwrap().to_string(),
            "did:abcdef:123456?service=frobnik#fragment"
        );

        assert_eq!(
            url.join("/path?service=frobnik#fragment")
                .unwrap()
                .to_string(),
            "did:abcdef:123456/path?service=frobnik#fragment"
        );
    }

    #[test]
    fn test_to_string() {
        use super::URL;
        use std::collections::BTreeMap;
        use time::OffsetDateTime;

        let url = URL {
            name: "abcdef".into(),
            method: "123456".into(),
            ..Default::default()
        };

        assert_eq!(url.to_string(), "did:abcdef:123456");

        let url = URL {
            name: "abcdef".into(),
            method: "123456".into(),
            path: Some("path".into()),
            ..Default::default()
        };

        assert_eq!(url.to_string(), "did:abcdef:123456/path");

        let url = URL {
            name: "abcdef".into(),
            method: "123456".into(),
            fragment: Some("fragment".into()),
            ..Default::default()
        };

        assert_eq!(url.to_string(), "did:abcdef:123456#fragment");

        let url = URL {
            name: "abcdef".into(),
            method: "123456".into(),
            path: Some("path".into()),
            fragment: Some("fragment".into()),
            ..Default::default()
        };

        assert_eq!(url.to_string(), "did:abcdef:123456/path#fragment");

        let url = URL {
            name: "abcdef".into(),
            method: "123456".into(),
            service: Some("frobnik".into()),
            ..Default::default()
        };

        assert_eq!(url.to_string(), "did:abcdef:123456?service=frobnik");

        let url = URL {
            name: "abcdef".into(),
            method: "123456".into(),
            service: Some("frobnik".into()),
            relative_ref: Some("/ref".into()),
            ..Default::default()
        };

        assert_eq!(
            url.to_string(),
            "did:abcdef:123456?service=frobnik&relativeRef=%2Fref"
        );

        let url = URL {
            name: "abcdef".into(),
            method: "123456".into(),
            service: Some("frobnik".into()),
            relative_ref: Some("/ref".into()),
            version_id: Some("1".into()),
            ..Default::default()
        };

        assert_eq!(
            url.to_string(),
            "did:abcdef:123456?service=frobnik&relativeRef=%2Fref&versionId=1"
        );

        let url = URL {
            name: "abcdef".into(),
            method: "123456".into(),
            service: Some("frobnik".into()),
            relative_ref: Some("/ref".into()),
            version_id: Some("1".into()),
            hash_link: Some("myhash".into()),
            ..Default::default()
        };

        assert_eq!(
            url.to_string(),
            "did:abcdef:123456?service=frobnik&relativeRef=%2Fref&versionId=1&hl=myhash",
        );

        let mut map = BTreeMap::new();
        map.insert("extra".into(), "parameter".into());

        let url = URL {
            name: "abcdef".into(),
            method: "123456".into(),
            service: Some("frobnik".into()),
            relative_ref: Some("/ref".into()),
            version_id: Some("1".into()),
            hash_link: Some("myhash".into()),
            extra_query: Some(map),
            ..Default::default()
        };

        assert_eq!(
            url.to_string(),
            "did:abcdef:123456?service=frobnik&relativeRef=%2Fref&versionId=1&hl=myhash&extra=parameter",
        );

        let mut map = BTreeMap::new();
        map.insert("extra".into(), "".into());

        let url = URL {
            name: "abcdef".into(),
            method: "123456".into(),
            service: Some("frobnik".into()),
            relative_ref: Some("/ref".into()),
            version_id: Some("1".into()),
            hash_link: Some("myhash".into()),
            extra_query: Some(map),
            ..Default::default()
        };

        assert_eq!(
            url.to_string(),
            "did:abcdef:123456?service=frobnik&relativeRef=%2Fref&versionId=1&hl=myhash&extra=",
        );

        let mut map = BTreeMap::new();
        map.insert("extra".into(), "parameter".into());

        let url = URL {
            name: "abcdef".into(),
            method: "123456".into(),
            extra_query: Some(map),
            ..Default::default()
        };

        assert_eq!(url.to_string(), "did:abcdef:123456?extra=parameter",);

        let mut map = BTreeMap::new();
        map.insert("extra".into(), "".into());

        let url = URL {
            name: "abcdef".into(),
            method: "123456".into(),
            extra_query: Some(map),
            ..Default::default()
        };

        assert_eq!(url.to_string(), "did:abcdef:123456?extra=",);

        let url = URL {
            name: "abcdef".into(),
            method: "123456".into(),
            path: Some("path".into()),
            fragment: Some("fragment".into()),
            service: Some("frobnik".into()),
            relative_ref: Some("/ref".into()),
            version_id: Some("1".into()),
            hash_link: Some("myhash".into()),
            ..Default::default()
        };

        assert_eq!(
            url.to_string(),
            "did:abcdef:123456/path?service=frobnik&relativeRef=%2Fref&versionId=1&hl=myhash#fragment",
        );

        let url = URL {
            name: "abcdef".into(),
            method: "123456".into(),
            path: Some("path".into()),
            fragment: Some("fragment".into()),
            service: Some("frobnik".into()),
            relative_ref: Some("/ref".into()),
            version_id: Some("1".into()),
            version_time: Some(OffsetDateTime::from_unix_timestamp(260690400).unwrap()),
            ..Default::default()
        };

        assert_eq!(
            url.to_string(),
            "did:abcdef:123456/path?service=frobnik&relativeRef=%2Fref&versionId=1&versionTime=1978-04-06T06:00:00#fragment",
        );
    }

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
