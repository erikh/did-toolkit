use crate::{
    did::DID,
    string::{method_id_encoded, url_decoded, url_encoded, validate_method_name},
    time::VersionTime,
};
use anyhow::anyhow;
use serde::{de::Visitor, Deserialize, Serialize};
use std::{collections::BTreeMap, fmt::Display};

/// DID URL handling, including parsing, (de)-serialization, and manipulation according to
/// <https://www.w3.org/TR/did-core/#did-url-syntax>.
///
/// DID URLs are nothing like hypertext URLs and it is strongly cautioned that you do not treat
/// them as such.
///
/// The struct includes a [DID] as well as optional [URLParameters] to extend the [DID]. Converting
/// to string, formatting for display, or serialization will cause the URL to be generated.
///
/// ```
/// use did_toolkit::prelude::*;
///
/// let url = URL::parse("did:mymethod:alice/path?service=foo#fragment").unwrap();
/// assert_eq!(url, URL {
///     did: DID::parse("did:mymethod:alice").unwrap(),
///     parameters: Some(URLParameters{
///         path: Some("path".as_bytes().to_vec()),
///         fragment: Some("fragment".as_bytes().to_vec()),
///         service: Some("foo".to_string()),
///         ..Default::default()
///     })
/// });
/// let url = URL {
///     did: DID::parse("did:mymethod:bob").unwrap(),
///     parameters: Some(URLParameters{
///         path: Some("path".as_bytes().to_vec()),
///         fragment: Some("fragment".as_bytes().to_vec()),
///         service: Some("bar".to_string()),
///         version_id: Some("1.0".to_string()),
///         ..Default::default()
///     })
/// };
///
/// assert_eq!(url.to_string(), "did:mymethod:bob/path?service=bar&versionId=1.0#fragment");
/// ```
#[derive(Clone, Default, Debug, Hash, PartialOrd, Ord, Eq, PartialEq)]
pub struct URL {
    pub did: DID,
    pub parameters: Option<URLParameters>,
}

/// A struct to encapsulate URL parameters. All members of this struct are optional, liberal use of
/// `..Default::default()` is recommended to couch the extra fields.
///
/// Many parts of this struct are concatenated into the query string, which has unique escaping
/// rules for each special parameter (see <https://www.w3.org/TR/did-core/#did-parameters>). These
/// are handled according to spec and may take [String] or [`Vec<u8>`] depending on needs. Query members
/// that do not match a special field are stuffed in the `extra_query` bucket.
#[derive(Clone, Default, Debug, Hash, PartialOrd, Ord, Eq, PartialEq)]
pub struct URLParameters {
    pub path: Option<Vec<u8>>,
    pub fragment: Option<Vec<u8>>,
    pub service: Option<String>,
    pub relative_ref: Option<Vec<u8>>,
    pub version_id: Option<String>,
    pub version_time: Option<VersionTime>,
    pub hash_link: Option<String>,
    pub extra_query: Option<BTreeMap<Vec<u8>, Vec<u8>>>,
}

impl Serialize for URL {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

struct URLVisitor;

impl Visitor<'_> for URLVisitor {
    type Value = URL;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("Expecting a decentralized identity URL")
    }

    fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        match URL::parse(&v) {
            Ok(url) => Ok(url),
            Err(e) => Err(E::custom(e)),
        }
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        match URL::parse(v) {
            Ok(url) => Ok(url),
            Err(e) => Err(E::custom(e)),
        }
    }
}

impl<'de> Deserialize<'de> for URL {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(URLVisitor)
    }
}

impl Display for URL {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut ret = String::from("did:");

        ret += &url_encoded(&self.did.name);
        ret += &(":".to_string() + &method_id_encoded(&self.did.id));

        if let Some(params) = &self.parameters {
            if let Some(path) = &params.path {
                ret += &("/".to_string() + &url_encoded(path));
            }

            if params.service.is_some()
                || params.relative_ref.is_some()
                || params.version_id.is_some()
                || params.version_time.is_some()
                || params.hash_link.is_some()
                || params.extra_query.is_some()
            {
                ret += "?";

                if let Some(service) = &params.service {
                    ret += &("service=".to_string() + service);
                    ret += "&";
                }

                if let Some(relative_ref) = &params.relative_ref {
                    ret += &("relativeRef=".to_string() + &url_encoded(relative_ref));
                    ret += "&";
                }

                if let Some(version_id) = &params.version_id {
                    ret += &("versionId=".to_string() + version_id);
                    ret += "&";
                }

                if let Some(version_time) = &params.version_time {
                    ret += &("versionTime=".to_string() + &version_time.to_string());
                    ret += "&";
                }

                if let Some(hash_link) = &params.hash_link {
                    ret += &("hl=".to_string() + hash_link);
                    ret += "&";
                }

                if let Some(extra_query) = &params.extra_query {
                    for (key, value) in extra_query.iter() {
                        ret += &format!("{}={}&", url_encoded(key), url_encoded(value));
                    }
                }

                ret = match ret.strip_suffix('&') {
                    Some(ret) => ret.to_string(),
                    None => ret,
                };
            }

            if let Some(fragment) = &params.fragment {
                ret += &("#".to_string() + &url_encoded(fragment));
            }
        }

        f.write_str(&ret)
    }
}

#[inline]
fn before(s: &str, left: char, right: char) -> bool {
    for c in s.chars() {
        if c == left {
            return true;
        } else if c == right {
            return false;
        }
    }

    false
}

impl URL {
    /// Parse a DID URL from string. See [URL] for more information.
    pub fn parse(s: &str) -> Result<Self, anyhow::Error> {
        match s.strip_prefix("did:") {
            Some(s) => match s.split_once(':') {
                Some((method_name, right)) => {
                    if !before(right, '?', '/') && !before(right, '#', '/') {
                        match right.split_once('/') {
                            Some((method_id, path)) => Self::match_path(
                                method_name.as_bytes(),
                                method_id.as_bytes(),
                                path.as_bytes(),
                            ),
                            None => Self::split_query(method_name.as_bytes(), right),
                        }
                    } else if before(right, '?', '#') {
                        Self::split_query(method_name.as_bytes(), right)
                    } else {
                        Self::split_fragment(method_name.as_bytes(), right)
                    }
                }
                None => return Err(anyhow!("DID did not contain method specific ID")),
            },
            None => return Err(anyhow!("DID did not start with `did:` scheme")),
        }
    }

    /// Parse and join a DID URL. If you want to join a URL from [URLParameters], see [DID::join].
    pub fn join(&self, s: &str) -> Result<Self, anyhow::Error> {
        if s.is_empty() {
            return Err(anyhow!("relative DID URL is empty"));
        }

        match s.chars().next().unwrap() {
            '/' => Self::match_path(&self.did.name, &self.did.id, &s.as_bytes()[1..]),
            '?' => Self::match_query(&self.did.name, &self.did.id, None, &s.as_bytes()[1..]),
            '#' => {
                Self::match_fragment(&self.did.name, &self.did.id, None, None, &s.as_bytes()[1..])
            }
            _ => Err(anyhow!("DID URL is not relative or is malformed")),
        }
    }

    /// Converts to the underlying [DID].
    pub fn to_did(&self) -> DID {
        DID {
            name: self.did.name.clone(),
            id: self.did.id.clone(),
        }
    }

    #[inline]
    fn split_query(method_name: &[u8], right: &str) -> Result<Self, anyhow::Error> {
        match right.split_once('?') {
            Some((method_id, query)) => {
                Self::match_query(method_name, method_id.as_bytes(), None, query.as_bytes())
            }
            None => Self::split_fragment(method_name, right),
        }
    }

    #[inline]
    fn split_fragment(method_name: &[u8], right: &str) -> Result<Self, anyhow::Error> {
        match right.split_once('#') {
            Some((method_id, fragment)) => Self::match_fragment(
                method_name,
                method_id.as_bytes(),
                None,
                None,
                fragment.as_bytes(),
            ),
            None => {
                validate_method_name(method_name)?;

                Ok(URL {
                    did: DID {
                        name: url_decoded(method_name),
                        id: url_decoded(right.as_bytes()),
                    },
                    ..Default::default()
                })
            }
        }
    }

    #[inline]
    fn match_path(
        method_name: &[u8],
        method_id: &[u8],
        left: &[u8],
    ) -> Result<Self, anyhow::Error> {
        let item = String::from_utf8_lossy(left);

        if !before(&item, '#', '?') {
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
                            did: DID {
                                name: url_decoded(method_name),
                                id: url_decoded(method_id),
                            },
                            parameters: Some(URLParameters {
                                path: Some(url_decoded(left)),
                                ..Default::default()
                            }),
                        })
                    }
                },
            }
        } else {
            match item.split_once('#') {
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
                        did: DID {
                            name: url_decoded(method_name),
                            id: url_decoded(method_id),
                        },
                        parameters: Some(URLParameters {
                            path: Some(url_decoded(left)),
                            ..Default::default()
                        }),
                    })
                }
            }
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
            did: DID {
                name: url_decoded(method_name),
                id: url_decoded(method_id),
            },
            parameters: Some(URLParameters {
                fragment: Some(url_decoded(fragment)),
                path: path.map(url_decoded),
                ..Default::default()
            }),
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
                    did: DID {
                        name: url_decoded(method_name),
                        id: url_decoded(method_id),
                    },
                    parameters: Some(URLParameters {
                        path: path.map(url_decoded),
                        ..Default::default()
                    }),
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
        if self.parameters.is_none() {
            self.parameters = Some(Default::default());
        }

        let mut params = self.parameters.clone().unwrap();
        let item = String::from_utf8(left.to_vec())?;

        match item.as_str() {
            "service" => params.service = Some(String::from_utf8(right.to_vec())?),
            "relativeRef" => {
                params.relative_ref = Some(url_decoded(right));
            }
            "versionId" => params.version_id = Some(String::from_utf8(right.to_vec())?),
            "versionTime" => {
                params.version_time = Some(VersionTime::parse(&String::from_utf8(right.to_vec())?)?)
            }
            "hl" => params.hash_link = Some(String::from_utf8(right.to_vec())?),
            _ => {
                extra_query.insert(url_decoded(left), url_decoded(right));
            }
        }

        self.parameters = Some(params);

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
            if self.parameters.is_none() {
                self.parameters = Some(Default::default());
            }

            let mut params = self.parameters.clone().unwrap();
            params.extra_query = Some(extra_query.clone());
            self.parameters = Some(params);
        }

        Ok(())
    }
}

mod tests {
    #[test]
    fn test_join() {
        use super::URL;
        use crate::did::DID;

        let url = URL {
            did: DID {
                name: "abcdef".into(),
                id: "123456".into(),
            },
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
        use super::{URLParameters, URL};
        use crate::did::DID;
        use crate::time::VersionTime;
        use std::collections::BTreeMap;
        use time::OffsetDateTime;

        let url = URL {
            did: DID {
                name: "abcdef".into(),
                id: "123456".into(),
            },
            ..Default::default()
        };

        assert_eq!(url.to_string(), "did:abcdef:123456");

        let url = URL {
            did: DID {
                name: "abcdef".into(),
                id: "123456".into(),
            },
            parameters: Some(URLParameters {
                path: Some("path".into()),
                ..Default::default()
            }),
        };

        assert_eq!(url.to_string(), "did:abcdef:123456/path");

        let url = URL {
            did: DID {
                name: "abcdef".into(),
                id: "123456".into(),
            },
            parameters: Some(URLParameters {
                fragment: Some("fragment".into()),
                ..Default::default()
            }),
        };

        assert_eq!(url.to_string(), "did:abcdef:123456#fragment");

        let url = URL {
            did: DID {
                name: "abcdef".into(),
                id: "123456".into(),
            },
            parameters: Some(URLParameters {
                path: Some("path".into()),
                fragment: Some("fragment".into()),
                ..Default::default()
            }),
        };

        assert_eq!(url.to_string(), "did:abcdef:123456/path#fragment");

        let url = URL {
            did: DID {
                name: "abcdef".into(),
                id: "123456".into(),
            },
            parameters: Some(URLParameters {
                service: Some("frobnik".into()),
                ..Default::default()
            }),
        };

        assert_eq!(url.to_string(), "did:abcdef:123456?service=frobnik");

        let url = URL {
            did: DID {
                name: "abcdef".into(),
                id: "123456".into(),
            },
            parameters: Some(URLParameters {
                service: Some("frobnik".into()),
                relative_ref: Some("/ref".into()),
                ..Default::default()
            }),
        };

        assert_eq!(
            url.to_string(),
            "did:abcdef:123456?service=frobnik&relativeRef=%2Fref"
        );

        let url = URL {
            did: DID {
                name: "abcdef".into(),
                id: "123456".into(),
            },
            parameters: Some(URLParameters {
                service: Some("frobnik".into()),
                relative_ref: Some("/ref".into()),
                version_id: Some("1".into()),
                ..Default::default()
            }),
        };

        assert_eq!(
            url.to_string(),
            "did:abcdef:123456?service=frobnik&relativeRef=%2Fref&versionId=1"
        );

        let url = URL {
            did: DID {
                name: "abcdef".into(),
                id: "123456".into(),
            },
            parameters: Some(URLParameters {
                service: Some("frobnik".into()),
                relative_ref: Some("/ref".into()),
                version_id: Some("1".into()),
                hash_link: Some("myhash".into()),
                ..Default::default()
            }),
        };

        assert_eq!(
            url.to_string(),
            "did:abcdef:123456?service=frobnik&relativeRef=%2Fref&versionId=1&hl=myhash",
        );

        let mut map = BTreeMap::new();
        map.insert("extra".into(), "parameter".into());

        let url = URL {
            did: DID {
                name: "abcdef".into(),
                id: "123456".into(),
            },
            parameters: Some(URLParameters {
                service: Some("frobnik".into()),
                relative_ref: Some("/ref".into()),
                version_id: Some("1".into()),
                hash_link: Some("myhash".into()),
                extra_query: Some(map),
                ..Default::default()
            }),
        };

        assert_eq!(
            url.to_string(),
            "did:abcdef:123456?service=frobnik&relativeRef=%2Fref&versionId=1&hl=myhash&extra=parameter",
        );

        let mut map = BTreeMap::new();
        map.insert("extra".into(), "".into());

        let url = URL {
            did: DID {
                name: "abcdef".into(),
                id: "123456".into(),
            },
            parameters: Some(URLParameters {
                service: Some("frobnik".into()),
                relative_ref: Some("/ref".into()),
                version_id: Some("1".into()),
                hash_link: Some("myhash".into()),
                extra_query: Some(map),
                ..Default::default()
            }),
        };

        assert_eq!(
            url.to_string(),
            "did:abcdef:123456?service=frobnik&relativeRef=%2Fref&versionId=1&hl=myhash&extra=",
        );

        let mut map = BTreeMap::new();
        map.insert("extra".into(), "parameter".into());

        let url = URL {
            did: DID {
                name: "abcdef".into(),
                id: "123456".into(),
            },
            parameters: Some(URLParameters {
                extra_query: Some(map),
                ..Default::default()
            }),
        };

        assert_eq!(url.to_string(), "did:abcdef:123456?extra=parameter",);

        let mut map = BTreeMap::new();
        map.insert("extra".into(), "".into());

        let url = URL {
            did: DID {
                name: "abcdef".into(),
                id: "123456".into(),
            },
            parameters: Some(URLParameters {
                extra_query: Some(map),
                ..Default::default()
            }),
        };

        assert_eq!(url.to_string(), "did:abcdef:123456?extra=",);

        let url = URL {
            did: DID {
                name: "abcdef".into(),
                id: "123456".into(),
            },
            parameters: Some(URLParameters {
                path: Some("path".into()),
                fragment: Some("fragment".into()),
                service: Some("frobnik".into()),
                relative_ref: Some("/ref".into()),
                version_id: Some("1".into()),
                hash_link: Some("myhash".into()),
                ..Default::default()
            }),
        };

        assert_eq!(
            url.to_string(),
            "did:abcdef:123456/path?service=frobnik&relativeRef=%2Fref&versionId=1&hl=myhash#fragment",
        );

        let url = URL {
            did: DID {
                name: "abcdef".into(),
                id: "123456".into(),
            },
            parameters: Some(URLParameters {
                path: Some("path".into()),
                fragment: Some("fragment".into()),
                service: Some("frobnik".into()),
                relative_ref: Some("/ref".into()),
                version_id: Some("1".into()),
                version_time: Some(VersionTime(
                    OffsetDateTime::from_unix_timestamp(260690400).unwrap(),
                )),
                ..Default::default()
            }),
        };

        assert_eq!(
            url.to_string(),
            "did:abcdef:123456/path?service=frobnik&relativeRef=%2Fref&versionId=1&versionTime=1978-04-06T06:00:00Z#fragment",
        );

        let url = URL {
            did: DID {
                name: "abcdef".into(),
                id: "123456:mumble:foo".into(),
            },
            ..Default::default()
        };

        assert_eq!(url.to_string(), "did:abcdef:123456:mumble:foo");
    }

    #[test]
    fn test_parse() {
        use super::{URLParameters, URL};
        use crate::did::DID;
        use crate::time::VersionTime;
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
                did: DID {
                    name: "abcdef".into(),
                    id: "123456".into(),
                },
                ..Default::default()
            }
        );

        let url = URL::parse("did:abcdef:123456/path").unwrap();
        assert_eq!(
            url,
            URL {
                did: DID {
                    name: "abcdef".into(),
                    id: "123456".into(),
                },
                parameters: Some(URLParameters {
                    path: Some("path".into()),
                    ..Default::default()
                }),
            }
        );

        let url = URL::parse("did:abcdef:123456#fragment").unwrap();
        assert_eq!(
            url,
            URL {
                did: DID {
                    name: "abcdef".into(),
                    id: "123456".into(),
                },
                parameters: Some(URLParameters {
                    fragment: Some("fragment".into()),
                    ..Default::default()
                }),
            }
        );

        let url = URL::parse("did:abcdef:123456/path#fragment").unwrap();
        assert_eq!(
            url,
            URL {
                did: DID {
                    name: "abcdef".into(),
                    id: "123456".into(),
                },
                parameters: Some(URLParameters {
                    path: Some("path".into()),
                    fragment: Some("fragment".into()),
                    ..Default::default()
                }),
            }
        );

        let url = URL::parse("did:abcdef:123456?service=frobnik").unwrap();
        assert_eq!(
            url,
            URL {
                did: DID {
                    name: "abcdef".into(),
                    id: "123456".into(),
                },
                parameters: Some(URLParameters {
                    service: Some("frobnik".into()),
                    ..Default::default()
                }),
            }
        );

        let url = URL::parse("did:abcdef:123456?service=frobnik&relativeRef=%2Fref").unwrap();
        assert_eq!(
            url,
            URL {
                did: DID {
                    name: "abcdef".into(),
                    id: "123456".into(),
                },
                parameters: Some(URLParameters {
                    service: Some("frobnik".into()),
                    relative_ref: Some("/ref".into()),
                    ..Default::default()
                }),
            }
        );

        let url =
            URL::parse("did:abcdef:123456?service=frobnik&relativeRef=%2Fref&versionId=1").unwrap();
        assert_eq!(
            url,
            URL {
                did: DID {
                    name: "abcdef".into(),
                    id: "123456".into(),
                },
                parameters: Some(URLParameters {
                    service: Some("frobnik".into()),
                    relative_ref: Some("/ref".into()),
                    version_id: Some("1".into()),
                    ..Default::default()
                }),
            }
        );

        let url = URL::parse(
            "did:abcdef:123456?service=frobnik&relativeRef=%2Fref&versionId=1&hl=myhash",
        )
        .unwrap();
        assert_eq!(
            url,
            URL {
                did: DID {
                    name: "abcdef".into(),
                    id: "123456".into(),
                },
                parameters: Some(URLParameters {
                    service: Some("frobnik".into()),
                    relative_ref: Some("/ref".into()),
                    version_id: Some("1".into()),
                    hash_link: Some("myhash".into()),
                    ..Default::default()
                }),
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
                did: DID {
                    name: "abcdef".into(),
                    id: "123456".into(),
                },
                parameters: Some(URLParameters {
                    service: Some("frobnik".into()),
                    relative_ref: Some("/ref".into()),
                    version_id: Some("1".into()),
                    hash_link: Some("myhash".into()),
                    extra_query: Some(map),
                    ..Default::default()
                }),
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
                did: DID {
                    name: "abcdef".into(),
                    id: "123456".into(),
                },
                parameters: Some(URLParameters {
                    service: Some("frobnik".into()),
                    relative_ref: Some("/ref".into()),
                    version_id: Some("1".into()),
                    hash_link: Some("myhash".into()),
                    extra_query: Some(map),
                    ..Default::default()
                }),
            }
        );

        let url = URL::parse("did:abcdef:123456?extra=parameter").unwrap();

        let mut map = BTreeMap::new();
        map.insert("extra".into(), "parameter".into());

        assert_eq!(
            url,
            URL {
                did: DID {
                    name: "abcdef".into(),
                    id: "123456".into(),
                },
                parameters: Some(URLParameters {
                    extra_query: Some(map),
                    ..Default::default()
                }),
            }
        );

        let url = URL::parse("did:abcdef:123456?extra").unwrap();

        let mut map = BTreeMap::new();
        map.insert("extra".into(), "".into());

        assert_eq!(
            url,
            URL {
                did: DID {
                    name: "abcdef".into(),
                    id: "123456".into(),
                },
                parameters: Some(URLParameters {
                    extra_query: Some(map),
                    ..Default::default()
                }),
            }
        );

        let url = URL::parse(
            "did:abcdef:123456/path?service=frobnik&relativeRef=%2Fref&versionId=1&hl=myhash#fragment",
        )
        .unwrap();
        assert_eq!(
            url,
            URL {
                did: DID {
                    name: "abcdef".into(),
                    id: "123456".into(),
                },
                parameters: Some(URLParameters {
                    path: Some("path".into()),
                    fragment: Some("fragment".into()),
                    service: Some("frobnik".into()),
                    relative_ref: Some("/ref".into()),
                    version_id: Some("1".into()),
                    hash_link: Some("myhash".into()),
                    ..Default::default()
                }),
            }
        );

        assert!(URL::parse(
            "did:abcdef:123456/path?service=frobnik&relativeRef=%2Fref&versionId=1&hl=myhash&versionTime=foo#fragment",
        )
        .is_err());

        let url = URL::parse(
            "did:abcdef:123456/path?service=frobnik&relativeRef=%2Fref&versionId=1&hl=myhash&versionTime=1978-04-06T06:00:00Z#fragment",
        )
        .unwrap();

        assert_eq!(
            url,
            URL {
                did: DID {
                    name: "abcdef".into(),
                    id: "123456".into(),
                },
                parameters: Some(URLParameters {
                    path: Some("path".into()),
                    fragment: Some("fragment".into()),
                    service: Some("frobnik".into()),
                    relative_ref: Some("/ref".into()),
                    version_id: Some("1".into()),
                    hash_link: Some("myhash".into()),
                    version_time: Some(VersionTime(
                        OffsetDateTime::from_unix_timestamp(260690400).unwrap()
                    )),
                    ..Default::default()
                }),
            }
        );

        let url = URL::parse("did:abcdef:123456:mumble:foo").unwrap();
        assert_eq!(
            url,
            URL {
                did: DID {
                    name: "abcdef".into(),
                    id: "123456:mumble:foo".into(),
                },
                ..Default::default()
            }
        );

        let url =
            URL::parse("did:example:123?service=agent&relativeRef=/credentials#degree").unwrap();

        assert_eq!(
            url,
            URL {
                did: DID {
                    name: "example".into(),
                    id: "123".into(),
                },
                parameters: Some(URLParameters {
                    service: Some("agent".into()),
                    relative_ref: Some("/credentials".into()),
                    fragment: Some("degree".into()),
                    ..Default::default()
                }),
            }
        );

        let url = URL::parse("did:example:123#/degree").unwrap();
        assert_eq!(
            url,
            URL {
                did: DID {
                    name: "example".into(),
                    id: "123".into(),
                },
                parameters: Some(URLParameters {
                    fragment: Some("/degree".into()),
                    ..Default::default()
                }),
            }
        );

        let url = URL::parse("did:example:123#?degree").unwrap();
        assert_eq!(
            url,
            URL {
                did: DID {
                    name: "example".into(),
                    id: "123".into(),
                },
                parameters: Some(URLParameters {
                    fragment: Some("?degree".into()),
                    ..Default::default()
                }),
            }
        );

        let url = URL::parse("did:example:123/path#?degree").unwrap();
        assert_eq!(
            url,
            URL {
                did: DID {
                    name: "example".into(),
                    id: "123".into(),
                },
                parameters: Some(URLParameters {
                    path: Some("path".into()),
                    fragment: Some("?degree".into()),
                    ..Default::default()
                }),
            }
        );

        let url = URL::parse("did:example:123#?/degree").unwrap();
        assert_eq!(
            url,
            URL {
                did: DID {
                    name: "example".into(),
                    id: "123".into(),
                },
                parameters: Some(URLParameters {
                    fragment: Some("?/degree".into()),
                    ..Default::default()
                }),
            }
        );

        let url = URL::parse("did:123456:123#?/degree").unwrap();
        assert_eq!(
            url,
            URL {
                did: DID {
                    name: "123456".into(),
                    id: "123".into(),
                },
                parameters: Some(URLParameters {
                    fragment: Some("?/degree".into()),
                    ..Default::default()
                }),
            }
        );
    }

    #[test]
    fn test_serde() {
        use super::{URLParameters, URL};
        use crate::did::DID;

        let url: [URL; 1] = serde_json::from_str(r#"["did:123456:123"]"#).unwrap();
        assert_eq!(
            url[0],
            URL {
                did: DID {
                    name: "123456".into(),
                    id: "123".into(),
                },
                ..Default::default()
            }
        );

        assert_eq!(
            serde_json::to_string(&url).unwrap(),
            r#"["did:123456:123"]"#
        );

        let url: [URL; 1] = serde_json::from_str(
            r#"["did:123456:123/path?service=foo&relativeRef=/ref#fragment"]"#,
        )
        .unwrap();
        assert_eq!(
            url[0],
            URL {
                did: DID {
                    name: "123456".into(),
                    id: "123".into(),
                },
                parameters: Some(URLParameters {
                    path: Some("path".into()),
                    service: Some("foo".into()),
                    relative_ref: Some("/ref".into()),
                    fragment: Some("fragment".into()),
                    ..Default::default()
                }),
            }
        );

        assert_eq!(
            serde_json::to_string(&url).unwrap(),
            r#"["did:123456:123/path?service=foo&relativeRef=%2Fref#fragment"]"#,
        );
    }
}
