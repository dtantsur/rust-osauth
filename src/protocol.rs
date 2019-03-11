// Copyright 2017 Dmitry Tantsur <divius.inside@gmail.com>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! JSON structures and protocol bits for the Identity V3 API.

#![allow(missing_docs)]

use std::str::FromStr;
use std::sync::Arc;

use chrono::{DateTime, FixedOffset};
use futures::future;
use futures::prelude::*;
use reqwest::{Method, Url};
use serde::de::{DeserializeOwned, Error as DeserError};
use serde::{Deserialize, Deserializer};

use super::request;
use super::services::ServiceType;
use super::url;
use super::{ApiVersion, AuthType, Error, ErrorKind};

#[derive(Clone, Debug, Deserialize)]
pub struct Link {
    #[serde(deserialize_with = "deser_url")]
    pub href: Url,
    pub rel: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct IdAndName {
    pub id: String,
    pub name: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Domain {
    pub name: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct UserAndPassword {
    pub name: String,
    pub password: String,
    pub domain: Domain,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PasswordAuth {
    pub user: UserAndPassword,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PasswordIdentity {
    pub methods: Vec<String>,
    pub password: PasswordAuth,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Project {
    pub name: String,
    pub domain: Domain,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ProjectScope {
    pub project: Project,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ProjectScopedAuth {
    pub identity: PasswordIdentity,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<ProjectScope>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ProjectScopedAuthRoot {
    pub auth: ProjectScopedAuth,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Endpoint {
    pub interface: String,
    pub region: String,
    pub url: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct CatalogRecord {
    #[serde(rename = "type")]
    pub service_type: String,
    pub endpoints: Vec<Endpoint>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct CatalogRoot {
    pub catalog: Vec<CatalogRecord>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Token {
    pub roles: Vec<IdAndName>,
    pub expires_at: DateTime<FixedOffset>,
    pub catalog: Vec<CatalogRecord>,
}

#[derive(Debug, Deserialize)]
pub struct TokenRoot {
    pub token: Token,
}

#[derive(Debug, Deserialize)]
pub struct Version {
    #[serde(deserialize_with = "deser_version")]
    pub id: ApiVersion,
    pub links: Vec<Link>,
    #[serde(deserialize_with = "empty_as_none", default)]
    pub status: Option<String>,
    #[serde(deserialize_with = "empty_as_none", default)]
    pub version: Option<ApiVersion>,
    #[serde(deserialize_with = "empty_as_none", default)]
    pub min_version: Option<ApiVersion>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum Root {
    MultipleVersions { versions: Vec<Version> },
    OneVersion { version: Version },
}

/// Information about API endpoint.
#[derive(Debug)]
pub struct ServiceInfo {
    /// Root endpoint.
    pub root_url: Url,
    /// Major API version.
    pub major_version: Option<ApiVersion>,
    /// Current API version (if supported).
    pub current_version: Option<ApiVersion>,
    /// Minimum API version (if supported).
    pub minimum_version: Option<ApiVersion>,
}

impl Version {
    pub fn is_stable(&self) -> bool {
        if let Some(ref status) = self.status {
            let upper = status.to_uppercase();
            upper == "STABLE" || upper == "CURRENT" || upper == "SUPPORTED"
        } else {
            true
        }
    }

    pub fn into_service_info(self) -> Result<ServiceInfo, Error> {
        let endpoint = match self.links.into_iter().find(|x| &x.rel == "self") {
            Some(link) => link.href,
            None => {
                return Err(Error::new(
                    ErrorKind::InvalidResponse,
                    "Invalid version - missing self link",
                ));
            }
        };

        Ok(ServiceInfo {
            root_url: endpoint,
            major_version: Some(self.id),
            current_version: self.version,
            minimum_version: self.min_version,
        })
    }
}

impl Root {
    /// Fetch versioning root from a URL.
    pub fn fetch(
        catalog_type: &'static str,
        endpoint: Url,
        auth: Arc<AuthType>,
    ) -> impl Future<Item = Root, Error = Error> {
        debug!("Fetching {} service info from {}", catalog_type, endpoint);

        auth.request(Method::GET, endpoint)
            .then(request::fetch_json)
    }

    /// Extract `ServiceInfo` from a version discovery root.
    pub fn into_service_info<Srv: ServiceType>(self, service: Srv) -> Result<ServiceInfo, Error> {
        trace!(
            "Available major versions for {} service: {:?}",
            service.catalog_type(),
            self
        );

        match self {
            Root::OneVersion { version: ver } => {
                if service.major_version_supported(ver.id) {
                    if !ver.is_stable() {
                        warn!(
                            "Using version {:?} of {} API that is not marked as stable",
                            ver,
                            service.catalog_type()
                        );
                    }

                    ver.into_service_info()
                } else {
                    Err(Error::new(
                        ErrorKind::EndpointNotFound,
                        "Major version not supported",
                    ))
                }
            }
            Root::MultipleVersions { versions: mut vers } => {
                vers.sort_unstable_by_key(|x| x.id);
                match vers
                    .into_iter()
                    .rfind(|x| x.is_stable() && service.major_version_supported(x.id))
                {
                    Some(ver) => ver.into_service_info(),
                    None => Err(Error::new_endpoint_not_found(service.catalog_type())),
                }
            }
        }
    }
}

impl ServiceInfo {
    /// Whether this service supports the given API version.
    ///
    /// Defaults to false if cannot be determined.
    #[inline]
    pub fn supports_api_version(&self, version: ApiVersion) -> bool {
        match (self.minimum_version, self.current_version) {
            (Some(min), Some(max)) => min <= version && max >= version,
            (None, Some(current)) => current == version,
            (Some(min), None) => version >= min,
            _ => false,
        }
    }

    /// Generic code to extract a `ServiceInfo` from a URL.
    pub fn fetch<Srv: ServiceType>(
        service: Srv,
        endpoint: Url,
        auth: Arc<AuthType>,
    ) -> impl Future<Item = ServiceInfo, Error = Error> {
        if !service.version_discovery_supported() {
            debug!(
                "Service {} does not support version discovery, using {}",
                service.catalog_type(),
                endpoint
            );
            return future::Either::A(future::ok(ServiceInfo {
                root_url: endpoint,
                major_version: None,
                current_version: None,
                minimum_version: None,
            }));
        }

        // Workaround for old version of Nova returning HTTP endpoints even if
        // accessed via HTTP
        let secure = endpoint.scheme() == "https";
        let catalog_type = service.catalog_type();

        future::Either::B(
            Root::fetch(catalog_type, endpoint.clone(), auth.clone())
                .or_else(move |e| {
                    if e.kind() == ErrorKind::ResourceNotFound {
                        if url::is_root(&endpoint) {
                            let err = Error::new_endpoint_not_found(catalog_type);
                            future::Either::A(future::err(err))
                        } else {
                            debug!("Got HTTP 404 from {}, trying parent endpoint", endpoint);
                            future::Either::B(Root::fetch(
                                catalog_type,
                                url::pop(endpoint, true),
                                auth,
                            ))
                        }
                    } else {
                        future::Either::A(future::err(e))
                    }
                })
                .and_then(|root| root.into_service_info(service))
                .map(move |mut info| {
                    // Older Nova returns insecure URLs even for secure protocol.
                    if secure && info.root_url.scheme() == "http" {
                        info.root_url.set_scheme("https").unwrap();
                    }

                    debug!("Received {:?} for {} service", info, catalog_type);
                    info
                }),
        )
    }
}

const PASSWORD_METHOD: &str = "password";

impl PasswordAuth {
    fn new<S1, S2, S3>(user_name: S1, password: S2, domain_name: S3) -> PasswordAuth
    where
        S1: Into<String>,
        S2: Into<String>,
        S3: Into<String>,
    {
        PasswordAuth {
            user: UserAndPassword {
                name: user_name.into(),
                password: password.into(),
                domain: Domain {
                    name: domain_name.into(),
                },
            },
        }
    }
}

impl PasswordIdentity {
    pub fn new<S1, S2, S3>(user_name: S1, password: S2, domain_name: S3) -> PasswordIdentity
    where
        S1: Into<String>,
        S2: Into<String>,
        S3: Into<String>,
    {
        PasswordIdentity {
            methods: vec![String::from(PASSWORD_METHOD)],
            password: PasswordAuth::new(user_name, password, domain_name),
        }
    }
}

impl ProjectScope {
    pub fn new<S1, S2>(project_name: S1, domain_name: S2) -> ProjectScope
    where
        S1: Into<String>,
        S2: Into<String>,
    {
        ProjectScope {
            project: Project {
                name: project_name.into(),
                domain: Domain {
                    name: domain_name.into(),
                },
            },
        }
    }
}

impl ProjectScopedAuthRoot {
    pub fn new(identity: PasswordIdentity, scope: Option<ProjectScope>) -> ProjectScopedAuthRoot {
        ProjectScopedAuthRoot {
            auth: ProjectScopedAuth { identity, scope },
        }
    }
}

/// Deserialize value where empty string equals None.
pub fn empty_as_none<'de, D, T>(des: D) -> ::std::result::Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: DeserializeOwned,
{
    let value = serde_json::Value::deserialize(des)?;
    match value {
        serde_json::Value::String(ref s) if s == "" => return Ok(None),
        _ => (),
    };

    serde_json::from_value(value).map_err(DeserError::custom)
}

pub fn deser_version<'de, D>(des: D) -> ::std::result::Result<ApiVersion, D::Error>
where
    D: Deserializer<'de>,
{
    let value = String::deserialize(des)?;
    if value.is_empty() {
        return Err(D::Error::custom("Empty version ID"));
    }

    let version_part = if value.starts_with('v') {
        &value[1..]
    } else {
        &value
    };

    ApiVersion::from_str(version_part).map_err(D::Error::custom)
}

/// Deserialize a URL.
pub fn deser_url<'de, D>(des: D) -> ::std::result::Result<Url, D::Error>
where
    D: Deserializer<'de>,
{
    Url::parse(&String::deserialize(des)?).map_err(DeserError::custom)
}

#[cfg(test)]
pub(crate) mod test {
    use reqwest::Url;

    use super::super::services::ServiceType;
    use super::super::ApiVersion;
    use super::super::ErrorKind;
    use super::{Link, Root, Version};

    #[test]
    fn test_version_current_is_stable() {
        let stable = Version {
            id: ApiVersion(2, 0),
            links: Vec::new(),
            status: Some("CURRENT".to_string()),
            version: None,
            min_version: None,
        };
        assert!(stable.is_stable());
    }

    #[test]
    fn test_version_stable_is_stable() {
        let stable = Version {
            id: ApiVersion(2, 0),
            links: Vec::new(),
            status: Some("Stable".to_string()),
            version: None,
            min_version: None,
        };
        assert!(stable.is_stable());
    }

    #[test]
    fn test_version_supported_is_stable() {
        let stable = Version {
            id: ApiVersion(2, 0),
            links: Vec::new(),
            status: Some("supported".to_string()),
            version: None,
            min_version: None,
        };
        assert!(stable.is_stable());
    }

    #[test]
    fn test_version_no_status_is_stable() {
        let stable = Version {
            id: ApiVersion(2, 0),
            links: Vec::new(),
            status: None,
            version: None,
            min_version: None,
        };
        assert!(stable.is_stable());
    }

    #[test]
    fn test_version_deprecated_is_not_stable() {
        let unstable = Version {
            id: ApiVersion(2, 0),
            links: Vec::new(),
            status: Some("DEPRECATED".to_string()),
            version: None,
            min_version: None,
        };
        assert!(!unstable.is_stable());
    }

    #[test]
    fn test_version_into_service_info() {
        let url = Url::parse("https://example.com/v2").unwrap();
        let ver = Version {
            id: ApiVersion(2, 0),
            links: vec![
                Link {
                    href: Url::parse("https://example.com/docs").unwrap(),
                    rel: "other".to_string(),
                },
                Link {
                    href: url.clone(),
                    rel: "self".to_string(),
                },
            ],
            status: None,
            version: Some(ApiVersion(2, 2)),
            min_version: None,
        };
        let info = ver.into_service_info().unwrap();
        assert_eq!(info.root_url, url);
        assert_eq!(info.major_version, Some(ApiVersion(2, 0)));
        assert_eq!(info.current_version, Some(ApiVersion(2, 2)));
        assert_eq!(info.minimum_version, None);
    }

    #[test]
    fn test_version_into_service_info_no_self_link() {
        let ver = Version {
            id: ApiVersion(2, 0),
            links: vec![Link {
                href: Url::parse("https://example.com/docs").unwrap(),
                rel: "other".to_string(),
            }],
            status: None,
            version: Some(ApiVersion(2, 2)),
            min_version: None,
        };
        let err = ver.into_service_info().err().unwrap();
        assert_eq!(err.kind(), ErrorKind::InvalidResponse);
    }

    struct ServiceWithDiscovery;

    impl ServiceType for ServiceWithDiscovery {
        fn catalog_type(&self) -> &'static str {
            "test-service-with-discovery"
        }

        fn major_version_supported(&self, version: ApiVersion) -> bool {
            version.0 == 1 && version.1 > 0
        }
    }

    #[test]
    fn test_root_into_service_info_one_version() {
        let url = Url::parse("https://example.com/v1.2").unwrap();
        let root = Root::OneVersion {
            version: Version {
                id: ApiVersion(1, 2),
                links: vec![Link {
                    href: url.clone(),
                    rel: "self".to_string(),
                }],
                status: Some("STABLE".to_string()),
                version: None,
                min_version: None,
            },
        };

        let info = root.into_service_info(ServiceWithDiscovery).unwrap();
        assert_eq!(info.root_url, url);
        assert_eq!(info.major_version, Some(ApiVersion(1, 2)));
    }

    #[test]
    fn test_root_into_service_info_one_version_unsupported() {
        let url = Url::parse("https://example.com/v1.0").unwrap();
        let root = Root::OneVersion {
            version: Version {
                id: ApiVersion(1, 0),
                links: vec![Link {
                    href: url.clone(),
                    rel: "self".to_string(),
                }],
                status: Some("STABLE".to_string()),
                version: None,
                min_version: None,
            },
        };

        let err = root.into_service_info(ServiceWithDiscovery).err().unwrap();
        assert_eq!(err.kind(), ErrorKind::EndpointNotFound);
    }

    #[test]
    fn test_root_into_service_info_versions() {
        let url = Url::parse("https://example.com/v1.2").unwrap();
        let root = Root::MultipleVersions {
            versions: vec![
                Version {
                    id: ApiVersion(1, 0),
                    links: vec![Link {
                        href: Url::parse("https://example.com/1.0").unwrap(),
                        rel: "self".to_string(),
                    }],
                    status: Some("STABLE".to_string()),
                    version: None,
                    min_version: None,
                },
                Version {
                    id: ApiVersion(1, 1),
                    links: vec![Link {
                        href: Url::parse("https://example.com/1.1").unwrap(),
                        rel: "self".to_string(),
                    }],
                    status: Some("STABLE".to_string()),
                    version: None,
                    min_version: None,
                },
                Version {
                    id: ApiVersion(1, 2),
                    links: vec![Link {
                        href: url.clone(),
                        rel: "self".to_string(),
                    }],
                    status: Some("STABLE".to_string()),
                    version: None,
                    min_version: None,
                },
                Version {
                    id: ApiVersion(2, 0),
                    links: vec![Link {
                        href: Url::parse("https://example.com/2.0").unwrap(),
                        rel: "self".to_string(),
                    }],
                    status: Some("STABLE".to_string()),
                    version: None,
                    min_version: None,
                },
            ],
        };

        let info = root.into_service_info(ServiceWithDiscovery).unwrap();
        assert_eq!(info.root_url, url);
        assert_eq!(info.major_version, Some(ApiVersion(1, 2)));
    }

    #[test]
    fn test_root_into_service_info_versions_unsupported() {
        let root = Root::MultipleVersions {
            versions: vec![
                Version {
                    id: ApiVersion(1, 0),
                    links: vec![Link {
                        href: Url::parse("https://example.com/1.0").unwrap(),
                        rel: "self".to_string(),
                    }],
                    status: Some("STABLE".to_string()),
                    version: None,
                    min_version: None,
                },
                Version {
                    id: ApiVersion(2, 0),
                    links: vec![Link {
                        href: Url::parse("https://example.com/2.0").unwrap(),
                        rel: "self".to_string(),
                    }],
                    status: Some("STABLE".to_string()),
                    version: None,
                    min_version: None,
                },
            ],
        };

        let err = root.into_service_info(ServiceWithDiscovery).err().unwrap();
        assert_eq!(err.kind(), ErrorKind::EndpointNotFound);
    }
}
