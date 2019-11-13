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

use std::convert::TryFrom;
use std::sync::Arc;

use log::{debug, trace, warn};
use osproto::common::{Root, Version};
use reqwest::{Method, Url};

use super::request;
use super::services::ServiceType;
use super::url;
use super::{ApiVersion, AuthType, Error, ErrorKind};

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

impl TryFrom<Version> for ServiceInfo {
    type Error = Error;

    fn try_from(value: Version) -> Result<ServiceInfo, Error> {
        let endpoint = match value.links.into_iter().find(|x| &x.rel == "self") {
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
            major_version: Some(value.id.into()),
            current_version: value.version.map(From::from),
            minimum_version: value.min_version.map(From::from),
        })
    }
}

#[inline]
async fn fetch_root(
    catalog_type: &'static str,
    endpoint: Url,
    auth: Arc<dyn AuthType>,
) -> Result<Root, Error> {
    debug!("Fetching {} service info from {}", catalog_type, endpoint);
    request::fetch_json(auth.request(Method::GET, endpoint).await?).await
}

impl ServiceInfo {
    fn from_root<Srv: ServiceType>(mut value: Root, service: Srv) -> Result<ServiceInfo, Error> {
        trace!(
            "Available major versions for {} service: {:?}",
            service.catalog_type(),
            value
        );

        if let Root::OneVersion { version: ver } = value {
            if service.major_version_supported(ver.id.into()) {
                if !ver.is_stable() {
                    warn!(
                        "Using version {:?} of {} API that is not marked as stable",
                        ver,
                        service.catalog_type()
                    );
                }

                ServiceInfo::try_from(ver)
            } else {
                Err(Error::new(
                    ErrorKind::EndpointNotFound,
                    "Major version not supported",
                ))
            }
        } else {
            value.sort();
            value
                .into_stable_iter()
                .rfind(|x| service.major_version_supported(x.id.into()))
                .ok_or_else(|| Error::new_endpoint_not_found(service.catalog_type()))
                .and_then(TryFrom::try_from)
        }
    }

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
    pub async fn fetch<Srv: ServiceType>(
        service: Srv,
        endpoint: Url,
        auth: Arc<dyn AuthType>,
    ) -> Result<ServiceInfo, Error> {
        let fallback = ServiceInfo {
            root_url: endpoint.clone(),
            major_version: None,
            current_version: None,
            minimum_version: None,
        };

        if !service.version_discovery_supported() {
            debug!(
                "Service {} does not support version discovery, using {}",
                service.catalog_type(),
                endpoint
            );
            return Ok(fallback);
        }

        // Workaround for old version of Nova returning HTTP endpoints even if
        // accessed via HTTP
        let secure = endpoint.scheme() == "https";
        let catalog_type = service.catalog_type();

        let root = match fetch_root(catalog_type, endpoint.clone(), auth.clone()).await {
            Ok(root) => root,
            Err(e) if e.kind() == ErrorKind::ResourceNotFound => {
                if url::is_root(&endpoint) {
                    let err = Error::new_endpoint_not_found(catalog_type);
                    return Err(err);
                } else {
                    debug!("Got HTTP 404 from {}, trying parent endpoint", endpoint);
                    fetch_root(catalog_type, url::pop(endpoint, true), auth).await?
                }
            }
            Err(e) => return Err(e),
        };

        let mut info = ServiceInfo::from_root(root, service).or_else(move |e| {
            if e.kind() == ErrorKind::EndpointNotFound {
                debug!(
                    "Service returned EndpointNotFound when attempting version discovery, using {}",
                    fallback.root_url
                );
                Ok(fallback)
            } else {
                Err(e)
            }
        })?;

        // Older Nova returns insecure URLs even for secure protocol.
        if secure && info.root_url.scheme() == "http" {
            info.root_url.set_scheme("https").unwrap();
        }

        debug!("Received {:?} for {} service", info, catalog_type);
        Ok(info)
    }
}

#[cfg(test)]
pub(crate) mod test {
    use std::convert::TryFrom;

    use osproto::common::{Link, Root, Version, XdotY};
    use reqwest::Url;

    use super::super::services::ServiceType;
    use super::super::{ApiVersion, ErrorKind};
    use super::ServiceInfo;

    #[test]
    fn test_version_into_service_info() {
        let url = Url::parse("https://example.com/v2").unwrap();
        let ver = Version {
            id: XdotY(2, 0),
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
            version: Some(XdotY(2, 2)),
            min_version: None,
        };
        let info = ServiceInfo::try_from(ver).unwrap();
        assert_eq!(info.root_url, url);
        assert_eq!(info.major_version, Some(ApiVersion(2, 0)));
        assert_eq!(info.current_version, Some(ApiVersion(2, 2)));
        assert_eq!(info.minimum_version, None);
    }

    #[test]
    fn test_version_into_service_info_no_self_link() {
        let ver = Version {
            id: XdotY(2, 0),
            links: vec![Link {
                href: Url::parse("https://example.com/docs").unwrap(),
                rel: "other".to_string(),
            }],
            status: None,
            version: Some(XdotY(2, 2)),
            min_version: None,
        };
        let err = ServiceInfo::try_from(ver).err().unwrap();
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
                id: XdotY(1, 2),
                links: vec![Link {
                    href: url.clone(),
                    rel: "self".to_string(),
                }],
                status: Some("STABLE".to_string()),
                version: None,
                min_version: None,
            },
        };

        let info = ServiceInfo::from_root(root, ServiceWithDiscovery).unwrap();
        assert_eq!(info.root_url, url);
        assert_eq!(info.major_version, Some(ApiVersion(1, 2)));
    }

    #[test]
    fn test_root_into_service_info_one_version_unsupported() {
        let url = Url::parse("https://example.com/v1.0").unwrap();
        let root = Root::OneVersion {
            version: Version {
                id: XdotY(1, 0),
                links: vec![Link {
                    href: url.clone(),
                    rel: "self".to_string(),
                }],
                status: Some("STABLE".to_string()),
                version: None,
                min_version: None,
            },
        };

        let err = ServiceInfo::from_root(root, ServiceWithDiscovery)
            .err()
            .unwrap();
        assert_eq!(err.kind(), ErrorKind::EndpointNotFound);
    }

    #[test]
    fn test_root_into_service_info_versions() {
        let url = Url::parse("https://example.com/v1.2").unwrap();
        let root = Root::MultipleVersions {
            versions: vec![
                Version {
                    id: XdotY(1, 0),
                    links: vec![Link {
                        href: Url::parse("https://example.com/1.0").unwrap(),
                        rel: "self".to_string(),
                    }],
                    status: Some("STABLE".to_string()),
                    version: None,
                    min_version: None,
                },
                Version {
                    id: XdotY(1, 1),
                    links: vec![Link {
                        href: Url::parse("https://example.com/1.1").unwrap(),
                        rel: "self".to_string(),
                    }],
                    status: Some("STABLE".to_string()),
                    version: None,
                    min_version: None,
                },
                Version {
                    id: XdotY(1, 2),
                    links: vec![Link {
                        href: url.clone(),
                        rel: "self".to_string(),
                    }],
                    status: Some("STABLE".to_string()),
                    version: None,
                    min_version: None,
                },
                Version {
                    id: XdotY(2, 0),
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

        let info = ServiceInfo::from_root(root, ServiceWithDiscovery).unwrap();
        assert_eq!(info.root_url, url);
        assert_eq!(info.major_version, Some(ApiVersion(1, 2)));
    }

    #[test]
    fn test_root_into_service_info_versions_unsupported() {
        let root = Root::MultipleVersions {
            versions: vec![
                Version {
                    id: XdotY(1, 0),
                    links: vec![Link {
                        href: Url::parse("https://example.com/1.0").unwrap(),
                        rel: "self".to_string(),
                    }],
                    status: Some("STABLE".to_string()),
                    version: None,
                    min_version: None,
                },
                Version {
                    id: XdotY(2, 0),
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

        let err = ServiceInfo::from_root(root, ServiceWithDiscovery)
            .err()
            .unwrap();
        assert_eq!(err.kind(), ErrorKind::EndpointNotFound);
    }
}
