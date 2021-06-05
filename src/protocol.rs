// Copyright 2017 Dmitry Tantsur <dtantsur@protonmail.com>
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
use std::iter::{DoubleEndedIterator, FusedIterator};
use std::vec::IntoIter;

use log::{debug, error, trace, warn};
use reqwest::{Method, Url};
use serde::Deserialize;

use super::client::AuthenticatedClient;
use super::common::Version;
use super::services::ServiceType;
use super::url;
use super::{ApiVersion, Error, ErrorKind};

/// A result of a version discovery endpoint.
#[derive(Clone, Debug, Deserialize)]
#[serde(untagged)]
pub enum Root {
    /// Multiple major versions.
    MultipleVersions { versions: Vec<Version> },
    /// Single major version.
    OneVersion { version: Version },
}

#[derive(Debug, Clone)]
enum IntoStableIterInner {
    Many(IntoIter<Version>),
    One(Option<Version>),
}

/// An iterator over stable versions.
#[derive(Debug)]
pub struct IntoStableIter(IntoStableIterInner);

impl Iterator for IntoStableIter {
    type Item = Version;

    fn next(&mut self) -> Option<Self::Item> {
        match self.0 {
            IntoStableIterInner::Many(ref mut inner) => {
                for next in inner {
                    if next.is_stable() {
                        return Some(next);
                    }
                }

                None
            }
            IntoStableIterInner::One(ref mut opt) => opt.take(),
        }
    }
}

impl DoubleEndedIterator for IntoStableIter {
    fn next_back(&mut self) -> Option<Self::Item> {
        match self.0 {
            IntoStableIterInner::Many(ref mut inner) => {
                while let Some(next) = inner.next_back() {
                    if next.is_stable() {
                        return Some(next);
                    }
                }

                None
            }
            IntoStableIterInner::One(ref mut opt) => opt.take(),
        }
    }
}

impl FusedIterator for IntoStableIter {}

impl Root {
    /// Sort versions from lowest to highest (using unstable sorting).
    #[inline]
    pub fn sort(&mut self) {
        if let Root::MultipleVersions {
            versions: ref mut vers,
        } = self
        {
            vers.sort_unstable();
        }
    }

    /// Create an iterator over stable versions.
    pub fn into_stable_iter(self) -> IntoStableIter {
        match self {
            Root::MultipleVersions { versions: vers } => {
                IntoStableIter(IntoStableIterInner::Many(vers.into_iter()))
            }
            Root::OneVersion { version: ver } => {
                let stable = if ver.is_stable() { Some(ver) } else { None };
                IntoStableIter(IntoStableIterInner::One(stable))
            }
        }
    }
}

/// Information about API endpoint.
#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq, Eq, Clone))]
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
            major_version: Some(value.id),
            current_version: value.version.map(From::from),
            minimum_version: value.min_version.map(From::from),
        })
    }
}

#[inline]
async fn fetch_root(
    catalog_type: &'static str,
    endpoint: Url,
    client: &AuthenticatedClient,
) -> Result<Root, Error> {
    debug!("Fetching {} service info from {}", catalog_type, endpoint);
    client.request(Method::GET, endpoint).fetch_json().await
}

impl ServiceInfo {
    #[inline]
    pub fn get_api_versions(&self) -> Option<(ApiVersion, ApiVersion)> {
        match (self.minimum_version, self.current_version) {
            (Some(min), Some(max)) => Some((min, max)),
            _ => None,
        }
    }

    #[inline]
    pub fn get_endpoint<I>(&self, path: I) -> Url
    where
        I: IntoIterator,
        I::Item: AsRef<str>,
    {
        url::extend(self.root_url.clone(), path)
    }

    #[inline]
    pub fn pick_api_version<I>(&self, versions: I) -> Option<ApiVersion>
    where
        I: IntoIterator<Item = ApiVersion>,
    {
        versions
            .into_iter()
            .filter(|item| self.supports_api_version(*item))
            .max()
    }

    fn from_root<Srv: ServiceType>(mut value: Root, service: Srv) -> Result<ServiceInfo, Error> {
        trace!(
            "Available major versions for {} service: {:?}",
            service.catalog_type(),
            value
        );

        if let Root::OneVersion { version: ver } = value {
            if service.major_version_supported(ver.id) {
                if !ver.is_stable() {
                    warn!(
                        "Using version {:?} of {} API that is not marked as stable",
                        ver,
                        service.catalog_type()
                    );
                }

                ServiceInfo::try_from(ver)
            } else {
                error!(
                    "Major version {} of the {} service is not supported",
                    ver.id,
                    service.catalog_type()
                );
                Err(Error::new(
                    ErrorKind::EndpointNotFound,
                    "Major version not supported",
                ))
            }
        } else {
            value.sort();
            value
                .into_stable_iter()
                .rfind(|x| service.major_version_supported(x.id))
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
        client: &AuthenticatedClient,
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

        let root = match fetch_root(catalog_type, endpoint.clone(), client).await {
            Ok(root) => root,
            Err(e) if e.kind() == ErrorKind::ResourceNotFound => {
                if url::is_root(&endpoint) {
                    error!(
                        "Got HTTP 404 from the root URL {}, invalid endpoint for {} service",
                        endpoint, catalog_type
                    );
                    let err = Error::new_endpoint_not_found(catalog_type);
                    return Err(err);
                } else {
                    debug!("Got HTTP 404 from {}, trying parent endpoint", endpoint);
                    fetch_root(catalog_type, url::pop(endpoint), client).await?
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

    use reqwest::Url;

    use super::{Root, ServiceInfo};
    use crate::common::{Link, Version, VersionStatus};
    use crate::services::ServiceType;
    use crate::{ApiVersion, ErrorKind};

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
            status: VersionStatus::Unknown,
            version: Some(ApiVersion(2, 2)),
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
            id: ApiVersion(2, 0),
            links: vec![Link {
                href: Url::parse("https://example.com/docs").unwrap(),
                rel: "other".to_string(),
            }],
            status: VersionStatus::Unknown,
            version: Some(ApiVersion(2, 2)),
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
                id: ApiVersion(1, 2),
                links: vec![Link {
                    href: url.clone(),
                    rel: "self".to_string(),
                }],
                status: VersionStatus::Supported,
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
                id: ApiVersion(1, 0),
                links: vec![Link {
                    href: url.clone(),
                    rel: "self".to_string(),
                }],
                status: VersionStatus::Supported,
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
                    id: ApiVersion(1, 0),
                    links: vec![Link {
                        href: Url::parse("https://example.com/1.0").unwrap(),
                        rel: "self".to_string(),
                    }],
                    status: VersionStatus::Supported,
                    version: None,
                    min_version: None,
                },
                Version {
                    id: ApiVersion(1, 1),
                    links: vec![Link {
                        href: Url::parse("https://example.com/1.1").unwrap(),
                        rel: "self".to_string(),
                    }],
                    status: VersionStatus::Supported,
                    version: None,
                    min_version: None,
                },
                Version {
                    id: ApiVersion(1, 2),
                    links: vec![Link {
                        href: url.clone(),
                        rel: "self".to_string(),
                    }],
                    status: VersionStatus::Supported,
                    version: None,
                    min_version: None,
                },
                Version {
                    id: ApiVersion(2, 0),
                    links: vec![Link {
                        href: Url::parse("https://example.com/2.0").unwrap(),
                        rel: "self".to_string(),
                    }],
                    status: VersionStatus::Supported,
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
                    id: ApiVersion(1, 0),
                    links: vec![Link {
                        href: Url::parse("https://example.com/1.0").unwrap(),
                        rel: "self".to_string(),
                    }],
                    status: VersionStatus::Supported,
                    version: None,
                    min_version: None,
                },
                Version {
                    id: ApiVersion(2, 0),
                    links: vec![Link {
                        href: Url::parse("https://example.com/2.0").unwrap(),
                        rel: "self".to_string(),
                    }],
                    status: VersionStatus::Supported,
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

    #[test]
    fn test_root_sort() {
        let vers: Vec<_> = [3, 1, 2]
            .iter()
            .map(|idx| Version {
                id: ApiVersion(*idx, 0),
                links: Vec::new(),
                status: VersionStatus::Unknown,
                version: None,
                min_version: None,
            })
            .collect();
        let mut root = Root::MultipleVersions { versions: vers };
        root.sort();
        if let Root::MultipleVersions { versions: res } = root {
            let idx = res.into_iter().map(|v| v.id.0).collect::<Vec<_>>();
            assert_eq!(idx, vec![1, 2, 3]);
        } else {
            unreachable!();
        }
    }

    #[test]
    fn test_root_sort_one() {
        let ver = Version {
            id: ApiVersion(2, 0),
            links: Vec::new(),
            status: VersionStatus::Supported,
            version: None,
            min_version: None,
        };
        let mut root = Root::OneVersion { version: ver };
        root.sort();
        if let Root::OneVersion { version: res } = root {
            assert_eq!(res.id.0, 2);
        } else {
            unreachable!();
        }
    }

    #[test]
    fn test_root_into_sorted() {
        let vers: Vec<_> = [3, 1, 2]
            .iter()
            .map(|idx| Version {
                id: ApiVersion(*idx, 0),
                links: Vec::new(),
                status: VersionStatus::Unknown,
                version: None,
                min_version: None,
            })
            .collect();
        let mut root = Root::MultipleVersions { versions: vers };
        root.sort();
        if let Root::MultipleVersions { versions: res } = root {
            let idx = res.into_iter().map(|v| v.id.0).collect::<Vec<_>>();
            assert_eq!(idx, vec![1, 2, 3]);
        } else {
            unreachable!();
        }
    }

    #[test]
    fn test_root_into_stable_iter() {
        let vers: Vec<_> = [3, 1, 2]
            .iter()
            .map(|idx| Version {
                id: ApiVersion(*idx, 0),
                links: Vec::new(),
                status: if *idx > 1 {
                    VersionStatus::Supported
                } else {
                    VersionStatus::Deprecated
                },
                version: None,
                min_version: None,
            })
            .collect();
        let root = Root::MultipleVersions { versions: vers };
        let idx = root
            .into_stable_iter()
            .map(|ver| ver.id.0)
            .collect::<Vec<_>>();
        assert_eq!(idx, vec![3, 2]);
    }

    #[test]
    fn test_root_into_stable_iter_reverse() {
        let vers: Vec<_> = [3, 1, 2]
            .iter()
            .map(|idx| Version {
                id: ApiVersion(*idx, 0),
                links: Vec::new(),
                status: if *idx > 1 {
                    VersionStatus::Supported
                } else {
                    VersionStatus::Deprecated
                },
                version: None,
                min_version: None,
            })
            .collect();
        let root = Root::MultipleVersions { versions: vers };
        let mut idx = root.into_stable_iter().map(|ver| ver.id.0);
        assert_eq!(idx.next_back(), Some(2));
        assert_eq!(idx.next_back(), Some(3));
        assert!(idx.next_back().is_none());
        assert!(idx.next().is_none());
    }

    #[test]
    fn test_root_into_stable_iter_one() {
        let ver = Version {
            id: ApiVersion(2, 0),
            links: Vec::new(),
            status: VersionStatus::Supported,
            version: None,
            min_version: None,
        };
        let root = Root::OneVersion { version: ver };
        let idx = root
            .into_stable_iter()
            .map(|ver| ver.id.0)
            .collect::<Vec<_>>();
        assert_eq!(idx, vec![2]);
    }

    #[test]
    fn test_root_into_stable_iter_one_unstable() {
        let ver = Version {
            id: ApiVersion(2, 0),
            links: Vec::new(),
            status: VersionStatus::Deprecated,
            version: None,
            min_version: None,
        };
        let root = Root::OneVersion { version: ver };
        let mut idx = root.into_stable_iter().map(|ver| ver.id.0);
        assert!(idx.next().is_none());
    }

    #[test]
    fn test_root_into_stable_iter_one_reverse() {
        let ver = Version {
            id: ApiVersion(2, 0),
            links: Vec::new(),
            status: VersionStatus::Supported,
            version: None,
            min_version: None,
        };
        let root = Root::OneVersion { version: ver };
        let mut idx = root.into_stable_iter().map(|ver| ver.id.0);
        assert_eq!(idx.next_back(), Some(2));
        assert!(idx.next_back().is_none());
    }

    const COMPUTE_ONE: &str = r#"{
  "version": {
    "status": "CURRENT",
    "updated": "2013-07-23T11:33:21Z",
    "links": [
      {
        "href": "https://example.org:13774/v2.1/",
        "rel": "self"
      },
      {
        "href": "http://docs.openstack.org/",
        "type": "text/html",
        "rel": "describedby"
      }
    ],
    "min_version": "2.1",
    "version": "2.42",
    "media-types": [
      {
        "base": "application/json",
        "type": "application/vnd.openstack.compute+json;version=2.1"
      }
    ],
    "id": "v2.1"
  }
}"#;

    #[test]
    fn test_parse_root_one_version() {
        let root: Root = serde_json::from_str(COMPUTE_ONE).unwrap();
        match root {
            Root::OneVersion { version } => {
                assert_eq!(version.id, ApiVersion(2, 1));
            }
            Root::MultipleVersions { .. } => panic!("Unexpected multiple versions"),
        }
    }
}
