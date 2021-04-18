// Copyright 2021 Dmitry Tantsur <dtantsur@protonmail.com>
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

//! Internal service information cache.

use std::collections::HashMap;

use log::debug;
use reqwest::Url;
use tokio::sync::RwLock;

use crate::protocol::ServiceInfo;
use crate::services::ServiceType;
use crate::{client::AuthenticatedClient, ErrorKind};
use crate::{EndpointFilters, Error};

/// Service information cache.
#[derive(Debug)]
pub struct EndpointCache {
    info: RwLock<HashMap<&'static str, ServiceInfo>>,
    pub filters: EndpointFilters,
    pub overrides: HashMap<String, Url>,
}

impl Clone for EndpointCache {
    /// Clone the cache removing the cached information but keeping filters and overrides.
    fn clone(&self) -> EndpointCache {
        EndpointCache {
            info: RwLock::new(HashMap::new()),
            filters: self.filters.clone(),
            overrides: self.overrides.clone(),
        }
    }
}

impl EndpointCache {
    /// Create a new empty cache.
    #[inline]
    pub fn new() -> Self {
        EndpointCache {
            info: RwLock::new(HashMap::new()),
            filters: EndpointFilters::default(),
            overrides: HashMap::new(),
        }
    }

    #[cfg(test)]
    pub fn new_with(service_type: &'static str, service_info: ServiceInfo) -> Self {
        let mut hm = HashMap::new();
        let _ = hm.insert(service_type, service_info);
        EndpointCache {
            info: RwLock::new(hm),
            filters: EndpointFilters::default(),
            overrides: HashMap::new(),
        }
    }

    /// Clear the cache.
    #[inline]
    pub fn clear(&mut self) -> &mut Self {
        self.info = RwLock::new(HashMap::new());
        self
    }

    /// Ensure service info and return the cache.
    pub async fn extract_service_info<Srv, F, T>(
        &self,
        client: &AuthenticatedClient,
        service: Srv,
        filter: F,
    ) -> Result<T, Error>
    where
        Srv: ServiceType + Send,
        F: FnOnce(&ServiceInfo) -> T + Send,
        T: Send,
    {
        let catalog_type = service.catalog_type();
        if let Some(info) = self.info.read().await.get(catalog_type) {
            return Ok(filter(info));
        }

        debug!(
            "No cached information for service {}, fetching",
            catalog_type
        );

        let mut lock = self.info.write().await;
        // Additonal check in case another thread has updated the token while we were waiting for
        // the write lock.
        Ok(if let Some(info) = lock.get(catalog_type) {
            filter(info)
        } else {
            let ep = match self.overrides.get(catalog_type) {
                Some(found) => found.clone(),
                None => client.get_endpoint(catalog_type, &self.filters).await?,
            };
            if ep.cannot_be_a_base() || !ep.has_host() {
                return Err(Error::new(
                    ErrorKind::InvalidResponse,
                    format!("Invalid URL {} received for service {}", ep, catalog_type),
                ));
            }
            let info = ServiceInfo::fetch(service, ep, client).await?;
            let value = filter(&info);
            let _ = lock.insert(catalog_type, info);
            value
        })
    }
}

#[cfg(test)]
mod test {
    use reqwest::Url;

    use crate::client::AuthenticatedClient;
    use crate::protocol::ServiceInfo;
    use crate::services::COMPUTE;
    use crate::ErrorKind;

    use super::EndpointCache;

    // We cannot test ServiceInfo::fetch unless we make extract_service_info generic
    // over it.

    #[tokio::test]
    async fn test_existing() {
        let client = AuthenticatedClient::new_noauth("http://localhost").await;
        let sinfo = ServiceInfo {
            root_url: Url::parse("http://localhost").unwrap(),
            major_version: None,
            current_version: None,
            minimum_version: None,
        };
        let cache = EndpointCache::new_with("compute", sinfo.clone());
        let sinfo2 = cache
            .extract_service_info(&client, COMPUTE, |s| s.clone())
            .await
            .unwrap();
        assert_eq!(sinfo, sinfo2);
    }

    #[tokio::test]
    async fn test_invalid_url() {
        let client = AuthenticatedClient::new_noauth("unix:/run/foo.socket").await;
        let cache = EndpointCache::new();
        let err = cache
            .extract_service_info(&client, COMPUTE, |s| s.clone())
            .await
            .err()
            .unwrap();
        assert_eq!(err.kind(), ErrorKind::InvalidResponse);
    }
}
