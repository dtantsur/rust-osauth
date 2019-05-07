// Copyright 2019 Dmitry Tantsur <divius.inside@gmail.com>
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

//! Internal session structure definition.

use std::sync::Arc;

use futures::future;
use futures::prelude::*;
use log::{debug, trace};
use reqwest::header::HeaderMap;
use reqwest::r#async::RequestBuilder;
use reqwest::{Method, Url};

use super::cache;
use super::protocol::ServiceInfo;
use super::services::ServiceType;
use super::url;
use super::{ApiVersion, AuthType, Error};

type Cache = cache::MapCache<&'static str, ServiceInfo>;

/// An internal implementation of a session.
#[derive(Debug, Clone)]
pub struct SessionInner {
    auth: Arc<AuthType>,
    cached_info: Arc<Cache>,
}

impl SessionInner {
    /// Create a new session with a given authentication plugin.
    pub fn new<Auth: AuthType + 'static>(auth_method: Auth) -> SessionInner {
        SessionInner {
            auth: Arc::new(auth_method),
            cached_info: Arc::new(cache::MapCache::default()),
        }
    }

    #[cfg(test)]
    pub(crate) fn cache_fake_service(
        &mut self,
        service_type: &'static str,
        service_info: ServiceInfo,
    ) {
        let _ = self.cached_info.set(service_type, service_info);
    }

    /// Get a reference to the authentication type in use.
    #[inline]
    pub fn auth_type(&self) -> &AuthType {
        self.auth.as_ref()
    }

    /// Get minimum/maximum API (micro)version information.
    pub fn get_api_versions<Srv: ServiceType + Send>(
        &self,
        service: Srv,
        endpoint_interface: &Option<String>,
    ) -> impl Future<Item = Option<(ApiVersion, ApiVersion)>, Error = Error> + Send {
        self.extract_service_info(service, endpoint_interface, |info| {
            match (info.minimum_version, info.current_version) {
                (Some(min), Some(max)) => Some((min, max)),
                _ => None,
            }
        })
    }

    /// Construct and endpoint for the given service from the path.
    pub fn get_endpoint<Srv, I>(
        &self,
        service: Srv,
        endpoint_interface: &Option<String>,
        path: I,
    ) -> impl Future<Item = Url, Error = Error> + Send
    where
        Srv: ServiceType + Send,
        I: IntoIterator,
        I::Item: AsRef<str>,
        I::IntoIter: Send,
    {
        let path_iter = path.into_iter();
        self.extract_service_info(service, endpoint_interface, |info| {
            url::extend(info.root_url.clone(), path_iter)
        })
    }

    /// Get the currently used major version from the given service.
    pub fn get_major_version<Srv: ServiceType + Send>(
        &self,
        service: Srv,
        endpoint_interface: &Option<String>,
    ) -> impl Future<Item = Option<ApiVersion>, Error = Error> + Send {
        self.extract_service_info(service, endpoint_interface, |info| info.major_version)
    }

    /// Ensure service info and return the cache.
    fn extract_service_info<Srv, F, T>(
        &self,
        service: Srv,
        endpoint_interface: &Option<String>,
        filter: F,
    ) -> impl Future<Item = T, Error = Error>
    where
        Srv: ServiceType + Send,
        F: FnOnce(&ServiceInfo) -> T + Send,
        T: Send,
    {
        let catalog_type = service.catalog_type();
        if self.cached_info.is_set(&catalog_type) {
            future::Either::A(future::ok(
                self.cached_info
                    .extract(&catalog_type, filter)
                    .expect("BUG: cached record removed while in extract_service_info"),
            ))
        } else {
            debug!(
                "No cached information for service {}, fetching",
                catalog_type
            );

            let endpoint_interface = endpoint_interface.clone();
            let cached_info = Arc::clone(&self.cached_info);
            let auth_type = Arc::clone(&self.auth);
            future::Either::B(
                self.auth
                    .get_endpoint(catalog_type.to_string(), endpoint_interface)
                    .and_then(move |ep| ServiceInfo::fetch(service, ep, auth_type))
                    .map(move |info| {
                        let value = filter(&info);
                        cached_info.set(catalog_type, info);
                        value
                    }),
            )
        }
    }

    /// Pick the highest API version supported by the service.
    pub fn pick_api_version<Srv, I>(
        &self,
        service: Srv,
        endpoint_interface: &Option<String>,
        versions: I,
    ) -> impl Future<Item = Option<ApiVersion>, Error = Error> + Send
    where
        Srv: ServiceType + Send,
        I: IntoIterator<Item = ApiVersion>,
        I::IntoIter: Send,
    {
        let vers = versions.into_iter();
        if vers.size_hint().1 == Some(0) {
            future::Either::A(future::ok(None))
        } else {
            future::Either::B(
                self.extract_service_info(service, endpoint_interface, |info| {
                    vers.filter(|item| info.supports_api_version(*item)).max()
                }),
            )
        }
    }

    /// Update the authentication and purges cached endpoint information.
    #[inline]
    pub fn refresh(&mut self) -> impl Future<Item = (), Error = Error> + Send {
        self.reset_cache();
        self.auth.refresh()
    }

    /// Make a request.
    pub fn request<Srv, I>(
        &self,
        service: Srv,
        endpoint_interface: &Option<String>,
        method: Method,
        path: I,
        api_version: Option<ApiVersion>,
    ) -> impl Future<Item = RequestBuilder, Error = Error> + Send
    where
        Srv: ServiceType + Send + Clone,
        I: IntoIterator,
        I::Item: AsRef<str>,
        I::IntoIter: Send,
    {
        let auth = Arc::clone(&self.auth);
        self.get_endpoint(service.clone(), endpoint_interface, path)
            .and_then(move |url| {
                trace!(
                    "Sending HTTP {} request to {} with API version {:?}",
                    method,
                    url,
                    api_version
                );
                auth.request(method, url)
            })
            .and_then(move |mut builder| {
                if let Some(version) = api_version {
                    let mut headers = HeaderMap::new();
                    match service.set_api_version_headers(&mut headers, version) {
                        Ok(()) => builder = builder.headers(headers),
                        Err(err) => return future::err(err),
                    }
                }
                future::ok(builder)
            })
    }

    /// Reset the internal cache.
    #[inline]
    pub fn reset_cache(&mut self) {
        self.cached_info = Arc::new(cache::MapCache::default());
    }

    /// Set a new authentication for this `Session`.
    #[inline]
    pub fn set_auth_type<Auth: AuthType + 'static>(&mut self, auth_method: Auth) {
        self.reset_cache();
        self.auth = Arc::new(auth_method);
    }
}
