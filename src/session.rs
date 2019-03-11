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

//! Session structure definition.

use std::sync::Arc;

use futures::future;
use futures::prelude::*;
use log::{debug, trace};
use reqwest::r#async::{RequestBuilder, Response};
use reqwest::{Method, Url};
use serde::de::DeserializeOwned;
use serde::Serialize;

use super::cache;
use super::protocol::ServiceInfo;
use super::request;
use super::services::ServiceType;
use super::url;
use super::{ApiVersion, AuthType, Error};

type Cache = cache::MapCache<&'static str, ServiceInfo>;

/// An OpenStack API session.
///
/// The session object serves as a wrapper around an HTTP(s) client, handling
/// authentication, accessing the service catalog and token refresh.
///
/// The session object also owns the endpoint interface to use.
#[derive(Debug, Clone)]
pub struct Session {
    auth: Arc<AuthType>,
    cached_info: Arc<Cache>,
    endpoint_interface: Option<String>,
}

impl Session {
    /// Create a new session with a given authentication plugin.
    ///
    /// The resulting session will use the default endpoint interface (usually,
    /// public).
    pub fn new<Auth: AuthType + 'static>(auth_method: Auth) -> Session {
        Session {
            auth: Arc::new(auth_method),
            cached_info: Arc::new(cache::MapCache::default()),
            endpoint_interface: None,
        }
    }

    /// Endpoint interface in use (if any).
    #[inline]
    pub fn endpoint_interface(&self) -> &Option<String> {
        &self.endpoint_interface
    }

    /// Set endpoint interface to use.
    ///
    /// This call clears the cached service information for this `Session`.
    /// It does not, however, affect clones of this `Session`.
    pub fn set_endpoint_interface<S>(&mut self, endpoint_interface: S)
    where
        S: Into<String>,
    {
        self.cached_info = Arc::new(cache::MapCache::default());
        self.endpoint_interface = Some(endpoint_interface.into());
    }

    /// Convert this session into one using the given endpoint interface.
    #[inline]
    pub fn with_endpoint_interface<S>(mut self, endpoint_interface: S) -> Session
    where
        S: Into<String>,
    {
        self.set_endpoint_interface(endpoint_interface);
        self
    }

    /// Get a reference to the authentication type in use.
    #[inline]
    pub fn auth_type(&self) -> &AuthType {
        self.auth.as_ref()
    }

    /// Invalidate internal caches.

    /// Construct and endpoint for the given service from the path.
    pub fn get_endpoint<Srv, I>(
        &self,
        service: Srv,
        path: I,
    ) -> impl Future<Item = Url, Error = Error> + Send
    where
        Srv: ServiceType + Send,
        I: IntoIterator,
        I::Item: AsRef<str>,
        I::IntoIter: Send,
    {
        let path_iter = path.into_iter();
        let catalog_type = service.catalog_type();
        self.ensure_service_info(service).map(move |infos| {
            let endpoint = infos
                .extract(&catalog_type, |info| info.root_url.clone())
                .expect("No cache record after caching");
            url::extend(endpoint, path_iter)
        })
    }

    /// Get the currently used major version from the given service.
    ///
    /// Can return `IncompatibleApiVersion` if the service does not support
    /// API version discovery at all.
    pub fn get_major_version<Srv: ServiceType + Send>(
        &self,
        service: Srv,
    ) -> impl Future<Item = Option<ApiVersion>, Error = Error> + Send {
        let catalog_type = service.catalog_type();
        self.ensure_service_info(service).map(move |infos| {
            infos
                .extract(&catalog_type, |info| info.major_version)
                .expect("No cache record after caching")
        })
    }

    /// Get minimum/maximum API (micro)version information.
    ///
    /// Returns `None` if the range cannot be determined, which usually means
    /// that microversioning is not supported.
    pub fn get_api_versions<Srv: ServiceType + Send>(
        &self,
        service: Srv,
    ) -> impl Future<Item = Option<(ApiVersion, ApiVersion)>, Error = Error> + Send {
        let catalog_type = service.catalog_type();
        self.ensure_service_info(service).map(move |infos| {
            let min_max = infos
                .extract(&catalog_type, |info| {
                    (info.minimum_version, info.current_version)
                })
                .expect("No cache record after caching");
            match min_max {
                (Some(min), Some(max)) => Some((min, max)),
                _ => None,
            }
        })
    }

    /// Pick the highest API version supported by the service.
    pub fn pick_api_version<Srv: ServiceType + Send>(
        &self,
        service: Srv,
        versions: Vec<ApiVersion>,
    ) -> impl Future<Item = Option<ApiVersion>, Error = Error> + Send {
        let catalog_type = service.catalog_type();
        self.ensure_service_info(service).map(move |infos| {
            infos
                .extract(&catalog_type, |info| {
                    versions
                        .iter()
                        .filter(|item| info.supports_api_version(**item))
                        .max()
                        .cloned()
                })
                .expect("No cache record after caching")
        })
    }

    /// Check if the service supports the API version.
    pub fn supports_api_version<Srv: ServiceType + Send>(
        &self,
        service: Srv,
        version: ApiVersion,
    ) -> impl Future<Item = bool, Error = Error> + Send {
        let catalog_type = service.catalog_type();
        self.ensure_service_info(service).map(move |infos| {
            infos
                .extract(&catalog_type, |info| info.supports_api_version(version))
                .expect("No cache record after caching")
        })
    }

    /// Make an HTTP request to the given service.
    pub fn request<Srv, I>(
        &self,
        service: Srv,
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
        self.get_endpoint(service.clone(), path)
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
                    builder = match service.set_api_version_headers(builder, version) {
                        Ok(builder) => builder,
                        Err(err) => return future::err(err),
                    }
                }
                future::ok(builder)
            })
    }

    /// Start a GET request.
    #[inline]
    pub fn start_get<Srv, I>(
        &self,
        service: Srv,
        path: I,
        api_version: Option<ApiVersion>,
    ) -> impl Future<Item = RequestBuilder, Error = Error> + Send
    where
        Srv: ServiceType + Send + Clone,
        I: IntoIterator,
        I::Item: AsRef<str>,
        I::IntoIter: Send,
    {
        self.request(service, Method::GET, path, api_version)
    }

    /// Issue a GET request.
    #[inline]
    pub fn get<Srv, I, T>(
        &self,
        service: Srv,
        path: I,
        api_version: Option<ApiVersion>,
    ) -> impl Future<Item = Response, Error = Error> + Send
    where
        Srv: ServiceType + Send + Clone,
        I: IntoIterator,
        I::Item: AsRef<str>,
        I::IntoIter: Send,
    {
        self.start_get(service, path, api_version)
            .then(request::send_checked)
    }

    /// Fetch a JSON using the GET request.
    #[inline]
    pub fn get_json<Srv, I, T>(
        &self,
        service: Srv,
        path: I,
        api_version: Option<ApiVersion>,
    ) -> impl Future<Item = T, Error = Error> + Send
    where
        Srv: ServiceType + Send + Clone,
        I: IntoIterator,
        I::Item: AsRef<str>,
        I::IntoIter: Send,
        T: DeserializeOwned + Send,
    {
        self.start_get(service, path, api_version)
            .then(request::fetch_json)
    }

    /// Start a POST request.
    #[inline]
    pub fn start_post<Srv, I>(
        &self,
        service: Srv,
        path: I,
        api_version: Option<ApiVersion>,
    ) -> impl Future<Item = RequestBuilder, Error = Error> + Send
    where
        Srv: ServiceType + Send + Clone,
        I: IntoIterator,
        I::Item: AsRef<str>,
        I::IntoIter: Send,
    {
        self.request(service, Method::POST, path, api_version)
    }

    /// POST a JSON object.
    #[inline]
    pub fn post<Srv, I, T>(
        &self,
        service: Srv,
        path: I,
        body: T,
        api_version: Option<ApiVersion>,
    ) -> impl Future<Item = Response, Error = Error> + Send
    where
        Srv: ServiceType + Send + Clone,
        I: IntoIterator,
        I::Item: AsRef<str>,
        I::IntoIter: Send,
        T: Serialize + Send,
    {
        self.start_post(service, path, api_version)
            .map(move |builder| builder.json(&body))
            .then(request::send_checked)
    }

    /// POST a JSON object and receive a JSON back.
    #[inline]
    pub fn post_json<Srv, I, T, R>(
        &self,
        service: Srv,
        path: I,
        body: T,
        api_version: Option<ApiVersion>,
    ) -> impl Future<Item = R, Error = Error> + Send
    where
        Srv: ServiceType + Send + Clone,
        I: IntoIterator,
        I::Item: AsRef<str>,
        I::IntoIter: Send,
        T: Serialize + Send,
        R: DeserializeOwned + Send,
    {
        self.start_post(service, path, api_version)
            .map(move |builder| builder.json(&body))
            .then(request::fetch_json)
    }

    /// Start a PUT request.
    #[inline]
    pub fn start_put<Srv, I>(
        &self,
        service: Srv,
        path: I,
        api_version: Option<ApiVersion>,
    ) -> impl Future<Item = RequestBuilder, Error = Error> + Send
    where
        Srv: ServiceType + Send + Clone,
        I: IntoIterator,
        I::Item: AsRef<str>,
        I::IntoIter: Send,
    {
        self.request(service, Method::PUT, path, api_version)
    }

    /// PUT a JSON object.
    #[inline]
    pub fn put<Srv, I, T>(
        &self,
        service: Srv,
        path: I,
        body: T,
        api_version: Option<ApiVersion>,
    ) -> impl Future<Item = Response, Error = Error> + Send
    where
        Srv: ServiceType + Send + Clone,
        I: IntoIterator,
        I::Item: AsRef<str>,
        I::IntoIter: Send,
        T: Serialize + Send,
    {
        self.start_put(service, path, api_version)
            .map(move |builder| builder.json(&body))
            .then(request::send_checked)
    }

    /// PUT a JSON object and receive a JSON back.
    #[inline]
    pub fn put_json<Srv, I, T, R>(
        &self,
        service: Srv,
        path: I,
        body: T,
        api_version: Option<ApiVersion>,
    ) -> impl Future<Item = R, Error = Error> + Send
    where
        Srv: ServiceType + Send + Clone,
        I: IntoIterator,
        I::Item: AsRef<str>,
        I::IntoIter: Send,
        T: Serialize + Send,
        R: DeserializeOwned + Send,
    {
        self.start_put(service, path, api_version)
            .map(move |builder| builder.json(&body))
            .then(request::fetch_json)
    }

    /// Start a DELETE request.
    #[inline]
    pub fn start_delete<Srv, I>(
        &self,
        service: Srv,
        path: I,
        api_version: Option<ApiVersion>,
    ) -> impl Future<Item = RequestBuilder, Error = Error> + Send
    where
        Srv: ServiceType + Send + Clone,
        I: IntoIterator,
        I::Item: AsRef<str>,
        I::IntoIter: Send,
    {
        self.request(service, Method::DELETE, path, api_version)
    }

    /// Issue a DELETE request.
    #[inline]
    pub fn delete<Srv, I>(
        &self,
        service: Srv,
        path: I,
        api_version: Option<ApiVersion>,
    ) -> impl Future<Item = Response, Error = Error> + Send
    where
        Srv: ServiceType + Send + Clone,
        I: IntoIterator,
        I::Item: AsRef<str>,
        I::IntoIter: Send,
    {
        self.start_delete(service, path, api_version)
            .then(request::send_checked)
    }

    fn ensure_service_info<Srv>(
        &self,
        service: Srv,
    ) -> impl Future<Item = Arc<Cache>, Error = Error>
    where
        Srv: ServiceType + Send,
    {
        let catalog_type = service.catalog_type();
        if self.cached_info.is_set(&catalog_type) {
            future::Either::A(future::ok(Arc::clone(&self.cached_info)))
        } else {
            debug!(
                "No cached information for service {}, fetching",
                catalog_type
            );

            let endpoint_interface = self.endpoint_interface.clone();
            let cached_info = Arc::clone(&self.cached_info);
            let auth_type = Arc::clone(&self.auth);
            future::Either::B(
                self.auth
                    .get_endpoint(catalog_type.to_string(), endpoint_interface)
                    .and_then(move |ep| ServiceInfo::fetch(service, ep, auth_type))
                    .map(move |info| {
                        cached_info.set(catalog_type, info);
                        cached_info
                    }),
            )
        }
    }
}

#[cfg(test)]
pub(crate) mod test {
    use futures::Future;
    use reqwest::Url;

    use super::super::protocol::ServiceInfo;
    use super::super::services::{GenericService, VersionSelector};
    use super::super::{ApiVersion, NoAuth};
    use super::Session;

    pub const URL: &str = "http://127.0.0.1:5000/";

    pub const URL_WITH_SUFFIX: &str = "http://127.0.0.1:5000/v2/servers";

    pub fn new_simple_session(url: &str) -> Session {
        let service_info = ServiceInfo {
            root_url: Url::parse(url).unwrap(),
            major_version: None,
            minimum_version: None,
            current_version: None,
        };
        new_session(url, service_info)
    }

    pub fn new_session(url: &str, service_info: ServiceInfo) -> Session {
        let auth = NoAuth::new(url).unwrap();
        let session = Session::new(auth);
        let _ = session.cached_info.set("fake", service_info);
        session
    }

    const FAKE: GenericService = GenericService::new("fake", VersionSelector::Any);

    #[test]
    fn test_get_endpoint() {
        let s = new_simple_session(URL);
        let ep = s.get_endpoint(FAKE, &[""]).wait().unwrap();
        assert_eq!(&ep.to_string(), URL);
    }

    #[test]
    fn test_get_endpoint_slice() {
        let s = new_simple_session(URL);
        let ep = s.get_endpoint(FAKE, &["v2", "servers"]).wait().unwrap();
        assert_eq!(&ep.to_string(), URL_WITH_SUFFIX);
    }

    #[test]
    fn test_get_endpoint_vec() {
        let s = new_simple_session(URL);
        let ep = s
            .get_endpoint(FAKE, vec!["v2".to_string(), "servers".to_string()])
            .wait()
            .unwrap();
        assert_eq!(&ep.to_string(), URL_WITH_SUFFIX);
    }

    #[test]
    fn test_get_major_version_absent() {
        let s = new_simple_session(URL);
        let res = s.get_major_version(FAKE).wait().unwrap();
        assert!(res.is_none());
    }

    #[test]
    fn test_get_major_version_present() {
        let service_info = ServiceInfo {
            root_url: Url::parse(URL).unwrap(),
            major_version: Some(ApiVersion(2, 0)),
            minimum_version: None,
            current_version: None,
        };
        let s = new_session(URL, service_info);
        let res = s.get_major_version(FAKE).wait().unwrap();
        assert_eq!(res, Some(ApiVersion(2, 0)));
    }
}
