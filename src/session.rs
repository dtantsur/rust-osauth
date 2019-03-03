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

use std::collections::HashMap;
use std::sync::Arc;

use futures::future;
use futures::prelude::*;
use reqwest::r#async::{RequestBuilder, Response};
use reqwest::{Method, Url};
use serde::de::DeserializeOwned;

use super::cache;
use super::protocol::ServiceInfo;
use super::url;
use super::{ApiVersion, AuthType, Error, ErrorKind};

/// Trait representing a service type.
pub trait ServiceType {
    /// Service type to pass to the catalog.
    fn catalog_type() -> &'static str;

    /// Check whether this service type is compatible with the given major version.
    fn major_version_supported(_version: ApiVersion) -> bool {
        true
    }

    /// Update the request to include the API version headers.
    ///
    /// The default implementation fails with `IncompatibleApiVersion`.
    fn set_api_version_headers(
        _request: RequestBuilder,
        _version: ApiVersion,
    ) -> Result<RequestBuilder, Error> {
        Err(Error::new(
            ErrorKind::IncompatibleApiVersion,
            format!(
                "The {} service does not support API versions",
                Self::catalog_type()
            ),
        ))
    }

    /// Whether this service supports version discovery at all.
    fn version_discovery_supported() -> bool {
        true
    }
}

/// Extension trait for HTTP calls with error handling.
pub trait RequestBuilderExt {
    /// Send a request and validate the status code.
    fn send_checked(self) -> Box<Future<Item = Response, Error = Error> + Send>;

    /// Send a request and discard the results.
    fn commit(self) -> Box<Future<Item = (), Error = Error> + Send>
    where
        Self: Sized,
    {
        Box::new(self.send_checked().map(|_resp| ()))
    }

    /// Send a request and receive a JSON back.
    fn receive_json<T: DeserializeOwned>(self) -> Box<Future<Item = (), Error = Error> + Send>
    where
        Self: Sized,
    {
        Box::new(
            self.send_checked()
                .and_then(move |mut resp| resp.json().from_err()),
        )
    }
}

#[derive(Debug, Clone, Deserialize)]
struct Message {
    message: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum ErrorResponse {
    Map(HashMap<String, Message>),
    Message(Message),
}

fn extract_message(resp: Response) -> impl Future<Item = String, Error = Error> {
    resp.into_body().concat2().from_err().map(|chunk| {
        serde_json::from_slice::<ErrorResponse>(&chunk)
            .ok()
            .and_then(|body| match body {
                ErrorResponse::Map(map) => map.into_iter().next().map(|(_k, v)| v.message),
                ErrorResponse::Message(msg) => Some(msg.message),
            })
            // TODO(dtantsur): detect the correct encoding? (should go into reqwest)
            .unwrap_or_else(|| String::from_utf8_lossy(&chunk).into_owned())
    })
}

impl RequestBuilderExt for RequestBuilder {
    fn send_checked(self) -> Box<Future<Item = Response, Error = Error> + Send> {
        Box::new(self.send().from_err().and_then(|resp| {
            let status = resp.status();
            if resp.status().is_client_error() || resp.status().is_server_error() {
                future::Either::A(extract_message(resp).and_then(move |message| {
                    trace!("HTTP request returned {}; error: {:?}", status, message);

                    future::err(Error::new(status.into(), message).with_status(status))
                }))
            } else {
                trace!("HTTP request to {} returned {}", resp.url(), resp.status());
                future::Either::B(future::ok(resp))
            }
        }))
    }
}

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
    endpoint_interface: String,
}

impl Session {
    /// Create a new session with a given authentication plugin.
    ///
    /// The resulting session will use the default endpoint interface (usually,
    /// public).
    pub fn new<Auth: AuthType + 'static>(auth_method: Auth) -> Session {
        let ep = auth_method.default_endpoint_interface();
        Session {
            auth: Arc::new(auth_method),
            cached_info: Arc::new(cache::MapCache::default()),
            endpoint_interface: ep,
        }
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
        self.endpoint_interface = endpoint_interface.into();
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
    pub fn get_endpoint<Srv: ServiceType + 'static>(
        &self,
        path: Vec<String>,
    ) -> impl Future<Item = Url, Error = Error> {
        let path_iter = path.into_iter();
        self.ensure_service_info::<Srv>().map(move |infos| {
            let endpoint = infos
                .extract(&Srv::catalog_type(), |info| info.root_url.clone())
                .expect("No cache record after caching");
            url::extend(endpoint, path_iter)
        })
    }

    /// Get the currently used major version from the given service.
    ///
    /// Can return `IncompatibleApiVersion` if the service does not support
    /// API version discovery at all.
    pub fn get_major_version<Srv: ServiceType + 'static>(
        &self,
    ) -> impl Future<Item = Option<ApiVersion>, Error = Error> {
        self.ensure_service_info::<Srv>().map(|infos| {
            infos
                .extract(&Srv::catalog_type(), |info| info.major_version)
                .expect("No cache record after caching")
        })
    }

    /// Get minimum/maximum API (micro)version information.
    ///
    /// Returns `None` if the range cannot be determined, which usually means
    /// that microversioning is not supported.
    pub fn get_api_versions<Srv: ServiceType + 'static>(
        &self,
    ) -> impl Future<Item = Option<(ApiVersion, ApiVersion)>, Error = Error> {
        self.ensure_service_info::<Srv>().map(|infos| {
            let min_max = infos
                .extract(&Srv::catalog_type(), |info| {
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
    pub fn pick_api_version<Srv: ServiceType + 'static>(
        &self,
        versions: Vec<ApiVersion>,
    ) -> impl Future<Item = Option<ApiVersion>, Error = Error> {
        self.ensure_service_info::<Srv>().map(move |infos| {
            infos
                .extract(&Srv::catalog_type(), |info| {
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
    pub fn supports_api_version<Srv: ServiceType + 'static>(
        &self,
        version: ApiVersion,
    ) -> impl Future<Item = bool, Error = Error> {
        self.ensure_service_info::<Srv>().map(move |infos| {
            infos
                .extract(&Srv::catalog_type(), |info| {
                    info.supports_api_version(version)
                })
                .expect("No cache record after caching")
        })
    }

    /// Make an HTTP request to the given service.
    pub fn request<Srv: ServiceType + 'static>(
        &self,
        method: Method,
        path: Vec<String>,
        api_version: Option<ApiVersion>,
    ) -> impl Future<Item = RequestBuilder, Error = Error> {
        let auth = Arc::clone(&self.auth);
        self.get_endpoint::<Srv>(path)
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
                    builder = match Srv::set_api_version_headers(builder, version) {
                        Ok(builder) => builder,
                        Err(err) => return future::err(err),
                    }
                }
                future::ok(builder)
            })
    }

    /// Start a GET request.
    #[inline]
    pub fn get<Srv: ServiceType + 'static>(
        &self,
        path: Vec<String>,
        api_version: Option<ApiVersion>,
    ) -> impl Future<Item = RequestBuilder, Error = Error> {
        self.request::<Srv>(Method::GET, path, api_version)
    }

    /// Start a POST request.
    #[inline]
    pub fn post<Srv: ServiceType + 'static>(
        &self,
        path: Vec<String>,
        api_version: Option<ApiVersion>,
    ) -> impl Future<Item = RequestBuilder, Error = Error> {
        self.request::<Srv>(Method::POST, path, api_version)
    }

    /// Start a PUT request.
    #[inline]
    pub fn put<Srv: ServiceType + 'static>(
        &self,
        path: Vec<String>,
        api_version: Option<ApiVersion>,
    ) -> impl Future<Item = RequestBuilder, Error = Error> {
        self.request::<Srv>(Method::PUT, path, api_version)
    }

    /// Start a DELETE request.
    #[inline]
    pub fn delete<Srv: ServiceType + 'static>(
        &self,
        path: Vec<String>,
        api_version: Option<ApiVersion>,
    ) -> impl Future<Item = RequestBuilder, Error = Error> {
        self.request::<Srv>(Method::DELETE, path, api_version)
    }

    fn ensure_service_info<Srv>(&self) -> impl Future<Item = Arc<Cache>, Error = Error>
    where
        Srv: ServiceType + 'static,
    {
        if self.cached_info.is_set(&Srv::catalog_type()) {
            future::Either::A(future::ok(Arc::clone(&self.cached_info)))
        } else {
            debug!(
                "No cached information for service {}, fetching",
                Srv::catalog_type()
            );

            let endpoint_interface = self.endpoint_interface.clone();
            let cached_info = Arc::clone(&self.cached_info);
            let auth_type = Arc::clone(&self.auth);
            future::Either::B(
                self.auth
                    .get_endpoint(
                        Srv::catalog_type().to_string(),
                        Some(endpoint_interface.clone()),
                    )
                    .and_then(move |ep| ServiceInfo::fetch::<Srv>(ep, auth_type))
                    .map(move |info| {
                        cached_info.set(Srv::catalog_type(), info);
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
    use super::super::{ApiVersion, NoAuth};
    use super::{ServiceType, Session};

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

    pub struct FakeService;

    impl ServiceType for FakeService {
        fn catalog_type() -> &'static str {
            "fake"
        }
    }

    #[test]
    fn test_get_endpoint() {
        let s = new_simple_session(URL);
        let ep = s.get_endpoint::<FakeService>(Vec::new()).wait().unwrap();
        assert_eq!(&ep.to_string(), URL);
    }

    #[test]
    fn test_get_endpoint2() {
        let s = new_simple_session(URL);
        let ep = s
            .get_endpoint::<FakeService>(vec!["v2".to_string(), "servers".to_string()])
            .wait()
            .unwrap();
        assert_eq!(&ep.to_string(), URL_WITH_SUFFIX);
    }

    #[test]
    fn test_get_major_version_absent() {
        let s = new_simple_session(URL);
        let res = s.get_major_version::<FakeService>().wait().unwrap();
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
        let res = s.get_major_version::<FakeService>().wait().unwrap();
        assert_eq!(res, Some(ApiVersion(2, 0)));
    }
}
