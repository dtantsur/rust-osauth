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

//! Synchronous wrapper for a session.
//!
//! This module is only available when the `sync` feature is enabled.

use std::cell::RefCell;

use futures::Future;
use reqwest::r#async::{RequestBuilder, Response};
use reqwest::{Method, Url};
use serde::de::DeserializeOwned;
use serde::Serialize;
use tokio::runtime::current_thread::Runtime;

use super::request;
use super::services::ServiceType;
use super::{ApiVersion, AuthType, Error, Session};

/// A result of an OpenStack operation.
pub type Result<T> = ::std::result::Result<T, Error>;

/// A synchronous wrapper for an asynchronous session.
#[derive(Debug)]
pub struct SyncSession {
    inner: Session,
    runtime: RefCell<Runtime>,
}

impl From<SyncSession> for Session {
    fn from(value: SyncSession) -> Session {
        value.inner
    }
}

impl From<Session> for SyncSession {
    fn from(value: Session) -> SyncSession {
        SyncSession::new(value)
    }
}

impl Clone for SyncSession {
    fn clone(&self) -> SyncSession {
        SyncSession::new(self.inner.clone())
    }
}

impl SyncSession {
    /// Create a new synchronous wrapper.
    pub fn new(session: Session) -> SyncSession {
        SyncSession {
            inner: session,
            runtime: RefCell::new(Runtime::new().expect("Cannot create a runtime")),
        }
    }

    /// Get a reference to the authentication type in use.
    #[inline]
    pub fn auth_type(&self) -> &AuthType {
        self.inner.auth_type()
    }

    /// Endpoint interface in use (if any).
    #[inline]
    pub fn endpoint_interface(&self) -> &Option<String> {
        &self.inner.endpoint_interface()
    }

    /// Refresh the session.
    #[inline]
    pub fn refresh(&mut self) -> Result<()> {
        let fut = self.inner.refresh();
        self.block_on(fut)
    }

    /// Reference to the asynchronous session used.
    #[inline]
    pub fn session(&self) -> &Session {
        &self.inner
    }

    /// Set a new authentication for this `Session`.
    ///
    /// This call clears the cached service information for this `Session`.
    /// It does not, however, affect clones of this `Session`.
    #[inline]
    pub fn set_auth_type<Auth: AuthType + 'static>(&mut self, auth_type: Auth) {
        self.inner.set_auth_type(auth_type);
    }

    /// Set endpoint interface to use.
    ///
    /// This call clears the cached service information for this `Session`.
    /// It does not, however, affect clones of this `Session`.
    #[inline]
    pub fn set_endpoint_interface<S>(&mut self, endpoint_interface: S)
    where
        S: Into<String>,
    {
        self.inner.set_endpoint_interface(endpoint_interface);
    }

    /// Convert this session into one using the given authentication.
    #[inline]
    pub fn with_auth_type<Auth: AuthType + 'static>(mut self, auth_method: Auth) -> SyncSession {
        self.set_auth_type(auth_method);
        self
    }

    /// Convert this session into one using the given endpoint interface.
    #[inline]
    pub fn with_endpoint_interface<S>(mut self, endpoint_interface: S) -> SyncSession
    where
        S: Into<String>,
    {
        self.set_endpoint_interface(endpoint_interface);
        self
    }

    /// Get minimum/maximum API (micro)version information.
    ///
    /// Returns `None` if the range cannot be determined, which usually means
    /// that microversioning is not supported.
    ///
    /// ```rust,no_run
    /// let session = osauth::sync::SyncSession::new(
    ///     osauth::from_env().expect("Failed to create an identity provider from the environment")
    /// );
    /// let maybe_versions = session
    ///     .get_api_versions(osauth::services::COMPUTE)
    ///     .expect("Cannot determine supported API versions");
    /// if let Some((min, max)) = maybe_versions {
    ///     println!("The compute service supports versions {} to {}", min, max);
    /// } else {
    ///     println!("The compute service does not support microversioning");
    /// }
    /// ```
    #[inline]
    pub fn get_api_versions<Srv>(&self, service: Srv) -> Result<Option<(ApiVersion, ApiVersion)>>
    where
        Srv: ServiceType + Send,
    {
        self.block_on(self.inner.get_api_versions(service))
    }

    /// Construct and endpoint for the given service from the path.
    ///
    /// You won't need to use this call most of the time, since all request calls can fetch the
    /// endpoint automatically.
    #[inline]
    pub fn get_endpoint<Srv, I>(&self, service: Srv, path: I) -> Result<Url>
    where
        Srv: ServiceType + Send,
        I: IntoIterator,
        I::Item: AsRef<str>,
        I::IntoIter: Send,
    {
        self.block_on(self.inner.get_endpoint(service, path))
    }

    /// Get the currently used major version from the given service.
    ///
    /// Can return `None` if the service does not support API version discovery at all.
    #[inline]
    pub fn get_major_version<Srv>(&self, service: Srv) -> Result<Option<ApiVersion>>
    where
        Srv: ServiceType + Send,
    {
        self.block_on(self.inner.get_major_version(service))
    }

    /// Pick the highest API version supported by the service.
    ///
    /// Returns `None` if none of the requested versions are available.
    ///
    /// ```rust,no_run
    /// let session = osauth::sync::SyncSession::new(
    ///     osauth::from_env().expect("Failed to create an identity provider from the environment")
    /// );
    /// let candidates = vec![osauth::ApiVersion(1, 2), osauth::ApiVersion(1, 42)];
    /// let maybe_version = session
    ///     .pick_api_version(osauth::services::COMPUTE, candidates)
    ///     .expect("Cannot negotiate an API version");
    /// if let Some(version) = maybe_version {
    ///     println!("Using version {}", version);
    /// } else {
    ///     println!("Using the base version");
    /// }
    /// ```
    #[inline]
    pub fn pick_api_version<Srv, I>(&self, service: Srv, versions: I) -> Result<Option<ApiVersion>>
    where
        Srv: ServiceType + Send,
        I: IntoIterator<Item = ApiVersion>,
        I::IntoIter: Send,
    {
        self.block_on(self.inner.pick_api_version(service, versions))
    }

    /// Check if the service supports the API version.
    #[inline]
    pub fn supports_api_version<Srv: ServiceType + Send>(
        &self,
        service: Srv,
        version: ApiVersion,
    ) -> Result<bool> {
        self.block_on(self.inner.supports_api_version(service, version))
    }

    /// Make an HTTP request to the given service.
    ///
    /// The `service` argument is an object implementing the
    /// [ServiceType](../services/trait.ServiceType.html) trait. Some known service types are
    /// available in the [services](../services/index.html) module.
    ///
    /// The `path` argument is a URL path without the service endpoint (e.g. `/servers/1234`).
    ///
    /// If `api_version` is set, it is send with the request to enable a higher API version.
    /// Otherwise the base API version is used. You can use
    /// [pick_api_version](#method.pick_api_version) to choose an API version to use.
    ///
    /// The result is a `RequestBuilder` that can be customized further. Error checking and response
    /// parsing can be done using e.g. [send_checked](#method.send_checked) or
    /// [fetch_json](#method.fetch_json).
    ///
    /// ```rust,no_run
    /// use reqwest::Method;
    ///
    /// let session = osauth::sync::SyncSession::new(
    ///     osauth::from_env().expect("Failed to create an identity provider from the environment")
    /// );
    /// session
    ///     .request(osauth::services::COMPUTE, Method::HEAD, &["servers", "1234"], None)
    ///     .and_then(|builder| session.send_checked(builder))
    ///     .map(|response| {
    ///         println!("Response: {:?}", response);
    ///     });
    /// ```
    ///
    /// This is the most generic call to make a request. You may prefer to use more specific `get`,
    /// `post`, `put` or `delete` calls instead.
    pub fn request<Srv, I>(
        &self,
        service: Srv,
        method: Method,
        path: I,
        api_version: Option<ApiVersion>,
    ) -> Result<RequestBuilder>
    where
        Srv: ServiceType + Send + Clone,
        I: IntoIterator,
        I::Item: AsRef<str>,
        I::IntoIter: Send,
    {
        self.block_on(self.inner.request(service, method, path, api_version))
    }

    /// Issue a GET request.
    ///
    /// See [request](#method.request) for an explanation of the parameters.
    #[inline]
    pub fn get<Srv, I>(
        &self,
        service: Srv,
        path: I,
        api_version: Option<ApiVersion>,
    ) -> Result<Response>
    where
        Srv: ServiceType + Send + Clone,
        I: IntoIterator,
        I::Item: AsRef<str>,
        I::IntoIter: Send,
    {
        self.send_checked(self.request(service, Method::GET, path, api_version)?)
    }

    /// Fetch a JSON using the GET request.
    ///
    /// ```rust,no_run
    /// use osproto::common::IdAndName;
    /// use serde::Deserialize;
    ///
    /// #[derive(Debug, Deserialize)]
    /// pub struct ServersRoot {
    ///     pub servers: Vec<IdAndName>,
    /// }
    ///
    /// let session = osauth::sync::SyncSession::new(
    ///     osauth::from_env().expect("Failed to create an identity provider from the environment")
    /// );
    ///
    /// session
    ///     .get_json(osauth::services::COMPUTE, &["servers"], None)
    ///     .map(|servers: ServersRoot| {
    ///         for srv in servers.servers {
    ///             println!("ID = {}, Name = {}", srv.id, srv.name);
    ///         }
    ///     });
    /// ```
    ///
    /// See [request](#method.request) for an explanation of the parameters.
    #[inline]
    pub fn get_json<Srv, I, T>(
        &self,
        service: Srv,
        path: I,
        api_version: Option<ApiVersion>,
    ) -> Result<T>
    where
        Srv: ServiceType + Send + Clone,
        I: IntoIterator,
        I::Item: AsRef<str>,
        I::IntoIter: Send,
        T: DeserializeOwned + Send,
    {
        self.fetch_json(self.request(service, Method::GET, path, api_version)?)
    }

    /// Fetch a JSON using the GET request with a query.
    ///
    /// See `reqwest` crate documentation for how to define a query.
    /// See [request](#method.request) for an explanation of the parameters.
    #[inline]
    pub fn get_json_query<Srv, I, Q, T>(
        &self,
        service: Srv,
        path: I,
        query: Q,
        api_version: Option<ApiVersion>,
    ) -> Result<T>
    where
        Srv: ServiceType + Send + Clone,
        I: IntoIterator,
        I::Item: AsRef<str>,
        I::IntoIter: Send,
        Q: Serialize + Send,
        T: DeserializeOwned + Send,
    {
        self.fetch_json(
            self.request(service, Method::GET, path, api_version)?
                .query(&query),
        )
    }

    /// Issue a GET request with a query
    ///
    /// See `reqwest` crate documentation for how to define a query.
    /// See [request](#method.request) for an explanation of the parameters.
    #[inline]
    pub fn get_query<Srv, I, Q>(
        &self,
        service: Srv,
        path: I,
        query: Q,
        api_version: Option<ApiVersion>,
    ) -> Result<Response>
    where
        Srv: ServiceType + Send + Clone,
        I: IntoIterator,
        I::Item: AsRef<str>,
        I::IntoIter: Send,
        Q: Serialize + Send,
    {
        self.send_checked(
            self.request(service, Method::GET, path, api_version)?
                .query(&query),
        )
    }

    /// POST a JSON object.
    ///
    /// The `body` argument is anything that can be serialized into JSON.
    ///
    /// See [request](#method.request) for an explanation of the other parameters.
    #[inline]
    pub fn post<Srv, I, T>(
        &self,
        service: Srv,
        path: I,
        body: T,
        api_version: Option<ApiVersion>,
    ) -> Result<Response>
    where
        Srv: ServiceType + Send + Clone,
        I: IntoIterator,
        I::Item: AsRef<str>,
        I::IntoIter: Send,
        T: Serialize + Send,
    {
        self.send_checked(
            self.request(service, Method::POST, path, api_version)?
                .json(&body),
        )
    }

    /// POST a JSON object and receive a JSON back.
    ///
    /// The `body` argument is anything that can be serialized into JSON.
    ///
    /// See [request](#method.request) for an explanation of the other parameters.
    #[inline]
    pub fn post_json<Srv, I, T, R>(
        &self,
        service: Srv,
        path: I,
        body: T,
        api_version: Option<ApiVersion>,
    ) -> Result<R>
    where
        Srv: ServiceType + Send + Clone,
        I: IntoIterator,
        I::Item: AsRef<str>,
        I::IntoIter: Send,
        T: Serialize + Send,
        R: DeserializeOwned + Send,
    {
        self.fetch_json(
            self.request(service, Method::POST, path, api_version)?
                .json(&body),
        )
    }

    /// PUT a JSON object.
    ///
    /// The `body` argument is anything that can be serialized into JSON.
    ///
    /// See [request](#method.request) for an explanation of the other parameters.
    #[inline]
    pub fn put<Srv, I, T>(
        &self,
        service: Srv,
        path: I,
        body: T,
        api_version: Option<ApiVersion>,
    ) -> Result<Response>
    where
        Srv: ServiceType + Send + Clone,
        I: IntoIterator,
        I::Item: AsRef<str>,
        I::IntoIter: Send,
        T: Serialize + Send,
    {
        self.send_checked(
            self.request(service, Method::PUT, path, api_version)?
                .json(&body),
        )
    }

    /// Issue an empty PUT request.
    ///
    /// See [request](#method.request) for an explanation of the parameters.
    #[inline]
    pub fn put_empty<Srv, I>(
        &self,
        service: Srv,
        path: I,
        api_version: Option<ApiVersion>,
    ) -> Result<Response>
    where
        Srv: ServiceType + Send + Clone,
        I: IntoIterator,
        I::Item: AsRef<str>,
        I::IntoIter: Send,
    {
        self.send_checked(self.request(service, Method::PUT, path, api_version)?)
    }

    /// PUT a JSON object and receive a JSON back.
    ///
    /// The `body` argument is anything that can be serialized into JSON.
    ///
    /// See [request](#method.request) for an explanation of the other parameters.
    #[inline]
    pub fn put_json<Srv, I, T, R>(
        &self,
        service: Srv,
        path: I,
        body: T,
        api_version: Option<ApiVersion>,
    ) -> Result<R>
    where
        Srv: ServiceType + Send + Clone,
        I: IntoIterator,
        I::Item: AsRef<str>,
        I::IntoIter: Send,
        T: Serialize + Send,
        R: DeserializeOwned + Send,
    {
        self.fetch_json(
            self.request(service, Method::PUT, path, api_version)?
                .json(&body),
        )
    }

    /// Issue a DELETE request.
    ///
    /// See [request](#method.request) for an explanation of the parameters.
    #[inline]
    pub fn delete<Srv, I>(
        &self,
        service: Srv,
        path: I,
        api_version: Option<ApiVersion>,
    ) -> Result<Response>
    where
        Srv: ServiceType + Send + Clone,
        I: IntoIterator,
        I::Item: AsRef<str>,
        I::IntoIter: Send,
    {
        self.send_checked(self.request(service, Method::DELETE, path, api_version)?)
    }

    /// Send the response and convert the response to a JSON.
    #[inline]
    pub fn fetch_json<T>(&self, builder: RequestBuilder) -> Result<T>
    where
        T: DeserializeOwned + Send,
    {
        self.block_on(builder.send().then(request::to_json))
    }

    /// Check the response and convert errors into OpenStack ones.
    #[inline]
    pub fn send_checked(&self, builder: RequestBuilder) -> Result<Response> {
        self.block_on(builder.send().then(request::check))
    }

    #[inline]
    fn block_on<F>(&self, f: F) -> ::std::result::Result<F::Item, F::Error>
    where
        F: Future,
    {
        self.runtime.borrow_mut().block_on(f)
    }
}

#[cfg(test)]
mod test {
    use super::super::session::test;
    use super::super::ApiVersion;
    use super::SyncSession;

    fn new_simple_sync_session(url: &str) -> SyncSession {
        SyncSession::new(test::new_simple_session(url))
    }

    fn new_sync_session(url: &str) -> SyncSession {
        SyncSession::new(test::new_session(url, test::fake_service_info()))
    }

    #[test]
    fn test_get_api_versions_absent() {
        let s = new_simple_sync_session(test::URL);
        let vers = s.get_api_versions(test::FAKE).unwrap();
        assert!(vers.is_none());
    }

    #[test]
    fn test_get_api_versions_present() {
        let s = new_sync_session(test::URL);
        let (min, max) = s.get_api_versions(test::FAKE).unwrap().unwrap();
        assert_eq!(min, test::MIN_VERSION);
        assert_eq!(max, test::MAX_VERSION);
    }

    #[test]
    fn test_get_endpoint() {
        let s = new_simple_sync_session(test::URL);
        let ep = s.get_endpoint(test::FAKE, &[""]).unwrap();
        assert_eq!(&ep.to_string(), test::URL);
    }

    #[test]
    fn test_get_endpoint_slice() {
        let s = new_simple_sync_session(test::URL);
        let ep = s.get_endpoint(test::FAKE, &["v2", "servers"]).unwrap();
        assert_eq!(&ep.to_string(), test::URL_WITH_SUFFIX);
    }

    #[test]
    fn test_get_endpoint_vec() {
        let s = new_simple_sync_session(test::URL);
        let ep = s
            .get_endpoint(test::FAKE, vec!["v2".to_string(), "servers".to_string()])
            .unwrap();
        assert_eq!(&ep.to_string(), test::URL_WITH_SUFFIX);
    }

    #[test]
    fn test_get_major_version_absent() {
        let s = new_simple_sync_session(test::URL);
        let res = s.get_major_version(test::FAKE).unwrap();
        assert!(res.is_none());
    }

    #[test]
    fn test_get_major_version_present() {
        let s = new_sync_session(test::URL);
        let res = s.get_major_version(test::FAKE).unwrap();
        assert_eq!(res, Some(test::MAJOR_VERSION));
    }

    #[test]
    fn test_pick_api_version_empty() {
        let s = new_sync_session(test::URL);
        let res = s.pick_api_version(test::FAKE, None).unwrap();
        assert!(res.is_none());
    }

    #[test]
    fn test_pick_api_version_empty_vec() {
        let s = new_sync_session(test::URL);
        let res = s.pick_api_version(test::FAKE, Vec::new()).unwrap();
        assert!(res.is_none());
    }

    #[test]
    fn test_pick_api_version() {
        let s = new_sync_session(test::URL);
        let choice = vec![
            ApiVersion(2, 0),
            ApiVersion(2, 2),
            ApiVersion(2, 4),
            ApiVersion(2, 99),
        ];
        let res = s.pick_api_version(test::FAKE, choice).unwrap();
        assert_eq!(res, Some(ApiVersion(2, 4)));
    }

    #[test]
    fn test_pick_api_version_option() {
        let s = new_sync_session(test::URL);
        let res = s
            .pick_api_version(test::FAKE, Some(ApiVersion(2, 4)))
            .unwrap();
        assert_eq!(res, Some(ApiVersion(2, 4)));
    }

    #[test]
    fn test_pick_api_version_impossible() {
        let s = new_sync_session(test::URL);
        let choice = vec![ApiVersion(2, 0), ApiVersion(2, 99)];
        let res = s.pick_api_version(test::FAKE, choice).unwrap();
        assert!(res.is_none());
    }
}