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

//! Adapter for a specific service.

use futures::Future;
use reqwest::r#async::{RequestBuilder, Response};
use reqwest::{Method, Url};
use serde::de::DeserializeOwned;
use serde::Serialize;

use super::config;
use super::request;
use super::services::ServiceType;
use super::sessioninner::SessionInner;
use super::{ApiVersion, AuthType, Error};

/// Adapter for a specific service.
///
/// An `Adapter` is very similar to a [Session](struct.Session.html), but is tied to a specific
/// service, and thus does not require passing a `service` argument to all calls.
#[derive(Debug, Clone)]
pub struct Adapter<Srv> {
    inner: SessionInner,
    service: Srv,
    endpoint_interface: Option<String>,
}

impl<Srv> Adapter<Srv> {
    /// Create a new adapter with a given authentication plugin.
    pub fn new<Auth: AuthType + 'static>(auth_type: Auth, service: Srv) -> Adapter<Srv> {
        Adapter {
            inner: SessionInner::new(auth_type),
            service,
            endpoint_interface: None,
        }
    }

    /// Create a new adapter from a `clouds.yaml` configuration file.
    pub fn from_config<S: AsRef<str>>(cloud_name: S, service: Srv) -> Result<Adapter<Srv>, Error> {
        Ok(config::from_config(cloud_name)?.into_adapter(service))
    }

    /// Create a new adapter with information from environment variables.
    ///
    /// Uses some of `OS_*` variables recognized by `python-openstackclient`.
    pub fn from_env(service: Srv) -> Result<Adapter<Srv>, Error> {
        Ok(config::from_env()?.into_adapter(service))
    }

    /// Create a new adapter from its components.
    #[inline]
    pub(crate) fn new_from(
        inner: SessionInner,
        service: Srv,
        endpoint_interface: Option<String>,
    ) -> Adapter<Srv> {
        Adapter {
            inner,
            service,
            endpoint_interface,
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
        &self.endpoint_interface
    }

    /// Update the authentication and purges cached endpoint information.
    ///
    /// # Warning
    ///
    /// Authentication will also be updated for clones of this `Adapter` and its parent `Session`,
    /// since they share the same authentication object.
    #[inline]
    pub fn refresh(&mut self) -> impl Future<Item = (), Error = Error> + Send {
        self.inner.refresh()
    }

    /// Set a new authentication for this `Adapter`.
    ///
    /// This call clears the cached service information for this `Adapter`.
    /// It does not, however, affect clones of this `Adapter`.
    #[inline]
    pub fn set_auth_type<Auth: AuthType + 'static>(&mut self, auth_type: Auth) {
        self.inner.set_auth_type(auth_type)
    }

    /// Set endpoint interface to use.
    ///
    /// This call clears the cached service information for this `Adapter`.
    /// It does not, however, affect clones of this `Adapter`.
    pub fn set_endpoint_interface<S>(&mut self, endpoint_interface: S)
    where
        S: Into<String>,
    {
        self.inner.reset_cache();
        self.endpoint_interface = Some(endpoint_interface.into());
    }

    /// Convert this adapter into one using the given authentication.
    #[inline]
    pub fn with_auth_type<Auth: AuthType + 'static>(mut self, auth_method: Auth) -> Adapter<Srv> {
        self.set_auth_type(auth_method);
        self
    }

    /// Convert this adapter into one using the given endpoint interface.
    #[inline]
    pub fn with_endpoint_interface<S>(mut self, endpoint_interface: S) -> Adapter<Srv>
    where
        S: Into<String>,
    {
        self.set_endpoint_interface(endpoint_interface);
        self
    }
}

impl<Srv: ServiceType + Send + Clone> Adapter<Srv> {
    /// Get minimum/maximum API (micro)version information.
    ///
    /// Returns `None` if the range cannot be determined, which usually means
    /// that microversioning is not supported.
    ///
    /// ```rust,no_run
    /// use futures::Future;
    ///
    /// let adapter = osauth::Adapter::from_env(osauth::services::COMPUTE)
    ///     .expect("Failed to create an identity provider from the environment");
    /// let future = adapter
    ///     .get_api_versions()
    ///     .map(|maybe_versions| {
    ///         if let Some((min, max)) = maybe_versions {
    ///             println!("The compute service supports versions {} to {}", min, max);
    ///         } else {
    ///             println!("The compute service does not support microversioning");
    ///         }
    ///     });
    /// ```
    pub fn get_api_versions(
        &self,
    ) -> impl Future<Item = Option<(ApiVersion, ApiVersion)>, Error = Error> + Send {
        self.inner
            .get_api_versions(self.service.clone(), &self.endpoint_interface)
    }

    /// Construct an endpoint from the path;
    ///
    /// You won't need to use this call most of the time, since all request calls can fetch the
    /// endpoint automatically.
    pub fn get_endpoint<I>(&self, path: I) -> impl Future<Item = Url, Error = Error> + Send
    where
        I: IntoIterator,
        I::Item: AsRef<str>,
        I::IntoIter: Send,
    {
        self.inner
            .get_endpoint(self.service.clone(), &self.endpoint_interface, path)
    }

    /// Get the currently used major version from the given service.
    ///
    /// Can return `None` if the service does not support API version discovery at all.
    pub fn get_major_version(
        &self,
    ) -> impl Future<Item = Option<ApiVersion>, Error = Error> + Send {
        self.inner
            .get_major_version(self.service.clone(), &self.endpoint_interface)
    }

    /// Pick the highest API version supported by the service.
    ///
    /// Returns `None` if none of the requested versions are available.
    ///
    /// ```rust,no_run
    /// use futures::Future;
    ///
    /// let adapter = osauth::Adapter::from_env(osauth::services::COMPUTE)
    ///     .expect("Failed to create an identity provider from the environment");
    /// let candidates = vec![osauth::ApiVersion(1, 2), osauth::ApiVersion(1, 42)];
    /// let future = adapter
    ///     .pick_api_version(candidates)
    ///     .and_then(|maybe_version| {
    ///         if let Some(version) = maybe_version {
    ///             println!("Using version {}", version);
    ///         } else {
    ///             println!("Using the base version");
    ///         }
    ///         adapter.get(&["servers"], maybe_version)
    ///     });
    /// ```
    pub fn pick_api_version<I>(
        &self,
        versions: I,
    ) -> impl Future<Item = Option<ApiVersion>, Error = Error> + Send
    where
        I: IntoIterator<Item = ApiVersion>,
        I::IntoIter: Send,
    {
        self.inner
            .pick_api_version(self.service.clone(), &self.endpoint_interface, versions)
    }

    /// Check if the service supports the API version.
    pub fn supports_api_version(
        &self,
        version: ApiVersion,
    ) -> impl Future<Item = bool, Error = Error> + Send {
        self.pick_api_version(Some(version)).map(|x| x.is_some())
    }

    /// Make an HTTP request.
    ///
    /// The `path` argument is a URL path without the service endpoint (e.g. `/servers/1234`).
    ///
    /// If `api_version` is set, it is send with the request to enable a higher API version.
    /// Otherwise the base API version is used. You can use
    /// [pick_api_version](#method.pick_api_version) to choose an API version to use.
    ///
    /// The result is a `RequestBuilder` that can be customized further. Error checking and response
    /// parsing can be done using functions from the [request](request/index.html) module.
    ///
    /// ```rust,no_run
    /// use futures::Future;
    /// use reqwest::Method;
    ///
    /// let adapter = osauth::Adapter::from_env(osauth::services::COMPUTE)
    ///     .expect("Failed to create an identity provider from the environment");
    /// let future = adapter
    ///     .request(Method::HEAD, &["servers", "1234"], None)
    ///     .then(osauth::request::send_checked)
    ///     .map(|response| {
    ///         println!("Response: {:?}", response);
    ///     });
    /// ```
    ///
    /// This is the most generic call to make a request. You may prefer to use more specific `get`,
    /// `post`, `put` or `delete` calls instead.
    pub fn request<I>(
        &self,
        method: Method,
        path: I,
        api_version: Option<ApiVersion>,
    ) -> impl Future<Item = RequestBuilder, Error = Error> + Send
    where
        I: IntoIterator,
        I::Item: AsRef<str>,
        I::IntoIter: Send,
    {
        self.inner.request(
            self.service.clone(),
            &self.endpoint_interface,
            method,
            path,
            api_version,
        )
    }

    /// Start a GET request.
    ///
    /// Use this call if you need some advanced features of the resulting `RequestBuilder`.
    /// Otherwise use:
    /// * [get](#method.get) to issue a generic GET without a query.
    /// * [get_query](#method.get_query) to issue a generic GET with a query.
    /// * [get_json](#method.get_json) to issue GET and parse a JSON result.
    /// * [get_json_query](#method.get_json_query) to issue GET with a query and parse a JSON
    ///   result.
    ///
    /// See [request](#method.request) for an explanation of the parameters.
    #[inline]
    pub fn start_get<I>(
        &self,
        path: I,
        api_version: Option<ApiVersion>,
    ) -> impl Future<Item = RequestBuilder, Error = Error> + Send
    where
        I: IntoIterator,
        I::Item: AsRef<str>,
        I::IntoIter: Send,
    {
        self.request(Method::GET, path, api_version)
    }

    /// Issue a GET request.
    ///
    /// See [request](#method.request) for an explanation of the parameters.
    #[inline]
    pub fn get<I>(
        &self,
        path: I,
        api_version: Option<ApiVersion>,
    ) -> impl Future<Item = Response, Error = Error> + Send
    where
        I: IntoIterator,
        I::Item: AsRef<str>,
        I::IntoIter: Send,
    {
        self.start_get(path, api_version)
            .then(request::send_checked)
    }

    /// Fetch a JSON using the GET request.
    ///
    /// ```rust,no_run
    /// use futures::Future;
    /// use serde::Deserialize;
    ///
    /// #[derive(Debug, Deserialize)]
    /// pub struct Server {
    ///     pub id: String,
    ///     pub name: String,
    /// }
    ///
    /// #[derive(Debug, Deserialize)]
    /// pub struct ServersRoot {
    ///     pub servers: Vec<Server>,
    /// }
    ///
    /// let adapter = osauth::from_env()
    ///     .expect("Failed to create an identity provider from the environment")
    ///     .into_adapter(osauth::services::COMPUTE);
    /// let future = adapter
    ///     .get_json(&["servers"], None)
    ///     .map(|servers: ServersRoot| {
    ///         for srv in servers.servers {
    ///             println!("ID = {}, Name = {}", srv.id, srv.name);
    ///         }
    ///     });
    /// ```
    ///
    /// See [request](#method.request) for an explanation of the parameters.
    #[inline]
    pub fn get_json<I, T>(
        &self,
        path: I,
        api_version: Option<ApiVersion>,
    ) -> impl Future<Item = T, Error = Error> + Send
    where
        I: IntoIterator,
        I::Item: AsRef<str>,
        I::IntoIter: Send,
        T: DeserializeOwned + Send,
    {
        self.start_get(path, api_version).then(request::fetch_json)
    }

    /// Fetch a JSON using the GET request with a query.
    ///
    /// See `reqwest` crate documentation for how to define a query.
    /// See [request](#method.request) for an explanation of the parameters.
    #[inline]
    pub fn get_json_query<I, Q, T>(
        &self,
        path: I,
        query: Q,
        api_version: Option<ApiVersion>,
    ) -> impl Future<Item = T, Error = Error> + Send
    where
        I: IntoIterator,
        I::Item: AsRef<str>,
        I::IntoIter: Send,
        Q: Serialize + Send,
        T: DeserializeOwned + Send,
    {
        self.start_get(path, api_version)
            .map(move |builder| builder.query(&query))
            .then(request::fetch_json)
    }

    /// Issue a GET request with a query
    ///
    /// See `reqwest` crate documentation for how to define a query.
    /// See [request](#method.request) for an explanation of the parameters.
    #[inline]
    pub fn get_query<I, Q>(
        &self,
        path: I,
        query: Q,
        api_version: Option<ApiVersion>,
    ) -> impl Future<Item = Response, Error = Error> + Send
    where
        I: IntoIterator,
        I::Item: AsRef<str>,
        I::IntoIter: Send,
        Q: Serialize + Send,
    {
        self.start_get(path, api_version)
            .map(move |builder| builder.query(&query))
            .then(request::send_checked)
    }

    /// Start a POST request.
    ///
    /// See [request](#method.request) for an explanation of the parameters.
    #[inline]
    pub fn start_post<I>(
        &self,
        path: I,
        api_version: Option<ApiVersion>,
    ) -> impl Future<Item = RequestBuilder, Error = Error> + Send
    where
        I: IntoIterator,
        I::Item: AsRef<str>,
        I::IntoIter: Send,
    {
        self.request(Method::POST, path, api_version)
    }

    /// POST a JSON object.
    ///
    /// The `body` argument is anything that can be serialized into JSON.
    ///
    /// See [request](#method.request) for an explanation of the other parameters.
    #[inline]
    pub fn post<I, T>(
        &self,
        path: I,
        body: T,
        api_version: Option<ApiVersion>,
    ) -> impl Future<Item = Response, Error = Error> + Send
    where
        I: IntoIterator,
        I::Item: AsRef<str>,
        I::IntoIter: Send,
        T: Serialize + Send,
    {
        self.start_post(path, api_version)
            .map(move |builder| builder.json(&body))
            .then(request::send_checked)
    }

    /// POST a JSON object and receive a JSON back.
    ///
    /// The `body` argument is anything that can be serialized into JSON.
    ///
    /// See [request](#method.request) for an explanation of the other parameters.
    #[inline]
    pub fn post_json<I, T, R>(
        &self,
        path: I,
        body: T,
        api_version: Option<ApiVersion>,
    ) -> impl Future<Item = R, Error = Error> + Send
    where
        I: IntoIterator,
        I::Item: AsRef<str>,
        I::IntoIter: Send,
        T: Serialize + Send,
        R: DeserializeOwned + Send,
    {
        self.start_post(path, api_version)
            .map(move |builder| builder.json(&body))
            .then(request::fetch_json)
    }

    /// Start a PUT request.
    ///
    /// See [request](#method.request) for an explanation of the parameters.
    #[inline]
    pub fn start_put<I>(
        &self,
        path: I,
        api_version: Option<ApiVersion>,
    ) -> impl Future<Item = RequestBuilder, Error = Error> + Send
    where
        I: IntoIterator,
        I::Item: AsRef<str>,
        I::IntoIter: Send,
    {
        self.request(Method::PUT, path, api_version)
    }

    /// PUT a JSON object.
    ///
    /// The `body` argument is anything that can be serialized into JSON.
    ///
    /// See [request](#method.request) for an explanation of the other parameters.
    #[inline]
    pub fn put<I, T>(
        &self,
        path: I,
        body: T,
        api_version: Option<ApiVersion>,
    ) -> impl Future<Item = Response, Error = Error> + Send
    where
        I: IntoIterator,
        I::Item: AsRef<str>,
        I::IntoIter: Send,
        T: Serialize + Send,
    {
        self.start_put(path, api_version)
            .map(move |builder| builder.json(&body))
            .then(request::send_checked)
    }

    /// Issue an empty PUT request.
    ///
    /// See [request](#method.request) for an explanation of the parameters.
    #[inline]
    pub fn put_empty<I>(
        &self,
        path: I,
        api_version: Option<ApiVersion>,
    ) -> impl Future<Item = Response, Error = Error> + Send
    where
        I: IntoIterator,
        I::Item: AsRef<str>,
        I::IntoIter: Send,
    {
        self.start_put(path, api_version)
            .then(request::send_checked)
    }

    /// PUT a JSON object and receive a JSON back.
    ///
    /// The `body` argument is anything that can be serialized into JSON.
    ///
    /// See [request](#method.request) for an explanation of the other parameters.
    #[inline]
    pub fn put_json<I, T, R>(
        &self,
        path: I,
        body: T,
        api_version: Option<ApiVersion>,
    ) -> impl Future<Item = R, Error = Error> + Send
    where
        I: IntoIterator,
        I::Item: AsRef<str>,
        I::IntoIter: Send,
        T: Serialize + Send,
        R: DeserializeOwned + Send,
    {
        self.start_put(path, api_version)
            .map(move |builder| builder.json(&body))
            .then(request::fetch_json)
    }

    /// Start a DELETE request.
    ///
    /// See [request](#method.request) for an explanation of the parameters.
    #[inline]
    pub fn start_delete<I>(
        &self,
        path: I,
        api_version: Option<ApiVersion>,
    ) -> impl Future<Item = RequestBuilder, Error = Error> + Send
    where
        I: IntoIterator,
        I::Item: AsRef<str>,
        I::IntoIter: Send,
    {
        self.request(Method::DELETE, path, api_version)
    }

    /// Issue a DELETE request.
    ///
    /// See [request](#method.request) for an explanation of the parameters.
    #[inline]
    pub fn delete<I>(
        &self,
        path: I,
        api_version: Option<ApiVersion>,
    ) -> impl Future<Item = Response, Error = Error> + Send
    where
        I: IntoIterator,
        I::Item: AsRef<str>,
        I::IntoIter: Send,
    {
        self.start_delete(path, api_version)
            .then(request::send_checked)
    }
}
