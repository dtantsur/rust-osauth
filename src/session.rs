// Copyright 2019-2020 Dmitry Tantsur <divius.inside@gmail.com>
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
use std::ops::Deref;
use std::sync::Arc;

#[cfg(feature = "stream")]
use futures::Stream;
use log::{debug, trace};
use reqwest::header::HeaderMap;
use reqwest::{Method, RequestBuilder, Response, Url};
use serde::de::DeserializeOwned;
use serde::Serialize;
use tokio::sync::RwLock;

use super::loading;
use super::protocol::ServiceInfo;
use super::request;
use super::services::ServiceType;
#[cfg(feature = "stream")]
use super::stream::{paginated, Resource};
use super::url;
use super::{Adapter, ApiVersion, AuthType, EndpointFilters, Error, InterfaceType};

type Cache = HashMap<&'static str, ServiceInfo>;

/// An OpenStack API session.
///
/// The session object serves as a wrapper around an [authentication type](trait.AuthType.html),
/// providing convenient methods to make HTTP requests and work with microversions.
///
/// # Note
///
/// All clones of one session share the same authentication and endpoint cache. Use
/// [with_auth_type](#method.with_auth_type) to detach a session.
#[derive(Debug, Clone)]
pub struct Session {
    auth: Arc<dyn AuthType>,
    cached_info: Arc<RwLock<Cache>>,
    endpoint_filters: EndpointFilters,
    endpoint_overrides: HashMap<String, Url>,
}

impl Session {
    /// Create a new session with a given authentication plugin.
    ///
    /// The resulting session will use the default endpoint interface (usually, public).
    pub fn new<Auth: AuthType + 'static>(auth_type: Auth) -> Session {
        Session {
            auth: Arc::new(auth_type),
            cached_info: Arc::new(RwLock::new(HashMap::new())),
            endpoint_filters: EndpointFilters::default(),
            endpoint_overrides: HashMap::new(),
        }
    }

    /// Create a `Session` from a `clouds.yaml` configuration file.
    ///
    /// See [openstacksdk
    /// documentation](https://docs.openstack.org/openstacksdk/latest/user/guides/connect_from_config.html)
    /// for detailed information on the format of the configuration file.
    ///
    /// The `cloud_name` argument is a name of the cloud entry to use.
    ///
    /// Supported features are:
    /// 1. Password and HTTP basic authentication, as well as no authentication.
    /// 2. Users, projects and domains by name.
    /// 3. Region names (for password authentication).
    /// 4. Custom TLS CA certificates.
    /// 5. Profiles from `clouds-public.yaml`.
    /// 6. Credentials from `secure.yaml`.
    ///
    /// A non-exhaustive list of features that are not currently supported:
    /// 1. Users, projects and domains by ID.
    /// 2. Adapter options, such as interfaces, default API versions and endpoint overrides.
    /// 3. Other authentication methods.
    /// 4. Identity v2.
    #[inline]
    pub fn from_config<S: AsRef<str>>(cloud_name: S) -> Result<Session, Error> {
        loading::from_config(cloud_name)
    }

    /// Create a `Session` from environment variables.
    ///
    /// Supports the following authentication types: `password`, `v3token`, `http_basic` and `noop`.
    ///
    /// Understands the following variables:
    /// * `OS_CLOUD` (equivalent to calling [from_config](#method.from_config) with the given cloud).
    /// * `OS_AUTH_TYPE` (defaults to `v3token` if `OS_TOKEN` is provided otherwise to `password`).
    /// * `OS_AUTH_URL` for `password` and `v3token`, `OS_ENDPOINT` for `http_basic` and `noop`.
    /// * `OS_USERNAME` and `OS_PASSWORD`.
    /// * `OS_PROJECT_NAME` or `OS_PROJECT_ID`.
    /// * `OS_USER_DOMAIN_NAME` or `OS_USER_DOMAIN_ID` (defaults to `Default`).
    /// * `OS_PROJECT_DOMAIN_NAME` or `OS_PROJECT_DOMAIN_ID`.
    /// * `OS_TOKEN` (for `v3token`).
    /// * `OS_REGION_NAME` and `OS_INTERFACE`.
    #[inline]
    pub fn from_env() -> Result<Session, Error> {
        loading::from_env()
    }

    /// Create an adapter for the specific service type.
    ///
    /// The new `Adapter` will share the same authentication and will initially use the same
    /// endpoint interface (although it can be changed later without affecting the `Session`).
    ///
    /// If you don't need the `Session` any more, using [into_adapter](#method.into_adapter) is a
    /// bit more efficient.
    ///
    /// ```rust,no_run
    /// let session = osauth::Session::from_env()
    ///     .expect("Failed to create an identity provider from the environment");
    /// let adapter = session.adapter(osauth::services::COMPUTE);
    /// ```
    #[inline]
    pub fn adapter<Srv>(&self, service: Srv) -> Adapter<Srv> {
        Adapter::from_session(self.clone(), service)
    }

    /// Create an adapter for the specific service type.
    ///
    /// The new `Adapter` will share the same authentication and will initially use the same
    /// endpoint interface (although it can be changed later without affecting the `Session`).
    ///
    /// This method is a bit more efficient than [adapter](#method.adapter) since it does not
    /// involve cloning internal structures.
    ///
    /// ```rust,no_run
    /// let session = osauth::Session::from_env()
    ///     .expect("Failed to create an identity provider from the environment");
    /// let adapter = session.into_adapter(osauth::services::COMPUTE);
    /// ```
    #[inline]
    pub fn into_adapter<Srv>(self, service: Srv) -> Adapter<Srv> {
        Adapter::from_session(self, service)
    }

    /// Get a reference to the authentication type in use.
    #[inline]
    pub fn auth_type(&self) -> &dyn AuthType {
        self.auth.as_ref()
    }

    /// Endpoint filters in use.
    #[inline]
    pub fn endpoint_filters(&self) -> &EndpointFilters {
        &self.endpoint_filters
    }

    /// Modify endpoint filters.
    ///
    /// This call clears the cached service information for this `Session`.
    /// It does not, however, affect clones of this `Session`.
    pub fn endpoint_filters_mut(&mut self) -> &mut EndpointFilters {
        self.reset_cache();
        &mut self.endpoint_filters
    }

    /// Endpoint overrides in use.
    #[inline]
    pub fn endpoint_overrides(&self) -> &HashMap<String, Url> {
        &self.endpoint_overrides
    }

    /// Modify endpoint overrides.
    ///
    /// This call clears the cached service information for this `Session`.
    /// It does not, however, affect clones of this `Session`.
    pub fn endpoint_overrides_mut(&mut self) -> &mut HashMap<String, Url> {
        self.reset_cache();
        &mut self.endpoint_overrides
    }

    /// Update the authentication and purges cached endpoint information.
    ///
    /// # Warning
    ///
    /// Authentication will also be updated for clones of this `Session`, since they share the same
    /// authentication object.
    #[inline]
    pub async fn refresh(&mut self) -> Result<(), Error> {
        self.reset_cache();
        self.auth.refresh().await
    }

    /// Reset the internal cache.
    #[inline]
    fn reset_cache(&mut self) {
        self.cached_info = Arc::new(RwLock::new(HashMap::new()));
    }

    /// Set a new authentication for this `Session`.
    ///
    /// This call clears the cached service information for this `Session`.
    /// It does not, however, affect clones of this `Session`.
    #[inline]
    pub fn set_auth_type<Auth: AuthType + 'static>(&mut self, auth_type: Auth) {
        self.reset_cache();
        self.auth = Arc::new(auth_type);
    }

    /// A convenience call to set an endpoint interface.
    ///
    /// This call clears the cached service information for this `Session`.
    /// It does not, however, affect clones of this `Session`.
    pub fn set_endpoint_interface(&mut self, endpoint_interface: InterfaceType) {
        self.reset_cache();
        self.endpoint_filters.set_interfaces(endpoint_interface);
    }

    /// A convenience call to set an endpoint override for one service.
    ///
    /// This call clears the cached service information for this `Session`.
    /// It does not, however, affect clones of this `Session`.
    pub fn set_endpoint_override<Svc: ServiceType>(&mut self, service: Svc, url: Url) {
        self.reset_cache();
        let _ = self
            .endpoint_overrides
            .insert(service.catalog_type().to_string(), url);
    }

    /// Convert this session into one using the given authentication.
    #[inline]
    pub fn with_auth_type<Auth: AuthType + 'static>(mut self, auth_method: Auth) -> Session {
        self.set_auth_type(auth_method);
        self
    }

    /// Convert this session into one using the given endpoint filters.
    #[inline]
    pub fn with_endpoint_filters(mut self, endpoint_filters: EndpointFilters) -> Session {
        *self.endpoint_filters_mut() = endpoint_filters;
        self
    }

    /// Convert this session into one using the given endpoint filters.
    #[inline]
    pub fn with_endpoint_interface(mut self, endpoint_interface: InterfaceType) -> Session {
        self.set_endpoint_interface(endpoint_interface);
        self
    }

    /// Convert this session into one using the given endpoint override for the given service.
    #[inline]
    pub fn with_endpoint_override<Srv: ServiceType>(mut self, service: Srv, url: Url) -> Session {
        self.set_endpoint_override(service, url);
        self
    }

    /// Convert this session into one using the given endpoint overrides.
    #[inline]
    pub fn with_endpoint_overrides(mut self, endpoint_overrides: HashMap<String, Url>) -> Session {
        *self.endpoint_overrides_mut() = endpoint_overrides;
        self
    }

    /// Get minimum/maximum API (micro)version information.
    ///
    /// Returns `None` if the range cannot be determined, which usually means
    /// that microversioning is not supported.
    ///
    /// ```rust,no_run
    /// # async fn example() -> Result<(), osauth::Error> {
    /// let session = osauth::Session::from_env()
    ///     .expect("Failed to create an identity provider from the environment");
    /// let maybe_versions = session
    ///     .get_api_versions(osauth::services::COMPUTE)
    ///     .await?;
    /// if let Some((min, max)) = maybe_versions {
    ///     println!("The compute service supports versions {} to {}", min, max);
    /// } else {
    ///     println!("The compute service does not support microversioning");
    /// }
    /// # Ok(()) }
    /// # #[tokio::main]
    /// # async fn main() { example().await.unwrap(); }
    /// ```
    pub async fn get_api_versions<Srv: ServiceType + Send>(
        &self,
        service: Srv,
    ) -> Result<Option<(ApiVersion, ApiVersion)>, Error> {
        self.extract_service_info(service, |info| {
            match (info.minimum_version, info.current_version) {
                (Some(min), Some(max)) => Some((min, max)),
                _ => None,
            }
        })
        .await
    }

    /// Construct and endpoint for the given service from the path.
    ///
    /// You won't need to use this call most of the time, since all request calls can fetch the
    /// endpoint automatically.
    pub async fn get_endpoint<Srv, I>(&self, service: Srv, path: I) -> Result<Url, Error>
    where
        Srv: ServiceType + Send,
        I: IntoIterator,
        I::Item: AsRef<str>,
        I::IntoIter: Send,
    {
        let path_iter = path.into_iter();
        self.extract_service_info(service, |info| {
            url::extend(info.root_url.clone(), path_iter)
        })
        .await
    }

    /// Get the currently used major version from the given service.
    ///
    /// Can return `None` if the service does not support API version discovery at all.
    pub async fn get_major_version<Srv>(&self, service: Srv) -> Result<Option<ApiVersion>, Error>
    where
        Srv: ServiceType + Send,
    {
        self.extract_service_info(service, |info| info.major_version)
            .await
    }

    /// Pick the highest API version supported by the service.
    ///
    /// Returns `None` if none of the requested versions are available.
    ///
    /// ```rust,no_run
    /// # async fn example() -> Result<(), osauth::Error> {
    /// let session = osauth::Session::from_env()
    ///     .expect("Failed to create an identity provider from the environment");
    /// let candidates = vec![osauth::ApiVersion(1, 2), osauth::ApiVersion(1, 42)];
    /// let maybe_version = session
    ///     .pick_api_version(osauth::services::COMPUTE, candidates)
    ///     .await?;
    /// if let Some(version) = maybe_version {
    ///     println!("Using version {}", version);
    /// } else {
    ///     println!("Using the base version");
    /// }
    /// let response = session
    ///     .get(osauth::services::COMPUTE, &["servers"], maybe_version)
    ///     .await?;
    /// # Ok(()) }
    /// # #[tokio::main]
    /// # async fn main() { example().await.unwrap(); }
    /// ```
    pub async fn pick_api_version<Srv, I>(
        &self,
        service: Srv,
        versions: I,
    ) -> Result<Option<ApiVersion>, Error>
    where
        Srv: ServiceType + Send,
        I: IntoIterator<Item = ApiVersion>,
        I::IntoIter: Send,
    {
        let vers = versions.into_iter();
        Ok(if vers.size_hint().1 == Some(0) {
            None
        } else {
            self.extract_service_info(service, |info| {
                vers.filter(|item| info.supports_api_version(*item)).max()
            })
            .await?
        })
    }

    /// Check if the service supports the API version.
    pub async fn supports_api_version<Srv>(
        &self,
        service: Srv,
        version: ApiVersion,
    ) -> Result<bool, Error>
    where
        Srv: ServiceType + Send,
    {
        self.pick_api_version(service, Some(version))
            .await
            .map(|x| x.is_some())
    }

    /// Make an HTTP request to the given service.
    ///
    /// The `service` argument is an object implementing the
    /// [ServiceType](services/trait.ServiceType.html) trait. Some known service types are available
    /// in the [services](services/index.html) module.
    ///
    /// The `path` argument is a URL path without the service endpoint (e.g. `/servers/1234`). For
    /// an empty path, [NO_PATH](request/constant.NO_PATH.html) can be used.
    ///
    /// If `api_version` is set, it is send with the request to enable a higher API version.
    /// Otherwise the base API version is used. You can use
    /// [pick_api_version](#method.pick_api_version) to choose an API version to use.
    ///
    /// The result is a `RequestBuilder` that can be customized further. Error checking and response
    /// parsing can be done using functions from the [request](request/index.html) module.
    ///
    /// ```rust,no_run
    /// # async fn example() -> Result<(), osauth::Error> {
    /// let session = osauth::Session::from_env()
    ///     .expect("Failed to create an identity provider from the environment");
    /// let response = osauth::request::send_checked(
    ///     session
    ///         .request(osauth::services::COMPUTE, reqwest::Method::HEAD, &["servers", "1234"], None)
    ///         .await?
    ///     )
    ///     .await?;
    /// println!("Response: {:?}", response);
    /// # Ok(()) }
    /// # #[tokio::main]
    /// # async fn main() { example().await.unwrap(); }
    /// ```
    ///
    /// This is the most generic call to make a request. You may prefer to use more specific `get`,
    /// `post`, `put` or `delete` calls instead.
    pub async fn request<Srv, I>(
        &self,
        service: Srv,
        method: Method,
        path: I,
        api_version: Option<ApiVersion>,
    ) -> Result<RequestBuilder, Error>
    where
        Srv: ServiceType + Send + Clone,
        I: IntoIterator,
        I::Item: AsRef<str>,
        I::IntoIter: Send,
    {
        let url = self.get_endpoint(service.clone(), path).await?;
        trace!(
            "Sending HTTP {} request to {} with API version {:?}",
            method,
            url,
            api_version
        );
        let mut builder = self.auth.request(method, url).await?;
        if let Some(version) = api_version {
            let mut headers = HeaderMap::new();
            service.set_api_version_headers(&mut headers, version)?;
            builder = builder.headers(headers)
        }
        Ok(builder)
    }

    /// Issue a GET request.
    ///
    /// See [request](#method.request) for an explanation of the parameters.
    #[inline]
    pub async fn get<Srv, I>(
        &self,
        service: Srv,
        path: I,
        api_version: Option<ApiVersion>,
    ) -> Result<Response, Error>
    where
        Srv: ServiceType + Send + Clone,
        I: IntoIterator,
        I::Item: AsRef<str>,
        I::IntoIter: Send,
    {
        request::send_checked(
            self.request(service, Method::GET, path, api_version)
                .await?,
        )
        .await
    }

    /// Fetch a JSON using the GET request.
    ///
    /// ```rust,no_run
    /// # async fn example() -> Result<(), osauth::Error> {
    /// use osproto::common::IdAndName;
    /// use serde::Deserialize;
    ///
    /// #[derive(Debug, Deserialize)]
    /// pub struct ServersRoot {
    ///     pub servers: Vec<IdAndName>,
    /// }
    ///
    /// let session = osauth::Session::from_env()
    ///     .expect("Failed to create an identity provider from the environment");
    ///
    /// let servers: ServersRoot = session
    ///     .get_json(osauth::services::COMPUTE, &["servers"], None)
    ///     .await?;
    /// for srv in servers.servers {
    ///     println!("ID = {}, Name = {}", srv.id, srv.name);
    /// }
    /// # Ok(()) }
    /// # #[tokio::main]
    /// # async fn main() { example().await.unwrap(); }
    /// ```
    ///
    /// See [request](#method.request) for an explanation of the parameters.
    #[inline]
    pub async fn get_json<Srv, I, T>(
        &self,
        service: Srv,
        path: I,
        api_version: Option<ApiVersion>,
    ) -> Result<T, Error>
    where
        Srv: ServiceType + Send + Clone,
        I: IntoIterator,
        I::Item: AsRef<str>,
        I::IntoIter: Send,
        T: DeserializeOwned + Send,
    {
        request::fetch_json(
            self.request(service, Method::GET, path, api_version)
                .await?,
        )
        .await
    }

    /// Fetch a paginated list of JSON objects using the GET request.
    ///
    /// ```rust,no_run
    /// # async fn example() -> Result<(), osauth::Error> {
    /// use futures::pin_mut;
    /// use futures::stream::TryStreamExt;
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
    /// // This implementatin defines the relationship between the root resource and its items.
    /// impl osauth::stream::Resource for Server {
    ///     type Id = String;
    ///     type Root = ServersRoot;
    ///     fn resource_id(&self) -> Self::Id {
    ///         self.id.clone()
    ///     }
    /// }
    ///
    /// // This is another required part of the pagination contract.
    /// impl From<ServersRoot> for Vec<Server> {
    ///     fn from(value: ServersRoot) -> Vec<Server> {
    ///         value.servers
    ///     }
    /// }
    ///
    /// let session = osauth::Session::from_env()
    ///     .expect("Failed to create an identity provider from the environment");
    ///
    /// let servers = session
    ///     .get_json_paginated::<_, _, Server>(
    ///         osauth::services::COMPUTE,
    ///         &["servers"],
    ///         None,
    ///         None,
    ///         None
    ///     )
    ///     .await?;
    ///
    /// pin_mut!(servers);
    /// while let Some(srv) = servers.try_next().await? {
    ///     println!("ID = {}, Name = {}", srv.id, srv.name);
    /// }
    /// # Ok(()) }
    /// # #[tokio::main]
    /// # async fn main() { example().await.unwrap(); }
    /// ```
    ///
    /// See [request](#method.request) for an explanation of the parameters.
    #[cfg(feature = "stream")]
    pub async fn get_json_paginated<Srv, I, T>(
        &self,
        service: Srv,
        path: I,
        api_version: Option<ApiVersion>,
        limit: Option<usize>,
        starting_with: Option<<T as Resource>::Id>,
    ) -> Result<impl Stream<Item = Result<T, Error>>, Error>
    where
        Srv: ServiceType + Send + Clone,
        I: IntoIterator,
        I::Item: AsRef<str>,
        I::IntoIter: Send,
        T: Resource + Unpin,
        <T as Resource>::Root: Into<Vec<T>> + Send,
    {
        let builder = self
            .request(service, Method::GET, path, api_version)
            .await?;
        Ok(paginated(builder, limit, starting_with))
    }

    /// Fetch a JSON using the GET request with a query.
    ///
    /// See `reqwest` crate documentation for how to define a query.
    /// See [request](#method.request) for an explanation of the parameters.
    #[inline]
    pub async fn get_json_query<Srv, I, Q, T>(
        &self,
        service: Srv,
        path: I,
        query: Q,
        api_version: Option<ApiVersion>,
    ) -> Result<T, Error>
    where
        Srv: ServiceType + Send + Clone,
        I: IntoIterator,
        I::Item: AsRef<str>,
        I::IntoIter: Send,
        Q: Serialize + Send,
        T: DeserializeOwned + Send,
    {
        request::fetch_json(
            self.request(service, Method::GET, path, api_version)
                .await?
                .query(&query),
        )
        .await
    }

    /// Fetch a paginated list of JSON objects using the GET request with a query.
    ///
    /// See `reqwest` crate documentation for how to define a query.
    /// See [request](#method.request) for an explanation of the parameters.
    #[cfg(feature = "stream")]
    pub async fn get_json_query_paginated<Srv, I, Q, T>(
        &self,
        service: Srv,
        path: I,
        query: Q,
        api_version: Option<ApiVersion>,
        limit: Option<usize>,
        starting_with: Option<<T as Resource>::Id>,
    ) -> Result<impl Stream<Item = Result<T, Error>>, Error>
    where
        Srv: ServiceType + Send + Clone,
        I: IntoIterator,
        I::Item: AsRef<str>,
        I::IntoIter: Send,
        Q: Serialize + Send,
        T: Resource + Unpin,
        <T as Resource>::Root: Into<Vec<T>> + Send,
    {
        let builder = self
            .request(service, Method::GET, path, api_version)
            .await?
            .query(&query);
        Ok(paginated(builder, limit, starting_with))
    }

    /// Issue a GET request with a query
    ///
    /// See `reqwest` crate documentation for how to define a query.
    /// See [request](#method.request) for an explanation of the parameters.
    #[inline]
    pub async fn get_query<Srv, I, Q>(
        &self,
        service: Srv,
        path: I,
        query: Q,
        api_version: Option<ApiVersion>,
    ) -> Result<Response, Error>
    where
        Srv: ServiceType + Send + Clone,
        I: IntoIterator,
        I::Item: AsRef<str>,
        I::IntoIter: Send,
        Q: Serialize + Send,
    {
        request::send_checked(
            self.request(service, Method::GET, path, api_version)
                .await?
                .query(&query),
        )
        .await
    }

    /// POST a JSON object.
    ///
    /// The `body` argument is anything that can be serialized into JSON.
    ///
    /// See [request](#method.request) for an explanation of the other parameters.
    #[inline]
    pub async fn post<Srv, I, T>(
        &self,
        service: Srv,
        path: I,
        body: T,
        api_version: Option<ApiVersion>,
    ) -> Result<Response, Error>
    where
        Srv: ServiceType + Send + Clone,
        I: IntoIterator,
        I::Item: AsRef<str>,
        I::IntoIter: Send,
        T: Serialize + Send,
    {
        request::send_checked(
            self.request(service, Method::POST, path, api_version)
                .await?
                .json(&body),
        )
        .await
    }

    /// POST a JSON object and receive a JSON back.
    ///
    /// The `body` argument is anything that can be serialized into JSON.
    ///
    /// See [request](#method.request) for an explanation of the other parameters.
    #[inline]
    pub async fn post_json<Srv, I, T, R>(
        &self,
        service: Srv,
        path: I,
        body: T,
        api_version: Option<ApiVersion>,
    ) -> Result<R, Error>
    where
        Srv: ServiceType + Send + Clone,
        I: IntoIterator,
        I::Item: AsRef<str>,
        I::IntoIter: Send,
        T: Serialize + Send,
        R: DeserializeOwned + Send,
    {
        request::fetch_json(
            self.request(service, Method::POST, path, api_version)
                .await?
                .json(&body),
        )
        .await
    }

    /// PUT a JSON object.
    ///
    /// The `body` argument is anything that can be serialized into JSON.
    ///
    /// See [request](#method.request) for an explanation of the other parameters.
    #[inline]
    pub async fn put<Srv, I, T>(
        &self,
        service: Srv,
        path: I,
        body: T,
        api_version: Option<ApiVersion>,
    ) -> Result<Response, Error>
    where
        Srv: ServiceType + Send + Clone,
        I: IntoIterator,
        I::Item: AsRef<str>,
        I::IntoIter: Send,
        T: Serialize + Send,
    {
        request::send_checked(
            self.request(service, Method::PUT, path, api_version)
                .await?
                .json(&body),
        )
        .await
    }

    /// Issue an empty PUT request.
    ///
    /// See [request](#method.request) for an explanation of the parameters.
    #[inline]
    pub async fn put_empty<Srv, I>(
        &self,
        service: Srv,
        path: I,
        api_version: Option<ApiVersion>,
    ) -> Result<Response, Error>
    where
        Srv: ServiceType + Send + Clone,
        I: IntoIterator,
        I::Item: AsRef<str>,
        I::IntoIter: Send,
    {
        request::send_checked(
            self.request(service, Method::PUT, path, api_version)
                .await?,
        )
        .await
    }

    /// PUT a JSON object and receive a JSON back.
    ///
    /// The `body` argument is anything that can be serialized into JSON.
    ///
    /// See [request](#method.request) for an explanation of the other parameters.
    #[inline]
    pub async fn put_json<Srv, I, T, R>(
        &self,
        service: Srv,
        path: I,
        body: T,
        api_version: Option<ApiVersion>,
    ) -> Result<R, Error>
    where
        Srv: ServiceType + Send + Clone,
        I: IntoIterator,
        I::Item: AsRef<str>,
        I::IntoIter: Send,
        T: Serialize + Send,
        R: DeserializeOwned + Send,
    {
        request::fetch_json(
            self.request(service, Method::PUT, path, api_version)
                .await?
                .json(&body),
        )
        .await
    }

    /// Issue a DELETE request.
    ///
    /// See [request](#method.request) for an explanation of the parameters.
    #[inline]
    pub async fn delete<Srv, I>(
        &self,
        service: Srv,
        path: I,
        api_version: Option<ApiVersion>,
    ) -> Result<Response, Error>
    where
        Srv: ServiceType + Send + Clone,
        I: IntoIterator,
        I::Item: AsRef<str>,
        I::IntoIter: Send,
    {
        request::send_checked(
            self.request(service, Method::DELETE, path, api_version)
                .await?,
        )
        .await
    }

    /// Ensure service info and return the cache.
    async fn extract_service_info<Srv, F, T>(&self, service: Srv, filter: F) -> Result<T, Error>
    where
        Srv: ServiceType + Send,
        F: FnOnce(&ServiceInfo) -> T + Send,
        T: Send,
    {
        let catalog_type = service.catalog_type();
        if let Some(info) = self.cached_info.read().await.get(catalog_type) {
            return Ok(filter(info));
        }

        debug!(
            "No cached information for service {}, fetching",
            catalog_type
        );

        let mut lock = self.cached_info.write().await;
        // Additonal check in case another thread has updated the token while we were waiting for
        // the write lock.
        Ok(if let Some(info) = lock.get(catalog_type) {
            filter(info)
        } else {
            let ep = match self.endpoint_overrides.get(catalog_type) {
                Some(found) => found.clone(),
                None => {
                    self.auth
                        .get_endpoint(catalog_type.to_string(), self.endpoint_filters.clone())
                        .await?
                }
            };
            let info = ServiceInfo::fetch(service, ep, self.auth.deref()).await?;
            let value = filter(&info);
            let _ = lock.insert(catalog_type, info);
            value
        })
    }

    #[cfg(test)]
    pub(crate) fn cache_fake_service(
        &mut self,
        service_type: &'static str,
        service_info: ServiceInfo,
    ) {
        let mut hm = HashMap::new();
        let _ = hm.insert(service_type, service_info);
        self.cached_info = Arc::new(RwLock::new(hm));
    }
}

#[cfg(test)]
pub(crate) mod test {
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
        let mut session = Session::new(auth);
        session.cache_fake_service("fake", service_info);
        session
    }

    pub const FAKE: GenericService = GenericService::new("fake", VersionSelector::Any);

    #[tokio::test]
    async fn test_get_endpoint() {
        let s = new_simple_session(URL);
        let ep = s.get_endpoint(FAKE, &[""]).await.unwrap();
        assert_eq!(&ep.to_string(), URL);
    }

    #[tokio::test]
    async fn test_get_endpoint_slice() {
        let s = new_simple_session(URL);
        let ep = s.get_endpoint(FAKE, &["v2", "servers"]).await.unwrap();
        assert_eq!(&ep.to_string(), URL_WITH_SUFFIX);
    }

    #[tokio::test]
    async fn test_get_endpoint_vec() {
        let s = new_simple_session(URL);
        let ep = s
            .get_endpoint(FAKE, vec!["v2".to_string(), "servers".to_string()])
            .await
            .unwrap();
        assert_eq!(&ep.to_string(), URL_WITH_SUFFIX);
    }

    #[tokio::test]
    async fn test_get_major_version_absent() {
        let s = new_simple_session(URL);
        let res = s.get_major_version(FAKE).await.unwrap();
        assert!(res.is_none());
    }

    pub const MAJOR_VERSION: ApiVersion = ApiVersion(2, 0);

    #[tokio::test]
    async fn test_get_major_version_present() {
        let service_info = ServiceInfo {
            root_url: Url::parse(URL).unwrap(),
            major_version: Some(MAJOR_VERSION),
            minimum_version: None,
            current_version: None,
        };
        let s = new_session(URL, service_info);
        let res = s.get_major_version(FAKE).await.unwrap();
        assert_eq!(res, Some(MAJOR_VERSION));
    }

    pub const MIN_VERSION: ApiVersion = ApiVersion(2, 1);
    pub const MAX_VERSION: ApiVersion = ApiVersion(2, 42);

    pub fn fake_service_info() -> ServiceInfo {
        ServiceInfo {
            root_url: Url::parse(URL).unwrap(),
            major_version: Some(MAJOR_VERSION),
            minimum_version: Some(MIN_VERSION),
            current_version: Some(MAX_VERSION),
        }
    }

    #[tokio::test]
    async fn test_pick_api_version_empty() {
        let service_info = fake_service_info();
        let s = new_session(URL, service_info);
        let res = s.pick_api_version(FAKE, None).await.unwrap();
        assert!(res.is_none());
    }

    #[tokio::test]
    async fn test_pick_api_version_empty_vec() {
        let service_info = fake_service_info();
        let s = new_session(URL, service_info);
        let res = s.pick_api_version(FAKE, Vec::new()).await.unwrap();
        assert!(res.is_none());
    }

    #[tokio::test]
    async fn test_pick_api_version() {
        let service_info = fake_service_info();
        let s = new_session(URL, service_info);
        let choice = vec![
            ApiVersion(2, 0),
            ApiVersion(2, 2),
            ApiVersion(2, 4),
            ApiVersion(2, 99),
        ];
        let res = s.pick_api_version(FAKE, choice).await.unwrap();
        assert_eq!(res, Some(ApiVersion(2, 4)));
    }

    #[tokio::test]
    async fn test_pick_api_version_option() {
        let service_info = fake_service_info();
        let s = new_session(URL, service_info);
        let res = s
            .pick_api_version(FAKE, Some(ApiVersion(2, 4)))
            .await
            .unwrap();
        assert_eq!(res, Some(ApiVersion(2, 4)));
    }

    #[tokio::test]
    async fn test_pick_api_version_impossible() {
        let service_info = fake_service_info();
        let s = new_session(URL, service_info);
        let choice = vec![ApiVersion(2, 0), ApiVersion(2, 99)];
        let res = s.pick_api_version(FAKE, choice).await.unwrap();
        assert!(res.is_none());
    }
}
