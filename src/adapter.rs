// Copyright 2019 Dmitry Tantsur <dtantsur@protonmail.com>
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

use http::{header::HeaderName, HeaderValue};
use reqwest::{Method, Url};
use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::services::VersionedService;

use super::client::RequestBuilder;
use super::services::ServiceType;
use super::{ApiVersion, AuthType, EndpointFilters, Error, InterfaceType, Session};

/// Adapter for a specific service.
///
/// An `Adapter` is very similar to a [Session](struct.Session.html), but is tied to a specific
/// service, and thus does not require passing a `service` argument to all calls.
#[derive(Debug, Clone)]
pub struct Adapter<Srv> {
    inner: Session,
    service: Srv,
    default_api_version: Option<ApiVersion>,
    api_version_header: Option<(HeaderName, HeaderValue)>,
}

impl<Srv> From<Adapter<Srv>> for Session {
    fn from(value: Adapter<Srv>) -> Session {
        value.inner
    }
}

impl<Srv> Adapter<Srv> {
    /// Create a new adapter with a given authentication plugin.
    pub async fn new<Auth: AuthType + 'static>(
        auth_type: Auth,
        service: Srv,
    ) -> Result<Adapter<Srv>, Error> {
        Ok(Adapter::from_session(
            Session::new(auth_type).await?,
            service,
        ))
    }

    /// Create a new adapter from a `clouds.yaml` configuration file.
    ///
    /// See [Session::from_config](struct.Session.html#method.from_config) for details.
    #[inline]
    pub async fn from_config<S: AsRef<str>>(
        cloud_name: S,
        service: Srv,
    ) -> Result<Adapter<Srv>, Error> {
        Ok(Session::from_config(cloud_name)
            .await?
            .into_adapter(service))
    }

    /// Create a new adapter with information from environment variables.
    ///
    /// See [Session::from_env](struct.Session.html#method.from_env) for details.
    #[inline]
    pub async fn from_env(service: Srv) -> Result<Adapter<Srv>, Error> {
        Ok(Session::from_env().await?.into_adapter(service))
    }

    /// Create a new adapter from a `Session`.
    #[inline]
    pub fn from_session(session: Session, service: Srv) -> Adapter<Srv> {
        Adapter {
            inner: session,
            service,
            default_api_version: None,
            api_version_header: None,
        }
    }

    /// Get a reference to the authentication type in use.
    #[inline]
    pub fn auth_type(&self) -> &dyn AuthType {
        self.inner.auth_type()
    }

    /// Endpoint filters in use.
    #[inline]
    pub fn endpoint_filters(&self) -> &EndpointFilters {
        self.inner.endpoint_filters()
    }

    /// Modify endpoint filters.
    ///
    /// This call clears the cached service information for this `Adapter`.
    /// It does not, however, affect clones of this `Adapter`.
    #[inline]
    pub fn endpoint_filters_mut(&mut self) -> &mut EndpointFilters {
        self.inner.endpoint_filters_mut()
    }

    /// Update the authentication and purges cached endpoint information.
    ///
    /// # Warning
    ///
    /// Authentication will also be updated for clones of this `Adapter` and its parent `Session`,
    /// since they share the same authentication object.
    #[inline]
    pub async fn refresh(&mut self) -> Result<(), Error> {
        self.inner.refresh().await
    }

    /// Session used for this adapter.
    #[inline]
    pub fn session(&self) -> &Session {
        &self.inner
    }

    /// Set a new authentication for this `Adapter`.
    ///
    /// This call clears the cached service information for this `Adapter`.
    /// It does not, however, affect clones of this `Adapter`.
    #[inline]
    pub fn set_auth_type<Auth: AuthType + 'static>(&mut self, auth_type: Auth) {
        self.inner.set_auth_type(auth_type)
    }

    /// A convenience call to set an endpoint interface.
    ///
    /// This call clears the cached service information for this `Adapter`.
    /// It does not, however, affect clones of this `Adapter`.
    #[inline]
    pub fn set_endpoint_interface(&mut self, endpoint_interface: InterfaceType) {
        self.inner.set_endpoint_interface(endpoint_interface);
    }

    /// Convert this adapter into one using the given authentication.
    #[inline]
    pub fn with_auth_type<Auth: AuthType + 'static>(mut self, auth_method: Auth) -> Adapter<Srv> {
        self.set_auth_type(auth_method);
        self
    }

    /// Convert this adapter into one using the given endpoint filters.
    #[inline]
    pub fn with_endpoint_filters(mut self, endpoint_filters: EndpointFilters) -> Adapter<Srv> {
        *self.endpoint_filters_mut() = endpoint_filters;
        self
    }

    /// Convert this adapter into one using the given endpoint filters.
    #[inline]
    pub fn with_endpoint_interface(mut self, endpoint_interface: InterfaceType) -> Adapter<Srv> {
        self.set_endpoint_interface(endpoint_interface);
        self
    }
}

impl<Srv> Adapter<Srv>
where
    Srv: VersionedService,
{
    /// Default API version used when no version is specified.
    #[inline]
    pub fn default_api_version(&self) -> Option<ApiVersion> {
        self.default_api_version
    }

    /// Set the default API version.
    ///
    /// This version will be used when no version is specified. No checks are done against this
    /// version inside of this call. If it is not valid, the subsequent `request` calls will fail.
    #[inline]
    pub fn set_default_api_version(&mut self, api_version: Option<ApiVersion>) {
        self.default_api_version = api_version;
        self.api_version_header =
            api_version.map(|version| self.service.get_version_header(version));
    }

    /// Convert this adapter into one using the given default API version.
    #[inline]
    pub fn with_default_api_version(mut self, api_version: Option<ApiVersion>) -> Adapter<Srv> {
        self.set_default_api_version(api_version);
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
    /// # async fn example() -> Result<(), osauth::Error> {
    /// let adapter = osauth::Adapter::from_env(osauth::services::COMPUTE)
    ///     .await
    ///     .expect("Failed to create an identity provider from the environment");
    /// let maybe_versions = adapter
    ///     .get_api_versions()
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
    #[inline]
    pub async fn get_api_versions(&self) -> Result<Option<(ApiVersion, ApiVersion)>, Error> {
        self.inner.get_api_versions(self.service.clone()).await
    }

    /// Construct an endpoint from the path;
    ///
    /// You won't need to use this call most of the time, since all request calls can fetch the
    /// endpoint automatically.
    pub async fn get_endpoint<I>(&self, path: I) -> Result<Url, Error>
    where
        I: IntoIterator,
        I::Item: AsRef<str>,
        I::IntoIter: Send,
    {
        self.inner.get_endpoint(self.service.clone(), path).await
    }

    /// Get the currently used major version from the given service.
    ///
    /// Can return `None` if the service does not support API version discovery at all.
    #[inline]
    pub async fn get_major_version(&self) -> Result<Option<ApiVersion>, Error> {
        self.inner.get_major_version(self.service.clone()).await
    }

    /// Pick the highest API version supported by the service.
    ///
    /// Returns `None` if none of the requested versions are available.
    ///
    /// ```rust,no_run
    /// # async fn example() -> Result<(), osauth::Error> {
    /// let adapter = osauth::Adapter::from_env(osauth::services::COMPUTE)
    ///     .await
    ///     .expect("Failed to create an identity provider from the environment");
    /// let candidates = vec![osauth::ApiVersion(1, 2), osauth::ApiVersion(1, 42)];
    /// let maybe_version = adapter
    ///     .pick_api_version(candidates)
    ///     .await?;
    ///
    /// let request = adapter.get(&["servers"]).await?;
    /// let response = if let Some(version) = maybe_version {
    ///     println!("Using version {}", version);
    ///     request.api_version(version)
    /// } else {
    ///     println!("Using the base version");
    ///     request
    /// }.send().await?;
    /// # Ok(()) }
    /// # #[tokio::main]
    /// # async fn main() { example().await.unwrap(); }
    /// ```
    pub async fn pick_api_version<I>(&self, versions: I) -> Result<Option<ApiVersion>, Error>
    where
        I: IntoIterator<Item = ApiVersion>,
        I::IntoIter: Send,
    {
        self.inner
            .pick_api_version(self.service.clone(), versions)
            .await
    }

    /// Check if the service supports the API version.
    #[inline]
    pub async fn supports_api_version(&self, version: ApiVersion) -> Result<bool, Error> {
        self.pick_api_version(Some(version))
            .await
            .map(|x| x.is_some())
    }

    /// Make an HTTP request.
    ///
    /// The `path` argument is a URL path without the service endpoint (e.g. `/servers/1234`).
    ///
    /// The result is a `RequestBuilder` that can be customized further. Error checking and response
    /// parsing can be done using functions from the [request](request/index.html) module.
    ///
    /// ```rust,no_run
    /// # async fn example() -> Result<(), osauth::Error> {
    /// let adapter = osauth::Adapter::from_env(osauth::services::COMPUTE)
    ///     .await
    ///     .expect("Failed to create an identity provider from the environment");
    /// let response = adapter
    ///     .request(reqwest::Method::HEAD, &["servers", "1234"])
    ///     .await?
    ///     .send()
    ///     .await?;
    /// println!("Response: {:?}", response);
    /// # Ok(()) }
    /// # #[tokio::main]
    /// # async fn main() { example().await.unwrap(); }
    /// ```
    ///
    /// This is the most generic call to make a request. You may prefer to use more specific `get`,
    /// `post`, `put` or `delete` calls instead.
    pub async fn request<I>(&self, method: Method, path: I) -> Result<RequestBuilder<Srv>, Error>
    where
        I: IntoIterator,
        I::Item: AsRef<str>,
        I::IntoIter: Send,
    {
        let rb = self
            .inner
            .request(self.service.clone(), method, path)
            .await?;

        Ok(
            if let Some((name, value)) = self.api_version_header.clone() {
                rb.header(name, value)
            } else {
                rb
            },
        )
    }

    /// Start a GET request.
    ///
    /// See [request](#method.request) for an explanation of the parameters.
    #[inline]
    pub async fn get<I>(&self, path: I) -> Result<RequestBuilder<Srv>, Error>
    where
        I: IntoIterator,
        I::Item: AsRef<str>,
        I::IntoIter: Send,
    {
        self.request(Method::GET, path).await
    }

    /// Fetch a JSON using the GET request.
    ///
    /// ```rust,no_run
    /// # async fn example() -> Result<(), osauth::Error> {
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
    /// let adapter = osauth::Adapter::from_env(osauth::services::COMPUTE)
    ///     .await
    ///     .expect("Failed to create an identity provider from the environment");
    /// let servers: ServersRoot = adapter
    ///     .get_json(&["servers"])
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
    pub async fn get_json<I, T>(&self, path: I) -> Result<T, Error>
    where
        I: IntoIterator,
        I::Item: AsRef<str>,
        I::IntoIter: Send,
        T: DeserializeOwned + Send,
    {
        self.request(Method::GET, path)
            .await?
            .fetch_json::<T>()
            .await
    }

    /// Start a POST request.
    ///
    /// See [request](#method.request) for an explanation of the parameters.
    #[inline]
    pub async fn post<I>(&self, path: I) -> Result<RequestBuilder<Srv>, Error>
    where
        I: IntoIterator,
        I::Item: AsRef<str>,
        I::IntoIter: Send,
    {
        self.request(Method::POST, path).await
    }

    /// POST a JSON object.
    ///
    /// The `body` argument is anything that can be serialized into JSON.
    ///
    /// See [request](#method.request) for an explanation of the other parameters.
    #[inline]
    pub async fn post_json<I, T>(&self, path: I, body: T) -> Result<RequestBuilder<Srv>, Error>
    where
        I: IntoIterator,
        I::Item: AsRef<str>,
        I::IntoIter: Send,
        T: Serialize + Send,
    {
        Ok(self.post(path).await?.json(&body))
    }

    /// Start a PUT request.
    ///
    /// See [request](#method.request) for an explanation of the parameters.
    #[inline]
    pub async fn put<I>(&self, path: I) -> Result<RequestBuilder<Srv>, Error>
    where
        I: IntoIterator,
        I::Item: AsRef<str>,
        I::IntoIter: Send,
    {
        self.request(Method::PUT, path).await
    }

    /// Issue an empty PUT request.
    ///
    /// See [request](#method.request) for an explanation of the parameters.
    #[inline]
    pub async fn put_empty<I>(&self, path: I) -> Result<(), Error>
    where
        I: IntoIterator,
        I::Item: AsRef<str>,
        I::IntoIter: Send,
    {
        self.request(Method::PUT, path)
            .await?
            .send()
            .await
            .map(|_| ())
    }

    /// PUT a JSON object.
    ///
    /// The `body` argument is anything that can be serialized into JSON.
    ///
    /// See [request](#method.request) for an explanation of the other parameters.
    #[inline]
    pub async fn put_json<I, T>(&self, path: I, body: T) -> Result<RequestBuilder<Srv>, Error>
    where
        I: IntoIterator,
        I::Item: AsRef<str>,
        I::IntoIter: Send,
        T: Serialize + Send,
    {
        Ok(self.put(path).await?.json(&body))
    }

    /// Start a DELETE request.
    ///
    /// See [request](#method.request) for an explanation of the parameters.
    #[inline]
    pub async fn delete<I>(&self, path: I) -> Result<RequestBuilder<Srv>, Error>
    where
        I: IntoIterator,
        I::Item: AsRef<str>,
        I::IntoIter: Send,
    {
        self.request(Method::DELETE, path).await
    }
}
