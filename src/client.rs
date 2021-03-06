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

//! Low-level authenticated client.

use std::collections::HashMap;
use std::convert::TryFrom;
use std::sync::Arc;
use std::time::Duration;

#[cfg(feature = "stream")]
use futures::Stream;
use http::header::{HeaderMap, HeaderName, HeaderValue};
use http::Error as HttpError;
use log::trace;
use reqwest::{Body, Client, Method, RequestBuilder as HttpRequestBuilder, Response, Url};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

#[cfg(feature = "stream")]
use super::stream::paginated;
#[cfg(feature = "stream")]
pub use super::stream::PaginatedResource;
use super::{AuthType, EndpointFilters, Error};

/// A properly typed constant for use with root paths.
///
/// The problem with just using `None` is that the exact type of `Option` is not known.
///
/// An example:
///
/// ```rust,no_run
/// # async fn example() -> Result<(), osauth::Error> {
/// let session = osauth::Session::from_env().await?;
/// let future = session
///     .get(osauth::services::OBJECT_STORAGE, osauth::client::NO_PATH, None)
///     .await?;
/// # Ok(()) }
/// # #[tokio::main]
/// # async fn main() { example().await.unwrap(); }
/// ```
pub const NO_PATH: Option<&'static str> = None;

/// Authenticated HTTP client.
///
/// Uses `Arc` internally and should be reused when possible by cloning it.
#[derive(Debug, Clone)]
pub struct AuthenticatedClient {
    client: Client,
    auth: Arc<dyn AuthType>,
}

impl AuthenticatedClient {
    /// Create a new authenticated client.
    pub async fn new<Auth: AuthType + 'static>(
        client: Client,
        auth_type: Auth,
    ) -> Result<AuthenticatedClient, Error> {
        auth_type.refresh(&client).await?;
        Ok(AuthenticatedClient::new_internal(
            client,
            Arc::new(auth_type),
        ))
    }

    #[inline]
    pub(crate) fn new_internal(client: Client, auth: Arc<dyn AuthType>) -> AuthenticatedClient {
        AuthenticatedClient { client, auth }
    }

    /// Get a reference to the authentication type in use.
    #[inline]
    pub fn auth_type(&self) -> &dyn AuthType {
        self.auth.as_ref()
    }

    /// Get a URL for the requested service.
    #[inline]
    pub async fn get_endpoint(
        &self,
        service_type: String,
        filters: EndpointFilters,
    ) -> Result<Url, Error> {
        self.auth
            .get_endpoint(&self.client, service_type, filters)
            .await
    }

    /// Get a reference to the inner (non-authenticated) client.
    #[inline]
    pub fn inner(&self) -> &Client {
        &self.client
    }

    /// Update the authentication.
    ///
    /// # Warning
    ///
    /// Authentication will also be updated for clones of this client, since they share the same
    /// authentication object.
    #[inline]
    pub async fn refresh(&mut self) -> Result<(), Error> {
        self.auth.refresh(&self.client).await
    }

    /// Set a new authentication for this client.
    #[inline]
    pub fn set_auth_type<Auth: AuthType + 'static>(&mut self, auth_type: Auth) {
        self.auth = Arc::new(auth_type);
    }

    /// Set a new internal client implementation.
    #[inline]
    pub fn set_inner(&mut self, client: Client) {
        self.client = client;
    }

    /// Start an authenticated request.
    #[inline]
    pub async fn request(&self, method: Method, url: Url) -> Result<RequestBuilder, Error> {
        self.auth
            .authenticate(
                &self.client,
                RequestBuilder::new(self.client.request(method, url)),
            )
            .await
    }
}

impl From<AuthenticatedClient> for Client {
    fn from(value: AuthenticatedClient) -> Client {
        value.client
    }
}

/// A request builder with error handling.
#[derive(Debug)]
#[must_use = "preparing a request is not enough to run it"]
pub struct RequestBuilder {
    inner: HttpRequestBuilder,
}

impl From<HttpRequestBuilder> for RequestBuilder {
    fn from(value: HttpRequestBuilder) -> RequestBuilder {
        RequestBuilder { inner: value }
    }
}

impl From<RequestBuilder> for HttpRequestBuilder {
    fn from(value: RequestBuilder) -> HttpRequestBuilder {
        value.inner
    }
}

#[derive(Debug, Deserialize)]
struct Message {
    message: String,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum ErrorResponse {
    Map(HashMap<String, Message>),
    Message(Message),
}

async fn extract_message(resp: Response) -> Result<String, Error> {
    let text = resp.text().await?;
    Ok(serde_json::from_str::<ErrorResponse>(&text)
        .ok()
        .and_then(|body| match body {
            ErrorResponse::Map(map) => map.into_iter().next().map(|(_k, v)| v.message),
            ErrorResponse::Message(msg) => Some(msg.message),
        })
        .unwrap_or(text))
}

/// Check for OpenStack errors in the response.
pub async fn check(response: Response) -> Result<Response, Error> {
    let status = response.status();
    if status.is_client_error() || status.is_server_error() {
        let message = extract_message(response).await?;
        trace!("HTTP request returned {}; error: {:?}", status, message);
        Err(Error::new(status.into(), message).with_status(status))
    } else {
        trace!(
            "HTTP request to {} returned {}",
            response.url(),
            response.status()
        );
        Ok(response)
    }
}

impl RequestBuilder {
    #[inline]
    fn new(inner: HttpRequestBuilder) -> RequestBuilder {
        RequestBuilder { inner }
    }

    /// Add a body to the request.
    pub fn body<T: Into<Body>>(self, body: T) -> RequestBuilder {
        RequestBuilder {
            inner: self.inner.body(body),
        }
    }

    /// Add a header to the request.
    pub fn header<K, V>(self, key: K, value: V) -> RequestBuilder
    where
        HeaderName: TryFrom<K>,
        <HeaderName as TryFrom<K>>::Error: Into<HttpError>,
        HeaderValue: TryFrom<V>,
        <HeaderValue as TryFrom<V>>::Error: Into<HttpError>,
    {
        RequestBuilder {
            inner: self.inner.header(key, value),
        }
    }

    /// Add headers to a request.
    pub fn headers(self, headers: HeaderMap) -> RequestBuilder {
        RequestBuilder {
            inner: self.inner.headers(headers),
        }
    }

    /// Add a JSON body to the request.
    pub fn json<T: Serialize + ?Sized>(self, json: &T) -> RequestBuilder {
        RequestBuilder {
            inner: self.inner.json(json),
        }
    }

    /// Send a query with the request.
    pub fn query<T: Serialize + ?Sized>(self, query: &T) -> RequestBuilder {
        RequestBuilder {
            inner: self.inner.query(query),
        }
    }

    /// Override the timeout for the request.
    pub fn timeout(self, timeout: Duration) -> RequestBuilder {
        RequestBuilder {
            inner: self.inner.timeout(timeout),
        }
    }

    /// Send the request and receive JSON in response.
    pub async fn fetch_json<T>(self) -> Result<T, Error>
    where
        T: DeserializeOwned + Send,
    {
        self.send().await?.json::<T>().await.map_err(Error::from)
    }

    /// Send the request and receive JSON in response with pagination.
    ///
    /// Note that the actual requests will happen only on iteration over the results.
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
    /// impl osauth::client::PaginatedResource for Server {
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
    /// let session = osauth::Session::from_env().await?;
    ///
    /// let servers = session
    ///     .get(
    ///         osauth::services::COMPUTE,
    ///         &["servers"],
    ///         None,
    ///     )
    ///     .await?
    ///     .fetch_json_paginated::<Server>(None, None)
    ///     .await;
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
    /// # Panics
    ///
    /// Will panic during iteration if the request builder has a streaming body.
    #[cfg(feature = "stream")]
    pub async fn fetch_json_paginated<T>(
        self,
        limit: Option<usize>,
        starting_with: Option<<T as PaginatedResource>::Id>,
    ) -> impl Stream<Item = Result<T, Error>>
    where
        T: PaginatedResource + Unpin,
        <T as PaginatedResource>::Root: Into<Vec<T>> + Send,
    {
        paginated(self, limit, starting_with)
    }

    /// Send the request and check for errors.
    pub async fn send(self) -> Result<Response, Error> {
        check(self.send_unchecked().await?).await
    }

    /// Send the request without checking for HTTP and OpenStack errors.
    pub async fn send_unchecked(self) -> Result<Response, Error> {
        self.inner.send().await.map_err(Error::from)
    }

    /// Attempt to clone this request builder.
    pub fn try_clone(&self) -> Option<RequestBuilder> {
        self.inner.try_clone().map(RequestBuilder::new)
    }

    pub(crate) fn basic_auth(self, username: &str, password: &str) -> RequestBuilder {
        RequestBuilder {
            inner: self.inner.basic_auth(username, Some(password)),
        }
    }
}
