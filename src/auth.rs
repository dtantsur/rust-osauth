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

//! Base code for authentication.

use std::fmt::Debug;

use async_trait::async_trait;
use reqwest::{Client, IntoUrl, Method, RequestBuilder, Url};

use super::{EndpointFilters, Error, ErrorKind};

/// Trait for an authentication type.
///
/// An OpenStack authentication type is expected to be able to:
///
/// 1. get an authentication token to use when accessing services,
/// 2. get an endpoint URL for the given service type.
///
/// An authentication type should cache the token as long as it's valid.
#[async_trait]
pub trait AuthType: Debug + Sync + Send {
    /// Get a URL for the requested service.
    async fn get_endpoint(
        &self,
        service_type: String,
        filters: EndpointFilters,
    ) -> Result<Url, Error>;

    /// Create an authenticated request.
    async fn request(&self, method: Method, url: Url) -> Result<RequestBuilder, Error>;

    /// Refresh the authentication (renew the token, etc).
    async fn refresh(&self) -> Result<(), Error>;
}

/// Authentication type that provides no authentication.
///
/// This type always uses a pre-defined endpoint and sends no authenticaiton information:
/// ```rust,no_run
/// let auth = osauth::NoAuth::new("https://cloud.local/baremetal")
///     .expect("Invalid auth URL");
/// let session = osauth::Session::new(auth);
/// ```
#[derive(Clone, Debug)]
pub struct NoAuth {
    client: Client,
    endpoint: Option<Url>,
}

impl NoAuth {
    /// Create a new fake authentication method using a fixed endpoint.
    ///
    /// This endpoint will be returned in response to all `get_endpoint` calls
    /// of the [AuthType](trait.AuthType.html) trait.
    #[inline]
    pub fn new<U>(endpoint: U) -> Result<NoAuth, Error>
    where
        U: IntoUrl,
    {
        Self::new_with_client(endpoint, Client::new())
    }

    /// Create a new fake authentication method using a fixed endpoint and an HTTP client.
    #[inline]
    pub fn new_with_client<U>(endpoint: U, client: Client) -> Result<NoAuth, Error>
    where
        U: IntoUrl,
    {
        Ok(NoAuth {
            client,
            endpoint: Some(endpoint.into_url()?),
        })
    }

    /// Create a new fake authentication method without an endpoint.
    ///
    /// All calls to `get_endpoint` will fail. This option is only useful with endpoint overrides.
    #[inline]
    pub fn new_without_endpoint(client: Client) -> NoAuth {
        NoAuth {
            client,
            endpoint: None,
        }
    }
}

#[async_trait]
impl AuthType for NoAuth {
    /// Create a request.
    async fn request(&self, method: Method, url: Url) -> Result<RequestBuilder, Error> {
        Ok(self.client.request(method, url))
    }

    /// Get a predefined endpoint for all service types
    async fn get_endpoint(
        &self,
        service_type: String,
        _filters: EndpointFilters,
    ) -> Result<Url, Error> {
        self.endpoint.clone().ok_or_else(|| {
            Error::new(
                ErrorKind::EndpointNotFound,
                format!(
                    "None authentication without an endpoint, use an override for {}",
                    service_type
                ),
            )
        })
    }

    /// This call does nothing for `NoAuth`.
    async fn refresh(&self) -> Result<(), Error> {
        Ok(())
    }
}

#[cfg(test)]
pub mod test {
    use super::{AuthType, NoAuth};

    #[test]
    fn test_noauth_new() {
        let a = NoAuth::new("http://127.0.0.1:8080/v1").unwrap();
        let e = a.endpoint.unwrap();
        assert_eq!(e.scheme(), "http");
        assert_eq!(e.host_str().unwrap(), "127.0.0.1");
        assert_eq!(e.port().unwrap(), 8080u16);
        assert_eq!(e.path(), "/v1");
    }

    #[test]
    fn test_noauth_new_fail() {
        let _ = NoAuth::new("foo bar").err().unwrap();
    }

    #[tokio::test]
    async fn test_noauth_get_endpoint() {
        let a = NoAuth::new("http://127.0.0.1:8080/v1").unwrap();
        let e = a
            .get_endpoint(String::from("foobar"), Default::default())
            .await
            .unwrap();
        assert_eq!(e.scheme(), "http");
        assert_eq!(e.host_str().unwrap(), "127.0.0.1");
        assert_eq!(e.port().unwrap(), 8080u16);
        assert_eq!(e.path(), "/v1");
    }
}
