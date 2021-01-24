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

use std::sync::Arc;

use reqwest::{Client, Method, RequestBuilder, Url};

use super::{AuthType, EndpointFilters, Error};

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
    pub fn new<Auth: AuthType + 'static>(client: Client, auth_type: Auth) -> AuthenticatedClient {
        AuthenticatedClient {
            client,
            auth: Arc::new(auth_type),
        }
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
            .authenticate(&self.client, self.client.request(method, url))
            .await
    }
}

impl From<AuthenticatedClient> for Client {
    fn from(value: AuthenticatedClient) -> Client {
        value.client
    }
}
