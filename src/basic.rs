// Copyright 2020 Dmitry Tantsur <dtantsur@protonmail.com>
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

//! HTTP basic authentication.

use async_trait::async_trait;
use reqwest::{Client, IntoUrl, RequestBuilder, Url};

use super::{AuthType, EndpointFilters, Error};

/// Authentication type that uses HTTP basic authentication.
///
/// This type always uses a pre-defined endpoint:
/// ```rust,no_run
/// let auth = osauth::BasicAuth::new("https://cloud.local/baremetal",
///                                   "username", "password")
///     .expect("Invalid endpoint URL");
/// let session = osauth::Session::new(auth);
/// ```
#[derive(Clone, Debug)]
pub struct BasicAuth {
    endpoint: Url,
    username: String,
    password: String,
}

impl BasicAuth {
    /// Create a new HTTP basic authentication method using a fixed endpoint.
    ///
    /// This endpoint will be returned in response to all `get_endpoint` calls
    /// of the [AuthType](trait.AuthType.html) trait.
    pub fn new<U, S1, S2>(endpoint: U, username: S1, password: S2) -> Result<BasicAuth, Error>
    where
        U: IntoUrl,
        S1: Into<String>,
        S2: Into<String>,
    {
        Ok(BasicAuth {
            endpoint: endpoint.into_url()?,
            username: username.into(),
            password: password.into(),
        })
    }
}

#[async_trait]
impl AuthType for BasicAuth {
    /// Authenticate a request.
    async fn authenticate(
        &self,
        _client: &Client,
        request: RequestBuilder,
    ) -> Result<RequestBuilder, Error> {
        Ok(request.basic_auth(&self.username, Some(&self.password)))
    }

    /// Get a predefined endpoint for all service types
    async fn get_endpoint(
        &self,
        _client: &Client,
        _service_type: String,
        _filters: EndpointFilters,
    ) -> Result<Url, Error> {
        Ok(self.endpoint.clone())
    }

    /// This call does nothing for `BasicAuth`.
    async fn refresh(&self, _client: &Client) -> Result<(), Error> {
        Ok(())
    }
}
