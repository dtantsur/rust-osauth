// Copyright 2019-2020 Dmitry Tantsur <dtantsur@protonmail.com>
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

//! Token authentication.

use async_trait::async_trait;
use reqwest::{Client, IntoUrl, Method, RequestBuilder, Url};

use super::internal::Internal;
use super::protocol;
use super::{IdOrName, Identity, Scope};
use crate::{AuthType, EndpointFilters, Error};

/// Token authentication using Identity API V3.
///
/// For any Identity authentication you need to know `auth_url`, which is an authentication endpoint
/// of the Identity service. For the Token authentication you also need:
/// 1. Existing authentication token.
/// 2. Name of the project to use.
/// 3. Domain of the project.
///
/// Start with creating a `Token` object using [new](#method.new), then add a project scope
/// with [with_project_scope](#method.with_project_scope):
///
/// ```rust,no_run
/// use osauth::common::IdOrName;
/// let auth = osauth::identity::Token::new(
///     "https://cloud.local/identity",
///     "<a token>",
/// )
/// .expect("Invalid auth_url")
/// .with_project_scope(IdOrName::from_name("project1"), IdOrName::from_id("default"));
///
/// let session = osauth::Session::new(auth);
/// ```
///
/// The authentication token is cached while it's still valid or until
/// [refresh](../trait.AuthType.html#tymethod.refresh) is called.
/// Clones of a `Token` also start with an empty cache.
#[derive(Debug, Clone)]
pub struct Token {
    inner: Internal,
}

impl Identity for Token {
    fn auth_url(&self) -> &Url {
        self.inner.auth_url()
    }
}

impl Token {
    /// Create a token authentication.
    pub fn new<U, S>(auth_url: U, token: S) -> Result<Self, Error>
    where
        U: IntoUrl,
        S: Into<String>,
    {
        Self::new_with_client(auth_url, Client::new(), token)
    }

    /// Create a token authentication with the provided HTTP client.
    pub fn new_with_client<U, S>(auth_url: U, client: Client, token: S) -> Result<Self, Error>
    where
        U: IntoUrl,
        S: Into<String>,
    {
        let auth_url = auth_url.into_url()?;

        let body = protocol::AuthRoot {
            auth: protocol::Auth {
                identity: protocol::Identity::Token(token.into()),
                scope: None,
            },
        };
        Ok(Self {
            inner: Internal::new(client, auth_url, body)?,
        })
    }

    /// Scope authentication to the given project.
    ///
    /// A convenience wrapper around `set_scope`.
    #[inline]
    pub fn set_project_scope(&mut self, project: IdOrName, domain: impl Into<Option<IdOrName>>) {
        self.set_scope(Scope::Project {
            project,
            domain: domain.into(),
        });
    }

    /// Add a scope to the authentication.
    ///
    /// This is required in the most cases.
    #[inline]
    pub fn set_scope(&mut self, scope: Scope) {
        self.inner.set_scope(scope);
    }

    /// Scope authentication to the given project.
    ///
    /// A convenience wrapper around `with_scope`.
    #[inline]
    pub fn with_project_scope(
        mut self,
        project: IdOrName,
        domain: impl Into<Option<IdOrName>>,
    ) -> Token {
        self.set_project_scope(project, domain);
        self
    }

    /// Add a scope to the authentication.
    #[inline]
    pub fn with_scope(mut self, scope: Scope) -> Self {
        self.set_scope(scope);
        self
    }

    /// Project name or ID (if project scoped).
    #[inline]
    pub fn project(&self) -> Option<&IdOrName> {
        self.inner.project()
    }
}

#[async_trait]
impl AuthType for Token {
    /// Create an authenticated request.
    async fn request(&self, method: Method, url: Url) -> Result<RequestBuilder, Error> {
        self.inner.request(method, url).await
    }

    /// Get a URL for the requested service.
    async fn get_endpoint(
        &self,
        service_type: String,
        filters: EndpointFilters,
    ) -> Result<Url, Error> {
        self.inner.get_endpoint(service_type, filters).await
    }

    /// Refresh the cached token and service catalog.
    async fn refresh(&self) -> Result<(), Error> {
        self.inner.refresh(true).await
    }
}

#[cfg(test)]
pub mod test {
    #![allow(unused_results)]

    use super::Token;
    use crate::identity::{IdOrName, Identity};

    #[test]
    fn test_identity_new() {
        let id = Token::new("http://127.0.0.1:8080/", "abcdef").unwrap();
        let e = id.auth_url();
        assert_eq!(e.scheme(), "http");
        assert_eq!(e.host_str().unwrap(), "127.0.0.1");
        assert_eq!(e.port().unwrap(), 8080u16);
        assert_eq!(e.path(), "/");
    }

    #[test]
    fn test_identity_new_invalid() {
        Token::new("http://127.0.0.1 8080/", "abcdef")
            .err()
            .unwrap();
    }

    #[test]
    fn test_identity_create() {
        let id = Token::new("http://127.0.0.1:8080/identity", "abcdef")
            .unwrap()
            .with_project_scope(
                IdOrName::Name("cool project".to_string()),
                IdOrName::Name("example.com".to_string()),
            );
        assert_eq!(id.auth_url().to_string(), "http://127.0.0.1:8080/identity");
        assert_eq!(
            id.project(),
            Some(&IdOrName::Name("cool project".to_string()))
        );
        assert_eq!(
            id.inner.token_endpoint(),
            "http://127.0.0.1:8080/identity/v3/auth/tokens"
        );
    }

    #[test]
    fn test_token_endpoint_with_trailing_slash() {
        let id = Token::new("http://127.0.0.1:8080/identity/", "abcdef")
            .unwrap()
            .with_project_scope(
                IdOrName::Name("cool project".to_string()),
                IdOrName::Name("example.com".to_string()),
            );
        assert_eq!(id.auth_url().to_string(), "http://127.0.0.1:8080/identity");
        assert_eq!(
            id.project(),
            Some(&IdOrName::Name("cool project".to_string()))
        );
        assert_eq!(
            id.inner.token_endpoint(),
            "http://127.0.0.1:8080/identity/v3/auth/tokens"
        );
    }

    #[test]
    fn test_token_endpoint_with_v3() {
        let id = Token::new("http://127.0.0.1:8080/identity/v3", "abcdef")
            .unwrap()
            .with_project_scope(
                IdOrName::Name("cool project".to_string()),
                IdOrName::Name("example.com".to_string()),
            );
        assert_eq!(
            id.auth_url().to_string(),
            "http://127.0.0.1:8080/identity/v3"
        );
        assert_eq!(
            id.project(),
            Some(&IdOrName::Name("cool project".to_string()))
        );
        assert_eq!(
            id.inner.token_endpoint(),
            "http://127.0.0.1:8080/identity/v3/auth/tokens"
        );
    }

    #[test]
    fn test_token_endpoint_with_trailing_slash_v3() {
        let id = Token::new("http://127.0.0.1:8080/identity/v3/", "abcdef")
            .unwrap()
            .with_project_scope(
                IdOrName::Name("cool project".to_string()),
                IdOrName::Name("example.com".to_string()),
            );
        assert_eq!(
            id.auth_url().to_string(),
            "http://127.0.0.1:8080/identity/v3"
        );
        assert_eq!(
            id.project(),
            Some(&IdOrName::Name("cool project".to_string()))
        );
        assert_eq!(
            id.inner.token_endpoint(),
            "http://127.0.0.1:8080/identity/v3/auth/tokens"
        );
    }
}
