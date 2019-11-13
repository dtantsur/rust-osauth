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

//! Authentication using Identity API v3.
//!
//! Currently only supports [Password](struct.Password.html) authentication.
//! Identity API v2 is not and will not be supported.

use std::collections::hash_map::DefaultHasher;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::sync::Arc;

use async_trait::async_trait;
use chrono::{Duration, Local};
use log::{debug, error, trace};
use osproto::identity as protocol;
use reqwest::{Client, IntoUrl, Method, RequestBuilder, Response, Url};

use super::cache::ValueCache;
use super::{catalog, request, AuthType, Error, ErrorKind};

pub use osproto::identity::IdOrName;

const MISSING_SUBJECT_HEADER: &str = "Missing X-Subject-Token header";
const INVALID_SUBJECT_HEADER: &str = "Invalid X-Subject-Token header";
// Required validity time in minutes. Here we refresh the token if it expires
// in 10 minutes or less.
const TOKEN_MIN_VALIDITY: i64 = 10;

/// A scope of a token.
///
/// Only project scopes are currently supported.
#[derive(Debug)]
pub enum Scope {
    /// A token scoped to a project.
    Project {
        /// Project ID or name.
        project: IdOrName,
        /// ID or name of the project domain.
        domain: Option<IdOrName>,
    },
}

/// Plain authentication token without additional details.
#[derive(Clone)]
struct Token {
    value: String,
    body: protocol::Token,
}

impl fmt::Debug for Token {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut hasher = DefaultHasher::new();
        self.value.hash(&mut hasher);
        write!(
            f,
            "Token {{ value: hash({}), body: {:?} }}",
            hasher.finish(),
            self.body
        )
    }
}

/// Generic trait for authentication using Identity API V3.
pub trait Identity {
    /// Get a reference to the auth URL.
    fn auth_url(&self) -> &Url;
}

/// Password authentication using Identity API V3.
///
/// For any Identity authentication you need to know `auth_url`, which is an authentication endpoint
/// of the Identity service. For the Password authentication you also need:
/// 1. User name and password.
/// 2. Domain of the user.
/// 3. Name of the project to use.
/// 4. Domain of the project.
///
/// Note: currently only names are supported for user, user domain and project domain. ID support is
/// coming later.
///
/// Start with creating a `Password` object using [new](#method.new), then add a project scope
/// with [with_project_scope](#method.with_project_scope):
///
/// ```rust,no_run
/// # use osauth::identity::IdOrName;
/// let auth = osauth::identity::Password::new(
///     "https://cloud.local/identity",
///     "admin",
///     "pa$$w0rd",
///     "Default"
/// )
/// .expect("Invalid auth_url")
/// .with_project_scope(IdOrName::Name("project1".to_string()), None);
///
/// let session = osauth::Session::new(auth);
/// ```
///
/// If your cloud has several regions, pick one using [with_region](#method.with_region):
///
/// ```rust,no_run
/// use osauth::identity::IdOrName;
///
/// let scope = osauth::identity::Scope::Project {
///     project: IdOrName::Name("project1".to_string()),
///     domain: Some(IdOrName::Id("default".to_string())),
/// };
/// let auth = osauth::identity::Password::new(
///     "https://cloud.local/identity",
///     "admin",
///     "pa$$w0rd",
///     "Default"
/// )
/// .expect("Invalid auth_url")
/// .with_scope(scope)
/// .with_region("US-East");
///
/// let session = osauth::Session::new(auth);
/// ```
///
/// By default, the `public` endpoint interface is used. f you would prefer to default to another
/// one, you can set it with
/// [with_default_endpoint_interface](#method.with_default_endpoint_interface).
///
/// ```rust,no_run
/// use osauth::identity::IdOrName;
///
/// let scope = osauth::identity::Scope::Project {
///     project: IdOrName::Name("project1".to_string()),
///     domain: Some(IdOrName::Id("default".to_string())),
/// };
/// let auth = osauth::identity::Password::new(
///     "https://cloud.local/identity",
///     "admin",
///     "pa$$w0rd",
///     "Default"
/// )
/// .expect("Invalid auth_url")
/// .with_scope(scope)
/// .with_default_endpoint_interface("internal");
/// ```
///
/// The authentication token is cached while it's still valid or until
/// [refresh](../trait.AuthType.html#tymethod.refresh) is called.
#[derive(Clone, Debug)]
pub struct Password {
    client: Client,
    auth_url: Url,
    body: protocol::AuthRoot,
    token_endpoint: String,
    region: Option<String>,
    cached_token: Arc<ValueCache<Token>>,
    endpoint_interface: String,
}

impl Identity for Password {
    fn auth_url(&self) -> &Url {
        &self.auth_url
    }
}

impl Password {
    /// Create a password authentication.
    pub fn new<U, S1, S2, S3>(
        auth_url: U,
        user_name: S1,
        password: S2,
        user_domain_name: S3,
    ) -> Result<Password, Error>
    where
        U: IntoUrl,
        S1: Into<String>,
        S2: Into<String>,
        S3: Into<String>,
    {
        Password::new_with_client(
            auth_url,
            Client::new(),
            user_name,
            password,
            user_domain_name,
        )
    }

    /// Create a password authentication with the provided HTTP client.
    pub fn new_with_client<U, S1, S2, S3>(
        auth_url: U,
        client: Client,
        user_name: S1,
        password: S2,
        user_domain_name: S3,
    ) -> Result<Password, Error>
    where
        U: IntoUrl,
        S1: Into<String>,
        S2: Into<String>,
        S3: Into<String>,
    {
        let url = auth_url.into_url()?;
        // TODO: more robust logic?
        let token_endpoint = if url.path().ends_with("/v3") {
            format!("{}/auth/tokens", url)
        } else {
            format!("{}/v3/auth/tokens", url)
        };
        let pw = protocol::UserAndPassword {
            user: protocol::IdOrName::Name(user_name.into()),
            password: password.into(),
            domain: Some(protocol::IdOrName::Name(user_domain_name.into())),
        };
        let body = protocol::AuthRoot {
            auth: protocol::Auth {
                identity: protocol::Identity::Password(pw),
                scope: None,
            },
        };
        Ok(Password {
            client,
            auth_url: url,
            region: None,
            body,
            token_endpoint,
            cached_token: Arc::new(ValueCache::default()),
            endpoint_interface: "public".to_string(),
        })
    }

    /// The default endpoint interface.
    #[inline]
    pub fn default_endpoint_interface(&self) -> &String {
        &self.endpoint_interface
    }

    /// Set the default endpoint interface to use.
    pub fn set_default_endpoint_interface<S>(&mut self, endpoint_interface: S)
    where
        S: Into<String>,
    {
        self.endpoint_interface = endpoint_interface.into();
    }

    /// Set a region for this authentication method.
    pub fn set_region<S>(&mut self, region: S)
    where
        S: Into<String>,
    {
        self.region = Some(region.into());
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
    pub fn set_scope(&mut self, scope: Scope) {
        self.body.auth.scope = Some(match scope {
            Scope::Project { project, domain } => {
                protocol::Scope::Project(protocol::Project { project, domain })
            }
        });
    }

    /// Convert this session into one using the given endpoint interface.
    #[inline]
    pub fn with_default_endpoint_interface<S>(mut self, endpoint_interface: S) -> Self
    where
        S: Into<String>,
    {
        self.set_default_endpoint_interface(endpoint_interface);
        self
    }

    /// Scope authentication to the given project.
    ///
    /// A convenience wrapper around `with_scope`.
    #[inline]
    pub fn with_project_scope(
        mut self,
        project: IdOrName,
        domain: impl Into<Option<IdOrName>>,
    ) -> Password {
        self.set_project_scope(project, domain);
        self
    }

    /// Set a region for this authentication method.
    #[inline]
    pub fn with_region<S>(mut self, region: S) -> Self
    where
        S: Into<String>,
    {
        self.set_region(region);
        self
    }

    /// Add a scope to the authentication.
    #[inline]
    pub fn with_scope(mut self, scope: Scope) -> Self {
        self.set_scope(scope);
        self
    }

    async fn do_refresh(&self, force: bool) -> Result<(), Error> {
        if force || !self.cached_token.validate(token_alive) {
            let cached_token = Arc::clone(&self.cached_token);
            let resp = self
                .client
                .post(&self.token_endpoint)
                .json(&self.body)
                .send()
                .await?;
            let token = token_from_response(request::check(resp).await?).await?;
            cached_token.set(token);
        }
        Ok(())
    }

    /// User name.
    #[inline]
    #[deprecated(since = "0.2.3", note = "Use user in preparation for user ID support.")]
    pub fn user_name(&self) -> &String {
        match *self.user() {
            protocol::IdOrName::Name(ref user) => user,
            // NOTE(dtantsur): change to panic when we support user IDs.
            _ => unreachable!(),
        }
    }

    /// User name or ID.
    #[inline]
    pub fn user(&self) -> &IdOrName {
        match self.body.auth.identity {
            protocol::Identity::Password(ref pw) => &pw.user,
            _ => unreachable!(),
        }
    }

    /// Project name or ID (if project scoped).
    #[inline]
    pub fn project(&self) -> Option<&IdOrName> {
        match self.body.auth.scope {
            Some(protocol::Scope::Project(ref prj)) => Some(&prj.project),
            _ => None,
        }
    }

    #[inline]
    async fn get_token(&self) -> Result<String, Error> {
        let cached_token = Arc::clone(&self.cached_token);
        self.do_refresh(false).await?;
        Ok(cached_token.extract(|t| t.value.clone()).unwrap())
    }
}

#[inline]
fn token_alive(value: &Token) -> bool {
    let validity_time_left = value.body.expires_at.signed_duration_since(Local::now());
    trace!("Token is valid for {:?}", validity_time_left);
    validity_time_left > Duration::minutes(TOKEN_MIN_VALIDITY)
}

#[async_trait]
impl AuthType for Password {
    /// Get region.
    fn region(&self) -> Option<String> {
        self.region.clone()
    }

    /// Create an authenticated request.
    async fn request(&self, method: Method, url: Url) -> Result<RequestBuilder, Error> {
        let token = self.get_token().await?;
        Ok(self
            .client
            .request(method, url)
            .header("x-auth-token", token))
    }

    /// Get a URL for the requested service.
    async fn get_endpoint(
        &self,
        service_type: String,
        endpoint_interface: Option<String>,
    ) -> Result<Url, Error> {
        let cached_token = Arc::clone(&self.cached_token);
        let real_interface = endpoint_interface.unwrap_or_else(|| self.endpoint_interface.clone());
        let region = self.region.clone();
        debug!(
            "Requesting a catalog endpoint for service '{}', interface \
             '{}' from region {:?}",
            service_type, real_interface, self.region
        );
        self.do_refresh(false).await?;
        cached_token
            .extract(|t| {
                catalog::extract_url(&t.body.catalog, &service_type, &real_interface, &region)
            })
            .expect("Token is not populated after refreshing")
    }

    /// Refresh the cached token and service catalog.
    async fn refresh(&self) -> Result<(), Error> {
        self.do_refresh(true).await
    }
}

async fn token_from_response(resp: Response) -> Result<Token, Error> {
    let value = match resp.headers().get("x-subject-token") {
        Some(hdr) => match hdr.to_str() {
            Ok(s) => Ok(s.to_string()),
            Err(e) => {
                error!(
                    "Invalid X-Subject-Token {:?} received from {}: {}",
                    hdr,
                    resp.url(),
                    e
                );
                Err(Error::new(
                    ErrorKind::InvalidResponse,
                    INVALID_SUBJECT_HEADER,
                ))
            }
        },
        None => {
            error!("No X-Subject-Token header received from {}", resp.url());
            Err(Error::new(
                ErrorKind::InvalidResponse,
                MISSING_SUBJECT_HEADER,
            ))
        }
    }?;

    let root = resp.json::<protocol::TokenRoot>().await?;
    debug!("Received a token expiring at {}", root.token.expires_at);
    trace!("Received catalog: {:?}", root.token.catalog);
    Ok(Token {
        value,
        body: root.token,
    })
}

#[cfg(test)]
pub mod test {
    #![allow(unused_results)]

    use super::super::AuthType;
    use super::{IdOrName, Identity, Password};

    #[test]
    fn test_identity_new() {
        let id = Password::new("http://127.0.0.1:8080/", "admin", "pa$$w0rd", "Default").unwrap();
        let e = id.auth_url();
        assert_eq!(e.scheme(), "http");
        assert_eq!(e.host_str().unwrap(), "127.0.0.1");
        assert_eq!(e.port().unwrap(), 8080u16);
        assert_eq!(e.path(), "/");
        assert_eq!(id.user(), &IdOrName::Name("admin".to_string()));
    }

    #[test]
    fn test_identity_new_invalid() {
        Password::new("http://127.0.0.1 8080/", "admin", "pa$$w0rd", "Default")
            .err()
            .unwrap();
    }

    #[test]
    fn test_identity_create() {
        let id = Password::new(
            "http://127.0.0.1:8080/identity",
            "user",
            "pa$$w0rd",
            "example.com",
        )
        .unwrap()
        .with_project_scope(
            IdOrName::Name("cool project".to_string()),
            IdOrName::Name("example.com".to_string()),
        );
        assert_eq!(id.auth_url().to_string(), "http://127.0.0.1:8080/identity");
        assert_eq!(id.user(), &IdOrName::Name("user".to_string()));
        assert_eq!(
            id.project(),
            Some(&IdOrName::Name("cool project".to_string()))
        );
        assert_eq!(
            &id.token_endpoint,
            "http://127.0.0.1:8080/identity/v3/auth/tokens"
        );
        assert_eq!(id.region(), None);
    }
}
