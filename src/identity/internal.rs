// Copyright 2020 Dmitry Tantsur <divius.inside@gmail.com>
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

//! Internal implementation of the identity authentication.

use std::collections::hash_map::DefaultHasher;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::ops::Deref;

use chrono::{Duration, Local};
use log::{debug, error, trace};
use reqwest::{Client, Method, RequestBuilder, Response, Url};
use tokio::sync::{RwLock, RwLockReadGuard};

use super::protocol::{self, AuthRoot};
use super::{IdOrName, Scope, INVALID_SUBJECT_HEADER, MISSING_SUBJECT_HEADER, TOKEN_MIN_VALIDITY};
use crate::{request, EndpointFilters, Error, ErrorKind};

/// Plain authentication token without additional details.
#[derive(Clone)]
pub(crate) struct Token {
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

/// Internal identity authentication object.
#[derive(Debug)]
pub(crate) struct Internal {
    client: Client,
    auth_url: Url,
    body: AuthRoot,
    token_endpoint: String,
    cached_token: RwLock<Option<Token>>,
    pub filters: EndpointFilters,
}

impl Internal {
    /// Create a new implementation.
    pub fn new(client: Client, mut auth_url: Url, body: AuthRoot) -> Result<Internal, Error> {
        let _ = auth_url
            .path_segments_mut()
            .map_err(|_| Error::new(ErrorKind::InvalidConfig, "Invalid auth_url: wrong schema?"))?
            .pop_if_empty();

        let token_endpoint = if auth_url.as_str().ends_with("/v3") {
            format!("{}/auth/tokens", auth_url)
        } else {
            format!("{}/v3/auth/tokens", auth_url)
        };

        Ok(Internal {
            client,
            auth_url,
            body,
            token_endpoint,
            cached_token: RwLock::new(None),
            filters: EndpointFilters::default(),
        })
    }

    /// Access to the auth URL.
    #[inline]
    pub fn auth_url(&self) -> &Url {
        &self.auth_url
    }

    /// Access to the cached token.
    pub async fn cached_token(&self) -> Result<RwLockReadGuard<'_, Token>, Error> {
        self.refresh(false).await?;
        let guard = self.cached_token.read().await;
        // unwrap is safe because do_refresh unconditionally populates the token
        Ok(RwLockReadGuard::try_map(guard, |opt| opt.as_ref()).unwrap())
    }

    /// Get a URL for the requested service.
    pub async fn get_endpoint(
        &self,
        service_type: String,
        filters: EndpointFilters,
    ) -> Result<Url, Error> {
        let real_filters = filters.with_defaults(&self.filters);
        debug!(
            "Requesting a catalog endpoint for service '{}', filters {:?}",
            service_type, real_filters
        );
        let token = self.cached_token().await?;
        real_filters.find_in_catalog(&token.body.catalog, &service_type)
    }

    /// Get the authentication token string.
    #[inline]
    pub async fn get_token(&self) -> Result<String, Error> {
        let token = self.cached_token().await?;
        Ok(token.value.clone())
    }

    /// Add a scope to the authentication.
    pub fn set_scope(&mut self, scope: Scope) {
        self.body.auth.scope = Some(match scope {
            Scope::Project { project, domain } => {
                protocol::Scope::Project(protocol::Project { project, domain })
            }
        });
    }

    /// User name or ID.
    #[inline]
    pub fn user(&self) -> Option<&IdOrName> {
        match self.body.auth.identity {
            protocol::Identity::Password(ref pw) => Some(&pw.user),
            _ => None,
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

    /// Refresh the token (if needed or forced).
    pub async fn refresh(&self, force: bool) -> Result<(), Error> {
        // This is executed every request at least once, so it's important to start with a read
        // lock. We expect to hit this branch most of the time.
        if !force && token_alive(&self.cached_token.read().await) {
            return Ok(());
        }

        let mut lock = self.cached_token.write().await;
        // Additonal check in case another thread has updated the token while we were waiting for
        // the write lock.
        if token_alive(&lock) {
            return Ok(());
        }

        let resp = self
            .client
            .post(&self.token_endpoint)
            .json(&self.body)
            .send()
            .await?;
        *lock = Some(token_from_response(request::check(resp).await?).await?);
        Ok(())
    }

    /// Create an authenticated request.
    pub async fn request(&self, method: Method, url: Url) -> Result<RequestBuilder, Error> {
        let token = self.get_token().await?;
        Ok(self
            .client
            .request(method, url)
            .header("x-auth-token", token))
    }

    #[cfg(test)]
    pub fn token_endpoint(&self) -> &str {
        &self.token_endpoint
    }
}

impl Clone for Internal {
    fn clone(&self) -> Internal {
        Internal {
            client: self.client.clone(),
            auth_url: self.auth_url.clone(),
            body: self.body.clone(),
            token_endpoint: self.token_endpoint.clone(),
            cached_token: RwLock::new(None),
            filters: self.filters.clone(),
        }
    }
}

#[inline]
fn token_alive(token: &impl Deref<Target = Option<Token>>) -> bool {
    if let Some(value) = token.deref() {
        let validity_time_left = value.body.expires_at.signed_duration_since(Local::now());
        trace!("Token is valid for {:?}", validity_time_left);
        validity_time_left > Duration::minutes(TOKEN_MIN_VALIDITY)
    } else {
        false
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
