// Copyright 2018-2020 Dmitry Tantsur <dtantsur@protonmail.com>
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

//! Support for `OS_` environment variables.

use std::env;
use std::str::FromStr;

use reqwest::Client;

use crate::common::IdOrName;
use crate::identity::{Password, Scope, Token};
use crate::loading;
use crate::{
    AuthType, BasicAuth, EndpointFilters, Error, ErrorKind, InterfaceType, NoAuth, Session,
};

// This is only used for unit testing.
trait Environment {
    fn get(&self, name: &'static str) -> Result<String, Error>;
}

#[derive(Debug, Clone, Copy)]
struct RealEnvironment;

impl Environment for RealEnvironment {
    fn get(&self, name: &'static str) -> Result<String, Error> {
        env::var(name).map_err(|_| {
            Error::new(
                ErrorKind::InvalidInput,
                format!("Required environment variable {} is not provided", name),
            )
        })
    }
}

#[inline]
fn create_session<T, E>(client: Client, auth: T, env: E) -> Result<Session, Error>
where
    T: AuthType + 'static,
    E: Environment,
{
    let mut filters = EndpointFilters::default();

    if let Ok(interface) = env.get("OS_INTERFACE") {
        filters.set_interfaces(InterfaceType::from_str(&interface)?);
    }

    if let Ok(region) = env.get("OS_REGION_NAME") {
        filters.region = Some(region);
    }

    Ok(Session::new_with_client(client, auth).with_endpoint_filters(filters))
}

#[inline]
fn _from_env<E: Environment>(env: E) -> Result<Session, Error> {
    if let Ok(cloud_name) = env.get("OS_CLOUD") {
        return loading::from_config(cloud_name);
    }

    let auth_type = env.get("OS_AUTH_TYPE").unwrap_or_else(|_| {
        if env.get("OS_TOKEN").is_ok() {
            "v3token".to_string()
        } else {
            "password".to_string()
        }
    });

    let client = loading::get_client(env.get("OS_CACERT").ok())?;

    if auth_type == "none" {
        let endpoint = env.get("OS_ENDPOINT")?;
        let id = NoAuth::new(&endpoint)?;
        return Ok(Session::new_with_client(client, id));
    }

    if auth_type == "http_basic" {
        let endpoint = env.get("OS_ENDPOINT")?;
        let user_name = env.get("OS_USERNAME")?;
        let password = env.get("OS_PASSWORD")?;
        let id = BasicAuth::new(&endpoint, user_name, password)?;
        return Ok(Session::new_with_client(client, id));
    }

    let auth_url = env.get("OS_AUTH_URL")?;
    let project = env
        .get("OS_PROJECT_ID")
        .map(IdOrName::Id)
        .or_else(|_| env.get("OS_PROJECT_NAME").map(IdOrName::Name))?;

    let project_domain = env
        .get("OS_PROJECT_DOMAIN_ID")
        .map(IdOrName::Id)
        .or_else(|_| env.get("OS_PROJECT_DOMAIN_NAME").map(IdOrName::Name))
        .ok();

    let scope = Scope::Project {
        project,
        domain: project_domain,
    };

    match auth_type.as_str() {
        "password" => {
            let user_name = env.get("OS_USERNAME")?;
            let password = env.get("OS_PASSWORD")?;
            let user_domain = env
                .get("OS_USER_DOMAIN_NAME")
                .unwrap_or_else(|_| String::from("Default"));
            let id = Password::new(&auth_url, user_name, password, user_domain)?;
            create_session(client, id.with_scope(scope), env)
        }
        "v3token" => {
            let token = env.get("OS_TOKEN")?;
            let id = Token::new(&auth_url, token)?;
            create_session(client, id.with_scope(scope), env)
        }
        _ => Err(Error::new(
            ErrorKind::InvalidInput,
            format!("Unsupported authentication type: {}", auth_type),
        )),
    }
}

/// Create a `Session` from environment variables.
///
/// Supported authentication types are `password`, `v3token`, `http_basic` and `none`.
pub fn from_env() -> Result<Session, Error> {
    _from_env(RealEnvironment)
}

#[cfg(test)]
pub mod test {
    use std::collections::HashMap;

    use maplit::hashmap;

    use super::{Environment, _from_env};
    use crate::{Error, ErrorKind};

    impl Environment for HashMap<&'static str, &'static str> {
        fn get(&self, name: &'static str) -> Result<String, Error> {
            self.get(name)
                .cloned()
                .map(From::from)
                .ok_or_else(|| Error::new(ErrorKind::InvalidInput, name))
        }
    }

    #[test]
    fn test_password_no_domains() {
        let env = hashmap! {
            "OS_AUTH_URL" => "http://example.com",
            "OS_USERNAME" => "admin",
            "OS_PASSWORD" => "password",
            "OS_PROJECT_NAME" => "admin",
        };

        let _session = _from_env(env).unwrap();
    }

    #[test]
    fn test_password_with_domains() {
        let env = hashmap! {
            "OS_AUTH_URL" => "http://example.com",
            "OS_USERNAME" => "admin",
            "OS_PASSWORD" => "password",
            "OS_PROJECT_NAME" => "admin",
            "OS_USER_DOMAIN_NAME" => "Default",
            "OS_PROJECT_DOMAIN_NAME" => "Default",
        };

        let _session = _from_env(env).unwrap();
    }

    #[test]
    fn test_password_with_type() {
        let env = hashmap! {
            "OS_AUTH_TYPE" => "password",
            "OS_AUTH_URL" => "http://example.com",
            "OS_USERNAME" => "admin",
            "OS_PASSWORD" => "password",
            "OS_PROJECT_NAME" => "admin",
            "OS_USER_DOMAIN_NAME" => "Default",
            "OS_PROJECT_DOMAIN_NAME" => "Default",
        };

        let _session = _from_env(env).unwrap();
    }

    #[test]
    fn test_token_no_domains() {
        let env = hashmap! {
            "OS_AUTH_URL" => "http://example.com",
            "OS_TOKEN" => "abcdef",
            "OS_PROJECT_NAME" => "admin",
        };

        let _session = _from_env(env).unwrap();
    }

    #[test]
    fn test_token_with_domains() {
        let env = hashmap! {
            "OS_AUTH_URL" => "http://example.com",
            "OS_TOKEN" => "abcdef",
            "OS_PROJECT_NAME" => "admin",
            "OS_PROJECT_DOMAIN_NAME" => "Default",
        };

        let _session = _from_env(env).unwrap();
    }

    #[test]
    fn test_token_with_type() {
        let env = hashmap! {
            "OS_AUTH_TYPE" => "v3token",
            "OS_AUTH_URL" => "http://example.com",
            "OS_TOKEN" => "abcdef",
            "OS_PROJECT_NAME" => "admin",
            "OS_PROJECT_DOMAIN_NAME" => "Default",
        };

        let _session = _from_env(env).unwrap();
    }

    #[test]
    fn test_http_basic() {
        let env = hashmap! {
            "OS_AUTH_TYPE" => "http_basic",
            "OS_ENDPOINT" => "http://example.com",
            "OS_USERNAME" => "admin",
            "OS_PASSWORD" => "password",
        };

        let _session = _from_env(env).unwrap();
    }

    #[test]
    fn test_none() {
        let env = hashmap! {
            "OS_AUTH_TYPE" => "none",
            "OS_ENDPOINT" => "http://example.com",
        };

        let _session = _from_env(env).unwrap();
    }
}
