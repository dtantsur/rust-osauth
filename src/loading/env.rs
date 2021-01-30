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

use std::env::{self, VarError};

use super::cloud::{Auth, CloudConfig};
use crate::Error;

// This is only used for unit testing.
trait Environment {
    fn get(&self, name: &'static str) -> Result<String, VarError>;
}

#[derive(Debug, Clone, Copy)]
struct RealEnvironment;

impl Environment for RealEnvironment {
    fn get(&self, name: &'static str) -> Result<String, VarError> {
        env::var(name)
    }
}

#[inline]
fn _from_env<E: Environment>(env: E) -> Result<CloudConfig, Error> {
    if let Ok(cloud_name) = env.get("OS_CLOUD") {
        return CloudConfig::from_config(cloud_name);
    }

    let auth = Auth {
        auth_url: env.get("OS_AUTH_URL").ok(),
        endpoint: env.get("OS_ENDPOINT").ok(),
        password: env.get("OS_PASSWORD").ok(),
        project_id: env.get("OS_PROJECT_ID").ok(),
        project_name: env.get("OS_PROJECT_NAME").ok(),
        project_domain_id: env.get("OS_PROJECT_DOMAIN_ID").ok(),
        project_domain_name: env.get("OS_PROJECT_DOMAIN_NAME").ok(),
        token: env.get("OS_TOKEN").ok(),
        username: env.get("OS_USERNAME").ok(),
        user_domain_name: env.get("OS_USER_DOMAIN_NAME").ok(),
    };

    let config = CloudConfig {
        auth: Some(auth),
        auth_type: env.get("OS_AUTH_TYPE").ok(),
        cacert: env.get("OS_CACERT").ok(),
        interface: env.get("OS_INTERFACE").ok(),
        region_name: env.get("OS_REGION_NAME").ok(),
        options: Default::default(),
    };

    Ok(config)
}

/// Create a `Session` from environment variables.
pub fn from_env() -> Result<CloudConfig, Error> {
    _from_env(RealEnvironment)
}

#[cfg(test)]
pub mod test {
    use std::collections::HashMap;
    use std::env::VarError;

    use maplit::hashmap;

    use super::{Environment, _from_env};

    impl Environment for HashMap<&'static str, &'static str> {
        fn get(&self, name: &'static str) -> Result<String, VarError> {
            self.get(name)
                .cloned()
                .map(From::from)
                .ok_or_else(|| VarError::NotPresent)
        }
    }

    fn check(env: impl Environment) {
        let _ = _from_env(env).unwrap().create_session_config().unwrap();
    }

    #[test]
    fn test_password_no_domains() {
        let env = hashmap! {
            "OS_AUTH_URL" => "http://example.com",
            "OS_USERNAME" => "admin",
            "OS_PASSWORD" => "password",
            "OS_PROJECT_NAME" => "admin",
        };

        check(env);
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

        check(env);
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

        check(env);
    }

    #[test]
    fn test_token_no_domains() {
        let env = hashmap! {
            "OS_AUTH_URL" => "http://example.com",
            "OS_TOKEN" => "abcdef",
            "OS_PROJECT_NAME" => "admin",
        };

        check(env);
    }

    #[test]
    fn test_token_with_domains() {
        let env = hashmap! {
            "OS_AUTH_URL" => "http://example.com",
            "OS_TOKEN" => "abcdef",
            "OS_PROJECT_NAME" => "admin",
            "OS_PROJECT_DOMAIN_NAME" => "Default",
        };

        check(env);
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

        check(env);
    }

    #[test]
    fn test_http_basic() {
        let env = hashmap! {
            "OS_AUTH_TYPE" => "http_basic",
            "OS_ENDPOINT" => "http://example.com",
            "OS_USERNAME" => "admin",
            "OS_PASSWORD" => "password",
        };

        check(env);
    }

    #[test]
    fn test_none() {
        let env = hashmap! {
            "OS_AUTH_TYPE" => "none",
            "OS_ENDPOINT" => "http://example.com",
        };

        check(env);
    }
}
