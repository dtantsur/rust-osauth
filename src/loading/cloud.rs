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

//! Cloud configuration structure.

use std::collections::HashMap;
use std::convert::TryFrom;
use std::str::FromStr;
use std::sync::Arc;

use reqwest::Url;
use serde::{Deserialize, Serialize};

use super::config::from_config;
use super::env::from_env;
use crate::client::AuthenticatedClient;
use crate::common::IdOrName;
use crate::identity::{Password, Scope, Token};
use crate::{AuthType, BasicAuth, Error, ErrorKind, InterfaceType, NoAuth, Session};

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub(crate) struct Auth {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) auth_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) project_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) project_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) project_domain_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) project_domain_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) user_domain_name: Option<String>,
}

/// Cloud configuration.
///
/// This is a source from which sessions and authentications can be created.
/// It can be loaded from a `clouds.yaml` configuration file or from environment variables.
/// Additionally, the configuration can be serialized and deserialized.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub struct CloudConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) auth: Option<Auth>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) auth_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) cacert: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) interface: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) region_name: Option<String>,
    #[serde(flatten)]
    pub(crate) options: HashMap<String, serde_yaml::Value>,
}

#[inline]
fn require(value: Option<String>, message: &str) -> Result<String, Error> {
    value.ok_or_else(|| Error::new(ErrorKind::InvalidConfig, message))
}

fn project_scope(
    project_id: Option<String>,
    project_name: Option<String>,
    project_domain_id: Option<String>,
    project_domain_name: Option<String>,
) -> Option<Scope> {
    let project_domain = project_domain_id
        .map(IdOrName::Id)
        .or_else(|| project_domain_name.map(IdOrName::Name))
        .unwrap_or_else(|| IdOrName::from_name("Default"));
    project_id
        .map(IdOrName::Id)
        .or_else(|| project_name.map(IdOrName::Name))
        .map(|project| Scope::Project {
            project,
            domain: Some(project_domain),
        })
}

impl Auth {
    fn create_basic_auth(self) -> Result<BasicAuth, Error> {
        let endpoint = require(
            self.endpoint,
            "HTTP basic authentication requires an endpoint",
        )?;
        let username = require(
            self.username,
            "HTTP basic authentication requires a username",
        )?;
        let password = require(
            self.password,
            "HTTP basic authentication requires a password",
        )?;
        BasicAuth::new(&endpoint, username, password)
    }

    fn create_none_auth(self) -> Result<NoAuth, Error> {
        if let Some(endpoint) = self.endpoint {
            NoAuth::new(&endpoint)
        } else {
            Ok(NoAuth::new_without_endpoint())
        }
    }

    fn create_password_auth(self) -> Result<Password, Error> {
        let auth_url = require(
            self.auth_url,
            "Password authentication requires an authentication URL",
        )?;
        let username = require(self.username, "Password authentication requires a username")?;
        let password = require(self.password, "Password authentication requires a password")?;
        let user_domain = self
            .user_domain_name
            .unwrap_or_else(|| String::from("Default"));
        let mut id = Password::new(&auth_url, username, password, user_domain)?;

        if let Some(scope) = project_scope(
            self.project_id,
            self.project_name,
            self.project_domain_id,
            self.project_domain_name,
        ) {
            id.set_scope(scope);
        }

        Ok(id)
    }

    fn create_token_auth(self) -> Result<Token, Error> {
        let auth_url = require(
            self.auth_url,
            "Token authentication requires an authentication URL",
        )?;
        let token = require(self.token, "Token authentication requires a token")?;
        let mut id = Token::new(&auth_url, token)?;

        if let Some(scope) = project_scope(
            self.project_id,
            self.project_name,
            self.project_domain_id,
            self.project_domain_name,
        ) {
            id.set_scope(scope);
        }

        Ok(id)
    }

    fn create_auth(self, auth_type: Option<String>) -> Result<Arc<dyn AuthType>, Error> {
        let auth_type = auth_type.unwrap_or_else(|| {
            if self.token.is_some() {
                "v3token"
            } else {
                "password"
            }
            .into()
        });

        Ok(if auth_type == "password" {
            Arc::new(self.create_password_auth()?)
        } else if auth_type == "v3token" {
            Arc::new(self.create_token_auth()?)
        } else if auth_type == "http_basic" {
            Arc::new(self.create_basic_auth()?)
        } else if auth_type == "none" {
            Arc::new(self.create_none_auth()?)
        } else {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!("Unsupported authentication type: {}", auth_type),
            ));
        })
    }
}

// This structure is not strictly necessary but very handy for unit tests.
#[derive(Debug)]
pub(crate) struct SessionConfig {
    pub(crate) client: AuthenticatedClient,
    pub(crate) endpoint_overrides: HashMap<String, Url>,
    pub(crate) interface: Option<InterfaceType>,
    pub(crate) region_name: Option<String>,
}

impl CloudConfig {
    /// Create a cloud config from the configuration file.
    pub fn from_config<S: AsRef<str>>(cloud_name: S) -> Result<CloudConfig, Error> {
        from_config(cloud_name.as_ref())
    }

    /// Create a cloud config from environment variables.
    pub fn from_env() -> Result<CloudConfig, Error> {
        from_env()
    }

    fn create_endpoint_overrides(&self) -> Result<HashMap<String, Url>, Error> {
        let mut result = HashMap::with_capacity(self.options.len());
        for (ref key, ref value) in &self.options {
            if let Some(service_type) = key.strip_suffix("_endpoint_override") {
                if let serde_yaml::Value::String(value) = value {
                    let url = Url::parse(value).map_err(|e| {
                        Error::new(
                            ErrorKind::InvalidConfig,
                            format!("Invalid {} `{}`: {}", key, value, e),
                        )
                    })?;
                    let _ = result.insert(service_type.to_string(), url.clone());
                    // Handle types like baremetal-introspection
                    let with_dashes = service_type.replace("_", "-");
                    let _ = result.insert(with_dashes, url);
                } else {
                    return Err(Error::new(
                        ErrorKind::InvalidConfig,
                        format!("{} must be a string, got {:?}", key, value),
                    ));
                }
            }
        }
        Ok(result)
    }

    #[inline]
    pub(crate) fn create_session_config(self) -> Result<SessionConfig, Error> {
        let endpoint_overrides = self.create_endpoint_overrides()?;
        let auth = if let Some(auth_info) = self.auth {
            auth_info.create_auth(self.auth_type)?
        } else {
            if self.auth_type.map(|x| x == "none").unwrap_or(false) {
                Arc::new(NoAuth::new_without_endpoint())
            } else {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    "Credentials can be missing only for none authentication",
                ));
            }
        };
        let client = AuthenticatedClient::new_internal(super::get_client(self.cacert)?, auth);
        let interface = if let Some(interface) = self.interface {
            Some(InterfaceType::from_str(&interface)?)
        } else {
            None
        };

        Ok(SessionConfig {
            client,
            endpoint_overrides,
            interface,
            region_name: self.region_name,
        })
    }

    /// Create a session from this configuration.
    pub fn create_session(self) -> Result<Session, Error> {
        let config = self.create_session_config()?;
        let mut result = Session::new_with_authenticated_client(config.client)
            .with_endpoint_overrides(config.endpoint_overrides);
        result.endpoint_filters_mut().region = config.region_name;
        if let Some(interface) = config.interface {
            result.endpoint_filters_mut().set_interfaces(interface);
        }
        Ok(result)
    }

    fn check_auth_type(&self, expected: &str) -> Result<(), Error> {
        if let Some(ref auth_type) = self.auth_type {
            if auth_type != expected {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    format!(
                        "Invalid authentication type, excepted {}, got {}",
                        expected, auth_type
                    ),
                ));
            }
        }
        Ok(())
    }
}

impl TryFrom<CloudConfig> for Session {
    type Error = Error;

    fn try_from(value: CloudConfig) -> Result<Session, Error> {
        value.create_session()
    }
}

impl TryFrom<CloudConfig> for NoAuth {
    type Error = Error;

    fn try_from(value: CloudConfig) -> Result<NoAuth, Error> {
        value.check_auth_type("none")?;
        if let Some(auth) = value.auth {
            auth.create_none_auth()
        } else {
            Ok(NoAuth::new_without_endpoint())
        }
    }
}

impl TryFrom<CloudConfig> for BasicAuth {
    type Error = Error;

    fn try_from(value: CloudConfig) -> Result<BasicAuth, Error> {
        value.check_auth_type("http_basic")?;
        if let Some(auth) = value.auth {
            auth.create_basic_auth()
        } else {
            Err(Error::new(
                ErrorKind::InvalidInput,
                "Credentials can be missing only for none authentication",
            ))
        }
    }
}

impl TryFrom<CloudConfig> for Password {
    type Error = Error;

    fn try_from(value: CloudConfig) -> Result<Password, Error> {
        value.check_auth_type("password")?;
        if let Some(auth) = value.auth {
            auth.create_password_auth()
        } else {
            Err(Error::new(
                ErrorKind::InvalidInput,
                "Credentials can be missing only for none authentication",
            ))
        }
    }
}

impl TryFrom<CloudConfig> for Token {
    type Error = Error;

    fn try_from(value: CloudConfig) -> Result<Token, Error> {
        value.check_auth_type("v3token")?;
        if let Some(auth) = value.auth {
            auth.create_token_auth()
        } else {
            Err(Error::new(
                ErrorKind::InvalidInput,
                "Credentials can be missing only for none authentication",
            ))
        }
    }
}

#[cfg(test)]
mod test_cloud_config {
    #[cfg(any(feature = "native-tls", feature = "rustls"))]
    use std::io::Write;

    use maplit::hashmap;
    use reqwest::Url;

    use super::{Auth, CloudConfig};

    #[test]
    fn test_endpoint_overrides_empty() {
        let cfg = CloudConfig::default();
        let result = cfg.create_endpoint_overrides().unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_endpoint_overrides_valid() {
        let options = hashmap! {
            "baremetal_endpoint_override".into() => "http://127.0.0.1/baremetal".into(),
            "baremetal_introspection_endpoint_override".into() => "http://127.0.0.1:5050/".into(),
            "something unrelated".into() => "banana".into(),
        };
        let cfg = CloudConfig {
            options,
            ..CloudConfig::default()
        };
        let result = cfg.create_endpoint_overrides().unwrap();
        assert_eq!(
            result,
            hashmap! {
                "baremetal".into() => Url::parse("http://127.0.0.1/baremetal").unwrap(),
                "baremetal_introspection".into() => Url::parse("http://127.0.0.1:5050/").unwrap(),
                "baremetal-introspection".into() => Url::parse("http://127.0.0.1:5050/").unwrap(),
            }
        );
    }

    #[test]
    fn test_endpoint_overrides_wrong_type() {
        let options = hashmap! {
            "baremetal_endpoint_override".into() => "http://127.0.0.1/baremetal".into(),
            "baremetal_introspection_endpoint_override".into() => 42.into(),
        };
        let cfg = CloudConfig {
            options,
            ..CloudConfig::default()
        };
        assert!(cfg.create_endpoint_overrides().is_err());
    }

    #[test]
    fn test_endpoint_overrides_wrong_url() {
        let options = hashmap! {
            "baremetal_endpoint_override".into() => "http://127.0.0.1/baremetal".into(),
            "baremetal_introspection_endpoint_override".into() => "?! banana".into(),
        };
        let cfg = CloudConfig {
            options,
            ..CloudConfig::default()
        };
        assert!(cfg.create_endpoint_overrides().is_err());
    }

    #[test]
    fn test_create_session_config_no_auth() {
        let cfg = CloudConfig::default();
        assert!(cfg.create_session_config().is_err());
    }

    #[tokio::test]
    async fn test_create_session_config_none_auth() {
        let options = hashmap! {
            "baremetal_endpoint_override".into() => "http://127.0.0.1/baremetal".into(),
        };
        let cfg = CloudConfig {
            auth_type: Some("none".into()),
            options,
            ..CloudConfig::default()
        };
        let sscfg = cfg.create_session_config().unwrap();
        assert!(sscfg
            .client
            .get_endpoint("baremetal".into(), Default::default())
            .await
            .is_err());
    }

    #[tokio::test]
    async fn test_create_session_config_basic_auth() {
        let cfg = CloudConfig {
            auth_type: Some("http_basic".into()),
            auth: Some(Auth {
                username: Some("vasya".into()),
                password: Some("hacker".into()),
                endpoint: Some("http://127.0.0.1".into()),
                ..Auth::default()
            }),
            ..CloudConfig::default()
        };
        let sscfg = cfg.create_session_config().unwrap();
        assert_eq!(
            sscfg
                .client
                .get_endpoint("baremetal".into(), Default::default())
                .await
                .unwrap()
                .as_str(),
            "http://127.0.0.1/"
        );
    }

    #[test]
    #[cfg(any(feature = "native-tls", feature = "rustls"))]
    fn test_create_session_config_with_region_and_cacert() {
        let mut cacert = tempfile::NamedTempFile::new().unwrap();
        write!(
            cacert,
            r#"-----BEGIN CERTIFICATE-----
MIIBYzCCAQqgAwIBAgIUJcTlPhsFyWG9S0pAAElKuSFEPBYwCgYIKoZIzj0EAwIw
FDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTIwMTAwMjExNTU1NloXDTIwMTEwMTEx
NTU1NlowFDESMBAGA1UEAwwJbG9jYWxob3N0MFkwEwYHKoZIzj0CAQYIKoZIzj0D
AQcDQgAEsfpkV9dAThk54U1K+rXUnNbpwuNo5wCRrKpk+cNR/2HBO8VydNj7dkxs
VBUvI7M9hY8dgg1jBVoPcCf0GSOvuqM6MDgwFAYDVR0RBA0wC4IJbG9jYWxob3N0
MAsGA1UdDwQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDATAKBggqhkjOPQQDAgNH
ADBEAiAdjF7484kjb3XJoLbgqnZh4V1yHKs57eBVuil9/V0YugIgLwb/vSUAPowb
hK9jLBzNvo8qzKqaGfnGieuLeXCqFDA=
-----END CERTIFICATE-----"#
        )
        .unwrap();
        cacert.flush().unwrap();

        let cfg = CloudConfig {
            auth_type: Some("password".into()),
            auth: Some(Auth {
                auth_url: Some("http://127.0.0.1".into()),
                username: Some("vasya".into()),
                password: Some("hacker".into()),
                project_name: Some("admin".into()),
                ..Auth::default()
            }),
            cacert: Some(cacert.path().to_str().unwrap().into()),
            region_name: Some("Lapland".into()),
            ..CloudConfig::default()
        };
        let sscfg = cfg.create_session_config().unwrap();
        assert_eq!(sscfg.region_name.as_ref().unwrap(), "Lapland");
    }

    #[test]
    #[cfg(any(feature = "native-tls", feature = "rustls"))]
    fn test_create_session_config_cacert_not_found() {
        let cfg = CloudConfig {
            auth_type: Some("password".into()),
            auth: Some(Auth {
                auth_url: Some("http://127.0.0.1".into()),
                username: Some("vasya".into()),
                password: Some("hacker".into()),
                project_name: Some("admin".into()),
                ..Auth::default()
            }),
            cacert: Some("/I/do/not/exist".into()),
            region_name: Some("Lapland".into()),
            ..CloudConfig::default()
        };
        assert!(cfg.create_session_config().is_err());
    }
}
