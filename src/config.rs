// Copyright 2018 Dmitry Tantsur <divius.inside@gmail.com>
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

//! Support for cloud configuration file.

use std::collections::HashMap;
use std::env;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use log::warn;
use serde::Deserialize;

use super::identity::{Password, Scope};
use super::utils;
use super::{BasicAuth, EndpointFilters, Error, ErrorKind, InterfaceType, Session};

use crate::identity::IdOrName;

#[derive(Debug, Deserialize)]
struct Auth {
    #[serde(default)]
    auth_url: Option<String>,
    #[serde(default)]
    endpoint: Option<String>,
    password: String,
    #[serde(default)]
    project_name: Option<String>,
    #[serde(default)]
    project_domain_name: Option<String>,
    username: String,
    #[serde(default)]
    user_domain_name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Cloud {
    auth: Auth,
    #[serde(default)]
    auth_type: Option<String>,
    #[serde(default)]
    region_name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Clouds {
    #[serde(flatten)]
    clouds: HashMap<String, Cloud>,
}

#[derive(Debug, Deserialize)]
struct Root {
    clouds: Clouds,
}

/// Inject profiles from clouds-public.yaml into clouds.yaml and return it in a new Value.
fn inject_profiles(
    clouds_public: &serde_yaml::Mapping,
    clouds: &mut serde_yaml::Mapping,
) -> Result<(), Error> {
    let clouds_mapping = match clouds.get_mut(&"clouds".into()).ok_or_else(|| {
        Error::new(
            ErrorKind::InvalidConfig,
            "clouds.yaml must contain a clouds object",
        )
    })? {
        serde_yaml::Value::Mapping(map) => map,
        other => {
            return Err(Error::new(
                ErrorKind::InvalidConfig,
                format!("clouds object must be a mapping, got {:?}", other),
            ));
        }
    };

    let clouds_public_mapping =
        match clouds_public.get(&"public-clouds".into()).ok_or_else(|| {
            Error::new(
                ErrorKind::InvalidConfig,
                "clouds-public.yaml must contain a public-clouds object",
            )
        })? {
            serde_yaml::Value::Mapping(map) => map,
            other => {
                return Err(Error::new(
                    ErrorKind::InvalidConfig,
                    format!("public-clouds object must be a mapping, got {:?}", other),
                ));
            }
        };

    for (cloud_name, cloud) in clouds_mapping.iter_mut() {
        if let Some(cloud_mapping) = cloud.as_mapping_mut() {
            if let Some(profile_value) = cloud_mapping.get(&"profile".into()) {
                if let Some(profile_name) = profile_value.as_str() {
                    if let Some(profile) = clouds_public_mapping.get(profile_value) {
                        if let Some(profile_mapping) = profile.as_mapping() {
                            // Do not overwrite keys that are already present.
                            utils::merge_mappings(profile_mapping.to_owned(), cloud_mapping, false);
                        }
                    } else {
                        return Err(Error::new(
                            ErrorKind::InvalidConfig,
                            format!("Missing profile {} in clouds-public.yaml", profile_name),
                        ));
                    }
                } else {
                    return Err(Error::new(
                        ErrorKind::InvalidConfig,
                        format!("Profile name {:?} is not a string", profile_value),
                    ));
                }
            }
        } else {
            warn!("Cloud record {:?} is not a mapping, ignoring", cloud_name);
        }
    }

    Ok(())
}

fn find_config<S: AsRef<str>>(filename: S) -> Option<PathBuf> {
    let filename = filename.as_ref();
    let current = Path::new(filename);
    if current.is_file() {
        match current.canonicalize() {
            Ok(val) => return Some(val),
            Err(e) => warn!("Cannot canonicalize {:?}: {}", current, e),
        }
    }

    if let Some(mut home) = dirs::home_dir() {
        home.push(format!(".config/openstack/{}", filename));
        if home.is_file() {
            return Some(home);
        }
    } else {
        warn!("Cannot find home directory");
    }

    let abs = PathBuf::from(format!("/etc/openstack/{}", filename));
    if abs.is_file() {
        Some(abs)
    } else {
        None
    }
}

#[inline]
fn with_one_key(key: &str) -> serde_yaml::Mapping {
    let mut result = serde_yaml::Mapping::with_capacity(1);
    let _ = result.insert(
        key.into(),
        serde_yaml::Value::Mapping(serde_yaml::Mapping::new()),
    );
    result
}

fn read_yaml(filename: &str, default_root_key: Option<&str>) -> Result<serde_yaml::Mapping, Error> {
    let path = match find_config(filename) {
        Some(path) => path,
        None => {
            if let Some(default) = default_root_key {
                return Ok(with_one_key(default));
            } else {
                return Err(Error::new(
                    ErrorKind::InvalidConfig,
                    format!("{} was not found in any location", filename),
                ));
            }
        }
    };

    let content = File::open(path).map_err(|e| {
        Error::new(
            ErrorKind::InvalidConfig,
            format!("Cannot read {}: {}", filename, e),
        )
    })?;

    match serde_yaml::from_reader(content).map_err(|e| {
        Error::new(
            ErrorKind::InvalidConfig,
            format!("Cannot parse {}: {}", filename, e),
        )
    })? {
        serde_yaml::Value::Mapping(mapping) => Ok(mapping),
        other => Err(Error::new(
            ErrorKind::InvalidConfig,
            format!("Root of {} is {:?}, not a mapping", filename, other),
        )),
    }
}

fn password_auth_from_cloud(auth: Auth, region_name: Option<String>) -> Result<Session, Error> {
    let user_domain = auth
        .user_domain_name
        .unwrap_or_else(|| String::from("Default"));
    let project_domain = auth
        .project_domain_name
        .unwrap_or_else(|| String::from("Default"));
    let auth_url = auth.auth_url.ok_or_else(|| {
        Error::new(
            ErrorKind::InvalidConfig,
            "Identity authentication requires an auth_url",
        )
    })?;
    let mut id = Password::new(&auth_url, auth.username, auth.password, user_domain)?;
    if let Some(project_name) = auth.project_name {
        let scope = Scope::Project {
            project: IdOrName::Name(project_name),
            domain: Some(IdOrName::Name(project_domain)),
        };
        id.set_scope(scope);
    }
    if let Some(region) = region_name {
        id.endpoint_filters_mut().region = Some(region);
    }

    Ok(Session::new(id))
}

fn from_files(
    name: &str,
    mut clouds: serde_yaml::Mapping,
    clouds_public: serde_yaml::Mapping,
    secure: serde_yaml::Mapping,
) -> Result<Session, Error> {
    utils::merge_mappings(secure, &mut clouds, true);

    inject_profiles(&clouds_public, &mut clouds)?;

    let mut clouds_root: Root = serde_yaml::from_value(serde_yaml::Value::Mapping(clouds))
        .map_err(|e| {
            Error::new(
                ErrorKind::InvalidConfig,
                format!("Cannot parse the merged cloud configuration: {}", e),
            )
        })?;

    let cloud =
        clouds_root.clouds.clouds.remove(name).ok_or_else(|| {
            Error::new(ErrorKind::InvalidConfig, format!("No such cloud: {}", name))
        })?;
    let auth_type = cloud.auth_type.unwrap_or_else(|| "password".to_string());

    match auth_type.as_str() {
        "password" => password_auth_from_cloud(cloud.auth, cloud.region_name),
        "http_basic" => {
            let endpoint = cloud.auth.endpoint.ok_or_else(|| {
                Error::new(
                    ErrorKind::InvalidConfig,
                    "Identity authentication requires an endpoint",
                )
            })?;

            let id = BasicAuth::new(&endpoint, cloud.auth.username, cloud.auth.password)?;
            Ok(Session::new(id))
        }
        _ => Err(Error::new(
            ErrorKind::InvalidConfig,
            format!("Unsupported authentication type: {}", auth_type),
        )),
    }
}

/// Create a `Session` from the config file.
pub fn from_config<S: AsRef<str>>(cloud_name: S) -> Result<Session, Error> {
    let clouds = read_yaml("clouds.yaml", None)?;
    let clouds_public = read_yaml("clouds-public.yaml", Some("public-clouds"))?;
    let secure = read_yaml("secure.yaml", Some("clouds"))?;

    from_files(cloud_name.as_ref(), clouds, clouds_public, secure)
}

fn password_auth_from_env(user_name: String, password: String) -> Result<Session, Error> {
    let auth_url = utils::require_env("OS_AUTH_URL")?;
    let user_domain = env::var("OS_USER_DOMAIN_NAME").unwrap_or_else(|_| String::from("Default"));

    let id = Password::new(&auth_url, user_name, password, user_domain)?;

    let project = utils::require_env("OS_PROJECT_ID")
        .map(IdOrName::Id)
        .or_else(|_| utils::require_env("OS_PROJECT_NAME").map(IdOrName::Name))?;

    let project_domain = utils::require_env("OS_PROJECT_DOMAIN_ID")
        .map(IdOrName::Id)
        .or_else(|_| utils::require_env("OS_PROJECT_DOMAIN_NAME").map(IdOrName::Name))
        .ok();

    let mut session = Session::new(id.with_project_scope(project, project_domain));
    let mut filters = EndpointFilters::default();

    if let Ok(interface) = env::var("OS_INTERFACE") {
        filters.set_interfaces(InterfaceType::from_str(&interface)?);
    }

    if let Ok(region) = env::var("OS_REGION_NAME") {
        filters.region = Some(region);
    }

    *session.endpoint_filters_mut() = filters;

    Ok(session)
}

/// Create a `Session` from environment variables.
pub fn from_env() -> Result<Session, Error> {
    if let Ok(cloud_name) = env::var("OS_CLOUD") {
        return from_config(cloud_name);
    }

    let user_name = utils::require_env("OS_USERNAME")?;
    let password = utils::require_env("OS_PASSWORD")?;
    let auth_type = env::var("OS_AUTH_TYPE").unwrap_or_else(|_| "password".to_string());

    match auth_type.as_str() {
        "password" => password_auth_from_env(user_name, password),
        "http_basic" => {
            let endpoint = utils::require_env("OS_ENDPOINT")?;
            let id = BasicAuth::new(&endpoint, user_name, password)?;
            Ok(Session::new(id))
        }
        _ => Err(Error::new(
            ErrorKind::InvalidInput,
            format!("Unsupported authentication type: {}", auth_type),
        )),
    }
}

#[cfg(test)]
pub mod test {
    use super::super::utils::test::to_yaml;
    use super::super::ErrorKind;
    use super::{find_config, from_files, inject_profiles, read_yaml, with_one_key};

    #[test]
    fn test_from_config() {
        let clouds = to_yaml(
            r#"clouds:
  cloud_name:
    auth:
      auth_url: http://url1
      username: user1
    profile: test_profile"#,
        );

        let clouds_public = to_yaml(
            r#"public-clouds:
  test_profile:
    region_name: region1"#,
        );

        let secure = to_yaml(
            r#"clouds:
  cloud_name:
    auth:
      password: password1"#,
        );

        let _ = from_files("cloud_name", clouds, clouds_public, secure).unwrap();
    }

    #[test]
    fn test_from_config_password() {
        let clouds = to_yaml(
            r#"clouds:
  cloud_name:
    auth_type: password
    auth:
      auth_url: http://url1
      username: user1
      password: password1
    region_name: region1"#,
        );

        let _ = from_files(
            "cloud_name",
            clouds,
            with_one_key("public-clouds"),
            with_one_key("clouds"),
        )
        .unwrap();
    }

    #[test]
    fn test_from_config_http_basic() {
        let clouds = to_yaml(
            r#"clouds:
  cloud_name:
    auth_type: http_basic
    auth:
      endpoint: http://url1
      username: user1
      password: password1"#,
        );

        let _ = from_files(
            "cloud_name",
            clouds,
            with_one_key("public-clouds"),
            with_one_key("clouds"),
        )
        .unwrap();
    }

    #[test]
    fn test_inject_profiles_error() {
        let mut clouds_data = to_yaml(
            r#"
clouds:
  cloud_name:
    auth:
      username: user1
      password: password1
    profile: test_profile"#,
        );

        let clouds_public_data = to_yaml(
            r#"
public-clouds:
  test_profile_other:
    auth:
        username: user2
        auth_url: url2
    region_name: region2"#,
        );

        let err = inject_profiles(&clouds_public_data, &mut clouds_data);
        assert_eq!(ErrorKind::InvalidConfig, err.as_ref().unwrap_err().kind());
        assert_eq!("configuration file cannot be found or is invalid: Missing profile test_profile in clouds-public.yaml", format!("{}", err.unwrap_err()));
    }

    #[test]
    fn test_inject_profiles_ok() {
        let mut clouds_data = to_yaml(
            r#"
clouds:
  cloud_name:
    auth:
      username: user1
      password: password1
    profile: test_profile"#,
        );

        let clouds_public_data = to_yaml(
            r#"
public-clouds:
  test_profile:
    auth:
        username: user2
        auth_url: url2
    region_name: region2"#,
        );

        inject_profiles(&clouds_public_data, &mut clouds_data).unwrap();

        assert_eq!(
            "region2",
            clouds_data
                .get(&"clouds".into())
                .unwrap()
                .as_mapping()
                .unwrap()
                .get(&"cloud_name".into())
                .unwrap()
                .as_mapping()
                .unwrap()
                .get(&"region_name".into())
                .unwrap()
        );

        assert_eq!(
            "user1",
            clouds_data
                .get(&"clouds".into())
                .unwrap()
                .as_mapping()
                .unwrap()
                .get(&"cloud_name".into())
                .unwrap()
                .as_mapping()
                .unwrap()
                .get(&"auth".into())
                .unwrap()
                .as_mapping()
                .unwrap()
                .get(&"username".into())
                .unwrap()
        );

        assert_eq!(
            "password1",
            clouds_data
                .get(&"clouds".into())
                .unwrap()
                .as_mapping()
                .unwrap()
                .get(&"cloud_name".into())
                .unwrap()
                .as_mapping()
                .unwrap()
                .get(&"auth".into())
                .unwrap()
                .as_mapping()
                .unwrap()
                .get(&"password".into())
                .unwrap()
        );

        assert_eq!(
            "url2",
            clouds_data
                .get(&"clouds".into())
                .unwrap()
                .as_mapping()
                .unwrap()
                .get(&"cloud_name".into())
                .unwrap()
                .as_mapping()
                .unwrap()
                .get(&"auth".into())
                .unwrap()
                .as_mapping()
                .unwrap()
                .get(&"auth_url".into())
                .unwrap()
        );
    }

    #[test]
    fn test_read_config_file_error() {
        let e = read_yaml("doesnt_exist", None).err().unwrap();
        assert_eq!("configuration file cannot be found or is invalid: doesnt_exist was not found in any location", e.to_string());
    }

    #[test]
    fn test_find_config_fail() {
        let config = find_config("shouldnt_exist");
        assert_eq!(config, None);
    }
}
