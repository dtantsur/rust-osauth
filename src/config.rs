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
use std::fs::read_to_string;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use dirs;
use log::warn;
use serde::Deserialize;
use serde_yaml;

use super::identity::{Password, Scope};
use super::{EndpointFilters, Error, ErrorKind, InterfaceType, Session};

use crate::identity::IdOrName;

#[derive(Debug, Deserialize)]
struct Auth {
    auth_url: String,
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

/// Merge two nested serde_yaml::Mapping structs
/// The values from src are merged into dest. Values in src override values in dest.
fn merge_mappings(src: &serde_yaml::Mapping, dest: &mut serde_yaml::Mapping) {
    for (src_key, src_value) in src.iter() {
        if let Some(src_mapping) = src_value.as_mapping() {
            if let Some(dest_value) = dest.get_mut(src_key) {
                match dest_value.as_mapping_mut() {
                    Some(dest_mapping) => {
                        merge_mappings(src_mapping, dest_mapping);
                        continue;
                    }
                    None => warn!("Type mismatch while merging mappings. Expected {:?} to be a Mapping. Overriding destination.", dest_value),
                }
            }
        }
        let _ = dest.insert(src_key.to_owned(), src_value.to_owned());
    }
}

// Inject profiles from clouds-public.yaml into clouds.yaml and return it in a new Value
fn inject_profiles(
    clouds_public: &serde_yaml::Mapping,
    clouds: &serde_yaml::Mapping,
) -> Result<serde_yaml::Value, Error> {
    let mut temp_mapping = serde_yaml::Mapping::new();

    if let (Some(clouds_value), Some(clouds_public_value)) = (
        clouds.get(&"clouds".into()),
        clouds_public.get(&"public-clouds".into()),
    ) {
        if let (Some(clouds_mapping), Some(clouds_public_mapping)) =
            (clouds_value.as_mapping(), clouds_public_value.as_mapping())
        {
            for (cloud_name, cloud) in clouds_mapping.iter() {
                if let Some(cloud_mapping) = cloud.as_mapping() {
                    if let Some(profile_value) = cloud_mapping.get(&"profile".into()) {
                        if let Some(profile_name) = profile_value.as_str() {
                            if let Some(profile) = clouds_public_mapping.get(profile_value) {
                                let mut clouds = serde_yaml::Mapping::new();
                                let _ = clouds.insert(cloud_name.to_owned(), profile.to_owned());

                                let _ = temp_mapping.insert("clouds".into(), clouds.into());
                            } else {
                                return Err(Error::new(
                                    ErrorKind::InvalidConfig,
                                    format!(
                                        "Missing profile {} in clouds-public.yaml.",
                                        profile_name
                                    ),
                                ));
                            }
                        }
                    }
                }
            }
        }
    }

    merge_mappings(clouds, &mut temp_mapping);
    Ok(serde_yaml::Value::Mapping(temp_mapping))
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

fn read_config_file(filename: &str) -> Result<String, Error> {
    let path = find_config(filename).ok_or_else(|| {
        Error::new(
            ErrorKind::InvalidConfig,
            format!("{} was not found in any location", filename),
        )
    })?;

    read_to_string(path).map_err(|e| {
        Error::new(
            ErrorKind::InvalidConfig,
            format!("Cannot read {}: {}", filename, e),
        )
    })
}

/// Create a `Session` from the config file.
pub fn from_config<S: AsRef<str>>(cloud_name: S) -> Result<Session, Error> {
    let mut clouds: serde_yaml::Value = serde_yaml::from_str(&read_config_file("clouds.yaml")?)
        .map_err(|e| {
            Error::new(
                ErrorKind::InvalidConfig,
                format!("Cannot parse clouds.yaml: {}", e),
            )
        })?;

    let clouds_public: serde_yaml::Value = serde_yaml::from_str(
        // If clouds-public.yaml is missing, let's pretend that it's there but empty.
        &read_config_file("clouds-public.yaml").unwrap_or_else(|_| String::from("---\n{}\n")),
    )
    .map_err(|e| {
        Error::new(
            ErrorKind::InvalidConfig,
            format!("Cannot parse clouds-public.yaml: {}", e),
        )
    })?;

    let secure: serde_yaml::Value = serde_yaml::from_str(
        // If secure.yaml is missing, let's pretend that it's there but empty.
        &read_config_file("secure.yaml").unwrap_or_else(|_| String::from("---\n{}\n")),
    )
    .map_err(|e| {
        Error::new(
            ErrorKind::InvalidConfig,
            format!("Cannot parse secure.yaml: {}", e),
        )
    })?;

    merge_mappings(
        secure.as_mapping().ok_or_else(|| {
            Error::new(
                ErrorKind::InvalidConfig,
                format!("secure.yaml's root is not a Mapping"),
            )
        })?,
        clouds.as_mapping_mut().ok_or_else(|| {
            Error::new(
                ErrorKind::InvalidConfig,
                format!("clouds.yaml's root is not a Mapping"),
            )
        })?,
    );

    clouds = inject_profiles(
        clouds_public.as_mapping().ok_or_else(|| {
            Error::new(
                ErrorKind::InvalidConfig,
                format!("clouds-public.yaml's root is not a Mapping"),
            )
        })?,
        clouds.as_mapping_mut().ok_or_else(|| {
            Error::new(
                ErrorKind::InvalidConfig,
                format!("clouds.yaml's root is not a Mapping"),
            )
        })?,
    )?;

    let mut clouds_root: Root = serde_yaml::from_value(clouds).map_err(|e| {
        Error::new(
            ErrorKind::InvalidConfig,
            format!("Cannot parse clouds.yaml: {}", e),
        )
    })?;

    let name = cloud_name.as_ref();
    let cloud =
        clouds_root.clouds.clouds.remove(name).ok_or_else(|| {
            Error::new(ErrorKind::InvalidConfig, format!("No such cloud: {}", name))
        })?;

    let auth = cloud.auth;
    let user_domain = auth
        .user_domain_name
        .unwrap_or_else(|| String::from("Default"));
    let project_domain = auth
        .project_domain_name
        .unwrap_or_else(|| String::from("Default"));
    let mut id = Password::new(&auth.auth_url, auth.username, auth.password, user_domain)?;
    if let Some(project_name) = auth.project_name {
        let scope = Scope::Project {
            project: IdOrName::Name(project_name),
            domain: Some(IdOrName::Name(project_domain)),
        };
        id.set_scope(scope);
    }
    if let Some(region) = cloud.region_name {
        id.endpoint_filters_mut().region = Some(region);
    }

    Ok(Session::new(id))
}

const MISSING_ENV_VARS: &str = "Not all required environment variables were provided";

#[inline]
fn _get_env(name: &str) -> Result<String, Error> {
    env::var(name).map_err(|_| Error::new(ErrorKind::InvalidInput, MISSING_ENV_VARS))
}

/// Create a `Session` from environment variables.
pub fn from_env() -> Result<Session, Error> {
    if let Ok(cloud_name) = env::var("OS_CLOUD") {
        from_config(cloud_name)
    } else {
        let auth_url = _get_env("OS_AUTH_URL")?;
        let user_name = _get_env("OS_USERNAME")?;
        let password = _get_env("OS_PASSWORD")?;
        let user_domain =
            env::var("OS_USER_DOMAIN_NAME").unwrap_or_else(|_| String::from("Default"));

        let id = Password::new(&auth_url, user_name, password, user_domain)?;

        let project = _get_env("OS_PROJECT_ID")
            .map(IdOrName::Id)
            .or_else(|_| _get_env("OS_PROJECT_NAME").map(IdOrName::Name))?;

        let project_domain = _get_env("OS_PROJECT_DOMAIN_ID")
            .map(IdOrName::Id)
            .or_else(|_| _get_env("OS_PROJECT_DOMAIN_NAME").map(IdOrName::Name))
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
}

#[cfg(test)]
pub mod test {
    use super::merge_mappings;
    use super::*;
    use env::set_current_dir;
    use std::fs::File;
    use std::io::Write;
    use tempfile::tempdir;

    #[test]
    fn test_from_config() {
        let dir = tempdir().unwrap();

        let clouds_file_path = dir.path().join("clouds.yaml");
        let mut clouds_file = File::create(&clouds_file_path).unwrap();
        write!(
            clouds_file,
            r#"clouds:
  cloud_name:
    auth:
      auth_url: http://url1
      username: user1
    profile: test_profile"#
        )
        .unwrap();

        let clouds_public_file_path = dir.path().join("clouds-public.yaml");
        let mut clouds_public_file = File::create(&clouds_public_file_path).unwrap();
        write!(
            clouds_public_file,
            r#"public-clouds:
  test_profile:
    region_name: region1"#
        )
        .unwrap();

        let secure_file_path = dir.path().join("secure.yaml");
        let mut secure_file = File::create(&secure_file_path).unwrap();
        write!(
            secure_file,
            r#"clouds:
  cloud_name:
    auth:
      password: password1"#
        )
        .unwrap();

        set_current_dir(&dir).unwrap();

        assert!(from_config("cloud_name").is_ok());

        drop(clouds_file);
        drop(clouds_public_file);
        drop(secure_file);

        dir.close().unwrap();
    }

    #[test]
    fn test_from_config_clouds_yaml_only() {
        let dir = tempdir().unwrap();

        let clouds_file_path = dir.path().join("clouds.yaml");
        let mut clouds_file = File::create(&clouds_file_path).unwrap();
        write!(
            clouds_file,
            r#"clouds:
  cloud_name:
    auth:
      auth_url: http://url1
      username: user1
      password: password1
    region_name: region1"#
        )
        .unwrap();

        set_current_dir(&dir).unwrap();

        assert!(from_config("cloud_name").is_ok());

        drop(clouds_file);
        dir.close().unwrap();
    }

    #[test]
    fn test_inject_profiles_error() {
        let clouds_data: serde_yaml::Value = serde_yaml::from_str(
            r#"
clouds:
  cloud_name:
    auth:
      username: user1
      password: password1
    profile: test_profile"#,
        )
        .unwrap();

        let clouds_public_data: serde_yaml::Value = serde_yaml::from_str(
            r#"
public-clouds:
  test_profile_other:
    auth:
        username: user2
        auth_url: url2
    region_name: region2"#,
        )
        .unwrap();

        let err = inject_profiles(
            clouds_public_data.as_mapping().unwrap(),
            clouds_data.as_mapping().unwrap(),
        );
        assert_eq!(ErrorKind::InvalidConfig, err.as_ref().unwrap_err().kind());
        assert_eq!("configuration file cannot be found or is invalid: Missing profile test_profile in clouds-public.yaml.", format!("{}", err.unwrap_err()));
    }

    #[test]
    fn test_inject_profiles_ok() {
        let clouds_data: serde_yaml::Value = serde_yaml::from_str(
            r#"
clouds:
  cloud_name:
    auth:
      username: user1
      password: password1
    profile: test_profile"#,
        )
        .unwrap();

        let clouds_public_data: serde_yaml::Value = serde_yaml::from_str(
            r#"
public-clouds:
  test_profile:
    auth:
        username: user2
        auth_url: url2
    region_name: region2"#,
        )
        .unwrap();

        let actual = inject_profiles(
            clouds_public_data.as_mapping().unwrap(),
            clouds_data.as_mapping().unwrap(),
        )
        .unwrap();

        assert_eq!(
            "region2",
            actual
                .as_mapping()
                .unwrap()
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
            actual
                .as_mapping()
                .unwrap()
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
            actual
                .as_mapping()
                .unwrap()
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
            actual
                .as_mapping()
                .unwrap()
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
        let result = read_config_file("doesnt_exist");

        match result {
            Err(e) => { assert_eq!("configuration file cannot be found or is invalid: doesnt_exist was not found in any location", e.to_string())
            }
            Ok(_) => { panic!("Result was unexpectedly Ok") }
        }
    }

    #[test]
    fn test_read_config_file_success() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("test_read_config_file_success");
        let mut file = File::create(&file_path).unwrap();
        write!(file, "test data").unwrap();

        set_current_dir(&dir).unwrap();

        let actual = read_config_file("test_read_config_file_success").unwrap();

        assert_eq!("test data", actual);

        drop(file);
        dir.close().unwrap();
    }

    #[test]
    fn test_find_config_success() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("test_find_config_success");
        let file = File::create(&file_path).unwrap();

        set_current_dir(&dir).unwrap();

        let found = find_config("test_find_config_success").unwrap();

        assert_eq!(file_path, found);

        drop(file);
        dir.close().unwrap();
    }

    #[test]
    fn test_find_config_fail() {
        let found = find_config("shouldnt_exist");
        assert!(found.is_none());
    }

    #[test]
    fn test_merge_clouds() {
        let src_clouds_data = r#"
clouds:
  cloud_name:
    auth:
      username: user2
      password: password1
    region_name: region2"#;

        let dest_clouds_data = r#"
clouds:
  cloud_name:
    auth:
      username: user1
      project_name: project1
      user_domain_name: domain1
      project_domain_name: domain1
      auth_url: "url1"
    region_name: region1"#;

        let src: serde_yaml::Value = serde_yaml::from_str(src_clouds_data).unwrap();
        let mut dest: serde_yaml::Value = serde_yaml::from_str(dest_clouds_data).unwrap();
        merge_mappings(&src.as_mapping().unwrap(), dest.as_mapping_mut().unwrap());

        let dest_cloud = dest
            .get("clouds")
            .unwrap()
            .as_mapping()
            .unwrap()
            .get(&"cloud_name".into())
            .unwrap()
            .to_owned();

        assert_eq!(
            &serde_yaml::Value::String("region2".into()),
            dest_cloud.get("region_name").unwrap()
        );

        let dest_auth = dest_cloud
            .get("auth")
            .unwrap()
            .as_mapping()
            .unwrap()
            .to_owned();

        assert_eq!(
            "user2",
            dest_auth.get(&"username".into()).unwrap().as_str().unwrap()
        );

        assert_eq!(
            "password1",
            dest_auth.get(&"password".into()).unwrap().as_str().unwrap()
        );

        assert_eq!(
            "project1",
            dest_auth
                .get(&"project_name".into())
                .unwrap()
                .as_str()
                .unwrap()
        );

        assert_eq!(
            "domain1",
            dest_auth
                .get(&"project_domain_name".into())
                .unwrap()
                .as_str()
                .unwrap()
        );

        assert_eq!(
            "domain1",
            dest_auth
                .get(&"user_domain_name".into())
                .unwrap()
                .as_str()
                .unwrap()
        );

        assert_eq!(
            "url1",
            dest_auth.get(&"auth_url".into()).unwrap().as_str().unwrap()
        );
    }

    #[test]
    fn test_merge_type_mismatch() {
        let src_data = r#"
map1:
  map2:
    auth:
      password: password1"#;

        let dest_data = r#"
map1:
  map2: 123"#;

        let src: serde_yaml::Value = serde_yaml::from_str(src_data).unwrap();
        let mut dest: serde_yaml::Value = serde_yaml::from_str(dest_data).unwrap();

        merge_mappings(&src.as_mapping().unwrap(), dest.as_mapping_mut().unwrap());

        assert_eq!(src, dest);
    }
}
