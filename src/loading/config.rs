// Copyright 2018-2021 Dmitry Tantsur <dtantsur@protonmail.com>
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
use std::fs::File;
use std::path::{Path, PathBuf};

use log::warn;
use serde::Deserialize;

use crate::loading::cloud::CloudConfig;
use crate::utils;
use crate::{Error, ErrorKind};

#[derive(Debug, Deserialize)]
struct Clouds {
    #[serde(flatten)]
    clouds: HashMap<String, CloudConfig>,
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
    let clouds_mapping = match clouds.get_mut("clouds").ok_or_else(|| {
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

    let clouds_public_mapping = match clouds_public.get("public-clouds").ok_or_else(|| {
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
            if let Some(profile_value) = cloud_mapping.get("profile") {
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

fn from_files(
    name: &str,
    mut clouds: serde_yaml::Mapping,
    clouds_public: serde_yaml::Mapping,
    secure: serde_yaml::Mapping,
) -> Result<CloudConfig, Error> {
    utils::merge_mappings(secure, &mut clouds, true);

    inject_profiles(&clouds_public, &mut clouds)?;

    let mut clouds_root: Root = serde_yaml::from_value(serde_yaml::Value::Mapping(clouds))
        .map_err(|e| {
            Error::new(
                ErrorKind::InvalidConfig,
                format!("Cannot parse the merged cloud configuration: {}", e),
            )
        })?;

    clouds_root
        .clouds
        .clouds
        .remove(name)
        .ok_or_else(|| Error::new(ErrorKind::InvalidConfig, format!("No such cloud: {}", name)))
}

/// Create a `Session` from a `clouds.yaml` configuration file.
pub fn from_config(cloud_name: &str) -> Result<CloudConfig, Error> {
    let clouds = read_yaml("clouds.yaml", None)?;
    let clouds_public = read_yaml("clouds-public.yaml", Some("public-clouds"))?;
    let secure = read_yaml("secure.yaml", Some("clouds"))?;

    from_files(cloud_name, clouds, clouds_public, secure)
}

#[cfg(test)]
pub mod test {
    use super::{find_config, from_files, inject_profiles, read_yaml, with_one_key};
    use crate::utils::test::to_yaml;
    use crate::ErrorKind;

    #[cfg(any(feature = "native-tls", feature = "rustls"))]
    use std::io::Write;

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

        let _ = from_files("cloud_name", clouds, clouds_public, secure)
            .unwrap()
            .create_session_config()
            .unwrap();
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
        .unwrap()
        .create_session_config()
        .unwrap();
    }

    #[test]
    fn test_from_config_none_without_endpoint() {
        let clouds = to_yaml(
            r#"clouds:
  cloud_name:
    auth_type: none
    auth: {}"#,
        );

        let _ = from_files(
            "cloud_name",
            clouds,
            with_one_key("public-clouds"),
            with_one_key("clouds"),
        )
        .unwrap()
        .create_session_config()
        .unwrap();
    }

    #[test]
    fn test_from_config_none_without_auth() {
        let clouds = to_yaml(
            r#"clouds:
  cloud_name:
    auth_type: none"#,
        );

        let _ = from_files(
            "cloud_name",
            clouds,
            with_one_key("public-clouds"),
            with_one_key("clouds"),
        )
        .unwrap()
        .create_session_config()
        .unwrap();
    }

    #[test]
    fn test_from_config_none_with_overrides() {
        let clouds = to_yaml(
            r#"clouds:
  cloud_name:
    auth_type: none
    baremetal_endpoint_override: http://baremetal/v1
    baremetal_introspection_endpoint_override: http://introspection/"#,
        );

        let sess = from_files(
            "cloud_name",
            clouds,
            with_one_key("public-clouds"),
            with_one_key("clouds"),
        )
        .unwrap()
        .create_session_config()
        .unwrap();
        assert_eq!(
            "http://baremetal/v1",
            sess.endpoint_overrides.get("baremetal").unwrap().as_str()
        );
        assert_eq!(
            "http://introspection/",
            sess.endpoint_overrides
                .get("baremetal-introspection")
                .unwrap()
                .as_str()
        );
    }

    #[test]
    #[cfg(any(feature = "native-tls", feature = "rustls"))]
    fn test_from_config_cacert() {
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

        let clouds = to_yaml(format!(
            r#"clouds:
  cloud_name:
    auth_type: http_basic
    auth:
      endpoint: http://url1
      username: user1
      password: password1
    cacert: "{}""#,
            cacert.path().display()
        ));

        let _ = from_files(
            "cloud_name",
            clouds,
            with_one_key("public-clouds"),
            with_one_key("clouds"),
        )
        .unwrap()
        .create_session_config()
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
                .get("clouds")
                .unwrap()
                .as_mapping()
                .unwrap()
                .get("cloud_name")
                .unwrap()
                .as_mapping()
                .unwrap()
                .get("region_name")
                .unwrap()
                .as_str()
                .unwrap()
        );

        assert_eq!(
            "user1",
            clouds_data
                .get("clouds")
                .unwrap()
                .as_mapping()
                .unwrap()
                .get("cloud_name")
                .unwrap()
                .as_mapping()
                .unwrap()
                .get("auth")
                .unwrap()
                .as_mapping()
                .unwrap()
                .get("username")
                .unwrap()
                .as_str()
                .unwrap()
        );

        assert_eq!(
            "password1",
            clouds_data
                .get("clouds")
                .unwrap()
                .as_mapping()
                .unwrap()
                .get("cloud_name")
                .unwrap()
                .as_mapping()
                .unwrap()
                .get("auth")
                .unwrap()
                .as_mapping()
                .unwrap()
                .get("password")
                .unwrap()
                .as_str()
                .unwrap()
        );

        assert_eq!(
            "url2",
            clouds_data
                .get("clouds")
                .unwrap()
                .as_mapping()
                .unwrap()
                .get("cloud_name")
                .unwrap()
                .as_mapping()
                .unwrap()
                .get("auth")
                .unwrap()
                .as_mapping()
                .unwrap()
                .get("auth_url")
                .unwrap()
                .as_str()
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
