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

//! Internal utilities

use std::env;

use log::warn;

use super::{Error, ErrorKind};

const MISSING_ENV_VARS: &str = "Not all required environment variables were provided";

/// Get a required environment variable.
#[inline]
pub fn require_env(name: &str) -> Result<String, Error> {
    env::var(name).map_err(|_| Error::new(ErrorKind::InvalidInput, MISSING_ENV_VARS))
}

/// Merge two nested serde_yaml::Mapping structs.
///
/// The values from src are merged into dest. Values in src override values in dest.
pub fn merge_mappings(src: serde_yaml::Mapping, dest: &mut serde_yaml::Mapping, overwrite: bool) {
    for (src_key, src_value) in src.into_iter() {
        match src_value {
            serde_yaml::Value::Mapping(src_mapping) => {
                if let Some(dest_value) = dest.get_mut(&src_key) {
                    match dest_value.as_mapping_mut() {
                        Some(dest_mapping) => {
                            merge_mappings(src_mapping, dest_mapping, overwrite);
                            continue;
                        }
                        None => {
                            warn!(
                                "Type mismatch while merging mappings. Expected {:?} to be a Mapping. Overriding destination.",
                                dest_value
                            );
                            let _ = dest.insert(src_key, serde_yaml::Value::Mapping(src_mapping));
                        }
                    }
                }
            }
            other => {
                if overwrite || !dest.contains_key(&src_key) {
                    let _ = dest.insert(src_key, other);
                }
            }
        }
    }
}

#[cfg(test)]
pub mod test {
    use super::merge_mappings;

    pub(crate) fn to_yaml<S: AsRef<str>>(source: S) -> serde_yaml::Mapping {
        let value = serde_yaml::from_str(source.as_ref()).unwrap();
        match value {
            serde_yaml::Value::Mapping(map) => map,
            _ => panic!("Unexpected {:?}", value),
        }
    }

    #[test]
    fn test_merge_clouds() {
        let src = to_yaml(
            r#"
clouds:
  cloud_name:
    auth:
      username: user2
      password: password1
    region_name: region2"#,
        );

        let mut dest = to_yaml(
            r#"
clouds:
  cloud_name:
    auth:
      username: user1
      project_name: project1
      user_domain_name: domain1
      project_domain_name: domain1
      auth_url: "url1"
    region_name: region1"#,
        );

        merge_mappings(src, &mut dest, true);

        let dest_cloud = dest
            .get(&"clouds".into())
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
        let src = to_yaml(
            r#"
map1:
  map2:
    auth:
      password: password1"#,
        );

        let mut dest = to_yaml(
            r#"
map1:
  map2: 123"#,
        );

        merge_mappings(src.clone(), &mut dest, true);

        assert_eq!(src, dest);
    }
}
