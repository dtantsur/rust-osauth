// Copyright 2019 Dmitry Tantsur <dtantsur@protonmail.com>
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

//! Reusable JSON structures and protocol bits.

use std::cmp::Ordering;

use reqwest::Url;
use serde::de::{DeserializeOwned, Error as DeserError};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;

use crate::ApiVersion;

/// A link to a resource.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, Hash)]
pub struct Link {
    /// Resource URL.
    pub href: Url,
    /// Relationship between the referencing and the referenced object.
    pub rel: String,
}

/// A reference to a subresource or an external resource.
///
/// Objects of this kind are usually seen in root resources and rarely occur in other contexts.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Ref {
    /// Identity of the references resource.
    pub id: String,
    /// A set of links to the resource.
    pub links: Vec<Link>,
}

/// A reference to an ID and name.
///
/// Objects of this kind are often returned by various listing APIs when invoked without
/// requesting details.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct IdAndName {
    /// Resource ID.
    pub id: String,
    /// Resource name.
    pub name: String,
}

/// A reference to a resource by either its ID or name.
#[derive(Clone, Debug, Serialize, PartialEq, Eq, Hash)]
pub enum IdOrName {
    /// Resource ID.
    #[serde(rename = "id")]
    Id(String),
    /// Resource name.
    #[serde(rename = "name")]
    Name(String),
}

/// Status of a major version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VersionStatus {
    /// The current version.
    Current,
    /// Supported version (that is not current).
    Supported,
    /// Deprecated version.
    Deprecated,
    /// Unknown version status.
    Unknown,
}

impl Default for VersionStatus {
    fn default() -> VersionStatus {
        VersionStatus::Unknown
    }
}

impl VersionStatus {
    /// If the version is considered stable.
    ///
    /// We assume that unknown statuses are also stable.
    #[inline]
    pub fn is_stable(&self) -> bool {
        !matches!(self, VersionStatus::Deprecated)
    }
}

impl<T> From<T> for VersionStatus
where
    T: Into<String>,
{
    fn from(value: T) -> VersionStatus {
        match value.into().to_uppercase().as_ref() {
            "CURRENT" => VersionStatus::Current,
            "SUPPORTED" | "STABLE" => VersionStatus::Supported,
            "DEPRECATED" => VersionStatus::Deprecated,
            _ => VersionStatus::Unknown,
        }
    }
}

impl<'de> Deserialize<'de> for VersionStatus {
    fn deserialize<D>(deserializer: D) -> Result<VersionStatus, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value: String = Deserialize::deserialize(deserializer)?;
        Ok(value.into())
    }
}

/// A single API version as returned by a version discovery endpoint.
#[derive(Clone, Debug, Deserialize)]
pub struct Version {
    /// Major version ID.
    ///
    /// This is usually a major version, but some API endpoints use two components here.
    pub id: ApiVersion,
    /// Links to subresources of this API version.
    #[serde(default)]
    pub links: Vec<Link>,
    /// Version status.
    #[serde(deserialize_with = "empty_as_default", default)]
    pub status: VersionStatus,
    /// Current API version (also known as microversion).
    #[serde(deserialize_with = "empty_as_default", default)]
    pub version: Option<ApiVersion>,
    /// Minimal supported API version (also known as microversion).
    #[serde(deserialize_with = "empty_as_default", default)]
    pub min_version: Option<ApiVersion>,
}

impl Version {
    /// Whether a version is considered stable according to its status.
    #[inline]
    pub fn is_stable(&self) -> bool {
        self.status.is_stable()
    }
}

impl PartialEq for Version {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for Version {}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> Ordering {
        self.id.cmp(&other.id)
    }
}

/// Deserialize a value where empty string is replaced by `Default` value.
pub fn empty_as_default<'de, D, T>(des: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: DeserializeOwned + Default,
{
    let value = Value::deserialize(des)?;
    match value {
        Value::String(ref s) if s.is_empty() => Ok(T::default()),
        _ => serde_json::from_value(value).map_err(D::Error::custom),
    }
}

#[cfg(test)]
pub mod test {
    use serde::{Deserialize, Serialize};
    use serde_json;

    use super::{empty_as_default, Version, VersionStatus};
    use crate::ApiVersion;

    pub fn compare<T: Serialize>(sample: &str, value: T) {
        let converted: serde_json::Value = serde_json::from_str(sample).unwrap();
        let result = serde_json::to_value(value).unwrap();
        assert_eq!(result, converted);
    }

    #[derive(Debug, Deserialize)]
    struct Custom(bool);

    #[derive(Debug, Deserialize)]
    struct EmptyAsDefault {
        #[serde(deserialize_with = "empty_as_default")]
        number: u8,
        #[serde(deserialize_with = "empty_as_default")]
        vec: Vec<String>,
        #[serde(deserialize_with = "empty_as_default")]
        opt: Option<Custom>,
        #[serde(deserialize_with = "empty_as_default")]
        string: Option<String>,
    }

    #[test]
    fn test_empty_as_default_with_values() {
        let s = "{\"number\": 42, \"vec\": [\"value\"], \"opt\": true, \"string\": \"value\"}";
        let r: EmptyAsDefault = serde_json::from_str(s).unwrap();
        assert_eq!(r.number, 42);
        assert_eq!(r.vec, vec!["value".to_string()]);
        assert!(r.opt.unwrap().0);
        assert_eq!(r.string.unwrap(), "value");
    }

    #[test]
    fn test_empty_as_default_with_empty_string() {
        let s = "{\"number\": \"\", \"vec\": \"\", \"opt\": \"\", \"string\": \"\"}";
        let r: EmptyAsDefault = serde_json::from_str(s).unwrap();
        assert_eq!(r.number, 0);
        assert!(r.vec.is_empty());
        assert!(r.opt.is_none());
        assert!(r.string.is_none());
    }

    #[test]
    fn test_version_current_is_stable() {
        let stable = Version {
            id: ApiVersion(2, 0),
            links: Vec::new(),
            status: VersionStatus::Current,
            version: None,
            min_version: None,
        };
        assert!(stable.is_stable());
    }

    #[test]
    fn test_version_supported_is_stable() {
        let stable = Version {
            id: ApiVersion(2, 0),
            links: Vec::new(),
            status: VersionStatus::Supported,
            version: None,
            min_version: None,
        };
        assert!(stable.is_stable());
    }

    #[test]
    fn test_version_no_status_is_stable() {
        let stable = Version {
            id: ApiVersion(2, 0),
            links: Vec::new(),
            status: VersionStatus::Unknown,
            version: None,
            min_version: None,
        };
        assert!(stable.is_stable());
    }

    #[test]
    fn test_version_deprecated_is_not_stable() {
        let unstable = Version {
            id: ApiVersion(2, 0),
            links: Vec::new(),
            status: VersionStatus::Deprecated,
            version: None,
            min_version: None,
        };
        assert!(!unstable.is_stable());
    }

    const COMPUTE_ONE: &str = r#"{
    "status": "CURRENT",
    "updated": "2013-07-23T11:33:21Z",
    "links": [
      {
        "href": "https://example.org:13774/v2.1/",
        "rel": "self"
      },
      {
        "href": "http://docs.openstack.org/",
        "type": "text/html",
        "rel": "describedby"
      }
    ],
    "min_version": "2.1",
    "version": "2.42",
    "media-types": [
      {
        "base": "application/json",
        "type": "application/vnd.openstack.compute+json;version=2.1"
      }
    ],
    "id": "v2.1"
}"#;

    #[test]
    fn test_version_parse() {
        let version: Version = serde_json::from_str(COMPUTE_ONE).unwrap();
        assert_eq!(version.id, ApiVersion(2, 1));
    }

    #[test]
    fn test_version_status_from_string() {
        assert_eq!(VersionStatus::from("SUPPORTED"), VersionStatus::Supported);
        assert_eq!(VersionStatus::from("Stable"), VersionStatus::Supported);
        assert_eq!(VersionStatus::from("CURRENT"), VersionStatus::Current);
        assert_eq!(VersionStatus::from("deprecated"), VersionStatus::Deprecated);
        assert_eq!(VersionStatus::from("banana!"), VersionStatus::Unknown);
    }

    #[test]
    fn test_version_status_parse() {
        assert_eq!(
            serde_json::from_str::<VersionStatus>("\"SUPPORTED\"").unwrap(),
            VersionStatus::Supported
        );
    }
}
