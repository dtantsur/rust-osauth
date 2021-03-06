// Copyright 2018 Dmitry Tantsur <dtantsur@protonmail.com>
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

//! ApiVersion implementation.

use std::fmt;
use std::str::FromStr;

use reqwest::header::HeaderValue;
use serde::de::{Error as DeserError, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::{Error, ErrorKind};

/// API version (major, minor).
#[derive(Copy, Clone, Debug, PartialEq, PartialOrd, Eq, Ord, Hash)]
pub struct ApiVersion(pub u16, pub u16);

impl fmt::Display for ApiVersion {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}.{}", self.0, self.1)
    }
}

fn parse_component(component: &str, message: &str) -> Result<u16, Error> {
    component
        .parse()
        .map_err(|_| Error::new(ErrorKind::InvalidResponse, message))
}

impl From<ApiVersion> for HeaderValue {
    fn from(value: ApiVersion) -> HeaderValue {
        value.to_string().parse().unwrap()
    }
}

impl FromStr for ApiVersion {
    type Err = Error;

    fn from_str(s: &str) -> Result<ApiVersion, Error> {
        let version_part = s.strip_prefix('v').unwrap_or(s);
        let parts: Vec<&str> = version_part.split('.').collect();

        if parts.is_empty() || parts.len() > 2 {
            let msg = format!("Invalid API version: expected X.Y or X, got {}", s);
            return Err(Error::new(ErrorKind::InvalidResponse, msg));
        }

        let major = parse_component(parts[0], "First version component is not a number")?;

        let minor = if parts.len() == 2 {
            parse_component(parts[1], "Second version component is not a number")?
        } else {
            0
        };

        Ok(ApiVersion(major, minor))
    }
}

impl Serialize for ApiVersion {
    fn serialize<S>(&self, serializer: S) -> ::std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

struct ApiVersionVisitor;

impl<'de> Visitor<'de> for ApiVersionVisitor {
    type Value = ApiVersion;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a string in format X.Y or X")
    }

    fn visit_str<E>(self, value: &str) -> ::std::result::Result<ApiVersion, E>
    where
        E: DeserError,
    {
        ApiVersion::from_str(value).map_err(DeserError::custom)
    }
}

impl<'de> Deserialize<'de> for ApiVersion {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<ApiVersion, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(ApiVersionVisitor)
    }
}

#[cfg(test)]
pub mod test {
    use std::str::FromStr;

    use serde::Deserialize;
    use serde_json;

    use super::ApiVersion;

    #[test]
    fn test_apiversion_display() {
        let xy = ApiVersion(1, 2);
        let s = format!("{}", xy);
        assert_eq!(s, "1.2");
    }

    #[test]
    fn test_apiversion_from_str() {
        assert_eq!(ApiVersion::from_str("v2.27").unwrap(), ApiVersion(2, 27));
        assert_eq!(ApiVersion::from_str("2.27").unwrap(), ApiVersion(2, 27));
        assert_eq!(ApiVersion::from_str("2").unwrap(), ApiVersion(2, 0));
    }

    #[test]
    fn test_apiversion_from_str_failure() {
        for s in &["foo", "1.foo", "foo.2", "1.2.3"] {
            let res: Result<ApiVersion, _> = ApiVersion::from_str(s);
            assert!(res.is_err());
        }
    }

    #[test]
    fn test_apiversion_serde_serialize() {
        let xy = ApiVersion(2, 27);
        let ser = serde_json::to_string(&xy).unwrap();
        assert_eq!(&ser, "\"2.27\"");
    }

    #[derive(Debug, Deserialize)]
    struct Struct {
        pub req: ApiVersion,
        pub opt: Option<ApiVersion>,
    }

    #[test]
    fn test_apiversion_serde_deserialize() {
        let xy: ApiVersion = serde_json::from_str("\"2.27\"").unwrap();
        assert_eq!(xy, ApiVersion(2, 27));
        let xy2: ApiVersion =
            serde_json::from_value(serde_json::Value::String("2.27".to_string())).unwrap();
        assert_eq!(xy2, ApiVersion(2, 27));
        let st: Struct = serde_json::from_str("{\"req\": \"2.27\", \"opt\": \"2.42\"}").unwrap();
        assert_eq!(st.req, ApiVersion(2, 27));
        assert_eq!(st.opt.unwrap(), ApiVersion(2, 42));
    }

    #[test]
    fn test_apiversion_serde_deserialize_with_v() {
        let xy: ApiVersion = serde_json::from_str("\"v2.27\"").unwrap();
        assert_eq!(xy, ApiVersion(2, 27));
        let xy2: ApiVersion =
            serde_json::from_value(serde_json::Value::String("v2.27".to_string())).unwrap();
        assert_eq!(xy2, ApiVersion(2, 27));
        let st: Struct = serde_json::from_str("{\"req\": \"v2.27\", \"opt\": \"v2.42\"}").unwrap();
        assert_eq!(st.req, ApiVersion(2, 27));
        assert_eq!(st.opt.unwrap(), ApiVersion(2, 42));
    }
}
