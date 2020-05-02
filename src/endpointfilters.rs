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

//! Endpoint filters for looking up endpoints.

use std::fmt;
use std::iter::FromIterator;
use std::ops::Deref;
use std::str::FromStr;

use log::{debug, error};
use osproto::identity::{CatalogRecord, Endpoint};
use reqwest::Url;

use super::{Error, ErrorKind};

/// Interface type: public, internal or admin.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InterfaceType {
    /// Public interface (used by default).
    Public,
    /// Internal interface.
    Internal,
    /// Administrator interface.
    Admin,
}

/// A list of acceptable interface types.
#[derive(Debug, Clone, Copy, Eq, Hash)]
pub struct ValidInterfaces {
    items: [InterfaceType; 3],
    len: u8,
}

/// Endpoint filters for looking up endpoints.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct EndpointFilters {
    /// Acceptable endpoint interfaces in the reverse priority order.
    pub interfaces: ValidInterfaces,
    /// Cloud region.
    pub region: Option<String>,
}

impl Default for InterfaceType {
    fn default() -> Self {
        InterfaceType::Public
    }
}

impl fmt::Display for InterfaceType {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        f.write_str(match self {
            InterfaceType::Public => "public",
            InterfaceType::Internal => "internal",
            InterfaceType::Admin => "admin",
        })
    }
}

impl<T> PartialEq<T> for InterfaceType
where
    T: AsRef<str>,
{
    fn eq(&self, other: &T) -> bool {
        if let Ok(converted) = InterfaceType::from_str(other.as_ref()) {
            *self == converted
        } else {
            false
        }
    }
}

impl AsRef<[InterfaceType]> for ValidInterfaces {
    fn as_ref(&self) -> &[InterfaceType] {
        self
    }
}

impl Default for ValidInterfaces {
    /// Defaults to "public".
    fn default() -> ValidInterfaces {
        ValidInterfaces {
            items: [InterfaceType::Public; 3],
            len: 1,
        }
    }
}

impl Deref for ValidInterfaces {
    type Target = [InterfaceType];

    fn deref(&self) -> &Self::Target {
        &self.items[..self.len as usize]
    }
}

impl From<InterfaceType> for ValidInterfaces {
    fn from(value: InterfaceType) -> ValidInterfaces {
        ValidInterfaces::one(value)
    }
}

impl From<Vec<InterfaceType>> for ValidInterfaces {
    fn from(value: Vec<InterfaceType>) -> ValidInterfaces {
        Self::from_iter(value)
    }
}

impl From<&[InterfaceType]> for ValidInterfaces {
    fn from(value: &[InterfaceType]) -> ValidInterfaces {
        let mut result = ValidInterfaces::empty();
        // NOTE(dtantsur): there are exactly 3 possible interface types, so overflow is impossible.
        for item in value.iter() {
            let _ = result.push(*item);
        }
        result
    }
}

impl FromIterator<InterfaceType> for ValidInterfaces {
    /// Create from an iterator of interface types.
    ///
    /// Any duplicates are ignored.
    fn from_iter<T: IntoIterator<Item = InterfaceType>>(iter: T) -> Self {
        let mut result = ValidInterfaces::empty();
        for item in iter {
            let _ = result.push(item);
        }
        result
    }
}

impl<'s> FromIterator<&'s InterfaceType> for ValidInterfaces {
    /// Create from an iterator of interface types.
    ///
    /// Any duplicates are ignored.
    fn from_iter<T: IntoIterator<Item = &'s InterfaceType>>(iter: T) -> Self {
        let mut result = ValidInterfaces::empty();
        for item in iter {
            let _ = result.push(*item);
        }
        result
    }
}

impl PartialEq for ValidInterfaces {
    fn eq(&self, other: &ValidInterfaces) -> bool {
        self.len == other.len && self.items[..self.len as usize] == other.items[..self.len as usize]
    }
}

impl ValidInterfaces {
    /// Append all items from another collection.
    ///
    /// Any duplicates are ignored.
    #[inline]
    pub fn append(&mut self, other: &ValidInterfaces) {
        self.items = other.items;
        self.len = other.len;
    }

    /// Whether the interfaces match the provided endpoint.
    pub fn check(&self, endpoint: &Endpoint) -> bool {
        self.find(&endpoint.interface).is_some()
    }

    /// One valid interface.
    #[inline]
    pub fn one(item: InterfaceType) -> ValidInterfaces {
        ValidInterfaces {
            items: [item; 3],
            len: 1,
        }
    }

    /// Add an item to the end.
    ///
    /// Returns `true` if the item was added and `false` on duplicate.
    #[inline]
    pub fn push(&mut self, item: InterfaceType) -> bool {
        // NOTE(dtantsur): there are exactly 3 possible interface types, so overflow is impossible.
        if !self.contains(&item) {
            self.items[self.len as usize] = item;
            self.len += 1;
            true
        } else {
            false
        }
    }

    #[inline]
    fn empty() -> ValidInterfaces {
        ValidInterfaces {
            items: [InterfaceType::Public; 3],
            len: 0,
        }
    }

    #[inline]
    fn find(&self, interface: &str) -> Option<usize> {
        self.iter().position(|x| x == &interface)
    }
}

impl FromStr for InterfaceType {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "public" | "publicURL" => Ok(InterfaceType::Public),
            "internal" | "internalURL" => Ok(InterfaceType::Internal),
            "admin" | "adminURL" => Ok(InterfaceType::Admin),
            other => Err(Error::new(
                ErrorKind::InvalidInput,
                format!("Unknown interface type: {}", other),
            )),
        }
    }
}

impl EndpointFilters {
    /// Create filters with interfaces and region.
    ///
    /// Hint: use `default` to create empty filters (and `with_*` methods to populate it).
    pub fn new<I, S>(interfaces: I, region: S) -> EndpointFilters
    where
        I: IntoIterator<Item = InterfaceType>,
        S: Into<String>,
    {
        EndpointFilters {
            interfaces: interfaces.into_iter().collect(),
            region: Some(region.into()),
        }
    }

    /// Whether the filters match the provided endpoint.
    pub fn check(&self, endpoint: &Endpoint) -> bool {
        if !self.interfaces.check(endpoint) {
            return false;
        }

        if let Some(ref region) = self.region {
            endpoint.region == *region
        } else {
            true
        }
    }

    /// Extract a URL from the service catalog.
    pub fn find_in_catalog(
        &self,
        catalog: &[CatalogRecord],
        service_type: &str,
    ) -> Result<Url, Error> {
        let endp = self.find_endpoint(catalog, service_type)?;
        debug!("Received {:?} for {}", endp, service_type);
        Url::parse(&endp.url).map_err(|e| {
            error!(
                "Invalid URL {} received from service catalog for service \
                 '{}', filters {:?}: {}",
                endp.url, service_type, self, e
            );
            Error::new(
                ErrorKind::InvalidResponse,
                format!("Invalid URL {} for {} - {}", endp.url, service_type, e),
            )
        })
    }

    /// Set one or more valid interfaces.
    ///
    /// Hint: because of the generic argument can be used with one `InterfaceType` as well.
    #[inline]
    pub fn set_interfaces<T: Into<ValidInterfaces>>(&mut self, value: T) {
        self.interfaces = value.into();
    }

    /// Set region.
    #[inline]
    pub fn set_region<T: Into<String>>(&mut self, value: T) {
        self.region = Some(value.into());
    }

    /// Add one or more valid interfaces.
    ///
    /// Hint: because of the generic argument can be used with one `InterfaceType` as well.
    #[inline]
    pub fn with_interfaces<T: Into<ValidInterfaces>>(mut self, value: T) -> Self {
        self.set_interfaces(value);
        self
    }

    /// Add a region.
    #[inline]
    pub fn with_region<T: Into<String>>(mut self, value: T) -> Self {
        self.set_region(value);
        self
    }

    /// Find an endpoint in the service catalog.
    pub(crate) fn find_endpoint<'c>(
        &self,
        catalog: &'c [CatalogRecord],
        service_type: &str,
    ) -> Result<&'c Endpoint, Error> {
        let svc = match catalog.iter().find(|x| x.service_type == *service_type) {
            Some(s) => s,
            None => return Err(Error::new_endpoint_not_found(service_type)),
        };

        let mut endpoints: Vec<_> = svc.endpoints.iter().filter(|x| self.check(x)).collect();
        endpoints
            // NOTE(dtantsur): because of the filter above unwrap never fails
            .sort_unstable_by_key(|x| self.interfaces.find(&x.interface).unwrap());
        endpoints
            .into_iter()
            .next()
            .ok_or_else(|| Error::new_endpoint_not_found(service_type))
    }

    /// Clone defaults from the provided filters.
    pub(crate) fn with_defaults(mut self, other: &EndpointFilters) -> EndpointFilters {
        if self.interfaces.is_empty() {
            self.interfaces = other.interfaces.clone();
        }
        self.region = self.region.or_else(|| other.region.clone());
        self
    }
}

#[cfg(test)]
pub mod test {
    use osproto::identity::{CatalogRecord, Endpoint};

    use super::super::{Error, ErrorKind};

    use super::{EndpointFilters, InterfaceType, ValidInterfaces};
    use InterfaceType::*;

    fn demo_service1() -> CatalogRecord {
        CatalogRecord {
            service_type: String::from("identity"),
            endpoints: vec![
                Endpoint {
                    interface: String::from("public"),
                    region: String::from("RegionOne"),
                    url: String::from("https://host.one/identity"),
                },
                Endpoint {
                    interface: String::from("internal"),
                    region: String::from("RegionOne"),
                    url: String::from("http://192.168.22.1/identity"),
                },
                Endpoint {
                    interface: String::from("public"),
                    region: String::from("RegionTwo"),
                    url: String::from("https://host.two:5000"),
                },
            ],
        }
    }

    fn demo_service2() -> CatalogRecord {
        CatalogRecord {
            service_type: String::from("baremetal"),
            endpoints: vec![
                Endpoint {
                    interface: String::from("public"),
                    region: String::from("RegionOne"),
                    url: String::from("https://host.one/baremetal"),
                },
                Endpoint {
                    interface: String::from("public"),
                    region: String::from("RegionTwo"),
                    url: String::from("https://host.two:6385"),
                },
            ],
        }
    }

    pub fn demo_catalog() -> Vec<CatalogRecord> {
        vec![demo_service1(), demo_service2()]
    }

    fn find_endpoint<'a>(
        cat: &'a Vec<CatalogRecord>,
        service_type: &str,
        interface_type: InterfaceType,
        region: Option<&str>,
    ) -> Result<&'a Endpoint, Error> {
        EndpointFilters {
            interfaces: ValidInterfaces::one(interface_type),
            region: region.map(|x| x.to_string()),
        }
        .find_endpoint(cat, service_type)
    }

    #[test]
    fn test_find_endpoint() {
        let cat = demo_catalog();

        let e1 = find_endpoint(&cat, "identity", Public, None).unwrap();
        assert_eq!(&e1.url, "https://host.one/identity");

        let e2 = find_endpoint(&cat, "identity", Internal, None).unwrap();
        assert_eq!(&e2.url, "http://192.168.22.1/identity");

        let e3 = find_endpoint(&cat, "baremetal", Public, None).unwrap();
        assert_eq!(&e3.url, "https://host.one/baremetal");
    }

    #[test]
    fn test_find_endpoint_from_many() {
        let cat = demo_catalog();
        let service_type = "identity";

        let e1 = EndpointFilters::default()
            .with_interfaces(vec![Public, Internal])
            .find_endpoint(&cat, service_type)
            .unwrap();
        assert_eq!(&e1.url, "https://host.one/identity");

        let e2 = EndpointFilters::default()
            .with_interfaces(vec![Admin, Internal, Public])
            .find_endpoint(&cat, service_type)
            .unwrap();
        assert_eq!(&e2.url, "http://192.168.22.1/identity");

        let e3 = EndpointFilters::default()
            .with_interfaces(vec![Admin, Public])
            .find_endpoint(&cat, service_type)
            .unwrap();
        assert_eq!(&e3.url, "https://host.one/identity");
    }

    #[test]
    fn test_find_endpoint_with_region() {
        let cat = demo_catalog();

        let e1 = find_endpoint(&cat, "identity", Public, Some("RegionTwo")).unwrap();
        assert_eq!(&e1.url, "https://host.two:5000");

        let e2 = find_endpoint(&cat, "identity", Internal, Some("RegionOne")).unwrap();
        assert_eq!(&e2.url, "http://192.168.22.1/identity");

        let e3 = find_endpoint(&cat, "baremetal", Public, Some("RegionTwo")).unwrap();
        assert_eq!(&e3.url, "https://host.two:6385");
    }

    fn assert_not_found(result: Result<&Endpoint, Error>) {
        let err = result.err().unwrap();
        if err.kind() != ErrorKind::EndpointNotFound {
            panic!("Unexpected error {}", err);
        }
    }

    #[test]
    fn test_find_endpoint_not_found() {
        let cat = demo_catalog();

        assert_not_found(find_endpoint(&cat, "foobar", Public, None));
        assert_not_found(find_endpoint(&cat, "identity", Public, Some("RegionFoo")));
        assert_not_found(find_endpoint(&cat, "baremetal", Internal, None));
        assert_not_found(find_endpoint(&cat, "identity", Internal, Some("RegionTwo")));

        let e1 = EndpointFilters::default()
            .with_interfaces(vec![Admin, Internal])
            .find_endpoint(&cat, "baremetal");
        assert_not_found(e1);
    }

    #[test]
    fn test_valid_interfaces_basics() {
        assert_eq!(std::mem::size_of::<ValidInterfaces>(), 4);

        let empty = ValidInterfaces::empty();
        assert_eq!(empty.len(), 0);
        assert!(empty
            .iter()
            .map(|x| *x)
            .collect::<Vec<InterfaceType>>()
            .is_empty());
        assert_eq!(
            empty.iter().collect::<ValidInterfaces>(),
            ValidInterfaces::empty()
        );
        let v: Vec<InterfaceType> = Vec::new();
        assert_eq!(
            v.into_iter().collect::<ValidInterfaces>(),
            ValidInterfaces::empty()
        );
    }

    #[test]
    fn test_valid_interfaces_default() {
        let default = ValidInterfaces::default();
        assert_eq!(default.len(), 1);
        assert_eq!(*default, [Public]);
        assert!(default.contains(&Public));
        assert!(!default.contains(&Internal));
    }

    #[test]
    fn test_valid_interfaces_one() {
        let default = ValidInterfaces::one(Internal);
        assert_eq!(default.len(), 1);
        assert_eq!(*default, [Internal]);
        assert!(!default.contains(&Public));
    }

    #[test]
    fn test_valid_interfaces_push() {
        let mut vi = ValidInterfaces::default();
        assert!(!vi.push(Public));
        assert_eq!(vi.len(), 1);
        assert!(vi.push(Admin));
        assert!(!vi.push(Public));
        assert_eq!(vi.len(), 2);
        assert!(vi.push(Internal));
        assert_eq!(*vi, [Public, Admin, Internal]);
    }

    #[test]
    fn test_valid_interfaces_from() {
        let vi: ValidInterfaces = vec![Public, Internal].into();
        assert_eq!(*vi, [Public, Internal]);

        let vi: ValidInterfaces = vec![Public, Internal, Public, Public, Admin, Internal].into();
        assert_eq!(*vi, [Public, Internal, Admin]);
    }
}
