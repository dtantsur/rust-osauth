// Copyright 2020 Dmitry Tantsur <dtantsur@protonmail.com>
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
use std::hash::{Hash, Hasher};
use std::iter::FromIterator;
use std::ops::Deref;
use std::str::FromStr;

use super::{Error, ErrorKind};
use crate::identity::protocol::Endpoint;

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
#[derive(Clone, Copy, Eq)]
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

impl fmt::Debug for ValidInterfaces {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ValidInterfaces ")?;
        f.debug_list()
            .entries(&self.items[..self.len as usize])
            .finish()
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

impl Hash for ValidInterfaces {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.len.hash(state);
        self.items[..self.len as usize].hash(state);
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
    pub(crate) fn find(&self, interface: &str) -> Option<usize> {
        self.iter().position(|x| x == &interface)
    }

    /// Whether the interfaces match the provided endpoint.
    pub(crate) fn check(&self, endpoint: &Endpoint) -> bool {
        self.find(&endpoint.interface).is_some()
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
}

#[cfg(test)]
pub mod test {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    use super::{InterfaceType, ValidInterfaces};
    use InterfaceType::*;

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
        assert_eq!("ValidInterfaces []", format!("{:?}", empty).as_str());
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
        assert_eq!(
            "ValidInterfaces [Public]",
            format!("{:?}", default).as_str()
        );
    }

    #[test]
    fn test_valid_interfaces_one() {
        let default = ValidInterfaces::one(Internal);
        assert_eq!(default.len(), 1);
        assert_eq!(*default, [Internal]);
        assert!(!default.contains(&Public));
        assert_eq!(
            "ValidInterfaces [Internal]",
            format!("{:?}", default).as_str()
        );
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
        assert_eq!(
            "ValidInterfaces [Public, Admin, Internal]",
            format!("{:?}", vi).as_str()
        );
    }

    fn get_hash(value: &ValidInterfaces) -> u64 {
        let mut hasher = DefaultHasher::new();
        value.hash(&mut hasher);
        hasher.finish()
    }

    #[test]
    fn test_valid_interfaces_cmp() {
        let mut vi1 = ValidInterfaces::default();
        let mut vi2 = ValidInterfaces::default();
        assert_eq!(vi1, vi2);
        assert_eq!(get_hash(&vi1), get_hash(&vi2));
        assert!(!vi1.push(Public));
        assert_eq!(vi1, vi2);
        assert_eq!(get_hash(&vi1), get_hash(&vi2));
        assert!(vi2.push(Internal));
        assert!(vi1 != vi2);
        assert!(get_hash(&vi1) != get_hash(&vi2));
        assert!(vi1.push(Internal));
        assert_eq!(vi1, vi2);
        assert_eq!(get_hash(&vi1), get_hash(&vi2));
    }

    #[test]
    fn test_valid_interfaces_from() {
        let vi: ValidInterfaces = vec![Public, Internal].into();
        assert_eq!(*vi, [Public, Internal]);

        let vi: ValidInterfaces = vec![Public, Internal, Public, Public, Admin, Internal].into();
        assert_eq!(*vi, [Public, Internal, Admin]);
    }
}
