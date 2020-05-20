// Copyright 2019 Dmitry Tantsur <divius.inside@gmail.com>
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

//! OpenStack service types.

use reqwest::header::HeaderMap;

use super::{ApiVersion, Error, ErrorKind};

/// Trait representing a service type.
pub trait ServiceType {
    /// Service type to pass to the catalog.
    fn catalog_type(&self) -> &'static str;

    /// Check whether this service type is compatible with the given major version.
    fn major_version_supported(&self, _version: ApiVersion) -> bool {
        true
    }

    /// Update the headers to include the API version headers.
    ///
    /// The default implementation fails with `IncompatibleApiVersion`.
    fn set_api_version_headers(
        &self,
        _headers: &mut HeaderMap,
        _version: ApiVersion,
    ) -> Result<(), Error> {
        Err(Error::new(
            ErrorKind::IncompatibleApiVersion,
            format!(
                "The {} service does not support API versions",
                self.catalog_type()
            ),
        ))
    }

    /// Whether this service supports version discovery at all.
    fn version_discovery_supported(&self) -> bool {
        true
    }
}

/// A major version selector.
#[derive(Copy, Clone, Debug)]
#[non_exhaustive]
pub enum VersionSelector {
    /// Match the major component.
    Major(u16),
    /// Match the full version.
    ///
    /// Some service have a minor component in their major versions, e.g. 2.1.
    Exact(ApiVersion),
    /// A range of major versions.
    Range(ApiVersion, ApiVersion),
    /// Any major version.
    Any,
}

// TODO(dtantsur): change $name to be a literal
macro_rules! service {
    ($(#[$attr:meta])* $var:ident: $cls:ident -> $name:expr, discovery $disc:expr) => {
        $(#[$attr])*
        #[derive(Copy, Clone, Debug)]
        #[non_exhaustive]
        pub struct $cls;

        impl $cls {
            /// Create a new service type.
            pub const fn new() -> $cls {
                $cls
            }
        }

        impl $crate::services::ServiceType for $cls {
            fn catalog_type(&self) -> &'static str {
                $name
            }

            fn version_discovery_supported(&self) -> bool {
                $disc
            }
        }

        $(#[$attr])*
        pub const $var: $cls = $cls::new();
    };

    ($(#[$attr:meta])* $var:ident: $cls:ident -> $name:expr) => {
        service! {
            $(#[$attr])*
            $var: $cls -> $name, discovery true
        }
    };

    ($(#[$attr:meta])* $var:ident: $cls:ident -> $name:expr, header $hdr:expr) => {
        $(#[$attr])*
        #[derive(Copy, Clone, Debug)]
        #[non_exhaustive]
        pub struct $cls;

        impl $cls {
            /// Create a new service type.
            pub const fn new() -> $cls {
                $cls
            }
        }

        impl $crate::services::ServiceType for $cls {
            fn catalog_type(&self) -> &'static str {
                $name
            }

            fn set_api_version_headers(
                &self,
                headers: &mut HeaderMap,
                version: ApiVersion,
            ) -> Result<(), Error> {
                let _ = headers.insert($hdr, version.into());
                Ok(())
            }
        }

        $(#[$attr])*
        pub const $var: $cls = $cls::new();
    };
}

/// A generic service.
#[derive(Copy, Clone, Debug)]
pub struct GenericService {
    catalog_type: &'static str,
    major_version: VersionSelector,
}

/// Compute service.
#[derive(Copy, Clone, Debug)]
#[non_exhaustive]
pub struct ComputeService;

service! {
    #[doc = "Bare Metal service."]
    BAREMETAL: BareMetalService -> "baremetal", header "x-openstack-ironic-api-version"
}

service! {
    #[doc = "Image service."]
    IMAGE: ImageService -> "image"
}

service! {
    #[doc = "Network service."]
    NETWORK: NetworkService -> "network"
}

service! {
    #[doc = "Object Storage service."]
    OBJECT_STORAGE: ObjectStorageService -> "object-store", discovery false
}

service! {
    #[doc = "Block Storage service (v3)."]
    BLOCK_STORAGE: BlockStorageService -> "volumev3"
}

impl GenericService {
    /// Create a new generic service.
    pub const fn new(catalog_type: &'static str, major_version: VersionSelector) -> GenericService {
        GenericService {
            catalog_type,
            major_version,
        }
    }
}

impl ServiceType for GenericService {
    fn catalog_type(&self) -> &'static str {
        self.catalog_type
    }

    fn major_version_supported(&self, version: ApiVersion) -> bool {
        match self.major_version {
            VersionSelector::Major(ver) => version.0 == ver,
            VersionSelector::Exact(ver) => version == ver,
            VersionSelector::Range(v1, v2) => v1 <= version && version <= v2,
            VersionSelector::Any => true,
        }
    }
}

impl ComputeService {
    /// Create a Compute service type.
    pub const fn new() -> ComputeService {
        ComputeService
    }
}

impl ServiceType for ComputeService {
    fn catalog_type(&self) -> &'static str {
        "compute"
    }

    fn major_version_supported(&self, version: ApiVersion) -> bool {
        version.0 == 2
    }

    fn set_api_version_headers(
        &self,
        headers: &mut HeaderMap,
        version: ApiVersion,
    ) -> Result<(), Error> {
        // TODO: new-style header support
        let _ = headers.insert("x-openstack-nova-api-version", version.into());
        Ok(())
    }
}

/// Compute service.
pub const COMPUTE: ComputeService = ComputeService::new();
