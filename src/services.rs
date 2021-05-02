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

//! OpenStack service types.

use http::{header::HeaderName, HeaderValue};

use super::ApiVersion;

/// Trait representing a service type.
pub trait ServiceType {
    /// Service type to pass to the catalog.
    fn catalog_type(&self) -> &'static str;

    /// Check whether this service type is compatible with the given major version.
    fn major_version_supported(&self, _version: ApiVersion) -> bool {
        true
    }

    /// Whether this service supports version discovery at all.
    fn version_discovery_supported(&self) -> bool {
        true
    }
}

/// Trait marking a service as supporting API versions.
pub trait VersionedService: ServiceType {
    /// Get a header for this version.
    fn get_version_header(&self, version: ApiVersion) -> (HeaderName, HeaderValue);
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

/// An indicator that no service is used.
#[derive(Copy, Clone, Debug)]
#[non_exhaustive]
pub struct NoService;

impl ServiceType for NoService {
    fn catalog_type(&self) -> &'static str {
        "<no service>"
    }

    fn major_version_supported(&self, _version: ApiVersion) -> bool {
        false
    }

    fn version_discovery_supported(&self) -> bool {
        false
    }
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
        }

        impl $crate::services::VersionedService for $cls {
            fn get_version_header(
                &self,
                version: ApiVersion,
            ) -> (::http::header::HeaderName, ::http::HeaderValue) {
                (::http::header::HeaderName::from_static($hdr), version.into())
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
}

impl VersionedService for ComputeService {
    fn get_version_header(&self, version: ApiVersion) -> (HeaderName, HeaderValue) {
        // TODO: new-style header support
        (
            HeaderName::from_static("x-openstack-nova-api-version"),
            version.into(),
        )
    }
}

/// Compute service.
pub const COMPUTE: ComputeService = ComputeService::new();
