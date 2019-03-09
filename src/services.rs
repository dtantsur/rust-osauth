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

use reqwest::r#async::RequestBuilder;

use super::{ApiVersion, Error, ErrorKind};

/// Trait representing a service type.
pub trait ServiceType {
    /// Service type to pass to the catalog.
    fn catalog_type(&self) -> &'static str;

    /// Check whether this service type is compatible with the given major version.
    fn major_version_supported(&self, _version: ApiVersion) -> bool {
        true
    }

    /// Update the request to include the API version headers.
    ///
    /// The default implementation fails with `IncompatibleApiVersion`.
    fn set_api_version_headers(
        &self,
        _request: RequestBuilder,
        _version: ApiVersion,
    ) -> Result<RequestBuilder, Error> {
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

/// A generic service.
#[derive(Copy, Clone, Debug)]
pub struct GenericService {
    catalog_type: &'static str,
    major_version: Option<u16>,
}

/// The Compute service.
#[derive(Copy, Clone, Debug)]
pub struct ComputeService {
    __use_new: (),
}

impl GenericService {
    /// Create a new generic service.
    pub const fn new(catalog_type: &'static str, major_version: Option<u16>) -> GenericService {
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
        if let Some(supported) = self.major_version {
            version.0 == supported
        } else {
            true
        }
    }
}

impl ComputeService {
    /// Create a Compute service type.
    pub const fn new() -> ComputeService {
        ComputeService { __use_new: () }
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
        request: RequestBuilder,
        version: ApiVersion,
    ) -> Result<RequestBuilder, Error> {
        // TODO: new-style header support
        Ok(request.header("x-openstack-nova-api-version", version.to_string()))
    }
}

/// Compute service.
pub const COMPUTE: ComputeService = ComputeService::new();

/// Image service.
pub const IMAGE: GenericService = GenericService::new("image", None);

/// Networking service.
pub const NETWORK: GenericService = GenericService::new("network", None);
