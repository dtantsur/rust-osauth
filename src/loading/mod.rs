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

//! Support for loading sessions from external input.

#[cfg(any(feature = "native-tls", feature = "rustls"))]
use std::fs;

#[cfg(any(feature = "native-tls", feature = "rustls"))]
use reqwest::Certificate;
use reqwest::Client;

use crate::{Error, ErrorKind};

/// Create an HTTP client with the provided CA certificate.
#[inline]
#[allow(unused_mut)] // mut builder unused with --no-default-features
fn get_client(cacert: Option<String>) -> Result<Client, Error> {
    let mut builder = Client::builder();
    #[cfg(any(feature = "native-tls", feature = "rustls"))]
    if let Some(cert_path) = cacert {
        let cert_content = fs::read(&cert_path).map_err(|e| {
            Error::new(
                ErrorKind::InvalidConfig,
                format!("Cannot open cacert file {}: {}", cert_path, e),
            )
        })?;

        let cert = Certificate::from_pem(&cert_content).map_err(|e| {
            Error::new(
                ErrorKind::InvalidConfig,
                format!("Cannot parse {} as PEM: {}", cert_path, e),
            )
        })?;

        builder = builder.add_root_certificate(cert);
    }

    #[cfg(not(any(feature = "native-tls", feature = "rustls")))]
    if cacert.is_some() {
        return Err(Error::new(
            ErrorKind::InvalidConfig,
            "TLS support is disabled",
        ));
    }

    Ok(builder.build().expect("Cannot initialize HTTP backend"))
}

mod config;
mod env;

pub use config::from_config;
pub use env::from_env;
