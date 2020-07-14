// Copyright 2018 Dmitry Tantsur <divius.inside@gmail.com>
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

//! Error and Result implementations.

use std::fmt;

use reqwest::Error as HttpClientError;
use reqwest::StatusCode;

/// Kind of an error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ErrorKind {
    /// Authentication failure
    ///
    /// Maps to HTTP 401.
    AuthenticationFailed,

    /// Access denied.
    ///
    /// Maps to HTTP 403.
    AccessDenied,

    /// Requested resource was not found.
    ///
    /// Roughly maps to HTTP 404 and 410.
    ResourceNotFound,

    /// Request returned more items than expected.
    TooManyItems,

    /// Requested service endpoint was not found.
    EndpointNotFound,

    /// Invalid value passed to one of paremeters.
    ///
    /// May be result of HTTP 400.
    InvalidInput,

    /// Unsupported or incompatible API version.
    ///
    /// May be a result of HTTP 406.
    IncompatibleApiVersion,

    /// Conflict in the request.
    Conflict,

    /// Operation has reached the specified time out.
    OperationTimedOut,

    /// Operation failed to complete.
    OperationFailed,

    /// Protocol-level error reported by underlying HTTP library.
    ProtocolError,

    /// Response received from the server is malformed.
    InvalidResponse,

    /// Internal server error.
    ///
    /// Maps to HTTP 5xx codes.
    InternalServerError,

    /// Invalid clouds.yaml, clouds-public.yaml or secure.yaml file.
    InvalidConfig,
}

/// Error from an OpenStack call.
#[derive(Debug, Clone)]
pub struct Error {
    kind: ErrorKind,
    message: String,
    status: Option<StatusCode>,
}

impl Error {
    /// Create a new error of the provided kind.
    #[inline]
    pub fn new<S: Into<String>>(kind: ErrorKind, message: S) -> Error {
        Error {
            kind,
            message: message.into(),
            status: None,
        }
    }

    /// Add an HTTP status code to the error.
    #[inline]
    pub fn set_status(&mut self, status: StatusCode) {
        self.status = Some(status);
    }

    /// Add an HTTP status code to the error.
    #[inline]
    pub fn with_status(mut self, status: StatusCode) -> Self {
        self.set_status(status);
        self
    }

    /// Error kind.
    #[inline]
    pub fn kind(&self) -> ErrorKind {
        self.kind
    }

    /// Helper - error of kind EndpointNotFound.
    pub(crate) fn new_endpoint_not_found<D: fmt::Display>(service_type: D) -> Error {
        Error::new(
            ErrorKind::EndpointNotFound,
            format!("Endpoint for service {} was not found", service_type),
        )
    }
}

impl ErrorKind {
    /// Short description of the error kind.
    #[allow(clippy::trivially_copy_pass_by_ref)]
    #[inline]
    pub fn description(&self) -> &'static str {
        match self {
            ErrorKind::AuthenticationFailed => "Failed to authenticate",
            ErrorKind::AccessDenied => "Access to the resource is denied",
            ErrorKind::ResourceNotFound => "Requested resource was not found",
            ErrorKind::TooManyItems => "Request returned too many items",
            ErrorKind::EndpointNotFound => "Requested endpoint was not found",
            ErrorKind::InvalidInput => "Input value(s) are invalid or missing",
            ErrorKind::IncompatibleApiVersion => "Incompatible or unsupported API version",
            ErrorKind::Conflict => "Requested cannot be fulfilled due to a conflict",
            ErrorKind::OperationTimedOut => "Time out reached while waiting for the operation",
            ErrorKind::OperationFailed => "Requested operation has failed",
            ErrorKind::ProtocolError => "Error when accessing the server",
            ErrorKind::InvalidResponse => "Received invalid response",
            ErrorKind::InternalServerError => "Internal server error or bad gateway",
            ErrorKind::InvalidConfig => "configuration file cannot be found or is invalid",
        }
    }
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.description())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}: {}", self.kind, self.message)
    }
}

impl ::std::error::Error for Error {
    fn description(&self) -> &str {
        self.kind.description()
    }

    fn cause(&self) -> Option<&dyn ::std::error::Error> {
        None
    }
}

impl From<StatusCode> for ErrorKind {
    fn from(value: StatusCode) -> ErrorKind {
        match value {
            StatusCode::UNAUTHORIZED => ErrorKind::AuthenticationFailed,
            StatusCode::FORBIDDEN => ErrorKind::AccessDenied,
            StatusCode::NOT_FOUND => ErrorKind::ResourceNotFound,
            StatusCode::NOT_ACCEPTABLE => ErrorKind::IncompatibleApiVersion,
            StatusCode::CONFLICT => ErrorKind::Conflict,
            c if c.is_client_error() => ErrorKind::InvalidInput,
            c if c.is_server_error() => ErrorKind::InternalServerError,
            _ => ErrorKind::InvalidResponse,
        }
    }
}

impl From<HttpClientError> for Error {
    fn from(value: HttpClientError) -> Error {
        let msg = value.to_string();
        let kind = if value.is_builder() {
            ErrorKind::InvalidInput
        } else {
            value
                .status()
                .map(From::from)
                .unwrap_or(ErrorKind::ProtocolError)
        };

        let error = Error::new(kind, msg);
        if let Some(status) = value.status() {
            error.with_status(status)
        } else {
            error
        }
    }
}

#[cfg(test)]
pub mod test {
    use super::{Error, ErrorKind};

    #[test]
    fn test_error_display() {
        let error = Error::new(ErrorKind::InvalidInput, "boom");
        assert_eq!(error.kind(), ErrorKind::InvalidInput);
        let s = format!("{}", error);
        assert_eq!(&s, "Input value(s) are invalid or missing: boom");
    }
}
