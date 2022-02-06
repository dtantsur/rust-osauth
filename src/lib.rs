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

//! Asynchronous OpenStack session and authentication.
//!
//! # Introduction
//!
//! This crate provides low-level asynchronous access to OpenStack API. It features:
//! 1. Authentication and token caching.
//! 2. Major and microversion handling.
//! 3. Service catalog integration.
//! 4. JSON API error handling.
//! 5. Service types for supported services.
//!
//! It does NOT provide:
//! 1. Protocol structures for any services.
//! 2. Automatic microversion negotiation.
//! 3. High-level object-oriented API.
//!
//! See [openstack crate](https://crates.io/crates/openstack) for these features.
//!
//! # Requirements
//!
//! This crate requires Rust 2018 edition and rustc version 1.51.0 or newer.
//!
//! OpenStack releases starting with Train are officially supported, although support for
//! releases older than 1.5 years is best-effort and may be dropped without a prior warning
//! (it will not be considered a breaking change).
//!
//! # Usage
//!
//! Your entry point to the API is the [Session](struct.Session.html) structure. To create it you
//! need an authentication type object first. It can be obtained by:
//! * Using [Password](identity/struct.Password.html) authentication against the Identity service.
//! * Using [NoAuth](struct.NoAuth.html) authentication type, allowing access to standalone
//!   services without authentication.
//! * Using HTTP [BasicAuth](struct.BasicAuth.html) authentication type for services supporting it
//!   (only ironic and ironic-inspector at the moment).
//! * By loading both authentication parameters and a session from:
//!   * `clouds.yaml`, `clouds-public.yaml` and `secure.yaml` configuration files using
//!     [from_config](struct.Session.html#method.from_config).
//!   * environment variables using [from_env](struct.Session.html#method.from_env).
//!
//! See [Session](struct.Session.html) documentation for the details on using a `Session` for making
//! OpenStack calls.
//!
//! If you need to work with a small number of servics, [Adapter](struct.Adapter.html) provides a
//! more convenient interface. An adapter can be created directly using
//! [Adapter::new](struct.Adapter.html#method.new) or from an existing `Session` using
//! [Session::adapter](struct.Session.html#method.adapter) or
//! [Session::into_adapter](struct.Session.html#method.into_adapter).
//!
//! # Features
//!
//! * `native-tls` or `rustls` add TLS support with two alternative implementations, `native-tls`
//!   is enabled by default.
//! * `stream` adds [get_json_paginated](struct.Session.html#method.get_json_paginated) and
//!   [get_json_query_paginated](struct.Session.html#method.get_json_query_paginated) to `Session`
//!   and `Adapter`; enabled by default.
//! * `sync` adds a [synchronous wrapper](sync/struct.SyncSession.html) around the `Session`;
//!   enabled by default.

#![crate_name = "osauth"]
#![crate_type = "lib"]
#![doc(html_root_url = "https://docs.rs/osauth/0.3.4")]
// NOTE: we do not use generic deny(warnings) to avoid breakages with new
// versions of the compiler. Add more warnings here as you discover them.
// Taken from https://github.com/rust-unofficial/patterns/
#![deny(
    bare_trait_objects,
    const_err,
    dead_code,
    improper_ctypes,
    missing_copy_implementations,
    missing_debug_implementations,
    missing_docs,
    non_shorthand_field_patterns,
    no_mangle_generic_items,
    overflowing_literals,
    path_statements,
    patterns_in_fns_without_body,
    private_in_public,
    trivial_casts,
    trivial_numeric_casts,
    unconditional_recursion,
    unsafe_code,
    unused,
    unused_allocation,
    unused_comparisons,
    unused_doc_comments,
    unused_import_braces,
    unused_parens,
    unused_qualifications,
    unused_results,
    while_true
)]

mod adapter;
mod apiversion;
mod auth;
mod basic;
mod cache;
mod catalog;
pub mod client;
pub mod common;
mod endpointfilters;
mod error;
pub mod identity;
mod loading;
mod protocol;
pub mod services;
mod session;
#[cfg(feature = "stream")]
mod stream;
#[cfg(feature = "sync")]
pub mod sync;
mod url;
mod utils;

pub use crate::adapter::Adapter;
pub use crate::apiversion::ApiVersion;
pub use crate::auth::{AuthType, NoAuth};
pub use crate::basic::BasicAuth;
pub use crate::endpointfilters::{EndpointFilters, InterfaceType, ValidInterfaces};
pub use crate::error::{Error, ErrorKind};
pub use crate::loading::CloudConfig;
pub use crate::session::Session;
