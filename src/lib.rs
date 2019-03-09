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

//! Asynchronous OpenStack session and authentication.

#![crate_name = "osauth"]
#![crate_type = "lib"]
// NOTE: we do not use generic deny(warnings) to avoid breakages with new
// versions of the compiler. Add more warnings here as you discover them.
// Taken from https://github.com/rust-unofficial/patterns/
#![deny(
    const_err,
    dead_code,
    improper_ctypes,
    legacy_directory_ownership,
    missing_copy_implementations,
    missing_debug_implementations,
    missing_docs,
    non_shorthand_field_patterns,
    no_mangle_generic_items,
    overflowing_literals,
    path_statements,
    patterns_in_fns_without_body,
    plugin_as_library,
    private_in_public,
    safe_extern_statics,
    trivial_casts,
    trivial_numeric_casts,
    unconditional_recursion,
    unions_with_drop_fields,
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
#![allow(unused_extern_crates)]
#![allow(
    clippy::new_ret_no_self,
    clippy::should_implement_trait,
    clippy::wrong_self_convention
)]

extern crate chrono;
extern crate dirs;
extern crate futures;
#[macro_use]
extern crate log;
extern crate reqwest;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;
extern crate serde_yaml;

mod apiversion;
mod auth;
mod cache;
mod catalog;
mod config;
mod error;
pub mod identity;
mod protocol;
pub mod request;
pub mod services;
mod session;
mod url;

pub use crate::apiversion::ApiVersion;
pub use crate::auth::{AuthType, NoAuth};
pub use crate::config::{from_config, from_env};
pub use crate::error::{Error, ErrorKind};
pub use crate::session::Session;
