// Copyright 2018-2020 Dmitry Tantsur <divius.inside@gmail.com>
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

//! Support for `OS_` environment variables.

use std::env;
use std::str::FromStr;

use reqwest::Client;

use crate::identity::{IdOrName, Password};
use crate::loading;
use crate::utils;
use crate::{BasicAuth, EndpointFilters, Error, ErrorKind, InterfaceType, Session};

fn password_auth_from_env(
    client: Client,
    user_name: String,
    password: String,
) -> Result<Session, Error> {
    let auth_url = utils::require_env("OS_AUTH_URL")?;
    let user_domain = env::var("OS_USER_DOMAIN_NAME").unwrap_or_else(|_| String::from("Default"));

    let id = Password::new_with_client(&auth_url, client, user_name, password, user_domain)?;

    let project = utils::require_env("OS_PROJECT_ID")
        .map(IdOrName::Id)
        .or_else(|_| utils::require_env("OS_PROJECT_NAME").map(IdOrName::Name))?;

    let project_domain = utils::require_env("OS_PROJECT_DOMAIN_ID")
        .map(IdOrName::Id)
        .or_else(|_| utils::require_env("OS_PROJECT_DOMAIN_NAME").map(IdOrName::Name))
        .ok();

    let mut session = Session::new(id.with_project_scope(project, project_domain));
    let mut filters = EndpointFilters::default();

    if let Ok(interface) = env::var("OS_INTERFACE") {
        filters.set_interfaces(InterfaceType::from_str(&interface)?);
    }

    if let Ok(region) = env::var("OS_REGION_NAME") {
        filters.region = Some(region);
    }

    *session.endpoint_filters_mut() = filters;

    Ok(session)
}

/// Create a `Session` from environment variables.
pub fn from_env() -> Result<Session, Error> {
    if let Ok(cloud_name) = env::var("OS_CLOUD") {
        return loading::from_config(cloud_name);
    }

    let user_name = utils::require_env("OS_USERNAME")?;
    let password = utils::require_env("OS_PASSWORD")?;
    let auth_type = env::var("OS_AUTH_TYPE").unwrap_or_else(|_| "password".to_string());

    let client = loading::get_client(env::var("OS_CACERT").ok())?;

    match auth_type.as_str() {
        "password" => password_auth_from_env(client, user_name, password),
        "http_basic" => {
            let endpoint = utils::require_env("OS_ENDPOINT")?;
            let id = BasicAuth::new_with_client(&endpoint, client, user_name, password)?;
            Ok(Session::new(id))
        }
        _ => Err(Error::new(
            ErrorKind::InvalidInput,
            format!("Unsupported authentication type: {}", auth_type),
        )),
    }
}
