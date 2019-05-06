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

//! Support for cloud configuration file.

use std::collections::HashMap;
use std::env;
use std::fs::File;
use std::path::{Path, PathBuf};

use dirs;
use log::warn;
use serde::Deserialize;
use serde_yaml;

use super::identity::Password;
use super::{Error, ErrorKind, Session};

#[derive(Debug, Deserialize)]
struct Auth {
    auth_url: String,
    password: String,
    #[serde(default)]
    project_name: Option<String>,
    #[serde(default)]
    project_domain_name: Option<String>,
    username: String,
    #[serde(default)]
    user_domain_name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Cloud {
    auth: Auth,
    #[serde(default)]
    region_name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Clouds {
    #[serde(flatten)]
    clouds: HashMap<String, Cloud>,
}

#[derive(Debug, Deserialize)]
struct Root {
    clouds: Clouds,
}

fn find_config() -> Option<PathBuf> {
    let current = Path::new("./clouds.yaml");
    if current.is_file() {
        match current.canonicalize() {
            Ok(val) => return Some(val),
            Err(e) => warn!("Cannot canonicalize {:?}: {}", current, e),
        }
    }

    if let Some(mut home) = dirs::home_dir() {
        home.push(".config/openstack/clouds.yaml");
        if home.is_file() {
            return Some(home);
        }
    } else {
        warn!("Cannot find home directory");
    }

    let abs = PathBuf::from("/etc/openstack/clouds.yaml");
    if abs.is_file() {
        Some(abs)
    } else {
        None
    }
}

/// Create a `Session` from the config file.
pub fn from_config<S: AsRef<str>>(cloud_name: S) -> Result<Session, Error> {
    let path = find_config().ok_or_else(|| {
        Error::new(
            ErrorKind::InvalidConfig,
            "clouds.yaml was not found in any location",
        )
    })?;
    let file = File::open(path).map_err(|e| {
        Error::new(
            ErrorKind::InvalidConfig,
            format!("Cannot read config.yaml: {}", e),
        )
    })?;
    let mut clouds_root: Root = serde_yaml::from_reader(file).map_err(|e| {
        Error::new(
            ErrorKind::InvalidConfig,
            format!("Cannot parse clouds.yaml: {}", e),
        )
    })?;

    let name = cloud_name.as_ref();
    let cloud =
        clouds_root.clouds.clouds.remove(name).ok_or_else(|| {
            Error::new(ErrorKind::InvalidConfig, format!("No such cloud: {}", name))
        })?;

    let auth = cloud.auth;
    let user_domain = auth
        .user_domain_name
        .unwrap_or_else(|| String::from("Default"));
    let project_domain = auth
        .project_domain_name
        .unwrap_or_else(|| String::from("Default"));
    let mut id = Password::new(&auth.auth_url, auth.username, auth.password, user_domain)?;
    if let Some(project_name) = auth.project_name {
        id.set_project_scope(project_name, project_domain);
    }
    if let Some(region) = cloud.region_name {
        id.set_region(region)
    }

    Ok(Session::new(id))
}

const MISSING_ENV_VARS: &str = "Not all required environment variables were provided";

#[inline]
fn _get_env(name: &str) -> Result<String, Error> {
    env::var(name).map_err(|_| Error::new(ErrorKind::InvalidInput, MISSING_ENV_VARS))
}

/// Create a `Session` from environment variables.
pub fn from_env() -> Result<Session, Error> {
    if let Ok(cloud_name) = env::var("OS_CLOUD") {
        from_config(cloud_name)
    } else {
        let auth_url = _get_env("OS_AUTH_URL")?;
        let user_name = _get_env("OS_USERNAME")?;
        let password = _get_env("OS_PASSWORD")?;
        let user_domain =
            env::var("OS_USER_DOMAIN_NAME").unwrap_or_else(|_| String::from("Default"));

        let id = Password::new(&auth_url, user_name, password, user_domain)?;

        let project_name = _get_env("OS_PROJECT_NAME")?;
        let project_domain =
            env::var("OS_PROJECT_DOMAIN_NAME").unwrap_or_else(|_| String::from("Default"));

        let mut session = Session::new(id.with_project_scope(project_name, project_domain));

        if let Ok(interface) = env::var("OS_INTERFACE") {
            session.set_endpoint_interface(interface)
        }

        Ok(session)
    }
}
