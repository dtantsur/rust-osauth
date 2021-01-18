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

//! Utilities to work with OpenStack requests.

use std::collections::HashMap;

use log::trace;
use reqwest::{RequestBuilder, Response};
use serde::de::DeserializeOwned;
use serde::Deserialize;

use super::Error;

#[derive(Debug, Deserialize)]
struct Message {
    message: String,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum ErrorResponse {
    Map(HashMap<String, Message>),
    Message(Message),
}

async fn extract_message(resp: Response) -> Result<String, Error> {
    let text = resp.text().await?;
    Ok(serde_json::from_str::<ErrorResponse>(&text)
        .ok()
        .and_then(|body| match body {
            ErrorResponse::Map(map) => map.into_iter().next().map(|(_k, v)| v.message),
            ErrorResponse::Message(msg) => Some(msg.message),
        })
        .unwrap_or(text))
}

/// Check the response and convert errors into OpenStack ones.
pub async fn check(response: Response) -> Result<Response, Error> {
    let status = response.status();
    if status.is_client_error() || status.is_server_error() {
        let message = extract_message(response).await?;
        trace!("HTTP request returned {}; error: {:?}", status, message);
        Err(Error::new(status.into(), message).with_status(status))
    } else {
        trace!(
            "HTTP request to {} returned {}",
            response.url(),
            response.status()
        );
        Ok(response)
    }
}

/// Send the request and check its result.
#[inline]
pub async fn send_checked(builder: RequestBuilder) -> Result<Response, Error> {
    check(builder.send().await?).await
}

/// Check the response and convert it to a JSON.
#[inline]
pub async fn to_json<T>(response: Response) -> Result<T, Error>
where
    T: DeserializeOwned + Send,
{
    check(response).await?.json::<T>().await.map_err(Into::into)
}

/// Send the response and convert the response to a JSON.
#[inline]
pub async fn fetch_json<T>(builder: RequestBuilder) -> Result<T, Error>
where
    T: DeserializeOwned + Send,
{
    send_checked(builder)
        .await?
        .json::<T>()
        .await
        .map_err(Into::into)
}

/// A properly typed constant for use with root paths.
///
/// The problem with just using `None` is that the exact type of `Option` is not known.
///
/// An example:
///
/// ```rust,no_run
/// let session = osauth::Session::from_env()
///     .expect("Failed to create an identity provider from the environment");
/// let future = session.get(osauth::services::OBJECT_STORAGE, osauth::request::NO_PATH, None);
/// ```
pub const NO_PATH: Option<&'static str> = None;
