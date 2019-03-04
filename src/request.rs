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

//! Utilities to work with OpenStack requests.

use std::collections::HashMap;

use futures::future::{self, Either};
use futures::prelude::*;
use reqwest::r#async::Response;
use serde::de::DeserializeOwned;

use super::Error;

#[derive(Debug, Clone, Deserialize)]
struct Message {
    message: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum ErrorResponse {
    Map(HashMap<String, Message>),
    Message(Message),
}

fn extract_message(resp: Response) -> impl Future<Item = String, Error = Error> {
    resp.into_body().concat2().from_err().map(|chunk| {
        serde_json::from_slice::<ErrorResponse>(&chunk)
            .ok()
            .and_then(|body| match body {
                ErrorResponse::Map(map) => map.into_iter().next().map(|(_k, v)| v.message),
                ErrorResponse::Message(msg) => Some(msg.message),
            })
            // TODO(dtantsur): detect the correct encoding? (should go into reqwest)
            .unwrap_or_else(|| String::from_utf8_lossy(&chunk).into_owned())
    })
}

/// Check the response and convert errors into OpenStack ones.
pub fn check<E>(maybe_response: Result<Response, E>) -> impl Future<Item = Response, Error = Error>
where
    E: Into<Error>,
{
    let resp = match maybe_response {
        Ok(resp) => resp,
        Err(err) => return Either::A(future::err(err.into())),
    };

    let status = resp.status();
    if resp.status().is_client_error() || resp.status().is_server_error() {
        future::Either::B(extract_message(resp).and_then(move |message| {
            trace!("HTTP request returned {}; error: {:?}", status, message);

            future::err(Error::new(status.into(), message).with_status(status))
        }))
    } else {
        trace!("HTTP request to {} returned {}", resp.url(), resp.status());
        future::Either::A(future::ok(resp))
    }
}

/// Check the response and convert it to a JSON.
pub fn to_json<T: DeserializeOwned, E: Into<Error>>(
    maybe_response: Result<Response, E>,
) -> impl Future<Item = T, Error = Error> {
    check(maybe_response).and_then(move |mut resp| resp.json().from_err())
}
