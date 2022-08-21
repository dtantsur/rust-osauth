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

use std::env;
use std::str::FromStr;

use futures::pin_mut;
use futures::stream::TryStreamExt;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Server {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Deserialize)]
pub struct ServersRoot {
    pub servers: Vec<Server>,
}

impl From<ServersRoot> for Vec<Server> {
    fn from(value: ServersRoot) -> Vec<Server> {
        value.servers
    }
}

impl osauth::client::PaginatedResource for Server {
    type Id = String;
    type Root = ServersRoot;
    fn resource_id(&self) -> Self::Id {
        self.id.clone()
    }
}

#[tokio::main]
async fn main() {
    env_logger::init();
    let limit = env::args()
        .nth(1)
        .map(|s| FromStr::from_str(&s).expect("Expected a number"));

    let session = osauth::Session::from_env()
        .await
        .expect("Failed to create an identity provider from the environment");
    let adapter = session.adapter(osauth::services::COMPUTE);

    let sstream = adapter
        .get(&["servers"])
        .fetch_paginated::<Server>(limit, None)
        .await;
    pin_mut!(sstream);
    while let Some(srv) = sstream
        .try_next()
        .await
        .expect("Failed to fetch the next chunk")
    {
        println!("ID = {}, Name = {}", srv.id, srv.name);
    }
    println!("Done listing");
}
