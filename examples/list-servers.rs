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

#[tokio::main]
async fn main() {
    env_logger::init();
    let session = osauth::Session::from_env()
        .await
        .expect("Failed to create an identity provider from the environment");

    let servers: ServersRoot = session
        .get_json(osauth::services::COMPUTE, &["servers"])
        .await
        .expect("Failed to list servers");
    for srv in servers.servers {
        println!("ID = {}, Name = {}", srv.id, srv.name);
    }
    println!("Done listing");
}
