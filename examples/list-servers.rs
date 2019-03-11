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

extern crate env_logger;
extern crate futures;
extern crate osauth;
extern crate tokio;

use futures::Future;
use serde::Deserialize;
use tokio::runtime::Runtime;

#[derive(Debug, Deserialize)]
pub struct Server {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Deserialize)]
pub struct ServersRoot {
    pub servers: Vec<Server>,
}

fn main() {
    env_logger::init();
    let mut rt = Runtime::new().expect("Cannot create a runtime");

    let session =
        osauth::from_env().expect("Failed to create an identity provider from the environment");

    rt.block_on(
        session
            .get_json(osauth::services::COMPUTE, &["servers"], None)
            .map(|servers: ServersRoot| {
                for srv in servers.servers {
                    println!("ID = {}, Name = {}", srv.id, srv.name);
                }
                println!("Done listing")
            }),
    )
    .expect("Execution failed");
}
