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
pub struct Node {
    #[serde(rename = "uuid")]
    pub id: String,
    pub name: Option<String>,
    pub provision_state: String,
}

#[derive(Debug, Deserialize)]
pub struct NodesRoot {
    pub nodes: Vec<Node>,
}

#[tokio::main]
async fn main() {
    env_logger::init();
    let session = osauth::Session::from_env()
        .expect("Failed to create an identity provider from the environment");

    let nodes: NodesRoot = session
        .get_json(
            osauth::services::BAREMETAL,
            &["nodes"],
            Some(osauth::ApiVersion(1, 5)),
        )
        .await
        .expect("Failed to list nodes");
    for node in nodes.nodes {
        println!(
            "ID = {}, Name = {:?}, State = {}",
            node.id, node.name, node.provision_state
        );
    }
    println!("Done listing");
}
