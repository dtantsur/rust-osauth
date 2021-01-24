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

static DATA: u8 = 42;

#[tokio::main]
async fn main() {
    env_logger::init();
    let adapter = osauth::Adapter::from_env(osauth::services::OBJECT_STORAGE)
        .expect("Failed to create an identity provider from the environment");

    adapter
        .put_empty(&["rust-osauth-test"], None)
        .await
        .expect("Failed to create a container");

    println!("Writing {} to rust-osauth-test/test-object", DATA);
    adapter
        .put_json(&["rust-osauth-test", "test-object"], DATA, None)
        .await
        .expect("Failed to start a PUT request")
        .send()
        .await
        .expect("Failed to save an object");

    let res: u8 = adapter
        .get_json(&["rust-osauth-test", "test-object"], None)
        .await
        .expect("Failed to download an object");
    println!("Received {} back", res);
}
