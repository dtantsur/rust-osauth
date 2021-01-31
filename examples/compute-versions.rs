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

#[tokio::main]
async fn main() {
    env_logger::init();
    let adapter = osauth::Adapter::from_env(osauth::services::COMPUTE)
        .await
        .expect("Failed to create an identity provider from the environment");

    let maybe_version = adapter
        .get_major_version()
        .await
        .expect("Failed to get major version");
    println!("Compute major version is {:?}", maybe_version);

    let maybe_versions = adapter
        .get_api_versions()
        .await
        .expect("Failed to get supported versions");
    if let Some((min, max)) = maybe_versions {
        println!("Microversions: {} to {}", min, max);
    } else {
        println!("Microversions are not supported");
    }
}
