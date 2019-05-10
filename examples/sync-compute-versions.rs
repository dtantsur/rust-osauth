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
extern crate osauth;

fn main() {
    env_logger::init();

    let session = osauth::sync::SyncSession::new(
        osauth::from_env().expect("Failed to create an identity provider from the environment"),
    );

    println!(
        "Compute major version is {:?}",
        session
            .get_major_version(osauth::services::COMPUTE)
            .expect("Cannot determine major version")
    );

    let maybe_versions = session
        .get_api_versions(osauth::services::COMPUTE)
        .expect("Cannot determine API versions");
    if let Some((min, max)) = maybe_versions {
        println!("Microversions: {} to {}", min, max);
    } else {
        println!("Microversions are not supported");
    }
}
