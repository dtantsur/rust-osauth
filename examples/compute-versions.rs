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

fn main() {
    env_logger::init();

    let session =
        osauth::from_env().expect("Failed to create an identity provider from the environment");

    tokio::run(
        session
            .get_major_version(osauth::services::COMPUTE)
            .map(|maybe_version| {
                println!("Compute major version is {:?}", maybe_version);
            })
            .and_then(move |_| session.get_api_versions(osauth::services::COMPUTE))
            .map(|maybe_versions| {
                if let Some((min, max)) = maybe_versions {
                    println!("Microversions: {} to {}", min, max);
                } else {
                    println!("Microversions are not supported");
                }
            })
            .map_err(|e| {
                panic!("Failed: {}", e);
            }),
    );
}
