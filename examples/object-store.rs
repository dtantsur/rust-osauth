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
use tokio::runtime::Runtime;

static DATA: u8 = 42;

fn main() {
    env_logger::init();
    let mut rt = Runtime::new().expect("Cannot create a runtime");

    let adapter = osauth::Adapter::from_env(osauth::services::COMPUTE)
        .expect("Failed to create an identity provider from the environment");

    rt.block_on(
        adapter
            .put_empty(&["rust-osauth-test"], None)
            .and_then(move |_| {
                println!("Writing {} to rust-osauth-test/test-object", DATA);
                adapter
                    .put(&["rust-osauth-test", "test-object"], DATA, None)
                    .and_then(move |_| {
                        adapter
                            .get_json(&["rust-osauth-test", "test-object"], None)
                            .map(|res: u8| {
                                println!("Received {} back", res);
                            })
                    })
            }),
    )
    .expect("Execution failed");
}
