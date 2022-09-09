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

osauth::protocol_enum! {
    #[doc = "Possible image statuses."]
    #[non_exhaustive]
    enum ImageStatus = Unknown {
        Queued = "queued",
        Saving = "saving",
        Active = "active",
        Killed = "killed",
        Deleted = "deleted",
        Deactivated = "deactivated",
        Unknown = "unknown"
    }
}

#[derive(Debug, Deserialize)]
pub struct Image {
    pub id: String,
    pub name: String,
    pub status: ImageStatus,
}

#[derive(Debug, Deserialize)]
pub struct ImagesRoot {
    pub images: Vec<Image>,
}

#[tokio::main]
async fn main() {
    env_logger::init();
    let session = osauth::Session::from_env()
        .await
        .expect("Failed to create an identity provider from the environment");

    let images: ImagesRoot = session
        .get_json(osauth::services::IMAGE, &["images"])
        .await
        .expect("Failed to list images");
    for srv in images.images {
        println!("Name = {}, Status = {}", srv.name, srv.status);
    }
    println!("Done listing");
}
