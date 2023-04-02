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

//! A stream of resources.

use std::fmt::Debug;

use async_stream::try_stream;
use async_trait::async_trait;
use futures::pin_mut;
use futures::stream::{Stream, TryStreamExt};
use serde::de::DeserializeOwned;
use serde::Serialize;

use super::Error;

/// A single resource.
///
/// This trait can normally be derived. You need to
///
/// * add a `#[resource_id]` attribute to the field that serves as a pagination marker
/// * add a `#[collection_name = "resources"]` attribute to the structure with a name of
///   the field that is returned in the collection (e.g. "servers" for Compute servers).
/// * add a `#[flat_collection]` attribute to the structure if the root collection is flat,
///   the listing API returns an array instead of an object.
///
/// ```rust,no_run
/// use osauth::PaginatedResource;
/// use serde::Deserialize;
///
/// #[derive(Debug, Deserialize, PaginatedResource)]
/// #[collection_name = "servers"]
/// pub struct Server {
///     #[resource_id]
///     pub id: String,
///     pub name: String,
/// }
/// ```
///
/// The trait and its dependencies can be implemented manually like this:
///
/// ```rust,no_run
/// use serde::Deserialize;
///
/// #[derive(Debug, Deserialize)]
/// pub struct Server {
///     pub id: String,
///     pub name: String,
/// }
///
/// #[derive(Debug, Deserialize)]
/// pub struct ServersRoot {
///     pub servers: Vec<Server>,  // equivalent of #[collection_name = "servers"]
/// }
///
/// // This implementatin defines the relationship between the root resource and its items.
/// impl osauth::PaginatedResource for Server {
///     type Id = String;
///     type Root = ServersRoot;
///     fn resource_id(&self) -> Self::Id {
///         self.id.clone()  // equivalent of #[resource_id] on the `id` field
///     }
/// }
///
/// // This is another required part of the pagination contract.
/// impl From<ServersRoot> for Vec<Server> {
///     fn from(value: ServersRoot) -> Vec<Server> {
///         value.servers
///     }
/// }
/// ```
pub trait PaginatedResource {
    /// Type of an ID.
    type Id: Debug + Serialize + Send;

    /// Root type of the listing.
    type Root: DeserializeOwned + Send;

    /// Retrieve a copy of the ID.
    fn resource_id(&self) -> Self::Id;
}

#[async_trait]
pub(crate) trait FetchNext {
    async fn fetch_next<Q: Serialize + Send, T: DeserializeOwned + Send>(
        &self,
        query: Q,
    ) -> Result<T, Error>;
}

#[derive(Serialize)]
struct Query<T: Serialize + Send> {
    #[serde(skip_serializing_if = "Option::is_none")]
    limit: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    marker: Option<T>,
}

fn chunks<F, T>(
    builder: F,
    limit: Option<usize>,
    starting_with: Option<T::Id>,
) -> impl Stream<Item = Result<Vec<T>, Error>>
where
    F: FetchNext,
    T: PaginatedResource + Unpin,
    T::Root: Into<Vec<T>>,
{
    let mut marker = starting_with;

    try_stream! {
        loop {
            let result: T::Root = builder.fetch_next(Query{ limit: limit, marker: marker.take() }).await?;
            let items = result.into();
            if let Some(new_m) = items.last() {
                marker = Some(new_m.resource_id());
                yield items;
            } else {
                break
            }
        }
    }
}

/// Creates a paginated resource stream.
///
/// # Panics
///
/// Will panic during iteration if the request builder has a streaming body.
pub(crate) fn paginated<F, T>(
    builder: F,
    limit: Option<usize>,
    starting_with: Option<T::Id>,
) -> impl Stream<Item = Result<T, Error>>
where
    F: FetchNext,
    T: PaginatedResource + Unpin,
    T::Root: Into<Vec<T>>,
{
    try_stream! {
        let iter = chunks(builder, limit, starting_with);
        pin_mut!(iter);
        while let Some(chunk) = iter.try_next().await? {
            for item in chunk {
                yield item;
            }
        }
    }
}
