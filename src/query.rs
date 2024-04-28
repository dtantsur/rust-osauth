// Copyright 2023 Dmitry Tantsur <dtantsur@protonmail.com>
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

use std::borrow::Cow;
use std::ops::{Deref, DerefMut};

use serde::ser::{Error as SerError, SerializeSeq};
use serde::{Serialize, Serializer};

/// An item in a query.
pub trait QueryItem {
    /// Represent the item for serialization into a query.
    ///
    /// The first item of the resulting tuple is a key, the second - its value.
    fn query_item(&self) -> Result<(&str, Cow<str>), crate::Error>;
}

/// A helper for queries.
///
/// The type `T` must implement [QueryItem](trait.QueryItem.html).
///
/// ```rust
/// use std::borrow::Cow;
/// use osauth::{Error, Query, QueryItem};
///
/// #[derive(Debug)]
/// enum MyQueryItem {
///     Str(String),
///     Bool(bool),
///     Int(i32),
/// }
///
/// impl QueryItem for MyQueryItem {
///     fn query_item(&self) -> Result<(&str, Cow<str>), Error> {
///         Ok(match self {
///             MyQueryItem::Str(s) => ("str", Cow::Borrowed(s)),
///             MyQueryItem::Bool(s) => ("bool", Cow::Owned(s.to_string())),
///             MyQueryItem::Int(s) => ("answer", Cow::Owned(s.to_string())),
///         })
///     }
/// }
///
/// let mut query = Query::default();
/// query.push(MyQueryItem::Bool(true));
/// query.push(MyQueryItem::Str("foo1".into()));
/// query.push(MyQueryItem::Int(42));
/// query.push(MyQueryItem::Str("foo2".into()));
/// let query_string = serde_urlencoded::to_string(query).expect("invalid query");
/// assert_eq!(&query_string, "bool=true&str=foo1&answer=42&str=foo2");
/// ```
///
/// It's usually better to derive `QueryItem` implementations:
///
/// ```rust
/// use osauth::{Error, Query, QueryItem};
///
/// #[derive(Debug, QueryItem)]
/// enum MyQueryItem {
///     Str(String),
///     Bool(bool),
///     #[query_item = "answer"]
///     Int(i32),
/// }
///
/// let mut query = Query::default();
/// query.push(MyQueryItem::Bool(true));
/// query.push(MyQueryItem::Str("foo1".into()));
/// query.push(MyQueryItem::Int(42));
/// query.push(MyQueryItem::Str("foo2".into()));
/// let query_string = serde_urlencoded::to_string(query).expect("invalid query");
/// assert_eq!(&query_string, "bool=true&str=foo1&answer=42&str=foo2");
/// ```
///
/// `Query` helps avoiding creating very large structures when only few query items are
/// normally used.
#[derive(Debug, Clone)]
pub struct Query<T>(pub Vec<T>);

impl<T> Default for Query<T> {
    fn default() -> Query<T> {
        Query(Vec::new())
    }
}

impl<T> Query<T> {
    /// Add a query item.
    #[inline]
    pub fn with(mut self, item: T) -> Self {
        self.0.push(item);
        self
    }
}

impl<T> Deref for Query<T> {
    type Target = Vec<T>;

    fn deref(&self) -> &Vec<T> {
        &self.0
    }
}

impl<T> DerefMut for Query<T> {
    fn deref_mut(&mut self) -> &mut Vec<T> {
        &mut self.0
    }
}

impl<T> Serialize for Query<T>
where
    T: QueryItem,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(self.len()))?;
        for e in &self.0 {
            let item = e.query_item().map_err(SerError::custom)?;
            seq.serialize_element(&item)?;
        }
        seq.end()
    }
}

#[cfg(test)]
pub mod test {
    use super::*;
    use crate::Error;

    #[derive(Debug)]
    #[allow(dead_code)]
    enum MyQueryItem {
        Foo(String),
        Bar(bool),
        Baz(String),
    }

    impl QueryItem for MyQueryItem {
        fn query_item(&self) -> Result<(&str, Cow<str>), Error> {
            Ok(match self {
                MyQueryItem::Foo(s) => ("foo", Cow::Borrowed(s)),
                MyQueryItem::Bar(b) => ("bar", b.to_string().into()),
                _ => unreachable!(),
            })
        }
    }

    #[test]
    fn test_query() {
        let mut q = Query::default();
        let _ = q.push(MyQueryItem::Bar(true));
        let _ = q.push(MyQueryItem::Foo("foo1".into()));
        let _ = q.push(MyQueryItem::Foo("foo2".into()));
        let s = serde_urlencoded::to_string(q).unwrap();
        assert_eq!(&s, "bar=true&foo=foo1&foo=foo2");
    }

    #[test]
    fn test_query_empty() {
        let q: Query<MyQueryItem> = Query::default();
        let s = serde_urlencoded::to_string(q).unwrap();
        assert_eq!(&s, "");
    }
}
