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

//! Caching.

use std::cell::RefCell;
use std::collections::HashMap;
use std::hash::Hash;

/// Cached clone-able value.
#[derive(Debug, Clone)]
pub struct ValueCache<T>(RefCell<Option<T>>);

/// Cached map of values.
#[derive(Debug, Clone)]
pub struct MapCache<K: Hash + Eq, V>(RefCell<HashMap<K, V>>);

impl<T> ValueCache<T> {
    /// Create a cache.
    #[inline]
    pub fn new(value: Option<T>) -> ValueCache<T> {
        ValueCache(RefCell::new(value))
    }

    /// Ensure that the cached value is valid.
    ///
    /// Returns `true` if the value exists and passes the check.
    pub fn validate<F>(&self, check: F) -> bool
    where
        F: FnOnce(&T) -> bool,
    {
        match self.0.borrow().as_ref() {
            Some(v) => check(v),
            None => false,
        }
    }

    /// Extract a part of the value.
    #[inline]
    pub fn extract<F, R>(&self, filter: F) -> Option<R>
    where
        F: FnOnce(&T) -> R,
    {
        self.0.borrow().as_ref().map(filter)
    }

    /// Set a new value.
    #[inline]
    pub fn set(&self, value: T) {
        *self.0.borrow_mut() = Some(value);
    }
}

impl<K: Hash + Eq, V> Default for MapCache<K, V> {
    fn default() -> MapCache<K, V> {
        MapCache(RefCell::new(HashMap::new()))
    }
}

impl<K: Hash + Eq, V> MapCache<K, V> {
    /// Extract a part of the value.
    #[inline]
    pub fn extract<F, R>(&self, key: &K, filter: F) -> Option<R>
    where
        F: FnOnce(&V) -> R,
    {
        self.0.borrow().get(key).map(filter)
    }

    /// Whether a value is set.
    #[inline]
    pub fn is_set(&self, key: &K) -> bool {
        self.0.borrow().contains_key(key)
    }

    /// Set a new value.
    #[inline]
    pub fn set(&self, key: K, value: V) {
        let _ = self.0.borrow_mut().insert(key, value);
    }
}

impl<K: Hash + Eq, V: Clone> MapCache<K, V> {
    /// Get a clone of the value.
    #[inline]
    pub fn get(&self, key: &K) -> Option<V> {
        self.0.borrow().get(key).cloned()
    }
}
