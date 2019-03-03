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

use std::collections::HashMap;
use std::hash::Hash;
use std::ops::Deref;
use std::sync::RwLock;

/// Cached value.
#[derive(Debug)]
pub struct ValueCache<T>(RwLock<Option<T>>);

/// Cached map of values.
#[derive(Debug)]
pub struct MapCache<K: Hash + Eq, V>(RwLock<HashMap<K, V>>);

impl<T> ValueCache<T> {
    /// Create a cache.
    #[inline]
    pub fn new(value: Option<T>) -> ValueCache<T> {
        ValueCache(RwLock::new(value))
    }

    /// Ensure that the cached value is valid.
    ///
    /// Returns `true` if the value exists and passes the check.
    pub fn validate<F>(&self, check: F) -> bool
    where
        F: FnOnce(&T) -> bool,
    {
        let guard = self.0.read().expect("Cache lock is poisoned");
        if let Some(ref value) = guard.deref() {
            check(value)
        } else {
            false
        }
    }

    /// Extract a part of the value.
    #[inline]
    pub fn extract<F, R>(&self, filter: F) -> Option<R>
    where
        F: FnOnce(&T) -> R,
    {
        let guard = self.0.read().expect("Cache lock is poisoned");
        guard.as_ref().map(filter)
    }

    /// Set a new value.
    #[inline]
    pub fn set(&self, value: T) {
        let mut guard = self.0.write().expect("Cache lock is poisoned");
        *guard = Some(value)
    }

    /// Drop the value.
    #[inline]
    pub fn invalidate(&mut self) {
        *self.0.get_mut().expect("Cache lock is poisoned") = None;
    }
}

impl<T: Clone> Clone for ValueCache<T> {
    fn clone(&self) -> ValueCache<T> {
        let guard = self.0.read().expect("Cache lock is poisoned");
        ValueCache(RwLock::new(guard.clone()))
    }
}

impl<K: Hash + Eq, V> Default for MapCache<K, V> {
    fn default() -> MapCache<K, V> {
        MapCache(RwLock::new(HashMap::new()))
    }
}

impl<K: Hash + Eq, V> MapCache<K, V> {
    /// Extract a part of the value.
    #[inline]
    pub fn extract<F, R>(&self, key: &K, filter: F) -> Option<R>
    where
        F: FnOnce(&V) -> R,
    {
        let guard = self.0.read().expect("Cache lock is poisoned");
        guard.get(key).map(filter)
    }

    /// Whether a value is set.
    #[inline]
    pub fn is_set(&self, key: &K) -> bool {
        let guard = self.0.read().expect("Cache lock is poisoned");
        guard.contains_key(key)
    }

    /// Set a new value.
    #[inline]
    pub fn set(&self, key: K, value: V) {
        let mut guard = self.0.write().expect("Cache lock is poisoned");
        let _ = guard.insert(key, value);
    }
}

impl<K: Hash + Eq + Clone, V: Clone> Clone for MapCache<K, V> {
    fn clone(&self) -> MapCache<K, V> {
        let guard = self.0.read().expect("Cache lock is poisoned");
        MapCache(RwLock::new(guard.clone()))
    }
}
