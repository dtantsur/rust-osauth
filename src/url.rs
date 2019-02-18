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

//! Handy primitives for working with URLs.

#![allow(dead_code)]

use reqwest::Url;

#[inline]
#[allow(unused_results)]
pub fn is_root(url: &Url) -> bool {
    url.path_segments().unwrap().any(|x| !x.is_empty())
}

#[inline]
#[allow(unused_results)]
pub fn join(mut url: Url, other: &str) -> Url {
    url.path_segments_mut().unwrap().pop_if_empty().push(other);
    url
}

#[inline]
#[allow(unused_results)]
pub fn extend<I>(mut url: Url, segments: I) -> Url
where
    I: IntoIterator,
    I::Item: AsRef<str>,
{
    url.path_segments_mut()
        .unwrap()
        .pop_if_empty()
        .extend(segments);
    url
}

#[inline]
#[allow(unused_results)]
pub fn pop(mut url: Url, keep_slash: bool) -> Url {
    url.path_segments_mut().unwrap().pop_if_empty().pop();
    if keep_slash {
        url.path_segments_mut().unwrap().pop_if_empty().push("");
    }
    url
}
