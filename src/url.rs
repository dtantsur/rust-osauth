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

//! Handy primitives for working with URLs.

#![allow(unused_results)]

use reqwest::Url;

#[inline]
pub fn is_root(url: &Url) -> bool {
    !url.path_segments().unwrap().any(|x| !x.is_empty())
}

#[inline]
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
pub fn pop(mut url: Url) -> Url {
    url.path_segments_mut()
        .expect("Invalid URL")
        .pop_if_empty()
        .pop()
        .pop_if_empty()
        .push("");
    url
}

/// Merges host, port, path and scheme from the source URL.
pub fn merge(dest: &mut Url, src: &Url) {
    // This function is called on URLs verified in EndpointCache, so unwraps are okay.
    dest.set_scheme(src.scheme()).unwrap();
    dest.set_host(src.host_str()).unwrap();
    dest.set_port(src.port()).unwrap();
    let existing: Vec<String> = dest.path_segments().unwrap().map(str::to_string).collect();
    dest.path_segments_mut()
        .unwrap()
        .clear()
        .extend(src.path_segments().unwrap())
        .pop_if_empty()
        .extend(existing);
}

#[cfg(test)]
mod test {
    use reqwest::Url;

    use super::*;

    #[test]
    fn test_is_root() {
        assert!(is_root(&Url::parse("https://example.com").unwrap()));
        assert!(is_root(&Url::parse("https://example.com/").unwrap()));
    }

    #[test]
    fn test_is_not_root() {
        assert!(!is_root(&Url::parse("https://example.com/v1/").unwrap()));
        assert!(!is_root(
            &Url::parse("https://example.com/v2/project_id").unwrap()
        ));
    }

    #[test]
    fn test_pop() {
        assert_eq!(
            pop(Url::parse("https://example.com/v1").unwrap()).as_str(),
            "https://example.com/"
        );
        assert_eq!(
            pop(Url::parse("https://example.com/v1/").unwrap()).as_str(),
            "https://example.com/"
        );
        assert_eq!(
            pop(Url::parse("https://example.com/v1/foobar").unwrap()).as_str(),
            "https://example.com/v1/"
        );
        assert_eq!(
            pop(Url::parse("https://example.com/v1/foobar/").unwrap()).as_str(),
            "https://example.com/v1/"
        );
    }

    #[test]
    fn test_merge_host_only() {
        let mut dest = Url::parse("http://compute").unwrap();
        let src = Url::parse("https://example.com").unwrap();
        merge(&mut dest, &src);
        assert_eq!(dest.as_str(), "https://example.com/");
    }

    #[test]
    fn test_merge_with_port() {
        let mut dest = Url::parse("http://compute").unwrap();
        let src = Url::parse("https://example.com:5050").unwrap();
        merge(&mut dest, &src);
        assert_eq!(dest.as_str(), "https://example.com:5050/");
    }

    #[test]
    fn test_merge_existing_path() {
        let mut dest = Url::parse("http://compute/path/1").unwrap();
        let src = Url::parse("https://example.com").unwrap();
        merge(&mut dest, &src);
        assert_eq!(dest.as_str(), "https://example.com/path/1");
    }

    #[test]
    fn test_merge_new_path() {
        let mut dest = Url::parse("http://compute").unwrap();
        let src = Url::parse("https://example.com/compute").unwrap();
        merge(&mut dest, &src);
        assert_eq!(dest.as_str(), "https://example.com/compute/");
    }

    #[test]
    fn test_merge_combine_args() {
        let mut dest = Url::parse("http://compute/?answer=42").unwrap();
        let src = Url::parse("https://example.com").unwrap();
        merge(&mut dest, &src);
        assert_eq!(dest.as_str(), "https://example.com/?answer=42");
    }

    #[test]
    fn test_merge_combine_path() {
        let mut dest = Url::parse("http://compute/path/1").unwrap();
        let src = Url::parse("https://example.com/compute").unwrap();
        merge(&mut dest, &src);
        assert_eq!(dest.as_str(), "https://example.com/compute/path/1");
    }

    #[test]
    fn test_merge_combine_everything() {
        let mut dest = Url::parse("http://compute/path/1/?foo=bar,answer=42").unwrap();
        let src = Url::parse("https://example.com:5050/compute/").unwrap();
        merge(&mut dest, &src);
        assert_eq!(
            dest.as_str(),
            "https://example.com:5050/compute/path/1/?foo=bar,answer=42"
        );
    }
}
