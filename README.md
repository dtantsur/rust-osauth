Asynchronous OpenStack session and authentication
=================================================

![CI](https://github.com/dtantsur/rust-osauth/workflows/CI/badge.svg)
[![License](https://img.shields.io/crates/l/osauth.svg)](https://github.com/dtantsur/rust-osauth/blob/master/LICENSE)
[![Latest
Version](https://img.shields.io/crates/v/osauth.svg)](https://crates.io/crates/osauth)
[![Documentation](https://img.shields.io/badge/documentation-latest-blueviolet.svg)](https://docs.rs/osauth)

The goal of this project is to provide an asynchronous API for HTTP requests
against OpenStack clouds. It provides support for various authentication
methods, service catalog queries, as well as for some OpenStack specific
concepts like microversions. The API is quite low level and does not provide
any ready-to-use objects (like `Server` or `Port`). Pagination is supported
but must be configured explicitly.

OpenStack releases starting with Queens are officially supported, although
support for releases older than 1.5 years is best-effort and may be dropped
without a prior warning (it will not be considered a breaking change).

For a more high-level (yet synchronous) API see
[rust-openstack](https://crates.io/crates/openstack).

Similarly to OpenStack itself, this project is licensed under Apache-2.0.
