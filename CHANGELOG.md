# Change Log

## 0.3.3  (2020-10-11)

#### Bug Fixes

*   repair and gate on the support for no-default-features ([cbb1078b](https://github.com/dtantsur/rust-osauth/commit/cbb1078b0a5f5a7d197393addc2743dccf9dd836))

#### Features

*   from_config/from_env directly on Session/SyncSession ([b033b37e](https://github.com/dtantsur/rust-osauth/commit/b033b37ef56b44bea221ede509547073de080781))
* **auth:**  suppor HTTP basic auth (for ironic) ([2cad612e](https://github.com/dtantsur/rust-osauth/commit/2cad612e206528c28e65c59fc6a906c0e290c76d))
* **config:**  support custom CA certificates ([a0efa046](https://github.com/dtantsur/rust-osauth/commit/a0efa046362519431464b2e20ca8451cfee32424))
* **session:**  support for endpoint overrides ([958a1330](https://github.com/dtantsur/rust-osauth/commit/958a133039d745655e7a4e90d862f2c1397576e4))

## 0.3.2 (2020-09-06)

#### Bug Fixes

*   several suspicious places detected by clippy ([c3d10c97](https://github.com/dtantsur/rust-osauth/commit/c3d10c97b09f3cb8bdaf63e3234e085d3aa1df47))

#### Features

*   Add support for clouds-public.yaml and secure.yaml (#16) ([2c3e4331](https://github.com/dtantsur/rust-osauth/commit/2c3e4331d64e86690885b5e23996a3e4da2231b8))

## 0.3.1 (2020-07-13)

#### Bug Fixes

* **config:**  read region from env (OS_REGION_NAME) when calling from_env ([d624ba40](https://github.com/dtantsur/rust-osauth/commit/d624ba407f9322a3a4cb519bef4d85983637fb65))
* **identity:**  Account for auth_urls with trailing slash (#14) ([d38c7827](https://github.com/dtantsur/rust-osauth/commit/d38c7827102dd4b682aa3f805987a358004a33ee))
* **protocol:**  fall-back to parent URL when doing service discovery (fixes #18) ([1cb0926a](https://github.com/dtantsur/rust-osauth/commit/1cb0926aca5c921bcaa7fbe3e476ee220408474c))

## 0.3.0 (2020-05-21)

#### Breaking Changes

* The library now uses async/await instead of explicit futures.
* A separate endpoint interface field is replaced by a new `EndpointFilters` structure everywhere.

Other:

*  remove deprecated user_name ([80125d0b](https://github.com/dtantsur/rust-osauth/commit/80125d0bbfa100e90f45f29c282c2b2203909d2e), breaks [#](https://github.com/dtantsur/rust-osauth/issues/))
*  enable project scope to take id or name (#10) ([c6b31f33](https://github.com/dtantsur/rust-osauth/commit/c6b31f3336bc25555423802f3c60aa054569c7c8), breaks [#](https://github.com/dtantsur/rust-osauth/issues/))

#### Features

*   add paginated query support ([a8bfdee6](https://github.com/dtantsur/rust-osauth/commit/a8bfdee6105cde19d2a5c4c4b03608319b173925))
*   switch to async/await ([e3a15093](https://github.com/dtantsur/rust-osauth/commit/e3a15093739b2a62c011125b19b64db9f3d2f952), breaks [#](https://github.com/dtantsur/rust-osauth/issues/))
* **auth:**  replace separate interface/region with endpoint filters ([4bcecd6c](https://github.com/dtantsur/rust-osauth/commit/4bcecd6c1947f21039cd928b6ef10eb875496d88), breaks [#](https://github.com/dtantsur/rust-osauth/issues/))
* **identity:**
  *  remove deprecated user_name ([80125d0b](https://github.com/dtantsur/rust-osauth/commit/80125d0bbfa100e90f45f29c282c2b2203909d2e), breaks [#](https://github.com/dtantsur/rust-osauth/issues/))
  *  add a separate Scope object ([24dcd3ca](https://github.com/dtantsur/rust-osauth/commit/24dcd3caeca55e807c84da59f51cda6257bcd9f4))
  *  enable project scope to take id or name (#10) ([c6b31f33](https://github.com/dtantsur/rust-osauth/commit/c6b31f3336bc25555423802f3c60aa054569c7c8), breaks [#](https://github.com/dtantsur/rust-osauth/issues/))

#### Bug Fixes

*   use async lock for caches and avoid Arc::clone ([04aad97f](https://github.com/dtantsur/rust-osauth/commit/04aad97fcc5fc40ecc2312e29c170fe21ec85c6d))

## 0.2.5 (2019-09-30)

#### Features

*   Expose rustls through a feature flag ([1a6190d](https://github.com/dtantsur/rust-osauth/commit/1a6190d463cee053eeeb2ee10bbdd3eec4338af8))
* **request:**  add NO_PATH ([703cd3d8](https://github.com/dtantsur/rust-osauth/commit/703cd3d8e276d7861941b8248f0a30c7f6f3ea21))
* **sync:**
  *  add SyncBody to convert Read into Stream ([e669a500](https://github.com/dtantsur/rust-osauth/commit/e669a500708f6b3c913e21ebba05fb67c3ab2a9b))
  *  implement download to read from body ([759c8d69](https://github.com/dtantsur/rust-osauth/commit/759c8d690431f42306b38da32b27cdec382392c5))

## 0.2.4 (2019-06-17)

#### Features

* **adapter:** add default_api_version ([2ec1e52](https://github.com/dtantsur/rust-osauth/commit/2ec1e52c34b1c837e2245425c1ccd5546ec717ab))

## 0.2.3 (2019-06-09)

#### Features

*   add SyncSession - a synchronous wrapper for Session ([36ad472d](https://github.com/dtantsur/rust-osauth/commit/36ad472dffcf238241a215b9489eda01f1492cba))
* **services:**  add support for ironic ([ae728f71](https://github.com/dtantsur/rust-osauth/commit/ae728f718d06b6381261148421018c0a3e969a48))

#### Bug Fixes

*   correct object-store example broken in the last merge ([d4b9d0a0](https://github.com/dtantsur/rust-osauth/commit/d4b9d0a04f622c43890f77eaad01aa65be2c9c0a))

## 0.2.2 (2019-05-06)

#### Features

*   introduce Adapter ([8c9e890d](https://github.com/dtantsur/rust-osauth/commit/8c9e890d415ff411c09bd485ad78fe5e5f537a85))
* **session:**  add into_adapter ([5019a7a9](https://github.com/dtantsur/rust-osauth/commit/5019a7a960c75b88ea8aa0dd0dc8d299a2003f84))

## 0.2.1 (2019-04-19)

#### Features

* **session:**  add get_query and get_json_query ([3e14f4fa](https://github.com/dtantsur/rust-osauth/commit/3e14f4fac70d48ab0b00350750ea210623975738))

## 0.2.0 (2019-04-11)

#### Breaking Changes

* **services:**
  *  change IMAGE and NETWORK to have their own types ([f6c38f33](https://github.com/dtantsur/rust-osauth/commit/f6c38f33a790537770d81a95c9e5e175ed4a5946))
  *  change set_api_version_headers to accept HeaderMap ([b6edf6b9](https://github.com/dtantsur/rust-osauth/commit/b6edf6b976860fa3e55c679c6341bb483843a00d))

#### Features

* **services:**
  *  support for object and block storage services ([da885d09](https://github.com/dtantsur/rust-osauth/commit/da885d090c386a3973ab4ab1629e1a8cc09060b8))

## 0.1.1 (2019-03-31)

#### Bug Fixes

* **session:**  short-cut pick\_api\_version on empty input ([744a5102](https://github.com/dtantsur/rust-osauth/commit/744a510228674b40b9d512e5f75d0488f19639fe))

#### Features

* **session:**
  *  accept IntoIterator in `pick_api_version` ([d19a4201](https://github.com/dtantsur/rust-osauth/commit/d19a42016ff85bc573d829c25d0d7bdbe3e6fd7a))
  *  add `refresh`, `set_auth_type` and `with_auth_type` ([80ea7579](https://github.com/dtantsur/rust-osauth/commit/80ea7579938e742930f938ea610530978bf99b4b))


## 0.1.0 (2019-03-16)

Initial version.
