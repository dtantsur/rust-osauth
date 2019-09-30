# Change Log

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
