// Copyright 2022 Dmitry Tantsur <dtantsur@protonmail.com>
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

//! Useful macros for definiting protocol structures.

/// A macro for defining serializable and deserializable protocol enums.
///
/// `Clone`, `Copy`, `Debug`, `Serialize`/`Deserialize` and equality traits are
/// automatically derived.
///
/// The easiest variant assumes that the carrier type is a string:
///
/// ```rust
/// osauth::protocol_enum! {
///     #[doc = "Possible image statuses."]
///     enum ImageStatus {
///         Queued = "queued",
///         Saving = "saving",
///         Active = "active",
///         Killed = "killed",
///         Deleted = "deleted",
///         Deactivated = "deactivated"
///     }
/// }
/// ```
///
/// The second variant assumes a non-string carrier type, which must be (de-)serializable:
///
/// ```rust
/// osauth::protocol_enum! {
///     #[doc = "Possible power states."]
///     enum ServerPowerState: u8 {
///         NoState = 0,
///         Running = 1,
///         Paused = 3,
///         Shutdown = 4,
///         Crashed = 6,
///         Suspended = 7
///     }
/// }
/// ```
///
/// These two variants produce a failure when an unknown value is deserialized. If you expect
/// the underlying enumeration to be extended in the future, provide a default value:
///
/// ```rust
/// osauth::protocol_enum! {
///     #[doc = "Possible image statuses."]
///     #[non_exhaustive]
///     enum ImageStatus = Unknown {
///         Queued = "queued",
///         Saving = "saving",
///         Active = "active",
///         Killed = "killed",
///         Deleted = "deleted",
///         Deactivated = "deactivated",
///         Unknown = "unknown"
///     }
/// }
///
/// osauth::protocol_enum! {
///     #[doc = "Possible power states."]
///     #[non_exhaustive]
///     enum ServerPowerState: u8 = NoState {
///         NoState = 0,
///         Running = 1,
///         Paused = 3,
///         Shutdown = 4,
///         Crashed = 6,
///         Suspended = 7
///     }
/// }
/// ```
#[macro_export]
macro_rules! protocol_enum {
    {$(#[$attr:meta])* enum $name:ident: $carrier:ty {
        $($(#[$iattr:meta])* $item:ident = $val:expr),+
    }} => (
        $crate::protocol_enum! {
            $(#[$attr])*
            __private $name: $carrier {
                $($(#[$iattr])* $item = $val),+
            }
        }

        impl<'de> ::serde::de::Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
                    where D: ::serde::de::Deserializer<'de> {
                let value: $carrier = ::serde::de::Deserialize::deserialize(deserializer)?;
                match value {
                    $($val => Ok($name::$item)),+,
                    other => {
                        use ::serde::de::Error;
                        let err = format!("Unexpected {}: {}", stringify!($name), other);
                        Err(D::Error::custom(err))
                    }
                }
            }
        }

        impl ::serde::ser::Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> ::std::result::Result<S::Ok, S::Error>
                    where S: ::serde::ser::Serializer {
                <$carrier>::from(*self).serialize(serializer)
            }
        }
    );

    {$(#[$attr:meta])* enum $name:ident: $carrier:ty = $default:ident {
        $($(#[$iattr:meta])* $item:ident = $val:expr),+
    }} => (
        $crate::protocol_enum! {
            $(#[$attr])*
            __private $name: $carrier {
                $($(#[$iattr])* $item = $val),+
            }
        }

        impl Default for $name {
            fn default() -> $name {
                $name::$default
            }
        }

        impl<'de> ::serde::de::Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
                    where D: ::serde::de::Deserializer<'de> {
                let value: $carrier = ::serde::de::Deserialize::deserialize(deserializer)?;
                Ok(match value {
                    $($val => $name::$item),+,
                    _ => Default::default()
                })
            }
        }

        impl ::serde::ser::Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> ::std::result::Result<S::Ok, S::Error>
                    where S: ::serde::ser::Serializer {
                <$carrier>::from(*self).serialize(serializer)
            }
        }
    );

    {$(#[$attr:meta])* enum $name:ident {
        $($(#[$iattr:meta])* $item:ident = $val:expr),+
    }} => (
        $crate::protocol_enum! {
            $(#[$attr])*
            __private $name: String {
                $($(#[$iattr])* $item = $val),+
            }
        }

        impl<'de> ::serde::de::Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
                    where D: ::serde::de::Deserializer<'de> {
                match String::deserialize(deserializer)?.as_ref() {
                    $($val => Ok($name::$item)),+,
                    other => {
                        use ::serde::de::Error;
                        let err = format!("Unexpected {}: {}",
                                          stringify!($name), other);
                        Err(D::Error::custom(err))
                    }
                }
            }
        }

        impl ::serde::ser::Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> ::std::result::Result<S::Ok, S::Error>
                    where S: ::serde::ser::Serializer {
                serializer.serialize_str(
                    match *self {
                        $($name::$item => $val),+,
                    }
                )
            }
        }
    );

    {$(#[$attr:meta])* enum $name:ident = $default:ident {
        $($(#[$iattr:meta])* $item:ident = $val:expr),+
    }} => (
        $crate::protocol_enum! {
            $(#[$attr])*
            __private $name: String {
                $($(#[$iattr])* $item = $val),+
            }
        }

        impl Default for $name {
            fn default() -> $name {
                $name::$default
            }
        }

        impl<'de> ::serde::de::Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
                    where D: ::serde::de::Deserializer<'de> {
                Ok(match String::deserialize(deserializer)?.as_ref() {
                    $($val => $name::$item),+,
                    _ => Default::default()
                })
            }
        }

        impl ::serde::ser::Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> ::std::result::Result<S::Ok, S::Error>
                    where S: ::serde::ser::Serializer {
                serializer.serialize_str(
                    match *self {
                        $($name::$item => $val),+,
                    }
                )
            }
        }
    );

    {$(#[$attr:meta])* __private $name:ident: $carrier:ty {
        $($(#[$iattr:meta])* $item:ident = $val:expr),+
    }} => (
        $(#[$attr])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum $name {
            $($(#[$iattr])* $item),+,
        }

        impl From<$name> for $carrier {
            /// Converts the enum to the carrier value.
            fn from(value: $name) -> $carrier {
                match value {
                    $($name::$item => $val.into()),+,
                }
            }
        }

        impl ::std::fmt::Display for $name {
            /// Displays the underlying protocol value.
            fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
                <$carrier>::from(*self).fmt(f)
            }
        }
    );
}

#[cfg(test)]
pub mod test {
    use serde_json;

    use crate::protocol_enum;

    protocol_enum! {
        enum ImageStatus {
            Queued = "queued",
            Saving = "saving",
            Active = "active",
            Killed = "killed",
            Deleted = "deleted",
            Deactivated = "deactivated"
        }
    }

    #[test]
    fn test_string() {
        assert_eq!("active", &String::from(ImageStatus::Active));
        assert_eq!("active", ImageStatus::Active.to_string());
        assert_eq!(
            ImageStatus::Active,
            serde_json::from_str("\"active\"").unwrap()
        );
        assert_eq!(
            "\"active\"",
            serde_json::to_string(&ImageStatus::Active).unwrap()
        );
        assert!(serde_json::from_str::<ImageStatus>("\"banana\"").is_err());
        assert!(serde_json::from_str::<ImageStatus>("42").is_err());
        assert_eq!(ImageStatus::Active, ImageStatus::Active);
        assert!(!(ImageStatus::Queued == ImageStatus::Active));
    }

    protocol_enum! {
        enum ServerPowerState: u8 {
            NoState = 0,
            Running = 1,
            Paused = 3,
            Shutdown = 4,
            Crashed = 6,
            Suspended = 7
        }
    }

    #[test]
    fn test_carrier() {
        assert_eq!(1, u8::from(ServerPowerState::Running));
        assert_eq!("1", ServerPowerState::Running.to_string());
        assert_eq!(
            ServerPowerState::Running,
            serde_json::from_str("1").unwrap()
        );
        assert_eq!(
            "1",
            serde_json::to_string(&ServerPowerState::Running).unwrap()
        );
        assert!(serde_json::from_str::<ServerPowerState>("\"banana\"").is_err());
        assert!(serde_json::from_str::<ServerPowerState>("42").is_err());
        assert_eq!(ServerPowerState::Running, ServerPowerState::Running);
        assert!(!(ServerPowerState::NoState == ServerPowerState::Running));
    }

    protocol_enum! {
        #[non_exhaustive]
        enum ImageStatusWithDefault = Unknown {
            Queued = "queued",
            Saving = "saving",
            Active = "active",
            Killed = "killed",
            Deleted = "deleted",
            Deactivated = "deactivated",
            Unknown = "unknown"
        }
    }

    #[test]
    fn test_string_with_default() {
        assert_eq!("active", &String::from(ImageStatusWithDefault::Active));
        assert_eq!("active", ImageStatusWithDefault::Active.to_string());
        assert_eq!(
            ImageStatusWithDefault::Active,
            serde_json::from_str("\"active\"").unwrap()
        );
        assert_eq!(
            "\"active\"",
            serde_json::to_string(&ImageStatusWithDefault::Active).unwrap()
        );
        assert_eq!(
            ImageStatusWithDefault::Unknown,
            ImageStatusWithDefault::default()
        );
        assert_eq!(
            ImageStatusWithDefault::Unknown,
            serde_json::from_str("\"banana\"").unwrap()
        );
        assert!(serde_json::from_str::<ImageStatusWithDefault>("42").is_err());
    }

    protocol_enum! {
        #[non_exhaustive]
        enum ServerPowerStateWithDefault: u8 = NoState {
            NoState = 0,
            Running = 1,
            Paused = 3,
            Shutdown = 4,
            Crashed = 6,
            Suspended = 7
        }
    }

    #[test]
    fn test_carrier_with_default() {
        assert_eq!(1, u8::from(ServerPowerStateWithDefault::Running));
        assert_eq!("1", ServerPowerStateWithDefault::Running.to_string());
        assert_eq!(
            ServerPowerStateWithDefault::Running,
            serde_json::from_str("1").unwrap()
        );
        assert_eq!(
            "1",
            serde_json::to_string(&ServerPowerStateWithDefault::Running).unwrap()
        );
        assert_eq!(
            ServerPowerStateWithDefault::NoState,
            ServerPowerStateWithDefault::default()
        );
        assert_eq!(
            ServerPowerStateWithDefault::NoState,
            serde_json::from_str("42").unwrap()
        );
        assert!(serde_json::from_str::<ServerPowerStateWithDefault>("\"banana\"").is_err());
    }
}
