#[cfg(feature = "zeroize")]
pub mod secret;

#[cfg(any(feature = "ids", feature = "encrypt"))]
pub mod rand;

pub mod from_env;

/// Generate `Display`, `FromStr`, `AsRef<str>`, and `Ord`/`PartialOrd`
/// for a newtype string ID.
///
/// The type must be a tuple struct wrapping a `String`.
///
/// # Example
///
/// ```rust,ignore
/// use rok_crypto::declare_id;
///
/// struct MyId(String);
/// declare_id!(MyId, "myid", 16);
///
/// let id = MyId("abcdef1234567890".to_string());
/// assert_eq!(id.as_str(), "abcdef1234567890");
/// ```
#[macro_export]
macro_rules! declare_id {
    ($name:ident, $kind:literal) => {
        $crate::declare_id!($name, $kind, 0);
    };
    ($name:ident, $kind:literal, $len:expr) => {
        impl $name {
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl std::str::FromStr for $name {
            type Err = $crate::ids::IdError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                let len = $len;
                if len > 0 && s.len() != len {
                    return Err($crate::ids::IdError::InvalidFormat($kind, "invalid length"));
                }
                Ok(Self(s.to_owned()))
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                &self.0
            }
        }

        impl std::cmp::PartialOrd for $name {
            fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
                Some(self.0.cmp(&other.0))
            }
        }

        impl std::cmp::Ord for $name {
            fn cmp(&self, other: &Self) -> std::cmp::Ordering {
                self.0.cmp(&other.0)
            }
        }
    };
}

/// Check two byte slices in constant time (no short-circuit on mismatch).
///
/// Useful for comparing MACs, signatures, or any secret values where
/// timing side-channels are a concern.
///
/// # Example
///
/// ```rust
/// use rok_crypto::constant_time_eq;
///
/// assert!(constant_time_eq!(b"abc", b"abc"));
/// assert!(!constant_time_eq!(b"abc", b"def"));
/// ```
#[macro_export]
macro_rules! constant_time_eq {
    ($a:expr, $b:expr) => {{
        let a = $a.as_ref();
        let b = $b.as_ref();
        if a.len() != b.len() {
            false
        } else {
            let mut r = 0u8;
            for (x, y) in a.iter().zip(b.iter()) {
                r |= x ^ y;
            }
            r == 0
        }
    }};
}
