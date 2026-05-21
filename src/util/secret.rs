use std::fmt;
use std::ops::Deref;

use zeroize::{Zeroize, ZeroizeOnDrop};

/// A byte array of size `N` that zeroizes its contents on drop.
///
/// Wraps `[u8; N]` and implements `Drop` + `ZeroizeOnDrop` so key material
/// is cleared from memory when the value goes out of scope.
///
/// # Example
///
/// ```rust
/// use rok_crypto::util::secret::SecretKey;
///
/// let key = SecretKey::<32>::new([0u8; 32]);
/// assert_eq!(key.len(), 32);
/// ```
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretKey<const N: usize>([u8; N]);

impl<const N: usize> SecretKey<N> {
    pub fn new(bytes: [u8; N]) -> Self {
        Self(bytes)
    }

    pub fn len(&self) -> usize {
        N
    }

    pub fn is_empty(&self) -> bool {
        N == 0
    }
}

impl<const N: usize> AsRef<[u8]> for SecretKey<N> {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<const N: usize> Deref for SecretKey<N> {
    type Target = [u8; N];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Display wrapper that shows `"***"` instead of the inner value.
///
/// Useful for secrets, keys, tokens that should never appear in logs.
///
/// Implements [`Zeroize`] for explicit clearing, but does **not**
/// auto-zeroize on drop so the inner value can be extracted via
/// [`into_inner`](Redacted::into_inner).
///
/// # Example
///
/// ```rust
/// use rok_crypto::util::secret::Redacted;
///
/// let secret = Redacted::new("my-secret-api-key".to_string());
/// assert_eq!(secret.to_string(), "***");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Zeroize)]
pub struct Redacted<T: Zeroize>(T);

impl<T: Zeroize> Redacted<T> {
    pub fn new(inner: T) -> Self {
        Self(inner)
    }

    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T: Zeroize> AsRef<T> for Redacted<T> {
    fn as_ref(&self) -> &T {
        &self.0
    }
}

impl<T: Zeroize> fmt::Display for Redacted<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("***")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_key_basic() {
        let key = SecretKey::<32>::new([0xABu8; 32]);
        assert_eq!(key.len(), 32);
        assert_eq!(key[0], 0xAB);
    }

    #[test]
    fn redacted_display_hides_value() {
        let r = Redacted::new("supersecret".to_string());
        assert_eq!(r.to_string(), "***");
    }

    #[test]
    fn redacted_into_inner() {
        let r = Redacted::new(String::from("hello"));
        assert_eq!(r.into_inner(), "hello");
    }
}
