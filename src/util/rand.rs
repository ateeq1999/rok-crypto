use rand::RngCore;

/// Generate a hex-encoded random string of `byte_len` bytes (result is `byte_len * 2` chars).
///
/// # Example
///
/// ```rust
/// use rok_crypto::util::rand::hex;
///
/// let h = hex(16);
/// assert_eq!(h.len(), 32);
/// assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
/// ```
pub fn hex(byte_len: usize) -> String {
    let mut bytes = vec![0u8; byte_len];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Generate a random alphanumeric string of `len` characters.
///
/// # Example
///
/// ```rust
/// use rok_crypto::util::rand::alphanumeric;
///
/// let s = alphanumeric(16);
/// assert_eq!(s.len(), 16);
/// assert!(s.chars().all(|c| c.is_ascii_alphanumeric()));
/// ```
pub fn alphanumeric(len: usize) -> String {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = rand::thread_rng();
    let mut result = String::with_capacity(len);
    for _ in 0..len {
        let idx = (rng.next_u32() as usize) % CHARSET.len();
        result.push(CHARSET[idx] as char);
    }
    result
}

/// Compare two byte slices in constant time.
///
/// Returns `true` if both slices have the same length and same contents.
/// The comparison takes the same amount of time regardless of where the
/// first mismatch occurs.
///
/// # Example
///
/// ```rust
/// use rok_crypto::util::rand::constant_time_eq;
///
/// assert!(constant_time_eq(b"abc", b"abc"));
/// assert!(!constant_time_eq(b"abc", b"abd"));
/// assert!(!constant_time_eq(b"abc", b"abcd")); // different lengths
/// ```
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut r = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        r |= x ^ y;
    }
    r == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_length() {
        assert_eq!(hex(0).len(), 0);
        assert_eq!(hex(8).len(), 16);
        assert_eq!(hex(32).len(), 64);
    }

    #[test]
    fn hex_is_hex() {
        let h = hex(16);
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn alphanumeric_length_and_charset() {
        let s = alphanumeric(32);
        assert_eq!(s.len(), 32);
        assert!(s.chars().all(|c| c.is_ascii_alphanumeric()));
    }

    #[test]
    fn constant_time_eq_matches() {
        assert!(constant_time_eq(b"", b""));
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"abcd"));
    }
}
