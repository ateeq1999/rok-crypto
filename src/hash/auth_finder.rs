/// Implemented by user/account model types that carry a stored password hash.
///
/// Allows [`Hasher`](crate::Hasher) to work directly with model references via
/// the `verify_for` and `needs_rehash_for` convenience methods.
///
/// # Example
///
/// ```rust,ignore
/// use rok_hash::AuthFinder;
///
/// pub struct User {
///     pub id:       i64,
///     pub email:    String,
///     pub password: String,
/// }
///
/// impl AuthFinder for User {
///     fn get_auth_password(&self) -> &str { &self.password }
/// }
/// ```
pub trait AuthFinder {
    /// Returns the stored password hash for this record.
    fn get_auth_password(&self) -> &str;
}
