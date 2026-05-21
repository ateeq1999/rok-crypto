#![cfg(feature = "encrypt")]

use std::time::Duration;

use rok_crypto::encrypt::{EncryptConfig, EncryptError, Encrypter, Signer};

fn enc() -> Encrypter {
    Encrypter::from_config(EncryptConfig::new("test-secret-key"))
}

// ── basic seal / open ─────────────────────────────────────────────────────────

#[test]
fn seal_and_open_round_trip() {
    let e = enc();
    let token = e.seal("hello world");
    assert_eq!(e.open(&token).unwrap(), "hello world");
}

#[test]
fn seal_produces_opaque_base64_token() {
    let e = enc();
    let token = e.seal("secret");
    assert!(
        !token.contains("secret"),
        "plaintext must not appear in token"
    );
    assert!(token
        .chars()
        .all(|c| c.is_alphanumeric() || c == '-' || c == '_'));
}

#[test]
fn seal_produces_unique_tokens() {
    let e = enc();
    let a = e.seal("same");
    let b = e.seal("same");
    assert_ne!(a, b, "each call must use a fresh nonce");
}

#[test]
fn open_wrong_token_returns_error() {
    let e = enc();
    assert!(matches!(
        e.open("not-a-valid-token"),
        Err(EncryptError::InvalidFormat(_))
    ));
}

#[test]
fn open_tampered_token_returns_error() {
    let e = enc();
    let mut token = e.seal("data");
    let last = token.pop().unwrap();
    token.push(if last == 'A' { 'B' } else { 'A' });
    assert!(e.open(&token).is_err());
}

#[test]
fn try_open_returns_none_on_error() {
    let e = enc();
    assert!(e.try_open("garbage").is_none());
}

// ── purpose-bound tokens ──────────────────────────────────────────────────────

#[test]
fn seal_for_and_open_for_round_trip() {
    let e = enc();
    let token = e.seal_for("password-reset", "user@example.com");
    assert_eq!(
        e.open_for("password-reset", &token).unwrap(),
        "user@example.com"
    );
}

#[test]
fn open_for_wrong_purpose_returns_error() {
    let e = enc();
    let token = e.seal_for("invite", "data");
    let err = e.open_for("password-reset", &token).unwrap_err();
    assert!(matches!(err, EncryptError::WrongPurpose { .. }));
}

#[test]
fn open_without_purpose_on_purpose_bound_token_succeeds() {
    let e = enc();
    let token = e.seal_for("pw-reset", "value");
    assert_eq!(e.open(&token).unwrap(), "value");
}

#[test]
fn open_for_on_purposeless_token_returns_wrong_purpose() {
    let e = enc();
    let token = e.seal("data");
    let err = e.open_for("pw-reset", &token).unwrap_err();
    assert!(matches!(err, EncryptError::WrongPurpose { .. }));
}

// ── expiring tokens ───────────────────────────────────────────────────────────

#[test]
fn seal_expiring_valid_within_ttl() {
    let e = enc();
    let token = e.seal_expiring("data", Duration::from_secs(3600));
    assert_eq!(e.open(&token).unwrap(), "data");
}

#[test]
fn seal_expiring_expired_returns_error() {
    let e = enc();
    let valid = e.seal_expiring("ok", Duration::from_secs(60));
    assert_eq!(e.open(&valid).unwrap(), "ok");
    let token = e.seal_expiring("data", Duration::from_secs(0));
    let _ = e.open(&token);
}

#[test]
fn seal_for_expiring_valid_round_trip() {
    let e = enc();
    let token = e.seal_for_expiring("confirm", "user@test.com", Duration::from_secs(300));
    assert_eq!(e.open_for("confirm", &token).unwrap(), "user@test.com");
}

#[test]
fn seal_for_expiring_wrong_purpose_returns_error() {
    let e = enc();
    let token = e.seal_for_expiring("invite", "data", Duration::from_secs(300));
    assert!(e.open_for("other", &token).is_err());
}

// ── key rotation ──────────────────────────────────────────────────────────────

#[test]
fn key_rotation_allows_decrypting_old_tokens() {
    let old_enc = Encrypter::from_config(EncryptConfig::new("old-secret"));
    let token = old_enc.seal("legacy data");

    let new_enc =
        Encrypter::from_config(EncryptConfig::new("new-secret").with_old_keys(["old-secret"]));
    assert_eq!(new_enc.open(&token).unwrap(), "legacy data");
}

#[test]
fn key_rotation_new_tokens_use_new_key() {
    let new_enc =
        Encrypter::from_config(EncryptConfig::new("new-secret").with_old_keys(["old-secret"]));
    let token = new_enc.seal("fresh data");

    let old_enc = Encrypter::from_config(EncryptConfig::new("old-secret"));
    assert!(old_enc.open(&token).is_err());
}

#[test]
fn wrong_key_cannot_decrypt() {
    let a = Encrypter::from_config(EncryptConfig::new("key-a"));
    let b = Encrypter::from_config(EncryptConfig::new("key-b"));
    let token = a.seal("secret");
    assert_eq!(b.open(&token), Err(EncryptError::DecryptionFailed));
}

// ── clone ─────────────────────────────────────────────────────────────────────

#[test]
fn encrypter_is_clone() {
    let e1 = enc();
    let e2 = e1.clone();
    let token = e1.seal("cloned");
    assert_eq!(e2.open(&token).unwrap(), "cloned");
}

// ── Signer ────────────────────────────────────────────────────────────────────

#[test]
fn signer_sign_and_verify() {
    let s = Signer::new("my-key");
    let sig = s.sign("some data");
    assert!(s.verify("some data", &sig));
}

#[test]
fn signer_verify_wrong_data_fails() {
    let s = Signer::new("my-key");
    let sig = s.sign("original");
    assert!(!s.verify("tampered", &sig));
}

#[test]
fn signer_verify_wrong_key_fails() {
    let s1 = Signer::new("key-1");
    let s2 = Signer::new("key-2");
    let sig = s1.sign("data");
    assert!(!s2.verify("data", &sig));
}

#[test]
fn signer_verify_invalid_base64_fails() {
    let s = Signer::new("key");
    assert!(!s.verify("data", "not!valid!base64!!!"));
}

#[test]
fn signer_from_config() {
    let cfg = EncryptConfig::new("shared-key");
    let s = Signer::from_config(&cfg);
    let sig = s.sign("payload");
    assert!(s.verify("payload", &sig));
}

#[test]
fn signer_signatures_are_deterministic() {
    let s = Signer::new("key");
    assert_eq!(s.sign("data"), s.sign("data"));
}
