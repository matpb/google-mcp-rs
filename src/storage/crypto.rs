//! AES-256-GCM seal/unseal with associated data (AAD).
//!
//! All refresh tokens at rest are sealed with the operator-supplied
//! `STORAGE_ENCRYPTION_KEY`, with the user's stable Google `sub` bound as
//! AAD so that swapping ciphertext between rows fails decryption.

use aes_gcm::aead::{Aead, OsRng, Payload};
use aes_gcm::{AeadCore, Aes256Gcm, Key, KeyInit, Nonce};

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("encryption failed")]
    Encrypt,
    #[error("decryption failed (wrong key, tampered ciphertext, or AAD mismatch)")]
    Decrypt,
    #[error("invalid nonce length")]
    InvalidNonce,
}

/// 12-byte random nonce + AES-256-GCM ciphertext (with appended 16-byte tag).
pub struct Sealed {
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

pub fn seal(key: &[u8; 32], aad: &[u8], plaintext: &[u8]) -> Result<Sealed, CryptoError> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, Payload { msg: plaintext, aad })
        .map_err(|_| CryptoError::Encrypt)?;
    Ok(Sealed {
        nonce: nonce.to_vec(),
        ciphertext,
    })
}

pub fn unseal(
    key: &[u8; 32],
    aad: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if nonce.len() != 12 {
        return Err(CryptoError::InvalidNonce);
    }
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Nonce::from_slice(nonce);
    cipher
        .decrypt(nonce, Payload { msg: ciphertext, aad })
        .map_err(|_| CryptoError::Decrypt)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> [u8; 32] {
        let mut k = [0u8; 32];
        for (i, b) in k.iter_mut().enumerate() {
            *b = i as u8;
        }
        k
    }

    #[test]
    fn round_trip() {
        let aad = b"user-sub-123";
        let plaintext = b"a-very-secret-google-refresh-token";
        let sealed = seal(&key(), aad, plaintext).expect("seal");
        let recovered = unseal(&key(), aad, &sealed.nonce, &sealed.ciphertext).expect("unseal");
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn nonces_are_unique_across_calls() {
        let aad = b"sub";
        let a = seal(&key(), aad, b"hi").unwrap();
        let b = seal(&key(), aad, b"hi").unwrap();
        assert_ne!(a.nonce, b.nonce, "nonces must not repeat");
        assert_ne!(a.ciphertext, b.ciphertext, "ciphertexts must differ");
    }

    #[test]
    fn aad_mismatch_fails() {
        let sealed = seal(&key(), b"sub-A", b"data").unwrap();
        let err = unseal(&key(), b"sub-B", &sealed.nonce, &sealed.ciphertext).unwrap_err();
        assert!(matches!(err, CryptoError::Decrypt));
    }

    #[test]
    fn wrong_key_fails() {
        let sealed = seal(&key(), b"sub", b"data").unwrap();
        let mut wrong = key();
        wrong[0] ^= 0xff;
        let err = unseal(&wrong, b"sub", &sealed.nonce, &sealed.ciphertext).unwrap_err();
        assert!(matches!(err, CryptoError::Decrypt));
    }

    #[test]
    fn tamper_detection() {
        let mut sealed = seal(&key(), b"sub", b"data").unwrap();
        sealed.ciphertext[0] ^= 0x01;
        let err = unseal(&key(), b"sub", &sealed.nonce, &sealed.ciphertext).unwrap_err();
        assert!(matches!(err, CryptoError::Decrypt));
    }

    #[test]
    fn invalid_nonce_length() {
        let sealed = seal(&key(), b"sub", b"data").unwrap();
        let err = unseal(&key(), b"sub", &[0u8; 8], &sealed.ciphertext).unwrap_err();
        assert!(matches!(err, CryptoError::InvalidNonce));
    }
}
