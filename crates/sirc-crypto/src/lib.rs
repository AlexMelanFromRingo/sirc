//! SIRC Cryptography Module
//!
//! Provides end-to-end encryption using modern cryptographic primitives:
//! - X25519 for key exchange (ECDH)
//! - ChaCha20-Poly1305 for AEAD encryption
//! - BLAKE3 for key derivation

pub mod keystore;

use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    ChaCha20Poly1305, Nonce,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Encryption failed")]
    EncryptionFailed,

    #[error("Decryption failed")]
    DecryptionFailed,

    #[error("Invalid key length")]
    InvalidKeyLength,

    #[error("Invalid nonce length")]
    InvalidNonceLength,

    #[error("Serialization error: {0}")]
    SerializationError(#[from] bincode::Error),
}

pub type Result<T> = std::result::Result<T, CryptoError>;

/// Key pair for asymmetric encryption
#[derive(ZeroizeOnDrop)]
pub struct KeyPair {
    #[zeroize(skip)]
    pub public: PublicKey,
    secret: StaticSecret,
}

impl KeyPair {
    /// Generate a new random key pair
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        Self { public, secret }
    }

    /// Get public key as bytes
    pub fn public_bytes(&self) -> &[u8; 32] {
        self.public.as_bytes()
    }

    /// Get secret key bytes (for serialization only)
    pub(crate) fn secret_bytes(&self) -> [u8; 32] {
        self.secret.to_bytes()
    }

    /// Perform Diffie-Hellman key exchange
    pub fn exchange(&self, their_public: &PublicKey) -> SharedSecret {
        let shared = self.secret.diffie_hellman(their_public);
        SharedSecret::new(*shared.as_bytes())
    }
}

impl fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyPair")
            .field("public", &hex::encode(self.public_bytes()))
            .field("secret", &"<redacted>")
            .finish()
    }
}

/// Shared secret derived from key exchange
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SharedSecret {
    bytes: [u8; 32],
}

impl SharedSecret {
    fn new(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }

    /// Derive encryption key using BLAKE3
    pub fn derive_key(&self, context: &[u8]) -> EncryptionKey {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&self.bytes);
        hasher.update(context);
        let hash = hasher.finalize();

        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&hash.as_bytes()[..32]);

        EncryptionKey::new(key_bytes)
    }
}

/// Symmetric encryption key
#[derive(Zeroize, ZeroizeOnDrop, Clone)]
pub struct EncryptionKey {
    bytes: [u8; 32],
}

impl EncryptionKey {
    fn new(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }

    /// Encrypt data with this key
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<EncryptedMessage> {
        let cipher = ChaCha20Poly1305::new((&self.bytes).into());

        // Generate random nonce
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|_| CryptoError::EncryptionFailed)?;

        Ok(EncryptedMessage {
            nonce: nonce_bytes,
            ciphertext,
        })
    }

    /// Decrypt data with this key
    pub fn decrypt(&self, message: &EncryptedMessage) -> Result<Vec<u8>> {
        let cipher = ChaCha20Poly1305::new((&self.bytes).into());
        let nonce = Nonce::from_slice(&message.nonce);

        cipher
            .decrypt(nonce, message.ciphertext.as_ref())
            .map_err(|_| CryptoError::DecryptionFailed)
    }
}

/// Encrypted message with nonce
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EncryptedMessage {
    nonce: [u8; 12],
    ciphertext: Vec<u8>,
}

impl EncryptedMessage {
    /// Serialize to bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).map_err(Into::into)
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        bincode::deserialize(bytes).map_err(Into::into)
    }

    /// Encode as base64 for text transmission
    pub fn to_base64(&self) -> Result<String> {
        Ok(base64::STANDARD.encode(self.to_bytes()?))
    }

    /// Decode from base64
    pub fn from_base64(s: &str) -> Result<Self> {
        let bytes = base64::STANDARD
            .decode(s)
            .map_err(|_| CryptoError::DecryptionFailed)?;
        Self::from_bytes(&bytes)
    }
}

/// Session for encrypted communication
pub struct EncryptedSession {
    local_keypair: KeyPair,
    remote_public: Option<PublicKey>,
    shared_key: Option<EncryptionKey>,
}

impl EncryptedSession {
    /// Create a new session
    pub fn new() -> Self {
        Self {
            local_keypair: KeyPair::generate(),
            remote_public: None,
            shared_key: None,
        }
    }

    /// Create session from existing keypair
    pub fn from_keypair(keypair: KeyPair) -> Self {
        Self {
            local_keypair: keypair,
            remote_public: None,
            shared_key: None,
        }
    }

    /// Get local public key
    pub fn public_key(&self) -> &PublicKey {
        &self.local_keypair.public
    }

    /// Get reference to keypair (for persistence)
    pub fn keypair(&self) -> &KeyPair {
        &self.local_keypair
    }

    /// Set remote public key and derive shared secret
    pub fn set_remote_key(&mut self, remote_key: PublicKey) {
        let shared_secret = self.local_keypair.exchange(&remote_key);
        self.shared_key = Some(shared_secret.derive_key(b"sirc-v1"));
        self.remote_public = Some(remote_key);
    }

    /// Encrypt a message
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<EncryptedMessage> {
        self.shared_key
            .as_ref()
            .ok_or(CryptoError::EncryptionFailed)?
            .encrypt(plaintext)
    }

    /// Decrypt a message
    pub fn decrypt(&self, message: &EncryptedMessage) -> Result<Vec<u8>> {
        self.shared_key
            .as_ref()
            .ok_or(CryptoError::DecryptionFailed)?
            .decrypt(message)
    }

    /// Check if session is ready for encryption
    pub fn is_ready(&self) -> bool {
        self.shared_key.is_some()
    }
}

impl Default for EncryptedSession {
    fn default() -> Self {
        Self::new()
    }
}

// Add base64 module
mod base64 {
    use std::fmt;

    pub struct GeneralPurpose;

    impl GeneralPurpose {
        pub fn encode(&self, input: impl AsRef<[u8]>) -> String {
            data_encoding::BASE64.encode(input.as_ref())
        }

        pub fn decode(&self, input: impl AsRef<[u8]>) -> Result<Vec<u8>, DecodeError> {
            data_encoding::BASE64
                .decode(input.as_ref())
                .map_err(|_| DecodeError)
        }
    }

    pub const STANDARD: GeneralPurpose = GeneralPurpose;

    #[derive(Debug)]
    pub struct DecodeError;

    impl fmt::Display for DecodeError {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "Base64 decode error")
        }
    }

    impl std::error::Error for DecodeError {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let kp1 = KeyPair::generate();
        let kp2 = KeyPair::generate();
        assert_ne!(kp1.public_bytes(), kp2.public_bytes());
    }

    #[test]
    fn test_key_exchange() {
        let alice = KeyPair::generate();
        let bob = KeyPair::generate();

        let alice_shared = alice.exchange(&bob.public);
        let bob_shared = bob.exchange(&alice.public);

        // Both should derive the same key
        let alice_key = alice_shared.derive_key(b"test");
        let bob_key = bob_shared.derive_key(b"test");

        assert_eq!(alice_key.bytes, bob_key.bytes);
    }

    #[test]
    fn test_encryption_decryption() {
        let key = EncryptionKey::new([42u8; 32]);
        let plaintext = b"Hello, SIRC!";

        let encrypted = key.encrypt(plaintext).unwrap();
        let decrypted = key.decrypt(&encrypted).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_session_encryption() {
        let mut alice = EncryptedSession::new();
        let mut bob = EncryptedSession::new();

        // Exchange keys
        alice.set_remote_key(*bob.public_key());
        bob.set_remote_key(*alice.public_key());

        assert!(alice.is_ready());
        assert!(bob.is_ready());

        // Alice encrypts, Bob decrypts
        let plaintext = b"Secret message";
        let encrypted = alice.encrypt(plaintext).unwrap();
        let decrypted = bob.decrypt(&encrypted).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_base64_encoding() {
        let key = EncryptionKey::new([1u8; 32]);
        let plaintext = b"Test message";

        let encrypted = key.encrypt(plaintext).unwrap();
        let encoded = encrypted.to_base64().unwrap();
        let decoded = EncryptedMessage::from_base64(&encoded).unwrap();
        let decrypted = key.decrypt(&decoded).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }
}
