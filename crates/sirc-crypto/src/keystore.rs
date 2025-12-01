//! Persistent key storage for SIRC
//!
//! Saves and loads encryption keys to/from disk for session persistence

use crate::{CryptoError, EncryptedSession, KeyPair, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use x25519_dalek::{PublicKey, StaticSecret};

#[derive(Serialize, Deserialize)]
struct StoredKeyPair {
    public: [u8; 32],
    secret: [u8; 32],
}

#[derive(Serialize, Deserialize)]
struct KeyStore {
    identity: StoredKeyPair,
    peers: std::collections::HashMap<String, [u8; 32]>, // peer_id -> public_key
}

impl KeyStore {
    fn new(keypair: &KeyPair) -> Self {
        Self {
            identity: StoredKeyPair {
                public: *keypair.public.as_bytes(),
                secret: keypair.secret_bytes(),
            },
            peers: std::collections::HashMap::new(),
        }
    }
}

/// Manages persistent storage of encryption keys
pub struct PersistentKeyStore {
    path: PathBuf,
}

impl PersistentKeyStore {
    /// Create a new key store at the given path
    pub fn new<P: AsRef<Path>>(path: P) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
        }
    }

    /// Get default key store location
    pub fn default_path(username: &str) -> PathBuf {
        let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
        home.join(".sirc").join(format!("{}.keys", username))
    }

    /// Save a keypair to disk
    pub fn save_keypair(&self, keypair: &KeyPair) -> Result<()> {
        // Create directory if it doesn't exist
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)
                .map_err(|_| CryptoError::SerializationError(
                    bincode::Error::new(bincode::ErrorKind::Custom("Failed to create directory".to_string()))
                ))?;
        }

        let keystore = KeyStore::new(keypair);
        let serialized = serde_json::to_string_pretty(&keystore)
            .map_err(|_| CryptoError::SerializationError(
                bincode::Error::new(bincode::ErrorKind::Custom("JSON serialization failed".to_string()))
            ))?;

        fs::write(&self.path, serialized)
            .map_err(|_| CryptoError::SerializationError(
                bincode::Error::new(bincode::ErrorKind::Custom("Failed to write file".to_string()))
            ))?;

        // Set file permissions to user-only on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&self.path)
                .map_err(|_| CryptoError::SerializationError(
                    bincode::Error::new(bincode::ErrorKind::Custom("Failed to get metadata".to_string()))
                ))?
                .permissions();
            perms.set_mode(0o600);
            fs::set_permissions(&self.path, perms)
                .map_err(|_| CryptoError::SerializationError(
                    bincode::Error::new(bincode::ErrorKind::Custom("Failed to set permissions".to_string()))
                ))?;
        }

        Ok(())
    }

    /// Load a keypair from disk, or generate new one if not found
    pub fn load_or_generate(&self) -> Result<KeyPair> {
        if self.path.exists() {
            self.load_keypair()
        } else {
            let keypair = KeyPair::generate();
            self.save_keypair(&keypair)?;
            Ok(keypair)
        }
    }

    /// Load a keypair from disk
    pub fn load_keypair(&self) -> Result<KeyPair> {
        let data = fs::read_to_string(&self.path)
            .map_err(|_| CryptoError::SerializationError(
                bincode::Error::new(bincode::ErrorKind::Custom("Failed to read file".to_string()))
            ))?;

        let keystore: KeyStore = serde_json::from_str(&data)
            .map_err(|_| CryptoError::SerializationError(
                bincode::Error::new(bincode::ErrorKind::Custom("JSON deserialization failed".to_string()))
            ))?;

        let secret = StaticSecret::from(keystore.identity.secret);
        let public = PublicKey::from(keystore.identity.public);

        Ok(KeyPair { public, secret })
    }

    /// Save a peer's public key
    pub fn save_peer_key(&self, peer_id: &str, public_key: &PublicKey) -> Result<()> {
        let mut keystore: KeyStore = if self.path.exists() {
            let data = fs::read_to_string(&self.path)
                .map_err(|_| CryptoError::SerializationError(
                    bincode::Error::new(bincode::ErrorKind::Custom("Failed to read file".to_string()))
                ))?;
            serde_json::from_str(&data)
                .map_err(|_| CryptoError::SerializationError(
                    bincode::Error::new(bincode::ErrorKind::Custom("JSON deserialization failed".to_string()))
                ))?
        } else {
            return Err(CryptoError::SerializationError(
                bincode::Error::new(bincode::ErrorKind::Custom("Identity not found".to_string()))
            ));
        };

        keystore.peers.insert(peer_id.to_string(), *public_key.as_bytes());

        let serialized = serde_json::to_string_pretty(&keystore)
            .map_err(|_| CryptoError::SerializationError(
                bincode::Error::new(bincode::ErrorKind::Custom("JSON serialization failed".to_string()))
            ))?;

        fs::write(&self.path, serialized)
            .map_err(|_| CryptoError::SerializationError(
                bincode::Error::new(bincode::ErrorKind::Custom("Failed to write file".to_string()))
            ))?;

        Ok(())
    }

    /// Load a peer's public key
    pub fn load_peer_key(&self, peer_id: &str) -> Result<Option<PublicKey>> {
        if !self.path.exists() {
            return Ok(None);
        }

        let data = fs::read_to_string(&self.path)
            .map_err(|_| CryptoError::SerializationError(
                bincode::Error::new(bincode::ErrorKind::Custom("Failed to read file".to_string()))
            ))?;

        let keystore: KeyStore = serde_json::from_str(&data)
            .map_err(|_| CryptoError::SerializationError(
                bincode::Error::new(bincode::ErrorKind::Custom("JSON deserialization failed".to_string()))
            ))?;

        Ok(keystore
            .peers
            .get(peer_id)
            .map(|bytes| PublicKey::from(*bytes)))
    }

    /// Delete the keystore file
    pub fn delete(&self) -> Result<()> {
        if self.path.exists() {
            fs::remove_file(&self.path)
                .map_err(|_| CryptoError::SerializationError(
                    bincode::Error::new(bincode::ErrorKind::Custom("Failed to delete file".to_string()))
                ))?;
        }
        Ok(())
    }
}

/// Extension trait for EncryptedSession to support persistence
pub trait PersistentSession {
    /// Create session from stored keys
    fn from_keystore(keystore: &PersistentKeyStore) -> Result<EncryptedSession>;

    /// Save session keys to store
    fn save_to_keystore(&self, keystore: &PersistentKeyStore) -> Result<()>;
}

impl PersistentSession for EncryptedSession {
    fn from_keystore(keystore: &PersistentKeyStore) -> Result<EncryptedSession> {
        let keypair = keystore.load_or_generate()?;
        Ok(EncryptedSession::from_keypair(keypair))
    }

    fn save_to_keystore(&self, keystore: &PersistentKeyStore) -> Result<()> {
        let keypair = self.keypair();
        keystore.save_keypair(keypair)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn test_save_and_load_keypair() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.keys");
        let store = PersistentKeyStore::new(&path);

        let original = KeyPair::generate();
        store.save_keypair(&original).unwrap();

        let loaded = store.load_keypair().unwrap();
        assert_eq!(original.public_bytes(), loaded.public_bytes());
    }

    #[test]
    fn test_load_or_generate() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test2.keys");
        let store = PersistentKeyStore::new(&path);

        // First call generates new key
        let kp1 = store.load_or_generate().unwrap();
        assert!(path.exists());

        // Second call loads existing key
        let kp2 = store.load_or_generate().unwrap();
        assert_eq!(kp1.public_bytes(), kp2.public_bytes());
    }

    #[test]
    fn test_save_peer_key() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test3.keys");
        let store = PersistentKeyStore::new(&path);

        let identity = KeyPair::generate();
        store.save_keypair(&identity).unwrap();

        let peer_key = KeyPair::generate();
        store.save_peer_key("alice", &peer_key.public).unwrap();

        let loaded = store.load_peer_key("alice").unwrap().unwrap();
        assert_eq!(peer_key.public_bytes(), loaded.as_bytes());
    }

    #[test]
    fn test_file_permissions() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test4.keys");
        let store = PersistentKeyStore::new(&path);

        let kp = KeyPair::generate();
        store.save_keypair(&kp).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let metadata = fs::metadata(&path).unwrap();
            let permissions = metadata.permissions();
            assert_eq!(permissions.mode() & 0o777, 0o600);
        }
    }
}
