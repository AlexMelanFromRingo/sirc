//! Forward-secure messaging via a symmetric KDF ratchet.
//!
//! This is a deliberately small subset of the Signal Double Ratchet — only
//! the *symmetric* (KDF) ratchet, which is enough to provide forward secrecy:
//! once a message has been processed, the chain key is replaced and the old
//! key zeroized. Compromise of the *current* chain therefore cannot reveal
//! any previously transmitted plaintext.
//!
//! Threat model recap:
//! * Forward secrecy: ✅ — past messages stay safe even if the chain key
//!   leaks now (the key that produced them was overwritten).
//! * Future / break-in recovery: ❌ — if the current chain leaks, the
//!   attacker can still read every future message until both peers re-key
//!   (e.g. by performing a fresh X25519 exchange). The Double Ratchet's
//!   second (DH) ratchet is what would close this gap; not implemented here.
//! * Out-of-order delivery: handled via skipped-message keys, capped to
//!   prevent a denial-of-service via huge counter jumps.

use crate::{CryptoError, KeyPair, Result, SharedSecret};
use chacha20poly1305::{aead::{Aead, KeyInit}, ChaCha20Poly1305, Nonce};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use x25519_dalek::PublicKey;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Maximum number of skipped messages we'll cache forward keys for. Beyond
/// this we drop the message — protects against an attacker advancing the
/// counter to exhaust memory.
const MAX_SKIP: u64 = 1_000;

/// One direction of the ratchet — either send or receive.
#[derive(Zeroize, ZeroizeOnDrop)]
struct ChainKey {
    bytes: [u8; 32],
    /// Counter increments after every message *key* derived from this chain.
    #[zeroize(skip)]
    counter: u64,
}

impl ChainKey {
    fn new(bytes: [u8; 32]) -> Self {
        Self { bytes, counter: 0 }
    }

    /// Derive the per-message symmetric key for the current counter without
    /// advancing the chain. Used so the receiver can verify the message before
    /// committing the ratchet step.
    fn message_key(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_keyed(&self.bytes);
        hasher.update(b"sirc.ratchet.msg/v1");
        hasher.update(&self.counter.to_le_bytes());
        let mk = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&mk.as_bytes()[..32]);
        out
    }

    /// Advance to the next chain key. Old key is overwritten.
    fn advance(&mut self) {
        let mut hasher = blake3::Hasher::new_keyed(&self.bytes);
        hasher.update(b"sirc.ratchet.chain/v1");
        let next = hasher.finalize();
        let mut new_key = [0u8; 32];
        new_key.copy_from_slice(&next.as_bytes()[..32]);
        // zeroize the old material before overwriting.
        self.bytes.zeroize();
        self.bytes = new_key;
        self.counter += 1;
    }
}

/// Wire format for a ratcheted message. The counter pinpoints which chain key
/// derived `ciphertext`'s symmetric key, so the receiver can advance its
/// chain or look up a cached skipped key.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RatchetMessage {
    pub counter: u64,
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

impl RatchetMessage {
    /// Serialize with bincode, then base64 — same envelope as `EncryptedMessage`.
    pub fn to_base64(&self) -> Result<String> {
        let bytes = bincode::serialize(self).map_err(CryptoError::SerializationError)?;
        Ok(data_encoding::BASE64.encode(&bytes))
    }

    pub fn from_base64(s: &str) -> Result<Self> {
        let bytes = data_encoding::BASE64
            .decode(s.as_bytes())
            .map_err(|_| CryptoError::DecryptionFailed)?;
        bincode::deserialize(&bytes).map_err(CryptoError::SerializationError)
    }
}

/// A forward-secure session between two peers. Each direction has its own
/// chain so a roving attacker who learns one direction's key cannot decrypt
/// the other.
pub struct RatchetSession {
    local_keypair: KeyPair,
    remote_public: Option<PublicKey>,
    send: Option<ChainKey>,
    recv: Option<ChainKey>,
    /// Cache of (counter -> message key) for messages that arrived ahead of
    /// the current recv counter, so we can decrypt out-of-order delivery.
    skipped: HashMap<u64, [u8; 32]>,
}

impl RatchetSession {
    pub fn new() -> Self {
        Self {
            local_keypair: KeyPair::generate(),
            remote_public: None,
            send: None,
            recv: None,
            skipped: HashMap::new(),
        }
    }

    pub fn from_keypair(keypair: KeyPair) -> Self {
        Self {
            local_keypair: keypair,
            remote_public: None,
            send: None,
            recv: None,
            skipped: HashMap::new(),
        }
    }

    pub fn public_key(&self) -> &PublicKey {
        &self.local_keypair.public
    }

    pub fn keypair(&self) -> &KeyPair {
        &self.local_keypair
    }

    pub fn is_ready(&self) -> bool {
        self.send.is_some() && self.recv.is_some()
    }

    /// Initialise the two chain keys from the X25519 shared secret. The
    /// "smaller" public key picks the send context; both peers compute the
    /// same pair of chains by ordering their pubs lexicographically. This
    /// removes the need for a separate role-negotiation roundtrip.
    pub fn set_remote_key(&mut self, remote: PublicKey) {
        let shared: SharedSecret = self.local_keypair.exchange(&remote);
        let (send_ctx, recv_ctx) = direction_contexts(&self.local_keypair.public, &remote);
        let send_seed = derive_seed(&shared, send_ctx);
        let recv_seed = derive_seed(&shared, recv_ctx);
        self.send = Some(ChainKey::new(send_seed));
        self.recv = Some(ChainKey::new(recv_seed));
        self.remote_public = Some(remote);
        self.skipped.clear();
    }

    /// Encrypt a payload, advancing the send chain.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<RatchetMessage> {
        let send = self.send.as_mut().ok_or(CryptoError::EncryptionFailed)?;
        let counter = send.counter;
        let mk = send.message_key();
        let cipher = ChaCha20Poly1305::new((&mk).into());
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|_| CryptoError::EncryptionFailed)?;
        send.advance();
        // mk is on the stack; clear it before drop.
        let mut mk_zero = mk;
        mk_zero.zeroize();
        Ok(RatchetMessage { counter, nonce: nonce_bytes, ciphertext })
    }

    /// Decrypt a payload, advancing the recv chain to match the message's
    /// counter. Out-of-order messages are buffered up to `MAX_SKIP`.
    pub fn decrypt(&mut self, msg: &RatchetMessage) -> Result<Vec<u8>> {
        // Late message — try the skipped-key cache first.
        if let Some(mk) = self.skipped.remove(&msg.counter) {
            return decrypt_with_key(&mk, &msg.nonce, &msg.ciphertext);
        }

        let recv = self.recv.as_mut().ok_or(CryptoError::DecryptionFailed)?;

        if msg.counter < recv.counter {
            // The chain has already moved past this message and the key
            // wasn't cached — caller cannot recover it (forward secrecy).
            return Err(CryptoError::DecryptionFailed);
        }

        let skip = msg.counter - recv.counter;
        if skip > MAX_SKIP {
            return Err(CryptoError::DecryptionFailed);
        }

        // Stash keys for messages we're about to step over.
        for _ in 0..skip {
            let mk = recv.message_key();
            self.skipped.insert(recv.counter, mk);
            recv.advance();
        }

        // Now `recv.counter == msg.counter`.
        let mk = recv.message_key();
        let plaintext = decrypt_with_key(&mk, &msg.nonce, &msg.ciphertext)?;
        recv.advance();
        Ok(plaintext)
    }
}

impl Default for RatchetSession {
    fn default() -> Self { Self::new() }
}

fn decrypt_with_key(mk: &[u8; 32], nonce: &[u8; 12], ct: &[u8]) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(mk.into());
    let nonce = Nonce::from_slice(nonce);
    cipher.decrypt(nonce, ct).map_err(|_| CryptoError::DecryptionFailed)
}

fn derive_seed(shared: &SharedSecret, context: &[u8]) -> [u8; 32] {
    shared.derive_chain_seed(context)
}

fn direction_contexts(local: &PublicKey, remote: &PublicKey) -> (&'static [u8], &'static [u8]) {
    if local.as_bytes() < remote.as_bytes() {
        (b"sirc.ratchet.dir.A2B/v1", b"sirc.ratchet.dir.B2A/v1")
    } else {
        (b"sirc.ratchet.dir.B2A/v1", b"sirc.ratchet.dir.A2B/v1")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn paired() -> (RatchetSession, RatchetSession) {
        let mut a = RatchetSession::new();
        let mut b = RatchetSession::new();
        a.set_remote_key(*b.public_key());
        b.set_remote_key(*a.public_key());
        assert!(a.is_ready() && b.is_ready());
        (a, b)
    }

    #[test]
    fn round_trip_in_order() {
        let (mut a, mut b) = paired();
        for i in 0..10 {
            let m = a.encrypt(format!("hi {}", i).as_bytes()).unwrap();
            assert_eq!(m.counter, i);
            let pt = b.decrypt(&m).unwrap();
            assert_eq!(pt, format!("hi {}", i).as_bytes());
        }
    }

    #[test]
    fn keys_advance_each_message() {
        let (mut a, mut b) = paired();
        let m0 = a.encrypt(b"first").unwrap();
        let m1 = a.encrypt(b"second").unwrap();
        assert_ne!(m0.nonce, m1.nonce);
        assert_eq!(m0.counter, 0);
        assert_eq!(m1.counter, 1);
        // Out-of-order delivery: deliver m1 first, then m0.
        let pt1 = b.decrypt(&m1).unwrap();
        assert_eq!(pt1, b"second");
        let pt0 = b.decrypt(&m0).unwrap();
        assert_eq!(pt0, b"first");
    }

    #[test]
    fn replay_after_advance_is_rejected() {
        let (mut a, mut b) = paired();
        let m = a.encrypt(b"once").unwrap();
        b.decrypt(&m).unwrap();
        // Replaying the same message — chain has advanced, key is gone.
        assert!(b.decrypt(&m).is_err());
    }

    #[test]
    fn forward_secrecy_after_advance() {
        let (mut a, mut b) = paired();
        let m1 = a.encrypt(b"alpha").unwrap();
        // Receiver advances past m1's counter without ever decrypting it.
        // (Pretend m1 was lost; new messages still come in.)
        let m2 = a.encrypt(b"beta").unwrap();
        let pt2 = b.decrypt(&m2).unwrap();
        assert_eq!(pt2, b"beta");
        // Out-of-order: m1 still decryptable via skipped-key cache,
        // but the *current* chain key (used for m2 onwards) has been advanced.
        let pt1 = b.decrypt(&m1).unwrap();
        assert_eq!(pt1, b"alpha");
        // After both processed, the skipped-key cache is empty.
        assert!(b.skipped.is_empty(), "skipped keys must be consumed once used");
    }

    #[test]
    fn skip_cap_prevents_dos() {
        let (mut a, mut b) = paired();
        // Encrypt 1 message but advance counter on sender to MAX_SKIP+5.
        // Simulate by manually constructing a message with a huge counter.
        let bogus = RatchetMessage {
            counter: MAX_SKIP + 5,
            nonce: [0u8; 12],
            ciphertext: vec![],
        };
        assert!(b.decrypt(&bogus).is_err());
        // And dropping the bogus didn't poison the chain — a real message
        // still goes through.
        let m = a.encrypt(b"ok").unwrap();
        assert_eq!(b.decrypt(&m).unwrap(), b"ok");
    }
}
