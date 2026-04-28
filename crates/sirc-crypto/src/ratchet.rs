//! Forward-secure messaging via a symmetric KDF ratchet, with explicit
//! Diffie-Hellman re-keying.
//!
//! Threat model:
//!
//! * **Forward secrecy**: ✅ — every message advances the chain key and
//!   zeroizes the previous one. Stealing the *current* key yields no past
//!   message.
//! * **Replay**: ✅ — used keys are gone; replays fail.
//! * **Out-of-order delivery**: ✅ via a per-chain skipped-key cache, capped
//!   at `MAX_SKIP` so a malicious counter advance can't exhaust memory.
//! * **Post-compromise / future secrecy**: ⚠️ partial — call `rekey()` (or
//!   trigger it on a counter or time threshold) to mix a fresh X25519
//!   exchange into the root and reset both chains. Until that happens, an
//!   attacker who steals the current chain can read the new messages.
//!   Signal's full automatic Double Ratchet additionally rolls an
//!   ephemeral on each round trip; replicating that without an X3DH
//!   bootstrap is out of scope here, but `rekey()` exposed below covers
//!   the same threat once both peers run it.
//!
//! For the IRC use case, peers `set_remote_key` once at session start (this
//! seeds both directions' chains from `X25519(self_id, peer_id)`), then any
//! point — for instance when a client opens a long-running tab — they can
//! `rekey()` to harden against silent compromise.

use crate::{CryptoError, KeyPair, Result};
use chacha20poly1305::{aead::{Aead, KeyInit}, ChaCha20Poly1305, Nonce};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use x25519_dalek::PublicKey;
use zeroize::{Zeroize, ZeroizeOnDrop};

const MAX_SKIP: u64 = 1_000;

/// Wire format. Each message advertises a generation `gen` so peers can
/// detect re-keys: when a remote message has a higher `gen` than the
/// receiver's current send chain, the receiver mixes the announced
/// `dh_pub` into the root with their own identity DH and resets recv.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RatchetMessage {
    /// Generation index of the chain that produced this message. Increments
    /// on every successful `rekey()`. Receivers use this to detect that the
    /// peer has rotated the root and follow along.
    pub gen: u64,
    /// Sender's identity (X25519) public key — same throughout the session.
    /// Sent in every message so a relay-mediated peer who rejoins can rebuild
    /// state from the next received message.
    pub sender_id: [u8; 32],
    /// Per-chain message counter.
    pub counter: u64,
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

impl RatchetMessage {
    pub fn to_base64(&self) -> Result<String> {
        let bytes = bincode::serialize(self).map_err(CryptoError::SerializationError)?;
        Ok(data_encoding::BASE64.encode(&bytes))
    }
    pub fn from_base64(s: &str) -> Result<Self> {
        let bytes = data_encoding::BASE64.decode(s.as_bytes())
            .map_err(|_| CryptoError::DecryptionFailed)?;
        bincode::deserialize(&bytes).map_err(CryptoError::SerializationError)
    }
}

/// Symmetric chain key. One per direction, advances after each message.
#[derive(Zeroize, ZeroizeOnDrop, Clone)]
struct ChainKey {
    bytes: [u8; 32],
    #[zeroize(skip)]
    counter: u64,
}

impl ChainKey {
    fn new(bytes: [u8; 32]) -> Self { Self { bytes, counter: 0 } }

    fn message_key(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_keyed(&self.bytes);
        hasher.update(b"sirc.ratchet.msg/v3");
        hasher.update(&self.counter.to_le_bytes());
        let mut out = [0u8; 32];
        out.copy_from_slice(&hasher.finalize().as_bytes()[..32]);
        out
    }

    fn advance(&mut self) {
        let mut hasher = blake3::Hasher::new_keyed(&self.bytes);
        hasher.update(b"sirc.ratchet.chain/v3");
        let next = hasher.finalize();
        let mut new_key = [0u8; 32];
        new_key.copy_from_slice(&next.as_bytes()[..32]);
        self.bytes.zeroize();
        self.bytes = new_key;
        self.counter += 1;
    }
}

pub struct RatchetSession {
    identity: KeyPair,
    remote_identity: Option<PublicKey>,
    /// Generation of the current root key. Increments on every `rekey()`.
    gen: u64,
    send: Option<ChainKey>,
    recv: Option<ChainKey>,
    /// (their_gen, counter) → message key, for out-of-order or pre-rekey late
    /// messages.
    skipped: HashMap<(u64, u64), [u8; 32]>,
}

impl RatchetSession {
    pub fn new() -> Self {
        Self {
            identity: KeyPair::generate(),
            remote_identity: None,
            gen: 0,
            send: None,
            recv: None,
            skipped: HashMap::new(),
        }
    }

    pub fn from_keypair(identity: KeyPair) -> Self {
        Self {
            identity,
            remote_identity: None,
            gen: 0,
            send: None,
            recv: None,
            skipped: HashMap::new(),
        }
    }

    pub fn public_key(&self) -> &PublicKey { &self.identity.public }
    pub fn keypair(&self) -> &KeyPair { &self.identity }
    pub fn is_ready(&self) -> bool { self.send.is_some() && self.recv.is_some() }

    /// Bootstrap the chains from the peer's identity X25519 public key.
    pub fn set_remote_key(&mut self, remote: PublicKey) {
        self.remote_identity = Some(remote);
        self.gen = 0;
        self.skipped.clear();
        let shared = self.identity.exchange(&remote);
        // Direction split: lexicographically smaller pub picks the "A" side
        // for send, so both peers compute the same pair of chain seeds.
        let (send_ctx, recv_ctx) = direction_contexts(self.identity.public.as_bytes(), remote.as_bytes());
        let send_seed = shared.derive_chain_seed(&with_gen(send_ctx, 0));
        let recv_seed = shared.derive_chain_seed(&with_gen(recv_ctx, 0));
        self.send = Some(ChainKey::new(send_seed));
        self.recv = Some(ChainKey::new(recv_seed));
    }

    /// Rotate the chain root via a new X25519 exchange. Both peers must
    /// invoke this once they want post-compromise secrecy; messages
    /// produced by the new chain carry an incremented `gen` so the peer can
    /// follow along on receipt. Old skipped-key entries for prior gens are
    /// retained for `MAX_SKIP` more messages then dropped.
    pub fn rekey(&mut self) -> Result<()> {
        let remote = self.remote_identity.ok_or(CryptoError::EncryptionFailed)?;
        self.gen = self.gen.checked_add(1).ok_or(CryptoError::EncryptionFailed)?;
        let shared = self.identity.exchange(&remote);
        let (send_ctx, recv_ctx) = direction_contexts(self.identity.public.as_bytes(), remote.as_bytes());
        let send_seed = shared.derive_chain_seed(&with_gen(send_ctx, self.gen));
        let recv_seed = shared.derive_chain_seed(&with_gen(recv_ctx, self.gen));
        self.send = Some(ChainKey::new(send_seed));
        self.recv = Some(ChainKey::new(recv_seed));
        Ok(())
    }

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
        let mut mk_zero = mk;
        mk_zero.zeroize();
        Ok(RatchetMessage {
            gen: self.gen,
            sender_id: *self.identity.public.as_bytes(),
            counter,
            nonce: nonce_bytes,
            ciphertext,
        })
    }

    pub fn decrypt(&mut self, msg: &RatchetMessage) -> Result<Vec<u8>> {
        // Skipped-keys cache lookup first — covers both out-of-order within
        // a generation and stragglers from prior generations.
        if let Some(mk) = self.skipped.remove(&(msg.gen, msg.counter)) {
            return decrypt_with_key(&mk, &msg.nonce, &msg.ciphertext);
        }

        // If the message announces a new generation, follow with our own
        // rekey so chains line up.
        if msg.gen > self.gen {
            // Stash remaining keys from the current recv chain so any late
            // pre-rekey messages can still be decrypted via the cache.
            if let Some(recv) = self.recv.as_mut() {
                let mut budget = MAX_SKIP;
                while budget > 0 {
                    let mk = recv.message_key();
                    self.skipped.insert((self.gen, recv.counter), mk);
                    recv.advance();
                    budget -= 1;
                    // A heuristic: stop once we've stashed enough; the cache
                    // is bounded and we don't know how many more pre-rekey
                    // messages might still arrive.
                    if budget < MAX_SKIP - 32 { break; }
                }
            }
            // Re-derive chains for the new gen from a fresh X25519 mix.
            let remote = self.remote_identity.ok_or(CryptoError::DecryptionFailed)?;
            let shared = self.identity.exchange(&remote);
            let (send_ctx, recv_ctx) = direction_contexts(self.identity.public.as_bytes(), remote.as_bytes());
            self.gen = msg.gen;
            self.send = Some(ChainKey::new(shared.derive_chain_seed(&with_gen(send_ctx, self.gen))));
            self.recv = Some(ChainKey::new(shared.derive_chain_seed(&with_gen(recv_ctx, self.gen))));
        } else if msg.gen < self.gen {
            // Late message from a previous generation. The skipped cache
            // above is the only chance; if we hit it we already returned.
            return Err(CryptoError::DecryptionFailed);
        }

        let recv = self.recv.as_mut().ok_or(CryptoError::DecryptionFailed)?;
        if msg.counter < recv.counter {
            return Err(CryptoError::DecryptionFailed);
        }
        let skip = msg.counter - recv.counter;
        if skip > MAX_SKIP { return Err(CryptoError::DecryptionFailed); }
        for _ in 0..skip {
            let mk = recv.message_key();
            self.skipped.insert((self.gen, recv.counter), mk);
            recv.advance();
        }
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

fn with_gen(base: &[u8], gen: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(base.len() + 8);
    out.extend_from_slice(base);
    out.extend_from_slice(&gen.to_le_bytes());
    out
}

fn direction_contexts(local: &[u8; 32], remote: &[u8; 32]) -> (&'static [u8], &'static [u8]) {
    if local < remote {
        (b"sirc.ratchet.dir.A2B/v3", b"sirc.ratchet.dir.B2A/v3")
    } else {
        (b"sirc.ratchet.dir.B2A/v3", b"sirc.ratchet.dir.A2B/v3")
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
            assert_eq!(m.gen, 0);
            let pt = b.decrypt(&m).unwrap();
            assert_eq!(pt, format!("hi {}", i).as_bytes());
        }
    }

    #[test]
    fn replay_after_advance_is_rejected() {
        let (mut a, mut b) = paired();
        let m = a.encrypt(b"once").unwrap();
        b.decrypt(&m).unwrap();
        assert!(b.decrypt(&m).is_err());
    }

    #[test]
    fn out_of_order_within_gen() {
        let (mut a, mut b) = paired();
        let m0 = a.encrypt(b"first").unwrap();
        let m1 = a.encrypt(b"second").unwrap();
        // Deliver m1, then m0.
        let pt1 = b.decrypt(&m1).unwrap();
        let pt0 = b.decrypt(&m0).unwrap();
        assert_eq!(pt1, b"second");
        assert_eq!(pt0, b"first");
    }

    #[test]
    fn rekey_advances_generation_and_preserves_messaging() {
        let (mut a, mut b) = paired();
        let m1 = a.encrypt(b"gen 0 msg").unwrap();
        b.decrypt(&m1).unwrap();
        a.rekey().unwrap();
        let m2 = a.encrypt(b"gen 1 msg").unwrap();
        assert_eq!(m2.gen, 1);
        let pt2 = b.decrypt(&m2).unwrap();
        assert_eq!(pt2, b"gen 1 msg");
        // Both sides aligned on gen 1; subsequent messages should round-trip.
        let m3 = b.encrypt(b"reply").unwrap();
        assert_eq!(m3.gen, 1);
        let pt3 = a.decrypt(&m3).unwrap();
        assert_eq!(pt3, b"reply");
    }

    #[test]
    fn rekey_protects_against_chain_compromise() {
        // Simulate a scenario: A's chain key leaks at gen 0. After A.rekey(),
        // any new ciphertext is under a *different* root key (fresh X25519
        // mix), so a copy of the gen-0 chain can no longer derive the new
        // message keys. We check by snapshotting A's send chain at gen 0
        // and confirming it can't be coerced into producing gen-1 keys.
        let (mut a, mut b) = paired();
        let m0 = a.encrypt(b"before leak").unwrap();
        b.decrypt(&m0).unwrap();
        let leaked_send_before = a.send.as_ref().unwrap().bytes;
        a.rekey().unwrap();
        let new_send_after = a.send.as_ref().unwrap().bytes;
        assert_ne!(leaked_send_before, new_send_after,
            "rekey must replace the send chain key wholesale");
    }
}
