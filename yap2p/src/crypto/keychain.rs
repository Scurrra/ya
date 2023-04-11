//! KeyChain for storing encryption keys
//! 
//! [`KeyChain`] is blockchain, used for storing keys for
//! encryption and decryption. It is our proposed way to
//! not use asymmetric cryptography, what helps to reduce
//! network load.

use sha2::{Sha256, Digest};

use std::sync::Mutex;

use super::dh::DH;
use crate::peer::Peer;

/// YAP2P keychain structure
pub struct KeyChain {
    top: Mutex<[u8; 32]>
}

impl KeyChain {
    /// Costructor for new [`KeyChain`] from `key_0` 256-bit hash
    /// 
    /// # Arguments
    /// 
    /// * `init` --- `key_0` 256-bit hash as `[u8; 32]`
    pub fn new(init: [u8; 32]) -> KeyChain {
        KeyChain { 
            top: Mutex::new(init)
        }
    }

    /// Costructor for new [`KeyChain`] from peer
    /// 
    /// # Arguments
    /// 
    /// * `peer` --- [`Peer`] you start to communicate with
    /// * `dh` --- Diffie-Hellman struct of this [`Peer`]
    pub fn new_from_peer(peer: Peer, dh: DH) -> KeyChain {
        KeyChain { 
            top: Mutex::new(dh.get_key_0_sha256(peer))
        }
    }

    /// Obtain current encryption key
    pub fn current(&self) -> [u8; 32] {
        *self.top.lock().unwrap()
    }

    /// Update encryption key
    /// 
    /// # Arguments
    /// 
    /// * `block` --- data for key updating; in this library it is a message hash 
    /// (not a message to not share private data with other parts of library)
    pub fn update(&self, block: [u8; 32]) {
        let mut top = self.top.lock().unwrap();
        
        let mut hasher = Sha256::new();
        hasher.update(*top);
        hasher.update(block);

        *top = hasher.finalize().into();
    }
}