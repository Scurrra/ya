//! YAP2P crypto primitives
//! 
//! Module containce structures for [Diffie-Hellman](DH) public
//! key exchange.

use serde::{Serialize, Deserialize};
use rand::{thread_rng, Rng};
use sha2::{Sha256, Digest};

use crate::peer::{Peer};

/// Structure for storing configuration for [Diffie-Hellman](DH)
/// public key exchange[^dh-wiki]. One per application.
/// 
/// [^dh-wiki] [Diffie-Hellman key exchange](https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange).
#[derive(Serialize, Deserialize, Debug)]
pub struct DHConfig {
    /// Number to exponentiate
    base: u64,

    /// Field modulus. [PeerId](peer::PeerId) generation considers 
    /// 56-bit length number
    modulus: u64
}

impl DHConfig {
    /// Constructor fo [`DHConfig`]
    /// 
    /// # Arguments
    /// 
    /// * `base` --- Number to exponentiate
    /// * `modulus` --- Field modulus
    pub fn new(base: u64, modulus: u64) -> DHConfig {
        DHConfig { 
            base, 
            modulus
        }
    }

    /// `Base` getter
    pub fn base(&self) -> u64 {
        self.base
    }

    /// `Modulus` getter
    pub fn modulus(&self) -> u64 {
        self.base
    }

    /// Diffie-Hellman public key generator
    /// 
    /// # Arguments
    /// 
    /// * `private_key` --- [Peer]'s private key, stored in [`DH`]
    /// 
    /// Returns `public_key` as a number.
    pub fn generate_public_key(&self, private_key: u32) -> u64 {
        let log = self.modulus.ilog(self.base); 
        let public_key = if private_key < log {
            self.base.pow(private_key)
        } else {
            let mut A = self.base.pow(log);
            for _i in log..private_key {
                A = A * self.base % self.modulus;
            }
            A
        };
        
        public_key
    }

    /// Diffie-Hellman public key generator
    /// 
    /// # Arguments
    /// 
    /// * `private_key` --- [Peer]'s private key, stored in [`DH`]
    /// 
    /// Returns `public_key` as an `u8` array.
    pub fn generate_public_key_bytes(&self, private_key: u32) -> [u8; 8] {
        let log = self.modulus.ilog(self.base); 
        let public_key = if private_key < log {
            self.base.pow(private_key)
        } else {
            let mut A = self.base.pow(log);
            for _i in log..private_key {
                A = A * self.base % self.modulus;
            }
            A
        };
        
        public_key.to_be_bytes()
    }
}

/// Diffie-Hellman key exchange logic
pub struct DH {
    /// Configuration
    config: DHConfig,

    /// [`Peer`]'s private key, generated in [DH::new]
    private_key: u32
}

impl DH {
    /// Constructor for [`DH`]
    /// 
    /// # Arguments
    /// 
    /// * `DHConfig`
    pub fn new(dhc: DHConfig) -> DH {
        let mut rng = thread_rng();
        DH {
            config: dhc,
            private_key: rng.gen::<u16>() as u32
        }
    }

    /// `private_key` getter
    pub fn private_key(&self) -> u32 {
        self.private_key
    }

    /// Diffie-Hellman public key generator
    /// 
    /// Returns `public_key` as a number    
    pub fn generate_public_key(&self) -> u64 {        
        self.config.generate_public_key(self.private_key)
    }

    /// Diffie-Hellman public key generator
    /// 
    /// Returns `public_key` as an `u8` array.
    pub fn generate_public_key_bytes(&self) -> [u8; 8] {        
        self.config.generate_public_key_bytes(self.private_key)
    }

    /// Generator of start private key for packets' encryption
    /// 
    /// Returns key as a number
    pub fn get_key_0(&self, contact: Peer) -> u64 {
        let mut key0 = contact.get_public_key();
        for _i in 1..self.private_key {
            key0 = key0 * self.config.base % self.config.modulus;
        }

        key0
    }

    /// Generator of start private key for packets' encryption
    /// 
    /// Returns key's hash, used as encryption/decryption key.
    pub fn get_key_0_sha256(&self, contact: Peer) -> [u8; 32] {
        let mut key0 = contact.get_public_key();
        for _i in 1..self.private_key {
            key0 = key0 * self.config.base % self.config.modulus;
        }

        let mut hasher = Sha256::new();
        hasher.update(key0.to_be_bytes());
        let key0: [u8; 32] = hasher.finalize().into();
        key0
    }
}