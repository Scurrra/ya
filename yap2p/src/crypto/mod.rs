use serde::{Serialize, Deserialize};
use rand::{thread_rng, Rng};
use sha2::{Sha256, Digest};

use crate::peer::{Peer};

#[derive(Serialize, Deserialize, Debug)]
pub struct DHConfig {
    base: u64,
    modulus: u64
}

impl DHConfig {
    pub fn new(base: u64, modulus: u64) -> DHConfig {
        DHConfig { 
            base, 
            modulus
        }
    }

    pub fn base(&self) -> u64 {
        self.base
    }

    pub fn modulus(&self) -> u64 {
        self.base
    }

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

pub struct DH {
    config: DHConfig,
    private_key: u32
}

impl DH {
    pub fn new(dhc: DHConfig) -> DH {
        let mut rng = thread_rng();
        DH {
            config: dhc,
            private_key: rng.gen::<u16>() as u32
        }
    }

    pub fn private_key(&self) -> u32 {
        self.private_key
    }

    pub fn generate_public_key(&self) -> u64 {        
        self.config.generate_public_key(self.private_key)
    }

    pub fn generate_public_key_bytes(&self) -> [u8; 8] {        
        self.config.generate_public_key_bytes(self.private_key)
    }

    pub fn get_key_0(&self, contact: Peer) -> u64 {
        let mut key0 = contact.get_public_key();
        for _i in 1..self.private_key {
            key0 = key0 * self.config.base % self.config.modulus;
        }

        key0
    }

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