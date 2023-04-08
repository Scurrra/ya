use serde::{Serialize, Deserialize};
use sha2::{Sha512, Digest};

use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Mutex;

use crate::crypto::DH;

#[derive(Serialize, Deserialize, Debug)]
pub struct PeerId {
    inner: [u8; 16]
}

impl PeerId {
    pub fn new(username: &str, dh: DH) -> PeerId {
        let mut id = [0u8; 16];
        
        // 1st byte, may be should be constructor argument
        id[0] = 42u8 ^ 69u8;

        // 2-7 bytes
        let public_key_bytes = dh.generate_public_key_bytes();
        for i in 1..8 {
            id[i] = public_key_bytes[i];
        }

        // 9-16 bytes
        let mut hasher = Sha512::new();
        hasher.update(username);
        let result = hasher.finalize();
        for i in 0..8 {
            for j in 0..8 {
                id[8 + j] ^= result[i*8 + j];
            }
        }

        PeerId {
            inner: id
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Peer {
    pub id: PeerId,
    pub name: String
}

impl Peer {
    pub fn new(username: &str, dh: DH) -> Peer {
        Peer {
            id: PeerId::new(username, dh),
            name: String::from(username)
        }
    }

    pub fn get_public_key(&self) -> u64 {
        let mut be_bytes = [0u8; 8];
        for i in 1..8 {
            be_bytes[i] = self.id.inner[i];
        }

        u64::from_be_bytes(be_bytes)
    }
}

#[derive(Serialize, Deserialize, Debug, Copy, Clone)]
pub struct Addr {
    pub V4: Option<Ipv4Addr>,
    pub V6: Option<Ipv6Addr>
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Node {
    pub peer: Peer,
    pub device: u16,
    addrs: Mutex<Addr>
}

impl Node {
    pub fn new(peer: Peer, device: u16, addrs: Addr) -> Node {
        Node {
            peer,
            device,
            addrs: Mutex::new(addrs)
        }
    }

    pub fn set_ips(&self, ipv4: Option<Ipv4Addr>, ipv6: Option<Ipv6Addr>) {
        let mut ips = self.addrs.lock().unwrap();
        *ips = Addr {
            V4: ipv4,
            V6: ipv6
        };
    }

    pub fn set_ipv4(&self, ipv4: Option<Ipv4Addr>) {
        let mut ips = self.addrs.lock().unwrap();
        (*ips).V4 = ipv4;
    }

    pub fn set_ipv6(&self, ipv6: Option<Ipv6Addr>) {
        let mut ips = self.addrs.lock().unwrap();
        (*ips).V6 = ipv6;
    }

    pub fn get_ips(&self) -> Addr {
        *self.addrs.lock().unwrap()
    }

    pub fn get_ipv4(&self) -> Option<Ipv4Addr> {
        self.addrs.lock().unwrap().V4
    }

    pub fn get_ipv6(&self) -> Option<Ipv6Addr> {
        self.addrs.lock().unwrap().V6
    }
}