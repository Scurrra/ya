//! YAP2P Peers' and Nodes' logic
//! 
//! Unlike other implementations, in `yap2p` `Peer` and `Node` are not the same. 
//! The user is called [`Peer`], while user's devices are called [`Node`].
 
use serde::{Serialize, Deserialize};
use sha2::{Sha512, Digest};

use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Mutex;

use crate::crypto::dh::DH;

/// [`Peer`]'s ID
/// 
/// [`PeerId`] looks like IPv6 address, but it's not the same. It also consists of
/// 16 bytes (128 bits), but it's special structure
/// - 1 byte is considered to be constant, in current implementation of library `42 | 69`
/// - 2-8 bytes hold [`Peer`]'s public key, used for Diffie-Hellman key exchange
/// - 9-16 bytes hold `username`'s hash checksum
#[derive(Serialize, Deserialize, Debug)]
pub struct PeerId {
    inner: [u8; 16]
}

impl PeerId {

    /// Constructor for [`PeerId`]
    /// 
    /// # Arguments
    /// 
    /// * `username` --- [`Peer`]'s username
    /// * `dh` --- [Diffie-Hellman](DH) structure
    /// 
    /// ! Is called from [`Peer::new()`]
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

/// `Peer` struct
/// 
/// [`Peer`] is the main struct, which contains all information to identify
/// the user.
#[derive(Serialize, Deserialize, Debug)]
pub struct Peer {
    /// Peer Id
    pub id: PeerId,

    /// Username in the Net
    pub name: String
}

impl Peer {
    /// Constructor for [`Peer`]
    /// 
    /// # Arguments
    /// 
    /// * `username` --- [`Peer`]'s username
    /// * `dh` --- [Diffie-Hellman](DH) structure
    pub fn new(username: &str, dh: DH) -> Peer {
        Peer {
            id: PeerId::new(username, dh),
            name: String::from(username)
        }
    }

    /// Public key extractor from [`PeerId`]
    pub fn get_public_key(&self) -> u64 {
        let mut be_bytes = [0u8; 8];
        for i in 1..8 {
            be_bytes[i] = self.id.inner[i];
        }

        u64::from_be_bytes(be_bytes)
    }
}

/// IP address of [`Node`]
/// 
/// Contains two fields: one for IPv4 address and one for IPv6,
/// because some devices have either, some have both.
#[derive(Serialize, Deserialize, Debug, Copy, Clone)]
pub struct Addr {
    /// IPv4 address
    pub V4: Option<Ipv4Addr>,

    /// IPv6 address
    pub V6: Option<Ipv6Addr>
}

/// `Node` struct
/// 
/// Represents the device user has.
/// 
/// There is a mapping between IPv6 and [`PeerId`]:
/// - address in IPv6 and [`PeerId`]
/// - port on device and [`Node`] of the user
#[derive(Serialize, Deserialize, Debug)]
pub struct Node {
    /// [`Peer`] that [`Node`] belongs to
    pub peer: Peer,

    /// Device number
    pub device: u16,
    addrs: Mutex<Addr>
}

impl Node {
    /// Constructor for [`Node`]
    /// 
    /// # Argments
    /// 
    /// * `peer` --- [`Peer`] that [`Node`] belongs to
    /// * `device` --- number of the device
    /// * `addrs` --- IP addresses of the device
    pub fn new(peer: Peer, device: u16, addrs: Addr) -> Node {
        Node {
            peer,
            device,
            addrs: Mutex::new(addrs)
        }
    }

    /// Function for changing [`Node`]'s IPs. Needed to hide `std::sync::Mutex`
    /// from the user
    pub fn set_ips(&self, ipv4: Option<Ipv4Addr>, ipv6: Option<Ipv6Addr>) {
        let mut ips = self.addrs.lock().unwrap();
        *ips = Addr {
            V4: ipv4,
            V6: ipv6
        };
    }

    /// Function for changing [`Node`]'s IPv4. Needed to hide `std::sync::Mutex`
    /// from the user
    pub fn set_ipv4(&self, ipv4: Option<Ipv4Addr>) {
        let mut ips = self.addrs.lock().unwrap();
        (*ips).V4 = ipv4;
    }

    /// Function for changing [`Node`]'s IPv6. Needed to hide `std::sync::Mutex`
    /// from the user
    pub fn set_ipv6(&self, ipv6: Option<Ipv6Addr>) {
        let mut ips = self.addrs.lock().unwrap();
        (*ips).V6 = ipv6;
    }

    /// Function for obtaining [`Node`]'s IPs. Needed to hide `std::sync::Mutex`
    /// from the user
    pub fn get_ips(&self) -> Addr {
        *self.addrs.lock().unwrap()
    }

    /// Function for obtaining [`Node`]'s IPv4. Needed to hide `std::sync::Mutex`
    /// from the user
    pub fn get_ipv4(&self) -> Option<Ipv4Addr> {
        self.addrs.lock().unwrap().V4
    }

    /// Function for obtaining [`Node`]'s IPv6. Needed to hide `std::sync::Mutex`
    /// from the user
    pub fn get_ipv6(&self) -> Option<Ipv6Addr> {
        self.addrs.lock().unwrap().V6
    }
}