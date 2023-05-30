//! YAP2P Peers' and Nodes' logic
//! 
//! Unlike other implementations, in `yap2p` `Peer` and `Node` are not the same. 
//! The user is called [`Peer`], while user's devices are called [`Node`].

use serde::{Serialize, Deserialize};
use sha2::{Sha512, Digest};

use std::net::{Ipv4Addr, Ipv6Addr, IpAddr};
use std::sync::Mutex;
use std::collections::HashMap;

use crate::crypto::dh::DH;

/// [`Peer`]'s ID
/// 
/// [`PeerId`] looks like IPv6 address, but it's not the same. It also consists of
/// 16 bytes (128 bits), but it's special structure
/// - 1 byte is considered to be constant, in current implementation of library `42 | 69`
/// - 2-8 bytes hold [`Peer`]'s public key, used for Diffie-Hellman key exchange
/// - 9-16 bytes hold `username`'s hash checksum
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PeerId {
    pub(crate) inner: [u8; 16]
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
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
pub struct Peer {
    /// Peer Id
    pub(crate) id: PeerId,

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

/// Address type
/// 
/// If it is `Static` the [`Node`] can be used as a server. If it is `Dynamic` [`Node`] is completely useless.
// as mylife do. TODO: remove this comment when become happy
#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
pub enum AddrType {
    /// Dynamic IP means that it changes all the time
    Dynamic, // NAT is present 
    /// Static IP means that it is constant all the time
    Static   // The best variant that could ever exist
}

/// IP address of [`Node`]
/// 
/// Contains two fields: one for IPv4 address and one for IPv6,
/// because some devices have either, some have both.
#[allow(non_snake_case)] // because `V#` is better than `v#`
#[derive(Serialize, Deserialize, Debug, Copy, Clone)]
pub struct Addr {
    /// Address type
    addr_t: AddrType,

    /// IPv4 address
    pub V4: Option<Ipv4Addr>,

    /// IPv6 address
    pub V6: Option<Ipv6Addr>
}

impl Addr {
    /// Function to check if given [`IpAddr`] is in struct
    pub fn satisfies(&self, ip_addr: IpAddr) -> bool {
        if let Some(ipv4_addr) = self.V4 {
            if ipv4_addr == ip_addr {
                return true;
            }
        }
        if let Some(ipv6_addr) = self.V6 {
            if ipv6_addr == ip_addr {
                return true;
            }
        }
        return false;
    }
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
    // better be [`std::sync::Arc`] because of it's weight
    pub peer: Peer,

    /// Device number
    pub device: u16,

    // [`std::sync::Mutex`] just for interior mutability
    // so `addrs` should not be used in async
    // I'm not actually sure that we really need [`Mutex`] here
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
    pub fn set_ips(&self, addr_t: AddrType, ipv4: Option<Ipv4Addr>, ipv6: Option<Ipv6Addr>) {
        let mut ips = self.addrs.lock().unwrap();
        *ips = Addr {
            addr_t,
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
        self.addrs.lock().unwrap().to_owned()
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

    /// Check if [`Addr`] is `Static`
    pub fn is_static(&self) -> bool {
        self.addrs.lock().unwrap().addr_t == AddrType::Static
    }
}

/// Analog for [`Node`] but for storing all available [`Node`]s of the [`Peer`]
pub struct Contact {
    /// [`Peer`] that owns all this [`Addr`]s
    pub peer: Peer,

    /// [`HashMap`] that refers pairs (address, port) to corresponding [`Node.device`]
    pub(crate) addrs: Mutex<HashMap<u16, (Addr, u16)>>
}

impl Contact {
    /// Constructs new contact from [`Peer`] and list of [`Node`]s with corresponding ports
    /// 
    /// Arguments
    /// 
    /// * `peer` --- [`Peer`] behind [`Contact`]
    /// * `nodes` --- pairs of [`Node`]s and corresponding ports
    /// 
    /// Notes
    /// 
    /// * It's assumed that all `nodes` refers to the `peer`, so it's not checked in the function  
    pub fn new(peer: &Peer, nodes: &Vec<(Node, u16)>) -> Contact {
        let mut addrs: HashMap<u16, (Addr, u16)> = HashMap::with_capacity(nodes.len());
        
        // potential problem if element of `nodes` does not refer to `peer`
        for node in nodes {
            addrs.insert(
                node.0.device, 
                (node.0.get_ips(), node.1)
            );
        }

        Contact { 
            peer: peer.clone(), 
            addrs: Mutex::new(addrs) 
        }
    }

    /// Updates or adds new node to the list of [`Node`]s of the [`Contact`]
    /// 
    /// Arguments
    /// 
    /// * `node` --- pair of [`Node`] and corresponding port
    pub fn set_or_add_node(&self, node: (&Node, u16)) {
        (
            *self.addrs.lock().unwrap()
        ).insert(
            node.0.device,
            (node.0.get_ips(), node.1)
        );
    }

    /// Updates or adds new node to the list of [`Node`]s of the [`Contact`]
    /// 
    /// Arguments
    /// 
    /// * `device` --- [`Node`]'s device number
    /// * `address` --- pair of [`Addr`] and port to be setted
    // for inner optimization
    pub(crate) fn set_or_add_addr(&self, device: u16, address: (Addr, u16)) {
        (
            *self.addrs.lock().unwrap()
        ).insert(
            device,
            address
        );
    }

    /// Removes node from the list of [`Node`]s of the [`Contact`]
    /// 
    /// Arguments
    /// 
    /// * `node` --- [`Node`] to be removed
    pub fn remove_node(&self, node: &Node) {
        (
            *self.addrs.lock().unwrap()
        ).remove(&node.device);
    }

    /// Removes node from the list of [`Node`]s of the [`Contact`]
    /// 
    /// Arguments
    /// 
    /// * `device` --- [`Node.device`] to be removed
    // for inner optimization
    pub(crate) fn remove_addr(&self, device: u16) {
        (
            *self.addrs.lock().unwrap()
        ).remove(&device);
    }

    /// List of alive devices
    pub(crate) fn devices(&self) -> Vec<u16> {
        (
            *self.addrs.lock().unwrap()
        ).keys().cloned().collect()
    }

    /// Address of the device
    pub(crate) fn get_addr(&self, device_id: u16) -> Option<(Addr, u16)> {
        (
            *self.addrs.lock().unwrap()
        ).get(&device_id).copied()
    }
}