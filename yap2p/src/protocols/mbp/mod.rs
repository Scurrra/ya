//! 
//! 
//! 

use std::error::Error;
use std::net::SocketAddr;
use std::sync::Mutex;
use std::collections::{VecDeque, HashSet};
use std::task::Waker;
use std::pin::Pin;

use serde::{Serialize, Deserialize};
use bincode;
use rand::Rng;

use super::*;
use crate::crypto::history::*;
use crate::peer::*;

/// [`Node`]s from MeshNet layer
#[derive(Debug, Serialize, Deserialize)]
pub struct MeshContacts {
    /// [`Node`]s with static addresses, which could be used as "servers". 
    /// If a [`Node`] has a static address but could not be used as a "server", it's marked as dynamic.
    static_nodes: Vec<Node>,

    /// [`Node`]s which public IPs are dynamic and are continuously changing.
    dynamic_nodes: Vec<Node>
}

impl MeshContacts {
    /// Serialize [`MeshContacts`] into bytes
    /// 
    /// # Panics
    /// 
    /// This function should not panic, 
    /// but if it does the problem is in `bincode` crate
    pub fn serialize(&self) -> Vec<u8> {
        bincode::serialize(&self).unwrap()
    }

    /// Deserialize [`MeshContacts`] from `bytes`
    #[track_caller]
    pub fn deserialize(bytes: Vec<u8>) -> MeshContacts {
        match bincode::deserialize(&bytes) {
            Ok(contacts) => contacts,
            Err(_) => panic!("Wrong size of `MeshContacts`"),
        }
    }
}