//! Data storing logic
//!
//! In yap2p every piece of the transmitted data
//! is called [`Message`].

use std::sync::Mutex;
use std::time::SystemTime;

use serde::{Serialize, Deserialize};
use bincode;

use super::keychain::KeyChain;
use crate::peer::*;

#[cfg_attr(docsrs, doc(cfg(feature = "unknown-fields")))]
#[cfg(feature = "regular_history")]
mod history_regular;
#[cfg_attr(docsrs, doc(cfg(feature = "unknown-fields")))]
#[cfg(feature = "regular_history")]
pub use history_regular::*;

//#[cfg(feature = "sync_safe_history")]
mod history_safe;
//#[cfg(feature = "sync_safe_history")]
pub use history_safe::*;

/// Chat type
#[derive(Debug, Clone, Copy)]
pub enum Chat {
    /// Simple conversation of two [`Peer`]s.
    OneToOne,

    /// Conversation of `N` [`Peer`]s, each of which can send data.
    /// Looks like `N` `Channel`s zipped.
    Group,

    /// Conversation of `N` [`Peer`]s with only one sender (separate [`Peer`]).
    Channel,
}

/// Struct for storing a piece of data to be transmitted.
#[derive(Debug, Clone)]
pub struct Message {
    /// Message sender
    /// Just one heavy (16 bytes for [`PeerId`] + N bytes for name) way to know, who sent this
    /// It could be [`Arc`] | [`Rc`] 
    pub sender: Peer,

    /// Timestamp of massage creation
    pub timestamp: u64,

    /// Encryption key
    pub key: [u8; 32],

    /// Is data encrypted or not
    pub is_encrypted: bool,

    /// Message data
    pub data: Vec<u8>
}

impl Message {
    /// New message constructor
    ///
    /// Arguments
    ///
    /// * `sender` --- [`Peer`] who sent this message
    /// * `data` --- data, contained by the [`Message`]
    /// * `key` --- encryption key; it's proposed to store raw data
    /// and use `key` only while sending data through network
    pub fn new(
        sender: Peer, 
        data: impl AsRef<[u8]>, 
        key: [u8; 32]
    ) -> Message {
        Message {
            sender,
            timestamp: SystemTime::now().elapsed().unwrap().as_secs(),
            key: key,
            is_encrypted: false,
            data: data.as_ref().to_owned(),
        }
    }

    /// New encrypted message constructor
    ///
    /// Arguments
    ///
    /// * `sender` --- [`Peer`] who sent this message
    /// * `data` --- data, contained by the [`Message`]
    /// * `key` --- encryption key; it's proposed to store raw data
    /// and use `key` only while sending data through network
    pub fn new_encrypted(
        sender: Peer, 
        data: &impl AsRef<[u8]>, 
        key: [u8; 32]
    ) -> Message {
        Message {
            sender,
            timestamp: SystemTime::now().elapsed().unwrap().as_secs(),
            key: key,
            is_encrypted: true,
            data: data.as_ref().to_owned(),
        }
    }

    /// New message constructor (for received ones)
    ///
    /// Arguments
    ///
    /// * `sender` --- [`Peer`] who sent this message
    /// * `data` --- data, contained by the [`Message`]
    /// * `key` --- encryption key; it's proposed to store raw data
    /// and use `key` only while sending data through network
    /// * `timestamp` --- creation time of message received
    pub fn new_received(
        sender: Peer, 
        data: &impl AsRef<[u8]>, 
        key: [u8; 32], 
        timestamp: u64
    ) -> Message {
        Message {
            sender,
            timestamp: timestamp,
            key: key,
            is_encrypted: false,
            data: data.as_ref().to_owned(),
        }
    }

    /// New encrypted message constructor (for received ones)
    ///
    /// Arguments
    ///
    /// * `sender` --- [`Peer`] who sent this message
    /// * `data` --- data, contained by the [`Message`]
    /// * `key` --- encryption key; it's proposed to store raw data
    /// and use `key` only while sending data through network
    /// * `timestamp` --- creation time of message received
    pub fn new_received_encrypted(
        sender: Peer, 
        data: &impl AsRef<[u8]>,
        key: [u8; 32],
        timestamp: u64,
    ) -> Message {
        Message {
            sender,
            timestamp: timestamp,
            key: key,
            is_encrypted: true,
            data: data.as_ref().to_owned(),
        }
    }
}

/// Struct for synchronizing chat histories on different [`Peer`]s and [`Node`]s
#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
pub struct ChatSynchronizer {
    /// Chat id
    pub chat_id: [u8; 32],
    
    /// Timestamp of last message stored
    pub timestamp: u64
}

impl ChatSynchronizer {
    /// [`ChatSynchronizer`] constructor
    /// 
    /// Better use `new_for_history`
    pub fn new(
        chat_id: [u8; 32],
        timestamp: u64
    ) -> ChatSynchronizer {
        ChatSynchronizer { chat_id, timestamp }
    }

    /// Serialize [`ChatSynchronizer`] into bytes
    /// 
    /// # Panics
    /// 
    /// This function should not panic, 
    /// but if it does the problem is in `bincode` crate
    pub fn serialize(&self) -> Vec<u8> {
        bincode::serialize(&self).unwrap()
    }

    /// Deserialize [`ChatSynchronizer`] from `bytes`
    #[track_caller]
    pub fn deserialize(bytes: Vec<u8>) -> ChatSynchronizer {
        match bincode::deserialize(&bytes) {
            Ok(chat_sync) => chat_sync,
            Err(_) => panic!("Wrong size of `ChatSynchronizer`"),
        }
    }
}

/// List of [`ChatSynchronizer`]s
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ChatSynchronizers {
    chat_syncs: Vec<ChatSynchronizer>
}

impl ChatSynchronizers {
    /// Serialize [`ChatSynchronizer`] into bytes
    /// 
    /// # Panics
    /// 
    /// This function should not panic, 
    /// but if it does the problem is in `bincode` crate
    pub fn serialize(&self) -> Vec<u8> {
        bincode::serialize(&self).unwrap()
    }

    /// Deserialize [`ChatSynchronizers`] from `bytes`
    #[track_caller]
    pub fn deserialize(bytes: Vec<u8>) -> ChatSynchronizers {
        match bincode::deserialize(&bytes) {
            Ok(chat_syncs) => chat_syncs,
            Err(_) => panic!("Wrong size of `ChatSynchronizers`"),
        }
    }
}