//! Data storing logic
//! 
//! In yap2p every piece of the transmitted data
//! is called [`Message`].
 
use sha2::{Sha256, Digest};
use aes::Aes256;
use aes::cipher::{
    BlockCipher, BlockEncrypt, BlockDecrypt, KeyInit,
    generic_array::{typenum::U16, GenericArray},
};

use std::sync::Mutex;
use std::time::SystemTime;

use super::keychain::KeyChain;
use crate::peer::Peer;

/// Struct for storing a piece of data to be transmitted.
pub struct Message {
    /// Timestamp of massage creation
    pub timestamp: u64,

    /// Encryption key
    pub key: [u8; 32],

    /// Is data encrypted or not
    pub encrypted: bool,
    
    /// Message data
    pub data: Box<dyn AsRef<[u8]>> // should work for whatever implements AsRef<u8>
}

impl Message {
    /// New message constructor
    /// 
    /// Arguments
    /// 
    /// * `data` --- data, contained by the [`Message`]
    /// * `key` --- encryption key; it's proposed to store raw data 
    /// and use `key` only while sending data through network
    pub fn new(data: impl AsRef<[u8]>, key: [u8; 32]) -> Message {
        Message { 
            timestamp:  SystemTime::now().elapsed().unwrap().as_secs(), 
            key:        key, 
            encrypted:  false,
            data:       Box::new(data.as_ref().to_owned())
        }
    }

    /// New encrypted message constructor
    /// 
    /// Arguments
    /// 
    /// * `data` --- data, contained by the [`Message`]
    /// * `key` --- encryption key; it's proposed to store raw data 
    /// and use `key` only while sending data through network
    pub fn new_encrypted(data: impl AsRef<[u8]>, key: [u8; 32]) -> Message {
        Message { 
            timestamp:  SystemTime::now().elapsed().unwrap().as_secs(), 
            key:        key, 
            encrypted:  true,
            data:       Box::new(data.as_ref().to_owned())
        }
    }
}

/// [`Message`]s storage, including all specific logic.
pub struct History {
    /// Key to encrypt new message. Needed because `messages` can be empty.
    pub top_key: KeyChain,

    /// Timestamp of the last message. Needed because `messages` can be empty.
    pub top_timestamp: u64,

    /// Maximum number of messages stored at a time.
    pub constraint: u16,

    /// Stored [`Message`]s
    pub messages: Vec<Message>
}

impl History {
    /// Initiate history
    /// 
    /// Arguments
    /// 
    /// * `init_key` --- initial encryption key
    /// * `constraint` --- maximum number of messages in [`History`] at a time
    pub fn init(init_key: KeyChain, constraint: u16) -> History {
        let init_message = Message::new(
            "Initial message",
            init_key.current()
        );
        History {
            top_key:        init_key,
            top_timestamp:  init_message.timestamp,
            constraint:     constraint,
            messages:       vec![init_message]
        }
    }

    /// Initiate history
    /// 
    /// Arguments
    /// 
    /// * `init_key` --- initial encryption key
    /// * `constraint` --- maximum number of messages in [`History`] at a time
    /// * `init_message` --- 
    pub fn init_with_message(init_key: KeyChain, constraint: u16, init_message: String) -> History {
        let init_message = Message::new(
            init_message,
            init_key.current()
        );
        History {
            top_key:        init_key,
            top_timestamp:  init_message.timestamp,
            constraint:     constraint,
            messages:       vec![init_message]
        }
    }
}