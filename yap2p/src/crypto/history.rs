//! Data storing logic
//! 
//! In yap2p every piece of the transmitted data
//! is called [`Message`].

use std::sync::Mutex;
use std::time::SystemTime;

use super::keychain::KeyChain;

/// Struct for storing a piece of data to be transmitted.
pub struct Message {
    /// Timestamp of massage creation
    pub timestamp: u64,

    /// Encryption key
    pub key: [u8; 32],

    /// Is data encrypted or not
    pub is_encrypted: bool,
    
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
            is_encrypted:  false,
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
            is_encrypted:  true,
            data:       Box::new(data.as_ref().to_owned())
        }
    }
}

/// [`Message`]s storage, including all specific logic.
pub struct History {
    /// Key to encrypt new message. Needed because `messages` can be empty.
    pub top_key: KeyChain,

    /// Timestamp of the last message. Needed because `messages` can be empty.
    pub top_timestamp: Mutex<u64>,

    /// Maximum number of messages stored at a time.
    pub constraint: usize,

    /// Time span, while all messages stay alive
    pub soft_ttl: u64,

    /// Time span, after which all messages are deleted
    pub hard_ttl: u64,

    /// Stored [`Message`]s
    pub messages: Mutex<Vec<Message>>
}

impl History {
    /// Initiate history
    /// 
    /// Arguments
    /// 
    /// * `init_key` --- initial encryption key
    /// * `timestamp` --- needed for history synchronization
    /// * `constraint` --- maximum number of messages in [`History`] at a time
    /// * `soft_ttl` --- soft time to live
    /// * `hard_ttl` --- hard time to live
    pub fn init(
            init_key: KeyChain, 
            timestamp: u64,
            constraint: u16, 
            soft_ttl: u64, 
            hard_ttl: u64
        ) -> History {
        History {
            top_key:        init_key,
            top_timestamp:  Mutex::new(timestamp),
            constraint:     constraint as usize,
            soft_ttl, hard_ttl,
            messages:       Mutex::new(Vec::new())
        }
    }

    /// Add new message to [`History`]
    /// 
    /// Arguments
    /// 
    /// * `data` --- message
    /// * `key` --- message encryption key
    /// 
    /// We do not need `&mut self` because of interior mutability
    pub fn new_message(&self, data: impl AsRef<[u8]>, key: [u8; 32]) {
        // create new message
        let message = Message::new(
            data, key.clone()
        );

        // update history's top key 
        self.top_key.update(key);

        // update history's top timestamp
        *(self.top_timestamp.lock().unwrap()) = message.timestamp;

        // finally, add new message to the history
        let mut messages = self.messages.lock().unwrap();
        (*messages).push(message);
    }

    /// Add new encrypted message to history
    /// 
    /// Arguments
    /// 
    /// * `data` --- message
    /// * `key` --- message encryption key
    /// 
    /// We do not need `&mut self` because of interior mutability
    pub fn new_message_encrypted(&self, data: impl AsRef<[u8]>, key: [u8; 32]) {
        // create new message
        let message = Message::new_encrypted(
            data, key.clone()
        );

        // update history's top key 
        self.top_key.update(key);

        // update history's top timestamp
        *(self.top_timestamp.lock().unwrap()) = message.timestamp;

        // finally, add new message to the history
        let mut messages = self.messages.lock().unwrap();
        (*messages).push(message);
    }

    /// Clean up [`History`]
    /// 
    /// We do not need `&mut self` because of interior mutability
    pub fn cleanup(&self) {
        // compute soft and hard deadlines
        let now = SystemTime::now().elapsed().unwrap().as_secs();
        let soft_deadline = now - self.soft_ttl;
        let hard_deadline = now - self.hard_ttl;

        let mut messages = self.messages.lock().unwrap();

        // drop all old messages
        (*messages).retain(
            |m| m.timestamp > hard_deadline
        );

        // leave in history only `constraint` number of messages older than `soft_ttl`
        while (*messages).len() > self.constraint && 
                (*messages)[0].timestamp < soft_deadline {
            (*messages).remove(0);
        }
    }
}