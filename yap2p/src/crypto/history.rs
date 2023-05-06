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

/// Chat type
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
pub struct Message {
    /// Message sender, None may be in [`Chat::Channel`]
    /// Just one heavy (16 bytes for [`PeerId`] + N bytes for name) way to know, who sent this
    /// It could be [`Arc`] | [`Rc`] 
    pub sender: Option<Peer>,

    /// Timestamp of massage creation
    pub timestamp: u64,

    /// Encryption key
    pub key: [u8; 32],

    /// Is data encrypted or not
    pub is_encrypted: bool,

    /// Message data
    pub data: Box<dyn AsRef<[u8]>>, // should work for whatever implements AsRef<u8>
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
        sender: Option<Peer>, 
        data: impl AsRef<[u8]>, 
        key: [u8; 32]
    ) -> Message {
        Message {
            sender,
            timestamp: SystemTime::now().elapsed().unwrap().as_secs(),
            key: key,
            is_encrypted: false,
            data: Box::new(data.as_ref().to_owned()),
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
        sender: Option<Peer>, 
        data: &impl AsRef<[u8]>, 
        key: [u8; 32]
    ) -> Message {
        Message {
            sender,
            timestamp: SystemTime::now().elapsed().unwrap().as_secs(),
            key: key,
            is_encrypted: true,
            data: Box::new(data.as_ref().to_owned()),
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
        sender: Option<Peer>, 
        data: &impl AsRef<[u8]>, 
        key: [u8; 32], 
        timestamp: u64
    ) -> Message {
        Message {
            sender,
            timestamp: timestamp,
            key: key,
            is_encrypted: false,
            data: Box::new(data.as_ref().to_owned()),
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
        sender: Option<Peer>, 
        data: &impl AsRef<[u8]>,
        key: [u8; 32],
        timestamp: u64,
    ) -> Message {
        Message {
            sender,
            timestamp: timestamp,
            key: key,
            is_encrypted: true,
            data: Box::new(data.as_ref().to_owned()),
        }
    }
}

/// [`Message`]s storage, including all specific logic.
pub struct History {
    /// [`Chat::OneToOne`] | [`Chat::Group`] | [`Chat::Channel`]
    pub chat_t: Chat,

    /// Chat id used for identifing chats (mostly needed for [`Chat::Group`] | [`Chat::Channel`])
    pub chat_id: [u8; 32],

    /// Is history encrypted
    pub is_encrypted: bool,

    /// Key to encrypt new message. Needed because `messages` can be empty.
    pub top_key: KeyChain,

    /// Timestamp of the last message. Needed because `messages` can be empty.
    pub top_timestamp: Mutex<u64>,

    /// Maximum number of messages stored at a time.
    constraint: usize,

    /// Time span, while all messages stay alive
    soft_ttl: u64,

    /// Time span, after which all messages are deleted
    hard_ttl: u64,

    /// Stored [`Message`]s
    pub messages: Mutex<Vec<Message>>,
}

impl History {
    /// Initiate history
    ///
    /// Arguments
    ///
    /// * `chat_t` --- needed for determining [`PacketType`]
    /// * `chat_id` --- chat identifier
    /// * `init_key` --- initial encryption key
    /// * `timestamp` --- needed for history synchronization
    /// * `constraint` --- maximum number of messages in [`History`] at a time
    /// * `soft_ttl` --- soft time to live
    /// * `hard_ttl` --- hard time to live
    pub fn init(
        chat_t: Chat,
        chat_id: [u8; 32],
        init_key: KeyChain,
        timestamp: u64,
        constraint: u16,
        soft_ttl: u64,
        hard_ttl: u64,
        is_encrypted: bool,
    ) -> History {
        History {
            chat_t: chat_t,
            chat_id: chat_id,
            is_encrypted: is_encrypted,
            top_key: init_key,
            top_timestamp: Mutex::new(timestamp),
            constraint: constraint as usize,
            soft_ttl,
            hard_ttl,
            messages: Mutex::new(Vec::new()),
        }
    }

    /// Add new message to [`History`]
    ///
    /// Arguments
    ///
    /// * `sender` --- [`Peer`] who sent this message
    /// * `data` --- message
    /// * `key` --- message encryption key
    ///
    /// We do not need `&mut self` because of interior mutability
    pub fn add_message(&self, 
        sender: Option<Peer>, 
        data: &impl AsRef<[u8]>, 
        key: [u8; 32]
    ) {
        // create new message
        let message = match self.is_encrypted {
            true => Message::new(sender, data, key.clone()),
            false => Message::new_encrypted(sender, data, key.clone()),
        };

        // update history's top key
        self.top_key.update(key);

        // update history's top timestamp
        *(self.top_timestamp.lock().unwrap()) = message.timestamp;

        // finally, add new message to the history
        let mut messages = self.messages.lock().unwrap();
        (*messages).push(message);
    }

    /// Add new received message to [`History`]
    ///
    /// Arguments
    ///
    /// * `sender` --- [`Peer`] who sent this message
    /// * `data` --- message
    /// * `key` --- message encryption key
    /// * `timestamp` --- creation time of message received
    ///
    /// We do not need `&mut self` because of interior mutability
    pub fn add_message_received(&self, 
        sender: Option<Peer>, 
        data: &impl AsRef<[u8]>, 
        key: [u8; 32], 
        timestamp: u64
    ) {
        // create new message
        let message = match self.is_encrypted {
            true => Message::new_received(sender, data, key.clone(), timestamp),
            false => Message::new_received_encrypted(sender, data, key.clone(), timestamp),
        };

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
        (*messages).retain(|m| m.timestamp > hard_deadline);

        // leave in history only `constraint` number of messages older than `soft_ttl`
        while (*messages).len() > self.constraint && (*messages)[0].timestamp < soft_deadline {
            (*messages).remove(0);
        }
    }

    /// Rearrange history in case recieved message is older than the last in history
    ///
    /// Potentially heavy
    pub fn rearrange(&self) {
        let mut messages = self.messages.lock().unwrap();
        messages.sort_by_key(|m| m.timestamp);
    }

    /// Equivalent for [`ChatSynchronizer::new`]
    pub fn synchronizer(&self) -> ChatSynchronizer {
        ChatSynchronizer { 
            chat_id: self.chat_id, 
            timestamp: *self.top_timestamp.lock().unwrap()
        }
    }
}

/// Struct for synchronizing chat histories on different [`Peer`]s and [`Node`]s
#[derive(Serialize, Deserialize, Debug)]
pub struct ChatSynchronizer {
    /// Chat id
    chat_id: [u8; 32],
    
    /// Timestamp of last message stored
    timestamp: u64
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

    /// [`ChatSynchronizer`] constructor from [`History`]
    pub fn new_from_history(
        chat: &History
    ) -> ChatSynchronizer {
        ChatSynchronizer { 
            chat_id: chat.chat_id, 
            timestamp: *chat.top_timestamp.lock().unwrap()
        }
    }

    /// Serialize [`ChatSynchronizer`] into bytes
    pub fn serialize(&self) -> Vec<u8> {
        bincode::serialize(&self).unwrap()
    }

    /// Deserialize [`ChatSynchronizer`] from `bytes`
    pub fn deserialize(bytes: Vec<u8>) -> ChatSynchronizer {
        bincode::deserialize(&bytes).unwrap()
    }
}