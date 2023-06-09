use super::*;

/// [`Message`]s storage, including all specific logic.
pub struct History {
    /// [`Chat::OneToOne`] | [`Chat::Group`] | [`Chat::Channel`]
    pub chat_t: Chat,

    /// Chat id used for identifing chats (mostly needed for [`Chat::Group`] | [`Chat::Channel`])
    pub chat_id: [u8; 32],

    /// Is history encrypted
    pub is_encrypted: bool,

    /// Key to encrypt new message. Needed because `messages` can be empty.
    top_key: KeyChain,

    /// Timestamp of the last message. Needed because `messages` can be empty.
    top_timestamp: Mutex<u64>,

    /// Maximum number of messages stored at a time.
    constraint: usize,

    /// Time span, while all messages stay alive
    soft_ttl: u64,

    /// Time span, after which all messages are deleted
    hard_ttl: u64,

    /// Stored [`Message`]s
    pub messages: Mutex<Vec<Message>>,

    /// Members of [`Chat::OneToOne`] | [`Chat::Group`] | [`Chat::Channel`]
    other_members: Mutex<Vec<Peer>>
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
    /// * `is_encrypted` --- shall messages be encrypted for sending
    /// * `other_members` --- members of chat except of current [`Peer`]
    pub fn init(
        chat_t: Chat,
        chat_id: [u8; 32],
        init_key: KeyChain,
        timestamp: u64,
        constraint: u16,
        soft_ttl: u64,
        hard_ttl: u64,
        is_encrypted: bool,
        other_members: Vec<Peer>
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
            other_members: Mutex::new(other_members)
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
        sender: Peer, 
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
        sender: Peer, 
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
            timestamp: self.top_timestamp.lock().unwrap().to_owned()
        }
    }

    /// Get other chat members
    pub fn members(&self) -> Vec<Peer> {
        self.other_members.lock().unwrap().to_owned()
    }
}