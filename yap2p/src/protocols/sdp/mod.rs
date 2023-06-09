//! Symmenric Datagram Protocol
//!
//! Protocol for message exchange.

mod sdp;
pub use sdp::*;

mod sdp_self;
pub use sdp_self::*;

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

const RECEIVE_BUFFER_SIZE: usize = 1220;
const WINDOW_SIZE: usize = 20;

#[derive(Debug, Clone)]
enum SentStatus {
    Awaiting,
    Synchronizing
}

/// Struct that ties [`Header`] and it's payload. The main purpose is checking if 
/// data piece is received
#[derive(Debug)]
pub struct Packet {
    status: Mutex<SentStatus>,
    header: Header,
    chat_sync: ChatSynchronizer,
    packet_sync: PacketSynchronizer,
    payload: Vec<u8>
}

impl Packet {
    /// Construct new [`Packet`] with manual construction of [`Header`] inside
    pub(crate) fn new(
        protocol_type: ProtocolType,
        packet_type: PacketType,
        src_id: &PeerId,
        rec_id: &PeerId,
        chat_sync: &ChatSynchronizer,
        packet_sync: PacketSynchronizer,
        payload: Vec<u8>
    ) -> Packet {
        Packet { 
            status:         Mutex::new(SentStatus::Awaiting), 
            header:         Header { 
                protocol_type, 
                packet_type, 
                length: 100 + payload.len() as u16, 
                src_id:     src_id.clone(), 
                rec_id:     rec_id.clone()
            }, 
            chat_sync:      chat_sync.clone(),
            packet_sync:    packet_sync.clone(),
            payload:        payload
        }
    }

    /// Update packet id. Needed in constructing of the first packet in transaction
    pub(crate) fn update_id(self) -> Packet {
        let mut rng = rand::thread_rng();

        Packet { 
            status: self.status, 
            header: self.header, 
            chat_sync: self.chat_sync, 
            packet_sync: PacketSynchronizer { 
                timestamp: self.packet_sync.timestamp, 
                n_packets: self.packet_sync.n_packets, 
                packet_id: rng.gen_range(u64::MIN..(u64::MAX - self.packet_sync.n_packets)) 
            }, 
            payload: self.payload 
        }
    }

    pub(crate) fn serialize(&self) -> Vec<u8> {
        let mut packet = self.header.serialize();
        packet.extend(&self.chat_sync.serialize());
        packet.extend(&self.packet_sync.serialize());
        packet.extend(&self.payload);
        return packet;
    }

    pub(crate) fn sync(&self) {
        *self.status.lock().unwrap() = SentStatus::Synchronizing;
    }
}

/// Struct for synchronizing [`Packet`]s transactions
#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
pub struct PacketSynchronizer {
    /// Timestamp of current [`Transaction`]
    timestamp: u64,

    /// Number of packets in current transaction
    n_packets: u64,

    /// Id of current [`Packet`]
    packet_id: u64   
}

impl PacketSynchronizer {
    /// [`PacketSynchronizer`] constructor
    pub fn new(timestamp: u64, n_packets: u64, packet_id: u64) -> PacketSynchronizer {
        PacketSynchronizer { timestamp, n_packets, packet_id }
    }

    /// Serialize [`PacketSynchronizer`] into bytes
    /// 
    /// # Panics
    /// 
    /// This function should not panic, 
    /// but if it does the problem is in `bincode` crate
    pub fn serialize(&self) -> Vec<u8> {
        bincode::serialize(&self).unwrap()
    }

    /// Deserialize [`PacketSynchronizer`] from `bytes`
    /// 
    /// # Panics
    /// 
    /// This function panics if `bytes.len() != 24`
    #[track_caller]
    pub fn deserialize(bytes: Vec<u8>) -> PacketSynchronizer {
        match bincode::deserialize(&bytes) {
            Ok(pack_sync) => pack_sync,
            Err(_) => panic!("Wrong size of `PacketSynchronizer`"),
        }
    }
}

/// Enum for representing current state of transaction
#[derive(Debug)]
pub enum Transaction {
    /// First packet in transaction and the rest of the data. Needed because first packet 
    /// should be acknowledged before sending others
    First {
        first_packet: Packet,
        rest_of_payload: VecDeque<Vec<u8>>
    },

    /// The rest of the packets to be transmitted
    Rest {
        first_packet_id: u64,
        payload: Mutex<VecDeque<Packet>>
    }
}

impl Transaction {

    fn update_id_strategy(self) -> Result<Transaction, Box<dyn Error>> {
        match self {
            Transaction::Rest { .. } => {
                Err("Updating `Transaction` id strategy is allowed only for `Transaction::First`".into())
            },
            Transaction::First { 
                first_packet, 
                rest_of_payload
            } => {
                Ok(Transaction::First { 
                    first_packet: first_packet.update_id(), 
                    rest_of_payload: rest_of_payload
                })
            }
        }
    }

    fn construct_rest(self, packet_id: u64) -> Transaction {
        match self {
            Transaction::First { 
                first_packet, 
                rest_of_payload 
            } => {
                let Header { 
                    protocol_type,
                    packet_type, 
                    length: _, 
                    src_id, 
                    rec_id 
                } = first_packet.header;
                let chat_sync = first_packet.chat_sync;
                let PacketSynchronizer{
                    timestamp,
                    n_packets,
                    packet_id: _
                } = first_packet.packet_sync;
                let payload = rest_of_payload.into_iter()
                    .zip((packet_id+1)..(packet_id+n_packets))
                    .map(
                        |(p, id)| 
                        Packet::new(
                            protocol_type,
                            packet_type,
                            &src_id,
                            &rec_id,
                            &chat_sync,
                            PacketSynchronizer::new(
                                timestamp, n_packets, id
                            ),
                            p.to_vec()
                        )
                    ).collect();

                Transaction::Rest { 
                    first_packet_id: packet_id,
                    payload: Mutex::new(payload)
                }
            },
            Transaction::Rest{ .. } => {
                self
            }
        }
    }

    fn ack_packets(&self, packet_ids: &Vec<u64>) {
        match self {
            Transaction::First { .. } => {  },
            Transaction::Rest{
                first_packet_id: _,
                payload
            } => {
                let mut packets = payload.lock().unwrap();
                (*packets).retain(|p| !packet_ids.contains(&p.packet_sync.packet_id));   
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ConnectionState {
    Receiving,
    Pending,
    Sending
}
#[derive(Debug, Clone)]
struct ConnectionWaker {
    state: ConnectionState,
    waker: Option<Waker>
}

/// Wrapper for a list of payloads of received [`Packet`]s
// May be the struct name is not the best
#[derive(Debug, Clone)]
pub struct MessageHandler {
    /// Sending [`Peer`]
    peer_id: PeerId,

    /// Message sender address
    sender_src: SocketAddr,

    /// Type of the chat [`Packet`]/[`Message`] belongs to
    chat_t: Chat,

    /// Timestamp of the last [`Message`] in the chat [`History`] 
    timestamp_l: u64,

    /// Synchronizer for the only first packet of the [`Transaction`]
    first_packet_sync: PacketSynchronizer,

    /// Payloads of all received [`Packet`]s alongside their ids
    data: Vec<(u64, Vec<u8>)>,

    /// ids of packets that are not acknowledged yet
    acknowledging: Vec<u64>,
    /// ids of packets that are acknowledged by the moment
    // needed because  
    acknowledged: HashSet<u64>
}

impl MessageHandler {
    fn acknow(&mut self) {
        self.acknowledged = self.acknowledged
            .union(&HashSet::from_iter(self.acknowledging.clone()))
            .map(|id| id.to_owned())
            .collect::<HashSet<u64>>();
    }
}

/// Payload of `ACK` packets
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PacketWindow {
    pub(crate) packet_ids: Vec<u64>
}

impl PacketWindow {
    pub(crate) fn serialize(&self) -> Vec<u8> {
        bincode::serialize(&self).unwrap()
    }

    #[track_caller]
    pub(crate) fn deserialize(bytes: Vec<u8>) -> Result<PacketWindow, Box<dyn Error>> {
        match bincode::deserialize(&bytes) {
            Ok(chat_sync) => Ok(chat_sync),
            Err(_) => Err("Wrong size of `PacketWindow`".into())
        }
    }
}

#[derive(Debug, Clone)]
/// Types of acknowledgement packets
pub enum Acknowledgement {
    /// 'ACK_SYN'
    First(PacketSynchronizer),
    /// 'ACK'
    Rest(PacketWindow)
}

/// Wrapper for a standard message 
#[derive(Debug)]
pub enum MessageWrapper {
    /// Regular message from `SYN` packet
    Receiving {
        /// Type of the chat
        chat_t: Chat,
        /// Synchronizer of the history
        chat_sync: ChatSynchronizer,
        /// Transmitted [`Message`]
        payload: Vec<u8>
    },

    /// Regular message to be sent
    Sending {
        /// All posible receivers of the [`Message`]
        receivers: Vec<Peer>,
        /// Type of the chat
        chat_t: Chat,
        /// Synchronizer of the history
        chat_sync: ChatSynchronizer,
        /// Transmitted [`Message`]
        message: Message,
    },

    /// Regular message from `SYN` packet
    // dead logic, but let it live for now
    Acknowledgement {
        /// Type of the chat
        chat_t: Chat,
        /// Synchronizer of the history
        chat_sync: ChatSynchronizer,
        /// Transmitted [`Message`]
        packets: Acknowledgement
    },

    /// `HI` packet
    Recover {
        /// Is it an ackhowledgement packet 
        ack: bool,
        /// Packet sender's id
        peer_id: PeerId,
        /// List of [`History`]s sender wants to synchronize
        histories: ChatSynchronizers
    },

    /// `INIT` packet in SDP
    Initial {
        /// Is it an ackhowledgement packet 
        ack: bool,
        /// Packet sender
        peer: Peer,
        /// [`History`] to be initialised
        history: ChatSynchronizer
    },

    /// `HI` packet
    SelfRecover {
        /// Is it an ackhowledgement packet 
        ack: bool,
        /// Packet sender's id
        device_id: u16,
        /// Data to synchronize
        sync: SelfSynchronizer
    },

    /// `INIT` packet in SDP
    SelfInitial {
        /// Is it an ackhowledgement packet 
        ack: bool,
        /// Packet sender
        device_id: u16,
        /// Data to synchronize
        sync: SelfSynchronizer
    }
}