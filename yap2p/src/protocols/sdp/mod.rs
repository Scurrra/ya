//! (Secure) Symmenric Datagram Protocol
//!
//!
//!

mod sdp;
pub use sdp::*;

use std::error::Error;
use std::net::SocketAddr;
use std::sync::Mutex;
use std::collections::VecDeque;
use std::ops::ControlFlow;
use std::task::{Context, Poll, Waker};
use std::future::Future;
use std::pin::Pin;

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
        let mut packet = bincode::serialize(&self.header).unwrap();
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
                (*packets).iter()
                    .filter(|p| packet_ids.contains(&p.packet_sync.packet_id))
                    .map(|p| p.sync());   
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

/// An abstraction for specific connection functions
/// 
/// ! No receiving functions, because they are into the [`Driver`] trait
pub trait Connection {
    /// Send service echo packet to another [`Peer`]
    ///
    /// Arguments
    ///
    /// * `sender` --- [`PeerId`] of *this* [`Node`]
    /// * `receiver` --- [`Node`] and corresponding port number as tuple
    fn echo(
        &self, cx: &mut Context<'_>,
        sender: &PeerId, receiver: (&Node, u16),
    ) -> Poll<std::io::Result<usize>>;

    /// Start sending the [`Message`]. Function constructs entities of special [`Transaction`]
    /// struct which defines which data should be sent. 
    /// 
    /// Arguments
    /// 
    /// * `chat_t` --- [`Chat`] type 
    /// * `message` --- the message to be sent
    /// * `chat_sync` --- synchronization information from the corresponding [`History`]
    fn send(
        &self, 
        chat_t: Chat,
        message: Message,
        chat_sync: ChatSynchronizer
    ) -> ControlFlow<Result<(), Box<dyn Error>>, u64>;

    /// Exact function that sends [`Transaction`]s
    fn poll_send(&self, cx: &mut Context<'_>) -> Poll<Result<(), Box<dyn Error>>>;
}

/// Wrapper for a list of payloads of received [`Packet`]s
// May be the struct name is not the best
#[derive(Debug, Clone)]
pub struct MessageHandler {
    /// Type of the chat [`Packet`]/[`Message`] belongs to
    chat_t: Chat,

    /// Timestamp of the last [`Message`] in the chat [`History`] 
    timestamp_l: u64,

    /// Synchronizer for the only first packet of the [`Transaction`]
    first_packet_sync: PacketSynchronizer,

    /// Payloads of all received [`Packet`]s alongside their ids
    data: Vec<(u64, Vec<u8>)>,
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
#[derive(Debug, Clone)]
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
        /// all posible receivers of the [`Message`]
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
        /// Packet sender
        peer: Peer,
        /// List of [`History`]s sender wants to synchronize
        histories: Vec<ChatSynchronizer>
    },

    /// `INIT` packet
    Initial {
        /// Is it an ackhowledgement packet 
        ack: bool,
        /// Packet sender
        peer: Peer,
        /// [`History`] to be initialised
        history: ChatSynchronizer
    }
}

/// An abstraction for specific driver functions
/// 
/// ! No sendinging functions, because they are into the [`Connection`] trait.
/// ! Alongside this trait the [`Future`] trait must be implemented.
pub trait Driver: Future {
    /// Function for handling a single datagram. This function also handles single-only packets of types
    /// [`PacketType::HI`] | [`PacketType::INIT`] | [`PacketType::ECHO`]
    /// 
    /// Arguments 
    /// 
    /// * `packet` --- the received packet
    /// * `packet_src` --- [`SocketAddr`] `packet` was received from
    /// 
    /// Panics
    /// 
    /// Function panics if there is no opened connections to the specified address
    fn handle_dataram(
        &mut self, 
        packet: &Vec<u8>, 
        packet_src: SocketAddr
    ) -> ControlFlow<Result<(), Box<dyn Error>>, [u8; 32]>;

    /// Function for handling a single message
    /// 
    /// Arguments 
    /// 
    /// * `chat_id` --- id of the chat the message belongs to
    fn handle_message(
        &mut self, 
        chat_id: &[u8; 32]
    ) -> ControlFlow<Result<(), Box<dyn Error>>, ()>;
}