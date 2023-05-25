//! (Secure) Symmenric Datagram Protocol
//!
//!
//!

mod sdp;
pub use sdp::*;

use std::error::Error;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::collections::{HashMap, VecDeque};

use tokio::net::UdpSocket;
use futures::channel::mpsc;
use generic_array::{typenum::U16, GenericArray};
use rand::Rng;

use super::*;
use crate::crypto::{chunk_data_for_encryption, chunk_data_for_packet_split, history::*};
use crate::peer::*;

enum SentStatus {
    Awaiting,
    Synchronizing
}

/// Struct that ties [`Header`] and it's payload. The main purpose is checking if 
/// data piece is received
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

    pub(crate) fn sync(self) {
        *self.status.lock().unwrap() = SentStatus::Synchronizing;
    }
}

/// Struct for synchronizing [`Packet`]s transactions
#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
pub struct PacketSynchronizer {
    /// Timestamp of current transaction
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

    fn construct_rest(self) -> Transaction {
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
                    packet_id
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
                            p
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
}


