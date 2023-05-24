//! (Secure) Symmenric Datagram Protocol
//!
//!
//!

use std::arch::x86_64::_SIDD_MASKED_NEGATIVE_POLARITY;
use std::error::Error;
use std::ops::ControlFlow;
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

/// Symmenric Datagram Protocol struct
pub struct SdpConnection {
    /// `UdpSocket`, used for this connection
    socket: Arc<UdpSocket>,

    /// [`Contact`] tied with connection
    contact: Contact,

    /// Channel used to send packets
    send_channel: mpsc::Receiver<Message>,

    /// "Queue" of packets to be sent.
    /// Only one message at a time, despite that it's not encrypted
    send_queue: Mutex<HashMap<u16, Transaction>>,

    /// Waker for sending pending packets. If there is nothing to send the field is [`None`]
    send_waker: Option<Waker>
}

impl SdpConnection {
    //  Functions that do not require connection to the receiver [`Node`]

    /// Send initial packet to another [`Peer`]
    ///
    /// Arguments
    ///
    /// * `socket` --- [`UdpSocket`] to be used for sending
    /// * `chat_t` --- type of communication
    /// * `sender` --- [`PeerId`] of *this* [`Node`]
    /// * `receiver` --- [`Node`] and corresponding port number as tuple
    /// * `payload` --- packet's payload
    pub async fn init(
        socket: &UdpSocket,
        chat_t: Chat,
        sender: PeerId,
        receiver: (Node, u16),
        payload: &impl AsRef<[u8]>,
    ) -> std::io::Result<usize> {
        let length: u16 = 36 + payload.as_ref().len() as u16;
        let mut packet = match chat_t {
            Chat::OneToOne => Header::new(
                ProtocolType::SDP,
                PacketType::CHAT | PacketType::INIT,
                length,
                sender,
                receiver.0.peer.id.to_owned(),
            )
            .serialize(),
            Chat::Group => Header::new(
                ProtocolType::SDP,
                PacketType::CONV | PacketType::INIT,
                length,
                sender,
                receiver.0.peer.id.to_owned(),
            )
            .serialize(),
            Chat::Channel => Header::new(
                ProtocolType::SDP,
                PacketType::CHAN | PacketType::INIT,
                length,
                sender,
                receiver.0.peer.id.to_owned(),
            )
            .serialize(),
        };

        packet.extend_from_slice(payload.as_ref());

        if let Some(addr) = receiver.0.get_ipv6() {
            return socket.send_to(&packet, (addr, receiver.1)).await;
        } else if let Some(addr) = receiver.0.get_ipv4() {
            return socket.send_to(&packet, (addr, receiver.1)).await;
        } else {
            // there probably will be no errors returned, but...
            return Err(std::io::Error::last_os_error());
        }
    }

    /// Send "hi" packet to another [`Peer`]
    ///
    /// Arguments
    ///
    /// * `socket` --- [`UdpSocket`] to be used for sending
    /// * `chat_t` --- type of communication
    /// * `sender` --- [`PeerId`] of *this* [`Node`]
    /// * `receiver` --- [`Node`] and corresponding port number as tuple
    /// * `payload` --- packet's payload
    pub async fn recover(
        socket: &UdpSocket,
        chat_t: Chat,
        sender: PeerId,
        receiver: (Node, u16),
        payload: &impl AsRef<[u8]>,
    ) -> std::io::Result<usize> {
        let length: u16 = 36 + payload.as_ref().len() as u16;
        let mut packet = match chat_t {
            Chat::OneToOne => Header::new(
                ProtocolType::SDP,
                PacketType::CHAT | PacketType::HI,
                length,
                sender,
                receiver.0.peer.id.to_owned(),
            )
            .serialize(),
            Chat::Group => Header::new(
                ProtocolType::SDP,
                PacketType::CONV | PacketType::HI,
                length,
                sender,
                receiver.0.peer.id.to_owned(),
            )
            .serialize(),
            Chat::Channel => Header::new(
                ProtocolType::SDP,
                PacketType::CHAN | PacketType::HI,
                length,
                sender,
                receiver.0.peer.id.to_owned(),
            )
            .serialize(),
        };

        packet.extend_from_slice(payload.as_ref());

        if let Some(addr) = receiver.0.get_ipv6() {
            return socket.send_to(&packet, (addr, receiver.1)).await;
        } else if let Some(addr) = receiver.0.get_ipv4() {
            return socket.send_to(&packet, (addr, receiver.1)).await;
        } else {
            // there probably will be no errors returned, but...
            return Err(std::io::Error::last_os_error());
        }
    }

    //  Functions that do not require connection to the receiver [`Node`]

    /// Create new [`SdpConnection`] connection
    ///
    /// Arguments
    ///
    /// * `socket` --- UdpSocket, used for the connection
    pub async fn connect(
        &self, 
        socket: Arc<UdpSocket>,
        contact: Contact,
        send_channel: mpsc::Receiver<Message>
    ) -> SdpConnection {
        SdpConnection { 
            socket,
            contact,
            send_channel,
            send_queue: Mutex::new(HashMap::new()),
            send_waker: None
        }
    }

    /// Send service echo packet to another [`Peer`]
    ///
    /// Arguments
    ///
    /// * `sender` --- [`PeerId`] of *this* [`Node`]
    /// * `receiver` --- [`Node`] and corresponding port number as tuple
    pub async fn echo(
        &self,
        sender: &PeerId,
        receiver: (&Node, u16),
    ) -> std::io::Result<usize> {
        let packet = Header::new(
                ProtocolType::SDP,
                PacketType::ECHO,
                36, // just empty header *for now*
                sender.clone(),
                receiver.0.peer.id.to_owned(),
            )
            .serialize();

        if let Some(addr) = receiver.0.get_ipv6() {
            return self.socket.send_to(&packet, (addr, receiver.1)).await;
        } else if let Some(addr) = receiver.0.get_ipv4() {
            return self.socket.send_to(&packet, (addr, receiver.1)).await;
        } else {
            // there probably will be no errors returned, but...
            return Err(std::io::Error::last_os_error());
        }
    }

    /// Start sending the [`Message`]. Function constructs entities of special [`Transaction`]
    /// struct which defines which data should be sent. 
    /// 
    /// Arguments
    /// 
    /// * `chat_t` --- [`Chat`] type 
    /// * `message` --- the message to be sent
    /// * `chat_sync` --- synchronization information from the corresponding [`History`]
    pub fn send(
        &self, 
        chat_t: Chat,
        message: Message,
        chat_sync: ChatSynchronizer
    ) -> ControlFlow<(), u64> {
        if self.send_waker.is_none() {
            return ControlFlow::Break(());
        }

        let mut rng = rand::thread_rng();

        let packet_type = match chat_t {
            Chat::Channel => PacketType::CHAN | PacketType::SYN,
            Chat::Group => PacketType::CONV | PacketType::SYN,
            Chat::OneToOne => PacketType::CHAT | PacketType::SYN,
        };

        // [`Message.data`] into `payload`
        let payload = message.data.as_ref().clone().as_ref().to_owned();
        // and than split this payload
        let mut payloads = chunk_data_for_packet_split(payload, 1120);
        let first_payload = payloads.pop_front().unwrap();

        // number of packets in transaction
        let n_packets = payloads.len() as u64;

        // initial synchronizer for the first packet in transaction
        let first_packet_sync = PacketSynchronizer::new(
            message.timestamp, n_packets, rng.gen_range(u64::MIN..(u64::MAX - n_packets))
        );

        let mut send_queue = self.send_queue.lock().unwrap();
        for device_id in self.contact.devices() {
            (*send_queue).insert(
                device_id, 
                Transaction::First { 
                    first_packet: Packet::new(
                        ProtocolType::SDP,
                        packet_type,
                        &message.sender.id,
                        &self.contact.peer.id,
                        &chat_sync,
                        first_packet_sync.clone(), // works without cloning, but I don't trust
                        first_payload.clone()
                    ), 
                    rest_of_payload: payloads.clone()
                }
            );
        }

        // here to be `self.poll_send()` to set waker

        return ControlFlow::Continue(n_packets);
    }
}
