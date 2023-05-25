use std::ops::ControlFlow;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::collections::{HashMap, VecDeque};

use tokio::net::UdpSocket;
use futures::channel::mpsc;
use generic_array::{typenum::U16, GenericArray};
use rand::Rng;

use super::*;
use crate::crypto::history::*;
use crate::peer::*;
use crate::utils::chunk_data_for_packet_split;

/// Symmenric Datagram Protocol struct
pub struct SdpConnection {
    /// `UdpSocket`, used for this connection
    socket: Arc<UdpSocket>,

    /// [`Contact`] tied with connection
    contact: Contact,

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
    /// * `socket` --- [`UdpSocket`], used for the connection
    /// * `contact` --- [`Contact`], tied with the connection
    pub async fn new(
        &self, 
        socket: Arc<UdpSocket>,
        contact: Contact,
    ) -> SdpConnection {
        SdpConnection { 
            socket,
            contact,
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