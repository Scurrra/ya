//! (Secure) Symmenric Datagram Protocol
//!
//!
//!

use std::net::Ipv4Addr;

use reqwest::header;
use tokio::net::UdpSocket;

use super::*;
use crate::crypto::{chunk_data, history::*};
use crate::peer::*;

/// Symmenric Datagram Protocol struct
pub struct SDP {
    /// `UdpSocket`, used for this connection
    socket: UdpSocket,
}

impl SDP {
    /// Create new [`SDP`] connection
    ///
    /// Arguments
    ///
    /// * `socket` --- UdpSocket, used for the connection
    pub async fn new(socket: UdpSocket) -> SDP {
        SDP { socket }
    }

    /// Send initial packet to another [`Peer`]
    ///
    /// Arguments
    ///
    /// * `chat_t` --- type of communication
    /// * `sender` --- [`PeerId`] of *this* [`Node`]
    /// * `receiver` --- [`Node`] and corresponding port number as tuple
    /// * `payload` --- packet's payload
    pub async fn init(
        &self,
        chat_t: Chat,
        sender: PeerId,
        receiver: (Node, u16),
        payload: &impl AsRef<[u8]>,
    ) -> std::io::Result<usize> {
        let length: u16 = 36 + 36 + payload.as_ref().len() as u16;
        let mut packet = match chat_t {
            Chat::OneToOne => Header::new(
                ProtocolType::SDP,
                PacketType::CHAT | PacketType::INIT,
                length,
                sender,
                receiver.0.peer.id.to_owned(),
            )
            .serialize()
            .unwrap(),
            Chat::Group => Header::new(
                ProtocolType::SDP,
                PacketType::CONV | PacketType::INIT,
                length,
                sender,
                receiver.0.peer.id.to_owned(),
            )
            .serialize()
            .unwrap(),
            Chat::Channel => Header::new(
                ProtocolType::SDP,
                PacketType::CHAN | PacketType::INIT,
                length,
                sender,
                receiver.0.peer.id.to_owned(),
            )
            .serialize()
            .unwrap(),
        };

        packet.extend_from_slice(payload.as_ref());

        if let Some(addr) = receiver.0.get_ipv6() {
            return self.socket.send_to(&packet, (addr, receiver.1)).await;
        } else if let Some(addr) = receiver.0.get_ipv4() {
            return self.socket.send_to(&packet, (addr, receiver.1)).await;
        } else {
            // there probably will be no errors returned, but...
            return Err(std::io::Error::last_os_error());
        }
    }

    /// Send "hi" packet to another [`Peer`]
    ///
    /// Arguments
    ///
    /// * `chat_t` --- type of communication
    /// * `sender` --- [`PeerId`] of *this* [`Node`]
    /// * `receiver` --- [`Node`] and corresponding port number as tuple
    /// * `payload` --- packet's payload
    pub async fn hi(
        &self,
        chat_t: Chat,
        sender: PeerId,
        receiver: (Node, u16),
        payload: &impl AsRef<[u8]>,
    ) -> std::io::Result<usize> {
        let length: u16 = 36 + 36 + payload.as_ref().len() as u16;
        let mut packet = match chat_t {
            Chat::OneToOne => Header::new(
                ProtocolType::SDP,
                PacketType::CHAT | PacketType::HI,
                length,
                sender,
                receiver.0.peer.id.to_owned(),
            )
            .serialize()
            .unwrap(),
            Chat::Group => Header::new(
                ProtocolType::SDP,
                PacketType::CONV | PacketType::HI,
                length,
                sender,
                receiver.0.peer.id.to_owned(),
            )
            .serialize()
            .unwrap(),
            Chat::Channel => Header::new(
                ProtocolType::SDP,
                PacketType::CHAN | PacketType::HI,
                length,
                sender,
                receiver.0.peer.id.to_owned(),
            )
            .serialize()
            .unwrap(),
        };

        packet.extend_from_slice(payload.as_ref());

        if let Some(addr) = receiver.0.get_ipv6() {
            return self.socket.send_to(&packet, (addr, receiver.1)).await;
        } else if let Some(addr) = receiver.0.get_ipv4() {
            return self.socket.send_to(&packet, (addr, receiver.1)).await;
        } else {
            // there probably will be no errors returned, but...
            return Err(std::io::Error::last_os_error());
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
        sender: PeerId,
        receiver: (Node, u16),
    ) -> std::io::Result<usize> {
        let packet = Header::new(
                ProtocolType::SDP,
                PacketType::ECHO,
                36, // just empty header *for now*
                sender,
                receiver.0.peer.id.to_owned(),
            )
            .serialize()
            .unwrap();

        if let Some(addr) = receiver.0.get_ipv6() {
            return self.socket.send_to(&packet, (addr, receiver.1)).await;
        } else if let Some(addr) = receiver.0.get_ipv4() {
            return self.socket.send_to(&packet, (addr, receiver.1)).await;
        } else {
            // there probably will be no errors returned, but...
            return Err(std::io::Error::last_os_error());
        }
    }

    ///
    pub async fn send(&self) {}

    ///
    pub async fn recv(&self) {}


}
