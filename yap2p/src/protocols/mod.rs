//! YAP2P protocols logic

use super::peer::{Peer, PeerId};

use bitflags::bitflags;

bitflags! {
    /// Protocols enum
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    #[repr(transparent)]
    pub struct ProtocolType : u8 {
        /// SDP --- Symmetric Datagram Protocol
        const SDP = 0b10000000;

        /// SSDP --- Secure Symmetric Datagram Protocol
        const SSDP = 0b01000000;

        // reserved for future
    }
}

bitflags! {
    /// Packet types enum
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    #[repr(transparent)]
    pub struct PacketType : u8 {
        /// For inner use for now
        const ECHO =    0b10000000;

        /// Initial connection (one per history)
        const INIT =    0b01000000;
        
        /// Hello packet for full synchronization
        const HI =      0b00100000;
        
        /// Synchronization packet for data transfission
        const SYN =     0b00010000;
        
        /// Acknowledgement packet
        const ACK =     0b00001000;

        
        /// 1-1 chat
        const CHAT =    0b00000100;
        
        /// n-n chat, or conversation
        const CONV =    0b00000010;
        
        /// 1-n chat, or channel
        const CHAN =    0b00000001;

        
        /// First `SYN` packet `ACK`
        const ACK_SYN = Self::ACK.bits() | Self::SYN.bits();

        /// `HI` packet `ACK`
        const ACK_HI = Self::ACK.bits() | Self::HI.bits();
        
        /// `INIT` packet `ACK`
        const ACK_INIT = Self::ACK.bits() | Self::INIT.bits();
    }           
}

/// Common packet header
pub struct Header {
    /// Protocol type
    pub protocol_type: ProtocolType,
    
    /// Packet type
    pub packet_type: PacketType,

    /// Length of packet in bytes
    pub length: u16,

    /// Source [`Peer`]'s Id
    pub src_id: PeerId,

    /// Receiver [`Peer`]'s Id
    pub rec_id: PeerId
}

impl Header {
    /// [`Header`] constructor
    pub fn new(
        protocol_type: ProtocolType,
        packet_type: PacketType,
        length: u16,
        src_id: PeerId,
        rec_id: PeerId
    ) -> Header {
        Header {
            protocol_type, packet_type, length, 
            src_id, rec_id
        }
    }
}