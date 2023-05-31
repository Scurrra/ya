//! YAP2P protocols logic

use crate::crypto::history::{ChatSynchronizer, ChatSynchronizers};

#[allow(unused_imports)]

use super::peer::{Peer, PeerId};

use bitflags::bitflags;
use serde::{Serialize, Deserialize};
use bincode;

pub mod sdp;

bitflags! {
    /// Protocols enum
    #[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
    #[repr(transparent)]
    #[serde(transparent)]
    pub struct ProtocolType : u8 {
        /// SDP --- Symmetric Datagram Protocol
        const SDP = 0b10000000;

        /// SSDP --- Self Symmetric Datagram Protocol
        const SSDP = 0b01000000;

        // reserved for future
    }
}

bitflags! {
    /// Packet types enum
    #[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
    #[repr(transparent)]
    #[serde(transparent)]
    pub struct PacketType : u8 {
        /// For inner use for now
        const ECHO =    0b10000000;

        /// Initial connection (one per history)
        const INIT =    0b01000000;
        
        /// Hello packet for full synchronization
        const HI =      0b00100000;

        /// First Hello packet in SelfSDP
        const HI_INIT = Self::INIT.bits() | Self::HI.bits();        
        
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

        /// `HI_INIT` packet `ACK`
        const ACK_HI_INIT = Self::ACK.bits() | Self::INIT.bits() | Self::HI.bits();
    }           
}

/// Common packet header
#[derive(Serialize, Deserialize, Debug)]
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
    /// 
    /// Arguments
    /// 
    /// * `protocol_type` --- protocol to be used
    /// * `packet_type` --- [`PacketType`]
    /// * `length` --- size of the packet
    /// * `src_id` --- sender [`PeerId`]
    /// * `rec_id` --- receiver [`PeerId`]
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

    /// Serialize [`Header`] into bytes
    /// 
    /// # Panics
    /// 
    /// This function should not panic, 
    /// but if it does the problem is in `bincode` crate
    pub fn serialize(&self) -> Vec<u8> {
        bincode::serialize(&self).unwrap()
    }

    /// Deserialize [`Header`] from `bytes`
    /// 
    /// # Panics
    /// 
    /// This function panics if `bytes.len() != 36` 
    #[track_caller]
    pub fn deserialize(bytes: Vec<u8>) -> Header {
        match bincode::deserialize(&bytes) {
            Ok(header) => header,
            Err(_) => panic!("Wrong size of `Header`"),
        }
    }
}

/// Interface for all synchronizers.
pub trait Synchronizer {  }

impl Synchronizer for ChatSynchronizer {  }
impl Synchronizer for ChatSynchronizers {  }