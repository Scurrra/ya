//! 
//! 
//! 
//! 
//! 

#![allow(missing_docs)]

use super::peer::PeerId;

use std::boxed::Box;

use bitflags::bitflags;

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    #[repr(transparent)]
    pub struct ProtocolType : u8 {
        const SDP = 0b10000000;
        const SSDP = 0b01000000;

        // reserved for future
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    #[repr(transparent)]
    pub struct PacketType : u8 {
        const ECHO =    0b10000000;
        const INIT =    0b01000000;
        const HI =      0b00100000;
        const SYN =     0b00010000;
        const ACK =     0b00001000;

        const CHAT =    0b00000100;
        const CONV =    0b00000010;
        const CHAN =    0b00000001;

        const ACK_SYN = Self::ACK.bits() | Self::SYN.bits();
    }           
}

pub struct Header {
    pub protocol_type: ProtocolType,
    pub packet_type: PacketType,
    pub length: u16,
    pub src_id: PeerId,
    pub rec_id: PeerId
}

impl Header {
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