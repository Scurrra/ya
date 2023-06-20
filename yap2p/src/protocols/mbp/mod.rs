//! 
//! 
//! 

use std::error::Error;
use std::net::SocketAddr;
use std::collections::{VecDeque, HashSet, HashMap};
use std::task::{Context, Poll};
use std::future::Future;
use std::task::Waker;
use std::pin::Pin;
use std::time::{Instant, Duration};

use serde::{Serialize, Deserialize};
use bincode;
use rand::Rng;
use tokio::io::ReadBuf;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

use super::*;
use crate::crypto::history::*;
use crate::peer::*;

const RECEIVE_BUFFER_SIZE: usize = 1220;

/// [`Node`]s from MeshNet layer
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct MeshContacts {
    /// [`Node`]s with static addresses, which could be used as "servers". 
    /// If a [`Node`] has a static address but could not be used as a "server", it's marked as dynamic.
    static_nodes: Vec<(Node, u16)>,

    /// [`Node`]s which public IPs are dynamic and are continuously changing.
    dynamic_nodes: Vec<(Node, u16)>
}

impl MeshContacts {
    /// Serialize [`MeshContacts`] into bytes
    /// 
    /// # Panics
    /// 
    /// This function should not panic, 
    /// but if it does the problem is in `bincode` crate
    pub(crate) fn serialize(&self) -> Vec<u8> {
        bincode::serialize(&self).unwrap()
    }

    /// Deserialize [`MeshContacts`] from `bytes`
    #[track_caller]
    pub(crate) fn deserialize(bytes: Vec<u8>) -> MeshContacts {
        match bincode::deserialize(&bytes) {
            Ok(contacts) => contacts,
            Err(_) => panic!("Wrong size of `MeshContacts`"),
        }
    }
}

/// Struct to keep [`Node`]s alive
struct Scheduler {
    /// Last moment [`Node`] sent `ECHO` packet 
    echoed: Instant,

    /// RTT to the [`Node`]
    rtt: Duration
}

pub struct MbpDriver {
    /// Socket used by the driver
    socket: UdpSocket,

    /// "Neighbors" of the [`Node`]
    static_nodes: Vec<(Node, u16)>,
    dynamic_nodes: Vec<(Node, u16)>,

    /// The way to find out "dead" [`Node`]s
    nodes_scheduler: HashMap<Node, Scheduler>
}

impl MbpDriver {
    /// Create new [`MbpDriver`]
    /// 
    /// Arguments
    /// 
    /// * `socket` --- UDP socket driver works with
    /// * `static_nodes` --- [`Node`]s with static IPs
    /// * `dynamic_nodes` --- [`Node`]s with dynamic addresses; we hope, that they have not been changed yet
    pub fn new(
        socket: UdpSocket,
        static_nodes: Vec<(Node, u16)>,
        dynamic_nodes: Vec<(Node, u16)>
    ) -> MbpDriver {
        // here we should measure rtts to all nodes in net and send them `ECHO` packets

        MbpDriver { 
            socket, 
            static_nodes, 
            dynamic_nodes,
            nodes_scheduler: HashMap::new()
        }
    }
}

impl Future for MbpDriver {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // Order:
        // 1. handle incoming packets
        // 2. send echo packets
        loop {
            // handling incoming packet 
            let mut buf_array = [0u8; RECEIVE_BUFFER_SIZE];
            let mut readbuf = ReadBuf::new(&mut buf_array);
            match self.socket.poll_recv_from(cx, &mut readbuf) {
                Poll::Ready(Ok(src_socket)) => {
                    let packet = readbuf.filled().to_vec();
                    let header = Header::deserialize(packet[0..36].to_vec());
                    let contacts = MeshContacts::deserialize(packet[36..].to_vec());

                    if header.protocol_type == ProtocolType::MBP {
                        match header.packet_type {
                            PacketType::INIT => {

                            },
                            PacketType::ACK_INIT => {

                            },
                            PacketType::HI => {

                            },
                            PacketType::ACK_HI => {

                            },
                            PacketType::ECHO => {

                            },
                            _ => {
                                // other types of packets are not supported
                            }
                        }
                    } else {
                        // wrong protocol
                    }

                    if let Some(contact) = self.static_nodes.iter()
                        .chain(self.dynamic_nodes.iter())
                        .find(|(node, port)| 
                            node.addrs.lock().unwrap().satisfies(src_socket.ip())
                                && port.to_owned() == src_socket.port()
                    ) {
                        
                    }
                },
                Poll::Ready(Err(_)) => {
                    continue;
                },
                Poll::Pending => {}
            }
        }
        return Poll::Ready(());
    }
}