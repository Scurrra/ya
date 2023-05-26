use std::ops::ControlFlow;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::collections::{HashMap, VecDeque};

use tokio::net::UdpSocket;
use futures::{
    channel::mpsc,
    ready
};
use rand::Rng;

use super::*;
use crate::crypto::history::*;
use crate::peer::*;
use crate::utils::chunk_data_for_packet_split;

/// Symmenric Datagram Protocol Connection struct
/// 
/// This struct is only for sending.
pub struct SdpConnection {
    /// `UdpSocket`, used for this connection
    socket: Arc<UdpSocket>,

    /// [`Contact`] tied with connection
    contact: Contact,

    /// "Queue" of packets to be sent.
    /// Only one message at a time, despite that it's not encrypted
    send_queue: Mutex<HashMap<u16, Transaction>>,

    /// Waker for sending pending packets. If there is nothing to send field is [`ConnectionState::Pending`]
    state: Mutex<ConnectionState>
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

    /// Create new SDP connection
    ///
    /// Arguments
    ///
    /// * `socket` --- [`UdpSocket`], used for the connection
    /// * `contact` --- [`Contact`], tied with the connection
    pub fn new( 
        socket: Arc<UdpSocket>,
        contact: Contact,
    ) -> SdpConnection {
        SdpConnection { 
            socket,
            contact,
            send_queue: Mutex::new(HashMap::new()),
            state: Mutex::new(ConnectionState::Pending)
        }
    }

    //  Functions that do require connection to the receiver [`Node`]

    /// Function for checking if [`SdpConnection`] is connected to the specified [`SocketAddr`]
    pub fn check_addr(&self, socket_addr: SocketAddr) -> Option<u16> {
        let addrs = self.contact.addrs.lock().unwrap();
        if addrs.len() == 0 {
            return None;
        }
        
        let addr_ip = socket_addr.ip();
        let addr_port = socket_addr.port();

        if let Some(device) = addrs.iter()
            .find(
                |(id, addr)| addr.0.satisfies(addr_ip) && addr.1 == addr_port
            ){
            return Some(device.0.to_owned());
        }

        return None;
    }
}

impl Connection for SdpConnection {
    /// Send service echo packet to another [`Peer`]
    ///
    /// Arguments
    ///
    /// * `sender` --- [`PeerId`] of *this* [`Node`]
    /// * `receiver` --- [`Node`] and corresponding port number as tuple
    fn echo(
        &self, cx: &mut Context<'_>,
        sender: &PeerId,
        receiver: (&Node, u16),
    ) -> Poll<std::io::Result<usize>> {
        let packet = Header::new(
                ProtocolType::SDP,
                PacketType::ECHO,
                36, // just empty header *for now*
                sender.clone(),
                receiver.0.peer.id.to_owned(),
            )
            .serialize();

        if let Some(addr) = receiver.0.get_ipv6() {
            return self.socket.poll_send_to(cx, &packet, (addr, receiver.1).into());
        } else if let Some(addr) = receiver.0.get_ipv4() {
            return self.socket.poll_send_to(cx, &packet, (addr, receiver.1).into());
        } else {
            // there probably will be no errors returned, but...
            return Poll::Ready(Err(std::io::Error::last_os_error()));
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
    fn send(
        &self, 
        chat_t: Chat,
        message: Message,
        chat_sync: ChatSynchronizer
    ) -> ControlFlow<(), u64> {
        let mut state = self.state.lock().unwrap();
        match *state {
            ConnectionState::Sending(_) => {
                return ControlFlow::Break(());
            },
            ConnectionState::Pending => {
                // will be changed in `poll_send`
                *state = ConnectionState::Sending(None);
            }
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

    fn poll_send(&self, cx: &mut Context<'_>) -> Poll<Result<(), Box<dyn Error>>> {
        // set waker
        // waker will be killed in driver
        let mut state = self.state.lock().unwrap();
        match *state {
            ConnectionState::Sending(None) => {
                (*state) = ConnectionState::Sending(Some(
                    cx.waker().clone()
                ))
            },
            ConnectionState::Pending => {
                return Poll::Ready(Err("`SdpConnection.poll_send` can't be called on state `ConnectionState::Pending`".into()))
            }
            _ => {}
        }

        // does not need to be mutable
        let send_queue = self.send_queue.lock().unwrap();   
        let mut devices_to_be_killed = Vec::new();     
        // iterate throw the send_queue
        // [`Transaction::First`] is checked because it's a match
        // P. S. if somehow occurs that transactions can't mutate, it't because of `(*send_queue).iter()`  
        // P. P. S. using `send_queue.iter()` fixes (because of borrow of MutexGuard?)
        // P. P. P. S. but it also does not allow to delete dead transactions
        for (device_id, transaction) in (*send_queue).iter() {
            let addr = self.contact.get_addr(*device_id).unwrap();
            
            match transaction {
                Transaction::First { 
                    first_packet, 
                    rest_of_payload: _
                } => {
                    // convert `(Addr, u16)` to SocketAddr
                    if let Some(addr_ip) = addr.0.V6 {
                        let addr = (addr_ip, addr.1).into();

                        if let Ok(n_bytes_sent) = ready!(self.socket.poll_send_to(
                            cx, 
                            first_packet.serialize().as_ref(), 
                            addr
                        )) {
                            // first_packet.sync() is never called, because it should be deleted 
                            // right after SYN | ACK

                            // if n_bytes_sent as u16 == first_packet.header.length {
                            //     first_packet.sync();
                            // }
                        } // if wasn't sent, it will not be sync
                    } else if let Some(addr_ip) = addr.0.V4 {
                        // oh, it's not *dry*
                        // WET CODE!
                        let addr = (addr_ip, addr.1).into();

                        if let Ok(n_bytes_sent) = ready!(self.socket.poll_send_to(
                            cx, 
                            first_packet.serialize().as_ref(), 
                            addr
                        )) {
                            // first_packet.sync() is never called, because it should be deleted 
                            // right after SYN | ACK

                            // if n_bytes_sent as u16 == first_packet.header.length {
                            //     first_packet.sync();
                            // }
                        } // if wasn't sent, it will not be sync
                    } else {
                        // this should be empty
                        // but if destination host is dead, we should somehow delete it

                        // may be will work, at least should
                        devices_to_be_killed.push(device_id);
                    };                   
                }

                Transaction::Rest { 
                    first_packet_id: _, // dead logic, at least for now
                    payload 
                } => {
                    let mut payload = payload.lock().unwrap();
                    let current_packet = (*payload).pop_front().unwrap();

                    // convert `(Addr, u16)` to SocketAddr
                    // change logic if it's changed in previous case
                    if let Some(addr_ip) = addr.0.V6 {
                        let addr = (addr_ip, addr.1).into();

                        if let Ok(n_bytes_sent) = ready!(self.socket.poll_send_to(
                            cx, 
                            current_packet.serialize().as_ref(), 
                            addr
                        )) {
                            if n_bytes_sent as u16 == current_packet.header.length {
                                current_packet.sync();
                            }
                        } // if wasn't sent, it will not be sync
                    } else if let Some(addr_ip) = addr.0.V4 {
                        // oh, it's not *dry*
                        // WET CODE!
                        let addr = (addr_ip, addr.1).into();

                        if let Ok(n_bytes_sent) = ready!(self.socket.poll_send_to(
                            cx, 
                            current_packet.serialize().as_ref(), 
                            addr
                        )) {
                            if n_bytes_sent as u16 == current_packet.header.length {
                                current_packet.sync();
                            }
                        } // if wasn't sent, it will not be sync
                    } else {
                        // this should be empty
                        // but if destination host is dead, we should somehow delete it

                        // may be will work
                        devices_to_be_killed.push(device_id);
                    };

                    // so packet is pushed to the end of the queue
                    // even packet with status `SentStatus::Synchronizing` can be sent again 
                    // I don't want to add timer here, but may be timer should be restarted after the last sending
                    (*payload).push_back(current_packet);
                }
            }
        }
        
        // because of immutable borrow in previous loop
        let mut send_queue = self.send_queue.lock().unwrap();
        // update: see P. P. S. before the loop
        // here dead connections be killed
        for dead in devices_to_be_killed {
            (*send_queue).remove(dead);
        }

        // if we kill all connections, we panic
        if send_queue.len() == 0 {
            return Poll::Ready(Err("All `Nodes` are dead before end of the transaction".into()));
        }

        // no way to return `Poll::Ready(())` because of it's semantics: poll is ready when all packets send 
        // and acknowledged what is checked while handling the message
        return Poll::Pending;
    }
}

/// Symmenric Datagram Protocol Driver struct
/// 
/// This struct is only for receiving. 
pub struct SdpDriver {
    /// [`PeerId`] of current [`Peer`]
    pub peer_id: PeerId,

    /// List of connections driver is responsible for
    pub connections: Vec<SdpConnection>,

    /// Channel for sending [`Message`]s
    pub(crate) sending: mpsc::Receiver<MessageWrapper>,

    /// Channel for receiving [`Message`]s, including `INIT` and `HI`
    pub(crate) receiving: mpsc::Sender<MessageWrapper>,

    // maps of currently handled transmissions
    handling: HashMap<[u8; 32], MessageHandler>, // for `SYN`
    acknowledging: HashMap<[u8; 32], Vec<u64>> // for `ACK`
}

impl SdpDriver {

    /// Create new SDP driver
    ///
    /// Arguments
    ///
    /// * `socket` --- [`UdpSocket`], used for the driver and inside connections
    /// * `contacts` --- list of [`Contact`]s, tied with the driver
    pub fn new(
        peer_id: &PeerId,
        socket: UdpSocket,
        contacts: Vec<Contact>
    ) -> (SdpDriver, mpsc::Sender<MessageWrapper>, mpsc::Receiver<MessageWrapper>) {
        let socket = Arc::new(socket);

        let mut connections = Vec::with_capacity(contacts.len());
        for contact in contacts {
            connections.push(
                SdpConnection::new( 
                    socket.clone(), 
                    contact
                )
            );
        }

        let (sending_tx, sending_rx) = mpsc::channel(CHANNEL_CAPACITY);
        let (receiving_tx, receiving_rx) = mpsc::channel(CHANNEL_CAPACITY);

        let driver = SdpDriver {
            peer_id: peer_id.clone(),
            connections,
            sending: sending_rx,
            receiving: receiving_tx,
            handling: HashMap::new(),
            acknowledging: HashMap::new()
        };

        (driver, sending_tx, receiving_rx)
    }
}

impl Driver for SdpDriver {
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
    ) -> ControlFlow<Result<(), Box<dyn Error>>, [u8; 32]>{

        // [`Packet`] [`Header`] processing
        let header = Header::deserialize(packet[0..36].to_vec());
        // check if packet is `ECHO`
        if header.packet_type.contains(PacketType::ECHO) {
            // check destination
            if header.rec_id != self.peer_id {
                return ControlFlow::Break(Err("'ECHO' for another peer. May be an attack".into()));
            }

            if header.packet_type == PacketType::ECHO {
                return ControlFlow::Break(Ok(()));
            } else {
                return ControlFlow::Break(Err("Bad constructed 'ECHO' packet".into()));
            }
        }
        // check destination
        if header.rec_id != self.peer_id {
            return ControlFlow::Break(Err("Wrong receiver".into()));
        }
        // check protocol type
        if header.protocol_type != ProtocolType::SDP {
            return ControlFlow::Break(Err("It's not an SDP packet".into()));
        }
        // check packet length
        if header.length as usize != packet.len() {
            return ControlFlow::Break(Err("Packet length mismatch".into()));
        }
        // obtain packet and chat type
        let (packet_type, chat_t) = if header.packet_type.contains(PacketType::CHAT) {
            (header.packet_type.difference(PacketType::CHAT), Chat::OneToOne)
        } else if header.packet_type.contains(PacketType::CHAN) {
            (header.packet_type.difference(PacketType::CHAN), Chat::Channel)
        } else if header.packet_type.contains(PacketType::CONV) {
            (header.packet_type.difference(PacketType::CONV), Chat::Group)
        } else {
            return ControlFlow::Break(Err("Wrong packet type".into()));
        };

        // check packet type
        match packet_type {
            PacketType::INIT => { 
                // chat for initializing
                let chat_sync = ChatSynchronizer::deserialize(packet[36..76].to_vec());
                // message sender
                let src_peer = if let Some(alive_conn) = self.connections.iter()
                    .find(
                |   conn| conn.contact.peer.id == header.src_id
                ){
                    match alive_conn.check_addr(packet_src) {
                        None => return ControlFlow::Break(Err("No connections to the address, while connected to the peer".into())),
                        Some(_) => alive_conn.contact.peer.clone()
                    }
                } else {
                    return ControlFlow::Break(Err("No connections to the source peer".into()));
                };
                // finally sending handled message to channel
                if let Err(e) = self.receiving.try_send(
                    MessageWrapper::Initial { 
                            ack: false, 
                            peer: src_peer, 
                            history: chat_sync
                }) {
                    // attempt to handle channel error
                    return ControlFlow::Break(Err(e.into()));
                }
            },
            PacketType::HI => {
                let chats_n = ((header.length - 36) / 40) as usize;
                // chats for synchronization
                let mut chat_syncs = Vec::with_capacity(chats_n.into());
                for chat_i in 0..chats_n {
                    chat_syncs.push(
                        ChatSynchronizer::deserialize(packet[(36+chat_i*40)..(36+(chat_i+1)*40)].to_vec())
                    );
                }
                // message sender
                let src_peer = if let Some(alive_conn) = self.connections.iter()
                    .find(
                |   conn| conn.contact.peer.id == header.src_id
                ){
                    match alive_conn.check_addr(packet_src) {
                        None => return ControlFlow::Break(Err("No connections to the address, while connected to the peer".into())),
                        Some(_) => alive_conn.contact.peer.clone()
                    }
                } else {
                    return ControlFlow::Break(Err("No connections to the source peer".into()));
                };
                // finally sending handled message to channel
                if let Err(e) = self.receiving.try_send(
                    MessageWrapper::Recover { 
                            ack: false, 
                            peer: src_peer, 
                            histories: chat_syncs
                }) {
                    // attempt to handle channel error
                    return ControlFlow::Break(Err(e.into()));
                }
            },
            PacketType::SYN => {
                // chat for the message
                let chat_sync = ChatSynchronizer::deserialize(packet[36..76].to_vec());
                // check if connection is alive
                if let Some(alive_conn) = self.connections.iter()
                    .find(
                        |conn| conn.contact.peer.id == header.src_id
                ){
                    match alive_conn.check_addr(packet_src) {
                        None => {
                            // drop transaction if it is started
                            self.handling.remove(&chat_sync.chat_id);
                            return ControlFlow::Break(Err("No connections to the address, while connected to the peer".into()))
                        },
                        Some(_) => {}
                    }
                } else {
                    // drop transaction if it is started
                    self.handling.remove(&chat_sync.chat_id);
                    return ControlFlow::Break(Err("No connections to the source peer".into()));
                };
                
                // getting packet synchronizer from 
                let packet_sync = PacketSynchronizer::deserialize(packet[76..100].to_vec());
                // add packet to the handling list
                if self.handling.contains_key(&chat_sync.chat_id) {
                    // I hope it will work
                    if let Some(data) = self.handling.get_mut(&chat_sync.chat_id) {
                        data.data.push((packet_sync.packet_id, packet[100..].to_vec()));
                    }
                } else { // first message in the transaction
                    self.handling.insert(
                        chat_sync.chat_id,
                        MessageHandler { 
                            chat_t: chat_t, 
                            timestamp_l: chat_sync.timestamp, 
                            first_packet_sync: packet_sync, 
                            data: Vec::from([(packet_sync.packet_id, packet[100..].to_vec())]) 
                        } 
                    );
                }
            },
            PacketType::ACK_INIT => { // like `INIT`, but another flag
                // chat for initializing
                let chat_sync = ChatSynchronizer::deserialize(packet[36..76].to_vec());
                // message sender
                let src_peer = if let Some(alive_conn) = self.connections.iter()
                    .find(
                |   conn| conn.contact.peer.id == header.src_id
                ){
                    match alive_conn.check_addr(packet_src) {
                        None => return ControlFlow::Break(Err("No connections to the address, while connected to the peer".into())),
                        Some(_) => alive_conn.contact.peer.clone()
                    }
                } else {
                    return ControlFlow::Break(Err("No connections to the source peer".into()));
                };
                // finally sending handled message to channel
                if let Err(e) = self.receiving.try_send(
                    MessageWrapper::Initial { 
                            ack: true, 
                            peer: src_peer, 
                            history: chat_sync
                }) {
                    // attempt to handle channel error
                    return ControlFlow::Break(Err(e.into()));
                }
            },
            PacketType::ACK_HI => { // like `HI`, but another flag
                let chats_n = ((header.length - 36) / 40) as usize;
                // chats for synchronization
                let mut chat_syncs = Vec::with_capacity(chats_n.into());
                for chat_i in 0..chats_n {
                    chat_syncs.push(
                        ChatSynchronizer::deserialize(packet[(36+chat_i*40)..(36+(chat_i+1)*40)].to_vec())
                    );
                }
                // message sender
                let src_peer = if let Some(alive_conn) = self.connections.iter()
                    .find(
                |   conn| conn.contact.peer.id == header.src_id
                ){
                    match alive_conn.check_addr(packet_src) {
                        None => return ControlFlow::Break(Err("No connections to the address, while connected to the peer".into())),
                        Some(_) => alive_conn.contact.peer.clone()
                    }
                } else {
                    return ControlFlow::Break(Err("No connections to the source peer".into()));
                };
                // finally sending handled message to channel
                if let Err(e) = self.receiving.try_send(
                    MessageWrapper::Recover { 
                            ack: true, 
                            peer: src_peer, 
                            histories: chat_syncs
                }) {
                    // attempt to handle channel error
                    return ControlFlow::Break(Err(e.into()));
                }
            },
            PacketType::ACK_SYN => {
                // chat for the message
                let chat_sync = ChatSynchronizer::deserialize(packet[36..76].to_vec());
                // check if connection is alive
                if let Some(alive_conn) = self.connections.iter()
                    .find(
                        |conn| conn.contact.peer.id == header.src_id
                ){
                    match alive_conn.check_addr(packet_src) {
                        None => {
                            // drop transaction if it is started
                            self.handling.remove(&chat_sync.chat_id);
                            return ControlFlow::Break(Err("No connections to the address, while connected to the peer".into()))
                        },
                        Some(_) => {}
                    }
                } else {
                    // drop transaction if it is started
                    self.handling.remove(&chat_sync.chat_id);
                    return ControlFlow::Break(Err("No connections to the source peer".into()));
                };
                
                // getting packet synchronizer from 
                let packet_sync = PacketSynchronizer::deserialize(packet[76..100].to_vec());
                // first message in the transaction
                if let Some(_) = self.acknowledging.insert(
                        chat_sync.chat_id,
                        Vec::from([packet_sync.packet_id])
                ){
                    return ControlFlow::Break(Err("Try to receive `ACK_SYN` once again".into()));
                }
            },
            PacketType::ACK => {
                // chat for the message
                let chat_sync = ChatSynchronizer::deserialize(packet[36..76].to_vec());
                // check if connection is alive
                if let Some(alive_conn) = self.connections.iter()
                    .find(
                        |conn| conn.contact.peer.id == header.src_id
                ){
                    match alive_conn.check_addr(packet_src) {
                        None => {
                            // drop transaction if it is started
                            self.handling.remove(&chat_sync.chat_id);
                            return ControlFlow::Break(Err("No connections to the address, while connected to the peer".into()))
                        },
                        Some(_) => {}
                    }
                } else {
                    // drop transaction if it is started
                    self.handling.remove(&chat_sync.chat_id);
                    return ControlFlow::Break(Err("No connections to the source peer".into()));
                };
                
                // getting packet synchronizer from 
                let packet_sync = PacketSynchronizer::deserialize(packet[76..100].to_vec());
                // add packet to the handling list
                if self.handling.contains_key(&chat_sync.chat_id) {
                    // I hope it will work
                    if let Some(data) = self.acknowledging.get_mut(&chat_sync.chat_id) {
                        data.push(packet_sync.packet_id);
                    }
                }
            },
            _ => {
                return ControlFlow::Break(Err("Unkhown packet type".into()));
            }
        }
        
        // if everything okay
        ControlFlow::Break(Ok(()))
    }

    /// Function for handling a single message
    /// 
    /// Arguments 
    /// 
    /// * `chat_id` --- id of the chat the message belongs to
    fn handle_message(
        &mut self, 
        chat_id: &[u8; 32]
    ) -> ControlFlow<Result<(), Box<dyn Error>>, ()> {
        if let Some(mut handler) = self.handling.remove(chat_id) {
            // wrong first packet
            if handler.data[0].0 != handler.first_packet_sync.packet_id {
                return ControlFlow::Break(Err("Wrong first packet".into()));
            }
            // wrong quantity of packets
            if handler.data.len() != handler.first_packet_sync.n_packets as usize {
                return ControlFlow::Break(Err("Wrong number of packets".into()));
            }
            
            handler.data
                .sort_by(
                    |(packet_id_1, _), (packet_id_2, _)| 
                    packet_id_1.cmp(packet_id_2)
            );

            // wrong quantity of packets, but deduped
            let mut ids = handler.data.iter()
                .map(|(id, _)| id.to_owned())
                .collect::<Vec<u64>>();
            ids.dedup();
            if ids.len() != handler.first_packet_sync.n_packets as usize {
                return ControlFlow::Break(Err("Wrong number of packets".into()));
            }
            if ids.last().unwrap() - ids.first().unwrap() + 1 != handler.first_packet_sync.n_packets {
                return ControlFlow::Break(Err("Wrong packets order".into()));
            }
            
            // collect payload
            let payload = handler.data.iter()
                .map(|(_, data)| data.to_owned())
                .collect::<Vec<Vec<u8>>>()
                .concat();
            
            if let Err(e) = self.receiving.try_send(
                MessageWrapper::Regular { 
                    chat_t: handler.chat_t, 
                    chat_sync: ChatSynchronizer { 
                        chat_id: chat_id.to_owned(), 
                        timestamp: handler.timestamp_l
                    }, 
                    payload: payload 
                }  
            ) {
                // attempt to handle channel error
                return ControlFlow::Break(Err(e.into()));
            }
        } else {
            return ControlFlow::Break(Err("Can't get message handler".into()));
        }
        ControlFlow::Break(Ok(()))
    }
}

impl Future for SdpDriver {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        loop {

        }
    }
}