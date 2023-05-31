use std::ops::ControlFlow;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::future::Future;
use std::collections::{HashMap, VecDeque};

use tokio::{
    net::UdpSocket,
    io::ReadBuf
};
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
    state: Mutex<ConnectionWaker>
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
    /// * `chat_sync` --- [`ChatSynchronizer`] of the chat to be synchronized
    pub async fn init(
        socket: &UdpSocket,
        chat_t: Chat,
        sender: PeerId,
        receiver: (Node, u16),
        chat_sync: ChatSynchronizer,
    ) -> std::io::Result<usize> {
        let chat_sync = chat_sync.serialize();
        let length: u16 = 36 + chat_sync.len() as u16;
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

        packet.extend_from_slice(&chat_sync);

        if let Some(addr) = receiver.0.get_ipv6() {
            return socket.send_to(&packet, (addr, receiver.1)).await;
        } else if let Some(addr) = receiver.0.get_ipv4() {
            return socket.send_to(&packet, (addr, receiver.1)).await;
        } else {
            // there probably will be no errors returned, but...
            return Err(std::io::Error::last_os_error());
        }
    }

    /// Send `HI` packet to another [`Peer`]
    ///
    /// Arguments
    ///
    /// * `socket` --- [`UdpSocket`] to be used for sending
    /// * `chat_t` --- type of communication
    /// * `sender` --- [`PeerId`] of *this* [`Node`]
    /// * `receiver` --- [`Node`] and corresponding port number as tuple
    /// * `chat_syncs` --- [`ChatSynchronizers`] of the chats to be synchronized
    pub async fn recover(
        socket: &UdpSocket,
        chat_t: Chat,
        sender: PeerId,
        receiver: (Node, u16),
        chat_syncs: ChatSynchronizers,
    ) -> std::io::Result<usize> {
        let chat_syncs = chat_syncs.serialize();
        let length: u16 = 36 + chat_syncs.len() as u16;
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

        packet.extend_from_slice(&chat_syncs);

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
            state: Mutex::new(ConnectionWaker {
                state: ConnectionState::Pending,
                waker: None
            })
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
                |(_, addr)| addr.0.satisfies(addr_ip) && addr.1 == addr_port
            ){
            return Some(device.0.to_owned());
        }

        return None;
    }

    /// Construct the rest of the packets for `device_id`
    // We need this because of its Rust, you know
    // but it should work
    pub fn construct_rest(&self, device_id: u16, packet_id: u64) {
        let mut send_queue = self.send_queue.lock().unwrap();
        let transaction = send_queue.remove(&device_id).unwrap();
        (*send_queue).insert(
            device_id,
            transaction.construct_rest(packet_id)
        );
    }

    /// Acknowledge specified packets for `device_id`
    // We need this because of its Rust, you know
    // but it should work
    pub fn ack_packets(&self, device_id: u16, packet_ids: &Vec<u64>) {
        let send_queue = self.send_queue.lock().unwrap();
        send_queue[&device_id].ack_packets(packet_ids);
    }

    /// Send `ACK` packet for the first [`Packet`]
    /// 
    /// Arguments
    /// 
    /// * `socket` --- local UDP socket
    /// * `chat_t` --- [`Chat`] type
    /// * `sender` --- sender id
    /// * `receiver` --- receiver id (id of `SYN` sender)
    /// * `receiver_sock` --- receiver socket address
    /// * `packet_sync` --- [`PacketSynchronizer`] of the first packet
    fn ack_first(
        cx: &mut Context<'_>,
        socket: &UdpSocket,
        chat_t: Chat,
        sender: PeerId,
        receiver: PeerId,
        receiver_sock: SocketAddr,
        packet_sync: PacketSynchronizer,
    ) -> Poll<std::io::Result<usize>> {
        let packet_sync = packet_sync.serialize();
        let length: u16 = 36 + packet_sync.len() as u16;
        let mut packet = match chat_t {
            Chat::OneToOne => Header::new(
                ProtocolType::SDP,
                PacketType::CHAT | PacketType::ACK_SYN,
                length,
                sender,
                receiver,
            )
            .serialize(),
            Chat::Group => Header::new(
                ProtocolType::SDP,
                PacketType::CONV | PacketType::ACK_SYN,
                length,
                sender,
                receiver,
            )
            .serialize(),
            Chat::Channel => Header::new(
                ProtocolType::SDP,
                PacketType::CHAN | PacketType::ACK_SYN,
                length,
                sender,
                receiver,
            )
            .serialize(),
        };

        packet.extend_from_slice(&packet_sync);

        socket.poll_send_to(cx, &packet, receiver_sock)
    }

    /// Send `ACK` packet for the bunch of [`Packet`]s
    /// 
    /// Arguments
    /// 
    /// * `socket` --- local UDP socket
    /// * `chat_t` --- [`Chat`] type
    /// * `sender` --- sender id
    /// * `receiver` --- receiver id (id of `SYN` sender)
    /// * `receiver_sock` --- receiver socket address
    /// * `packet_window` --- [`PacketWindow`] which contains ids of a bunch of packets
    fn ack_window(
        cx: &mut Context<'_>,
        socket: &UdpSocket,
        chat_t: Chat,
        sender: PeerId,
        receiver: PeerId,
        receiver_sock: SocketAddr,
        packet_window: &PacketWindow,
    ) -> Poll<std::io::Result<usize>> {
        let packet_window = packet_window.serialize();
        let length: u16 = 36 + packet_window.len() as u16;
        let mut packet = match chat_t {
            Chat::OneToOne => Header::new(
                ProtocolType::SDP,
                PacketType::CHAT | PacketType::ACK,
                length,
                sender,
                receiver,
            )
            .serialize(),
            Chat::Group => Header::new(
                ProtocolType::SDP,
                PacketType::CONV | PacketType::ACK,
                length,
                sender,
                receiver,
            )
            .serialize(),
            Chat::Channel => Header::new(
                ProtocolType::SDP,
                PacketType::CHAN | PacketType::ACK,
                length,
                sender,
                receiver,
            )
            .serialize(),
        };

        packet.extend_from_slice(&packet_window);

        socket.poll_send_to(cx, &packet, receiver_sock)
    }

    /// Try to wake sending process. Works only if state is 'Sending', ignores otherwise.
    pub fn try_wake_sending(&self) {
        let mut conn_waker = self.state.lock().unwrap();
        match (*conn_waker).state {
            ConnectionState::Sending => {
                if let Some(waker) = (*conn_waker).waker.take() {
                    waker.wake();
                }
            },
            _ => {}
        }
    }
}

// Separate implementation just because
impl SdpConnection {
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
                receiver.0.peer.id,
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
    ) -> ControlFlow<Result<(), Box<dyn Error>>, u64> {
        let mut conn_state = self.state.lock().unwrap();
        match (*conn_state).state {
            ConnectionState::Receiving => {
                return ControlFlow::Break(Err("Connection is blocked for sending because of receiving".into()));
            },
            ConnectionState::Sending => {
                return ControlFlow::Break(Ok(()));
            },
            ConnectionState::Pending => {
                // will be changed in `poll_send`
                (*conn_state).state = ConnectionState::Sending;
                (*conn_state).waker = None;
            }
        }

        let mut rng = rand::thread_rng();

        let packet_type = match chat_t {
            Chat::Channel => PacketType::CHAN | PacketType::SYN,
            Chat::Group => PacketType::CONV | PacketType::SYN,
            Chat::OneToOne => PacketType::CHAT | PacketType::SYN,
        };

        // [`Message.data`] into `payload`
        let payload = message.data;
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

        return ControlFlow::Continue(n_packets);
    }

    /// Main sending process
    fn poll_send(&self, cx: &mut Context<'_>) -> Poll<Result<(), Box<dyn Error>>> {
        // set waker
        // waker will be killed in driver
        let mut conn_state = self.state.lock().unwrap();
        match (*conn_state).state {
            ConnectionState::Sending => {
                (*conn_state).waker = Some(cx.waker().clone());
            },
            ConnectionState::Pending | ConnectionState::Receiving => {
                return Poll::Ready(Err("`SdpConnection.poll_send` can't be called on state `ConnectionState::Pending`".into()))
            }
        }

        // transactions to update id
        let mut transactions_to_update_ids = Vec::new();

        // does not need to be mutable
        let send_queue = self.send_queue.lock().unwrap();   
        let mut devices_to_be_killed = Vec::new();     
        let mut devices_transacted = Vec::new();
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

                            transactions_to_update_ids.push(device_id.to_owned());
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

                            transactions_to_update_ids.push(device_id.to_owned());
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
                    let current_packet = match (*payload).pop_front() {
                        Some(current_packet) => current_packet,
                        None => {
                            // empty send queue
                            devices_transacted.push(device_id);
                            continue;
                        }
                    };

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
            (*conn_state).waker = None;
            (*conn_state).state = ConnectionState::Pending;
            return Poll::Ready(Err("All `Nodes` are dead before end of the transaction".into()));
        }

        // kill ended transactions
        for dead in devices_transacted {
            (*send_queue).remove(dead);
        }

        // return `Poll::Ready(())`: poll is ready when all packets send 
        if send_queue.len() == 0 {
            (*conn_state).waker = None;
            (*conn_state).state = ConnectionState::Pending;
            return Poll::Ready(Ok(()));
        }

        // update id strategy for sent first packets
        for trans in transactions_to_update_ids {
            let transaction = (*send_queue).remove(&trans).unwrap();
            (*send_queue).insert(trans, transaction.update_id_strategy().unwrap());
        }

        // and acknowledged what is checked while handling the message
        return Poll::Pending;
    }
}

/// Symmenric Datagram Protocol Driver struct
/// 
/// This struct is only for receiving. 
pub struct SdpDriver {
    /// Socket for the driver
    pub socket: Arc<UdpSocket>,
    /// [`PeerId`] of current [`Peer`]
    pub peer_id: PeerId,

    /// List of connections driver is responsible for
    pub connections: HashMap<Peer, SdpConnection>,

    /// Channel for sending [`Message`]s
    pub(crate) sending: mpsc::Receiver<MessageWrapper>,
    pub(crate) sending_deque: VecDeque<MessageWrapper>,

    /// Channel for receiving [`Message`]s, including `INIT` and `HI`
    pub(crate) receiving: mpsc::Sender<MessageWrapper>,

    // maps of currently handled transmissions
    handling: HashMap<[u8; 32], MessageHandler>, // for `SYN`
    handling_keys: HashSet<[u8; 32]> 
}

impl SdpDriver {

    /// Create new SDP driver
    ///
    /// Arguments
    ///
    /// * `socket` --- [`UdpSocket`], used for the driver and inside connections
    /// * `contacts` --- list of [`Contact`]s, tied with the driver
    pub fn new(
        channel_capacity: usize,
        peer_id: &PeerId,
        socket: UdpSocket,
        contacts: Vec<Contact>
    ) -> (SdpDriver, mpsc::Sender<MessageWrapper>, mpsc::Receiver<MessageWrapper>) {
        let socket = Arc::new(socket);

        let mut connections = HashMap::with_capacity(contacts.len());
        for contact in contacts {
            connections.insert(
                contact.peer.clone(),
                SdpConnection::new( 
                    socket.clone(), 
                    contact
                )
            );
        }

        let (sending_tx, sending_rx) = mpsc::channel(channel_capacity);
        let (receiving_tx, receiving_rx) = mpsc::channel(channel_capacity);

        let driver = SdpDriver {
            socket: socket, // I'm not sure about `Arc`
            peer_id: peer_id.clone(),
            connections,
            sending: sending_rx,
            sending_deque: VecDeque::new(),
            receiving: receiving_tx,
            handling: HashMap::new(),
            handling_keys: HashSet::new()
        };

        (driver, sending_tx, receiving_rx)
    }
}

// Separate implementation just because
impl SdpDriver {
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
    ) -> ControlFlow<Result<(), Box<dyn Error>>, [u8; 32]> {

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
                // it's not a wrong logic, because [`Peer`]s should contact phisically for the first time
                let src_peer = if let Some(alive_conn) = self.connections.iter()
                    .find(
                    |(peer, _)| peer.id == header.src_id
                ){
                    match alive_conn.1.check_addr(packet_src) {
                        None => return ControlFlow::Break(Err("No connections to the address, while connected to the peer".into())),
                        Some(_) => alive_conn.0.clone()
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
                // chats for synchronization
                let chat_syncs = ChatSynchronizers::deserialize(packet[36..].to_vec());
                // message sender
                let src_peer = if let Some(alive_conn) = self.connections.iter()
                    .find(
                        |(peer, _)| peer.id == header.src_id
                ){
                    match alive_conn.1.check_addr(packet_src) {
                        None => return ControlFlow::Break(Err("No connections to the address, while connected to the peer".into())),
                        Some(_) => alive_conn.0.clone()
                    }
                } else {
                    return ControlFlow::Break(Err("No connections to the source peer".into()));
                };
                // finally sending handled message to channel
                if let Err(e) = self.receiving.try_send(
                    MessageWrapper::Recover { 
                            ack: false, 
                            peer_id: src_peer.id, 
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
                let alive_conn = if let Some(alive_conn) = self.connections.iter()
                    .find(
                        |(peer, _)| peer.id == header.src_id
                ){
                    match alive_conn.1.check_addr(packet_src) {
                        None => {
                            // drop transaction if it is started
                            self.handling.remove(&chat_sync.chat_id);
                            return ControlFlow::Break(Err("No connections to the address, while connected to the peer".into()))
                        },
                        Some(_) => {
                            alive_conn
                        }
                    }
                } else {
                    // drop transaction if it is started
                    self.handling.remove(&chat_sync.chat_id);
                    self.handling_keys.remove(&chat_sync.chat_id);
                    return ControlFlow::Break(Err("No connections to the source peer".into()));
                };
                
                // getting packet synchronizer from 
                let packet_sync = PacketSynchronizer::deserialize(packet[76..100].to_vec());
                // add packet to the handling list
                if self.handling.contains_key(&chat_sync.chat_id) {
                    // I hope it will work
                    if let Some(data) = self.handling.get_mut(&chat_sync.chat_id) {
                        // handling data only if it's not handling yet
                        // so some checks in `handle_message` are not needed
                        if !data.acknowledged.contains(&packet_sync.packet_id) &&
                                !data.acknowledging.contains(&packet_sync.packet_id) {
                            data.acknowledging.push(packet_sync.packet_id);
                            data.data.push((packet_sync.packet_id, packet[100..].to_vec()));
                        }
                    }
                } else { // first message in the transaction
                    self.handling.insert(
                        chat_sync.chat_id,
                        MessageHandler { 
                            peer_id: alive_conn.0.id,
                            sender_src: packet_src,
                            chat_t: chat_t, 
                            timestamp_l: chat_sync.timestamp, 
                            first_packet_sync: packet_sync, 
                            data: Vec::from([(packet_sync.packet_id, packet[100..].to_vec())]),
                            acknowledging: Vec::with_capacity(WINDOW_SIZE), // frankly speaking, it's not a "window"  
                            acknowledged: HashSet::new()             
                        } 
                    );
                    self.handling_keys.insert(chat_sync.chat_id);
                    // change state of the connection
                    // while handling `ACK` state should be `Sending` so we do not need to check or change it
                    (*alive_conn.1.state.lock().unwrap()).state = ConnectionState::Receiving;
                    return ControlFlow::Continue(chat_sync.chat_id);
                }
            },
            PacketType::ACK_INIT => { // like `INIT`, but another flag
                // chat for initializing
                let chat_sync = ChatSynchronizer::deserialize(packet[36..76].to_vec());
                // message sender
                let src_peer = if let Some(alive_conn) = self.connections.iter()
                    .find(
                |   conn| conn.0.id == header.src_id
                ){
                    match alive_conn.1.check_addr(packet_src) {
                        None => return ControlFlow::Break(Err("No connections to the address, while connected to the peer".into())),
                        Some(_) => alive_conn.0.clone()
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
                // chats for synchronization
                let chat_syncs = ChatSynchronizers::deserialize(packet[36..].to_vec());
                // message sender
                let src_peer = if let Some(alive_conn) = self.connections.iter()
                    .find(
                |   conn| conn.0.id == header.src_id
                ){
                    match alive_conn.1.check_addr(packet_src) {
                        None => return ControlFlow::Break(Err("No connections to the address, while connected to the peer".into())),
                        Some(_) => alive_conn.0.clone()
                    }
                } else {
                    return ControlFlow::Break(Err("No connections to the source peer".into()));
                };
                // finally sending handled message to channel
                if let Err(e) = self.receiving.try_send(
                    MessageWrapper::Recover { 
                            ack: true, 
                            peer_id: src_peer.id, 
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
                        |conn| conn.0.id == header.src_id
                ){
                    match alive_conn.1.check_addr(packet_src) {
                        None => {
                            // drop transaction if it is started
                            self.handling.remove(&chat_sync.chat_id);
                            return ControlFlow::Break(Err("No connections to the address, while connected to the peer".into()))
                        },
                        Some(device_id) => {
                            // getting packet synchronizer from 
                            let PacketSynchronizer { 
                                timestamp: _,
                                n_packets: _, 
                                packet_id 
                            } = PacketSynchronizer::deserialize(packet[76..100].to_vec());
                
                            // construct the rest of the packets in transaction
                            // by constructing the rest of the transaction, the first packet is also acknowledged
                            // (Transaction::First.first_packet.status is not needed)
                            // construct_rest constracts packets from packet_sync.packet_id
                            alive_conn.1.construct_rest(device_id, packet_id);
                        }
                    }
                } else {
                    // drop transaction if it is started
                    self.handling.remove(&chat_sync.chat_id);
                    return ControlFlow::Break(Err("No connections to the source peer".into()));
                };
            },
            PacketType::ACK => {
                // chat for the message
                let chat_sync = ChatSynchronizer::deserialize(packet[36..76].to_vec());
                // check if connection is alive
                if let Some(alive_conn) = self.connections.iter()
                    .find(
                        |conn| conn.0.id == header.src_id
                ){
                    match alive_conn.1.check_addr(packet_src) {
                        None => {
                            // drop transaction if it is started
                            self.handling.remove(&chat_sync.chat_id);
                            return ControlFlow::Break(Err("No connections to the address, while connected to the peer".into()))
                        },
                        Some(device_id) => {
                            // getting packet synchronizers from 
                            let PacketWindow { packet_ids } = match PacketWindow::deserialize(packet[76..].to_vec()) {
                                Ok(packets_sync) => packets_sync,
                                Err(e) => {
                                    return ControlFlow::Break(Err(e));
                                }
                            };
                            // and acknow it
                            alive_conn.1.ack_packets(device_id, &packet_ids)
                        }
                    }
                } else {
                    // drop transaction if it is started
                    self.handling.remove(&chat_sync.chat_id);
                    return ControlFlow::Break(Err("No connections to the source peer".into()));
                };
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
            // dedup isn't needed because of `acknowledging` field
            // let mut ids = handler.data.iter()
            //     .map(|(id, _)| id.to_owned())
            //     .collect::<Vec<u64>>();
            // ids.dedup();
            // if ids.len() != handler.first_packet_sync.n_packets as usize {
            //     return ControlFlow::Break(Err("Wrong number of packets".into()));
            // }
            // if ids.last().unwrap() - ids.first().unwrap() + 1 != handler.first_packet_sync.n_packets {
            //     return ControlFlow::Break(Err("Wrong packets order".into()));
            // }
            
            // collect payload
            let payload = handler.data.iter()
                .map(|(_, data)| data.to_owned())
                .collect::<Vec<Vec<u8>>>()
                .concat();
            
            if let Err(e) = self.receiving.try_send(
                MessageWrapper::Receiving { 
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

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let socket = self.socket.clone();
        let peer_id = self.peer_id.clone();
        // Oreder:
        // 1. handle message
        // 2. handle incoming packets
        // 3. send packets; while sending block handling on the connection
        //      ! there is no machanism for handling packets from the specified address, block all of them
        // 4. previous steps are needed because of SSDP (another module)
        // 
        // 
        // 
        loop {
            // handle message
            // I hate this copies
            // it's needed because of calling self.handle_message
            let handling_chat_ids = self.handling_keys.clone();
            for chat_id in handling_chat_ids {
                let data_len = self.handling[&chat_id].data.len();
                let n_packets = self.handling[&chat_id].first_packet_sync.n_packets as usize;

                if data_len == n_packets {
                    // acknow remaining packets
                    let acknowledging = PacketWindow {
                        packet_ids: self.handling[&chat_id].acknowledging.clone()
                    };
                    if let Some(handling_chat) = self.handling.get_mut(&chat_id) {
                        if let Ok(_) = ready!(SdpConnection::ack_window(
                            cx, 
                            &socket, 
                            handling_chat.chat_t, 
                            peer_id, 
                            handling_chat.peer_id, 
                            handling_chat.sender_src, 
                            &acknowledging)
                        ) {
                            handling_chat.acknow();
                        } else {
                            continue;
                        }
                    }
                    
                    // now we can handle message
                    match self.handle_message(&chat_id) {
                        ControlFlow::Continue(()) => {
                            // never
                        },
                        ControlFlow::Break(Err(_)) => {
                            // for logging in the future
                        },
                        ControlFlow::Break(Ok(())) => { 
                            // all okay here
                        }
                    }
                }

                if self.handling[&chat_id].acknowledging.len() == WINDOW_SIZE {
                    let acknowledging = PacketWindow {
                        packet_ids: self.handling[&chat_id].acknowledging.clone()
                    };
                    if let Some(handling_chat) = self.handling.get_mut(&chat_id) {
                        if let Ok(_) = ready!(SdpConnection::ack_window(
                            cx, 
                            &socket, 
                            handling_chat.chat_t, 
                            peer_id, 
                            handling_chat.peer_id, 
                            handling_chat.sender_src, 
                            &acknowledging)
                        ) {
                            handling_chat.acknow();
                        } else {
                            continue;
                        }
                    }
                }
            }

            // handling incoming packet 
            let mut buf_array = [0u8; RECEIVE_BUFFER_SIZE];
            let mut readbuf = ReadBuf::new(&mut buf_array);
            match self.socket.poll_recv_from(cx, &mut readbuf) {
                Poll::Ready(Ok(src_socket)) => {
                    let packet = readbuf.filled().to_vec();
                    // here used reference to packet to not lose ownership
                    match self.handle_dataram(&packet, src_socket) {
                        ControlFlow::Continue(chat_id) => {
                            // connection is already blocked
                            // send `ACK_SYN`
                            if let Some(handling_chat) = self.handling.get_mut(&chat_id) {
                                if let Ok(_) = ready!(SdpConnection::ack_first(
                                    cx, 
                                    &socket, 
                                    handling_chat.chat_t, 
                                    peer_id, 
                                    handling_chat.peer_id, 
                                    handling_chat.sender_src, 
                                    handling_chat.first_packet_sync)
                                ) {
                                    // first packet acknowledged
                                } else {
                                    continue;
                                }
                            }
                        },
                        ControlFlow::Break(Err(_)) => {
                            // for logging in the future
                        },
                        ControlFlow::Break(Ok(_)) => { 
                            // all okay here
                        }
                    }
                },
                Poll::Ready(Err(_)) => {
                    continue;
                },
                Poll::Pending => {}
            }

            // send packets from the channel
            // we can't send top packet from the channel, if needed connections are blocked for sending
            // so sending_deque is used and it must be checked first
            let mut sent_from_deque = Vec::new();
            for i in 0..self.sending_deque.len() {
                // send message to all ready peers
                let mut is_sent = false;
                let wrapper = &self.sending_deque[i];
                match &self.sending_deque[i] {
                    MessageWrapper::Sending { 
                        receivers, 
                        chat_t, 
                        chat_sync, 
                        message 
                    } => {
                        for receiver in receivers {
                            let state = self.connections[&receiver].state.lock().unwrap();
                            if ConnectionState::Sending == state.to_owned().state {
                                continue;
                            }
                            match self.connections[receiver].send(
                                chat_t.to_owned(), 
                                message.clone(), 
                                chat_sync.to_owned()
                            ) {
                                ControlFlow::Break(Ok(())) => {    
                                    // another message is currently sending
                                    // dead code
                                },
                                ControlFlow::Break(Err(e)) => {
                                    // blocked for sending
                                    // dead code
                                },
                                ControlFlow::Continue(n_packets) => {
                                    match self.connections[&receiver].poll_send(cx) {
                                        Poll::Ready(Ok(())) => {
                                            is_sent = true;
                                        },
                                        Poll::Ready(Err(e)) => {
                                            // if I'm right, connection is already ConnectionState::Pending
                                        },
                                        Poll::Pending => {
                                            // if I'm right, it's dead logic
                                        }
                                    }
                                },
                            }
                        }
                    }, 
                    // handle 'HI', 'INIT', and ignore other types
                    _ => {}
                }
                if is_sent {
                    sent_from_deque.push(i);
                }
            }
            for sent in sent_from_deque {
                self.sending_deque.remove(sent);
            }

            // now try read one message from sending channel
            match self.sending.try_next() {
                Ok(Some(message)) => {
                    // send message to all ready peers
                    let mut is_sent = false;
                    match &message {
                        MessageWrapper::Sending { 
                            receivers, 
                            chat_t, 
                            chat_sync, 
                            message 
                        } => {
                            for receiver in receivers {
                                let state = self.connections[&receiver].state.lock().unwrap();
                                if ConnectionState::Sending == state.to_owned().state {
                                    continue;
                                }
                                match self.connections[receiver].send(
                                    chat_t.to_owned(), 
                                    message.clone(), 
                                    chat_sync.to_owned()
                                ) {
                                    ControlFlow::Break(Ok(())) => {
                                        // another message is currently sending
                                        // dead code
                                    },
                                    ControlFlow::Break(Err(e)) => {
                                        // blocked for sending
                                        // dead code
                                    },
                                    ControlFlow::Continue(n_packets) => {
                                        is_sent = true;
                                    },
                                }
                            }
                        }, 
                        // handle 'HI', 'INIT', and ignore other types
                        _ => {}
                    }
                    if is_sent {
                        self.sending_deque.push_back(message);
                    }
                },
                Ok(None) => {
                    // "when channel is closed and no messages left in the queue"
                    // so driver is dead and we can drop it?
                    return Poll::Ready(());
                },
                Err(e) => {
                    // "when there are no messages available, but channel is not yet closed"
                    continue;
                }
            }

            // wake sending 
            for (_, conn) in self.connections.iter() {
                conn.try_wake_sending();
            }
        }
    }
}