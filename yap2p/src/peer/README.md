# Peers and Nodes

Network user is called `Peer`. One user may has (and almost everytime does) more than one device. Every device `Peer` has is called `Node`.

To be identified every `Peer` has `PeerId`. It looks like IPv6, but it's not. First byte is constant for the network, 2-8 bytes are `Peer`'s public key, used for symmetric (yes, exactly), 9-16 bytes hold some "salt", constructed with hash of username. `Node`s of one `Peer` are represented like ports alongside IP.

At a time one `Node` can have both IPv4 and IPv6 addresses. Both of them are stored in the `Addr` struct.

For storing `Node`s of another `Peer` the `Contact` struct is used.