# Yet Another Peer-to-Peer Network (YAP2P)

> **Note**
> Library is under development right now

> **Warning**
> Library needs testing 

This library proposes a new P2P network topology that enables users to connect multiple devices to one peer. The topology provides an opportunity to implement distributed applications over it.

[![Crates.io][crates-badge]][crates-url]
[![MIT licensed][mit-badge]][mit-url]

[crates-badge]: https://img.shields.io/crates/v/yap2p.svg
[crates-url]: https://crates.io/crates/yap2p
[mit-badge]: https://img.shields.io/badge/license-MIT-blue.svg
[mit-url]: https://github.com/Scurrra/ya/blob/master/yap2p/LICENSE

## TODO:
- [x] Cryptographic
   - [x] Diffie-Hellman Key Exchange
   - [x] Something called KeyChain
   - [x] Messages and History
- [x] Peers and Nodes
- [ ] Protocols
   - [ ] Symmetric Datagram Protocol
      - [x] Sending messages
      - [X] Receiving Messages
      - [ ] Packets acknowledgement
   - [ ] Secure Symmetric Datagram Protocol
- [ ] Network
   - [x] Description
   - [ ] SelfNet
   - [ ] MeshNet
   - [ ] ContactNet 
- [ ] NAT
   - [ ] Description
   - [ ] Identifying
   - [ ] Traversal

## License

This project is licensed under the [MIT license].

[MIT license]: https://github.com/Scurrra/ya/blob/master/yap2p/LICENSE

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in YAP2P by you, shall be licensed as MIT, without any additional terms or conditions.