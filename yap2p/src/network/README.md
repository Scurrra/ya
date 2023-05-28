# Network architecture

## TODO:
- [ ] Network
   - [ ] SelfNet
   - [ ] MeshNet
   - [ ] ContactNet

`yap2p` architecture consists of three layers:
 - SelfNet
 - MeshNet
 - ContactsNet

**SelfNet** consisits of `Node`s of the `Peer` and is used for synchronization. It is a fully connected graph, each `Peer`'s `Node` is connected to other `Node`s.

**MeshNet** also consists of `Node`s, ideally all `Node`s relate to different `Peer`s. It is a graph, that consisits of intersecting star-graphs. MeshNet is primarily used for connecting to the network, while being one of the main yap2p's features: using MeshNet many distributed applications can be built.

**ContactNet** is used for explicit exchange of messages between `Peer`s. ContactNet is a hidden layer, i. e. information about contacts can not be shared with other layers. 