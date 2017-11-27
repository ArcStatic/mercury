# quic-rust

This is an undergraduate dissertation project aiming to implement as much of the QUIC protocol as humanely possible before March 2018.

### Current progress:
* Rust compiles!
* Server listens for incoming packets on a constant loop
* Client can send messages as ShortHeader or LongHeader packets
* Client can start a connection using ClientInitial
* Encoding and decoding obeys AVTCORE WG guidance to avoid multiplexing conflicts

### Next steps:
* Make server respond to ClientInitial
* Start work on cryptographic handshake (using TLS 1.3)
* Create tests using QuickCheck
