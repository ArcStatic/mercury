# quic-rust

This is an undergraduate dissertation project aiming to implement as much of the QUIC protocol as humanely possible before March 2018.

### Current progress:
* Rust compiles!
* Server listens for incoming packets on a constant loop
* Client can send custom messages as ShortHeader or LongHeader packets
* Client and server can perform a complete connection process if client runs using the 'start' command variant 
* Encoding and decoding obeys AVTCORE WG guidance to avoid multiplexing conflicts (outlined in quic-transport v8)

### Next steps:
* Integrate cryptographic handshake in connection process (using TLS 1.3)
* Create tests using QuickCheck

### Usage:
Create a server listening on `addr:port`:

`cargo run listen [addr]:[port]`

Create a client which sets up a connection with a server at `dest-addr:dest-port`:

`cargo run start [addr]:[port] [dest-addr]:[dest-port]`

Create a client which sends a ShortHeader or LongHeader message (`[packet_type]`) with a custom payload to `dest-addr:dest-port`:

`cargo run send packet_type payload [addr]:[port] [dest-addr]:[dest-port]`
