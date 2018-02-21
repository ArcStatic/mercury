# Mercury

This is an undergraduate dissertation project aiming to implement as much of the QUIC protocol as humanely possible before March 2018.

### Current progress:
* Rust compiles!
* Server listens for incoming packets on a constant loop
* Client can send custom messages as ShortHeader or LongHeader packets
* Client and server can perform a complete handshake process using the commands given
* Encoding and decoding obeys AVTCORE WG guidance to avoid multiplexing conflicts (outlined in quic-transport v8)
* Modified rustls to use UDP and mimic required QUIC behaviour

### Next steps:
* Integrate cryptographic handshake in connection process (using TLS 1.3)
* Create tests using QuickCheck

### Usage:
Run the following from the base directory:

quic-server:
`cargo run --example quic-server -- --certs test-ca/rsa/end.fullchain --key test-ca/rsa/end.rsa http`

quic-client:
`cargo run --example udpclient -- --cafile test-ca/rsa/ca.cert localhost --http -p [port]`
