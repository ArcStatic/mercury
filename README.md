# Mercury

[Documentation](https://htmlpreview.github.io/?https://raw.githubusercontent.com/ArcStatic/mercury/master/documentation/mercury/header/index.html)

This is an undergraduate dissertation project aiming to implement as much of the QUIC protocol as humanely possible before March 2018. The current implementation is compliant with quic-transport draft 08, but will be upgraded to 10 over the next few months.

### Current progress:
* Encoding and decoding obeys AVTCORE WG guidance to avoid multiplexing conflicts (outlined in quic-transport v8)
* Modified rustls to use UDP and mimic required QUIC behaviour
* Handshake completes using TLS 1.3-encrypted payloads
* All client-server communication uses correctly formatted QUIC packets
* Rustdoc pages created

### Next steps:
* Encrypt everything, not just payloads
* Add version negotiation, current implementation accepts anything
* Implement key management
* Use frames in communications, current version just sends "hello world" equivalent
* Implement streams
* Create tests using QuickCheck

### Usage:
Run the following from the base directory:

quic-server:
`cargo run --example quic-server -- --certs test-ca/rsa/end.fullchain --key test-ca/rsa/end.rsa http`

quic-client:
`cargo run --example udpclient -- --cafile test-ca/rsa/ca.cert localhost --http -p [port]`
