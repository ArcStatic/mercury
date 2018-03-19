use std::sync::Arc;

extern crate mio;
use mio::net::UdpSocket;
use std::net::SocketAddr;

extern crate bytes;
use bytes::Bytes;

#[macro_use]
extern crate log;

use std::fs;
use std::io::Result;
use std::str::FromStr;
use std::io::{Write, Read, BufReader};
use std::collections::HashMap;

#[macro_use]
extern crate serde_derive;
extern crate docopt;
use docopt::Docopt;

extern crate env_logger;

extern crate rustls;
use rustls::{RootCertStore, Session, NoClientAuth, AllowAnyAuthenticatedClient,
             AllowAnyAnonymousOrAuthenticatedClient};

extern crate mercury;
use mercury::header::{Header, decode, PacketTypeLong, ConnectionBuffer, QuicSocket};

// Token for our listening socket.
const LISTENER: mio::Token = mio::Token(0);

//Structs and enums:
struct TlsServer {
    server: QuicSocket,
    connections: HashMap<SocketAddr, Connection>,
    tls_config: Arc<rustls::ServerConfig>
}


impl TlsServer {
    fn new(server: QuicSocket, cfg: Arc<rustls::ServerConfig>) -> TlsServer {
        TlsServer {
            server: server,
            connections: HashMap::new(),
            tls_config: cfg,
        }
    }

    fn accept(&mut self, client_addr: SocketAddr, conn_id: Option<u64>, packet_number: u32, version: Option<u32>) -> bool {
        let tls_session = rustls::ServerSession::new(&self.tls_config);

        println!("Accepting new 'connection'\n");
        println!("{:?}\n", client_addr);

        //ConnectionID and version should be present in Initial packets, since they're LongHeaders
        //Added 0 as a fallback just in case
        let connection_id = match conn_id.is_some(){
            true => conn_id.unwrap(),
            false => 0
        };

        let version = match version.is_some(){
            true => version.unwrap(),
            false => 0
        };

        self.connections.insert(client_addr, Connection::new(client_addr, connection_id, packet_number, version, tls_session));

        println!("Accept complete.\n");
        true
    }
}

#[derive(Debug, PartialOrd, PartialEq)]
//Track which stage a connection is in
enum ConnectionStatus {
    Initial,
    Handshake,
    DataSharing,
    Closing
}

/// This is a connection which has been accepted by the server,
/// and is currently being served.
///
/// It has a QuicServerSocket replacing a TCP-level stream, a TLS-level session, and some
/// other state/metadata.
struct Connection {
    addr: SocketAddr,
    buf : ConnectionBuffer,
    token: mio::Token,
    connection_id : u64,
    packet_number : u32,
    version : u32,
    status: ConnectionStatus,
    tls_session: rustls::ServerSession,
}

impl Connection {
    fn new(addr: SocketAddr,
           connection_id: u64,
           packet_number: u32,
           version: u32,
           tls_session: rustls::ServerSession)
           -> Connection {
        Connection {
            addr,
            buf: ConnectionBuffer{buf : [0;10000], offset: 0},
            token: LISTENER,
            connection_id,
            packet_number,
            version,
            status: ConnectionStatus::Initial,
            tls_session,
        }
    }

    fn process_event(&mut self, poll: &mut mio::Poll, ev: &mio::Event, buffer: &[u8], mut socket: &mut QuicSocket) {
        match self.status {

            ConnectionStatus::Initial => {
                println!("Initial:\n");
                let client = self.do_tls_read(buffer);
                println!("Client: {:?}\n", client);
                let client_plain = self.try_plain_read(socket);
                println!("Client_plain: {:?}\n", client_plain);
                self.status = ConnectionStatus::Handshake;
            }

            ConnectionStatus::Handshake => {
                //ie. a write event is currently being processed, but no longer wants write after do_tls_write()
                //Complete TLS handshake message will be sent as payload
                println!("Writing handshake message...\n");
                self.do_tls_write();

                //Must only be encoded once to avoid multiple headers being sent in one packet
                if ev.readiness().is_writable() && !self.tls_session.wants_write() {

                    self.send_quic_packet(&mut socket);
                    println!("TLS message sent.");
                }
            }

            ConnectionStatus::DataSharing => {
                println!("Sending response...\n");
                let client = self.do_tls_read(buffer);
                println!("Client: {:?}\n", client);
                //Server will send HTTP response if try_plain_read yields valid plaintext
                let client_plain = self.try_plain_read(socket);
                println!("Client_plain: {:?}\n", client_plain);
            }

            ConnectionStatus::Closing => {
                println!("Connection closing...\n");
            }

        }

        //Register or reregister events with poll
        //register succeeds for write events, reregister succeeds for read events
        match self.register(poll, socket) {
            Ok(_) => {

            },
            Err(_) => {
                self.reregister(poll, socket).unwrap();
            }
        }
    }


    fn do_tls_read(&mut self, buffer: &[u8]) {
        // Read some TLS data.
        //Read from buffer passed from listener, data no longer in socket
        let rc = self.tls_session.read_tls(&mut &buffer[0..]);
        if rc.is_err() {
            let err = rc.unwrap_err();
            error!("read error {:?}", err);
            return
        }

        // Process newly-received TLS messages.
        let processed = self.tls_session.process_new_packets();
        if processed.is_err() {
            error!("cannot process packet: {:?}", processed);
            return
        }
    }

    fn try_plain_read(&mut self, socket: &mut QuicSocket) {
        // Read and process all available plaintext.
        let mut buf = Vec::new();

        let rc = self.tls_session.read_to_end(&mut buf);
        if rc.is_err() {
            error!("plaintext read failed: {:?}", rc);
            return;
        }

        if !buf.is_empty() {
            println!("plaintext read {:?}\n\n", buf);
            self.send_response(socket);
        }
    }

    fn send_response(&mut self, mut socket: &mut QuicSocket) {
        let response = b"HTTP/1.0 200 OK\r\nConnection: close\r\n\r\nHello from Viridian!  \r\n";

        self.tls_session
            .write_all(response)
            .unwrap();

        //Track how long the TLS record given by write_tls is
        //TLS record is written to ConnectionBuffer - [u8;10000] with custom format trait
        //[u8] has read/write traits implemented by default
        let res = self.tls_session.write_tls(&mut self.buf.buf.as_mut()).unwrap();
        //Increment packet number for each message sent
        self.packet_number += 1;

        //Construct header
        //NOTE: this is not 0-RTT protected in current implementation
        let header = Header::LongHeader{packet_type : PacketTypeLong::ZeroRTTProtected,
            connection_id : self.connection_id,
            packet_number : self.packet_number,
            version : self.version,
            payload :self.buf.buf[0..res].to_vec()};

        //Encode and send response to client
        socket.write(&header.encode()).unwrap();

        println!("HTTP response sent, sending close_notify...\n");
        self.tls_session.send_close_notify();
        //let self = self.tls_session.write_tls(&mut self.buf.buf.as_mut()).unwrap();
        self.buf.offset = self.tls_session.write_tls(&mut self.buf.buf.as_mut()).unwrap();

        self.send_quic_packet(socket);


    }

    fn do_tls_write(&mut self) {
        //Write from offset to allow multiple TLS messages to be buffered before sending
        let rc = self.tls_session.write_tls(&mut self.buf.buf[self.buf.offset..10000].as_mut());
        if rc.is_err() {
            error!("write failed {:?}", rc);
        } else {
            self.buf.offset += rc.unwrap();
        }
    }

    //register works when socket wants write
    //Anything readable is already registered in initial loop in main, writable needs registering as new event
    fn register(&self, poll: &mut mio::Poll, socket: &QuicSocket) -> Result<()>{

        poll.register(&socket.sock,
                      self.token,
                      self.event_set(),
                      mio::PollOpt::oneshot())?;
        Ok(())
    }


    //reregister works when socket wants read
    fn reregister(&self, poll: &mut mio::Poll, socket: &QuicSocket) -> Result<()> {

        poll.reregister(&socket.sock,
                        self.token,
                        self.event_set(),
                        mio::PollOpt::oneshot())?;
        Ok(())

    }

    /// What IO events we're currently waiting for,
    /// based on wants_read/wants_write.
    fn event_set(&self) -> mio::Ready {
        let rd = self.tls_session.wants_read();
        let wr = self.tls_session.wants_write();

        if rd && wr {
            mio::Ready::readable() | mio::Ready::writable()
        } else if wr {
            mio::Ready::writable()
        } else {
            mio::Ready::readable()
        }
    }

    /// Send encoded QUIC Header
    /// Increments packet count and connection status
    pub fn send_quic_packet(&mut self, mut socket : &mut QuicSocket) {

        self.packet_number += 1;

        let packet_type = match self.status {
            ConnectionStatus::Initial => PacketTypeLong::Initial,
            ConnectionStatus::Handshake  => PacketTypeLong::Handshake,
            ConnectionStatus:: DataSharing => PacketTypeLong::ZeroRTTProtected,
            ConnectionStatus:: Closing => PacketTypeLong::ZeroRTTProtected
        };

        let header = Header::LongHeader {packet_type,
            connection_id : self.connection_id,
            packet_number : self.packet_number,
            version : self.version,
            payload : self.buf.buf[0..self.buf.offset].to_vec()};

        println!("Sending packet: {:?}", header);

        //Encode and send message to server using custom QuicServerSocket behaviour
        socket.write(&header.encode()).unwrap();

        self.status = match self.status {
            ConnectionStatus::Initial => ConnectionStatus::Handshake,
            ConnectionStatus::Handshake => ConnectionStatus::DataSharing,
            //Closes connection after sending a single HTTP response
            ConnectionStatus:: DataSharing => ConnectionStatus::Closing,
            ConnectionStatus:: Closing => ConnectionStatus::Closing
        };
    }

}



const USAGE: &'static str =
    "
Runs a TLS server on :PORT.  The default PORT is 443.

`echo' mode means the server echoes received data on each connection.

`http' mode means the server blindly sends a HTTP response on each
connection.

`forward' means the server forwards plaintext to a connection made to
localhost:fport.

`--certs' names the full certificate chain, `--key' provides the
RSA private key.

Usage:
  tlsserver --certs CERTFILE --key KEYFILE [--suite SUITE ...] \
     [--proto PROTO ...] [options] echo
  tlsserver --certs CERTFILE --key KEYFILE [--suite SUITE ...] \
     [--proto PROTO ...] [options] http
  tlsserver --certs CERTFILE --key KEYFILE [--suite SUITE ...] \
     [--proto PROTO ...] [options] forward <fport>
  tlsserver (--version | -v)
  tlsserver (--help | -h)

Options:
    -p, --port PORT     Listen on PORT [default: 443].
    --certs CERTFILE    Read server certificates from CERTFILE.
                        This should contain PEM-format certificates
                        in the right order (the first certificate should
                        certify KEYFILE, the last should be a root CA).
    --key KEYFILE       Read private key from KEYFILE.  This should be a RSA
                        private key or PKCS8-encoded private key, in PEM format.
    --ocsp OCSPFILE     Read DER-encoded OCSP response from OCSPFILE and staple
                        to certificate.  Optional.
    --auth CERTFILE     Enable client authentication, and accept certificates
                        signed by those roots provided in CERTFILE.
    --require-auth      Send a fatal alert if the client does not complete client
                        authentication.
    --resumption        Support session resumption.
    --tickets           Support tickets.
    --suite SUITE       Disable default cipher suite list, and use
                        SUITE instead.  May be used multiple times.
    --proto PROTOCOL    Negotiate PROTOCOL using ALPN.
                        May be used multiple times.
    --verbose           Emit log output.
    --version, -v       Show tool version.
    --help, -h          Show this screen.
";

#[derive(Debug, Deserialize)]
struct Args {
    cmd_echo: bool,
    cmd_http: bool,
    cmd_forward: bool,
    flag_port: Option<u16>,
    flag_verbose: bool,
    flag_suite: Vec<String>,
    flag_proto: Vec<String>,
    flag_certs: Option<String>,
    flag_key: Option<String>,
    flag_ocsp: Option<String>,
    flag_auth: Option<String>,
    flag_require_auth: bool,
    flag_resumption: bool,
    flag_tickets: bool,
    arg_fport: Option<u16>,
}

fn find_suite(name: &str) -> Option<&'static rustls::SupportedCipherSuite> {
    for suite in &rustls::ALL_CIPHERSUITES {
        let sname = format!("{:?}", suite.suite).to_lowercase();

        if sname == name.to_string().to_lowercase() {
            return Some(suite);
        }
    }

    None
}

fn lookup_suites(suites: &[String]) -> Vec<&'static rustls::SupportedCipherSuite> {
    let mut out = Vec::new();

    for csname in suites {
        let scs = find_suite(csname);
        match scs {
            Some(s) => out.push(s),
            None => panic!("cannot look up ciphersuite '{}'", csname),
        }
    }

    out
}

fn load_certs(filename: &str) -> Vec<rustls::Certificate> {
    let certfile = fs::File::open(filename).expect("cannot open certificate file");
    let mut reader = BufReader::new(certfile);
    rustls::internal::pemfile::certs(&mut reader).unwrap()
}

fn load_private_key(filename: &str) -> rustls::PrivateKey {
    let rsa_keys = {
        let keyfile = fs::File::open(filename)
            .expect("cannot open private key file");
        let mut reader = BufReader::new(keyfile);
        rustls::internal::pemfile::rsa_private_keys(&mut reader)
            .expect("file contains invalid rsa private key")
    };

    let pkcs8_keys = {
        let keyfile = fs::File::open(filename)
            .expect("cannot open private key file");
        let mut reader = BufReader::new(keyfile);
        rustls::internal::pemfile::pkcs8_private_keys(&mut reader)
            .expect("file contains invalid pkcs8 private key (encrypted keys not supported)")
    };

    // prefer to load pkcs8 keys
    if !pkcs8_keys.is_empty() {
        pkcs8_keys[0].clone()
    } else {
        assert!(!rsa_keys.is_empty());
        rsa_keys[0].clone()
    }
}

fn load_ocsp(filename: &Option<String>) -> Vec<u8> {
    let mut ret = Vec::new();

    if let &Some(ref name) = filename {
        fs::File::open(name)
            .expect("cannot open ocsp file")
            .read_to_end(&mut ret)
            .unwrap();
    }

    ret
}

fn make_config(args: &Args) -> Arc<rustls::ServerConfig> {
    let client_auth = if args.flag_auth.is_some() {
        let roots = load_certs(args.flag_auth.as_ref().unwrap());
        let mut client_auth_roots = RootCertStore::empty();
        for root in roots {
            client_auth_roots.add(&root).unwrap();
        }
        if args.flag_require_auth {
            AllowAnyAuthenticatedClient::new(client_auth_roots)
        } else {
            AllowAnyAnonymousOrAuthenticatedClient::new(client_auth_roots)
        }
    } else {
        NoClientAuth::new()
    };

    let mut config = rustls::ServerConfig::new(client_auth);

    let certs = load_certs(args.flag_certs.as_ref().expect("--certs option missing"));
    let privkey = load_private_key(args.flag_key.as_ref().expect("--key option missing"));
    let ocsp = load_ocsp(&args.flag_ocsp);
    config.set_single_cert_with_ocsp_and_sct(certs, privkey, ocsp, vec![]);

    if !args.flag_suite.is_empty() {
        config.ciphersuites = lookup_suites(&args.flag_suite);
    }

    if args.flag_resumption {
        config.set_persistence(rustls::ServerSessionMemoryCache::new(256));
    }

    if args.flag_tickets {
        config.ticketer = rustls::Ticketer::new();
    }

    config.set_protocols(&args.flag_proto);

    Arc::new(config)
}


fn server_setup() -> TlsServer {
    let version = env!("CARGO_PKG_NAME").to_string() + ", version: " + env!("CARGO_PKG_VERSION");

    let args: Args = Docopt::new(USAGE)
        .and_then(|d| Ok(d.help(true)))
        .and_then(|d| Ok(d.version(Some(version))))
        .and_then(|d| d.deserialize())
        .unwrap_or_else(|e| e.exit());

    let bind_info = SocketAddr::from_str("127.0.0.1:9090").unwrap();
    let socket = UdpSocket::bind(&bind_info).unwrap();

    //127.0.0.1:4444 is a placeholder for recent_client, will be changed as soon as new client accepted
    let quic_sock = QuicSocket { sock: socket, addr: SocketAddr::from_str("127.0.0.1:4444").unwrap() };

    let config = make_config(&args);

    let tlsserv = TlsServer::new(quic_sock, config);

    tlsserv
}


fn main(){
    //TODO: allow user-specified addr:port
    //let args : Vec<String> = env::args.collect();

    let mut tlsserv = server_setup();
    //println!("QUIC server listening on {:?}:{:?}", addr, port);

    let mut event_count = 0;

    let mut poll = mio::Poll::new()
        .unwrap();
    //Socket only needs to be registered once, detecting readable and writable events
    poll.register(&tlsserv.server.sock,
                  LISTENER,
                  mio::Ready::readable(),
                  mio::PollOpt::edge())
        .unwrap();
    let mut events = mio::Events::with_capacity(256);

    let mut recv_buf : [u8; 1500] = [0;1500];

    loop {
        poll.poll(&mut events, None)
            .unwrap();
        for event in events.iter() {
            if event.readiness().is_readable() {
                println!("Readable event:");
                //Error being thrown here for multiple clients
                let client_info = tlsserv.server.sock.recv_from(&mut recv_buf).unwrap();
                //Parse header from incoming packet
                let header = decode(Bytes::from(&recv_buf[0..client_info.0]));

                println!("Packet: {:?}", header);

                //If client's address is not in the hashmap containing established connections, call accept to add it
                if !(tlsserv.connections.contains_key(&client_info.1)) {
                    tlsserv.accept(client_info.1, header.get_conn_id(), header.get_packet_number(), header.get_version());
                };

                //Process readable event as normal
                event_count += 1;
                println!("------------------\nEvent #{:?}\n", event_count);
                println!("Event: {:?}\n", event);
                //Obtain mutable reference to Connection for this specific client
                let mut client = tlsserv.connections.get_mut(&client_info.1).unwrap();

                client.packet_number = header.get_packet_number();

                client.process_event(&mut poll, &event, &header.get_payload().as_slice(), &mut tlsserv.server);

                //Change addr on QuicServerSocket to recent client to allow application data to be sent
                tlsserv.server.addr = client_info.1;

            // If it's a writable event, client address info is already held in connections hashtable
            } else {
                event_count += 1;
                println!("------------------\nEvent #{:?}\n", event_count);
                println!("Event: {:?}\n", event);
                let mut client = tlsserv.connections.get_mut(&tlsserv.server.addr).unwrap();
                //Process writeable event
                //Checks for most recently processed client in hashtable - this will need refactored in future
                client.process_event(&mut poll, &event, &mut recv_buf, &mut tlsserv.server);

            };

            //Remove any connection which is marked as closing
            if tlsserv.connections.get_mut(&tlsserv.server.addr).unwrap().status == ConnectionStatus::Closing {
                tlsserv.connections.remove(&tlsserv.server.addr);
                println!("Connection removed.\n");
            }

        }
    }

}