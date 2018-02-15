use std::sync::Arc;

extern crate mio;
use mio::net::UdpSocket;
use std::net::SocketAddr;

#[macro_use]
extern crate log;

use std::fs;
use std::io;
use std::io::Result;
use std::str::FromStr;
use std::io::{Write, Read, BufReader};
use std::collections::HashMap;
use std::{thread, time};
use std::fmt;

#[macro_use]
extern crate serde_derive;
extern crate docopt;
use docopt::Docopt;

extern crate env_logger;

extern crate rustls;

use rustls::{RootCertStore, Session, NoClientAuth, AllowAnyAuthenticatedClient,
             AllowAnyAnonymousOrAuthenticatedClient};

// Token for our listening socket.
const LISTENER: mio::Token = mio::Token(0);

//Custom structs:

pub struct TlsBuffer{
    pub buf : [u8;10000],
    pub offset : usize
}


impl fmt::Debug for TlsBuffer{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", &self.buf[0..self.offset])
    }
}


#[derive(Debug)]
pub struct QuicSocket {
    pub sock : UdpSocket,
    pub buf : TlsBuffer,
    pub addr : SocketAddr,
}


impl Read for QuicSocket {
    fn read (&mut self, mut output : &mut [u8]) -> Result<usize> {
        let res = UdpSocket::recv_from(&mut self.sock, output)?;
        println!("recv_from complete\n");
        Ok(res.0)
    }
}

impl Write for QuicSocket {
    fn write(&mut self, input : &[u8]) -> Result<usize> {
        println!("\nCustom socket send_to...\n");
        let bytes = UdpSocket::send_to(&mut self.sock, input, &self.addr)?;
        println!("send_to complete\n");
        Ok(bytes)
    }


    fn flush(&mut self) -> Result<()>{
        println!("\nCustom flush...\n");
        &mut self.buf.buf.as_mut().flush()?;
        Ok(())
    }

}

//End of custom structs

// Which mode the server operates in.
#[derive(Clone)]
enum ServerMode {
    /// Write back received bytes
    Echo,

    /// Do one read, then write a bodged HTTP response and
    /// cleanly close the connection.
    Http,

}

/// This binds together a TCP listening socket, some outstanding
/// connections, and a TLS server configuration.
struct TlsServer {
    server: QuicSocket,
    connections: HashMap<SocketAddr, Connection>,
    tls_config: Arc<rustls::ServerConfig>,
    mode: ServerMode,
}

impl TlsServer {
    fn new(server: QuicSocket, mode: ServerMode, cfg: Arc<rustls::ServerConfig>) -> TlsServer {
        TlsServer {
            server: server,
            connections: HashMap::new(),
            tls_config: cfg,
            mode: mode,
        }
    }

    fn accept(&mut self, client_addr: SocketAddr) -> bool {

        let tls_session = rustls::ServerSession::new(&self.tls_config);
        let mode = self.mode.clone();

        println!("Accepting new 'connection'\n");
        println!("{:?}\n", client_addr);

        //let q_sock = QuicSocket{sock: self.server.sock.try_clone().unwrap(), buf: TlsBuffer{buf : [0;10000], offset: 0}, addr: client_addr};

        self.connections.insert(client_addr, Connection::new(client_addr, mode, tls_session));

        println!("Accept complete.\n");
        return true;

    }


    fn conn_event_read(&mut self, poll: &mut mio::Poll, event: &mio::Event, client_addr: SocketAddr, buffer: &mut [u8], msg_len: usize) {

        println!("Checking for key...\n");
        if self.connections.contains_key(&client_addr) {
            self.connections
                .get_mut(&client_addr)
                .unwrap()
                .ready(poll, event, buffer, msg_len, &mut self.server);

        }

        println!("Closed? {:?}\n", self.connections[&client_addr].is_closed());
        //Checking closing label with is_closed() causes connection to be removed too early
        println!("Check remove client_addr - conn_event_write");
        if (self.connections[&client_addr].closed) && self.connections[&client_addr].sent_http_response {
            println!("Remove client_addr - conn_event_read");
            self.connections.remove(&client_addr);
            println!("Connection removed from hashmap.\n");
        }
    }

    fn conn_event_write(&mut self, poll: &mut mio::Poll, event: &mio::Event, client_addr: SocketAddr) {

        println!("Checking for key...\n");
        if self.connections.contains_key(&client_addr) {
            self.connections
                .get_mut(&client_addr)
                .unwrap()
                .ready_write(poll, event, &self.server);

        }

        println!("Closed? {:?}\n", self.connections[&client_addr].is_closed());
        //Checking closing label with is_closed() causes connection to be removed too early
        println!("Check remove client_addr - conn_event_write");
        if (self.connections[&client_addr].closed) && self.connections[&client_addr].sent_http_response {
            println!("Remove client_addr - conn_event_write");
            self.connections.remove(&client_addr);
            println!("Connection removed from hashmap.\n");
        }
    }

}

/// This is a connection which has been accepted by the server,
/// and is currently being served.
///
/// It has a QuicSocket replacing a TCP-level stream, a TLS-level session, and some
/// other state/metadata.
struct Connection {
    addr: SocketAddr,
    buf : TlsBuffer,
    token: mio::Token,
    //In process of closing
    closing: bool,
    //Finished closing, should be removed from list of connections
    closed: bool,
    mode: ServerMode,
    tls_session: rustls::ServerSession,
    sent_http_response: bool,
}

impl Connection {
    fn new(addr: SocketAddr,
           mode: ServerMode,
           tls_session: rustls::ServerSession)
           -> Connection {
        Connection {
            addr: addr,
            buf: TlsBuffer{buf : [0;10000], offset: 0},
            token: LISTENER,
            closing: false,
            closed: false,
            mode: mode,
            tls_session: tls_session,
            sent_http_response: false,
        }
    }


    /// We're a connection, and we have something to do.
    fn ready(&mut self, poll: &mut mio::Poll, ev: &mio::Event, buffer: &mut [u8], msg_len: usize, socket: &mut QuicSocket) {
        // If we're readable: read some TLS.  Then
        // see if that yielded new plaintext.  Then
        // see if the backend is readable too.
        println!("Handshaking? - {:?}\n", self.tls_session.is_handshaking());
        if ev.readiness().is_readable() {
            println!("Readable! \n");
            let client = self.do_tls_read(buffer, msg_len);
            println!("Client: {:?}\n", client);
            let client_plain = self.try_plain_read(poll, socket);
            println!("Client_plain: {:?}\n", client_plain);
        }

        if ev.readiness().is_writable() {
            println!("Writeable! \n");
            self.do_tls_write();
        }

        println!("Wants write? {:?}", self.tls_session.wants_write());

        if self.closing && !self.tls_session.wants_write() {
            //if self.closing {
            println!("Connection closing...\n");
            //Prepare to remove connection from hashmap
            self.closed = true;


        } else {
            //register succeeds for write events, reregister succeeds for read events
            match self.register(poll, socket) {
                Ok(_) => {
                    println!("Register performed on poll.\n");
                },
                Err(_) => {
                    self.reregister(poll, socket).unwrap();
                    println!("Reregister performed on poll.\n");
                }
            }
        }

    }

    /// We're a connection, and we have something to do.
    fn ready_write(&mut self, poll: &mut mio::Poll, ev: &mio::Event, socket: &QuicSocket) {
        // If we're readable: read some TLS.  Then
        // see if that yielded new plaintext.  Then
        // see if the backend is readable too.
        println!("Handshaking? - {:?}\n", self.tls_session.is_handshaking());

        if ev.readiness().is_writable() {
            println!("Writeable! \n");
            self.do_tls_write();
        }


        println!("Wants write (ready_write)? {:?}", self.tls_session.wants_write());

        if self.closing && !self.tls_session.wants_write() {
            //if self.closing {
            println!("Connection closing...\n");
            //Prepare to remove connection from hashmap
            self.closed = true;

        //Send complete buffered TLS message to client
        } else if !self.tls_session.wants_write(){
            //TODO: refactor this garbage
            socket.sock.send_to(&self.buf.buf[0..self.buf.offset], &self.addr).unwrap();
            println!("TLS message sent.");

            self.reregister(poll, socket).unwrap();


        } else {
            //register succeeds for write events, reregister succeeds for read events
            match self.register(poll, socket) {
                Ok(_) => {
                    println!("Register performed on poll.\n");
                },
                Err(_) => {
                    self.reregister(poll, socket).unwrap();
                    println!("Reregister performed on poll.\n");
                }
            }
        }

    }


    fn do_tls_read(&mut self, buffer: &mut [u8], msg_len: usize) {
        // Read some TLS data.
        println!("read_tls (session -> socket) ... \n");
        //Read from buffer passed from listener, data no longer in socket
        let rc = self.tls_session.read_tls(&mut &buffer[0..msg_len]);
        println!("result: {:?}\n", rc);
        if rc.is_err() {
            let err = rc.unwrap_err();

            if let io::ErrorKind::WouldBlock = err.kind() {
                return
            }

            error!("read error {:?}", err);
            return
        }

        // Process newly-received TLS messages.
        let processed = self.tls_session.process_new_packets();
        println!("process_new_packets (session) ... \n");
        println!("result: {:?}\n", processed);
        if processed.is_err() {
            error!("cannot process packet: {:?}", processed);
            return
        }
    }

    fn try_plain_read(&mut self, poll: &mut mio::Poll, socket: &mut QuicSocket) {
        // Read and process all available plaintext.
        let mut buf = Vec::new();

        let rc = self.tls_session.read_to_end(&mut buf);
        println!("read_to_end/plain_read (session -> buf (new vec)) ... \n");
        println!("result: {:?}\n", rc);
        if rc.is_err() {
            error!("plaintext read failed: {:?}", rc);
            return;
        }

        if !buf.is_empty() {
            println!("plaintext read {:?}\n\n", buf);
            self.incoming_plaintext(&buf, poll, socket);
        }
        println!("End of try_plain_read\n");
    }


    /// Process some amount of received plaintext.
    fn incoming_plaintext(&mut self, buf: &[u8], poll: &mut mio::Poll, socket: &mut QuicSocket) {
        match self.mode {
            ServerMode::Echo => {
                println!("write_all (session -> buf) ... \n");
                self.tls_session.write_all(buf).unwrap();
            }
            ServerMode::Http => {
                self.send_http_response_once(poll, socket);
            }
        }
    }

    fn send_http_response_once(&mut self, poll: &mut mio::Poll, mut socket: &mut QuicSocket) {
        let response = b"HTTP/1.0 200 OK\r\nConnection: close\r\n\r\nHello from Viridian! o/  \r\n";
        if !self.sent_http_response {

            self.tls_session
                .write_all(response)
                .unwrap();


            println!("write_all (session -> http response) ... \n");
            //Send response
            self.tls_session.write_tls(&mut socket).unwrap();
            //socket.sock.send_to(&self.tls_session, &self.addr);
            self.sent_http_response = true;
            self.closing = true;
            println!("HTTP response sent, sending close_notify...\n");
            self.tls_session.send_close_notify();
            self.tls_session.write_tls(&mut socket).unwrap();
            //socket.sock.send_to(&self.tls_session, &self.addr);

            self.reregister(poll, socket).unwrap();


        }
    }

    fn do_tls_write(&mut self) {
        println!("write_tls (session -> socket) ... \n");
        let rc = self.tls_session.write_tls(&mut self.buf.buf[self.buf.offset..10000].as_mut());
        //println!("sent: {:?}\n", rc);
        println!("written: {:?}\n", rc);
        if rc.is_err() {
            error!("write failed {:?}", rc);
            return;
        } else {
            //self.socket.buf.offset = rc.unwrap();
            self.buf.offset += rc.unwrap();
            println!("Buf: {:?}", self.buf);
            println!("Offset: {:?} - {:?}", self.buf.offset, self.buf.buf[self.buf.offset-1]);
            return;
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

    fn is_closed(&self) -> bool {
        self.closing
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

fn main() {
    let version = env!("CARGO_PKG_NAME").to_string() + ", version: " + env!("CARGO_PKG_VERSION");

    let args: Args = Docopt::new(USAGE)
        .and_then(|d| Ok(d.help(true)))
        .and_then(|d| Ok(d.version(Some(version))))
        .and_then(|d| d.deserialize())
        .unwrap_or_else(|e| e.exit());

    if args.flag_verbose {
        let mut logger = env_logger::LogBuilder::new();
        logger.parse("debug");
        logger.init().unwrap();
    }
    let mut event_count = 0;

    //let mut addr: net::SocketAddr = "0.0.0.0:443".parse().unwrap();
    //addr.set_port(args.flag_port.unwrap_or(443));

    let config = make_config(&args);

    let mut poll = mio::Poll::new()
        .unwrap();



    let mode = if args.cmd_echo {
        ServerMode::Echo
    } else {
        ServerMode::Http
    };

    //Custom QuicSocket setup
    //Create socket
    let bind_info = SocketAddr::from_str("127.0.0.1:9090").unwrap();
    let socket = UdpSocket::bind(&bind_info).unwrap();

    //let tls_buf = TlsBuffer{buf : Vec::new()};
    let tls_buf = TlsBuffer{buf : [0;10000], offset : 0};
    let quic_sock = QuicSocket{sock: socket, buf : tls_buf, addr : SocketAddr::from_str("127.0.0.1:8080").unwrap()};

    let mut tlsserv = TlsServer::new(quic_sock, mode, config);

    //Socket only needs to be registered once, detecting readable and writable events
    poll.register(&tlsserv.server.sock,
                  LISTENER,
                  mio::Ready::readable(),
                  mio::PollOpt::edge())
                  //mio::PollOpt::level())
        .unwrap();


    //Placeholder for recent_client, will be changed as soon as new client accepted
    let mut recent_client = SocketAddr::from_str("127.0.0.1:4444").unwrap();

    let mut events = mio::Events::with_capacity(256);
    loop {
        poll.poll(&mut events, None)
            .unwrap();

        //let sleep_time = time::Duration::from_millis(1000);
        //thread::sleep(sleep_time);

        for event in events.iter() {

            match event.token() {
                //Single socket in poll, shouldn't be any other matches
                LISTENER => {
                    println!("Event received:");
                    //Readable event could be a new client initiating contact
                    //recv_from needs to be called here to check if client is already held in connections hashtable
                    //No other way to retrieve client SocketAddr - unfortunate side-effect of this is needing two separate conn_event functions which take different args
                    if event.readiness().is_readable() {
                        println!("Readable event:");
                        let mut array : [u8; 1500] = [0;1500];
                        //Error being thrown here
                        let client_info = tlsserv.server.sock.recv_from(&mut array).unwrap();
                        println!("Recv_from complete");
                        //If client's address is not in the hashmap containing established connections, call accept to add it
                        if !(tlsserv.connections.contains_key(&client_info.1)) {
                            tlsserv.accept(client_info.1);
                        };

                        //Process readable event as normal
                        event_count += 1;
                        println!("------------------\nEvent (listener) #{:?}\n", event_count);
                        println!("Event: {:?}\n", event);
                        tlsserv.conn_event_read(&mut poll, &event, client_info.1, &mut array, client_info.0);

                        //Change addr on QuicSocket to recent client to allow application data to be sent
                        recent_client = client_info.1;
                        tlsserv.server.addr = recent_client;

                    //If it's a writable event, client address info is already held in connections hashtable
                    } else {
                        event_count += 1;
                        println!("------------------\nEvent (listener) #{:?}\n", event_count);
                        println!("Event: {:?}\n", event);
                        //Process writeable event
                        tlsserv.conn_event_write(&mut poll, &event, recent_client)
                    };

                }
                _ => println!("If you're seeing this something has gone very wrong...\n")
            }
        }
    }
}
