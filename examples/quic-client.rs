use std::sync::{Arc, Mutex};
use std::process;

extern crate mio;
use mio::net::UdpSocket;

use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::str;
use std::io;
use std::fs;
use std::collections;
use std::io::{Read, Write, BufReader};

extern crate bytes;
use bytes::Bytes;

extern crate rand;
use rand::Rng;

extern crate mercury;
use mercury::header::{Header, PacketTypeLong, ConnectionBuffer, decode, QuicSocket};

extern crate env_logger;

#[macro_use]
extern crate serde_derive;
extern crate docopt;
use docopt::Docopt;

extern crate rustls;
extern crate webpki;
extern crate webpki_roots;
extern crate ct_logs;


use rustls::Session;

const CLIENT: mio::Token = mio::Token(0);


#[derive(Debug, PartialOrd, PartialEq)]
//Track which stage a connection is in
enum ConnectionStatus {
    Initial,
    Handshake,
    DataSharing,
    Closing
}

//End of custom structs


/// This encapsulates the TCP-level connection, some connection
/// state, and the underlying TLS-level session.
struct TlsClient {
    socket: QuicSocket,
    buf : ConnectionBuffer,
    connection_id : u64,
    packet_number : u32,
    version : u32,
    status: ConnectionStatus,
    tls_session: rustls::ClientSession,
}

/// We implement `io::Write` and pass through to the TLS session
impl io::Write for TlsClient {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.tls_session.write(bytes)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.tls_session.flush()
    }
}

impl io::Read for TlsClient {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        //println!("read (session -> bytes) ... \n");
        self.tls_session.read(bytes)
    }
}

impl TlsClient {

    fn process_event(&mut self,
             poll: &mut mio::Poll,
             ev: &mio::Event) {
        assert_eq!(ev.token(), CLIENT);

        match self.status {
            ConnectionStatus::Initial => {
                //Send initial TLS message to server
                println!("Initial write (ClientHello)");
                self.do_write();

                self.send_quic_packet();
            }

            ConnectionStatus::Handshake => {
                //Read handshake response from server
                println!("Reading handshake response (ServerHello)\n");
                self.do_read();
                //Send Finished response to complete handshake
                println!("Sending message to complete handshake (Finished)");
                self.do_write();

                self.send_quic_packet();
            }

            ConnectionStatus::DataSharing => {
                if ev.readiness().is_writable() {
                    println!("Sending data:");
                    self.do_write();

                    self.send_quic_packet();

                } else {
                    println!("Reading data:");
                    self.do_read();
                }
            }

            ConnectionStatus::Closing => {
                println!("Connection closing.");
            }
        }

        //println!("Handshaking? - {:?}\n", self.tls_session.is_handshaking());

        self.reregister(poll);
    }

    /// Send encoded QUIC Header
    /// Increments packet count and connection status
    pub fn send_quic_packet(&mut self) {

        self.packet_number += 1;

        let packet_type = match self.status {
            ConnectionStatus::Initial => PacketTypeLong::Initial,
            ConnectionStatus::Handshake  => PacketTypeLong::Handshake,
            ConnectionStatus:: DataSharing => PacketTypeLong::ZeroRTTProtected,
            ConnectionStatus:: Closing => panic!("Connection closing, cannot send packet.")
        };

        let header = Header::LongHeader {packet_type,
            connection_id : self.connection_id,
            packet_number : self.packet_number,
            version : self.version,
            payload : self.buf.buf[0..self.buf.offset].to_vec()};

        println!("Packet: {:?}", header);

        //Encode and send message to server using custom QuicClientSocket behaviour
        self.socket.write(&header.encode()).unwrap();

        self.status = match self.status {
            ConnectionStatus::Initial => ConnectionStatus::Handshake,
            ConnectionStatus::Handshake => ConnectionStatus::DataSharing,
            ConnectionStatus:: DataSharing => ConnectionStatus::DataSharing,
            ConnectionStatus:: Closing => panic!("Connection closing.")
        };
    }


    fn new(sock: QuicSocket, hostname: webpki::DNSNameRef, cfg: Arc<rustls::ClientConfig>) -> TlsClient {

        //Packet number is a randomly chosen value between 0 and 2^32 - 1025
        let rng_packet_number = (rand::thread_rng().gen::<u32>()) - 1025;
        //Connection ID is a randomly chosen value between 0 and 2^64
        let rng_conn_id = rand::thread_rng().gen::<u64>();
        TlsClient {
            socket: sock,
            buf: ConnectionBuffer{buf : [0;10000], offset: 0},
            connection_id: rng_conn_id,
            packet_number: rng_packet_number,
            //IETF experimental versions follow the format 0x?a?a?a?a
            //IETF quic-transport draft 08 uses version 0xff000008
            version: 0xff000008,
            status: ConnectionStatus::Initial,
            tls_session: rustls::ClientSession::new(&cfg, hostname),
        }
    }

    fn read_source_to_end(&mut self, rd: &mut io::Read) -> io::Result<usize> {
        let mut buf = Vec::new();
        let len = rd.read_to_end(&mut buf)?;
        self.tls_session.write_all(&buf).unwrap();
        println!("write_all/read_source_to_end (session -> buf) ... \n");
        println!("sent: {:?}\n", buf);
        Ok(len)
    }

    /// We're ready to do a read.
    fn do_read(&mut self) {
        // Read TLS data.
        let mut array : [u8;7000] = [0;7000];
        //Retrieve data from socket and parse into Header struct
        let offset = &self.socket.read(&mut array).unwrap();
        let header = decode(Bytes::from(&array[0..*offset]));
        println!("Packet: {:?}", header);

        //Update packet number to continue incrementation correctly
        self.packet_number = header.get_packet_number();

        let rc = self.tls_session.read_tls(&mut header.get_payload().as_slice());
        println!("read_tls (session -> socket) ... \n");
        println!("result: {:?}\n", rc);
        if rc.is_err() {
            println!("TLS read error: {:?}", rc);
            self.status = ConnectionStatus::Closing;
            return;
        }

        // If we're ready but there's no data: EOF.
        if rc.unwrap() == 0 {
            println!("EOF");
            self.status = ConnectionStatus::Closing;
            return;
        }

        // Reading some TLS data might have yielded new TLS
        // messages to process.  Errors from this indicate
        // TLS protocol problems and are fatal.
        let processed = self.tls_session.process_new_packets();
        println!("process_new_packets (session) ... \n");
        println!("result: {:?}\n", processed);
        if processed.is_err() {
            println!("TLS error: {:?}", processed.unwrap_err());
            self.status = ConnectionStatus::Closing;
            return;
        }

        // Having read some TLS data, and processed any new messages,
        // we might have new plaintext as a result.
        //
        // Read it and then write it to stdout.
        let mut plaintext = Vec::new();
        let rc = self.tls_session.read_to_end(&mut plaintext);
        println!("read_to_end/plain_read (session -> plaintext) ... \n");
        println!("result: {:?}\n", plaintext);
        if !plaintext.is_empty() {
            io::stdout().write_all(&plaintext).unwrap();
        }

        // If that fails, the peer might have started a clean TLS-level
        // session closure.
        if rc.is_err() {
            let err = rc.unwrap_err();
            println!("Plaintext read error: {:?}", err);
            self.status = ConnectionStatus::Closing;
            return;
        }
    }

    fn do_write(&mut self) {
        println!("write_tls(session -> socket) ... \n");
        //Write tls messages to buffer and update offset marker
        self.buf.offset = self.tls_session.write_tls(&mut self.buf.buf[0..].as_mut()).unwrap();

    }

    fn register(&self, poll: &mut mio::Poll) {
        poll.register(&self.socket.sock,
                      CLIENT,
                      self.ready_interest(),
                      mio::PollOpt::level() | mio::PollOpt::oneshot())
            .unwrap();
    }

    fn reregister(&self, poll: &mut mio::Poll) {
        poll.reregister(&self.socket.sock,
                        CLIENT,
                        self.ready_interest(),
                        mio::PollOpt::level() | mio::PollOpt::oneshot())
            .unwrap();
    }

    // Use wants_read/wants_write to register for different mio-level
    // IO readiness events.
    fn ready_interest(&self) -> mio::Ready {
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

}

/// This is an example cache for client session data.
/// It optionally dumps cached data to a file, but otherwise
/// is just in-memory.
///
/// Note that the contents of such a file are extremely sensitive.
/// Don't write this stuff to disk in production code.
struct PersistCache {
    cache: Mutex<collections::HashMap<Vec<u8>, Vec<u8>>>,
    filename: Option<String>,
}

impl PersistCache {
    /// Make a new cache.  If filename is Some, load the cache
    /// from it and flush changes back to that file.
    fn new(filename: &Option<String>) -> PersistCache {
        let cache = PersistCache {
            cache: Mutex::new(collections::HashMap::new()),
            filename: filename.clone(),
        };
        if cache.filename.is_some() {
            cache.load();
        }
        cache
    }

    /// If we have a filename, save the cache contents to it.
    fn save(&self) {
        use rustls::internal::msgs::codec::Codec;
        use rustls::internal::msgs::base::PayloadU16;

        if self.filename.is_none() {
            return;
        }

        let mut file = fs::File::create(self.filename.as_ref().unwrap())
            .expect("cannot open cache file");

        for (key, val) in self.cache.lock().unwrap().iter() {
            let mut item = Vec::new();
            let key_pl = PayloadU16::new(key.clone());
            let val_pl = PayloadU16::new(val.clone());
            key_pl.encode(&mut item);
            val_pl.encode(&mut item);
            file.write_all(&item).unwrap();
        }
    }

    /// We have a filename, so replace the cache contents from it.
    fn load(&self) {
        use rustls::internal::msgs::codec::{Codec, Reader};
        use rustls::internal::msgs::base::PayloadU16;

        let mut file = match fs::File::open(self.filename.as_ref().unwrap()) {
            Ok(f) => f,
            Err(_) => return,
        };
        let mut data = Vec::new();
        file.read_to_end(&mut data).unwrap();

        let mut cache = self.cache.lock()
            .unwrap();
        cache.clear();
        let mut rd = Reader::init(&data);

        while rd.any_left() {
            let key_pl = PayloadU16::read(&mut rd).unwrap();
            let val_pl = PayloadU16::read(&mut rd).unwrap();
            cache.insert(key_pl.0, val_pl.0);
        }
    }
}

impl rustls::StoresClientSessions for PersistCache {
    /// put: insert into in-memory cache, and perhaps persist to disk.
    fn put(&self, key: Vec<u8>, value: Vec<u8>) -> bool {
        self.cache.lock()
            .unwrap()
            .insert(key, value);
        self.save();
        true
    }

    /// get: from in-memory cache
    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.cache.lock()
            .unwrap()
            .get(key).cloned()
    }
}

const USAGE: &'static str = "
Connects to the TLS server at hostname:PORT.  The default PORT
is 443.  By default, this reads a request from stdin (to EOF)
before making the connection.  --http replaces this with a
basic HTTP GET request for /.

If --cafile is not supplied, a built-in set of CA certificates
are used from the webpki-roots crate.

Usage:
  tlsclient [options] [--suite SUITE ...] [--proto PROTO ...] <hostname>
  tlsclient (--version | -v)
  tlsclient (--help | -h)

Options:
    -p, --port PORT     Connect to PORT [default: 443].
    --http              Send a basic HTTP GET request for /.
    --cafile CAFILE     Read root certificates from CAFILE.
    --auth-key KEY      Read client authentication key from KEY.
    --auth-certs CERTS  Read client authentication certificates from CERTS.
                        CERTS must match up with KEY.
    --suite SUITE       Disable default cipher suite list, and use
                        SUITE instead.  May be used multiple times.
    --proto PROTOCOL    Send ALPN extension containing PROTOCOL.
                        May be used multiple times to offer serveral protocols.
    --cache CACHE       Save session cache to file CACHE.
    --no-tickets        Disable session ticket support.
    --no-sni            Disable server name indication support.
    --insecure          Disable certificate verification.
    --verbose           Emit log output.
    --mtu MTU           Limit outgoing messages to MTU bytes.
    --version, -v       Show tool version.
    --help, -h          Show this screen.
";

#[derive(Debug, Deserialize)]
struct Args {
    flag_port: Option<u16>,
    flag_http: bool,
    flag_verbose: bool,
    flag_suite: Vec<String>,
    flag_proto: Vec<String>,
    flag_mtu: Option<usize>,
    flag_cafile: Option<String>,
    flag_cache: Option<String>,
    flag_no_tickets: bool,
    flag_no_sni: bool,
    flag_insecure: bool,
    flag_auth_key: Option<String>,
    flag_auth_certs: Option<String>,
    arg_hostname: String,
}

/// Find a ciphersuite with the given name
fn find_suite(name: &str) -> Option<&'static rustls::SupportedCipherSuite> {
    for suite in &rustls::ALL_CIPHERSUITES {
        let sname = format!("{:?}", suite.suite).to_lowercase();

        if sname == name.to_string().to_lowercase() {
            return Some(suite);
        }
    }

    None
}

/// Make a vector of ciphersuites named in `suites`
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
    let keyfile = fs::File::open(filename).expect("cannot open private key file");
    let mut reader = BufReader::new(keyfile);
    let keys = rustls::internal::pemfile::rsa_private_keys(&mut reader).unwrap();
    assert!(keys.len() == 1);
    keys[0].clone()
}

fn load_key_and_cert(config: &mut rustls::ClientConfig, keyfile: &str, certsfile: &str) {
    let certs = load_certs(certsfile);
    let privkey = load_private_key(keyfile);

    config.set_single_client_cert(certs, privkey);
}

#[cfg(feature = "dangerous_configuration")]
mod danger {
    use super::rustls;
    use webpki;

    pub struct NoCertificateVerification {}

    impl rustls::ServerCertVerifier for NoCertificateVerification {
        fn verify_server_cert(&self,
                              _roots: &rustls::RootCertStore,
                              _presented_certs: &[rustls::Certificate],
                              _dns_name: webpki::DNSNameRef,
                              _ocsp: &[u8]) -> Result<rustls::ServerCertVerified, rustls::TLSError> {
            Ok(rustls::ServerCertVerified::assertion())
        }
    }
}

#[cfg(feature = "dangerous_configuration")]
fn apply_dangerous_options(args: &Args, cfg: &mut rustls::ClientConfig) {
    if args.flag_insecure {
        cfg
            .dangerous()
            .set_certificate_verifier(Arc::new(danger::NoCertificateVerification {}));
    }
}

#[cfg(not(feature = "dangerous_configuration"))]
fn apply_dangerous_options(args: &Args, _: &mut rustls::ClientConfig) {
    if args.flag_insecure {
        panic!("This build does not support --insecure.");
    }
}

/// Build a `ClientConfig` from our arguments
fn make_config(args: &Args) -> Arc<rustls::ClientConfig> {
    let mut config = rustls::ClientConfig::new();

    if !args.flag_suite.is_empty() {
        config.ciphersuites = lookup_suites(&args.flag_suite);
    }

    if args.flag_cafile.is_some() {
        let cafile = args.flag_cafile.as_ref().unwrap();

        let certfile = fs::File::open(&cafile).expect("Cannot open CA file");
        let mut reader = BufReader::new(certfile);
        config.root_store
            .add_pem_file(&mut reader)
            .unwrap();
    } else {
        config.root_store.add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
        config.ct_logs = Some(&ct_logs::LOGS);
    }

    if args.flag_no_tickets {
        config.enable_tickets = false;
    }

    if args.flag_no_sni {
        //config.enable_sni = false;
        config.enable_tickets = false;
    }

    let persist = Arc::new(PersistCache::new(&args.flag_cache));

    config.set_protocols(&args.flag_proto);
    config.set_persistence(persist);
    config.set_mtu(&args.flag_mtu);

    apply_dangerous_options(args, &mut config);

    if args.flag_auth_key.is_some() || args.flag_auth_certs.is_some() {
        load_key_and_cert(&mut config,
                          args.flag_auth_key
                              .as_ref()
                              .expect("must provide --auth-key with --auth-certs"),
                          args.flag_auth_certs
                              .as_ref()
                              .expect("must provide --auth-certs with --auth-key"));
    }

    Arc::new(config)
}

/// Parse some arguments, then make a TLS client connection
/// somewhere.
fn client_setup() -> TlsClient {
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

    //let port = args.flag_port.unwrap_or(5050);
    //Not sure why this is stubbornly persisting with port 443 instead of 5050
    let port: u16 = match args.flag_port {
        Some(num) => num,
        None => 5050
    };
    let addr = IpAddr::from_str("127.0.0.1").unwrap();
    println!("port: {:?}", port);
    println!("addr: {:?}", addr);
    let socket = UdpSocket::bind(&SocketAddr::new(addr, port)).unwrap();

    println!("socket: {:?}", socket);

    let config = make_config(&args);

    //Create socket
    let quic_sock = QuicSocket{sock: socket, addr : SocketAddr::from_str("127.0.0.1:9090").unwrap()};

    let dns_name = webpki::DNSNameRef::try_from_ascii_str(&args.arg_hostname).unwrap();
    //Hardcoded connection_id - not ideal
    let mut tlsclient = TlsClient::new(quic_sock, dns_name, config);

    if args.flag_http {
        let httpreq = format!("GET / HTTP/1.1\r\nHost: {}\r\nConnection: \
                               close\r\nAccept-Encoding: identity\r\n\r\n",
                              args.arg_hostname);
        tlsclient.write_all(httpreq.as_bytes()).unwrap();
    } else {
        let mut stdin = io::stdin();
        tlsclient.read_source_to_end(&mut stdin).unwrap();
    }

    tlsclient
}

//Main polling loop for processing events
fn main() {
    let mut tlsclient = client_setup();

    let mut poll = mio::Poll::new()
        .unwrap();
    let mut events = mio::Events::with_capacity(32);
    tlsclient.register(&mut poll);

    let mut event_count = 0;

    loop {
        poll.poll(&mut events, None)
            .unwrap();

        for ev in events.iter() {
            event_count += 1;
            println!("------------------\nEvent #{:?}\n", event_count);
            tlsclient.process_event(&mut poll, &ev);
            //Exit if an error has occured or the connection has been intentionally closed
            if tlsclient.status == ConnectionStatus::Closing {
                process::exit(0);
            }
        }
    }
}
