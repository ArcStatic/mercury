#![allow(dead_code)]
#![allow(unused_variables)]
#![allow(unused_must_use)]
#![allow(unused_imports)]


extern crate mio;
extern crate bytes;
extern crate quickcheck;
extern crate rustls;
extern crate webpki;
extern crate webpki_roots;

mod header;

use mio::net::UdpSocket;
use rustls::{Session, ServerConfig};
use std::sync::Arc;
use std::env;
use std::net::SocketAddr;
use std::str::FromStr;
use std::io::Write;
use std::io::stdout;
use std::io::{self, BufReader};
use std::io::prelude::*;
use std::fs::File;

//use bytes::{Bytes, BytesMut, BufMut, BigEndian};
use bytes::{Bytes};

use header::{Header, PacketType, PacketNumber, ConnectionID, TlsBuffer, QuicSocket};

fn main() {
    
    println!("\n QUIC and Rust combine...\n");
   
    //Expected command line use:
    //cargo run send packet_type "some payload message" bind_ip:bind_port dest_ip:dest_port
    //cargo run listen bind_ip:bind_port
    //cargo run start bind_ip:bind_port dest_ip:dest_port
    //cargo run tls bind_ip:bind_port dest_ip:dest_port
    let args: Vec<String> = env::args().collect();
    
    println!("{:?}", args);
    
    match args[1].trim() {
    	"send" => send_msg(&args[2], &args[3], &args[4], &args[5]),
    	"listen" => listen(&args[2]),
        "listen_tls" => listen_tls(&args[2]),
    	"start" => initial_connect(&args[2], &args[3]),
    	"tls" => header::tls_start_client(&args[2], &args[3]),
        "tls_test" => header::tls_start_client_test(&args[2], &args[3]),
    	//TODO: anything other than panic! here
    	_ => panic!("Invalid first argument supplied - 'send', 'listen' or 'start' only."),
    }
    
}



//Start a connection with a listening server
fn initial_connect(bind_str: &str, dest_str: &str){
	
	//Start new connection with server
    Header::start_new_connection(bind_str, dest_str);
}



//Send a message/packet type
fn send_msg(header_type: &str, msg: &str, bind_str: &str, dest_str: &str){
	
	//Write payload as bytes
	let mut payload_vec : Vec<u8> = Vec::new();
	payload_vec.write(msg.as_bytes()).unwrap();
	
	//Check if message being sent is a LongHeader, ShortHeader or just some arbitrary text
	//Fill in relevant Header fields
	let msg_to_send = match header_type{
		"long_header" => Header::LongHeader{
		                                    packet_type : PacketType::ZeroRTTProtected,
		                                    connection_id : 0x0000af40,
		                                    packet_number : 0x00050a10,
		                                    version : 0b10011000,
		                                    payload : payload_vec
		                                   },
		
		"short_header" => Header::ShortHeader{
		                                      key_phase : true,
		                                      connection_id : Some(ConnectionID(0x000e5a00)),
		                                      packet_number : PacketNumber::OneOctet(0b00010101),
		                                      payload : payload_vec
		                                     },
		
		_ => panic!("Unrecognised header type."),
	};
	
	//Print Header info
	println!("Header created: {:?} ", msg_to_send);
	
	//Create SocketAddr
	//let bind_info = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127,0,0,1)), 8080);
	let bind_info = SocketAddr::from_str(bind_str).unwrap();
	
	//Bind socket to given address
	let socket = UdpSocket::bind(&bind_info).unwrap();
	
	//Print socket info
	//println!("UDP socket {:?} created in send mode.", socket);
		
	//Create SocketAddr from supplied addr:port str
	let dest_info = SocketAddr::from_str(dest_str).unwrap();
	
	
	//println!("{:?}", &socket_addr.unwrap())
	//Send message to dest_addr:dest_port
	//TODO: Horrible conversion of Bytes to [u8] here - maybe get generate_bytes to return an array of u8 instead?
	UdpSocket::send_to(&socket, std::convert::AsRef::as_ref(&Header::generate_bytes(msg_to_send)), &dest_info).expect("Couldn't send custom message.");
	
	println!("Message sent to {:?}", &dest_info);

}



//Listen for incoming messages/packet types
fn listen(bind_str: &str){
	//Create SocketAddr
	//let bind_info = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127,0,0,1)), 8080);
	let bind_info = SocketAddr::from_str(bind_str).unwrap();
	
	//Bind socket to given address
	let socket = UdpSocket::bind(&bind_info).unwrap();
	
	//Set up a [u8] buffer for incoming messages/packets
	//Size 1200 bytes to match current QUIC specification
	let mut input_buf = [0; 1200];
	
	loop {
		//Attempt to retrieve data from socket
		match socket.recv_from(&mut input_buf){
			Ok(addr) => {//Convert [u8] into Bytes struct
	                    let input_buf = Bytes::from(&input_buf[..]);
	
	                    //println!("msg received: {:?}\n\n", &input_buf);
	
	                    //Parse received message
	                    let recv_header = Header::parse_message(input_buf);
	
	                    //Print the raw bytestream
	                    //TODO: uncomment
	                    //println!("recv_header: {:?}", &recv_header);
	
	                    //Detect which packet type was received
	                    //if Header::is_new_connection(&recv_header){
	                    match &recv_header {
	                        
	                        //Initial sent by client
                            &Header::LongHeader{packet_type : header::PacketType::Initial, connection_id, packet_number, version, ref payload} => {//If compatible version, send a Handshake packet to client
	                            println!("Intial received from client - potential new connection.\n");
	                            if Header::is_compatible_version(&recv_header){
	                                
	                                //Write payload as bytes
	                                let mut payload_vec : Vec<u8> = Vec::new();
	                                payload_vec.write(b"Some TLS payload here");
	                                
	                                //Create LongHeader
	                                let response = Header::LongHeader{
		                                        packet_type : PacketType::Handshake,
		                                        connection_id : 0x0000aaaa,
		                                        packet_number : 0x00050a11,
		                                        version : 0b00000001,
		                                        payload : payload_vec
		                            };
	                                //Send LongHeader as a bytestream
	                                UdpSocket::send_to(&socket, std::convert::AsRef::as_ref(&Header::generate_bytes(response)), &addr.1).expect("Couldn't send Handshake packet to client.");
	                                println!("Handshake response sent to client.\n");
	                            };
	                        }
	                        
	                        
	                        //Handshake sent by client
	                        &Header::LongHeader{packet_type : header::PacketType::Handshake, connection_id, packet_number, version, ref payload} => {
	                            println!("Handshake received from client.");
	                            
	                            //Write payload as bytes
                                let mut payload_vec : Vec<u8> = Vec::new();
                                payload_vec.write(b"Some application payload here");
                                
                                //Create ShortHeader
                                let response = Header::ShortHeader{
	                                        key_phase : true,
	                                        connection_id : Some(ConnectionID(0x0000aaaa)),
	                                        packet_number : PacketNumber::FourOctet(0x0040ffff),
	                                        payload : payload_vec
	                            };
                                //Send ShortHeader as a bytestream
                                UdpSocket::send_to(&socket, std::convert::AsRef::as_ref(&Header::generate_bytes(response)), &addr.1).expect("Couldn't send 1-RTT ShortHeader packet to client.");
                                println!("1-RTT ShortHeader sent to client.\n");
	                        }
	                        
	                        
	                        //1-RTT ShortHeader sent by client
	                        &Header::ShortHeader{key_phase: true, ref connection_id, ref packet_number, ref payload} => {
	                            println!("1-RTT ShortHeader received from client.");
	                            
	                            //Write payload as bytes
                                let mut payload_vec : Vec<u8> = Vec::new();
                                payload_vec.write(b"Some ShortHeader response payload here");                               
                                
                                //Create LongHeader
                                let response = Header::ShortHeader{
	                                        key_phase : true,
	                                        connection_id : Some(ConnectionID(0x0000aaaa)),
	                                        packet_number : PacketNumber::FourOctet(0x00050a11),
	                                        payload : payload_vec
	                            };
	                            
                                //Send ShortHeader as a bytestream
                                UdpSocket::send_to(&socket, std::convert::AsRef::as_ref(&Header::generate_bytes(response)), &addr.1).expect("Couldn't send 1-RTT ShortHeader packet to client.");
                                println!("1-RTT ShortHeader sent to client.\n");
	                        }
	                        
                            _ => println!("Unrecognised packet type received.\n"),
                            
	                    //End of packet matching block  
	                    };
	        }
			Err(_) => continue,
		};
	}
	
	
	
	//Attempt to print as a String
	//println!("Output as str: {:?}", std::str::from_utf8(&output_buf.payload));
}


//Listen for incoming messages/packet types
fn listen_tls(bind_str: &str){
    println!("Listening for TLS");

	//Prepare cert and key in DER format
    //let key_file = File::open("quic-rust-new.pem");
	let key_file = File::open("rsa/end.rsa");
    let mut key_read = BufReader::new(key_file.unwrap());
	//let cert_file = File::open("quic-rust-new.crt");
	let cert_file = File::open("rsa/end.fullchain");
	let mut cert_read = BufReader::new(cert_file.unwrap());
	let mut der_key = rustls::internal::pemfile::rsa_private_keys(&mut key_read).unwrap();
	let der_cert = rustls::internal::pemfile::certs(&mut cert_read).unwrap();
	println!("{:?}\n", key_read);
	println!("{:?}\n", rustls::internal::pemfile::certs(&mut key_read));
	println!("der_key: {:?}.\n", der_key);
	println!("der_cert: {:?}.\n", der_cert);
	println!("Key/cert parsing done.\n");

    //Create and bind socket
    //let bind_info = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127,0,0,1)), 8080);
    let bind_info = SocketAddr::from_str(bind_str).unwrap();
    let socket = UdpSocket::bind(&bind_info).unwrap();
	println!("Socket bound.\n");

	//Default ciphersuites
	let mut config = rustls::ServerConfig::new();
	//Add key and cert to config
	ServerConfig::set_single_cert(&mut config, der_cert, der_key.remove(0));
	println!("Key/cert added to config.\n");

    let config_ref_count = Arc::new(config);
    let mut tls_buf = TlsBuffer{buf : Vec::new()};

    //Create server
    let mut server = rustls::ServerSession::new(&config_ref_count);

	let mut quic_sock = QuicSocket{sock: socket, buf : tls_buf, addr : SocketAddr::from_str("127.0.0.1:8080").unwrap()};

    let mut tls_stream = rustls::Stream::new(&mut server, &mut quic_sock);

    //Set up a [u8] buffer for incoming messages/packets
    //Size 1200 bytes to match current QUIC specification
    let mut input_buf = vec![0;500];

	println!("Listening...");

	let mut content = Vec::new();

	loop {
		match tls_stream.sess.read_tls(tls_stream.sock){
			Ok(_) => {
				tls_stream.sess.process_new_packets();
				tls_stream.sess.read_to_end(&mut content);
				println!("Content: {:?}\n", content);
				break;
			}
			Err(_) => continue,
		}

	}

	tls_stream.sess.write_all("You found a plaintext TLS message! Congrats.".as_bytes()).unwrap();
	println!("\n\nTLS message sent to client.\n");

	/*
    loop {
        //Attempt to retrieve data from socket
        //match tls_stream.sock.sock.recv_from(&mut input_buf){
		match tls_stream.sock.read(&mut input_buf){
            Ok(recv_addr) => {//Convert [u8] into Bytes struct
                let mut output_buf : [u8 ; 500] = [0;500];

                println!("TLS message received from client.\n");
                stdout().write_all(&mut input_buf);

				//let mut plaintext = Vec::new();

				println!("\nread_tls...\n");
				tls_stream.sess.read_tls(&mut tls_stream.sock).unwrap();
				println!("process_new_packets...\n");
				tls_stream.sess.process_new_packets().unwrap();

				tls_stream.sess.read_to_end(&mut tls_stream.sock.buf.buf).unwrap();
				println!("\n\nProcessed message:\n\n");
				stdout().write_all(&mut tls_stream.sock.buf.buf).unwrap();

				tls_stream.sess.write_tls(tls_stream.sock).unwrap();

            }
            Err(_) => continue,
        };
    }
	*/

}
