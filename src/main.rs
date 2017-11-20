extern crate mio;
extern crate bytes;
extern crate quickcheck;

use mio::net::UdpSocket;

mod header;

use std::env;
use std::net::SocketAddr;
use std::str::FromStr;
use std::io::Write;

//use bytes::{Bytes, BytesMut, BufMut, BigEndian};
use bytes::{Bytes};

use header::{Header, PacketType, PacketNumber, ConnectionID};


fn main() {
    
    println!("\n QUIC and Rust combine...\n");
   
    //Expected command line use:
    //cargo run send packet_type "some payload message" bind_ip:bind_port dest_ip:dest_port
    //cargo run listen bind_ip:bind_port
    //cargo run start bind_ip:bind_port dest_ip:dest_port
    let args: Vec<String> = env::args().collect();
    
    println!("{:?}", args);
    
    match args[1].trim() {
    	"send" => send_msg(&args[2], &args[3], &args[4], &args[5]),
    	"listen" => listen(&args[2]),
    	"start" => initial_connect(&args[2], &args[3]),
    	//TODO: anything other than panic! here
    	_ => panic!("Invalid first argument supplied - 'send', 'listen' or 'start' only."),
    }
    
}



//Start a connection with a listening server
fn initial_connect(bind_str: &str, dest_str: &str){
	
	//Send ClientInitial packet
    Header::start_new_connection(bind_str, dest_str);
    println!("\nStarting new QUIC connection...\nClientInitial packet sent.\n");
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
	UdpSocket::send_to(&socket, std::convert::AsRef::as_ref(&Header::generate_bytes(msg_to_send)), &dest_info).expect("Couldn't send message.");
	
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
	let mut input_buf = [0; 1200];
	
	loop {
		//Attempt to retrieve data from socket
		match socket.recv_from(&mut input_buf){
			Ok(_) => break,
			Err(_) => continue,
		};
	}
	
	//Convert [u8] into Bytes struct
	let input_buf = Bytes::from(&input_buf[..]);
	
	println!("msg received: {:?}\n\n", &input_buf);
	
	//Parse received message
	//TODO: get a Header struct returned
	let output_buf = Header::parse_message(input_buf);
	
	//Print the raw bytestream
	println!("output_buf: {:?}", &output_buf);
	
	//Attempt to print as a String
	//println!("Output as str: {:?}", std::str::from_utf8(&output_buf.payload));
}
