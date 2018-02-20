#![allow(dead_code)]
#![allow(unused_variables)]
#![allow(unused_imports)]
#![allow(unused_must_use)]

extern crate rustls;
extern crate bytes;
extern crate webpki;
extern crate webpki_roots;

use bytes::{Bytes, BytesMut, Buf, BufMut, IntoBuf, BigEndian};

use header::rustls::{Session, ProtocolVersion};
use header::rustls::internal::msgs::handshake::{ClientHelloPayload, ClientExtension, ConvertProtocolNameList, ProtocolNameList, SessionID, Random};
use header::rustls::internal::msgs::enums::{Compression, CipherSuite};

use header::webpki::DNSNameRef;

use mio::net::UdpSocket;

use std::sync::Arc;
use std::str::from_utf8;
use std::net::SocketAddr;
use std::str::FromStr;
use std::io::Read;
use std::io::Write;
use std::io::Error;
use std::io::stdout;
use std::io::{self, BufReader};
use std::io::prelude::*;
use std::fs::File;
use std::result::Result;
use std::convert::AsRef;
use std::string::String;
use std::fmt;

#[derive(Debug)]
pub struct TlsBuffer{
	pub buf : Vec<u8>
}

impl Read for TlsBuffer {
	fn read (&mut self, mut output : &mut [u8]) -> Result<usize, Error> {
		//match output.write(&mut self.buf) {
        output.write(&mut self.buf)?;
		Ok(self.buf.len())
	}
}

impl Write for TlsBuffer {
	fn write(&mut self, input: &[u8]) -> Result<usize, Error>{
		&mut self.buf.write(input)?;
		//println!("tls_buf: {:?}", &mut self.buf);
		Ok(self.buf.len())
	}

    //TODO: correct this
	fn flush(&mut self) -> Result<(), Error>{
		&mut self.buf.flush()?;
		Ok(())
	}
}

pub struct ConnectionBuffer{
	pub buf : [u8;10000],
	pub offset : usize
}


impl fmt::Debug for ConnectionBuffer{
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		write!(f, "{:?}", &self.buf[0..self.offset])
	}
}


pub struct QuicSocket {
    pub sock : UdpSocket,
    pub buf : TlsBuffer,
    //pub buf : ConnectionBuffer,
    pub addr : SocketAddr,
}

impl Read for QuicSocket {
    fn read (&mut self, mut output : &mut [u8]) -> Result<usize, Error> {
        //match output.write(&mut self.buf) {
        //println!("\nCustom socket recv_from...\n");
        //UdpSocket::recv_from(&mut self.sock, output)?;
        loop {
            match UdpSocket::recv_from(&mut self.sock, output){
                Ok(addr) => {
                    println!("recv_from complete\n");
                    return Ok(output.len());
                }
                Err(_) => continue,
            }
        }
    }
}

impl Write for QuicSocket {
    fn write(&mut self, input : &[u8]) -> Result<usize, Error>{
        UdpSocket::send_to(&mut self.sock, input, &self.addr)?;
        Ok(input.len())
    }

    //TODO: correct this
    fn flush(&mut self) -> Result<(), Error>{
        &mut self.buf.flush()?;
        Ok(())
    }
}



#[derive(Debug)]
pub struct ConnectionID(pub u64);

#[derive(Debug)]
pub enum PacketNumber{
    OneOctet(u8),
    TwoOctet(u16),
    FourOctet(u32)
}

#[derive(Debug)]
pub enum PacketType{
    Initial,
    Retry,
    Handshake,
    ZeroRTTProtected
}

#[derive(Debug)]
pub enum Header {
	
	LongHeader{
		packet_type : PacketType,
		connection_id : u64,
		packet_number : u32,
		version : u32,
		//Payload is not a fixed size number of bits
		payload : Vec<u8>,
	},

	ShortHeader{
		key_phase : bool,
		//connection_id is present only if the bit for connection ID flag is set to 0
		connection_id : Option<ConnectionID>,
		packet_number : PacketNumber,
		//Payload is not a fixed size number of bits
		payload : Vec<u8>,
	}

}


//Methods associated with enum Header
impl Header{

    //GENERATE_BYTES METHOD    
    
	//Return a representation of a header in the form of a Bytes struct 
	pub fn generate_bytes(self) -> Bytes{

		let mut buf = BytesMut::with_capacity(1200);
		
		println!("\n{:?}\n", &self);
	
		//Determine which type of Header is being operated on
		match self {
			//LongHeader variant
		
			// 0                   1                   2                   3
			// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
			//+-+-+-+-+-+-+-+-+
			//|1|   Type (7)  |
			//+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			//|                                                               |
			//+                       Connection ID (64)                      +
			//|                                                               |
			//+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			//|                       Packet Number (32)                      |
			//+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			//|                         Version (32)                          |
			//+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			//|                          Payload (*)                        ...
			//+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			
			Header::LongHeader{packet_type, connection_id, packet_number, version, payload} => {
			    
			    //128 added to all values to mark this as a long header
			    //AVTCORE compliance: packet numbers in range 127-122 (descending)
			    match packet_type {
			        PacketType::Initial => buf.put_u8(128 + 0x7F),
                    PacketType::Retry => buf.put_u8(128 + 0x7E),
                    PacketType::Handshake => buf.put_u8(128 + 0x7D),
                    PacketType::ZeroRTTProtected => buf.put_u8(128 + 0x7C)
			    }

				buf.put_u64::<BigEndian>(connection_id);
				buf.put_u32::<BigEndian>(packet_number);
				buf.put_u32::<BigEndian>(version);
				buf.put_slice(&payload);
				println!("Length of packet: {}", BytesMut::len(&buf));
				println!("Capacity of packet: {}", BytesMut::capacity(&buf));
				println!("Remaining capacity of packet: {}", BytesMut::remaining_mut(&buf));
				
				println!("{:?}", buf);
				
				//All sent LongHeader packets must be padded to 1200 octets minimum according to IETF QUIC document v7
				let padding = vec![0; BytesMut::remaining_mut(&buf)];
				//Can't use array - complains about non-constant value being supplied
				//let padding = [0; BytesMut::remaining_mut(&buf)];
				
				buf.put_slice(&padding);
				println!("Padding added - any space left?: {:?}", BytesMut::has_remaining_mut(&buf));
				//buf.put(msg);
				//buf.put(&b"LongHeaderByteString"[..]);
			}
		
			//ShortHeader variant
		
			// 0                   1                   2                   3
			// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
			//+-+-+-+-+-+-+-+-+
			//|0|C|K| Type (5)|
			//+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			//|                                                               |
			//+                     [Connection ID (64)]                      +
			//|                                                               |
			//+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			//|                      Packet Number (8/16/32)                ...
			//+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			//|                     Protected Payload (*)                   ...
			//+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			
			Header::ShortHeader{key_phase, connection_id, packet_number, payload} => {
				
				//AVTCORE compliance: connection_flag is 0 for present ConnectionID, 1 for absent - counterintuitive, but necessary for multiplexing compatibility
				let connection_flag_bit = match connection_id {
				    Some(_) => 0b00000000,
				    None => 0b01000000
				};
				
				let key_phase_bit = match key_phase {
				    true => 0b00100000,
				    false => 0b00000000
				};
				
				//AVTCORE compliance: packet types in descending order
				//Last 5 bits - types range from 31 - 29 in current implementation
				let packet_type = match packet_number {
				    PacketNumber::OneOctet(_) => 0x1F,
				    PacketNumber::TwoOctet(_) => 0x1E,
				    PacketNumber::FourOctet(_) => 0x1D,
				};
				
				let initial_octet = 0b01111111 & (connection_flag_bit | key_phase_bit | packet_type);
				
				buf.put_u8(initial_octet);
				
				match connection_id {
				    Some(ConnectionID(num)) => buf.put_u64::<BigEndian>(num),
				    None => {}
				}
				
				match packet_number {
				    PacketNumber::OneOctet(num) => buf.put_u8(num),
				    PacketNumber::TwoOctet(num) => buf.put_u16::<BigEndian>(num),
				    PacketNumber::FourOctet(num) => buf.put_u32::<BigEndian>(num),
				}

				buf.put_slice(&payload);
				//buf.put(msg);
				//buf.put(&b"ShortHeaderByteString"[..]);
			}
		
		}
	
		//Freeze buf to allow it to be used elsewhere
		buf.freeze()
	
	}
	
	//END GENERATE_BYTES METHOD
	//--------------------------------------
	
	
	//PARSE_MESSAGE METHOD
	
	//Reconstruct a Header struct from a Bytes object
	pub fn parse_message(input : Bytes) -> Header{
	    
	    println!("Length of received packet: {}", Bytes::len(&input));
	    
	    let mut input = Bytes::into_buf(input);
	    
	    let initial_octet : u8 = input.get_u8();
        println!("Octet: {}", initial_octet);
	
        //Match the initial, basic information in a received message
        //Use masking to extract the most significant bit in the message (ie. octet 0, bit 0)
        //initial_bit is set to 1 for long header, 0 for short header
        let initial_bit = (0b10000000 & initial_octet) >> 7;
        println!("Bit: {}", initial_bit);

        match initial_bit {
            //Most significant bit is 1 - long header received
            1 => {
                            println!("Long header packet received.");
                            //7 remaining bits are the packet type
                            let packet_marker = 0b01111111 & initial_octet;
                            println!("Packet type: {}", packet_marker);
                            
                            //AVTCORE compliance: packet numbers in range 127-124 (descending)
                            let packet_type = match packet_marker {
                                0x7F => PacketType::Initial,
                                0x7E => PacketType::Retry,
                                0x7D => PacketType::Handshake,
                                0x7C => PacketType::ZeroRTTProtected,
                                _ => panic!("Unrecognised packet type for LongHeader")
                            };
                            
                            //Get Connection ID
                            let connection_id = input.get_u64::<BigEndian>();
                            
                            //Get packet number
                            let packet_number = input.get_u32::<BigEndian>();
                            
                            //Get version
                            let version = input.get_u32::<BigEndian>();
                            
                            //Get payload
                            let payload = bytes::Buf::bytes(&input).to_vec();
                            //println!("Payload as str: {:?}", from_utf8(&payload).unwrap());
                            
                            return Header::LongHeader{
                                packet_type,
                                connection_id,
                                packet_number,
                                version,
                                payload
                            }
                            
                      }
            //Most significant bit is 0 - short header received
            0 => {
                   println!("Short header packet received.");
                   
                   //Connection flag: second most significant bit, shifted right 6 to be 1 or 0
                   //AVTCORE compliance: connection_flag is 0 for present ConnectionID, 1 for absent - counterintuitive, but necessary for multiplexing compatibility
                   let connection_flag = match (0b01000000 & initial_octet) >> 6{
                        0 => true,
                        _ => false
                   };
                   
                   println!("Connection flag: {}", connection_flag);
                   
                   //Key phase: third most significant bit, shifted
                   let key_phase = match (0b00100000 & initial_octet) >> 5{
                        0 => false,
                        _ => true
                   };
                   
                   println!("Key phase: {}", key_phase);
                   
                   //No connection_id if connection_flag = false
                   let connection_id = match connection_flag {
                         true => Some(ConnectionID(input.get_u64::<BigEndian>())),
                         false => None
                   };

                   println!("Connection id: {:?}", connection_id);
                   
                   
                   //Get packet_number
                   //AVTCORE compliance: packet types range from 31-29 (descending)
                   let packet_number = match 0b00011111 & initial_octet {
                        0x1F => PacketNumber::OneOctet(input.get_u8()),
                        0x1E => PacketNumber::TwoOctet(input.get_u16::<BigEndian>()),
                        0x1D => PacketNumber::FourOctet(input.get_u32::<BigEndian>()),
                        _ => panic!("Unrecognised packet number length given.")
                   };
                   
                   println!("Packet number: {:?}", packet_number);
                   
                   //Get payload
                   //let payload = input.bytes().to_vec();
					let payload = bytes::Buf::bytes(&input).to_vec();
                   
                   //println!("Payload as str: {:?}", from_utf8(&payload).unwrap());
                   
                   return Header::ShortHeader{
                        key_phase,
                        connection_id,
                        packet_number,
                        payload
                   }
            }

            //If this happens something has gone terribly wrong...
            _ => panic!("Could not determine header type."),
            
        }
	    
	}
	
	//END PARSE_MESSAGE METHOD
	//--------------------------------------
	
	//START_NEW_CONNECTION METHOD
	//Client sends a ClientInitial type packet to start a new QUIC connection with a server
	pub fn start_new_connection(addr_info : &str, dest_info : &str){
        
        //Write payload as bytes
	    let mut payload_vec : Vec<u8> = Vec::new();
	    payload_vec.write("Initial client packet payload!".as_bytes()).unwrap();
        
        //Initial handshake packets are always LongHeaders
        let client_initial = Header::LongHeader{
		    packet_type : PacketType::Initial,
		    connection_id : 0x00a19d00,
		    packet_number : 0b000001,
		    version : 0b00000001,
		    //Payload is not a fixed size number of bits
		    payload : payload_vec,
	    };
	    
	    //Create SocketAddr
	    let addr_info = SocketAddr::from_str(addr_info).unwrap();
	
	    //Bind socket to given address
	    let socket = UdpSocket::bind(&addr_info).unwrap();
		
	    //Create SocketAddr from supplied addr:port str
	    let dest_info = SocketAddr::from_str(dest_info).unwrap();
        	
        //Send Initial packet to server
        //generate_bytes pads sent packet to 1200 octets according to IETF specification (draft v8)        
	    UdpSocket::send_to(&socket, AsRef::as_ref(&Header::generate_bytes(client_initial)), &dest_info).expect("Couldn't send Initial packet to server.");
	    
	    println!("\nStarting new QUIC connection...\nInitial packet sent.\n");
	    
	    //Set up a [u8] buffer for incoming messages/packets
	    //Size 1200 bytes to match current QUIC specification
	    let mut input_buf = [0; 1200];
	    
	    //Listen for reponse from server
        println!("Listening for response to Initial from server...\n");
        loop {
            match socket.recv_from(&mut input_buf){
                Ok(_) => {  //Convert [u8] into Bytes struct
	                        let input_buf = Bytes::from(&input_buf[..]);
	
	                        //Parse received message
	                        let recv_header = Header::parse_message(input_buf);
	
	                        //Print the raw bytestream
	                        //TODO: uncomment
	                        //println!("recv_header: {:?}", &recv_header);
	                        
	                        //Check that server response is a Handshake packet
	                        match recv_header {
	                            Header::LongHeader{packet_type : PacketType::Handshake, connection_id, packet_number, version, payload} => println!("Response received from server: Handshake.\n"),
	                            _ => println!("Unrecognised response from server.\n"),
	                            
	                        }
	                        break;
	            }
			    Err(_) => continue,
		    }
        }
        
        //Send Handshake packet carrying TLS {Finished} message to server
        //Write payload as bytes
	    let mut payload_vec : Vec<u8> = Vec::new();
	    payload_vec.write(b"TLS Finished message here.");
        
        //Initial handshake packets are always LongHeaders
        //Must be padded to 1200 octets according to IETF specification (draft v8)
        let client_handshake = Header::LongHeader{
		    packet_type : PacketType::Handshake,
		    connection_id : 0x00a19d00,
		    packet_number : 0b000001,
		    version : 0b00000001,
		    //Payload is not a fixed size number of bits
		    payload : payload_vec,
	    };
	    
	    //Send Handshake packet to server
        //generate_bytes pads sent packet to 1200 octets according to IETF specification (draft v8)        
	    UdpSocket::send_to(&socket, AsRef::as_ref(&Header::generate_bytes(client_handshake)), &dest_info).expect("Couldn't send Handshake packet to server.\n");
	    println!("Handshake sent to server.\n");
	    
	    //Listen for reponse from server
        println!("Listening for response to Handshake from server...\n");
        loop {
            match socket.recv_from(&mut input_buf){
                Ok(_) => {  //Convert [u8] into Bytes struct
	                        let input_buf = Bytes::from(&input_buf[..]);
	
	                        //Parse received message
	                        let recv_header = Header::parse_message(input_buf);
	
	                        //Print the raw bytestream
	                        //TODO: uncomment
	                        //println!("recv_header: {:?}", &recv_header);
	                        
	                        //Check that server response is a ZeroRTTProtected packet
	                        match recv_header {
	                            Header::ShortHeader{key_phase, connection_id, packet_number, payload} => println!("Response received from server: 1-RTT ShortHeader.\n"),
	                            _ => println!("Unrecognised response from server.\n"),
	                            
	                        }
	                        break;
	            }
			    Err(_) => continue,
		    }
        }
        
        //Send 3 1-RTT ShortHeader packets for testing
        for i in 0..3{
            //Write payload as bytes
	        let mut payload_vec : Vec<u8> = Vec::new();
	        payload_vec.write(b"(Application-relevant data here)");
            
            //Initial handshake packets are always LongHeaders
            //Must be padded to 1200 octets according to IETF specification (draft v8)
            let client_short = Header::ShortHeader{
		        key_phase : true,
		        connection_id : Some(ConnectionID(0x00a19d00)),
		        packet_number : PacketNumber::TwoOctet(0x000011a0),
		        //Payload is not a fixed size number of bits
		        payload : payload_vec,
	        };
	        
	        //Send Handshake packet to server
            //generate_bytes pads sent packet to 1200 octets according to IETF specification (draft v8)        
	        UdpSocket::send_to(&socket, AsRef::as_ref(&Header::generate_bytes(client_short)), &dest_info).expect("Couldn't send 1-RTT ShortHeader packet to server.\n");
	        println!("1-RTT ShortHeader sent to server.\n");
	        
	        //Listen for reponse from server
            println!("Listening for response to 1-RTT ShortHeader from server...\n");
            loop {
                match socket.recv_from(&mut input_buf){
                    Ok(_) => {  //Convert [u8] into Bytes struct
	                            let input_buf = Bytes::from(&input_buf[..]);
	
	                            //Parse received message
	                            let recv_header = Header::parse_message(input_buf);
	
	                            //Print the raw bytestream
	                            //TODO: uncomment
	                            //println!("recv_header: {:?}", &recv_header);
	                            
	                            //Check that server response is a ShortHeader packet with key_phase 1
	                            match recv_header {
	                                Header::ShortHeader{key_phase: true, connection_id, packet_number, payload} => println!("Response received from server: ShortHeader.\n"),
	                                _ => println!("Unrecognised response from server.\n"),
	                                
	                            }
	                            break;
	                }
			        Err(_) => continue,
		        }
            }
        };
        
        println!("Connection process complete.\n");
        
	}

    //END START_NEW_CONNECTION METHOD
	//--------------------------------------
	
	
	//IS_NEW_CONNECTION METHOD
	
	pub fn is_new_connection(&self) -> bool{
	    match self {
	        &Header::LongHeader{ref packet_type, ref connection_id, ref packet_number, ref version, ref payload} => {        
                match packet_type { 
	                &PacketType::Initial => {println!("Initial received - potential new connection detected."); return true;},
	                &PacketType::Handshake => {println!("Handshake received - not a new connection."); return false;},
	                _ => {println!("Nothing of interest received."); return false;},
	                }
	        }
	        _ => return false,
	        
	    }
	}
	
	//END IS_NEW_CONNECTION METHOD
	//--------------------------------------
	
	//IS_COMPATIBLE_VERSION METHOD
	
	pub fn is_compatible_version(&self) -> bool{
	    match self {
	        &Header::LongHeader{ref packet_type, ref connection_id, ref packet_number, ref version, ref payload} => {        
	            match version { 
	                &0b00000001 => {println!("Compatible version detected: {:?}\n", &version); return true;},
	                _ => {println!("Incompatible version detected: {:?}\n", version); return false;},
	            }
	        }
	        _ => return false,
	        
	    }
	}
	
	//END IS_COMPATIBLE_VERSION METHOD
	//--------------------------------------
    
}








