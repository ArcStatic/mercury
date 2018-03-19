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


/// Buffer for holding connection-specific TLS messages
pub struct ConnectionBuffer{
	pub buf : [u8;10000],
	pub offset : usize
}


impl fmt::Debug for ConnectionBuffer{
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		write!(f, "{:?}", &self.buf[0..self.offset])
	}
}

/// Socket which can hold client or server address info (ie. SocketAddr of intended recipient)
pub struct QuicSocket {
    pub sock : UdpSocket,
    pub addr : SocketAddr,
}

/// Calls recv_from on UDP socket
impl Read for QuicSocket {
    fn read (&mut self, mut output : &mut [u8]) -> Result<usize, Error> {
		let res = UdpSocket::recv_from(&mut self.sock, output)?;
		Ok(res.0)
    }
}

/// Calls send_to on UDP socket
///
/// Implemented as write trait to mimic writing to a stream
impl Write for QuicSocket {
    fn write(&mut self, input : &[u8]) -> Result<usize, Error>{
        UdpSocket::send_to(&mut self.sock, input, &self.addr)?;
        Ok(input.len())
    }

    //TODO: find fix for this - problems with infinite recursion
    fn flush(&mut self) -> Result<(), Error>{
        &mut self.flush()?;
        Ok(())
    }
}


#[derive(Debug, PartialEq)]
/// ID to keep track of clients
pub struct ConnectionID(pub u64);

#[derive(Debug, PartialEq)]
/// How many octets are being used for the packet number section of a ShortHeader packet and the associated value
pub enum PacketNumber{
    OneOctet(u8),
    TwoOctet(u16),
    FourOctet(u32)
}

#[derive(Debug)]
/// How many octets are being used for the packet number section of a ShortHeader packet - only a description, no associated value
pub enum PacketTypeShort{
	OneOctet,
	TwoOctet,
	FourOctet
}

#[derive(Debug, PartialEq)]
/// Type of LongHeader packet
pub enum PacketTypeLong {
    Initial,
    Retry,
    Handshake,
    ZeroRTTProtected,
}

#[derive(Debug)]
/// Two Header types which can be sent
pub enum HeaderType {
	LongHeader,
	ShortHeader
}

#[derive(Debug, PartialEq)]
/// Format of messages which will be sent between client and server
pub enum Header {
	
	LongHeader {
		packet_type : PacketTypeLong,
		connection_id : u64,
		packet_number : u32,
		version : u32,
		//Payload is not a fixed size number of bits
		payload : Vec<u8>,
	},

	ShortHeader {
		key_phase : u8,
		//connection_id is present only if the bit for connection ID flag is set to 0
		connection_id : Option<ConnectionID>,
		packet_number : PacketNumber,
		//Payload is not a fixed size number of bits
		payload : Vec<u8>,
	}

}


impl Header {
    
	///Return a representation of Header as Bytes
	pub fn encode(self) -> Bytes {
	
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

				//Packet capacity will need to be larger for TLS handshake messages
				//Not subject to 1200 octet limit like packets carrying application data
				let mut buf = match packet_type {
					PacketTypeLong::Handshake => BytesMut::with_capacity(7000),
					_ => BytesMut::with_capacity(1200)
				};

			    //128 added to all values to mark this as a long header
			    //AVTCORE compliance: packet numbers in range 127-122 (descending)
				//NOTE: quic-transport draft 08 has a typo in packet type values - values used here are correct
			    match packet_type {
			        PacketTypeLong::Initial => buf.put_u8(128 + 0x7F),
                    PacketTypeLong::Retry => buf.put_u8(128 + 0x7E),
                    PacketTypeLong::Handshake => buf.put_u8(128 + 0x7D),
                    PacketTypeLong::ZeroRTTProtected => buf.put_u8(128 + 0x7C)
			    }

				buf.put_u64::<BigEndian>(connection_id);
				buf.put_u32::<BigEndian>(packet_number);
				buf.put_u32::<BigEndian>(version);
				buf.put_slice(&payload);
				println!("Length of packet: {}", BytesMut::len(&buf));
				println!("Capacity of packet: {}", BytesMut::capacity(&buf));
				println!("Remaining capacity of packet: {}", BytesMut::remaining_mut(&buf));
				
				//println!("{:?}", buf);

				//All non-Handshake and non-initial LongHeader packets must be padded to 1200 octets minimum according to IETF QUIC document v7
				/*
				if packet_type != PacketTypeLong::Initial && packet_type != PacketTypeLong::Handshake {
					let padding = vec![0; BytesMut::remaining_mut(&buf)];
					//Can't use array - complains about non-constant value being supplied
					//let padding = [0; BytesMut::remaining_mut(&buf)];

					buf.put_slice(&padding);
					println!("Padding added - any space left?: {:?}", BytesMut::has_remaining_mut(&buf));
				}
				*/

				//Freeze buf to allow it to be used elsewhere
				buf.freeze()
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

				//Packet size limited to 1200 for v7 quic-transport spec
				let mut buf = BytesMut::with_capacity(1200);

				//AVTCORE compliance: connection_flag is 0 for present ConnectionID, 1 for absent
				//counterintuitive, but necessary for multiplexing compatibility
				let connection_flag_bit = match connection_id {
				    Some(_) => 0b00000000,
				    None => 0b01000000
				};
				
				let key_phase_bit = match key_phase {
				    1 => 0b00100000,
				    _ => 0b00000000
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

				//Freeze buf to allow it to be used elsewhere
				buf.freeze()
			}

		
		}
	
		//Freeze buf to allow it to be used elsewhere
		//buf.freeze()
	
	}


	///DEPRECATED: NO LONGER USED
	pub fn is_new_connection(&self) -> bool{
	    match self {
	        &Header::LongHeader{ref packet_type, ref connection_id, ref packet_number, ref version, ref payload} => {        
                match packet_type { 
	                &PacketTypeLong::Initial => {println!("Initial received - potential new connection detected."); return true;},
	                &PacketTypeLong::Handshake => {println!("Handshake received - not a new connection."); return false;},
	                _ => {println!("Nothing of interest received."); return false;},
	                }
	        }
	        _ => return false,
	        
	    }
	}



	/// DEPRECATED: DO NOT USE
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


	/// Obtain a Header's packet number, if it is present
	pub fn get_conn_id(&self) -> Option<u64> {
		let conn_id = match self {
			&Header::LongHeader {ref packet_type, ref connection_id, ref packet_number, ref version, ref payload} => Some(*connection_id),
			&Header::ShortHeader {ref key_phase, ref connection_id, ref packet_number, ref payload} => match connection_id {
				&Some(ConnectionID(id)) => Some(id),
				&None => None
			}
		};
		conn_id
	}

	/// Obtain a Header's packet number
	///
	/// Note that OneOctet(u8) and TwoOctet(u16) packet numbers will be cast to u32
	pub fn get_packet_number(&self) -> u32 {
		let packet_number = match self {
			&Header::LongHeader {ref packet_type, ref connection_id, ref packet_number, ref version, ref payload} => *packet_number,
			&Header::ShortHeader {ref key_phase, ref connection_id, ref packet_number, ref payload} => match packet_number {
				&PacketNumber::OneOctet(num) => num as u32,
				&PacketNumber::TwoOctet(num) => num as u32,
				&PacketNumber::FourOctet(num) => num
			}
		};
		packet_number
	}

	/// Obtain a Header's version number, if present
	///
	/// Will always return None for ShortHeader variants
	pub fn get_version(&self) -> Option<u32> {
		let version = match self {
			&Header::LongHeader {ref packet_type, ref connection_id, ref packet_number, ref version, ref payload} => Some(*version),
			&Header::ShortHeader {ref key_phase, ref connection_id, ref packet_number, ref payload} => None
		};
		version
	}

	/// Obtain an immutable reference to a Header's payload - payload data should not be modified within the struct, only read by other functions
	pub fn get_payload(&self) -> &Vec<u8> {
		let payload = match self {
			&Header::LongHeader {ref packet_type, ref connection_id, ref packet_number, ref version, ref payload} => payload,
			&Header::ShortHeader {ref key_phase, ref connection_id, ref packet_number, ref payload} => payload
		};
		payload
	}
    
}

///Reconstruct a Header from Bytes
pub fn decode(input : Bytes) -> Header{

	println!("Length of received packet: {}", Bytes::len(&input));
	//Change this to vec?
	let mut input = Bytes::into_buf(input);

	let initial_octet = input.get_u8();

	//Determine which packet type has been received
	//First bit is 0 for ShortHeader
	if ((0b10000000 & initial_octet) >> 7) == 0 {
		//Get connection_omit, key_phase, and PacketTypeShort info
		let packet_info = get_short_info(initial_octet).unwrap();
		//Parse Connection ID if present
		let connection_id = match connection_id_present(packet_info.0) {
			true => Some(ConnectionID(input.get_u64::<BigEndian>())),
			false => None
		};

		//Parse packet number
		let packet_number = match packet_info.2 {
			PacketTypeShort::OneOctet => PacketNumber::OneOctet(input.get_u8()),
			PacketTypeShort::TwoOctet => PacketNumber::TwoOctet(input.get_u16::<BigEndian>()),
			PacketTypeShort::FourOctet => PacketNumber::FourOctet(input.get_u32::<BigEndian>()),
		};

		//Retrieve payload from the rest of the packet
		let payload = bytes::Buf::bytes(&input).to_vec();

		Header::ShortHeader {
			key_phase : packet_info.1,
			connection_id,
			packet_number,
			payload,
		}

		//First bit is 1 for LongHeader
	} else {
		let packet_type = get_long_info(initial_octet).unwrap();
		let connection_id = input.get_u64::<BigEndian>();
		let packet_number = input.get_u32::<BigEndian>();
		let version = input.get_u32::<BigEndian>();
		let payload = bytes::Buf::bytes(&input).to_vec();

		Header::LongHeader{
			packet_type,
			connection_id,
			packet_number,
			version,
			payload
		}
	}

}

/// Parse info from first octet of LongHeader - currently this only consists of PacketTypeLong
///
/// Will return an error if packet type is not recognised
pub fn get_long_info(input : u8) -> Result<PacketTypeLong, &'static str> {
	//LongHeader always has initial bit set to 1 (ie. value of input is 128 + value of packet type)
	match input & 0b01111111 {
		0x7F => return Ok(PacketTypeLong::Initial),
		0x7E => return Ok(PacketTypeLong::Retry),
		0x7D => return Ok(PacketTypeLong::Handshake),
		0x7C => return Ok(PacketTypeLong::ZeroRTTProtected),

		_ => return Err("Unrecognised packet type for LongHeader"),

	};
}



/// Get information for ShortHeader packet
///
/// Returns a tuple detailing if connection_ID is omitted, which key phase is being used, and PacketTypeShort being used (ie. how many octets will be read for the packet number)
pub fn get_short_info(input : u8) -> Result<(bool, u8, PacketTypeShort), &'static str> {
	//Second bit of first octet determines if ConnectionID is omitted or not
	let connection_omit = match (input & 0b01000000) >> 6 {
		0 => false,
		_ => true
	};

	//Third bit of first octet determines which key phase is being used
	let key_phase = (input & 0b00100000) >> 5;

	//Final five bits of first octet determines how many octets will be used for the packet number
	let packet_type = match input & 0b00011111 {
		0x1F => PacketTypeShort::OneOctet,
		0x1E => PacketTypeShort::TwoOctet,
		0x1D => PacketTypeShort::FourOctet,
		_ => return Err("Unrecognised packet type for ShortHeader.")
	};

	Ok((connection_omit, key_phase, packet_type))
}

//ConnectionID flag is confusing - created two functions to give a straightforward answer
/// Used for getting a straightforward answer to whether a Connection ID is present
///
/// get_short_info returns a bool signalling if Connection ID is omitted - this function just inverts it
pub fn connection_id_present(flag : bool) -> bool {
	match flag {
		true => false,
		false => true
	}
}

/// This function is primarily for readability - returns the bool given for connection_omit by get_short_info
pub fn connection_id_omitted(flag : bool) -> bool {
	flag
}






