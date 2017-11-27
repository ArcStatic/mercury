use bytes::{Bytes, BytesMut, Buf, BufMut, IntoBuf, BigEndian};

use mio::net::UdpSocket;

use std::str::from_utf8;
use std::net::SocketAddr;
use std::str::FromStr;
use std::io::Write;
use std::convert::AsRef;


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
    VersionNegotiation,
    ClientInitial,
    ServerStatelessRetry,
    ServerCleartext,
    ClientCleartext,
    ZeroRTTProtected,
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
		//connection_id is nonzero only if the bit for connection ID flag is set to 1
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
			        PacketType::VersionNegotiation => buf.put_u8(128 + 0x7F),
                    PacketType::ClientInitial => buf.put_u8(128 + 0x7E),
                    PacketType::ServerStatelessRetry => buf.put_u8(128 + 0x7D),
                    PacketType::ServerCleartext => buf.put_u8(128 + 0x7C),
                    PacketType::ClientCleartext => buf.put_u8(128 + 0x7B),
                    PacketType::ZeroRTTProtected => buf.put_u8(128 + 0x7A)
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
				//Last 5 bits - types range from 16 - 14 in current implementation
				let packet_type = match packet_number {
				    PacketNumber::OneOctet(_) => 0x10,
				    PacketNumber::TwoOctet(_) => 0xF,
				    PacketNumber::FourOctet(_) => 0xE,
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
                            
                            //AVTCORE compliance: packet numbers in range 127-122 (descending)
                            let packet_type = match packet_marker {
                                0x7F => PacketType::VersionNegotiation,
                                0x7E => PacketType::ClientInitial,
                                0x7D => PacketType::ServerStatelessRetry,
                                0x7C => PacketType::ServerCleartext,
                                0x7B => PacketType::ClientCleartext,
                                0x7A => PacketType::ZeroRTTProtected,
                                _ => panic!("Unrecognised packet type for LongHeader")
                            };
                            
                            //Get Connection ID
                            let connection_id = input.get_u64::<BigEndian>();
                            
                            //Get packet number
                            let packet_number = input.get_u32::<BigEndian>();
                            
                            //Get version
                            let version = input.get_u32::<BigEndian>();
                            
                            //Get payload
                            let payload = input.bytes().to_vec();
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
                   
                   /*
                   //5 remaining bits are packet type
                   let packet_type = match 0b00011111 & initial_octet {
                        0x01 => PacketType::PacketNumber,
                        0x02 => PacketType::PacketNumber,
                        0x03 => PacketType::PacketNumber,
                        _ => panic!("Unrecognised packet type for ShortHeader")
                   };
                   
                   println!("Packet type: {:?}", packet_type);
                   */
                   
                   //Get packet_number
                   //AVTCORE compliance: packet types range from 16-14 (descending)
                   let packet_number = match 0b00011111 & initial_octet {
                        0x10 => PacketNumber::OneOctet(input.get_u8()),
                        0xF => PacketNumber::TwoOctet(input.get_u16::<BigEndian>()),
                        0xE => PacketNumber::FourOctet(input.get_u32::<BigEndian>()),
                        _ => panic!("Unrecognised packet number length given.")
                   };
                   
                   println!("Packet number: {:?}", packet_number);
                   
                   //Get payload
                   let payload = input.bytes().to_vec();
                   
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
        //Must be padded to 1200 octets according to IETF specification (draft v7)
        let client_initial = Header::LongHeader{
		    packet_type : PacketType::ClientInitial,
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
        	
        //Send ClientInitial packet to server        
	    UdpSocket::send_to(&socket, AsRef::as_ref(&Header::generate_bytes(client_initial)), &dest_info).expect("Couldn't send message.");
	}

    //END START_NEW_CONNECTION METHOD
	//--------------------------------------
	
	
	//IS_NEW_CONNECTION METHOD
	
	pub fn is_new_connection(&self) -> bool{
	    match self {
	        &Header::LongHeader{ref packet_type, ref connection_id, ref packet_number, ref version, ref payload} => {        match packet_type { 
	            &PacketType::ClientInitial => {println!("ClientInitial received - potential new connection detected."); return true;},
	            _ => return false,
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
	        &Header::LongHeader{ref packet_type, ref connection_id, ref packet_number, ref version, ref payload} => {        match version { 
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






