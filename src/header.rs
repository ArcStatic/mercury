use bytes::{Bytes, BytesMut, Buf, BufMut, IntoBuf, BigEndian};
use std::str::from_utf8;

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

	//Return a Bytes object 
	pub fn generate_bytes(self) -> Bytes{

		let mut buf = BytesMut::with_capacity(1024);
	
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
			    match packet_type {
			        PacketType::VersionNegotiation => buf.put_u8(128 + 0x01),
                    PacketType::ClientInitial => buf.put_u8(128 + 0x02),
                    PacketType::ServerStatelessRetry => buf.put_u8(128 + 0x03),
                    PacketType::ServerCleartext => buf.put_u8(128 + 0x04),
                    PacketType::ClientCleartext => buf.put_u8(128 + 0x05),
                    PacketType::ZeroRTTProtected => buf.put_u8(128 + 0x06)
			    }

				buf.put_u64::<BigEndian>(connection_id);
				buf.put_u32::<BigEndian>(packet_number);
				buf.put_u32::<BigEndian>(version);
				buf.put_slice(&payload);
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
				
				let connection_flag_bit = match connection_id {
				    Some(_) => 0b01000000,
				    None => 0b00000000
				};
				
				let key_phase_bit = match key_phase {
				    true => 0b00100000,
				    false => 0b00000000
				};
				
				let packet_type = match packet_number {
				    PacketNumber::OneOctet(_) => 0x01,
				    PacketNumber::TwoOctet(_) => 0x02,
				    PacketNumber::FourOctet(_) => 0x03,
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
	
	
	//Parse the content of received messages and return a LongHeader or ShortHeader
	pub fn parse_message(input : Bytes) -> Header{
	
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
                            let packet_type = match packet_marker {
                                0x01 => PacketType::VersionNegotiation,
                                0x02 => PacketType::ClientInitial,
                                0x03 => PacketType::ServerStatelessRetry,
                                0x04 => PacketType::ServerCleartext,
                                0x05 => PacketType::ClientCleartext,
                                0x06 => PacketType::ZeroRTTProtected,
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
                            println!("Payload as str: {:?}", from_utf8(&payload).unwrap());
                            
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
                   
                   //TODO: improve this, seems inefficient
                   //Connection flag: second most significant bit, shifted right 6 to be 1 or 0
                   let connection_flag = match (0b01000000 & initial_octet) >> 6{
                        0 => false,
                        _ => true
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
                   let packet_number = match 0b00011111 & initial_octet {
                        0x01 => PacketNumber::OneOctet(input.get_u8()),
                        0x02 => PacketNumber::TwoOctet(input.get_u16::<BigEndian>()),
                        0x03 => PacketNumber::FourOctet(input.get_u32::<BigEndian>()),
                        _ => panic!("Unrecognised packet number length given.")
                   };
                   
                   println!("Packet number: {:?}", packet_number);
                   
                   //Get payload
                   let payload = input.bytes().to_vec();
                   
                   println!("Payload as str: {:?}", from_utf8(&payload).unwrap());
                   
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
	

}






