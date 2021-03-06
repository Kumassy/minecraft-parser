use bytes::Buf;
use std::str;
use thiserror::Error;

const VARINT_MAX_BYTES: usize = 5;

#[derive(Error, Debug, PartialEq)]
pub enum MinecraftParseError {
    #[error("VarInt is corrupted")]
    InvalidVarInt,
    #[error("u_short is corrupted")]
    InvalidUShort,
    #[error("Byte-encoded string is corrupted")]
    InvalidStringEncoding(#[from] str::Utf8Error),
    #[error("Byte-encoded string length is not sufficient")]
    StringTooShort,
    #[error("Packet length does not match its actual payload")]
    LengthNotMatch,
    #[error("This packet is not for handshaking")]
    NotHandshake,
}


#[derive(Debug, PartialEq)]
pub struct Handshake {
    protocol_version: i32,
    address: String,
    port: u16,
    next_state: i32,
}

fn parse_ushort(buf: &mut dyn Buf) -> Result<u16, MinecraftParseError> {
    if buf.remaining() < 2 {
        return Err(MinecraftParseError::InvalidUShort);
    }
    let val = buf.get_u16();
    Ok(val)
}

fn parse_varint(buf: &mut dyn Buf) -> Result<i32, MinecraftParseError> {
    let mut v: i32 = 0;
    let mut bit_place: usize = 0;
    let mut i: usize = 0;
    let mut has_more = true;

    while has_more {
        if i == VARINT_MAX_BYTES || buf.remaining() < 1 {
            return Err(MinecraftParseError::InvalidVarInt)
        }
        let byte = buf.get_u8();
        
        has_more = byte & 0x80 != 0;
        v |= ((byte as i32) & 0x7F) << bit_place;
        bit_place += 7;
        i += 1;
    }

    Ok(v)
}

fn parse_string_n(buf: &mut dyn Buf) -> Result<String, MinecraftParseError> {
    let len = parse_varint(buf)? as usize;

    if buf.remaining() < len {
        return Err(MinecraftParseError::StringTooShort);
    }

    let bytes = buf.copy_to_bytes(len);
    let val: String = str::from_utf8(&bytes)?.to_string();
    Ok(val)
}

pub fn parse_handshake(buf: &mut dyn Buf) -> Result<Handshake, MinecraftParseError> {
    let len = parse_varint(buf)?;
    if buf.remaining() != len as usize {
        return Err(MinecraftParseError::LengthNotMatch);
    }

    let id = parse_varint(buf)?;
    if id != 0x00 {
        return Err(MinecraftParseError::NotHandshake);
    }

    let version = parse_varint(buf)?;
    let address = parse_string_n(buf)?;
    let port = parse_ushort(buf)?;
    let next_state = parse_varint(buf)?;

    let handshake = Handshake {
        protocol_version: version,
        address,
        port,
        next_state
    };

    Ok(handshake)
}


#[cfg(test)]
mod tests {
    mod parse_varint {
        use crate::*;

        #[test]
        fn parse_1_byte_positive_value() {
            let mut buf = &b"\x16"[..];
            let val = parse_varint(&mut buf).unwrap();
            assert_eq!(val, 22);
        }
        #[test]
        fn parse_0() {
            let mut buf = &b"\x00"[..];
            let val = parse_varint(&mut buf).unwrap();
            assert_eq!(val, 0);
        }

        #[test]
        fn parse_754() {
            let mut buf = &b"\xf2\x05"[..];
            let val = parse_varint(&mut buf).unwrap();
            assert_eq!(val, 754);
        }

        #[test]
        fn reject_empty_packet() {
            let mut buf = &b""[..];
            let val = parse_handshake(&mut buf).err().unwrap();
            assert!(matches!(val, MinecraftParseError::InvalidVarInt));
        }

        #[test]
        fn reject_not_terminated_packet() {
            let mut buf = &b"\xd7"[..];
            let val = parse_handshake(&mut buf).err().unwrap();
            assert!(matches!(val, MinecraftParseError::InvalidVarInt));
        }
        #[test]
        fn reject_too_long_num() {
            let mut buf = &b"\xf3\xf3\xf3\xf3\xf3\x05"[..];
            let val = parse_varint(&mut buf).err().unwrap();
            assert!(matches!(val, MinecraftParseError::InvalidVarInt));
        }
    }

    mod parse_ushort {
        use crate::*;

        #[test]
        fn parse_25565() {
            let mut buf = &b"\x63\xdd"[..];
            let val = parse_ushort(&mut buf).unwrap();
            assert_eq!(val, 25565);
        }

        #[test]
        fn reject_1_byte() {
            let mut buf = &b"\x63"[..];
            let val = parse_ushort(&mut buf).err().unwrap();
            assert_eq!(val, MinecraftParseError::InvalidUShort);
        }

        #[test]
        fn reject_empty() {
            let mut buf = &b""[..];
            let val = parse_ushort(&mut buf).err().unwrap();
            assert_eq!(val, MinecraftParseError::InvalidUShort);
        }
    }

    mod parse_string_n {
        use crate::*;

        #[test]
        fn parse_string() {
            let mut buf = &b"\x0c\x31\x32\x33\x2e\x34\x35\x2e\x36\x37\x2e\x38\x39"[..];
            let val = parse_string_n(&mut buf).unwrap();
            assert_eq!(val, "123.45.67.89".to_string());
        }
        
        #[test]
        fn reject_invalid_string() {
            let mut buf = &b"\x0f\xf1\x36\x30\x2e\x32\x35\x31\x2e\x31\x30\x30\x2e\x32\x34\x39"[..];
            let val = parse_string_n(&mut buf).err().unwrap();
            assert!(matches!(val, MinecraftParseError::InvalidStringEncoding(_)));
        }
        
        #[test]
        fn reject_short_string() {
            let mut buf = &b"\x03\x31\x36"[..];
            let val = parse_string_n(&mut buf).err().unwrap();
            assert!(matches!(val, MinecraftParseError::StringTooShort));
        }

        #[test]
        fn reject_empty() {
            let mut buf = &b""[..];
            let val = parse_string_n(&mut buf).err().unwrap();
            assert!(matches!(val, MinecraftParseError::InvalidVarInt));
        }
    }

    mod parse_handshake {
        use crate::*;

        #[test]
        fn parse_good_packet() {
            let mut buf = &b"\x13\x00\xf2\x05\x0c\x31\x32\x33\x2e\x34\x35\x2e\x36\x37\x2e\x38\x39\x63\xdd\x02"[..];
            let val = parse_handshake(&mut buf).unwrap();
            assert_eq!(val, Handshake {
                protocol_version: 754,
                address: "123.45.67.89".to_string(),
                port: 25565,
                next_state: 2,
            });
        }
    }
}