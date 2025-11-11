use byteorder::{BigEndian, ReadBytesExt};
/// STUN packet parser for extracting ICE username from STUN packets
/// Based on RFC 5389: https://tools.ietf.org/html/rfc5389
use std::io::Cursor;

/// STUN message types
#[allow(dead_code)]
pub const BINDING_REQUEST: u16 = 0x0001;
#[allow(dead_code)]
pub const BINDING_RESPONSE: u16 = 0x0101;

/// STUN attribute types
pub const USERNAME: u16 = 0x0006;

/// STUN magic cookie (RFC 5389)
#[allow(dead_code)]
pub const STUN_MAGIC_COOKIE: u32 = 0x2112A442;

/// Parsed STUN packet
#[derive(Debug, Clone)]
pub struct StunPacket {
    pub message_type: u16,
    pub username: Option<String>,
}

impl StunPacket {
    /// Parse a STUN packet from raw bytes
    ///
    /// STUN packet format:
    /// ```
    /// 0                   1                   2                   3
    /// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |0 0|     STUN Message Type     |         Message Length        |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |                         Magic Cookie                          |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |                                                               |
    /// |                     Transaction ID (96 bits)                  |
    /// |                                                               |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |                         Attributes                            |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// ```
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        if data.len() < 20 {
            return Err(format!("STUN packet too short: {} bytes", data.len()));
        }

        let mut cursor = Cursor::new(data);

        // Read STUN header (20 bytes)
        let message_type = cursor
            .read_u16::<BigEndian>()
            .map_err(|e| format!("Failed to read message type: {}", e))?;

        let message_len = cursor
            .read_u16::<BigEndian>()
            .map_err(|e| format!("Failed to read message length: {}", e))?;

        // Skip magic cookie (4 bytes)
        cursor.set_position(cursor.position() + 4);

        // Skip transaction ID (12 bytes)
        cursor.set_position(cursor.position() + 12);

        // Verify packet length
        if data.len() != 20 + message_len as usize {
            return Err(format!(
                "Invalid STUN packet length: expected {}, got {}",
                20 + message_len,
                data.len()
            ));
        }

        let mut username = None;

        // Parse attributes
        while cursor.position() < data.len() as u64 {
            if (data.len() as u64 - cursor.position()) < 4 {
                break;
            }

            let attr_type = cursor
                .read_u16::<BigEndian>()
                .map_err(|e| format!("Failed to read attribute type: {}", e))?;

            let attr_len = cursor
                .read_u16::<BigEndian>()
                .map_err(|e| format!("Failed to read attribute length: {}", e))?;

            if (data.len() as u64 - cursor.position()) < attr_len as u64 {
                return Err(format!(
                    "Attribute length {} exceeds remaining data",
                    attr_len
                ));
            }

            // Read attribute value
            let pos = cursor.position() as usize;
            let attr_value = &data[pos..pos + attr_len as usize];
            cursor.set_position(cursor.position() + attr_len as u64);

            // Handle padding (attributes are padded to 4-byte boundary)
            let padding = (4 - (attr_len % 4)) % 4;
            cursor.set_position(cursor.position() + padding as u64);

            // Parse USERNAME attribute
            if attr_type == USERNAME {
                if let Ok(username_str) = String::from_utf8(attr_value.to_vec()) {
                    username = Some(username_str.clone());
                }
            }
        }

        Ok(StunPacket {
            message_type,
            username,
        })
    }

    /// Get the full username (local_ufrag:remote_ufrag)
    pub fn get_username(&self) -> Option<&str> {
        self.username.as_deref()
    }
}
