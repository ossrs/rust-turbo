use serde::{Deserialize, Serialize};
use std::error::Error;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};

// SRS RTC Private TCP port for cascading
pub const SRS_RTC_PRIVATE_TCP_PORT: u16 = 9999;

/// JSON signaling message types
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
#[serde(rename_all = "lowercase")]
enum SignalingMessage {
    Publish { stream: String, sdp: String },
    Play { stream: String, sdp: String },
}

/// JSON response from SRS
#[derive(Debug, Serialize, Deserialize)]
struct SignalingResponse {
    code: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    session: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sdp: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    details: Option<String>,
}

/// WebRTC Private TCP client for publishing to SRS
/// The stream is split into read and write halves to avoid deadlocks
pub struct PrivateTcpClient {
    read_half: Option<OwnedReadHalf>,
    write_half: Option<OwnedWriteHalf>,
    session_id: Option<String>,
}

impl PrivateTcpClient {
    /// Create a new Private TCP client
    pub fn new() -> Self {
        Self {
            read_half: None,
            write_half: None,
            session_id: None,
        }
    }

    /// Connect to SRS Private TCP port
    pub async fn connect(&mut self, host: &str) -> Result<(), Box<dyn Error>> {
        let addr = format!("{}:{}", host, SRS_RTC_PRIVATE_TCP_PORT);
        println!("Connecting to SRS Private TCP at {}", addr);

        let stream = TcpStream::connect(&addr).await?;
        println!("Connected to SRS Private TCP");

        // Split the stream into read and write halves
        let (read_half, write_half) = stream.into_split();
        self.read_half = Some(read_half);
        self.write_half = Some(write_half);
        Ok(())
    }

    /// Start a coroutine to read packets from the Private TCP connection
    /// and send them to the client via UDP.
    ///
    /// This coroutine runs in the background and forwards all packets received
    /// from SRS (STUN responses, DTLS, RTP, RTCP) to the client's UDP address.
    ///
    /// # Arguments
    /// * `udp_socket` - The shared UDP socket to send packets through
    /// * `session_manager` - The session manager to look up the UDP address
    /// * `session_key` - The session key for looking up UDP address
    pub fn start_reader_coroutine(
        &mut self,
        udp_socket: Arc<tokio::net::UdpSocket>,
        session_manager: crate::session_manager::SessionManager,
        session_key: String,
    ) {
        // Take ownership of the read half
        let Some(mut read_half) = self.read_half.take() else {
            eprintln!(
                "Warning: No read half available for session {}",
                session_key
            );
            return;
        };

        tokio::spawn(async move {
            use tokio::io::AsyncReadExt;

            println!("Started reader coroutine for session: {}", session_key);

            loop {
                // Read 2-byte length prefix (big-endian)
                let length = match read_half.read_u16().await {
                    Ok(len) => len,
                    Err(e) => {
                        eprintln!(
                            "Error reading length from SRS for session {}: {}",
                            session_key, e
                        );
                        break;
                    }
                };

                // Read packet data
                let mut packet = vec![0u8; length as usize];
                if let Err(e) = read_half.read_exact(&mut packet).await {
                    eprintln!(
                        "Error reading packet from SRS for session {}: {}",
                        session_key, e
                    );
                    break;
                }

                println!(
                    "Received packet from SRS for session {}: {} bytes",
                    session_key,
                    packet.len()
                );

                // Get the UDP address from the session
                let udp_addr = session_manager.get_udp_address(&session_key).await;

                if let Some(addr) = udp_addr {
                    // Send packet to client via UDP
                    match udp_socket.send_to(&packet, addr).await {
                        Ok(sent) => {
                            println!("Sent {} bytes to client at {}", sent, addr);
                        }
                        Err(e) => {
                            eprintln!("Error sending packet to client {}: {}", addr, e);
                        }
                    }
                } else {
                    println!(
                        "Warning: No UDP address for session {}, packet dropped",
                        session_key
                    );
                }
            }

            println!("Reader coroutine ended for session: {}", session_key);
        });
    }

    /// Send a framed packet using RFC 4571 framing (2-byte length prefix)
    async fn send_framed_packet(&mut self, data: &[u8]) -> Result<(), Box<dyn Error>> {
        let write_half = self.write_half.as_mut().ok_or("Not connected to SRS")?;

        // Check packet size limit (max 65535 bytes)
        if data.len() > 65535 {
            return Err("Packet too large (max 65535 bytes)".into());
        }

        // Write 2-byte length prefix (big-endian)
        let length = data.len() as u16;
        write_half.write_u16(length).await?;

        // Write packet data
        write_half.write_all(data).await?;
        write_half.flush().await?;

        println!(
            "Sent framed packet: {} bytes (length prefix: {})",
            data.len(),
            length
        );

        Ok(())
    }

    /// Send JSON signaling message
    async fn send_json_message(
        &mut self,
        message: &SignalingMessage,
    ) -> Result<(), Box<dyn Error>> {
        let json_str = serde_json::to_string(message)?;
        println!("Sending JSON signaling: {}", json_str);

        self.send_framed_packet(json_str.as_bytes()).await?;

        Ok(())
    }

    /// Receive JSON signaling response
    async fn recv_json_response(&mut self) -> Result<SignalingResponse, Box<dyn Error>> {
        let read_half = self.read_half.as_mut().ok_or("Not connected to SRS")?;

        // Read 2-byte length prefix (big-endian)
        let length = read_half.read_u16().await?;
        println!("Receiving framed packet: {} bytes", length);

        // Read packet data
        let mut data = vec![0u8; length as usize];
        read_half.read_exact(&mut data).await?;

        println!("Received framed packet: {} bytes", data.len());

        // Check if this is a JSON packet (starts with '{')
        if data.is_empty() || data[0] != b'{' {
            return Err(format!(
                "Expected JSON packet, got first byte: 0x{:02x}",
                data.get(0).unwrap_or(&0)
            )
            .into());
        }

        let json_str = String::from_utf8(data)?;
        println!("Received JSON response: {}", json_str);

        let response: SignalingResponse = serde_json::from_str(&json_str)?;

        Ok(response)
    }

    /// Publish a stream to SRS using Private TCP protocol
    pub async fn publish(
        &mut self,
        stream_path: &str,
        sdp_offer: &str,
    ) -> Result<String, Box<dyn Error>> {
        // Ensure we're connected
        if self.read_half.is_none() || self.write_half.is_none() {
            return Err("Not connected to SRS. Call connect() first.".into());
        }

        // Create publish request
        let message = SignalingMessage::Publish {
            stream: stream_path.to_string(),
            sdp: sdp_offer.to_string(),
        };

        // Send publish request
        self.send_json_message(&message).await?;

        // Receive response
        let response = self.recv_json_response().await?;

        // Check response code
        if response.code != 0 {
            let error_msg = response
                .message
                .unwrap_or_else(|| "Unknown error".to_string());
            let details = response.details.unwrap_or_default();
            return Err(format!(
                "Publish failed (code {}): {} - {}",
                response.code, error_msg, details
            )
            .into());
        }

        // Extract session ID and SDP answer
        let session_id = response.session.ok_or("Missing session ID in response")?;
        let sdp_answer = response.sdp.ok_or("Missing SDP answer in response")?;

        self.session_id = Some(session_id.clone());

        println!("Publish successful!");
        println!("  Session ID: {}", session_id);
        println!("  SDP answer: {} bytes", sdp_answer.len());

        Ok(sdp_answer)
    }

    /// Send a raw WebRTC packet (STUN/DTLS/RTP/RTCP) to SRS
    ///
    /// This method sends WebRTC media packets using RFC 4571 framing.
    /// The packet is sent as-is with a 2-byte length prefix.
    ///
    /// # Arguments
    /// * `packet` - The raw packet data (STUN/DTLS/RTP/RTCP)
    ///
    /// # Returns
    /// Result indicating success or error
    pub async fn send_webrtc_packet(&mut self, packet: &[u8]) -> Result<(), Box<dyn Error>> {
        self.send_framed_packet(packet).await
    }

    /// Get the current session ID
    pub fn session_id(&self) -> Option<&str> {
        self.session_id.as_deref()
    }

    /// Close the connection
    pub async fn close(&mut self) -> Result<(), Box<dyn Error>> {
        // Drop the read half
        self.read_half = None;

        // Drop the write half
        self.write_half = None;

        println!("Closed Private TCP connection");
        self.session_id = None;
        Ok(())
    }
}

impl Drop for PrivateTcpClient {
    fn drop(&mut self) {
        if self.read_half.is_some() {
            println!("PrivateTcpClient dropped with active connection");
        }
    }
}
