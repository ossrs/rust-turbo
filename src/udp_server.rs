use std::error::Error;
use std::sync::Arc;
use tokio::net::UdpSocket;

// SRS RTC UDP port.
pub const SRS_RTC_UDP_PORT: &str = "8000";

// UDP listen port.
pub const TURBO_UDP_LISTEN_PORT: &str = "18000";

/// Replace SRS UDP port with Turbo UDP port in SDP ICE candidates.
///
/// This function modifies the SDP response from SRS by replacing the UDP port
/// in ICE candidate lines from SRS_RTC_UDP_PORT to TURBO_UDP_LISTEN_PORT.
///
/// # Arguments
/// * `sdp_body` - The SDP response body from SRS
///
/// # Returns
/// The modified SDP body with updated port numbers
///
/// # Example
/// Input:  a=candidate:0 1 udp 2130706431 192.168.3.158 8000 typ host generation 0
/// Output: a=candidate:0 1 udp 2130706431 192.168.3.158 18000 typ host generation 0
pub fn replace_sdp_port(sdp_body: &str) -> String {
    // Replace "8000 typ host" with "18000 typ host"
    let port_pattern = format!("{} typ host", SRS_RTC_UDP_PORT);
    let port_replacement = format!("{} typ host", TURBO_UDP_LISTEN_PORT);

    let modified_body = sdp_body.replace(&port_pattern, &port_replacement);

    println!(
        "Modified SDP: replaced '{}' with '{}'",
        port_pattern, port_replacement
    );

    modified_body
}

/// Extract ICE username fragment from SDP content.
///
/// This function searches for the `a=ice-ufrag:` attribute in the SDP
/// and returns the username fragment value.
///
/// # Arguments
/// * `sdp` - The SDP content to parse
///
/// # Returns
/// The ICE username fragment if found, None otherwise
///
/// # Example
/// Input: "a=ice-ufrag:406b41c5"
/// Output: Some("406b41c5")
pub fn extract_ice_ufrag(sdp: &str) -> Option<String> {
    for line in sdp.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("a=ice-ufrag:") {
            let ufrag = trimmed.strip_prefix("a=ice-ufrag:")?.trim();
            return Some(ufrag.to_string());
        }
    }
    None
}

/// Filter the SDP answer from SRS and build RTC session from ICE information.
///
/// This function processes the SDP offer and answer, replacing the UDP port
/// in ICE candidate lines and extracting ICE information to build an RTC session.
/// It creates a session ID in the format "offer_username:answer_username" from
/// the ICE username fragments.
///
/// # Arguments
/// * `offer` - The SDP offer from the client
/// * `answer` - The SDP answer from SRS
///
/// # Returns
/// The modified SDP answer with updated port numbers
///
/// # Example
/// Input answer:  a=candidate:0 1 udp 2130706431 192.168.3.158 8000 typ host generation 0
/// Output answer: a=candidate:0 1 udp 2130706431 192.168.3.158 18000 typ host generation 0
pub fn filter_sdp_answer(offer: &str, answer: &str) -> String {
    println!("Processing SDP offer: {} bytes", offer.len());
    println!("Processing SDP answer: {} bytes", answer.len());

    // Extract ICE username fragments from offer and answer
    let offer_ufrag = extract_ice_ufrag(offer);
    let answer_ufrag = extract_ice_ufrag(answer);

    // Build session ID from ICE username fragments
    if let (Some(offer_username), Some(answer_username)) = (&offer_ufrag, &answer_ufrag) {
        let session_id = format!("{}:{}", offer_username, answer_username);
        println!("Created RTC session ID: {}", session_id);
        println!("  Offer ICE ufrag: {}", offer_username);
        println!("  Answer ICE ufrag: {}", answer_username);
    } else {
        eprintln!("Warning: Failed to extract ICE username fragments");
        if offer_ufrag.is_none() {
            eprintln!("  - Could not find ice-ufrag in offer");
        }
        if answer_ufrag.is_none() {
            eprintln!("  - Could not find ice-ufrag in answer");
        }
    }

    // Replace SRS UDP port with Turbo UDP port in SDP ICE candidates.
    return replace_sdp_port(answer);
}

/// Handle STUN packet processing.
///
/// This function parses a STUN packet, extracts the ICE username,
/// looks up the corresponding session, and updates the UDP address.
///
/// # Arguments
/// * `session_manager` - The global session manager
/// * `buf` - The buffer containing the STUN packet data
/// * `len` - The length of the STUN packet data
/// * `addr` - The socket address of the sender
async fn handle_stun_packet(
    session_manager: &crate::session_manager::SessionManager,
    buf: &[u8],
    len: usize,
    addr: std::net::SocketAddr,
) {
    println!("-> STUN packet detected");

    // Parse STUN packet to extract username
    let stun_packet = match crate::stun::StunPacket::parse(&buf[..len]) {
        Ok(packet) => packet,
        Err(e) => {
            eprintln!("  -> Error parsing STUN packet: {}", e);
            return;
        }
    };

    // Extract ICE username from STUN packet
    let ice_username = match stun_packet.get_username() {
        Some(username) => username,
        None => {
            println!("  -> Warning: STUN packet has no username attribute");
            return;
        }
    };

    println!(
        "  -> STUN {} username: {}",
        stun_packet.message_type, ice_username
    );
    println!("  -> Looking up session by ice_username: {}", ice_username);

    // Update session's UDP address
    if !session_manager.update_udp_address(ice_username, addr).await {
        println!(
            "  -> Warning: No session found for ice_username: {}",
            ice_username
        );
        let sessions = session_manager.list_sessions().await;
        println!("  -> Active sessions: {:?}", sessions);
        return;
    }

    println!("  -> Session found and UDP address updated");

    // Forward STUN packet to SRS via Private TCP connection
    match session_manager.send_packet(ice_username, &buf[..len]).await {
        Ok(_) => {
            println!("  -> Forwarded STUN packet to SRS ({} bytes)", len);
        }
        Err(e) => {
            eprintln!("  -> Error forwarding STUN packet to SRS: {}", e);
        }
    }
}

/// Handle incoming UDP packet.
///
/// This function processes a UDP packet received from a client.
/// It extracts the ICE username from STUN packets and looks up the
/// corresponding Private TCP client from the session manager.
///
/// # Arguments
/// * `session_manager` - The global session manager
/// * `buf` - The buffer containing the received data
/// * `len` - The length of the received data
/// * `addr` - The socket address of the sender
async fn handle_udp_packet(
    session_manager: &crate::session_manager::SessionManager,
    buf: &[u8],
    len: usize,
    addr: std::net::SocketAddr,
) {
    if len <= 0 {
        println!("  -> Received empty UDP packet");
        return;
    }

    // Check packet type by first byte
    let first_byte = buf[0];
    match first_byte {
        0x00..=0x01 => {
            handle_stun_packet(session_manager, buf, len, addr).await;
        }
        0x14..=0x3F => {
            println!("  -> DTLS packet detected");
        }
        0x80..=0xBF => {
            println!("  -> RTP/RTCP packet detected");
        }
        0x7B => {
            println!("  -> JSON packet detected (unexpected on UDP)");
        }
        _ => {
            println!("  -> Unknown packet type: 0x{:02x}", first_byte);
        }
    }
}

/// UDP packet receiver task.
///
/// This task continuously receives UDP packets from the socket and processes them.
///
/// **Important**: UDP sockets are thread-safe, but there should be only ONE UDP packet
/// receiver task. Multiple receiver tasks would compete for packets, leading to
/// unpredictable behavior. However, there can be multiple UDP packet senders
/// (via `socket.send_to()`) from different tasks/threads safely.
///
/// # Arguments
/// * `session_manager` - The global session manager for looking up sessions
/// * `socket` - The shared UDP socket (Arc-wrapped for thread-safe access)
///
/// # Returns
/// Never returns unless an error occurs
pub async fn udp_receiver_task(
    session_manager: crate::session_manager::SessionManager,
    socket: Arc<UdpSocket>,
) -> Result<(), Box<dyn Error>> {
    let mut buf = vec![0u8; 2048];

    loop {
        match socket.recv_from(&mut buf).await {
            Ok((len, addr)) => {
                handle_udp_packet(&session_manager, &buf, len, addr).await;
            }
            Err(e) => {
                eprintln!("Error receiving data: {}", e);
            }
        }
    }
}
