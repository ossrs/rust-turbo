use crate::private_tcp::PrivateTcpClient;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;

/// RTC connection information for a WebRTC session
pub struct RtcConnection {
    /// The Private TCP client connection to SRS
    /// The client is NOT wrapped in Mutex because the TCP stream is split:
    /// - Read half is taken by the reader coroutine
    /// - Write half stays in the client for sending packets
    pub client: PrivateTcpClient,
    /// The ICE username fragment from the offer (client side)
    pub offer_ufrag: String,
    /// The ICE username fragment from the answer (server side)
    pub answer_ufrag: String,
    /// The stream path (e.g., "/live/livestream")
    pub stream_path: String,
    /// Client token for DELETE requests (UUID)
    pub client_token: String,
    /// Backend session ID from SRS
    pub backend_token: String,
    /// Location path for DELETE requests
    pub location: String,
    /// UDP address of the client (updated when STUN packets arrive)
    pub udp_address: Option<SocketAddr>,
}

// RtcConnection methods are defined below

impl std::fmt::Debug for RtcConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RtcConnection")
            .field("offer_ufrag", &self.offer_ufrag)
            .field("answer_ufrag", &self.answer_ufrag)
            .field("stream_path", &self.stream_path)
            .field("client_token", &self.client_token)
            .field("backend_token", &self.backend_token)
            .field("location", &self.location)
            .field("udp_address", &self.udp_address)
            .field("client", &"<PrivateTcpClient>")
            .finish()
    }
}

/// Global session manager that stores active WebRTC sessions
/// Key: ICE username fragment from the offer (client side)
/// Value: RtcConnection containing the Private TCP client and session info
#[derive(Clone)]
pub struct SessionManager {
    sessions: Arc<Mutex<HashMap<String, RtcConnection>>>,
    udp_socket: Arc<tokio::net::UdpSocket>,
}

impl SessionManager {
    /// Create a new session manager with a UDP socket
    pub fn new(udp_socket: Arc<tokio::net::UdpSocket>) -> Self {
        Self {
            sessions: Arc::new(Mutex::new(HashMap::new())),
            udp_socket,
        }
    }

    /// Add a session to the manager
    pub async fn add_session(
        &self,
        offer_ufrag: String,
        answer_ufrag: String,
        stream_path: String,
        mut client: PrivateTcpClient,
        client_token: String,
        backend_token: String,
        location: String,
    ) {
        // Use "answer_ufrag:offer_ufrag" as the session key (matches STUN username format)
        let session_key = format!("{}:{}", answer_ufrag, offer_ufrag);

        // Start the reader coroutine for this session before adding to the map
        client.start_reader_coroutine(self.udp_socket.clone(), self.clone(), session_key.clone());

        let rtc_connection = RtcConnection {
            client,
            offer_ufrag: offer_ufrag.clone(),
            answer_ufrag: answer_ufrag.clone(),
            stream_path,
            client_token: client_token.clone(),
            backend_token,
            location,
            udp_address: None, // Will be updated when first STUN packet arrives
        };

        self.sessions
            .lock()
            .await
            .insert(session_key.clone(), rtc_connection);
        println!(
            "Added session to manager: session_key={}, client_token={}",
            session_key, client_token
        );
    }

    /// Send a WebRTC packet via the session's Private TCP client
    pub async fn send_packet(
        &self,
        ice_username: &str,
        packet: &[u8],
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut sessions = self.sessions.lock().await;
        let session = sessions.get_mut(ice_username).ok_or("Session not found")?;
        session.client.send_webrtc_packet(packet).await
    }

    /// Find and remove a session by client token
    pub async fn remove_session_by_token(&self, client_token: &str) -> Option<RtcConnection> {
        let mut sessions = self.sessions.lock().await;

        // Find the offer_ufrag that matches the client_token
        let offer_ufrag = sessions
            .iter()
            .find(|(_, conn)| conn.client_token == client_token)
            .map(|(key, _)| key.clone());

        if let Some(ufrag) = offer_ufrag {
            let session = sessions.remove(&ufrag);
            if session.is_some() {
                println!("Removed session by client_token: {}", client_token);
            }
            session
        } else {
            None
        }
    }

    /// List all active session ICE username fragments
    pub async fn list_sessions(&self) -> Vec<String> {
        self.sessions.lock().await.keys().cloned().collect()
    }

    /// Update the UDP address for a session by STUN username
    /// The ice_username should be in format "answer_ufrag:offer_ufrag"
    /// Returns true if the session was found and updated
    pub async fn update_udp_address(&self, ice_username: &str, addr: SocketAddr) -> bool {
        let mut sessions = self.sessions.lock().await;
        if let Some(session) = sessions.get_mut(ice_username) {
            let prev_addr = session.udp_address;
            session.udp_address = Some(addr);

            if prev_addr.is_none() {
                println!("Session {} UDP address initialized: {}", ice_username, addr);
            } else if prev_addr != Some(addr) {
                println!(
                    "Session {} UDP address changed: {:?} -> {}",
                    ice_username, prev_addr, addr
                );
            }

            true
        } else {
            false
        }
    }

    /// Get the UDP address for a session
    pub async fn get_udp_address(&self, ice_username: &str) -> Option<std::net::SocketAddr> {
        self.sessions
            .lock()
            .await
            .get(ice_username)
            .and_then(|s| s.udp_address)
    }
}

// RtcConnection cannot be cloned because PrivateTcpClient owns the TCP stream halves

// SessionManager no longer implements Default because it requires a UDP socket
