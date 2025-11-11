mod http_api;
mod private_tcp;
mod session_manager;
mod stun;
mod udp_server;

use http_api::http_handler_task;
use session_manager::SessionManager;
use std::error::Error;
use std::sync::Arc;
use tokio::net::UdpSocket;
use udp_server::{TURBO_UDP_LISTEN_PORT, udp_receiver_task};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Create UDP socket first
    let addr = format!("0.0.0.0:{}", TURBO_UDP_LISTEN_PORT);
    let udp_socket = Arc::new(UdpSocket::bind(&addr).await?);
    println!("UDP listener started on {}", addr);

    // Create global session manager with the UDP socket
    let session_manager = SessionManager::new(udp_socket.clone());

    // Spawn UDP receiver in background with session manager
    {
        let session_manager = session_manager.clone();
        tokio::spawn(async move {
            if let Err(e) = udp_receiver_task(session_manager, udp_socket).await {
                eprintln!("UDP receiver error: {}", e);
            }
        });
    }

    // Spawn HTTP request handler in background with session manager
    {
        let session_manager = session_manager.clone();
        tokio::spawn(async move {
            if let Err(e) = http_handler_task(session_manager).await {
                eprintln!("HTTP server error: {}", e);
            }
        });
    }

    // Keep the main task alive
    tokio::signal::ctrl_c().await?;
    println!("Shutting down...");

    Ok(())
}
