use axum::{
    Router,
    extract::{Query, State},
    http::{HeaderMap, HeaderName, Method, StatusCode, Uri, header},
    response::IntoResponse,
    routing::any,
};
use serde::Deserialize;
use std::error::Error;

use crate::session_manager::SessionManager;

#[derive(Debug, Deserialize)]
struct WhipParams {
    #[serde(default)]
    app: Option<String>,
    #[serde(default)]
    stream: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    action: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    session: Option<String>,
    #[serde(default)]
    token: Option<String>,
}

// Add CORS headers to an existing HeaderMap if CORS is required
fn add_cors_headers(response_headers: &mut HeaderMap, cors_required: bool) {
    if cors_required {
        // SRS does not need cookie or credentials, so we disable CORS credentials, and use * for CORS origin,
        // headers, expose headers and methods.
        response_headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*".parse().unwrap());
        response_headers.insert(header::ACCESS_CONTROL_ALLOW_HEADERS, "*".parse().unwrap());
        response_headers.insert(header::ACCESS_CONTROL_ALLOW_METHODS, "*".parse().unwrap());
        response_headers.insert(header::ACCESS_CONTROL_EXPOSE_HEADERS, "*".parse().unwrap());
        response_headers.insert(
            header::ACCESS_CONTROL_ALLOW_CREDENTIALS,
            "false".parse().unwrap(),
        );
        // CORS header for private network access, starting in Chrome 104
        response_headers.insert(
            HeaderName::from_static("access-control-request-private-network"),
            "true".parse().unwrap(),
        );
    }
}

// Setup CORS headers based on whether CORS is required
fn setup_cors_headers(cors_required: bool) -> HeaderMap {
    let mut response_headers = HeaderMap::new();
    add_cors_headers(&mut response_headers, cors_required);
    response_headers
}

// Handle OPTIONS request (CORS preflight)
fn handle_options_request(mut response_headers: HeaderMap) -> (StatusCode, HeaderMap, String) {
    response_headers.insert(header::CONTENT_LENGTH, "0".parse().unwrap());
    (StatusCode::OK, response_headers, "".to_string())
}

// Handle DELETE request - close the RTC session
async fn handle_delete_request(
    session_manager: SessionManager,
    params: &WhipParams,
    cors_required: bool,
    mut response_headers: HeaderMap,
) -> (StatusCode, HeaderMap, String) {
    let client_token = params.token.clone().unwrap_or_default();

    if client_token.is_empty() {
        response_headers.insert(header::CONTENT_LENGTH, "11".parse().unwrap());
        return (
            StatusCode::BAD_REQUEST,
            response_headers,
            "token empty".to_string(),
        );
    }

    println!("WHIP DELETE request - client_token: {}", client_token);

    // Look up and remove the session by client token
    let rtc_connection = session_manager.remove_session_by_token(&client_token).await;

    match rtc_connection {
        Some(mut conn) => {
            println!(
                "Found RTC session: backend_token={}, location={}, offer_ufrag={}",
                conn.backend_token, conn.location, conn.offer_ufrag
            );

            // Close the Private TCP connection
            if let Err(e) = conn.client.close().await {
                eprintln!("Failed to close Private TCP connection: {}", e);
            } else {
                println!(
                    "Closed Private TCP connection for client_token={}",
                    client_token
                );
            }

            // Ensure CORS headers are present if needed
            add_cors_headers(&mut response_headers, cors_required);

            response_headers.insert(header::CONTENT_LENGTH, "0".parse().unwrap());
            (StatusCode::OK, response_headers, "".to_string())
        }
        None => {
            eprintln!("Token not found: {}", client_token);
            response_headers.insert(header::CONTENT_LENGTH, "15".parse().unwrap());
            (
                StatusCode::NOT_FOUND,
                response_headers,
                "token not found".to_string(),
            )
        }
    }
}

// Handle POST request - use Private TCP protocol to connect to SRS
async fn handle_post_request(
    session_manager: SessionManager,
    _uri: Uri,
    params: &WhipParams,
    body: String,
    cors_required: bool,
    mut response_headers: HeaderMap,
) -> (StatusCode, HeaderMap, String) {
    let app = params.app.clone().unwrap_or_else(|| "live".to_string());
    let stream = params
        .stream
        .clone()
        .unwrap_or_else(|| "livestream".to_string());
    let offer = body;

    println!(
        "WHIP POST request - app: {}, stream: {}, offer: {} bytes",
        app,
        stream,
        offer.len()
    );

    // Build stream path for Private TCP protocol
    let stream_path = format!("/{}/{}", app, stream);
    println!(
        "Using Private TCP protocol with stream path: {}",
        stream_path
    );

    // Create Private TCP client and connect to SRS
    let mut client = crate::private_tcp::PrivateTcpClient::new();

    if let Err(e) = client.connect("127.0.0.1").await {
        eprintln!("Failed to connect to SRS Private TCP: {}", e);
        response_headers.insert(header::CONTENT_LENGTH, "28".parse().unwrap());
        return (
            StatusCode::BAD_GATEWAY,
            response_headers,
            "Failed to reach backend".to_string(),
        );
    }

    // Send publish request via Private TCP
    let sdp_answer = match client.publish(&stream_path, &offer).await {
        Ok(answer) => answer,
        Err(e) => {
            eprintln!("Failed to publish via Private TCP: {}", e);
            let error_msg = format!("Publish failed: {}", e);
            response_headers.insert(
                header::CONTENT_LENGTH,
                error_msg.len().to_string().parse().unwrap(),
            );
            return (StatusCode::BAD_REQUEST, response_headers, error_msg);
        }
    };

    println!(
        "Private TCP publish successful, SDP answer: {} bytes",
        sdp_answer.len()
    );

    // Filter SDP answer and build RTC session from ICE information
    let response_body = crate::udp_server::filter_sdp_answer(&offer, &sdp_answer);

    // Extract ICE username fragments from offer and answer
    let offer_ufrag = crate::udp_server::extract_ice_ufrag(&offer);
    let answer_ufrag = crate::udp_server::extract_ice_ufrag(&sdp_answer);

    // Get session ID before moving the client
    let session_id = client.session_id().unwrap_or("unknown").to_string();

    // Generate a client token for session management
    let client_token = uuid::Uuid::new_v4().to_string();

    // Build Location header for DELETE requests
    let location = format!(
        "/rtc/v1/whip/?action=delete&token={}&app={}&stream={}",
        client_token, app, stream
    );

    // Store the Private TCP client in the session manager
    // Return error if ICE username fragments cannot be extracted
    let (offer_username, answer_username) = match (offer_ufrag, answer_ufrag) {
        (Some(offer), Some(answer)) => (offer, answer),
        _ => {
            eprintln!("Error: Could not extract ICE username fragments from SDP");
            let error_msg = "Failed to extract ICE credentials from SDP";
            response_headers.insert(
                header::CONTENT_LENGTH,
                error_msg.len().to_string().parse().unwrap(),
            );
            return (
                StatusCode::BAD_REQUEST,
                response_headers,
                error_msg.to_string(),
            );
        }
    };

    session_manager
        .add_session(
            offer_username.clone(),
            answer_username.clone(),
            stream_path.clone(),
            client,
            client_token.clone(),
            session_id.clone(),
            location.clone(),
        )
        .await;

    println!(
        "Stored RTC session: offer_ufrag={}, answer_ufrag={}, client_token={}",
        offer_username, answer_username, client_token
    );

    if let Ok(parsed_location) = location.parse() {
        response_headers.insert(header::LOCATION, parsed_location);
    }

    // Set Content-Type for SDP
    response_headers.insert(header::CONTENT_TYPE, "application/sdp".parse().unwrap());

    // Update Content-Length header
    if let Ok(content_length_value) = response_body.len().to_string().parse() {
        response_headers.insert(header::CONTENT_LENGTH, content_length_value);
    }

    // Ensure CORS headers are present if needed
    add_cors_headers(&mut response_headers, cors_required);

    // Return 201 Created as per WHIP specification
    (StatusCode::CREATED, response_headers, response_body)
}

// Handler for /rtc/v1/whip/ - handles OPTIONS, POST and DELETE
async fn handle_whip(
    State(session_manager): State<SessionManager>,
    method: Method,
    headers: HeaderMap,
    uri: Uri,
    Query(params): Query<WhipParams>,
    body: String,
) -> impl IntoResponse {
    // Check if CORS is required (if Origin header is present)
    let cors_required = headers.get(header::ORIGIN).is_some();

    // Prepare CORS headers if required
    let mut response_headers = setup_cors_headers(cors_required);

    // Handle OPTIONS request (CORS preflight)
    if method == Method::OPTIONS {
        return handle_options_request(response_headers);
    }

    // Handle DELETE request
    if method == Method::DELETE {
        return handle_delete_request(
            session_manager.clone(),
            &params,
            cors_required,
            response_headers,
        )
        .await;
    }

    // Handle POST request
    if method == Method::POST {
        return handle_post_request(
            session_manager,
            uri,
            &params,
            body,
            cors_required,
            response_headers,
        )
        .await;
    }

    // Method not allowed
    response_headers.insert(header::CONTENT_LENGTH, "0".parse().unwrap());
    (
        StatusCode::METHOD_NOT_ALLOWED,
        response_headers,
        "".to_string(),
    )
}

// HTTP server task
pub async fn http_handler_task(session_manager: SessionManager) -> Result<(), Box<dyn Error>> {
    // Build the HTTP API router
    let app = Router::new()
        .route("/rtc/v1/whip/", any(handle_whip))
        .with_state(session_manager);

    // Start HTTP server
    let listener = tokio::net::TcpListener::bind("0.0.0.0:11985").await?;
    println!("HTTP API server started on http://0.0.0.0:11985");
    println!("WHIP endpoint available at: http://0.0.0.0:11985/rtc/v1/whip/");

    axum::serve(listener, app).await?;

    Ok(())
}
