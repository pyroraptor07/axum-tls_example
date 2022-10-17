use std::future::ready;
use std::net::SocketAddr;

use axum::http::StatusCode;
mod tls;

use axum::response::IntoResponse;
use axum::routing::get;
use axum::{debug_handler, Router};
use color_eyre::Result;
use futures::StreamExt;
use hyper::server::accept;
use hyper::server::conn::AddrIncoming;
use tls_listener::TlsListener;
use tokio_rustls::TlsAcceptor;


#[debug_handler]
async fn root_handler() -> impl IntoResponse {
    (StatusCode::OK, "Hello, World!")
}

async fn run_server() -> Result<()> {
    color_eyre::install()?;
    let tls_config = tls::load_tls_config()?;

    // Setup layers and routes
    let app = Router::new().route("/", get(root_handler));

    // Bind to address/port
    let addr = "127.0.0.1:5000".parse::<SocketAddr>()?;
    let addr_incoming = AddrIncoming::bind(&addr)?;

    // Setup TLS
    // Filter on TLS listener is there to handle TLS errors gracefully.
    // If omitted, server will stop when receiving a TLS connection that
    // has misconfigured TLS.
    let tls_acceptor = TlsAcceptor::try_from(tls_config)?;
    let tls_listener = TlsListener::new(tls_acceptor, addr_incoming).filter(|conn| {
        if let Err(e) = conn {
            eprintln!("TLS ERROR: {}", e);
            ready(false)
        } else {
            ready(true)
        }
    });

    // Start server
    let server =
        axum::Server::builder(accept::from_stream(tls_listener)).serve(app.into_make_service());

    println!("Starting server at https://127.0.0.1:5000");
    server.await?;

    Ok(())
}


#[tokio::main]
async fn main() {
    if let Err(e) = run_server().await {
        eprintln!("{}", e);
    }
}
