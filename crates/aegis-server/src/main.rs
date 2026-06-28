//! Aegis Messenger — Minimal Relay Server Binary

use std::net::SocketAddr;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "aegis_server=info,warn".into()),
        )
        .with(tracing_subscriber::fmt::layer()
            .with_target(false)
        )
        .init();

    let addr: SocketAddr = std::env::var("AEGIS_BIND")
        .unwrap_or_else(|_| "0.0.0.0:8080".into())
        .parse()
        .expect("invalid AEGIS_BIND address");

    tracing::info!(%addr, "Aegis relay server starting");

    let app = aegis_server::routes::build_router(aegis_server::state::RelayMode::Strict);

    let listener = tokio::net::TcpListener::bind(addr).await
        .expect("failed to bind TCP port");

    tracing::info!("Listening on {}", addr);

    axum::serve(listener, app)
        .await
        .expect("server error");
}
