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
        .with(tracing_subscriber::fmt::layer().with_target(false))
        .init();

    let addr: SocketAddr = std::env::var("AEGIS_BIND")
        .unwrap_or_else(|_| "127.0.0.1:8080".into())
        .parse()
        .expect("invalid AEGIS_BIND address");

    let allow_insecure_public_http = std::env::var("AEGIS_ALLOW_INSECURE_PUBLIC_HTTP")
        .map(|value| value == "1" || value.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if !addr.ip().is_loopback() && !allow_insecure_public_http {
        panic!(
            "refusing public plaintext HTTP bind; use a TLS 1.3 reverse proxy or set AEGIS_ALLOW_INSECURE_PUBLIC_HTTP=1 for explicit lab-only testing"
        );
    }

    tracing::info!(%addr, "Aegis relay server starting");

    let ttl_seconds = std::env::var("AEGIS_RELAY_TTL_SECONDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(86_400);
    let relay_mode = match std::env::var("AEGIS_RELAY_MODE").as_deref() {
        Ok("strict_ephemeral") => aegis_server::state::RelayMode::StrictEphemeral,
        _ => aegis_server::state::RelayMode::TtlPersistent { ttl_seconds },
    };

    let app = match relay_mode {
        aegis_server::state::RelayMode::StrictEphemeral => {
            aegis_server::routes::build_router(relay_mode)
        }
        aegis_server::state::RelayMode::TtlPersistent { .. } => {
            let path = std::env::var("AEGIS_RELAY_STORE_PATH")
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|_| std::path::PathBuf::from("aegis-relay-store.json"));
            aegis_server::routes::build_router_with_persistence(relay_mode, path)
        }
    };

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("failed to bind TCP port");

    tracing::info!("Listening on {}", addr);

    axum::serve(listener, app).await.expect("server error");
}
