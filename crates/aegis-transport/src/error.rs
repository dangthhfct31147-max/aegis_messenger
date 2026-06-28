//! Transport error types

use thiserror::Error;

#[derive(Error, Debug)]
pub enum TransportError {
    #[error("network: connection failed")]
    ConnectionFailed(String),

    #[error("network: request failed")]
    RequestFailed(String),

    #[error("server: {0}")]
    Server(String),

    #[error("parse: {0}")]
    Parse(String),

    #[error("crypto: {0}")]
    Crypto(String),
}
