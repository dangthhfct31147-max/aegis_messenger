//! Aegis Messenger — Protocol

pub mod contact;
pub mod envelope;
pub mod error;
pub mod group;
pub mod handshake;
pub mod models;
pub mod session;

pub use error::ProtocolError;
pub use models::*;
