//! Aegis Messenger — Protocol

pub mod envelope;
pub mod session;
pub mod handshake;
pub mod contact;
pub mod group;
pub mod error;

pub use error::ProtocolError;
