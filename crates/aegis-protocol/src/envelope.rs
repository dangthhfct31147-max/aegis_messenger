//! Envelope format

use aegis_crypto::{CipherSuite, PROTOCOL_VERSION};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EnvelopeHeader {
    pub protocol_version: u16,
    pub cipher_suite: CipherSuite,
    pub key_version: u32,
    pub sender_ephemeral: [u8; 32],
    pub message_number: u64,
    pub previous_chain: u64,
}

impl EnvelopeHeader {
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("envelope header serialization must not fail")
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, crate::error::ProtocolError> {
        serde_json::from_slice(bytes)
            .map_err(|e| crate::error::ProtocolError::Envelope(e.to_string()))
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Envelope {
    pub header: EnvelopeHeader,
    pub ciphertext: Vec<u8>,
}

impl Envelope {
    pub fn new(
        cipher_suite: CipherSuite,
        key_version: u32,
        sender_ephemeral: [u8; 32],
        message_number: u64,
        previous_chain: u64,
        ciphertext: Vec<u8>,
    ) -> Self {
        Self {
            header: EnvelopeHeader {
                protocol_version: PROTOCOL_VERSION,
                cipher_suite,
                key_version,
                sender_ephemeral,
                message_number,
                previous_chain,
            },
            ciphertext,
        }
    }

    pub fn serialize(&self) -> Result<Vec<u8>, crate::error::ProtocolError> {
        let header_bytes = serde_json::to_vec(&self.header)
            .map_err(|e| crate::error::ProtocolError::Envelope(e.to_string()))?;

        let mut result = Vec::with_capacity(4 + header_bytes.len() + self.ciphertext.len());
        result.extend_from_slice(&(header_bytes.len() as u32).to_be_bytes());
        result.extend_from_slice(&header_bytes);
        result.extend_from_slice(&self.ciphertext);
        Ok(result)
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, crate::error::ProtocolError> {
        if data.len() < 4 { return Err(crate::error::ProtocolError::Envelope("too short".into())); }
        let header_len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
        if data.len() < 4 + header_len { return Err(crate::error::ProtocolError::Envelope("header truncated".into())); }
        let header = EnvelopeHeader::from_bytes(&data[4..4 + header_len])?;
        let ciphertext = data[4 + header_len..].to_vec();
        Ok(Self { header, ciphertext })
    }

    pub fn aad(&self) -> Vec<u8> { self.header.to_bytes() }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MessageContent {
    #[serde(rename = "type")]
    pub content_type: MessageType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attachment: Option<AttachmentRef>,
    pub sender_timestamp_ms: u64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MessageType {
    Text,
    Attachment,
    GroupCreate,
    GroupUpdate,
    GroupLeave,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AttachmentRef {
    pub chunk_id: String,
    pub file_key: Vec<u8>,
    pub filename: Option<String>,
    pub mime_type: Option<String>,
    pub size_bucket: u32,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ContactInvite {
    pub v: u16,
    pub q: String,
    pub r: String,
    pub w: String,
    pub pk: String,
    pub id: String,
    pub sig: String,
    pub exp: u64,
}

impl ContactInvite {
    pub fn signable_bytes(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&self.v.to_be_bytes());
        data.extend_from_slice(self.q.as_bytes());
        data.extend_from_slice(self.r.as_bytes());
        data.extend_from_slice(self.w.as_bytes());
        data.extend_from_slice(self.pk.as_bytes());
        data.extend_from_slice(self.id.as_bytes());
        data.extend_from_slice(&self.exp.to_be_bytes());
        data
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_envelope_roundtrip() {
        let header = EnvelopeHeader {
            protocol_version: PROTOCOL_VERSION,
            cipher_suite: CipherSuite::Aegis1,
            key_version: 1,
            sender_ephemeral: [1u8; 32],
            message_number: 5,
            previous_chain: 0,
        };
        let ciphertext = vec![0u8; 32];
        let envelope = Envelope { header, ciphertext };
        let serialized = envelope.serialize().unwrap();
        let deserialized = Envelope::deserialize(&serialized).unwrap();
        assert_eq!(deserialized.header.message_number, 5);
        assert_eq!(deserialized.header.protocol_version, PROTOCOL_VERSION);
    }
}
