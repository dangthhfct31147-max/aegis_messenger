//! Server API client

use base64::Engine;
use serde::Deserialize;

pub struct TransportClient {
    server_url: String,
    client: reqwest::Client,
}

impl TransportClient {
    pub fn new(server_url: &str) -> Self {
        Self {
            server_url: server_url.to_string(),
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .expect("reqwest client creation failed"),
        }
    }

    pub async fn health_check(&self) -> Result<HealthResponse, crate::error::TransportError> {
        let resp = self.client
            .get(format!("{}/health", self.server_url))
            .send()
            .await
            .map_err(|e| crate::error::TransportError::ConnectionFailed(e.to_string()))?;
        let health: HealthResponse = resp.json()
            .await
            .map_err(|e| crate::error::TransportError::Parse(e.to_string()))?;
        Ok(health)
    }

    pub async fn create_account(&self) -> Result<AccountInfo, crate::error::TransportError> {
        #[derive(serde::Serialize)]
        struct Body { public_metadata: serde_json::Value }
        let resp = self.client
            .post(format!("{}/v1/accounts", self.server_url))
            .json(&Body { public_metadata: serde_json::json!({}) })
            .send()
            .await
            .map_err(|e| crate::error::TransportError::ConnectionFailed(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(crate::error::TransportError::Server(format!("status: {}", resp.status())));
        }
        let info: AccountInfo = resp.json()
            .await
            .map_err(|e| crate::error::TransportError::Parse(e.to_string()))?;
        Ok(info)
    }

    pub async fn create_queue(&self, ttl_seconds: Option<i64>) -> Result<QueueInfo, crate::error::TransportError> {
        #[derive(serde::Serialize)]
        struct Body { ttl_seconds: Option<i64> }
        let resp = self.client
            .post(format!("{}/v1/queues", self.server_url))
            .json(&Body { ttl_seconds })
            .send()
            .await
            .map_err(|e| crate::error::TransportError::ConnectionFailed(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(crate::error::TransportError::Server(format!("status: {}", resp.status())));
        }
        let info: QueueInfo = resp.json()
            .await
            .map_err(|e| crate::error::TransportError::Parse(e.to_string()))?;
        Ok(info)
    }

    pub async fn upload_envelope(&self, queue_id: &str, ciphertext: &[u8], padded_size_bucket: i32) -> Result<EnvelopeInfo, crate::error::TransportError> {
        #[derive(serde::Serialize)]
        struct Body<'a> {
            queue_id_hash: &'a str,
            ciphertext_blob: String,
            padded_size_bucket: i32,
            ttl_seconds: Option<i64>,
        }
        let body = Body {
            queue_id_hash: queue_id,
            ciphertext_blob: base64_url_encode(ciphertext),
            padded_size_bucket,
            ttl_seconds: None,
        };
        let resp = self.client
            .post(format!("{}/v1/envelopes", self.server_url))
            .json(&body)
            .send()
            .await
            .map_err(|e| crate::error::TransportError::ConnectionFailed(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(crate::error::TransportError::Server(format!("status: {}", resp.status())));
        }
        let info: EnvelopeInfo = resp.json()
            .await
            .map_err(|e| crate::error::TransportError::Parse(e.to_string()))?;
        Ok(info)
    }

    pub async fn poll_envelopes(&self, queue_id: &str) -> Result<Vec<EnvelopeData>, crate::error::TransportError> {
        let resp = self.client
            .get(format!("{}/v1/envelopes?queue={}", self.server_url, queue_id))
            .send()
            .await
            .map_err(|e| crate::error::TransportError::ConnectionFailed(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(crate::error::TransportError::Server(format!("status: {}", resp.status())));
        }
        #[derive(Deserialize)]
        struct Response { envelopes: Vec<EnvelopeData> }
        let data: Response = resp.json()
            .await
            .map_err(|e| crate::error::TransportError::Parse(e.to_string()))?;
        Ok(data.envelopes)
    }

    pub async fn ack_envelope(&self, envelope_id: &str) -> Result<(), crate::error::TransportError> {
        let resp = self.client
            .delete(format!("{}/v1/envelopes/{}", self.server_url, envelope_id))
            .send()
            .await
            .map_err(|e| crate::error::TransportError::ConnectionFailed(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(crate::error::TransportError::Server(format!("status: {}", resp.status())));
        }
        Ok(())
    }
}

fn base64_url_encode(data: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

#[derive(Debug, Deserialize)]
pub struct HealthResponse { pub status: String, pub version: String, pub timestamp: String }

#[derive(Debug, Deserialize)]
pub struct AccountInfo { pub account_id: String, pub created_at: String }

#[derive(Debug, Deserialize)]
pub struct QueueInfo {
    pub queue_id: String,
    pub read_token: String,
    pub write_token: String,
    pub expires_at: String,
}

#[derive(Debug, Deserialize)]
pub struct EnvelopeInfo { pub envelope_id: String, pub expires_at: String }

#[derive(Debug, Deserialize)]
pub struct EnvelopeData {
    pub envelope_id: String,
    pub ciphertext_blob: String,
    pub created_at_bucket: String,
}
