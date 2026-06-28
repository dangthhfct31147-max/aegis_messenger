//! MLS-facing protocol facade.
//!
//! The production backend for this module is OpenMLS. The public types here
//! intentionally avoid exposing OpenMLS internals to desktop/server code so the
//! storage and transport contracts stay stable while the backend is hardened.

use serde::{Deserialize, Serialize};

pub const MLS_BACKEND: &str = "openmls";
pub const MLS_PROTOCOL_VERSION: u16 = 1;

#[cfg(feature = "openmls-backend")]
pub const OPENMLS_BACKEND_ENABLED: bool = true;

#[cfg(not(feature = "openmls-backend"))]
pub const OPENMLS_BACKEND_ENABLED: bool = false;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MlsKeyPackage {
    pub device_id: String,
    pub key_package: Vec<u8>,
    pub credential: Vec<u8>,
    pub signature: Vec<u8>,
    pub created_at_bucket: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MlsWelcome {
    pub group_id: [u8; 32],
    pub epoch: u64,
    pub welcome: Vec<u8>,
    pub ratchet_tree: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MlsCommit {
    pub group_id: [u8; 32],
    pub from_epoch: u64,
    pub to_epoch: u64,
    pub commit: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MlsApplicationMessage {
    pub group_id: [u8; 32],
    pub epoch: u64,
    pub ciphertext: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MlsEpochState {
    pub group_id: [u8; 32],
    pub epoch: u64,
    pub member_device_ids: Vec<String>,
    pub backend: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AegisMlsGroup {
    pub state: MlsEpochState,
    pub pending_commits: Vec<MlsCommit>,
    pub serialized_group_state: Vec<u8>,
}

impl AegisMlsGroup {
    pub fn new(group_id: [u8; 32], creator_device_id: String) -> Self {
        Self {
            state: MlsEpochState {
                group_id,
                epoch: 0,
                member_device_ids: vec![creator_device_id],
                backend: MLS_BACKEND.to_string(),
            },
            pending_commits: Vec::new(),
            serialized_group_state: Vec::new(),
        }
    }

    pub fn queue_add_member_commit(&mut self, device_id: String, commit: Vec<u8>) -> MlsCommit {
        let next_epoch = self.state.epoch + 1;
        let mls_commit = MlsCommit {
            group_id: self.state.group_id,
            from_epoch: self.state.epoch,
            to_epoch: next_epoch,
            commit,
        };
        self.pending_commits.push(mls_commit.clone());
        if !self.state.member_device_ids.contains(&device_id) {
            self.state.member_device_ids.push(device_id);
        }
        mls_commit
    }

    pub fn apply_commit(&mut self, commit: &MlsCommit) -> Result<(), MlsStateError> {
        if commit.group_id != self.state.group_id {
            return Err(MlsStateError::WrongGroup);
        }
        if commit.from_epoch != self.state.epoch || commit.to_epoch != self.state.epoch + 1 {
            return Err(MlsStateError::EpochMismatch);
        }
        self.state.epoch = commit.to_epoch;
        self.pending_commits
            .retain(|pending| pending.to_epoch != commit.to_epoch);
        Ok(())
    }

    pub fn protect_application_message(&self, ciphertext: Vec<u8>) -> MlsApplicationMessage {
        MlsApplicationMessage {
            group_id: self.state.group_id,
            epoch: self.state.epoch,
            ciphertext,
        }
    }

    pub fn validate_application_message(
        &self,
        message: &MlsApplicationMessage,
    ) -> Result<(), MlsStateError> {
        if message.group_id != self.state.group_id {
            return Err(MlsStateError::WrongGroup);
        }
        if message.epoch != self.state.epoch {
            return Err(MlsStateError::EpochMismatch);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MlsStateError {
    WrongGroup,
    EpochMismatch,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClaimGateStatus {
    Claimable,
    Blocked { reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityClaimGates {
    pub mls_groups: ClaimGateStatus,
    pub relay_transport_pfs: ClaimGateStatus,
    pub traffic_correlation_resistance: ClaimGateStatus,
    pub ml_kem_production: ClaimGateStatus,
}

impl SecurityClaimGates {
    pub fn conservative_default() -> Self {
        Self {
            mls_groups: ClaimGateStatus::Blocked {
                reason: "MLS groups require OpenMLS-backed group state and interop tests".into(),
            },
            relay_transport_pfs: ClaimGateStatus::Blocked {
                reason: "relay PFS claim requires TLS 1.3 strict-ephemeral deployment".into(),
            },
            traffic_correlation_resistance: ClaimGateStatus::Blocked {
                reason: "global traffic-correlation resistance requires indistinguishable dummy envelopes plus cadence controls".into(),
            },
            ml_kem_production: ClaimGateStatus::Blocked {
                reason: "ML-KEM production claim requires KATs, fuzzing, downgrade review, and external audit".into(),
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrafficProfile {
    pub mode: TrafficProfileMode,
    pub fixed_size_buckets: Vec<u32>,
    pub min_poll_interval_ms: u64,
    pub max_poll_jitter_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrafficProfileMode {
    Direct,
    Padded,
    HighPrivacy,
}

impl Default for TrafficProfile {
    fn default() -> Self {
        Self {
            mode: TrafficProfileMode::Padded,
            fixed_size_buckets: vec![1024, 4096, 16_384, 65_536],
            min_poll_interval_ms: 5_000,
            max_poll_jitter_ms: 2_000,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mls_group_rejects_epoch_mismatch() {
        let mut group = AegisMlsGroup::new([1u8; 32], "device-a".into());
        let commit = group.queue_add_member_commit("device-b".into(), b"commit".to_vec());
        assert!(group.apply_commit(&commit).is_ok());
        assert_eq!(group.state.epoch, 1);

        let stale = MlsApplicationMessage {
            group_id: [1u8; 32],
            epoch: 0,
            ciphertext: b"old".to_vec(),
        };
        assert_eq!(
            group.validate_application_message(&stale),
            Err(MlsStateError::EpochMismatch)
        );
    }

    #[test]
    fn claim_gates_start_blocked_until_evidence_exists() {
        let gates = SecurityClaimGates::conservative_default();
        assert!(matches!(gates.mls_groups, ClaimGateStatus::Blocked { .. }));
        assert!(matches!(
            gates.ml_kem_production,
            ClaimGateStatus::Blocked { .. }
        ));
    }
}
