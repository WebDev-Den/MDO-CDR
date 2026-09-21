use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use arc_swap::ArcSwap;
use hmac::{Hmac, Mac};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::FileDefender;
use crate::error::DefenderError;
use crate::policy::DefensePolicy;
use crate::types::{DefendResult, DefenseContext, SignatureLocation};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct TenantPolicyVersion(pub u64);

impl TenantPolicyVersion {
    pub const fn initial() -> Self {
        Self(1)
    }

    pub const fn next(self) -> Self {
        Self(self.0.saturating_add(1))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TenantPolicyUpdateResult {
    Applied {
        version: TenantPolicyVersion,
    },
    IgnoredStale {
        current_version: TenantPolicyVersion,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TenantPolicyRemoveResult {
    Applied {
        version: TenantPolicyVersion,
    },
    IgnoredStale {
        current_version: TenantPolicyVersion,
    },
    AlreadyRemoved {
        version: TenantPolicyVersion,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TenantOverrideProvenance {
    pub actor: String,
    pub source: String,
    pub reason: Option<String>,
    pub updated_at_unix_ms: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct TenantMediaLimitsOverride {
    pub video_max_duration_secs: Option<u64>,
    pub video_max_bitrate_kbps: Option<u64>,
    pub audio_max_duration_secs: Option<u64>,
    pub audio_max_bitrate_kbps: Option<u64>,
    pub audio_max_channels: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct TenantPolicySnapshot {
    pub tenant_id: String,
    pub version: TenantPolicyVersion,
    pub policy: Option<DefensePolicy>,
    pub provenance: Option<TenantOverrideProvenance>,
}

#[derive(Debug, Clone)]
pub struct SignedTenantPolicySnapshot {
    pub snapshot: TenantPolicySnapshot,
    pub sha256: String,
}

#[derive(Debug, Clone)]
pub struct HmacTenantPolicySnapshot {
    pub snapshot: TenantPolicySnapshot,
    pub key_id: String,
    pub hmac_sha256: String,
}

#[derive(Debug, Clone)]
pub struct TenantMediaLimitsSnapshot {
    pub tenant_id: String,
    pub version: TenantPolicyVersion,
    pub limits: Option<TenantMediaLimitsOverride>,
    pub provenance: Option<TenantOverrideProvenance>,
}

#[derive(Debug, Clone)]
pub struct SignedTenantMediaLimitsSnapshot {
    pub snapshot: TenantMediaLimitsSnapshot,
    pub sha256: String,
}

#[derive(Debug, Clone)]
pub struct HmacTenantMediaLimitsSnapshot {
    pub snapshot: TenantMediaLimitsSnapshot,
    pub key_id: String,
    pub hmac_sha256: String,
}

#[derive(Debug, Clone)]
pub struct HmacKeyRing {
    active_key_id: String,
    keys: HashMap<String, HmacKeyEntry>,
    grace_period_ms: u64,
    usage: Arc<Mutex<HashMap<String, HmacKeyUsageStats>>>,
}

#[derive(Debug, Clone)]
struct HmacKeyEntry {
    secret: Vec<u8>,
    deprecated_after_unix_ms: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct HmacKeyUsageStats {
    pub seen: u64,
    pub verified: u64,
    pub verified_in_grace: u64,
    pub rejected_unknown_key: u64,
    pub rejected_expired: u64,
    pub rejected_invalid_signature: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HmacVerificationOutcome {
    VerifiedCurrent,
    VerifiedInGrace,
    RejectedUnknownKey,
    RejectedExpired,
    RejectedInvalidSignature,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TenantSnapshotImportReport {
    pub upsert_applied: usize,
    pub upsert_ignored_stale: usize,
    pub remove_applied: usize,
    pub remove_ignored_stale: usize,
    pub remove_already_removed: usize,
    pub rejected_invalid_signature: usize,
}

#[derive(Debug, Clone)]
struct TenantPolicySlot {
    version: TenantPolicyVersion,
    defender: Option<Arc<FileDefender>>,
    policy: Option<DefensePolicy>,
    provenance: Option<TenantOverrideProvenance>,
    media_limits: Option<TenantMediaLimitsOverride>,
    media_provenance: Option<TenantOverrideProvenance>,
}

#[derive(Debug)]
pub struct TenantDefenderRegistry {
    fallback: Arc<FileDefender>,
    snapshots: ArcSwap<HashMap<String, TenantPolicySlot>>,
}

impl TenantDefenderRegistry {
    pub fn new(fallback_policy: DefensePolicy) -> Self {
        Self {
            fallback: Arc::new(FileDefender::new(fallback_policy)),
            snapshots: ArcSwap::from_pointee(HashMap::new()),
        }
    }

    pub fn with_seeded_tenants(
        fallback_policy: DefensePolicy,
        tenants: impl IntoIterator<Item = (String, DefensePolicy)>,
    ) -> Self {
        let mut seeded = HashMap::new();
        for (tenant_id, policy) in tenants {
            seeded.insert(
                tenant_id,
                build_tenant_slot(
                    TenantPolicyVersion::initial(),
                    Some(policy),
                    None,
                    None,
                    None,
                    &fallback_policy,
                ),
            );
        }
        Self {
            fallback: Arc::new(FileDefender::new(fallback_policy)),
            snapshots: ArcSwap::from_pointee(seeded),
        }
    }

    pub fn upsert_tenant_policy(&self, tenant_id: impl Into<String>, policy: DefensePolicy) {
        self.upsert_tenant_policy_with_provenance(tenant_id, policy, None);
    }

    pub fn upsert_tenant_policy_with_provenance(
        &self,
        tenant_id: impl Into<String>,
        policy: DefensePolicy,
        provenance: Option<TenantOverrideProvenance>,
    ) {
        let tenant_id = tenant_id.into();
        let mut current = self.snapshots.load();
        loop {
            let mut next = current.as_ref().clone();
            let next_version = match next.get(&tenant_id) {
                Some(TenantPolicySlot {
                    version,
                    defender: _,
                    policy: _,
                    provenance: _,
                    media_limits: _,
                    media_provenance: _,
                }) => version.next(),
                None => TenantPolicyVersion::initial(),
            };
            next.insert(
                tenant_id.clone(),
                build_tenant_slot(
                    next_version,
                    Some(policy.clone()),
                    provenance.clone(),
                    None,
                    None,
                    self.fallback.policy(),
                ),
            );
            let previous = self.snapshots.compare_and_swap(&*current, Arc::new(next));
            let swapped = Arc::as_ptr(&*current) == Arc::as_ptr(&*previous);
            if swapped {
                return;
            }
            current = previous;
        }
    }

    pub fn remove_tenant_policy(&self, tenant_id: &str) {
        let mut current = self.snapshots.load();
        loop {
            let mut next = current.as_ref().clone();
            let next_version = match next.get(tenant_id) {
                Some(TenantPolicySlot {
                    version,
                    defender: _,
                    policy: _,
                    provenance: _,
                    media_limits: _,
                    media_provenance: _,
                }) => version.next(),
                None => TenantPolicyVersion::initial(),
            };
            next.insert(
                tenant_id.to_string(),
                build_tenant_slot(next_version, None, None, None, None, self.fallback.policy()),
            );
            let previous = self.snapshots.compare_and_swap(&*current, Arc::new(next));
            let swapped = Arc::as_ptr(&*current) == Arc::as_ptr(&*previous);
            if swapped {
                return;
            }
            current = previous;
        }
    }

    pub fn upsert_tenant_policy_if_newer(
        &self,
        tenant_id: impl Into<String>,
        version: TenantPolicyVersion,
        policy: DefensePolicy,
    ) -> TenantPolicyUpdateResult {
        self.upsert_tenant_policy_if_newer_with_provenance(tenant_id, version, policy, None)
    }

    pub fn upsert_tenant_policy_if_newer_with_provenance(
        &self,
        tenant_id: impl Into<String>,
        version: TenantPolicyVersion,
        policy: DefensePolicy,
        provenance: Option<TenantOverrideProvenance>,
    ) -> TenantPolicyUpdateResult {
        let tenant_id = tenant_id.into();
        let mut current = self.snapshots.load();
        loop {
            let mut next = current.as_ref().clone();
            let existing = next.get(&tenant_id);
            if let Some(TenantPolicySlot {
                version: current_version,
                defender: _,
                policy: _,
                provenance: _,
                media_limits: _,
                media_provenance: _,
            }) = existing
                && *current_version >= version
            {
                return TenantPolicyUpdateResult::IgnoredStale {
                    current_version: *current_version,
                };
            }
            next.insert(
                tenant_id.clone(),
                build_tenant_slot(
                    version,
                    Some(policy.clone()),
                    provenance.clone(),
                    None,
                    None,
                    self.fallback.policy(),
                ),
            );
            let previous = self.snapshots.compare_and_swap(&*current, Arc::new(next));
            let swapped = Arc::as_ptr(&*current) == Arc::as_ptr(&*previous);
            if swapped {
                return TenantPolicyUpdateResult::Applied { version };
            }
            current = previous;
        }
    }

    pub fn remove_tenant_policy_if_newer(
        &self,
        tenant_id: &str,
        version: TenantPolicyVersion,
    ) -> TenantPolicyRemoveResult {
        let mut current = self.snapshots.load();
        loop {
            let mut next = current.as_ref().clone();
            let existing = next.get(tenant_id);
            if let Some(TenantPolicySlot {
                version: current_version,
                defender,
                policy: _,
                provenance: _,
                media_limits: _,
                media_provenance: _,
            }) = existing
            {
                if *current_version > version {
                    return TenantPolicyRemoveResult::IgnoredStale {
                        current_version: *current_version,
                    };
                }
                if *current_version == version && defender.is_none() {
                    return TenantPolicyRemoveResult::AlreadyRemoved { version };
                }
            }
            next.insert(
                tenant_id.to_string(),
                build_tenant_slot(version, None, None, None, None, self.fallback.policy()),
            );
            let previous = self.snapshots.compare_and_swap(&*current, Arc::new(next));
            let swapped = Arc::as_ptr(&*current) == Arc::as_ptr(&*previous);
            if swapped {
                return TenantPolicyRemoveResult::Applied { version };
            }
            current = previous;
        }
    }

    pub fn resolve(&self, tenant_id: Option<&str>) -> Arc<FileDefender> {
        if let Some(tenant_id) = tenant_id {
            let current = self.snapshots.load();
            if let Some(TenantPolicySlot {
                version: _,
                defender: Some(defender),
                policy: _,
                provenance: _,
                media_limits: _,
                media_provenance: _,
            }) = current.get(tenant_id)
            {
                return Arc::clone(defender);
            }
        }
        Arc::clone(&self.fallback)
    }

    pub fn export_snapshots(&self) -> Vec<TenantPolicySnapshot> {
        let current = self.snapshots.load();
        let mut output = Vec::new();
        for (tenant_id, slot) in current.as_ref() {
            output.push(TenantPolicySnapshot {
                tenant_id: tenant_id.clone(),
                version: slot.version,
                policy: materialize_tenant_policy(
                    slot.policy.as_ref(),
                    slot.media_limits.as_ref(),
                    self.fallback.policy(),
                ),
                provenance: effective_snapshot_provenance(slot),
            });
        }
        output
    }

    pub fn import_snapshots_if_newer(
        &self,
        snapshots: impl IntoIterator<Item = TenantPolicySnapshot>,
    ) -> TenantSnapshotImportReport {
        let mut report = empty_import_report();
        for TenantPolicySnapshot {
            tenant_id,
            version,
            policy,
            provenance,
        } in snapshots
        {
            if let Some(policy) = policy {
                let update = self.upsert_tenant_policy_if_newer_with_provenance(
                    tenant_id, version, policy, provenance,
                );
                match update {
                    TenantPolicyUpdateResult::Applied { version: _ } => {
                        report.upsert_applied += 1;
                    }
                    TenantPolicyUpdateResult::IgnoredStale { current_version: _ } => {
                        report.upsert_ignored_stale += 1;
                    }
                }
                continue;
            }
            let remove = self.remove_tenant_policy_if_newer(&tenant_id, version);
            match remove {
                TenantPolicyRemoveResult::Applied { version: _ } => {
                    report.remove_applied += 1;
                }
                TenantPolicyRemoveResult::IgnoredStale { current_version: _ } => {
                    report.remove_ignored_stale += 1;
                }
                TenantPolicyRemoveResult::AlreadyRemoved { version: _ } => {
                    report.remove_already_removed += 1;
                }
            }
        }
        report
    }

    pub fn import_signed_snapshots_if_newer(
        &self,
        snapshots: impl IntoIterator<Item = SignedTenantPolicySnapshot>,
    ) -> TenantSnapshotImportReport {
        let mut report = empty_import_report();
        for signed in snapshots {
            if !signed.verify() {
                report.rejected_invalid_signature += 1;
                continue;
            }
            let import = self.import_snapshots_if_newer([signed.snapshot]);
            report.upsert_applied += import.upsert_applied;
            report.upsert_ignored_stale += import.upsert_ignored_stale;
            report.remove_applied += import.remove_applied;
            report.remove_ignored_stale += import.remove_ignored_stale;
            report.remove_already_removed += import.remove_already_removed;
            report.rejected_invalid_signature += import.rejected_invalid_signature;
        }
        report
    }

    pub fn import_media_limits_snapshots_if_newer(
        &self,
        snapshots: impl IntoIterator<Item = TenantMediaLimitsSnapshot>,
    ) -> TenantSnapshotImportReport {
        let mut report = empty_import_report();
        for TenantMediaLimitsSnapshot {
            tenant_id,
            version,
            limits,
            provenance,
        } in snapshots
        {
            if let Some(limits) = limits {
                let update = self
                    .upsert_tenant_media_limits_if_newer(tenant_id, version, limits, provenance);
                match update {
                    TenantPolicyUpdateResult::Applied { version: _ } => {
                        report.upsert_applied += 1;
                    }
                    TenantPolicyUpdateResult::IgnoredStale { current_version: _ } => {
                        report.upsert_ignored_stale += 1;
                    }
                }
                continue;
            }
            let remove = self.clear_tenant_media_limits_if_newer(&tenant_id, version);
            match remove {
                TenantPolicyRemoveResult::Applied { version: _ } => {
                    report.remove_applied += 1;
                }
                TenantPolicyRemoveResult::IgnoredStale { current_version: _ } => {
                    report.remove_ignored_stale += 1;
                }
                TenantPolicyRemoveResult::AlreadyRemoved { version: _ } => {
                    report.remove_already_removed += 1;
                }
            }
        }
        report
    }

    pub fn import_hmac_snapshots_if_newer(
        &self,
        snapshots: impl IntoIterator<Item = HmacTenantPolicySnapshot>,
        secret: &[u8],
    ) -> TenantSnapshotImportReport {
        let mut report = empty_import_report();
        for signed in snapshots {
            if !signed.verify(secret) {
                report.rejected_invalid_signature += 1;
                continue;
            }
            let import = self.import_snapshots_if_newer([signed.snapshot]);
            report.upsert_applied += import.upsert_applied;
            report.upsert_ignored_stale += import.upsert_ignored_stale;
            report.remove_applied += import.remove_applied;
            report.remove_ignored_stale += import.remove_ignored_stale;
            report.remove_already_removed += import.remove_already_removed;
            report.rejected_invalid_signature += import.rejected_invalid_signature;
        }
        report
    }

    pub fn import_hmac_snapshots_with_keyring_if_newer(
        &self,
        snapshots: impl IntoIterator<Item = HmacTenantPolicySnapshot>,
        keyring: &HmacKeyRing,
    ) -> TenantSnapshotImportReport {
        self.import_hmac_snapshots_with_keyring_at_if_newer(snapshots, keyring, current_unix_ms())
    }

    pub fn import_hmac_snapshots_with_keyring_at_if_newer(
        &self,
        snapshots: impl IntoIterator<Item = HmacTenantPolicySnapshot>,
        keyring: &HmacKeyRing,
        now_unix_ms: u64,
    ) -> TenantSnapshotImportReport {
        let mut report = empty_import_report();
        for signed in snapshots {
            let outcome = signed.verify_with_keyring_outcome(keyring, now_unix_ms);
            if !matches!(
                outcome,
                HmacVerificationOutcome::VerifiedCurrent | HmacVerificationOutcome::VerifiedInGrace
            ) {
                report.rejected_invalid_signature += 1;
                continue;
            }
            let import = self.import_snapshots_if_newer([signed.snapshot]);
            report.upsert_applied += import.upsert_applied;
            report.upsert_ignored_stale += import.upsert_ignored_stale;
            report.remove_applied += import.remove_applied;
            report.remove_ignored_stale += import.remove_ignored_stale;
            report.remove_already_removed += import.remove_already_removed;
            report.rejected_invalid_signature += import.rejected_invalid_signature;
        }
        report
    }

    pub fn import_signed_media_limits_snapshots_if_newer(
        &self,
        snapshots: impl IntoIterator<Item = SignedTenantMediaLimitsSnapshot>,
    ) -> TenantSnapshotImportReport {
        let mut report = empty_import_report();
        for signed in snapshots {
            if !signed.verify() {
                report.rejected_invalid_signature += 1;
                continue;
            }
            let import = self.import_media_limits_snapshots_if_newer([signed.snapshot]);
            report.upsert_applied += import.upsert_applied;
            report.upsert_ignored_stale += import.upsert_ignored_stale;
            report.remove_applied += import.remove_applied;
            report.remove_ignored_stale += import.remove_ignored_stale;
            report.remove_already_removed += import.remove_already_removed;
            report.rejected_invalid_signature += import.rejected_invalid_signature;
        }
        report
    }

    pub fn import_hmac_media_limits_snapshots_if_newer(
        &self,
        snapshots: impl IntoIterator<Item = HmacTenantMediaLimitsSnapshot>,
        secret: &[u8],
    ) -> TenantSnapshotImportReport {
        let mut report = empty_import_report();
        for signed in snapshots {
            if !signed.verify(secret) {
                report.rejected_invalid_signature += 1;
                continue;
            }
            let import = self.import_media_limits_snapshots_if_newer([signed.snapshot]);
            report.upsert_applied += import.upsert_applied;
            report.upsert_ignored_stale += import.upsert_ignored_stale;
            report.remove_applied += import.remove_applied;
            report.remove_ignored_stale += import.remove_ignored_stale;
            report.remove_already_removed += import.remove_already_removed;
            report.rejected_invalid_signature += import.rejected_invalid_signature;
        }
        report
    }

    pub fn import_hmac_media_limits_snapshots_with_keyring_if_newer(
        &self,
        snapshots: impl IntoIterator<Item = HmacTenantMediaLimitsSnapshot>,
        keyring: &HmacKeyRing,
    ) -> TenantSnapshotImportReport {
        self.import_hmac_media_limits_snapshots_with_keyring_at_if_newer(
            snapshots,
            keyring,
            current_unix_ms(),
        )
    }

    pub fn import_hmac_media_limits_snapshots_with_keyring_at_if_newer(
        &self,
        snapshots: impl IntoIterator<Item = HmacTenantMediaLimitsSnapshot>,
        keyring: &HmacKeyRing,
        now_unix_ms: u64,
    ) -> TenantSnapshotImportReport {
        let mut report = empty_import_report();
        for signed in snapshots {
            let outcome = signed.verify_with_keyring_outcome(keyring, now_unix_ms);
            if !matches!(
                outcome,
                HmacVerificationOutcome::VerifiedCurrent | HmacVerificationOutcome::VerifiedInGrace
            ) {
                report.rejected_invalid_signature += 1;
                continue;
            }
            let import = self.import_media_limits_snapshots_if_newer([signed.snapshot]);
            report.upsert_applied += import.upsert_applied;
            report.upsert_ignored_stale += import.upsert_ignored_stale;
            report.remove_applied += import.remove_applied;
            report.remove_ignored_stale += import.remove_ignored_stale;
            report.remove_already_removed += import.remove_already_removed;
            report.rejected_invalid_signature += import.rejected_invalid_signature;
        }
        report
    }

    fn upsert_tenant_media_limits_if_newer(
        &self,
        tenant_id: impl Into<String>,
        version: TenantPolicyVersion,
        limits: TenantMediaLimitsOverride,
        provenance: Option<TenantOverrideProvenance>,
    ) -> TenantPolicyUpdateResult {
        let tenant_id = tenant_id.into();
        let mut current = self.snapshots.load();
        loop {
            let mut next = current.as_ref().clone();
            let existing = next.get(&tenant_id);
            if let Some(TenantPolicySlot {
                version: current_version,
                defender: _,
                policy: _,
                provenance: _,
                media_limits: _,
                media_provenance: _,
            }) = existing
                && *current_version >= version
            {
                return TenantPolicyUpdateResult::IgnoredStale {
                    current_version: *current_version,
                };
            }
            let base_policy = existing.and_then(|slot| slot.policy.clone());
            let policy_provenance = existing.and_then(|slot| slot.provenance.clone());
            next.insert(
                tenant_id.clone(),
                build_tenant_slot(
                    version,
                    base_policy,
                    policy_provenance,
                    Some(limits.clone()),
                    provenance.clone(),
                    self.fallback.policy(),
                ),
            );
            let previous = self.snapshots.compare_and_swap(&*current, Arc::new(next));
            let swapped = Arc::as_ptr(&*current) == Arc::as_ptr(&*previous);
            if swapped {
                return TenantPolicyUpdateResult::Applied { version };
            }
            current = previous;
        }
    }

    fn clear_tenant_media_limits_if_newer(
        &self,
        tenant_id: &str,
        version: TenantPolicyVersion,
    ) -> TenantPolicyRemoveResult {
        let mut current = self.snapshots.load();
        loop {
            let mut next = current.as_ref().clone();
            let existing = next.get(tenant_id);
            if let Some(TenantPolicySlot {
                version: current_version,
                defender: _,
                policy: _,
                provenance: _,
                media_limits,
                media_provenance: _,
            }) = existing
            {
                if *current_version > version {
                    return TenantPolicyRemoveResult::IgnoredStale {
                        current_version: *current_version,
                    };
                }
                if *current_version == version && media_limits.is_none() {
                    return TenantPolicyRemoveResult::AlreadyRemoved { version };
                }
            }

            let (base_policy, policy_provenance) = if let Some(slot) = existing {
                (slot.policy.clone(), slot.provenance.clone())
            } else {
                (None, None)
            };

            next.insert(
                tenant_id.to_string(),
                build_tenant_slot(
                    version,
                    base_policy,
                    policy_provenance,
                    None,
                    None,
                    self.fallback.policy(),
                ),
            );
            let previous = self.snapshots.compare_and_swap(&*current, Arc::new(next));
            let swapped = Arc::as_ptr(&*current) == Arc::as_ptr(&*previous);
            if swapped {
                return TenantPolicyRemoveResult::Applied { version };
            }
            current = previous;
        }
    }

    pub fn defend_bytes_for_tenant(
        &self,
        tenant_id: Option<&str>,
        input_bytes: Vec<u8>,
        file_name: Option<String>,
        mut context: DefenseContext,
    ) -> Result<DefendResult, DefenderError> {
        if let Some(tenant_id) = tenant_id {
            context.tenant_id = Some(tenant_id.to_string());
        }
        self.resolve(tenant_id)
            .defend_bytes(input_bytes, file_name, context)
    }
}

impl SignedTenantPolicySnapshot {
    pub fn sign(snapshot: TenantPolicySnapshot) -> Self {
        let canonical = canonical_policy_snapshot_payload(&snapshot);
        let sha256 = sha256_hex(&canonical);
        Self { snapshot, sha256 }
    }

    pub fn verify(&self) -> bool {
        let canonical = canonical_policy_snapshot_payload(&self.snapshot);
        let digest = sha256_hex(&canonical);
        digest == self.sha256
    }
}

impl HmacTenantPolicySnapshot {
    pub fn sign(snapshot: TenantPolicySnapshot, secret: &[u8]) -> Self {
        Self::sign_with_key(snapshot, "default", secret)
    }

    pub fn sign_with_key(
        snapshot: TenantPolicySnapshot,
        key_id: impl Into<String>,
        secret: &[u8],
    ) -> Self {
        let key_id = key_id.into();
        let canonical = canonical_policy_snapshot_payload(&snapshot);
        let hmac_sha256 = hmac_sha256_hex(secret, &canonical);
        Self {
            snapshot,
            key_id,
            hmac_sha256,
        }
    }

    pub fn verify(&self, secret: &[u8]) -> bool {
        let canonical = canonical_policy_snapshot_payload(&self.snapshot);
        let digest = hmac_sha256_hex(secret, &canonical);
        digest == self.hmac_sha256
    }

    pub fn verify_with_keyring(&self, keyring: &HmacKeyRing) -> bool {
        self.verify_with_keyring_outcome(keyring, current_unix_ms())
            .is_verified()
    }

    pub fn verify_with_keyring_at(&self, keyring: &HmacKeyRing, now_unix_ms: u64) -> bool {
        self.verify_with_keyring_outcome(keyring, now_unix_ms)
            .is_verified()
    }

    fn verify_with_keyring_outcome(
        &self,
        keyring: &HmacKeyRing,
        now_unix_ms: u64,
    ) -> HmacVerificationOutcome {
        let canonical = canonical_policy_snapshot_payload(&self.snapshot);
        keyring.verify_digest(
            &self.key_id,
            &canonical,
            self.hmac_sha256.as_str(),
            now_unix_ms,
        )
    }
}

impl SignedTenantMediaLimitsSnapshot {
    pub fn sign(snapshot: TenantMediaLimitsSnapshot) -> Self {
        let canonical = canonical_media_snapshot_payload(&snapshot);
        let sha256 = sha256_hex(&canonical);
        Self { snapshot, sha256 }
    }

    pub fn verify(&self) -> bool {
        let canonical = canonical_media_snapshot_payload(&self.snapshot);
        let digest = sha256_hex(&canonical);
        digest == self.sha256
    }
}

impl HmacTenantMediaLimitsSnapshot {
    pub fn sign(snapshot: TenantMediaLimitsSnapshot, secret: &[u8]) -> Self {
        Self::sign_with_key(snapshot, "default", secret)
    }

    pub fn sign_with_key(
        snapshot: TenantMediaLimitsSnapshot,
        key_id: impl Into<String>,
        secret: &[u8],
    ) -> Self {
        let key_id = key_id.into();
        let canonical = canonical_media_snapshot_payload(&snapshot);
        let hmac_sha256 = hmac_sha256_hex(secret, &canonical);
        Self {
            snapshot,
            key_id,
            hmac_sha256,
        }
    }

    pub fn verify(&self, secret: &[u8]) -> bool {
        let canonical = canonical_media_snapshot_payload(&self.snapshot);
        let digest = hmac_sha256_hex(secret, &canonical);
        digest == self.hmac_sha256
    }

    pub fn verify_with_keyring(&self, keyring: &HmacKeyRing) -> bool {
        self.verify_with_keyring_outcome(keyring, current_unix_ms())
            .is_verified()
    }

    pub fn verify_with_keyring_at(&self, keyring: &HmacKeyRing, now_unix_ms: u64) -> bool {
        self.verify_with_keyring_outcome(keyring, now_unix_ms)
            .is_verified()
    }

    fn verify_with_keyring_outcome(
        &self,
        keyring: &HmacKeyRing,
        now_unix_ms: u64,
    ) -> HmacVerificationOutcome {
        let canonical = canonical_media_snapshot_payload(&self.snapshot);
        keyring.verify_digest(
            &self.key_id,
            &canonical,
            self.hmac_sha256.as_str(),
            now_unix_ms,
        )
    }
}

impl HmacKeyRing {
    pub fn new(active_key_id: impl Into<String>, active_secret: impl Into<Vec<u8>>) -> Self {
        let active_key_id = active_key_id.into();
        let mut keys = HashMap::new();
        keys.insert(
            active_key_id.clone(),
            HmacKeyEntry {
                secret: active_secret.into(),
                deprecated_after_unix_ms: None,
            },
        );
        Self {
            active_key_id,
            keys,
            grace_period_ms: 0,
            usage: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn insert_key(&mut self, key_id: impl Into<String>, secret: impl Into<Vec<u8>>) {
        let key_id = key_id.into();
        self.keys.insert(
            key_id,
            HmacKeyEntry {
                secret: secret.into(),
                deprecated_after_unix_ms: None,
            },
        );
    }

    pub fn with_key(mut self, key_id: impl Into<String>, secret: impl Into<Vec<u8>>) -> Self {
        self.insert_key(key_id, secret);
        self
    }

    pub fn active_key_id(&self) -> &str {
        &self.active_key_id
    }

    pub fn secret_for(&self, key_id: &str) -> Option<&[u8]> {
        let key = self.keys.get(key_id)?;
        Some(key.secret.as_slice())
    }

    pub fn set_grace_period_ms(&mut self, grace_period_ms: u64) {
        self.grace_period_ms = grace_period_ms;
    }

    pub fn with_grace_period_ms(mut self, grace_period_ms: u64) -> Self {
        self.set_grace_period_ms(grace_period_ms);
        self
    }

    pub fn deprecate_key_at(&mut self, key_id: &str, deprecated_after_unix_ms: u64) -> bool {
        let Some(entry) = self.keys.get_mut(key_id) else {
            return false;
        };
        entry.deprecated_after_unix_ms = Some(deprecated_after_unix_ms);
        true
    }

    pub fn usage_snapshot(&self) -> HashMap<String, HmacKeyUsageStats> {
        let Ok(usage) = self.usage.lock() else {
            return HashMap::new();
        };
        usage.clone()
    }

    fn verify_digest(
        &self,
        key_id: &str,
        payload: &[u8],
        provided_digest: &str,
        now_unix_ms: u64,
    ) -> HmacVerificationOutcome {
        let Some(entry) = self.keys.get(key_id) else {
            self.record_usage(key_id, HmacVerificationOutcome::RejectedUnknownKey);
            return HmacVerificationOutcome::RejectedUnknownKey;
        };
        let state = if let Some(deprecated_after_unix_ms) = entry.deprecated_after_unix_ms {
            let expires_at = deprecated_after_unix_ms.saturating_add(self.grace_period_ms);
            if now_unix_ms > expires_at {
                self.record_usage(key_id, HmacVerificationOutcome::RejectedExpired);
                return HmacVerificationOutcome::RejectedExpired;
            }
            HmacVerificationOutcome::VerifiedInGrace
        } else {
            HmacVerificationOutcome::VerifiedCurrent
        };
        let expected = hmac_sha256_hex(entry.secret.as_slice(), payload);
        if expected == provided_digest {
            self.record_usage(key_id, state);
            return state;
        }
        self.record_usage(key_id, HmacVerificationOutcome::RejectedInvalidSignature);
        HmacVerificationOutcome::RejectedInvalidSignature
    }

    fn record_usage(&self, key_id: &str, outcome: HmacVerificationOutcome) {
        let Ok(mut usage) = self.usage.lock() else {
            return;
        };
        let entry = usage.entry(key_id.to_string()).or_default();
        entry.seen = entry.seen.saturating_add(1);
        match outcome {
            HmacVerificationOutcome::VerifiedCurrent => {
                entry.verified = entry.verified.saturating_add(1);
            }
            HmacVerificationOutcome::VerifiedInGrace => {
                entry.verified = entry.verified.saturating_add(1);
                entry.verified_in_grace = entry.verified_in_grace.saturating_add(1);
            }
            HmacVerificationOutcome::RejectedUnknownKey => {
                entry.rejected_unknown_key = entry.rejected_unknown_key.saturating_add(1);
            }
            HmacVerificationOutcome::RejectedExpired => {
                entry.rejected_expired = entry.rejected_expired.saturating_add(1);
            }
            HmacVerificationOutcome::RejectedInvalidSignature => {
                entry.rejected_invalid_signature =
                    entry.rejected_invalid_signature.saturating_add(1);
            }
        }
    }
}

impl HmacVerificationOutcome {
    fn is_verified(self) -> bool {
        matches!(
            self,
            HmacVerificationOutcome::VerifiedCurrent | HmacVerificationOutcome::VerifiedInGrace
        )
    }
}

fn empty_import_report() -> TenantSnapshotImportReport {
    TenantSnapshotImportReport {
        upsert_applied: 0,
        upsert_ignored_stale: 0,
        remove_applied: 0,
        remove_ignored_stale: 0,
        remove_already_removed: 0,
        rejected_invalid_signature: 0,
    }
}

fn apply_media_limits_override(policy: &mut DefensePolicy, limits: &TenantMediaLimitsOverride) {
    if let Some(value) = limits.video_max_duration_secs {
        policy.video.max_duration_secs = value;
    }
    if let Some(value) = limits.video_max_bitrate_kbps {
        policy.video.max_bitrate_kbps = value;
    }
    if let Some(value) = limits.audio_max_duration_secs {
        policy.audio.max_duration_secs = value;
    }
    if let Some(value) = limits.audio_max_bitrate_kbps {
        policy.audio.max_bitrate_kbps = value;
    }
    if let Some(value) = limits.audio_max_channels {
        policy.audio.max_channels = value;
    }
}

fn materialize_tenant_policy(
    base_policy: Option<&DefensePolicy>,
    media_limits: Option<&TenantMediaLimitsOverride>,
    fallback_policy: &DefensePolicy,
) -> Option<DefensePolicy> {
    match (base_policy, media_limits) {
        (Some(policy), Some(limits)) => {
            let mut effective = policy.clone();
            apply_media_limits_override(&mut effective, limits);
            Some(effective)
        }
        (Some(policy), None) => Some(policy.clone()),
        (None, Some(limits)) => {
            let mut effective = fallback_policy.clone();
            apply_media_limits_override(&mut effective, limits);
            Some(effective)
        }
        (None, None) => None,
    }
}

fn build_tenant_slot(
    version: TenantPolicyVersion,
    policy: Option<DefensePolicy>,
    provenance: Option<TenantOverrideProvenance>,
    media_limits: Option<TenantMediaLimitsOverride>,
    media_provenance: Option<TenantOverrideProvenance>,
    fallback_policy: &DefensePolicy,
) -> TenantPolicySlot {
    let effective_policy =
        materialize_tenant_policy(policy.as_ref(), media_limits.as_ref(), fallback_policy);
    let defender = effective_policy.map(|value| Arc::new(FileDefender::new(value)));
    TenantPolicySlot {
        version,
        defender,
        policy,
        provenance,
        media_limits,
        media_provenance,
    }
}

fn effective_snapshot_provenance(slot: &TenantPolicySlot) -> Option<TenantOverrideProvenance> {
    if slot.media_limits.is_some() {
        return slot
            .media_provenance
            .clone()
            .or_else(|| slot.provenance.clone());
    }
    slot.provenance.clone()
}

#[derive(Serialize)]
struct CanonicalPolicySnapshotPayload<'a> {
    tenant_id: &'a str,
    version: u64,
    policy: Option<CanonicalDefensePolicy<'a>>,
    provenance: Option<&'a TenantOverrideProvenance>,
}

#[derive(Serialize)]
struct CanonicalMediaSnapshotPayload<'a> {
    tenant_id: &'a str,
    version: u64,
    limits: Option<&'a TenantMediaLimitsOverride>,
    provenance: Option<&'a TenantOverrideProvenance>,
}

#[derive(Serialize)]
struct CanonicalDefensePolicy<'a> {
    minimum_reconstruction_level: crate::policy::ReconstructionLevel,
    max_handler_duration_ms: u64,
    max_input_size_bytes: u64,
    max_output_size_bytes: u64,
    max_output_expansion_ratio: f64,
    enforce_output_kind_match: bool,
    block_on_unknown_output_mime: bool,
    enforce_output_mime_whitelist: bool,
    output_mime_whitelist: &'a crate::policy::OutputMimeWhitelist,
    output_mime_denylist: &'a [String],
    enforcement_mode: crate::policy::EnforcementMode,
    block_kind_mismatch: bool,
    unknown_kind_mode: crate::policy::UnknownKindMode,
    decoder_failure_mode: crate::policy::DecoderFailureMode,
    signature_scan_mode: crate::policy::SignatureScanMode,
    block_on_pre_scan_match: bool,
    blocked_extensions: &'a [String],
    signature_rules: Vec<CanonicalSignatureRule<'a>>,
    image: &'a crate::policy::ImagePolicy,
    animated_image: &'a crate::policy::AnimatedImagePolicy,
    gif: &'a crate::policy::GifPolicy,
    video: &'a crate::policy::VideoPolicy,
    audio: &'a crate::policy::AudioPolicy,
    other: &'a crate::policy::OtherPolicy,
}

#[derive(Serialize)]
struct CanonicalSignatureRule<'a> {
    name: &'a str,
    pattern_hex: String,
    location: CanonicalSignatureLocation,
}

#[derive(Serialize)]
enum CanonicalSignatureLocation {
    Anywhere,
    FirstBytes(u64),
    LastBytes(u64),
}

fn canonical_defense_policy(policy: &DefensePolicy) -> CanonicalDefensePolicy<'_> {
    CanonicalDefensePolicy {
        minimum_reconstruction_level: policy.minimum_reconstruction_level,
        max_handler_duration_ms: policy.max_handler_duration_ms,
        max_input_size_bytes: policy.max_input_size_bytes,
        max_output_size_bytes: policy.max_output_size_bytes,
        max_output_expansion_ratio: policy.max_output_expansion_ratio,
        enforce_output_kind_match: policy.enforce_output_kind_match,
        block_on_unknown_output_mime: policy.block_on_unknown_output_mime,
        enforce_output_mime_whitelist: policy.enforce_output_mime_whitelist,
        output_mime_whitelist: &policy.output_mime_whitelist,
        output_mime_denylist: &policy.output_mime_denylist,
        enforcement_mode: policy.enforcement_mode,
        block_kind_mismatch: policy.block_kind_mismatch,
        unknown_kind_mode: policy.unknown_kind_mode,
        decoder_failure_mode: policy.decoder_failure_mode,
        signature_scan_mode: policy.signature_scan_mode,
        block_on_pre_scan_match: policy.block_on_pre_scan_match,
        blocked_extensions: &policy.blocked_extensions,
        signature_rules: policy
            .signature_rules
            .iter()
            .map(canonical_signature_rule)
            .collect(),
        image: &policy.image,
        animated_image: &policy.animated_image,
        gif: &policy.gif,
        video: &policy.video,
        audio: &policy.audio,
        other: &policy.other,
    }
}

fn canonical_signature_rule(rule: &crate::types::SignatureRule) -> CanonicalSignatureRule<'_> {
    CanonicalSignatureRule {
        name: rule.name.as_str(),
        pattern_hex: hex::encode(&rule.pattern),
        location: canonical_signature_location(&rule.location),
    }
}

fn canonical_signature_location(location: &SignatureLocation) -> CanonicalSignatureLocation {
    match location {
        SignatureLocation::Anywhere => CanonicalSignatureLocation::Anywhere,
        SignatureLocation::FirstBytes(limit) => CanonicalSignatureLocation::FirstBytes(*limit),
        SignatureLocation::LastBytes(limit) => CanonicalSignatureLocation::LastBytes(*limit),
    }
}

fn canonical_policy_snapshot_payload(snapshot: &TenantPolicySnapshot) -> Vec<u8> {
    serde_json::to_vec(&CanonicalPolicySnapshotPayload {
        tenant_id: snapshot.tenant_id.as_str(),
        version: snapshot.version.0,
        policy: snapshot.policy.as_ref().map(canonical_defense_policy),
        provenance: snapshot.provenance.as_ref(),
    })
    .expect("tenant policy snapshot payload should serialize")
}

fn canonical_media_snapshot_payload(snapshot: &TenantMediaLimitsSnapshot) -> Vec<u8> {
    serde_json::to_vec(&CanonicalMediaSnapshotPayload {
        tenant_id: snapshot.tenant_id.as_str(),
        version: snapshot.version.0,
        limits: snapshot.limits.as_ref(),
        provenance: snapshot.provenance.as_ref(),
    })
    .expect("tenant media snapshot payload should serialize")
}

fn sha256_hex(payload: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(payload);
    let digest = hasher.finalize();
    hex::encode(digest)
}

fn hmac_sha256_hex(secret: &[u8], payload: &[u8]) -> String {
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(secret).expect("hmac accepts any key length");
    mac.update(payload);
    let digest = mac.finalize().into_bytes();
    hex::encode(digest)
}

fn current_unix_ms() -> u64 {
    let Ok(duration) = SystemTime::now().duration_since(UNIX_EPOCH) else {
        return 0;
    };
    duration.as_millis() as u64
}
