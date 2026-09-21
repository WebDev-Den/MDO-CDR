use file_defender::policy::DefensePolicy;
use file_defender::tenant::{
    HmacKeyRing, HmacTenantMediaLimitsSnapshot, HmacTenantPolicySnapshot,
    SignedTenantMediaLimitsSnapshot, SignedTenantPolicySnapshot, TenantDefenderRegistry,
    TenantMediaLimitsOverride, TenantMediaLimitsSnapshot, TenantOverrideProvenance,
    TenantPolicyRemoveResult, TenantPolicySnapshot, TenantPolicyUpdateResult, TenantPolicyVersion,
    TenantSnapshotImportReport,
};
use file_defender::{DefenderError, DefenseContext};

#[test]
fn tenant_registry_uses_tenant_snapshot_if_present() {
    let fallback = DefensePolicy::default();
    let tenant_policy = DefensePolicy {
        blocked_extensions: vec!["bin".to_string()],
        ..DefensePolicy::default()
    };
    let registry = TenantDefenderRegistry::with_seeded_tenants(
        fallback,
        [("enterprise".to_string(), tenant_policy)],
    );

    let result = registry.defend_bytes_for_tenant(
        Some("enterprise"),
        b"payload".to_vec(),
        Some("sample.bin".to_string()),
        DefenseContext::default(),
    );

    match result {
        Err(DefenderError::BlockedExtension { extension }) => {
            assert_eq!(extension, "bin");
        }
        other => panic!("expected BlockedExtension for tenant policy, got {other:?}"),
    }
}

#[test]
fn tenant_registry_falls_back_when_tenant_missing() {
    let fallback = DefensePolicy {
        blocked_extensions: vec!["bin".to_string()],
        ..DefensePolicy::default()
    };
    let registry = TenantDefenderRegistry::new(fallback);

    let result = registry.defend_bytes_for_tenant(
        Some("missing-tenant"),
        b"payload".to_vec(),
        Some("sample.bin".to_string()),
        DefenseContext::default(),
    );

    match result {
        Err(DefenderError::BlockedExtension { extension }) => {
            assert_eq!(extension, "bin");
        }
        other => panic!("expected fallback BlockedExtension, got {other:?}"),
    }
}

#[test]
fn tenant_registry_upsert_and_remove_are_visible() {
    let registry = TenantDefenderRegistry::new(DefensePolicy::default());
    let policy = DefensePolicy {
        blocked_extensions: vec!["txt".to_string()],
        ..DefensePolicy::default()
    };

    registry.upsert_tenant_policy("public", policy);
    let blocked = registry.defend_bytes_for_tenant(
        Some("public"),
        b"payload".to_vec(),
        Some("note.txt".to_string()),
        DefenseContext::default(),
    );
    match blocked {
        Err(DefenderError::BlockedExtension { extension }) => {
            assert_eq!(extension, "txt");
        }
        other => panic!("expected BlockedExtension for tenant upsert, got {other:?}"),
    }

    registry.remove_tenant_policy("public");
    let unblocked = registry.defend_bytes_for_tenant(
        Some("public"),
        b"payload".to_vec(),
        Some("note.txt".to_string()),
        DefenseContext::default(),
    );
    assert!(unblocked.is_ok());
}

#[test]
fn tenant_registry_rejects_stale_versioned_upsert() {
    let registry = TenantDefenderRegistry::new(DefensePolicy::default());
    let blocked_policy = DefensePolicy {
        blocked_extensions: vec!["txt".to_string()],
        ..DefensePolicy::default()
    };
    let allowed_policy = DefensePolicy::default();

    let applied =
        registry.upsert_tenant_policy_if_newer("streamed", TenantPolicyVersion(10), blocked_policy);
    assert_eq!(
        applied,
        TenantPolicyUpdateResult::Applied {
            version: TenantPolicyVersion(10)
        }
    );

    let stale =
        registry.upsert_tenant_policy_if_newer("streamed", TenantPolicyVersion(9), allowed_policy);
    assert_eq!(
        stale,
        TenantPolicyUpdateResult::IgnoredStale {
            current_version: TenantPolicyVersion(10)
        }
    );

    let result = registry.defend_bytes_for_tenant(
        Some("streamed"),
        b"payload".to_vec(),
        Some("note.txt".to_string()),
        DefenseContext::default(),
    );
    match result {
        Err(DefenderError::BlockedExtension { extension }) => {
            assert_eq!(extension, "txt");
        }
        other => panic!("expected latest policy to stay active, got {other:?}"),
    }
}

#[test]
fn tenant_registry_rejects_stale_versioned_remove() {
    let registry = TenantDefenderRegistry::new(DefensePolicy::default());
    let policy = DefensePolicy {
        blocked_extensions: vec!["txt".to_string()],
        ..DefensePolicy::default()
    };
    let applied =
        registry.upsert_tenant_policy_if_newer("streamed", TenantPolicyVersion(12), policy);
    assert_eq!(
        applied,
        TenantPolicyUpdateResult::Applied {
            version: TenantPolicyVersion(12)
        }
    );

    let stale_remove = registry.remove_tenant_policy_if_newer("streamed", TenantPolicyVersion(11));
    assert_eq!(
        stale_remove,
        TenantPolicyRemoveResult::IgnoredStale {
            current_version: TenantPolicyVersion(12)
        }
    );

    let applied_remove =
        registry.remove_tenant_policy_if_newer("streamed", TenantPolicyVersion(13));
    assert_eq!(
        applied_remove,
        TenantPolicyRemoveResult::Applied {
            version: TenantPolicyVersion(13)
        }
    );

    let stale_upsert = registry.upsert_tenant_policy_if_newer(
        "streamed",
        TenantPolicyVersion(12),
        DefensePolicy::default(),
    );
    assert_eq!(
        stale_upsert,
        TenantPolicyUpdateResult::IgnoredStale {
            current_version: TenantPolicyVersion(13)
        }
    );
}

#[test]
fn tenant_registry_can_export_and_import_snapshots() {
    let source = TenantDefenderRegistry::new(DefensePolicy::default());
    let policy = DefensePolicy {
        blocked_extensions: vec!["txt".to_string()],
        ..DefensePolicy::default()
    };
    let applied = source.upsert_tenant_policy_if_newer("tenant-a", TenantPolicyVersion(21), policy);
    assert_eq!(
        applied,
        TenantPolicyUpdateResult::Applied {
            version: TenantPolicyVersion(21)
        }
    );
    let remove = source.remove_tenant_policy_if_newer("tenant-b", TenantPolicyVersion(7));
    assert_eq!(
        remove,
        TenantPolicyRemoveResult::Applied {
            version: TenantPolicyVersion(7)
        }
    );

    let snapshots = source.export_snapshots();
    let target = TenantDefenderRegistry::new(DefensePolicy::default());
    let report = target.import_snapshots_if_newer(snapshots);
    assert_eq!(
        report,
        TenantSnapshotImportReport {
            upsert_applied: 1,
            upsert_ignored_stale: 0,
            remove_applied: 1,
            remove_ignored_stale: 0,
            remove_already_removed: 0,
            rejected_invalid_signature: 0,
        }
    );

    let blocked = target.defend_bytes_for_tenant(
        Some("tenant-a"),
        b"payload".to_vec(),
        Some("note.txt".to_string()),
        DefenseContext::default(),
    );
    match blocked {
        Err(DefenderError::BlockedExtension { extension }) => {
            assert_eq!(extension, "txt");
        }
        other => panic!("expected imported active policy to block txt, got {other:?}"),
    }

    let removed_fallback = target.defend_bytes_for_tenant(
        Some("tenant-b"),
        b"payload".to_vec(),
        Some("note.txt".to_string()),
        DefenseContext::default(),
    );
    match removed_fallback {
        Ok(_) => {}
        other => panic!("expected removed tenant to fallback, got {other:?}"),
    }
}

#[test]
fn tenant_registry_import_ignores_stale_snapshots() {
    let registry = TenantDefenderRegistry::new(DefensePolicy::default());
    let newer = DefensePolicy {
        blocked_extensions: vec!["txt".to_string()],
        ..DefensePolicy::default()
    };
    let first = registry.upsert_tenant_policy_if_newer("tenant-x", TenantPolicyVersion(30), newer);
    assert_eq!(
        first,
        TenantPolicyUpdateResult::Applied {
            version: TenantPolicyVersion(30)
        }
    );

    let stale = vec![
        TenantPolicySnapshot {
            tenant_id: "tenant-x".to_string(),
            version: TenantPolicyVersion(29),
            policy: Some(DefensePolicy::default()),
            provenance: None,
        },
        TenantPolicySnapshot {
            tenant_id: "tenant-y".to_string(),
            version: TenantPolicyVersion(5),
            policy: None,
            provenance: None,
        },
    ];
    let report = registry.import_snapshots_if_newer(stale);
    assert_eq!(
        report,
        TenantSnapshotImportReport {
            upsert_applied: 0,
            upsert_ignored_stale: 1,
            remove_applied: 1,
            remove_ignored_stale: 0,
            remove_already_removed: 0,
            rejected_invalid_signature: 0,
        }
    );

    let still_blocked = registry.defend_bytes_for_tenant(
        Some("tenant-x"),
        b"payload".to_vec(),
        Some("note.txt".to_string()),
        DefenseContext::default(),
    );
    match still_blocked {
        Err(DefenderError::BlockedExtension { extension }) => {
            assert_eq!(extension, "txt");
        }
        other => panic!("expected stale import to be ignored, got {other:?}"),
    }
}

#[test]
fn tenant_registry_imports_media_limit_overrides() {
    let registry = TenantDefenderRegistry::new(DefensePolicy::default());
    let base = DefensePolicy::default();
    let applied =
        registry.upsert_tenant_policy_if_newer("tenant-media", TenantPolicyVersion(40), base);
    assert_eq!(
        applied,
        TenantPolicyUpdateResult::Applied {
            version: TenantPolicyVersion(40)
        }
    );

    let overrides = vec![TenantMediaLimitsSnapshot {
        tenant_id: "tenant-media".to_string(),
        version: TenantPolicyVersion(41),
        limits: Some(TenantMediaLimitsOverride {
            video_max_duration_secs: Some(90),
            video_max_bitrate_kbps: Some(2500),
            audio_max_duration_secs: Some(70),
            audio_max_bitrate_kbps: Some(256),
            audio_max_channels: Some(1),
        }),
        provenance: None,
    }];
    let report = registry.import_media_limits_snapshots_if_newer(overrides);
    assert_eq!(
        report,
        TenantSnapshotImportReport {
            upsert_applied: 1,
            upsert_ignored_stale: 0,
            remove_applied: 0,
            remove_ignored_stale: 0,
            remove_already_removed: 0,
            rejected_invalid_signature: 0,
        }
    );

    let snapshots = registry.export_snapshots();
    let mut found = None;
    for snapshot in snapshots {
        if snapshot.tenant_id == "tenant-media" {
            found = Some(snapshot);
            break;
        }
    }
    let Some(snapshot) = found else {
        panic!("expected tenant-media snapshot after override import");
    };
    let Some(policy) = snapshot.policy else {
        panic!("expected tenant-media to remain active");
    };
    assert_eq!(policy.video.max_duration_secs, 90);
    assert_eq!(policy.video.max_bitrate_kbps, 2500);
    assert_eq!(policy.audio.max_duration_secs, 70);
    assert_eq!(policy.audio.max_bitrate_kbps, 256);
    assert_eq!(policy.audio.max_channels, 1);
}

#[test]
fn tenant_registry_clears_media_limit_override_without_dropping_base_policy() {
    let registry = TenantDefenderRegistry::new(DefensePolicy::default());
    let base = DefensePolicy {
        blocked_extensions: vec!["txt".to_string()],
        video: file_defender::policy::VideoPolicy {
            max_duration_secs: 180,
            ..DefensePolicy::default().video
        },
        ..DefensePolicy::default()
    };
    let seed = registry.upsert_tenant_policy_if_newer(
        "tenant-media-clear",
        TenantPolicyVersion(40),
        base.clone(),
    );
    assert_eq!(
        seed,
        TenantPolicyUpdateResult::Applied {
            version: TenantPolicyVersion(40)
        }
    );

    let apply = registry.import_media_limits_snapshots_if_newer([TenantMediaLimitsSnapshot {
        tenant_id: "tenant-media-clear".to_string(),
        version: TenantPolicyVersion(41),
        limits: Some(TenantMediaLimitsOverride {
            video_max_duration_secs: Some(90),
            video_max_bitrate_kbps: None,
            audio_max_duration_secs: None,
            audio_max_bitrate_kbps: None,
            audio_max_channels: None,
        }),
        provenance: Some(TenantOverrideProvenance {
            actor: "secops".to_string(),
            source: "runtime-hardening".to_string(),
            reason: Some("incident".to_string()),
            updated_at_unix_ms: 1_715_555_100_000,
        }),
    }]);
    assert_eq!(
        apply,
        TenantSnapshotImportReport {
            upsert_applied: 1,
            upsert_ignored_stale: 0,
            remove_applied: 0,
            remove_ignored_stale: 0,
            remove_already_removed: 0,
            rejected_invalid_signature: 0,
        }
    );

    let clear = registry.import_media_limits_snapshots_if_newer([TenantMediaLimitsSnapshot {
        tenant_id: "tenant-media-clear".to_string(),
        version: TenantPolicyVersion(42),
        limits: None,
        provenance: Some(TenantOverrideProvenance {
            actor: "secops".to_string(),
            source: "runtime-hardening".to_string(),
            reason: Some("resolved".to_string()),
            updated_at_unix_ms: 1_715_555_200_000,
        }),
    }]);
    assert_eq!(
        clear,
        TenantSnapshotImportReport {
            upsert_applied: 0,
            upsert_ignored_stale: 0,
            remove_applied: 1,
            remove_ignored_stale: 0,
            remove_already_removed: 0,
            rejected_invalid_signature: 0,
        }
    );

    let snapshots = registry.export_snapshots();
    let snapshot = snapshots
        .into_iter()
        .find(|value| value.tenant_id == "tenant-media-clear")
        .expect("expected tenant-media-clear snapshot after clearing override");
    let policy = snapshot
        .policy
        .expect("expected base tenant policy to remain after clearing override");
    assert_eq!(policy.video.max_duration_secs, 180);

    let result = registry.defend_bytes_for_tenant(
        Some("tenant-media-clear"),
        b"payload".to_vec(),
        Some("note.txt".to_string()),
        DefenseContext::default(),
    );
    match result {
        Err(DefenderError::BlockedExtension { extension }) => {
            assert_eq!(extension, "txt");
        }
        other => panic!("expected base tenant policy to remain active, got {other:?}"),
    }
}

#[test]
fn tenant_registry_ignores_stale_media_limit_overrides() {
    let registry = TenantDefenderRegistry::new(DefensePolicy::default());
    let seed = registry.upsert_tenant_policy_if_newer(
        "tenant-media",
        TenantPolicyVersion(50),
        DefensePolicy::default(),
    );
    assert_eq!(
        seed,
        TenantPolicyUpdateResult::Applied {
            version: TenantPolicyVersion(50)
        }
    );

    let stale = vec![TenantMediaLimitsSnapshot {
        tenant_id: "tenant-media".to_string(),
        version: TenantPolicyVersion(49),
        limits: Some(TenantMediaLimitsOverride {
            video_max_duration_secs: Some(45),
            video_max_bitrate_kbps: None,
            audio_max_duration_secs: None,
            audio_max_bitrate_kbps: None,
            audio_max_channels: None,
        }),
        provenance: None,
    }];
    let report = registry.import_media_limits_snapshots_if_newer(stale);
    assert_eq!(
        report,
        TenantSnapshotImportReport {
            upsert_applied: 0,
            upsert_ignored_stale: 1,
            remove_applied: 0,
            remove_ignored_stale: 0,
            remove_already_removed: 0,
            rejected_invalid_signature: 0,
        }
    );
}

#[test]
fn tenant_registry_preserves_override_provenance_on_import() {
    let registry = TenantDefenderRegistry::new(DefensePolicy::default());
    let snapshots = vec![TenantPolicySnapshot {
        tenant_id: "tenant-prov".to_string(),
        version: TenantPolicyVersion(77),
        policy: Some(DefensePolicy::default()),
        provenance: Some(TenantOverrideProvenance {
            actor: "secops-bot".to_string(),
            source: "control-plane".to_string(),
            reason: Some("incident-123".to_string()),
            updated_at_unix_ms: 1_715_555_000_000,
        }),
    }];

    let report = registry.import_snapshots_if_newer(snapshots);
    assert_eq!(
        report,
        TenantSnapshotImportReport {
            upsert_applied: 1,
            upsert_ignored_stale: 0,
            remove_applied: 0,
            remove_ignored_stale: 0,
            remove_already_removed: 0,
            rejected_invalid_signature: 0,
        }
    );

    let exported = registry.export_snapshots();
    let mut found = None;
    for snapshot in exported {
        if snapshot.tenant_id == "tenant-prov" {
            found = Some(snapshot);
            break;
        }
    }
    let Some(snapshot) = found else {
        panic!("expected tenant-prov snapshot");
    };
    let Some(provenance) = snapshot.provenance else {
        panic!("expected provenance after import");
    };
    assert_eq!(provenance.actor, "secops-bot");
    assert_eq!(provenance.source, "control-plane");
    assert_eq!(provenance.reason.as_deref(), Some("incident-123"));
    assert_eq!(provenance.updated_at_unix_ms, 1_715_555_000_000);
}

#[test]
fn tenant_registry_imports_signed_policy_snapshots_and_rejects_tampered() {
    let registry = TenantDefenderRegistry::new(DefensePolicy::default());
    let good = SignedTenantPolicySnapshot::sign(TenantPolicySnapshot {
        tenant_id: "tenant-signed".to_string(),
        version: TenantPolicyVersion(90),
        policy: Some(DefensePolicy {
            blocked_extensions: vec!["txt".to_string()],
            ..DefensePolicy::default()
        }),
        provenance: None,
    });
    let mut bad = SignedTenantPolicySnapshot::sign(TenantPolicySnapshot {
        tenant_id: "tenant-bad".to_string(),
        version: TenantPolicyVersion(91),
        policy: Some(DefensePolicy::default()),
        provenance: None,
    });
    bad.sha256 = "deadbeef".to_string();

    let report = registry.import_signed_snapshots_if_newer([good, bad]);
    assert_eq!(
        report,
        TenantSnapshotImportReport {
            upsert_applied: 1,
            upsert_ignored_stale: 0,
            remove_applied: 0,
            remove_ignored_stale: 0,
            remove_already_removed: 0,
            rejected_invalid_signature: 1,
        }
    );

    let result = registry.defend_bytes_for_tenant(
        Some("tenant-signed"),
        b"payload".to_vec(),
        Some("note.txt".to_string()),
        DefenseContext::default(),
    );
    match result {
        Err(DefenderError::BlockedExtension { extension }) => {
            assert_eq!(extension, "txt");
        }
        other => panic!("expected signed snapshot to be imported, got {other:?}"),
    }
}

#[test]
fn tenant_policy_signatures_distinguish_delimited_provenance_values() {
    let first = SignedTenantPolicySnapshot::sign(TenantPolicySnapshot {
        tenant_id: "tenant-signing".to_string(),
        version: TenantPolicyVersion(92),
        policy: Some(DefensePolicy::default()),
        provenance: Some(TenantOverrideProvenance {
            actor: "a|b".to_string(),
            source: "c".to_string(),
            reason: Some(String::new()),
            updated_at_unix_ms: 1,
        }),
    });
    let second = SignedTenantPolicySnapshot::sign(TenantPolicySnapshot {
        tenant_id: "tenant-signing".to_string(),
        version: TenantPolicyVersion(92),
        policy: Some(DefensePolicy::default()),
        provenance: Some(TenantOverrideProvenance {
            actor: "a".to_string(),
            source: "b|c".to_string(),
            reason: Some(String::new()),
            updated_at_unix_ms: 1,
        }),
    });

    assert_ne!(first.sha256, second.sha256);
}

#[test]
fn tenant_registry_imports_signed_media_snapshots_and_rejects_tampered() {
    let registry = TenantDefenderRegistry::new(DefensePolicy::default());
    let seed = registry.upsert_tenant_policy_if_newer(
        "tenant-media-signed",
        TenantPolicyVersion(100),
        DefensePolicy::default(),
    );
    assert_eq!(
        seed,
        TenantPolicyUpdateResult::Applied {
            version: TenantPolicyVersion(100)
        }
    );

    let good = SignedTenantMediaLimitsSnapshot::sign(TenantMediaLimitsSnapshot {
        tenant_id: "tenant-media-signed".to_string(),
        version: TenantPolicyVersion(101),
        limits: Some(TenantMediaLimitsOverride {
            video_max_duration_secs: Some(44),
            video_max_bitrate_kbps: None,
            audio_max_duration_secs: None,
            audio_max_bitrate_kbps: None,
            audio_max_channels: None,
        }),
        provenance: None,
    });
    let mut bad = SignedTenantMediaLimitsSnapshot::sign(TenantMediaLimitsSnapshot {
        tenant_id: "tenant-media-bad".to_string(),
        version: TenantPolicyVersion(102),
        limits: Some(TenantMediaLimitsOverride {
            video_max_duration_secs: Some(12),
            video_max_bitrate_kbps: None,
            audio_max_duration_secs: None,
            audio_max_bitrate_kbps: None,
            audio_max_channels: None,
        }),
        provenance: None,
    });
    bad.sha256 = "badc0de".to_string();

    let report = registry.import_signed_media_limits_snapshots_if_newer([good, bad]);
    assert_eq!(
        report,
        TenantSnapshotImportReport {
            upsert_applied: 1,
            upsert_ignored_stale: 0,
            remove_applied: 0,
            remove_ignored_stale: 0,
            remove_already_removed: 0,
            rejected_invalid_signature: 1,
        }
    );

    let snapshots = registry.export_snapshots();
    let mut found = None;
    for snapshot in snapshots {
        if snapshot.tenant_id == "tenant-media-signed" {
            found = Some(snapshot);
            break;
        }
    }
    let Some(snapshot) = found else {
        panic!("expected signed media snapshot import");
    };
    let Some(policy) = snapshot.policy else {
        panic!("expected active policy");
    };
    assert_eq!(policy.video.max_duration_secs, 44);
}

#[test]
fn tenant_media_signatures_distinguish_delimited_provenance_values() {
    let first = SignedTenantMediaLimitsSnapshot::sign(TenantMediaLimitsSnapshot {
        tenant_id: "tenant-media-signing".to_string(),
        version: TenantPolicyVersion(103),
        limits: Some(TenantMediaLimitsOverride {
            video_max_duration_secs: Some(44),
            video_max_bitrate_kbps: None,
            audio_max_duration_secs: None,
            audio_max_bitrate_kbps: None,
            audio_max_channels: None,
        }),
        provenance: Some(TenantOverrideProvenance {
            actor: "a|b".to_string(),
            source: "c".to_string(),
            reason: Some(String::new()),
            updated_at_unix_ms: 1,
        }),
    });
    let second = SignedTenantMediaLimitsSnapshot::sign(TenantMediaLimitsSnapshot {
        tenant_id: "tenant-media-signing".to_string(),
        version: TenantPolicyVersion(103),
        limits: Some(TenantMediaLimitsOverride {
            video_max_duration_secs: Some(44),
            video_max_bitrate_kbps: None,
            audio_max_duration_secs: None,
            audio_max_bitrate_kbps: None,
            audio_max_channels: None,
        }),
        provenance: Some(TenantOverrideProvenance {
            actor: "a".to_string(),
            source: "b|c".to_string(),
            reason: Some(String::new()),
            updated_at_unix_ms: 1,
        }),
    });

    assert_ne!(first.sha256, second.sha256);
}

#[test]
fn tenant_registry_imports_hmac_policy_snapshots_and_rejects_wrong_secret() {
    let registry = TenantDefenderRegistry::new(DefensePolicy::default());
    let secret = b"top-secret";
    let good = HmacTenantPolicySnapshot::sign(
        TenantPolicySnapshot {
            tenant_id: "tenant-hmac".to_string(),
            version: TenantPolicyVersion(200),
            policy: Some(DefensePolicy {
                blocked_extensions: vec!["txt".to_string()],
                ..DefensePolicy::default()
            }),
            provenance: None,
        },
        secret,
    );
    let bad = HmacTenantPolicySnapshot::sign(
        TenantPolicySnapshot {
            tenant_id: "tenant-hmac-bad".to_string(),
            version: TenantPolicyVersion(201),
            policy: Some(DefensePolicy::default()),
            provenance: None,
        },
        b"other-secret",
    );

    let report = registry.import_hmac_snapshots_if_newer([good, bad], secret);
    assert_eq!(
        report,
        TenantSnapshotImportReport {
            upsert_applied: 1,
            upsert_ignored_stale: 0,
            remove_applied: 0,
            remove_ignored_stale: 0,
            remove_already_removed: 0,
            rejected_invalid_signature: 1,
        }
    );
}

#[test]
fn tenant_registry_imports_hmac_media_snapshots_and_rejects_wrong_secret() {
    let registry = TenantDefenderRegistry::new(DefensePolicy::default());
    let seed = registry.upsert_tenant_policy_if_newer(
        "tenant-hmac-media",
        TenantPolicyVersion(300),
        DefensePolicy::default(),
    );
    assert_eq!(
        seed,
        TenantPolicyUpdateResult::Applied {
            version: TenantPolicyVersion(300)
        }
    );
    let secret = b"media-secret";
    let good = HmacTenantMediaLimitsSnapshot::sign(
        TenantMediaLimitsSnapshot {
            tenant_id: "tenant-hmac-media".to_string(),
            version: TenantPolicyVersion(301),
            limits: Some(TenantMediaLimitsOverride {
                video_max_duration_secs: Some(33),
                video_max_bitrate_kbps: None,
                audio_max_duration_secs: None,
                audio_max_bitrate_kbps: None,
                audio_max_channels: None,
            }),
            provenance: None,
        },
        secret,
    );
    let bad = HmacTenantMediaLimitsSnapshot::sign(
        TenantMediaLimitsSnapshot {
            tenant_id: "tenant-hmac-media-bad".to_string(),
            version: TenantPolicyVersion(302),
            limits: Some(TenantMediaLimitsOverride {
                video_max_duration_secs: Some(11),
                video_max_bitrate_kbps: None,
                audio_max_duration_secs: None,
                audio_max_bitrate_kbps: None,
                audio_max_channels: None,
            }),
            provenance: None,
        },
        b"bad-media-secret",
    );

    let report = registry.import_hmac_media_limits_snapshots_if_newer([good, bad], secret);
    assert_eq!(
        report,
        TenantSnapshotImportReport {
            upsert_applied: 1,
            upsert_ignored_stale: 0,
            remove_applied: 0,
            remove_ignored_stale: 0,
            remove_already_removed: 0,
            rejected_invalid_signature: 1,
        }
    );
}

#[test]
fn tenant_registry_accepts_previous_key_during_rotation() {
    let registry = TenantDefenderRegistry::new(DefensePolicy::default());
    let snapshot = HmacTenantPolicySnapshot::sign_with_key(
        TenantPolicySnapshot {
            tenant_id: "tenant-rotate".to_string(),
            version: TenantPolicyVersion(400),
            policy: Some(DefensePolicy {
                blocked_extensions: vec!["txt".to_string()],
                ..DefensePolicy::default()
            }),
            provenance: None,
        },
        "old-key",
        b"old-secret",
    );
    let keyring = HmacKeyRing::new("new-key", b"new-secret".to_vec())
        .with_key("old-key", b"old-secret".to_vec());
    let report = registry.import_hmac_snapshots_with_keyring_if_newer([snapshot], &keyring);
    assert_eq!(
        report,
        TenantSnapshotImportReport {
            upsert_applied: 1,
            upsert_ignored_stale: 0,
            remove_applied: 0,
            remove_ignored_stale: 0,
            remove_already_removed: 0,
            rejected_invalid_signature: 0,
        }
    );
}

#[test]
fn tenant_registry_rejects_unknown_key_id_after_rotation() {
    let registry = TenantDefenderRegistry::new(DefensePolicy::default());
    let snapshot = HmacTenantMediaLimitsSnapshot::sign_with_key(
        TenantMediaLimitsSnapshot {
            tenant_id: "tenant-rotate-media".to_string(),
            version: TenantPolicyVersion(401),
            limits: Some(TenantMediaLimitsOverride {
                video_max_duration_secs: Some(10),
                video_max_bitrate_kbps: None,
                audio_max_duration_secs: None,
                audio_max_bitrate_kbps: None,
                audio_max_channels: None,
            }),
            provenance: None,
        },
        "old-key",
        b"old-secret",
    );
    let keyring = HmacKeyRing::new("new-key", b"new-secret".to_vec());
    let report =
        registry.import_hmac_media_limits_snapshots_with_keyring_if_newer([snapshot], &keyring);
    assert_eq!(
        report,
        TenantSnapshotImportReport {
            upsert_applied: 0,
            upsert_ignored_stale: 0,
            remove_applied: 0,
            remove_ignored_stale: 0,
            remove_already_removed: 0,
            rejected_invalid_signature: 1,
        }
    );
}

#[test]
fn tenant_registry_allows_deprecated_key_within_grace_window() {
    let registry = TenantDefenderRegistry::new(DefensePolicy::default());
    let snapshot = HmacTenantPolicySnapshot::sign_with_key(
        TenantPolicySnapshot {
            tenant_id: "tenant-grace".to_string(),
            version: TenantPolicyVersion(500),
            policy: Some(DefensePolicy {
                blocked_extensions: vec!["txt".to_string()],
                ..DefensePolicy::default()
            }),
            provenance: None,
        },
        "old-key",
        b"old-secret",
    );
    let mut keyring = HmacKeyRing::new("new-key", b"new-secret".to_vec())
        .with_key("old-key", b"old-secret".to_vec())
        .with_grace_period_ms(10_000);
    let deprecated_set = keyring.deprecate_key_at("old-key", 1_000);
    assert!(deprecated_set);

    let report =
        registry.import_hmac_snapshots_with_keyring_at_if_newer([snapshot], &keyring, 9_000);
    assert_eq!(
        report,
        TenantSnapshotImportReport {
            upsert_applied: 1,
            upsert_ignored_stale: 0,
            remove_applied: 0,
            remove_ignored_stale: 0,
            remove_already_removed: 0,
            rejected_invalid_signature: 0,
        }
    );
}

#[test]
fn tenant_registry_rejects_deprecated_key_after_grace_window() {
    let registry = TenantDefenderRegistry::new(DefensePolicy::default());
    let snapshot = HmacTenantPolicySnapshot::sign_with_key(
        TenantPolicySnapshot {
            tenant_id: "tenant-expired".to_string(),
            version: TenantPolicyVersion(501),
            policy: Some(DefensePolicy::default()),
            provenance: None,
        },
        "old-key",
        b"old-secret",
    );
    let mut keyring = HmacKeyRing::new("new-key", b"new-secret".to_vec())
        .with_key("old-key", b"old-secret".to_vec())
        .with_grace_period_ms(10_000);
    let deprecated_set = keyring.deprecate_key_at("old-key", 1_000);
    assert!(deprecated_set);

    let report =
        registry.import_hmac_snapshots_with_keyring_at_if_newer([snapshot], &keyring, 11_001);
    assert_eq!(
        report,
        TenantSnapshotImportReport {
            upsert_applied: 0,
            upsert_ignored_stale: 0,
            remove_applied: 0,
            remove_ignored_stale: 0,
            remove_already_removed: 0,
            rejected_invalid_signature: 1,
        }
    );
}

#[test]
fn tenant_registry_tracks_hmac_key_usage_metrics() {
    let registry = TenantDefenderRegistry::new(DefensePolicy::default());
    let mut keyring = HmacKeyRing::new("active-key", b"active-secret".to_vec())
        .with_key("old-key", b"old-secret".to_vec())
        .with_grace_period_ms(10_000);
    let deprecated_set = keyring.deprecate_key_at("old-key", 1_000);
    assert!(deprecated_set);

    let valid_in_grace = HmacTenantPolicySnapshot::sign_with_key(
        TenantPolicySnapshot {
            tenant_id: "tenant-metrics".to_string(),
            version: TenantPolicyVersion(600),
            policy: Some(DefensePolicy::default()),
            provenance: None,
        },
        "old-key",
        b"old-secret",
    );
    let invalid_sig = HmacTenantPolicySnapshot::sign_with_key(
        TenantPolicySnapshot {
            tenant_id: "tenant-metrics-2".to_string(),
            version: TenantPolicyVersion(601),
            policy: Some(DefensePolicy::default()),
            provenance: None,
        },
        "active-key",
        b"wrong-secret",
    );
    let unknown_key = HmacTenantPolicySnapshot::sign_with_key(
        TenantPolicySnapshot {
            tenant_id: "tenant-metrics-3".to_string(),
            version: TenantPolicyVersion(602),
            policy: Some(DefensePolicy::default()),
            provenance: None,
        },
        "missing-key",
        b"missing-secret",
    );
    let expired = HmacTenantPolicySnapshot::sign_with_key(
        TenantPolicySnapshot {
            tenant_id: "tenant-metrics-4".to_string(),
            version: TenantPolicyVersion(603),
            policy: Some(DefensePolicy::default()),
            provenance: None,
        },
        "old-key",
        b"old-secret",
    );

    let _ =
        registry.import_hmac_snapshots_with_keyring_at_if_newer([valid_in_grace], &keyring, 5_000);
    let _ = registry.import_hmac_snapshots_with_keyring_at_if_newer([invalid_sig], &keyring, 5_000);
    let _ = registry.import_hmac_snapshots_with_keyring_at_if_newer([unknown_key], &keyring, 5_000);
    let _ = registry.import_hmac_snapshots_with_keyring_at_if_newer([expired], &keyring, 20_000);

    let usage = keyring.usage_snapshot();
    let old = usage.get("old-key").expect("old-key usage expected");
    assert_eq!(old.verified, 1);
    assert_eq!(old.verified_in_grace, 1);
    assert_eq!(old.rejected_expired, 1);
    let active = usage.get("active-key").expect("active-key usage expected");
    assert_eq!(active.rejected_invalid_signature, 1);
    let missing = usage
        .get("missing-key")
        .expect("missing-key usage expected");
    assert_eq!(missing.rejected_unknown_key, 1);
}
