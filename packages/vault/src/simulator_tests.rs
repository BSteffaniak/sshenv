use crate::{DataKey, Vault, recipient::build_entry_for_public_key_line};

#[cfg(feature = "device-seal")]
#[test]
fn independent_sealed_lifecycles_repeat_with_selected_custody() {
    fn run() -> Vec<u8> {
        let (mut vault, key) =
            Vault::create_with_data_key("sim-age:sealed", DataKey::new([1; 32])).unwrap();
        vault.migrate_to_v2(&["sim-age:sealed".into()]).unwrap();
        vault.enable_profile_keys().unwrap();
        vault.profiles.set("provider", "TOKEN", "synthetic".into());
        let factor = crate::models::UnlockFactorV2 {
            id: "synthetic-device".into(),
            kind: crate::models::UnlockFactorKindV2::DeviceSeal,
            recipient_fingerprint: None,
            params: std::collections::BTreeMap::new(),
        };
        vault
            .enable_device_seal_factor_with(|| {
                Ok((factor.clone(), zeroize::Zeroizing::new([3; 32])))
            })
            .unwrap();
        vault
            .require_profile_device_seal_with("provider", || {
                Ok((factor.clone(), zeroize::Zeroizing::new([3; 32])))
            })
            .unwrap();
        let mut stored = Vec::new();
        vault
            .save_with_effects(
                &key,
                || Ok(DataKey::new([2; 32])),
                |bytes, expected| {
                    assert!(expected.is_none());
                    stored = bytes.to_vec();
                    Ok(())
                },
            )
            .unwrap();
        let mut calls = 0;
        let mut derive = |metadata: &crate::models::UnlockFactorV2| {
            calls += 1;
            assert_eq!(metadata, &factor);
            Ok(zeroize::Zeroizing::new([3; 32]))
        };
        let (mut opened, _) = Vault::unlock_metadata_with_data_key_and_device_factor(
            Vault::decode_ciphertext(&stored).unwrap(),
            DataKey::new(*key),
            None,
            &mut derive,
        )
        .unwrap();
        assert!(opened.profiles.get("provider").is_none());
        opened
            .unlock_profile_with_device_factor("provider", &key, None, &mut derive)
            .unwrap();
        assert_eq!(calls, 2);
        assert_eq!(
            opened.profiles.get("provider").unwrap()["TOKEN"],
            "synthetic"
        );
        opened.profiles.set("provider", "TOKEN", "updated".into());
        opened
            .save_with_effects(
                &key,
                || Ok(DataKey::new([2; 32])),
                |bytes, expected| {
                    assert!(expected.is_some());
                    stored = bytes.to_vec();
                    Ok(())
                },
            )
            .unwrap();
        let (updated, _) = Vault::unlock_with_data_key_and_device_factor(
            Vault::decode_ciphertext(&stored).unwrap(),
            DataKey::new(*key),
            None,
            |_| Ok(zeroize::Zeroizing::new([3; 32])),
        )
        .unwrap();
        assert_eq!(
            updated.profiles.get("provider").unwrap()["TOKEN"],
            "updated"
        );
        stored
    }
    assert_eq!(run(), run());
}

#[test]
fn rejects_invalid_simulation_identities() {
    for identity in ["", "sim-age:", "age:alice", "ssh-ed25519 real"] {
        assert!(build_entry_for_public_key_line(identity, &[1; 32]).is_err());
    }
}

#[test]
fn rejects_invalid_simulation_key_lengths() {
    for len in [0, 10, 31, 33] {
        let err = build_entry_for_public_key_line("sim-age:alice", &vec![1; len]).unwrap_err();
        assert!(
            err.to_string()
                .contains("invalid simulation data key length")
        );
    }
}

#[test]
fn independent_simulated_vault_lifecycles_repeat_and_reject_wrong_identity() {
    fn run() -> Vec<u8> {
        let (mut vault, key) =
            Vault::create_with_data_key("sim-age:alice", DataKey::new([1; 32])).unwrap();
        vault.migrate_to_v2(&["sim-age:alice".into()]).unwrap();
        vault.enable_profile_keys().unwrap();
        vault.profiles.set("provider", "TOKEN", "synthetic".into());
        let mut stored = Vec::new();
        vault
            .save_with_effects(
                &key,
                || Ok(DataKey::new([2; 32])),
                |bytes, expected| {
                    assert!(expected.is_none());
                    stored = bytes.to_vec();
                    Ok(())
                },
            )
            .unwrap();
        assert!(
            Vault::unlock_with_identity_strings(
                Vault::decode_ciphertext(&stored).unwrap(),
                &["sim-age:bob"],
                None
            )
            .is_err()
        );
        let (mut opened, reopened_key) = Vault::unlock_with_identity_strings(
            Vault::decode_ciphertext(&stored).unwrap(),
            &["sim-age:alice"],
            None,
        )
        .unwrap();
        assert_eq!(
            opened
                .profiles
                .get("provider")
                .unwrap()
                .get("TOKEN")
                .unwrap(),
            "synthetic"
        );
        assert!(opened.profile_keys_enabled());
        opened.profiles.set("provider", "TOKEN", "updated".into());
        opened
            .save_with_effects(
                &reopened_key,
                || Ok(DataKey::new([3; 32])),
                |bytes, expected| {
                    assert!(expected.is_some());
                    stored = bytes.to_vec();
                    Ok(())
                },
            )
            .unwrap();
        let (updated, _) = Vault::unlock_with_identity_strings(
            Vault::decode_ciphertext(&stored).unwrap(),
            &["sim-age:alice"],
            None,
        )
        .unwrap();
        assert_eq!(
            updated
                .profiles
                .get("provider")
                .unwrap()
                .get("TOKEN")
                .unwrap(),
            "updated"
        );
        stored
    }
    assert_eq!(run(), run());
    assert!(Vault::create_with_data_key("ssh-ed25519 real", DataKey::new([1; 32])).is_err());
}
