#![cfg(feature = "simulator")]

use sshenv_vault::{DataKey, Vault};

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
