//! Path discovery tests do not create or open vaults.
use std::path::PathBuf;

#[test]
fn vault_path_precedence() {
    const CASE: &str = "SSHENV_PATH_TEST_CASE";
    if let Ok(case) = std::env::var(CASE) {
        let check = || {
            let expected = match case.as_str() {
                "override" => PathBuf::from("explicit-vault"),
                "empty" => PathBuf::new(),
                _ => switchy_fs::directories::home_dir().map_or_else(
                    || PathBuf::from(".sshenv/vault"),
                    |home| home.join(".sshenv/vault"),
                ),
            };
            assert_eq!(sshenv_vault::default_vault_path(), expected);
        };
        #[cfg(feature = "simulated-directories")]
        {
            use std::sync::Arc;
            use switchy_fs::{
                directories::DirectoryLocations,
                simulator::{Filesystem, with_filesystem},
            };
            for home in [None, Some(PathBuf::from("virtual-home"))] {
                let fs = Arc::new(Filesystem::with_directory_locations(DirectoryLocations {
                    home: home.clone(),
                    ..DirectoryLocations::default()
                }));
                with_filesystem(&fs, || {
                    assert_eq!(switchy_fs::directories::home_dir(), home);
                    check();
                });
            }
        }
        #[cfg(not(feature = "simulated-directories"))]
        check();
        return;
    }
    for case in ["default", "override", "empty"] {
        let mut child = std::process::Command::new(std::env::current_exe().unwrap());
        child
            .args(["--exact", "vault_path_precedence"])
            .env(CASE, case)
            .env_remove("SSHENV_VAULT");
        if case != "default" {
            child.env(
                "SSHENV_VAULT",
                if case == "empty" {
                    ""
                } else {
                    "explicit-vault"
                },
            );
        }
        assert!(child.status().unwrap().success());
    }
}
