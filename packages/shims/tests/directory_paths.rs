use sshenv_shims_models::BindingsFile;
use std::path::PathBuf;

#[test]
fn shim_path_precedence() {
    const CASE: &str = "SSHENV_SHIM_PATH_TEST";
    if let Ok(case) = std::env::var(CASE) {
        let check = || {
            let home = switchy_fs::directories::home_dir();
            let base = home.map_or_else(|| PathBuf::from(".sshenv"), |h| h.join(".sshenv"));
            let expected_bindings = match case.as_str() {
                "override" => PathBuf::from("environment-bindings"),
                "empty" => PathBuf::new(),
                _ => base.join("bindings.toml"),
            };
            let expected_shims = match case.as_str() {
                "override" => PathBuf::from("environment-bin"),
                "empty" => PathBuf::new(),
                _ => base.join("bin"),
            };
            assert_eq!(sshenv_shims::default_bindings_path(), expected_bindings);
            assert_eq!(
                sshenv_shims::resolve_shim_dir(&BindingsFile::default()),
                expected_shims
            );
            let bindings = BindingsFile {
                shim_dir: Some("explicit-bin".into()),
                ..BindingsFile::default()
            };
            assert_eq!(
                sshenv_shims::resolve_shim_dir(&bindings),
                PathBuf::from("explicit-bin")
            );
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
                    home,
                    ..DirectoryLocations::default()
                }));
                with_filesystem(&fs, check);
            }
        }
        #[cfg(not(feature = "simulated-directories"))]
        check();
        return;
    }
    for case in ["default", "override", "empty"] {
        let mut child = std::process::Command::new(std::env::current_exe().unwrap());
        child
            .args(["--exact", "shim_path_precedence"])
            .env(CASE, case)
            .env_remove("SSHENV_BINDINGS")
            .env_remove("SSHENV_SHIM_DIR");
        if case != "default" {
            child.env(
                "SSHENV_BINDINGS",
                if case == "empty" {
                    ""
                } else {
                    "environment-bindings"
                },
            );
            child.env(
                "SSHENV_SHIM_DIR",
                if case == "empty" {
                    ""
                } else {
                    "environment-bin"
                },
            );
        }
        assert!(child.status().unwrap().success());
    }
}
