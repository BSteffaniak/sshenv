//! Compatibility re-exports for SSH identity discovery/loading.
//!
//! The reusable implementation lives in `sshenv_vault::identity` so other
//! applications can embed sshenv without depending on the CLI crate.

pub use sshenv_vault::identity::*;
