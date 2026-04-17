//! Data structures for shim bindings.
//!
//! A *binding* pairs a profile name with a command name. Each binding
//! yields one shim script: `~/.sshenv/bin/<command>` that execs
//! `sshenv run <profile> -- <command> "$@"`.

use serde::{Deserialize, Serialize};

/// One shim binding: "when you run `<command>`, load secrets from
/// `<profile>` first."
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Binding {
    pub profile: String,
    pub command: String,
}

/// The full bindings file, deserialized from `~/.sshenv/bindings.toml`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BindingsFile {
    /// Optional override for the shim output directory. When `None`,
    /// defaults to `$SSHENV_SHIM_DIR` or `~/.sshenv/bin`.
    pub shim_dir: Option<String>,

    /// The bindings, deserialized from `[[binding]]` TOML tables.
    #[serde(default, rename = "binding")]
    pub bindings: Vec<Binding>,
}

/// Errors for the shims models crate.
#[derive(Debug, thiserror::Error)]
pub enum ShimsModelsError {
    #[error("command '{command}' is already bound to profile '{existing}'")]
    DuplicateCommand { command: String, existing: String },
}

impl BindingsFile {
    /// Look up the profile bound to `command`, if any.
    #[must_use]
    pub fn find_by_command(&self, command: &str) -> Option<&Binding> {
        self.bindings.iter().find(|b| b.command == command)
    }

    /// All unique commands bound under a given profile (sorted).
    #[must_use]
    pub fn commands_for_profile(&self, profile: &str) -> Vec<String> {
        let mut v: Vec<String> = self
            .bindings
            .iter()
            .filter(|b| b.profile == profile)
            .map(|b| b.command.clone())
            .collect();
        v.sort();
        v
    }

    /// Insert a new binding, rejecting if `command` is already bound to a
    /// different profile. If the same profile+command pair is already
    /// present, returns `Ok(false)` (idempotent).
    ///
    /// # Errors
    ///
    /// Returns an error if `command` is already bound to a different
    /// profile.
    pub fn add(&mut self, profile: &str, command: &str) -> Result<bool, ShimsModelsError> {
        if let Some(existing) = self.find_by_command(command) {
            if existing.profile == profile {
                return Ok(false);
            }
            return Err(ShimsModelsError::DuplicateCommand {
                command: command.to_string(),
                existing: existing.profile.clone(),
            });
        }
        self.bindings.push(Binding {
            profile: profile.to_string(),
            command: command.to_string(),
        });
        self.sort();
        Ok(true)
    }

    /// Remove the binding for `command`. Returns `true` if one was
    /// removed.
    pub fn remove_by_command(&mut self, command: &str) -> bool {
        let before = self.bindings.len();
        self.bindings.retain(|b| b.command != command);
        self.bindings.len() < before
    }

    fn sort(&mut self) {
        self.bindings.sort_by(|a, b| {
            a.profile
                .cmp(&b.profile)
                .then_with(|| a.command.cmp(&b.command))
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_then_find() {
        let mut f = BindingsFile::default();
        f.add("p1", "c1").unwrap();
        assert_eq!(f.find_by_command("c1").unwrap().profile, "p1");
    }

    #[test]
    fn add_same_pair_is_idempotent() {
        let mut f = BindingsFile::default();
        assert!(f.add("p1", "c1").unwrap());
        assert!(!f.add("p1", "c1").unwrap());
    }

    #[test]
    fn add_conflicting_command_fails() {
        let mut f = BindingsFile::default();
        f.add("p1", "c1").unwrap();
        let err = f.add("p2", "c1").unwrap_err();
        assert!(matches!(err, ShimsModelsError::DuplicateCommand { .. }));
    }

    #[test]
    fn remove_returns_presence() {
        let mut f = BindingsFile::default();
        f.add("p1", "c1").unwrap();
        assert!(f.remove_by_command("c1"));
        assert!(!f.remove_by_command("c1"));
    }

    #[test]
    fn commands_for_profile_is_sorted() {
        let mut f = BindingsFile::default();
        f.add("p", "beta").unwrap();
        f.add("p", "alpha").unwrap();
        f.add("p", "gamma").unwrap();
        assert_eq!(f.commands_for_profile("p"), vec!["alpha", "beta", "gamma"]);
    }
}
