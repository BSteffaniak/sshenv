//! Shared CLI argument types for `sshenv`.

#![allow(clippy::multiple_crate_versions)]

use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};

/// SSH-key-backed encrypted vault for environment variables.
#[derive(Debug, Parser)]
#[command(
    name = "sshenv",
    version,
    about = "SSH-key-backed encrypted vault for environment variables",
    long_about = "sshenv manages an encrypted vault of environment variables, \
                  unlocked by any of the SSH keys on your machine. Run shell \
                  commands with per-profile env vars injected via `sshenv run` \
                  or via PATH shims bound with `sshenv shims bind`.",
    propagate_version = true,
    disable_help_subcommand = true
)]
pub struct Cli {
    /// Override the vault file path (default: `~/.sshenv/vault` or
    /// `$SSHENV_VAULT`).
    #[arg(long, global = true, value_name = "PATH")]
    pub vault: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Create a new vault.
    Init(InitArgs),
    /// Run checks on the vault, recipients, and shim setup.
    Doctor,
    /// Rotate the vault data key while preserving current recipients.
    RotateKey(RotateKeyArgs),
    /// Explicitly migrate a vault to a newer format.
    MigrateVault(MigrateVaultArgs),
    /// Inspect and configure security posture.
    #[command(subcommand)]
    Security(SecurityCommand),

    /// Add an SSH public key as a recipient authorized to unlock the
    /// vault.
    AddRecipient(AddRecipientArgs),
    /// List all recipients.
    ListRecipients(ListRecipientsArgs),
    /// Remove a recipient by fingerprint.
    RemoveRecipient(RemoveRecipientArgs),

    /// Set a variable in a profile.
    Set(SetArgs),
    /// Remove a variable from a profile.
    Unset(UnsetArgs),
    /// List profile names, or variables in a profile.
    List(ListArgs),
    /// Print the values of every variable in a profile to stdout.
    Show(ShowArgs),
    /// Delete an entire profile.
    RmProfile(RmProfileArgs),
    /// Rename an entire profile.
    RenameProfile(RenameProfileArgs),

    /// Run a command with a profile's environment vars loaded.
    Run(RunArgs),
    /// Print `export VAR=value` lines for a profile to stdout.
    Export(ExportArgs),

    /// List or signal tracked `sshenv run` executions.
    #[command(subcommand)]
    Sessions(SessionsCommand),

    /// Manage PATH shims.
    #[command(subcommand)]
    Shims(ShimsCommand),
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum VaultFormatVersionArg {
    V2,
}

#[derive(Debug, clap::Args)]
pub struct MigrateVaultArgs {
    /// Target vault format version.
    #[arg(long, value_enum)]
    pub to: VaultFormatVersionArg,
    /// Public key for a current recipient. Repeat for each recipient that
    /// cannot be discovered from local `~/.ssh/*.pub` files.
    #[arg(long = "recipient-key", value_name = "PATH_OR_LINE")]
    pub recipient_keys: Vec<String>,
}

#[derive(Debug, clap::Args)]
pub struct RotateKeyArgs {
    /// Public key for a current recipient. Repeat for each recipient that
    /// cannot be discovered from local `~/.ssh/*.pub` files.
    #[arg(long = "recipient-key", value_name = "PATH_OR_LINE")]
    pub recipient_keys: Vec<String>,
}

#[derive(Debug, Subcommand)]
pub enum SecurityCommand {
    /// Show vault version, enabled hardening features, and key-strength hints.
    Status,
    /// Require a passphrase factor in addition to SSH recipient unlock.
    EnablePassphrase(EnablePassphraseArgs),
    /// Change the existing sshenv vault passphrase factor.
    ChangePassphrase(ChangePassphraseArgs),
    /// Remove the existing sshenv vault passphrase factor.
    DisablePassphrase(DisablePassphraseArgs),
    /// Require a local device seal in addition to SSH recipient unlock.
    EnableDeviceSeal,
    /// Apply a named security preset.
    Preset(SecurityPresetArgs),
    /// Manage advisory per-profile security policy metadata.
    #[command(subcommand)]
    ProfilePolicy(ProfilePolicyCommand),
}

#[derive(Debug, Subcommand)]
pub enum ProfilePolicyCommand {
    /// List profile policy metadata.
    List,
    /// Show effective security posture for one profile.
    Status(ProfilePolicyStatusArgs),
    /// Store profiles as independently encrypted v2 payload entries.
    Migrate,
    /// Rotate one profile's per-profile data key.
    RotateKey(ProfilePolicyRotateKeyArgs),
    /// Require a passphrase before this profile may be used.
    RequirePassphrase(ProfilePolicyRequirePassphraseArgs),
    /// Change a profile-specific passphrase requirement.
    ChangePassphrase(ProfilePolicyChangePassphraseArgs),
    /// Remove a profile-specific passphrase requirement.
    DisablePassphrase(ProfilePolicyDisablePassphraseArgs),
    /// Require a device-seal factor before this profile may be used.
    RequireDeviceSeal(ProfilePolicyRequirementArgs),
    /// Remove a profile-specific device-seal requirement.
    DisableDeviceSeal(ProfilePolicyRequirementArgs),
    /// Clear all explicit factor requirements for a profile.
    ClearRequirements(ProfilePolicyRequirementArgs),
    /// Apply a preset as concrete profile-specific enforcement.
    Apply(ProfilePolicyApplyArgs),
    /// Set advisory policy metadata for a profile.
    Set(ProfilePolicySetArgs),
}

#[derive(Debug, clap::Args)]
pub struct ProfilePolicyStatusArgs {
    pub profile: String,
}

#[derive(Debug, clap::Args)]
pub struct ProfilePolicyRotateKeyArgs {
    pub profile: String,
}

#[derive(Debug, clap::Args)]
pub struct ProfilePolicyRequirementArgs {
    pub profile: String,
}

#[derive(Debug, clap::Args)]
pub struct ProfilePolicyRequirePassphraseArgs {
    pub profile: String,
    /// Profile passphrase. If omitted, read from a hidden prompt.
    #[arg(long)]
    pub passphrase: Option<String>,
}

#[derive(Debug, clap::Args)]
pub struct ProfilePolicyChangePassphraseArgs {
    pub profile: String,
    /// Current profile passphrase. If omitted, read from `$SSHENV_PROFILE_PASSPHRASE` or prompt.
    #[arg(long)]
    pub old_passphrase: Option<String>,
    /// New profile passphrase. If omitted, read from a hidden prompt.
    #[arg(long)]
    pub new_passphrase: Option<String>,
}

#[derive(Debug, clap::Args)]
pub struct ProfilePolicyDisablePassphraseArgs {
    pub profile: String,
    /// Current profile passphrase. If omitted, read from `$SSHENV_PROFILE_PASSPHRASE` or prompt.
    #[arg(long)]
    pub passphrase: Option<String>,
}

#[derive(Debug, clap::Args)]
pub struct ProfilePolicyApplyArgs {
    pub profile: String,
    /// Preset to apply as concrete profile-specific enforcement.
    #[arg(long, value_enum)]
    pub preset: SecurityPresetArg,
    /// Public key for a current recipient when v1-to-v2 migration cannot discover it.
    /// Repeat as needed.
    #[arg(long = "recipient-key", value_name = "PATH_OR_LINE")]
    pub recipient_keys: Vec<String>,
    /// New profile passphrase for presets that require one. If omitted, read from a hidden prompt.
    #[arg(long)]
    pub passphrase: Option<String>,
}

#[derive(Debug, clap::Args)]
pub struct ProfilePolicySetArgs {
    pub profile: String,
    /// Intended security preset for this profile.
    #[arg(long, value_enum)]
    pub preset: SecurityPresetArg,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum SecurityPresetArg {
    Standard,
    Recommended,
    Portable,
    Paranoid,
}

#[derive(Debug, clap::Args)]
pub struct SecurityPresetArgs {
    /// Preset to apply.
    #[arg(value_enum)]
    pub preset: SecurityPresetArg,
    /// Public key for a current recipient when migration cannot discover it.
    /// Repeat as needed.
    #[arg(long = "recipient-key", value_name = "PATH_OR_LINE")]
    pub recipient_keys: Vec<String>,
    /// New passphrase for presets that enable the passphrase factor. If
    /// omitted, read from a hidden prompt.
    #[arg(long)]
    pub passphrase: Option<String>,
}

#[derive(Debug, clap::Args)]
pub struct EnablePassphraseArgs {
    /// Passphrase value. If omitted, read from a hidden prompt.
    #[arg(long)]
    pub passphrase: Option<String>,
}

#[derive(Debug, clap::Args)]
pub struct ChangePassphraseArgs {
    /// Current passphrase. If omitted, read from `$SSHENV_PASSPHRASE` or a hidden prompt.
    #[arg(long)]
    pub old_passphrase: Option<String>,
    /// New passphrase. If omitted, read from a hidden prompt.
    #[arg(long)]
    pub new_passphrase: Option<String>,
}

#[derive(Debug, clap::Args)]
pub struct DisablePassphraseArgs {
    /// Current passphrase. If omitted, read from `$SSHENV_PASSPHRASE` or a hidden prompt.
    #[arg(long)]
    pub passphrase: Option<String>,
}

#[derive(Debug, clap::Args)]
pub struct InitArgs {
    /// Path to an SSH public key file, or the public key line itself
    /// (`ssh-ed25519 AAAA...`). If omitted, sshenv will prompt
    /// interactively to pick a pubkey from `~/.ssh/` (requires a TTY).
    #[arg(long, value_name = "PATH_OR_LINE")]
    pub recipient_key: Option<String>,
}

#[derive(Debug, clap::Args)]
pub struct AddRecipientArgs {
    /// Path to an SSH public key file, or the public key line itself.
    /// If omitted, sshenv will prompt interactively to pick a pubkey
    /// from `~/.ssh/` (requires a TTY).
    #[arg(long, value_name = "PATH_OR_LINE")]
    pub key: Option<String>,
}

#[derive(Debug, clap::Args)]
pub struct ListRecipientsArgs {
    /// Print the full public key line for each recipient.
    #[arg(long)]
    pub verbose: bool,
}

#[derive(Debug, clap::Args)]
pub struct RemoveRecipientArgs {
    /// Fingerprint of the recipient to remove (as printed by
    /// `list-recipients`).
    #[arg(long, value_name = "SHA256:...")]
    pub fingerprint: String,
    /// Also rotate the vault data key after removing the recipient.
    #[arg(long)]
    pub rotate: bool,
    /// Public key for a remaining current recipient when `--rotate` cannot
    /// discover it from local `~/.ssh/*.pub` files. Repeat as needed.
    #[arg(long = "recipient-key", value_name = "PATH_OR_LINE")]
    pub recipient_keys: Vec<String>,
}

#[derive(Debug, clap::Args)]
pub struct SetArgs {
    /// Profile name (free-form; `/` allowed as a convention).
    pub profile: String,
    /// Environment variable name (upper-case recommended).
    pub var: String,
    /// Value. If omitted, read from a hidden stdin prompt.
    #[arg(long)]
    pub value: Option<String>,
}

#[derive(Debug, clap::Args)]
pub struct UnsetArgs {
    pub profile: String,
    pub var: String,
}

#[derive(Debug, clap::Args)]
pub struct ListArgs {
    /// If given, list variable names in this profile. Otherwise, list
    /// all profile names.
    pub profile: Option<String>,
    /// When listing profile names, filter to names starting with this
    /// prefix.
    #[arg(long)]
    pub prefix: Option<String>,
}

#[derive(Debug, clap::Args)]
pub struct ShowArgs {
    pub profile: String,
}

#[derive(Debug, clap::Args)]
pub struct RmProfileArgs {
    pub profile: String,
}

#[derive(Debug, clap::Args)]
pub struct RenameProfileArgs {
    pub from: String,
    pub to: String,
}

#[derive(Debug, clap::Args)]
pub struct RunArgs {
    /// Do not add this execution to the local session registry.
    #[arg(long)]
    pub incognito: bool,

    pub profile: String,
    /// Command and its arguments. Use `--` to separate from sshenv's own
    /// flags.
    #[arg(trailing_var_arg = true, allow_hyphen_values = true, required = true)]
    pub command: Vec<String>,
}

#[derive(Debug, clap::Args)]
pub struct ExportArgs {
    pub profile: String,
}

#[derive(Debug, Subcommand)]
pub enum SessionsCommand {
    /// List tracked live executions for the current vault.
    List(SessionsListArgs),
    /// Send a signal to tracked live executions for a profile in the current vault.
    Kill(SessionsKillArgs),
}

#[derive(Debug, clap::Args)]
pub struct SessionsListArgs {
    /// Only show sessions for this profile.
    #[arg(long)]
    pub profile: Option<String>,
}

#[derive(Debug, clap::Args)]
pub struct SessionsKillArgs {
    /// Kill tracked executions for all profiles in the current vault.
    #[arg(long, conflicts_with = "profile")]
    pub all: bool,

    /// Profile whose tracked executions should receive the signal.
    #[arg(required_unless_present = "all")]
    pub profile: Option<String>,

    /// Signal to send.
    #[arg(long, value_enum, default_value_t = SessionSignal::Term)]
    pub signal: SessionSignal,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum SessionSignal {
    Term,
    Int,
    Hup,
    Kill,
}

#[derive(Debug, Subcommand)]
pub enum ShimsCommand {
    /// Bind a command to a profile. Auto-regenerates shims.
    Bind(ShimsBindArgs),
    /// Unbind a command. Auto-regenerates shims.
    Unbind(ShimsUnbindArgs),
    /// Rename a bound command. Auto-regenerates shims.
    Rename(ShimsRenameArgs),
    /// List current bindings.
    List,
    /// Regenerate all shim files from the bindings file.
    Sync,
    /// Print the resolved shim output directory.
    Dir,
    /// Print a `PATH=...` snippet suitable for adding to your shell rc.
    Path,
}

#[derive(Debug, clap::Args)]
pub struct ShimsBindArgs {
    pub profile: String,
    #[arg(long, value_name = "NAME")]
    pub command: String,
}

#[derive(Debug, clap::Args)]
pub struct ShimsUnbindArgs {
    #[arg(long, value_name = "NAME")]
    pub command: String,
}

#[derive(Debug, clap::Args)]
pub struct ShimsRenameArgs {
    #[arg(long, value_name = "OLD")]
    pub command: String,
    #[arg(long, value_name = "NEW")]
    pub to: String,
}
