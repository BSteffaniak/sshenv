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
    /// Guided security hardening flow (defaults to the recommended preset).
    Harden(HardenArgs),
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

#[derive(Debug, clap::Args)]
pub struct HardenArgs {
    /// Preset to apply. Defaults to recommended.
    #[arg(long, value_enum, default_value = "recommended")]
    pub preset: SecurityPresetArg,
    /// Public key for a current recipient when migration cannot discover it.
    /// Repeat as needed.
    #[arg(long = "recipient-key", value_name = "PATH_OR_LINE")]
    pub recipient_keys: Vec<String>,
    /// New passphrase for presets that enable the passphrase factor. If
    /// omitted and needed, read from a hidden prompt.
    #[arg(long)]
    pub passphrase: Option<String>,
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
    EnableDeviceSeal(EnableDeviceSealArgs),
    /// Apply a named security preset.
    Preset(SecurityPresetArgs),
    /// Inspect future passphrase-cache design and controls.
    #[command(subcommand)]
    PassphraseCache(PassphraseCacheCommand),
    /// Inspect stronger rollback-protection designs.
    #[command(subcommand)]
    Rollback(RollbackCommand),
    /// Manage local device-seal authorization.
    #[command(subcommand)]
    Device(DeviceCommand),
    /// Inspect and plan hardware-backed recipient setup.
    #[command(subcommand)]
    Hardware(HardwareCommand),
    /// Plan threshold/break-glass recovery from non-secret metadata.
    #[command(subcommand)]
    Recovery(RecoveryCommand),
    /// Validate remote/KMS factor metadata.
    #[command(subcommand)]
    Remote(RemoteCommand),
    /// Manage advisory per-profile security policy metadata.
    #[command(subcommand)]
    ProfilePolicy(ProfilePolicyCommand),
}

#[derive(Debug, clap::Args)]
pub struct EnableDeviceSealArgs {
    /// High-level device-seal policy to satisfy.
    #[arg(long, value_enum, conflicts_with = "backend")]
    pub mode: Option<DeviceSealModeArg>,
    /// Concrete device-seal backend to use.
    #[arg(long, value_enum, conflicts_with = "mode")]
    pub backend: Option<DeviceSealBackendArg>,
    /// Reject weaker fallback behavior such as plaintext local-file storage or
    /// transparent stores that are not guaranteed device-bound.
    #[arg(long)]
    pub strict: bool,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum DeviceSealModeArg {
    Default,
    TransparentDeviceOnly,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum DeviceSealBackendArg {
    MacosKeychain,
    MacosKeychainDeviceOnly,
    WindowsDpapiCurrentUser,
    LinuxTpm,
    LinuxSecretService,
    SecureEnclave,
    LocalFile,
}

#[derive(Debug, Subcommand)]
pub enum PassphraseCacheCommand {
    /// Show passphrase-cache status for this build.
    Status(PassphraseCacheStatusArgs),
    /// Print the passphrase-cache threat model and implementation plan.
    Plan(PassphraseCacheStatusArgs),
    /// Clear cached passphrases if a cache backend is available.
    Clear,
}

#[derive(Debug, clap::Args)]
pub struct PassphraseCacheStatusArgs {
    /// Print machine-readable JSON.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Subcommand)]
pub enum RollbackCommand {
    /// Show local rollback-protection status for this build/vault.
    Status(RollbackStatusArgs),
    /// Print a stronger rollback-protection plan.
    Plan(RollbackPlanArgs),
    /// Generate a non-secret remote-checkpoint JSON template.
    CheckpointTemplate(RollbackCheckpointTemplateArgs),
    /// Validate a non-secret rollback checkpoint JSON file against the current vault.
    ValidateCheckpoint(RollbackCheckpointArgs),
}

#[derive(Debug, clap::Args)]
pub struct RollbackStatusArgs {
    /// Print machine-readable JSON.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, clap::Args)]
pub struct RollbackPlanArgs {
    /// Stronger rollback backend family to plan for.
    #[arg(long, value_enum)]
    pub backend: RollbackBackendArg,
    /// Print machine-readable JSON.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, clap::Args)]
pub struct RollbackCheckpointTemplateArgs {
    /// Vault identifier. Defaults to the canonical current vault id.
    #[arg(long)]
    pub vault_id: Option<String>,
    /// Generation to put in the checkpoint. Defaults to current v2 vault generation.
    #[arg(long)]
    pub generation: Option<u64>,
}

#[derive(Debug, clap::Args)]
pub struct RollbackCheckpointArgs {
    /// Path to a rollback checkpoint JSON document.
    pub checkpoint_path: PathBuf,
    /// Print machine-readable JSON.
    #[arg(long)]
    pub json: bool,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum RollbackBackendArg {
    TpmMonotonic,
    RemoteCheckpoint,
    MultiDeviceSync,
}

#[derive(Debug, Subcommand)]
pub enum DeviceCommand {
    /// List configured device-seal factors.
    List,
    /// Authorize this device by enabling the vault device-seal factor.
    Authorize,
    /// Remove the vault-level device-seal factor.
    Remove,
    /// Print a setup plan for a future device-seal backend.
    Plan(DevicePlanArgs),
}

#[derive(Debug, clap::Args)]
pub struct DevicePlanArgs {
    /// Device-seal backend family to plan for.
    #[arg(long, value_enum)]
    pub backend: DeviceBackendArg,
    /// Print machine-readable JSON.
    #[arg(long)]
    pub json: bool,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum DeviceBackendArg {
    WindowsDpapi,
    LinuxSecretService,
    Tpm,
    SecureEnclave,
}

#[derive(Debug, Subcommand)]
pub enum HardwareCommand {
    /// Show hardware-recipient feature and plugin discovery status.
    Status(HardwareStatusArgs),
    /// Print an actionable setup plan for a hardware recipient family.
    Plan(HardwarePlanArgs),
    /// Discover hardware recipients via a command-backed provider adapter.
    Discover(HardwareDiscoverArgs),
    /// Resolve one hardware recipient via a command-backed provider adapter.
    Enroll(HardwareEnrollArgs),
    /// Validate a public recipient descriptor and show its stable fingerprint.
    ValidateRecipient(HardwareValidateRecipientArgs),
}

#[derive(Debug, clap::Args)]
pub struct HardwareStatusArgs {
    /// Print machine-readable JSON.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, clap::Args)]
pub struct HardwarePlanArgs {
    /// Hardware recipient family to plan for.
    #[arg(long, value_enum)]
    pub kind: HardwareKindArg,
    /// age plugin name, without `age-plugin-` prefix.
    #[arg(long)]
    pub plugin: Option<String>,
    /// Print machine-readable JSON.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, clap::Args)]
pub struct HardwareDiscoverArgs {
    /// Provider adapter executable. It receives non-secret JSON on stdin and returns JSON on stdout.
    #[arg(long)]
    pub command: String,
    /// Hardware recipient family to request from the adapter.
    #[arg(long, value_enum, default_value_t = HardwareKindArg::AgePlugin)]
    pub kind: HardwareKindArg,
    /// Optional plugin/provider name hint.
    #[arg(long)]
    pub plugin: Option<String>,
    /// Print machine-readable JSON.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, clap::Args)]
pub struct HardwareEnrollArgs {
    /// Provider adapter executable. It receives non-secret JSON on stdin and returns JSON on stdout.
    #[arg(long)]
    pub command: String,
    /// Hardware recipient id to resolve.
    #[arg(long)]
    pub id: String,
    /// Hardware recipient family to request from the adapter.
    #[arg(long, value_enum, default_value_t = HardwareKindArg::AgePlugin)]
    pub kind: HardwareKindArg,
    /// Optional plugin/provider name hint.
    #[arg(long)]
    pub plugin: Option<String>,
    /// Print machine-readable JSON.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, clap::Args)]
pub struct HardwareValidateRecipientArgs {
    /// Public SSH key line or age-plugin recipient descriptor.
    pub descriptor: String,
    /// Print machine-readable JSON.
    #[arg(long)]
    pub json: bool,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum HardwareKindArg {
    AgePlugin,
    YubiKeyPiv,
    FidoSecurityKey,
}

#[derive(Debug, Subcommand)]
pub enum RecoveryCommand {
    /// List recovery-share metadata stored in the current v2 vault.
    List(RecoveryListArgs),
    /// Import non-secret recovery-share metadata into the current v2 vault.
    Import(RecoveryMetadataArgs),
    /// Remove a recovery-share metadata set from the current v2 vault.
    Remove(RecoveryRemoveArgs),
    /// Split a hex secret from stdin into encoded Shamir recovery-share envelopes.
    Split(RecoverySplitArgs),
    /// Split the current vault data key into encoded Shamir recovery-share envelopes.
    SplitVaultKey(RecoveryVaultKeySplitArgs),
    /// Validate one encoded Shamir recovery-share envelope file.
    ValidateShare(RecoveryShareFileArgs),
    /// Combine encoded Shamir recovery-share envelope files and print the recovered secret as hex.
    Combine(RecoveryCombineArgs),
    /// Recover a vault with Shamir shares and add a new recipient to a new vault file.
    RecoverRecipient(RecoveryRecoverRecipientArgs),
    /// Validate a recovery-share metadata JSON file.
    Validate(RecoveryMetadataArgs),
    /// Plan an M-of-N or break-glass recovery flow from metadata and provided share ids.
    Plan(RecoveryPlanArgs),
}

#[derive(Debug, Subcommand)]
pub enum RemoteCommand {
    /// List remote/KMS factor metadata stored in the current v2 vault.
    List(RemoteListArgs),
    /// Import non-secret remote/KMS factor metadata into the current v2 vault.
    Import(RemoteMetadataArgs),
    /// Remove remote/KMS factor metadata from the current v2 vault.
    Remove(RemoteRemoveArgs),
    /// Print a metadata template and setup plan for a remote/KMS backend.
    Plan(RemotePlanArgs),
    /// Generate a remote/KMS request JSON template from metadata.
    RequestTemplate(RemoteRequestTemplateArgs),
    /// Validate a remote/KMS request JSON file against metadata.
    ValidateRequest(RemoteRequestArgs),
    /// Wrap a hex payload key via a command-backed remote factor.
    CommandWrap(RemoteCommandWrapArgs),
    /// Unwrap a hex payload key via a command-backed remote factor.
    CommandUnwrap(RemoteCommandUnwrapArgs),
    /// Enable a command-backed remote/KMS factor for the current vault.
    EnableCommand(RemoteEnableCommandArgs),
    /// Validate a remote/KMS factor metadata JSON file.
    Validate(RemoteMetadataArgs),
}

#[derive(Debug, clap::Args)]
pub struct RemoteMetadataArgs {
    /// Path to a JSON RemoteFactorMetadataV2 document.
    pub metadata_path: PathBuf,
    /// Print machine-readable JSON.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, clap::Args)]
pub struct RemoteListArgs {
    /// Print machine-readable JSON.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, clap::Args)]
pub struct RemoteRemoveArgs {
    /// Remote/KMS factor id to remove.
    pub id: String,
}

#[derive(Debug, clap::Args)]
pub struct RemotePlanArgs {
    /// Remote/KMS backend family to plan for.
    #[arg(long, value_enum)]
    pub backend: RemoteBackendArg,
    /// Stable metadata id to include in the template.
    #[arg(long, default_value = "remote-default")]
    pub id: String,
    /// Service URL for self-hosted or OIDC approval backends.
    #[arg(long)]
    pub url: Option<String>,
    /// Cloud KMS key id/alias/resource name.
    #[arg(long)]
    pub key: Option<String>,
    /// Optional command-backed adapter executable to include in the metadata template.
    #[arg(long)]
    pub command: Option<String>,
    /// Print machine-readable JSON.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, clap::Args)]
pub struct RemoteRequestArgs {
    /// Path to a JSON RemoteFactorMetadataV2 document.
    pub metadata_path: PathBuf,
    /// Path to a JSON RemoteFactorRequest document.
    pub request_path: PathBuf,
    /// Expected vault id for this request context.
    #[arg(long)]
    pub expected_vault_id: Option<String>,
    /// Expected vault generation for this request context.
    #[arg(long)]
    pub expected_generation: Option<u64>,
    /// Expected request id for this request context.
    #[arg(long)]
    pub expected_request_id: Option<String>,
    /// Print machine-readable JSON.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, clap::Args)]
pub struct RemoteCommandWrapArgs {
    /// Path to a JSON RemoteFactorMetadataV2 document with a `command` param.
    pub metadata_path: PathBuf,
    /// Path to a JSON RemoteFactorRequest document.
    pub request_path: PathBuf,
    /// Read the payload key as hex from stdin.
    #[arg(long)]
    pub payload_key_hex_stdin: bool,
    /// Print machine-readable JSON.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, clap::Args)]
pub struct RemoteCommandUnwrapArgs {
    /// Path to a JSON RemoteFactorMetadataV2 document with a `command` param.
    pub metadata_path: PathBuf,
    /// Path to a JSON RemoteFactorRequest document.
    pub request_path: PathBuf,
    /// Read the wrapped key as hex from stdin.
    #[arg(long)]
    pub wrapped_key_hex_stdin: bool,
    /// Print machine-readable JSON.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, clap::Args)]
pub struct RemoteEnableCommandArgs {
    /// Path to a JSON RemoteFactorMetadataV2 document with a `command` param.
    pub metadata_path: PathBuf,
    /// Path to a JSON RemoteFactorRequest document used to wrap the generated factor.
    pub request_path: PathBuf,
}

#[derive(Debug, clap::Args)]
pub struct RemoteRequestTemplateArgs {
    /// Path to a JSON RemoteFactorMetadataV2 document.
    pub metadata_path: PathBuf,
    /// Vault identifier to bind into the request.
    #[arg(long, default_value = "vault")]
    pub vault_id: String,
    /// Vault generation to bind into the request.
    #[arg(long, default_value_t = 0)]
    pub generation: u64,
    /// Request expiry as Unix seconds. Defaults to now + 300 seconds.
    #[arg(long)]
    pub expires_unix: Option<u64>,
    /// Stable request id. Defaults to a timestamp-derived id.
    #[arg(long)]
    pub request_id: Option<String>,
    /// Self-hosted client id.
    #[arg(long)]
    pub client_id: Option<String>,
    /// Cloud KMS encryption context string.
    #[arg(long)]
    pub encryption_context: Option<String>,
    /// OIDC subject.
    #[arg(long)]
    pub subject: Option<String>,
    /// OIDC audience.
    #[arg(long)]
    pub audience: Option<String>,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum RemoteBackendArg {
    SelfHosted,
    CloudKms,
    OidcApproval,
}

#[derive(Debug, clap::Args)]
pub struct RecoveryMetadataArgs {
    /// Path to a JSON RecoveryShareSetMetadataV2 document.
    pub metadata_path: PathBuf,
    /// Print machine-readable JSON.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, clap::Args)]
pub struct RecoveryListArgs {
    /// Print machine-readable JSON.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, clap::Args)]
pub struct RecoveryRemoveArgs {
    /// Recovery-share set id to remove.
    pub set_id: String,
}

#[derive(Debug, clap::Args)]
pub struct RecoveryShareFileArgs {
    /// File containing one encoded recovery-share envelope.
    pub share_file: PathBuf,
    /// Optional recovery metadata JSON to verify set id, threshold, and share index.
    #[arg(long)]
    pub metadata: Option<PathBuf>,
    /// Print machine-readable JSON.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, clap::Args)]
pub struct RecoverySplitArgs {
    /// Recovery metadata JSON to derive set id, threshold, and share count.
    #[arg(long)]
    pub metadata: Option<PathBuf>,
    /// Recovery-share set id to embed in the envelopes.
    #[arg(long)]
    pub set_id: Option<String>,
    /// Number of shares required to recover.
    #[arg(long)]
    pub threshold: Option<u8>,
    /// Total shares to generate.
    #[arg(long)]
    pub share_count: Option<u8>,
    /// Read the secret as hex from stdin.
    #[arg(long)]
    pub secret_hex_stdin: bool,
    /// Print machine-readable JSON.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, clap::Args)]
pub struct RecoveryVaultKeySplitArgs {
    /// Recovery metadata JSON to derive set id, threshold, and share count.
    #[arg(long)]
    pub metadata: Option<PathBuf>,
    /// Recovery-share set id to embed in the envelopes.
    #[arg(long)]
    pub set_id: Option<String>,
    /// Number of shares required to recover.
    #[arg(long)]
    pub threshold: Option<u8>,
    /// Total shares to generate.
    #[arg(long)]
    pub share_count: Option<u8>,
    /// Print machine-readable JSON.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, clap::Args)]
pub struct RecoveryCombineArgs {
    /// File containing one encoded recovery-share envelope. Repeat for each collected share.
    #[arg(long = "share-file", required = true)]
    pub share_files: Vec<PathBuf>,
    /// Optional recovery metadata JSON to verify set id, threshold, and share indices.
    #[arg(long)]
    pub metadata: Option<PathBuf>,
    /// Print machine-readable JSON.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, clap::Args)]
pub struct RecoveryRecoverRecipientArgs {
    /// File containing one encoded recovery-share envelope. Repeat for each collected share.
    #[arg(long = "share-file", required = true)]
    pub share_files: Vec<PathBuf>,
    /// Optional recovery metadata JSON to verify set id, threshold, and share indices.
    #[arg(long)]
    pub metadata: Option<PathBuf>,
    /// Public SSH key line or age-plugin recipient descriptor to add to the recovered vault.
    #[arg(long)]
    pub recipient_key: String,
    /// Output vault path. Required so recovery never overwrites the current vault implicitly.
    #[arg(long)]
    pub output: PathBuf,
    /// Optional vault passphrase factor if the recovered vault also requires it.
    #[arg(long)]
    pub passphrase: Option<String>,
}

#[derive(Debug, clap::Args)]
pub struct RecoveryPlanArgs {
    /// Path to a JSON RecoveryShareSetMetadataV2 document.
    pub metadata_path: PathBuf,
    /// Recovery share id that is available. Repeat for each collected share.
    #[arg(long = "share-id")]
    pub share_ids: Vec<String>,
    /// Include break-glass emergency steps instead of only threshold readiness.
    #[arg(long)]
    pub break_glass: bool,
    /// Print machine-readable JSON.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Subcommand)]
pub enum ProfilePolicyCommand {
    /// List profile policy metadata.
    List,
    /// List profile-policy backup files adjacent to the current vault.
    Backups(ProfilePolicyBackupsArgs),
    /// Prune older profile-policy backup files adjacent to the current vault.
    PruneBackups(ProfilePolicyPruneBackupsArgs),
    /// Show effective security posture for one profile.
    Status(ProfilePolicyStatusArgs),
    /// Validate policy consistency across all profiles.
    Check(ProfilePolicyCheckArgs),
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
    /// Preview applying a preset to all profiles.
    ApplyAll(ProfilePolicyApplyAllArgs),
    /// Repair/reconcile a profile's policy metadata with concrete enforcement.
    Repair(ProfilePolicyRepairArgs),
    /// Repair/reconcile all existing profile policy metadata.
    RepairAll(ProfilePolicyRepairAllArgs),
    /// Restore the current vault from a profile-policy backup file.
    RestoreBackup(ProfilePolicyRestoreBackupArgs),
    /// Verify a profile-policy backup file is readable and unlockable.
    VerifyBackup(ProfilePolicyVerifyBackupArgs),
    /// Set advisory policy metadata for a profile.
    Set(ProfilePolicySetArgs),
}

#[derive(Debug, clap::Args)]
pub struct ProfilePolicyBackupsArgs {
    /// Print machine-readable JSON.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, clap::Args)]
pub struct ProfilePolicyPruneBackupsArgs {
    /// Number of newest backups to keep.
    #[arg(long)]
    pub keep: usize,
    /// Show what would be pruned without deleting files.
    #[arg(long)]
    pub dry_run: bool,
    /// Delete planned files. Without this, prune-backups only plans.
    #[arg(long)]
    pub confirm: bool,
    /// Print machine-readable JSON.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, clap::Args)]
pub struct ProfilePolicyStatusArgs {
    pub profile: String,
    /// Print machine-readable JSON.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, clap::Args)]
pub struct ProfilePolicyCheckArgs {
    /// Print machine-readable JSON.
    #[arg(long)]
    pub json: bool,
    /// Exit nonzero when warnings are present, not only errors.
    #[arg(long)]
    pub strict: bool,
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
    /// Show the apply plan without changing the vault.
    #[arg(long)]
    pub dry_run: bool,
    /// Print the apply plan as machine-readable JSON without changing the vault.
    #[arg(long)]
    pub json: bool,
    /// Fail before mutation when planned repair needs recipient-key input.
    #[arg(long)]
    pub strict_inputs: bool,
}

#[derive(Debug, clap::Args)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "CLI flag structs mirror independent command-line switches"
)]
pub struct ProfilePolicyApplyAllArgs {
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
    /// Deprecated: bulk profile-policy mutations create backups by default.
    #[arg(long, hide = true, conflicts_with = "no_backup")]
    pub backup: bool,
    /// Do not create a timestamped backup before mutating all profiles.
    #[arg(long)]
    pub no_backup: bool,
    /// Show the bulk apply plan without changing the vault.
    #[arg(long)]
    pub dry_run: bool,
    /// Print the bulk apply plan as machine-readable JSON.
    #[arg(long)]
    pub json: bool,
    /// Fail before mutation when planned repair needs recipient-key input.
    #[arg(long)]
    pub strict_inputs: bool,
}

#[derive(Debug, clap::Args)]
pub struct ProfilePolicyRestoreBackupArgs {
    /// Backup vault file to restore over the current vault.
    pub backup_path: PathBuf,
    /// Preview the restore without changing the current vault.
    #[arg(long)]
    pub dry_run: bool,
    /// Print the restore preview as machine-readable JSON without changing the vault.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, clap::Args)]
pub struct ProfilePolicyVerifyBackupArgs {
    /// Backup vault file to verify.
    pub backup_path: PathBuf,
    /// Print machine-readable JSON.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, clap::Args)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "CLI flag structs mirror independent command-line switches"
)]
pub struct ProfilePolicyRepairAllArgs {
    /// Public key for a current recipient when v1-to-v2 migration cannot discover it.
    /// Repeat as needed.
    #[arg(long = "recipient-key", value_name = "PATH_OR_LINE")]
    pub recipient_keys: Vec<String>,
    /// New profile passphrase when repair needs to create passphrase bindings.
    /// If omitted and needed, read from a hidden prompt.
    #[arg(long)]
    pub passphrase: Option<String>,
    /// Deprecated: bulk profile-policy mutations create backups by default.
    #[arg(long, hide = true, conflicts_with = "no_backup")]
    pub backup: bool,
    /// Do not create a timestamped backup before mutating all profiles.
    #[arg(long)]
    pub no_backup: bool,
    /// Show the bulk repair plan without changing the vault.
    #[arg(long)]
    pub dry_run: bool,
    /// Print the bulk repair plan as machine-readable JSON.
    #[arg(long)]
    pub json: bool,
    /// Fail before mutation when planned repair needs recipient-key input.
    #[arg(long)]
    pub strict_inputs: bool,
}

#[derive(Debug, clap::Args)]
pub struct ProfilePolicyRepairArgs {
    pub profile: String,
    /// Public key for a current recipient when v1-to-v2 migration cannot discover it.
    /// Repeat as needed.
    #[arg(long = "recipient-key", value_name = "PATH_OR_LINE")]
    pub recipient_keys: Vec<String>,
    /// New profile passphrase when repair needs to create a passphrase binding.
    /// If omitted and needed, read from a hidden prompt.
    #[arg(long)]
    pub passphrase: Option<String>,
    /// Show the repair plan without changing the vault.
    #[arg(long)]
    pub dry_run: bool,
    /// Print the repair plan as machine-readable JSON without changing the vault.
    #[arg(long)]
    pub json: bool,
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
    Team,
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
    /// Path to a public recipient descriptor, or the descriptor line itself.
    /// SSH public keys are always supported; age-plugin recipients require
    /// the `age-plugin-recipient` feature. If omitted, sshenv will prompt
    /// interactively to pick an SSH pubkey from `~/.ssh/` (requires a TTY).
    #[arg(long, value_name = "PATH_OR_LINE")]
    pub key: Option<String>,
    /// Add a hardware-backed recipient. This is currently reserved for future
    /// age-plugin/YubiKey/FIDO integrations.
    #[arg(long)]
    pub hardware: bool,
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
    /// Clear inherited environment before injecting profile variables.
    #[arg(long)]
    pub clean_env: bool,

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
