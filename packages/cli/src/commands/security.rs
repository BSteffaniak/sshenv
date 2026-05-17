#[cfg(feature = "age-plugin-recipient")]
use std::collections::BTreeSet;
use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::io::IsTerminal;
#[cfg(any(feature = "remote-factor", feature = "shamir-sharing"))]
use std::io::Read;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

#[allow(
    unused_imports,
    reason = "Context trait is only used by feature-gated commands"
)]
use anyhow::Context as AnyhowContext;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use sshenv_cli_models::{
    ChangePassphraseArgs, DeviceBackendArg, DevicePlanArgs, DisablePassphraseArgs,
    EnablePassphraseArgs, HardenArgs, HardwareDiscoverArgs, HardwareEnrollArgs, HardwareKindArg,
    HardwarePlanArgs, HardwareStatusArgs, HardwareValidateRecipientArgs, PassphraseCacheStatusArgs,
    ProfilePolicyApplyAllArgs, ProfilePolicyApplyArgs, ProfilePolicyBackupsArgs,
    ProfilePolicyChangePassphraseArgs, ProfilePolicyCheckArgs, ProfilePolicyDisablePassphraseArgs,
    ProfilePolicyPruneBackupsArgs, ProfilePolicyRepairAllArgs, ProfilePolicyRepairArgs,
    ProfilePolicyRequirePassphraseArgs, ProfilePolicyRequirementArgs,
    ProfilePolicyRestoreBackupArgs, ProfilePolicyRotateKeyArgs, ProfilePolicySetArgs,
    ProfilePolicyStatusArgs, ProfilePolicyVerifyBackupArgs, RecoveryCombineArgs, RecoveryListArgs,
    RecoveryMetadataArgs, RecoveryPlanArgs, RecoveryRecoverRecipientArgs, RecoveryRemoveArgs,
    RecoveryShareFileArgs, RecoverySplitArgs, RecoveryVaultKeySplitArgs, RemoteBackendArg,
    RemoteCommandUnwrapArgs, RemoteCommandWrapArgs, RemoteEnableCommandArgs, RemoteListArgs,
    RemoteMetadataArgs, RemotePlanArgs, RemoteRemoveArgs, RemoteRequestArgs,
    RemoteRequestTemplateArgs, RollbackBackendArg, RollbackCheckpointArgs,
    RollbackCheckpointTemplateArgs, RollbackPlanArgs, RollbackStatusArgs, SecurityPresetArg,
    SecurityPresetArgs,
};
use sshenv_vault::models::{
    ProfileFactorRequirement, ProfilePolicy, ProfilePolicyFinding, ProfilePolicyFindingCode,
    ProfilePolicyPreset, ProfilePolicyRepairAction, ProfilePolicyRepairPlan,
    RemoteFactorBackendKindV2, RemoteFactorMetadataV2, UnlockFactorKindV2, VERSION, VERSION_V2,
};
#[cfg(feature = "remote-factor")]
use sshenv_vault::remote::RemoteFactorBackend;
use sshenv_vault::{DataKey, Vault, atomic_write};

use crate::commands::Context as CmdContext;
#[cfg(feature = "passphrase-factor")]
use crate::commands::unlock_ciphertext_with_passphrase;
use crate::commands::{
    load_and_unlock_metadata, load_and_unlock_profile, load_ciphertext_and_fps, save_vault,
    set_rollback, unlock_ciphertext,
};
use crate::identity::{discover_private_key_paths, public_fingerprint_for_private_key};

#[cfg(feature = "passphrase-factor")]
pub fn enable_passphrase(ctx: &CmdContext, args: EnablePassphraseArgs) -> Result<()> {
    let passphrase =
        passphrase_arg_or_prompt(args.passphrase, "Enter new sshenv vault passphrase: ")?;

    let (ciphertext, recipients) = load_ciphertext_and_fps(&ctx.vault_path)?;
    let (mut vault, data_key) = unlock_ciphertext(ciphertext, &recipients)?;
    vault.enable_passphrase_factor(passphrase.as_str())?;
    save_vault(ctx, &mut vault, &data_key)?;
    eprintln!("Enabled passphrase factor for this v2 vault.");
    Ok(())
}

#[cfg(feature = "passphrase-factor")]
pub fn change_passphrase(ctx: &CmdContext, args: ChangePassphraseArgs) -> Result<()> {
    let new_passphrase =
        passphrase_arg_or_prompt(args.new_passphrase, "Enter new sshenv vault passphrase: ")?;
    let (ciphertext, recipients) = load_ciphertext_and_fps(&ctx.vault_path)?;
    let (mut vault, data_key) =
        unlock_ciphertext_with_passphrase(ciphertext, &recipients, args.old_passphrase.as_deref())?;
    vault.change_passphrase_factor(new_passphrase.as_str())?;
    save_vault(ctx, &mut vault, &data_key)?;
    eprintln!("Changed passphrase factor for this v2 vault.");
    Ok(())
}

#[cfg(feature = "passphrase-factor")]
pub fn disable_passphrase(ctx: &CmdContext, args: DisablePassphraseArgs) -> Result<()> {
    let (ciphertext, recipients) = load_ciphertext_and_fps(&ctx.vault_path)?;
    let (mut vault, data_key) =
        unlock_ciphertext_with_passphrase(ciphertext, &recipients, args.passphrase.as_deref())?;
    vault.disable_passphrase_factor()?;
    save_vault(ctx, &mut vault, &data_key)?;
    eprintln!("Disabled passphrase factor for this v2 vault.");
    Ok(())
}

#[cfg(feature = "passphrase-factor")]
fn passphrase_arg_or_prompt(
    value: Option<String>,
    prompt: &str,
) -> Result<zeroize::Zeroizing<String>> {
    Ok(match value {
        Some(value) => zeroize::Zeroizing::new(value),
        None => {
            if !std::io::stdin().is_terminal() {
                anyhow::bail!(
                    "failed to read passphrase: stdin is not a terminal; pass --passphrase for non-interactive use"
                );
            }
            zeroize::Zeroizing::new(
                rpassword::prompt_password(prompt).context("failed to read passphrase")?,
            )
        }
    })
}

#[cfg(not(feature = "passphrase-factor"))]
pub fn enable_passphrase(_ctx: &CmdContext, _args: EnablePassphraseArgs) -> Result<()> {
    anyhow::bail!("this sshenv build was compiled without passphrase-factor support")
}

#[cfg(not(feature = "passphrase-factor"))]
pub fn change_passphrase(_ctx: &CmdContext, _args: ChangePassphraseArgs) -> Result<()> {
    anyhow::bail!("this sshenv build was compiled without passphrase-factor support")
}

#[cfg(not(feature = "passphrase-factor"))]
pub fn disable_passphrase(_ctx: &CmdContext, _args: DisablePassphraseArgs) -> Result<()> {
    anyhow::bail!("this sshenv build was compiled without passphrase-factor support")
}

#[derive(Debug, Serialize)]
struct PassphraseCacheOutput {
    available: bool,
    enabled: bool,
    backend: &'static str,
    ttl_seconds: u64,
    opt_in_required: bool,
    expiry_controls: Vec<String>,
    threat_model: Vec<String>,
}

pub fn passphrase_cache_status(args: PassphraseCacheStatusArgs) -> Result<()> {
    let output = passphrase_cache_output();
    if args.json {
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!("passphrase cache status");
        println!("=======================");
        println!("available: {}", yes_no(output.available));
        println!("enabled: {}", yes_no(output.enabled));
        println!("backend: {}", output.backend);
        println!("ttl seconds: {}", output.ttl_seconds);
        println!("opt-in required: {}", yes_no(output.opt_in_required));
    }
    Ok(())
}

pub fn passphrase_cache_plan(args: PassphraseCacheStatusArgs) -> Result<()> {
    let output = passphrase_cache_output();
    if args.json {
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!("passphrase cache plan");
        println!("=====================");
        println!("backend: {}", output.backend);
        println!("expiry/clear controls:");
        for item in &output.expiry_controls {
            println!("- {item}");
        }
        println!("threat model:");
        for item in &output.threat_model {
            println!("- {item}");
        }
    }
    Ok(())
}

pub fn passphrase_cache_clear(ctx: &CmdContext) -> Result<()> {
    if crate::passphrase_cache::clear_vault_passphrase(&ctx.vault_path)? {
        eprintln!(
            "Cleared cached vault passphrase for {}.",
            ctx.vault_path.display()
        );
    } else {
        eprintln!(
            "No cached vault passphrase was found for {}.",
            ctx.vault_path.display()
        );
    }
    Ok(())
}

fn passphrase_cache_output() -> PassphraseCacheOutput {
    let status = crate::passphrase_cache::status().unwrap_or(
        crate::passphrase_cache::PassphraseCacheStatus {
            enabled: false,
            backend: "unavailable",
            backend_available: false,
            ttl_seconds: 300,
        },
    );
    PassphraseCacheOutput {
        available: status.backend_available,
        enabled: status.enabled,
        backend: status.backend,
        ttl_seconds: status.ttl_seconds,
        opt_in_required: true,
        expiry_controls: vec![
            "cache entries must have explicit TTLs".to_string(),
            "users need `sshenv security passphrase-cache clear` to evict all entries".to_string(),
            "cache keys should bind vault path, vault generation, and profile name where relevant"
                .to_string(),
        ],
        threat_model: vec![
            "improves repeated command ergonomics but increases risk on an unlocked local account"
                .to_string(),
            "must never write plaintext passphrases to the vault or logs".to_string(),
            "macOS Keychain backend requires local user/session access and supports TTL expiry"
                .to_string(),
        ],
    }
}

#[derive(Debug, Serialize)]
struct RollbackStatusOutput {
    local_feature_enabled: bool,
    vault_generation: Option<u64>,
    local_baseline_generation: Option<u64>,
    synced_baseline_generation: Option<u64>,
    rollback_state_path: String,
    rollback_sync_path: Option<String>,
    baseline_status: String,
    stronger_backends_available: bool,
    notes: Vec<String>,
}

#[derive(Debug, Serialize)]
struct RollbackPlanOutput {
    backend: String,
    local_feature_enabled: bool,
    required_metadata: Vec<String>,
    write_path: Vec<String>,
    read_path: Vec<String>,
    failure_modes: Vec<String>,
}

#[derive(Debug, Serialize)]
struct RollbackCheckpointValidationOutput {
    valid: bool,
    checkpoint_generation: u64,
    vault_generation: Option<u64>,
    would_reject_current_vault: bool,
    signature_verified: bool,
    notes: Vec<String>,
}

pub fn rollback_status(ctx: &CmdContext, args: RollbackStatusArgs) -> Result<()> {
    let generation = if ctx.vault_path.exists() {
        Vault::load_ciphertext(&ctx.vault_path)
            .ok()
            .and_then(|vault| vault.generation())
    } else {
        None
    };
    let local_baseline = rollback_local_baseline(&ctx.vault_path)?;
    let synced_baseline = rollback_synced_baseline(&ctx.vault_path)?;
    let output = RollbackStatusOutput {
        local_feature_enabled: cfg!(feature = "rollback-protection"),
        vault_generation: generation,
        local_baseline_generation: local_baseline,
        synced_baseline_generation: synced_baseline,
        rollback_state_path: rollback_state_path_display(),
        rollback_sync_path: rollback_sync_path_display(),
        baseline_status: rollback_combined_baseline_status(generation, local_baseline, synced_baseline),
        stronger_backends_available: synced_baseline.is_some(),
        notes: vec![
            "current rollback protection is local best-effort generation tracking".to_string(),
            "explicit restore updates the local baseline".to_string(),
            "set SSHENV_ROLLBACK_SYNC to a trusted synced state file for opt-in multi-device rollback observations".to_string(),
            "signed remote checkpoints require SSHENV_ROLLBACK_CHECKPOINT or SSHENV_ROLLBACK_CHECKPOINT_COMMAND for runtime enforcement".to_string(),
            "TPM/monotonic adapters can enforce SSHENV_ROLLBACK_MONOTONIC_COMMAND for check/record operations".to_string(),
        ],
    };
    if args.json {
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!("rollback protection status");
        println!("==========================");
        println!(
            "local feature: {}",
            enabled_label(output.local_feature_enabled)
        );
        println!(
            "vault generation: {}",
            output
                .vault_generation
                .map_or_else(|| "unknown".to_string(), |value| value.to_string())
        );
        println!(
            "local baseline generation: {}",
            output
                .local_baseline_generation
                .map_or_else(|| "none".to_string(), |value| value.to_string())
        );
        println!(
            "synced baseline generation: {}",
            output
                .synced_baseline_generation
                .map_or_else(|| "none".to_string(), |value| value.to_string())
        );
        println!("baseline status: {}", output.baseline_status);
        println!("state path: {}", output.rollback_state_path);
        println!(
            "sync path: {}",
            output
                .rollback_sync_path
                .as_deref()
                .unwrap_or("not configured")
        );
        println!("stronger backends: opt-in sync/checkpoint only");
    }
    Ok(())
}

#[cfg(feature = "rollback-protection")]
fn rollback_local_baseline(vault_path: &Path) -> Result<Option<u64>> {
    crate::rollback::generation_for(vault_path)
}

#[cfg(not(feature = "rollback-protection"))]
#[allow(clippy::missing_const_for_fn, clippy::unnecessary_wraps)]
fn rollback_local_baseline(_vault_path: &Path) -> Result<Option<u64>> {
    Ok(None)
}

#[cfg(feature = "rollback-protection")]
fn rollback_state_path_display() -> String {
    crate::rollback::default_rollback_path()
        .display()
        .to_string()
}

#[cfg(not(feature = "rollback-protection"))]
fn rollback_state_path_display() -> String {
    std::env::var("SSHENV_ROLLBACK")
        .unwrap_or_else(|_| "rollback-protection feature disabled".to_string())
}

#[cfg(feature = "rollback-protection")]
fn rollback_synced_baseline(vault_path: &Path) -> Result<Option<u64>> {
    crate::rollback::synced_generation_for(vault_path)
}

#[cfg(not(feature = "rollback-protection"))]
#[allow(clippy::missing_const_for_fn, clippy::unnecessary_wraps)]
fn rollback_synced_baseline(_vault_path: &Path) -> Result<Option<u64>> {
    Ok(None)
}

#[cfg(feature = "rollback-protection")]
fn rollback_sync_path_display() -> Option<String> {
    crate::rollback::rollback_sync_path().map(|path| path.display().to_string())
}

#[cfg(not(feature = "rollback-protection"))]
fn rollback_sync_path_display() -> Option<String> {
    std::env::var("SSHENV_ROLLBACK_SYNC").ok()
}

fn rollback_combined_baseline_status(
    vault_generation: Option<u64>,
    local_baseline_generation: Option<u64>,
    synced_baseline_generation: Option<u64>,
) -> String {
    let effective = local_baseline_generation.max(synced_baseline_generation);
    rollback_baseline_status(vault_generation, effective)
}

fn rollback_baseline_status(
    vault_generation: Option<u64>,
    local_baseline_generation: Option<u64>,
) -> String {
    match (vault_generation, local_baseline_generation) {
        (Some(current), Some(baseline)) if current < baseline => {
            format!(
                "rollback suspected: current generation {current} is older than local baseline {baseline}"
            )
        }
        (Some(current), Some(baseline)) if current == baseline => "current".to_string(),
        (Some(current), Some(baseline)) => {
            format!("current generation {current} is newer than local baseline {baseline}")
        }
        (Some(_), None) => "no local baseline recorded".to_string(),
        (None, Some(baseline)) => format!("local baseline {baseline}; vault generation unknown"),
        (None, None) => "unknown".to_string(),
    }
}

pub fn rollback_checkpoint_template(
    ctx: &CmdContext,
    args: RollbackCheckpointTemplateArgs,
) -> Result<()> {
    let generation = match args.generation {
        Some(generation) => generation,
        None => vault_generation(&ctx.vault_path).ok_or_else(|| {
            anyhow::anyhow!(
                "rollback checkpoint template requires a v2 vault generation or --generation"
            )
        })?,
    };
    let created_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());
    let document = crate::rollback_checkpoint::RollbackCheckpointDocument {
        backend: "remote-checkpoint".to_string(),
        vault_id: args
            .vault_id
            .unwrap_or_else(|| crate::session_registry::vault_id(&ctx.vault_path)),
        generation,
        created_unix,
        signer: None,
        signature: None,
    };
    println!("{}", serde_json::to_string_pretty(&document)?);
    Ok(())
}

pub fn rollback_validate_checkpoint(ctx: &CmdContext, args: RollbackCheckpointArgs) -> Result<()> {
    let checkpoint = crate::rollback_checkpoint::load_checkpoint(&args.checkpoint_path)?;
    crate::rollback_checkpoint::validate_checkpoint_shape(&checkpoint)?;
    let current_generation = vault_generation(&ctx.vault_path);
    let would_reject_current_vault =
        current_generation.is_some_and(|generation| generation < checkpoint.generation);
    let signature_verified = crate::rollback_checkpoint::verify_checkpoint_signature(&checkpoint)?;
    let mut notes = vec!["checkpoint metadata is non-secret".to_string()];
    if signature_verified {
        notes.push("checkpoint SSH signature verified".to_string());
    } else {
        notes.push("unsigned checkpoint accepted; configure signer/signature to authenticate remote checkpoints".to_string());
    }
    if would_reject_current_vault {
        notes.push("current vault generation is older than checkpoint generation".to_string());
    }
    let output = RollbackCheckpointValidationOutput {
        valid: true,
        checkpoint_generation: checkpoint.generation,
        vault_generation: current_generation,
        would_reject_current_vault,
        signature_verified,
        notes,
    };
    if args.json {
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!("rollback checkpoint: valid");
        println!("checkpoint generation: {}", output.checkpoint_generation);
        println!(
            "vault generation: {}",
            output
                .vault_generation
                .map_or_else(|| "unknown".to_string(), |value| value.to_string())
        );
        println!(
            "would reject current vault: {}",
            yes_no(output.would_reject_current_vault)
        );
        println!("signature verified: {}", yes_no(output.signature_verified));
    }
    Ok(())
}

fn vault_generation(vault_path: &Path) -> Option<u64> {
    if vault_path.exists() {
        Vault::load_ciphertext(vault_path)
            .ok()
            .and_then(|vault| vault.generation())
    } else {
        None
    }
}

pub fn rollback_plan(args: RollbackPlanArgs) -> Result<()> {
    let output = RollbackPlanOutput {
        backend: format!("{:?}", args.backend),
        local_feature_enabled: cfg!(feature = "rollback-protection"),
        required_metadata: rollback_required_metadata(args.backend),
        write_path: rollback_write_path(args.backend),
        read_path: rollback_read_path(args.backend),
        failure_modes: rollback_failure_modes(args.backend),
    };
    if args.json {
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!("stronger rollback protection plan");
        println!("=================================");
        println!("backend: {}", output.backend);
        println!("required metadata:");
        for item in &output.required_metadata {
            println!("- {item}");
        }
        println!("write path:");
        for item in &output.write_path {
            println!("- {item}");
        }
        println!("read path:");
        for item in &output.read_path {
            println!("- {item}");
        }
        println!("failure modes:");
        for item in &output.failure_modes {
            println!("- {item}");
        }
    }
    Ok(())
}

fn rollback_required_metadata(backend: RollbackBackendArg) -> Vec<String> {
    match backend {
        RollbackBackendArg::TpmMonotonic => vec![
            "TPM public name / NV index identifier".to_string(),
            "counter policy and PCR binding, if used".to_string(),
            "last accepted vault generation".to_string(),
            "optional SSHENV_ROLLBACK_MONOTONIC_COMMAND adapter path".to_string(),
        ],
        RollbackBackendArg::RemoteCheckpoint => vec![
            "checkpoint service URL/command adapter and public verification key".to_string(),
            "vault id and latest signed generation".to_string(),
            "request authentication/audit policy".to_string(),
        ],
        RollbackBackendArg::MultiDeviceSync => vec![
            "device id and public signing key per trusted device".to_string(),
            "last observed generation per device".to_string(),
            "conflict policy for offline devices".to_string(),
        ],
    }
}

fn rollback_write_path(backend: RollbackBackendArg) -> Vec<String> {
    match backend {
        RollbackBackendArg::TpmMonotonic => vec![
            "after successful vault save, invoke SSHENV_ROLLBACK_MONOTONIC_COMMAND with operation=record".to_string(),
            "record the generation accepted by TPM state".to_string(),
        ],
        RollbackBackendArg::RemoteCheckpoint => vec![
            "after successful vault save, submit signed generation checkpoint".to_string(),
            "require service acknowledgement before reporting durable success for strict mode"
                .to_string(),
        ],
        RollbackBackendArg::MultiDeviceSync => vec![
            "sign local generation observations".to_string(),
            "sync observations opportunistically across trusted devices".to_string(),
        ],
    }
}

fn rollback_read_path(backend: RollbackBackendArg) -> Vec<String> {
    match backend {
        RollbackBackendArg::TpmMonotonic => vec![
            "before unlock, invoke SSHENV_ROLLBACK_MONOTONIC_COMMAND with operation=check".to_string(),
            "refuse older generations unless explicit restore updates the baseline".to_string(),
        ],
        RollbackBackendArg::RemoteCheckpoint => vec![
            "before unlock, fetch latest signed checkpoint with SSHENV_ROLLBACK_CHECKPOINT_COMMAND or read SSHENV_ROLLBACK_CHECKPOINT".to_string(),
            "refuse vaults older than the service checkpoint unless explicitly restored"
                .to_string(),
        ],
        RollbackBackendArg::MultiDeviceSync => vec![
            "before unlock, compare with locally cached signed observations".to_string(),
            "surface conflicts when another device has observed a newer generation".to_string(),
        ],
    }
}

fn rollback_failure_modes(backend: RollbackBackendArg) -> Vec<String> {
    match backend {
        RollbackBackendArg::TpmMonotonic => vec![
            "TPM clear or motherboard replacement requires recovery flow".to_string(),
            "PCR-bound policies can break after OS updates".to_string(),
        ],
        RollbackBackendArg::RemoteCheckpoint => vec![
            "network/service outage must choose fail-open vs fail-closed policy".to_string(),
            "service compromise can deny unlock or publish stale checkpoints without signatures"
                .to_string(),
        ],
        RollbackBackendArg::MultiDeviceSync => vec![
            "offline devices can have stale views".to_string(),
            "device compromise requires key revocation and checkpoint reset".to_string(),
        ],
    }
}

#[cfg(feature = "device-seal")]
pub fn enable_device_seal(ctx: &CmdContext) -> Result<()> {
    let (ciphertext, recipients) = load_ciphertext_and_fps(&ctx.vault_path)?;
    let (mut vault, data_key) = unlock_ciphertext(ciphertext, &recipients)?;
    vault.enable_device_seal_factor()?;
    save_vault(ctx, &mut vault, &data_key)?;
    eprintln!("Enabled device-seal factor for this v2 vault.");
    Ok(())
}

#[cfg(not(feature = "device-seal"))]
pub fn enable_device_seal(_ctx: &CmdContext) -> Result<()> {
    anyhow::bail!("this sshenv build was compiled without device-seal support")
}

pub fn device_list(ctx: &CmdContext) -> Result<()> {
    println!("sshenv device seals");
    println!("===================");
    println!("backend: {}", device_seal_backend_status());
    let (vault, _key) = load_and_unlock_metadata(&ctx.vault_path)?;
    let mut found = false;
    for policy in vault
        .policy_metadata
        .as_ref()
        .into_iter()
        .flat_map(|metadata| &metadata.policies)
    {
        for factor in &policy.factors {
            if factor.kind == UnlockFactorKindV2::DeviceSeal {
                found = true;
                println!("vault: {} ({:?})", factor.id, factor.params);
            }
        }
    }
    for (profile, policy) in &vault.profiles.profile_policies {
        for factor in &policy.factor_metadata {
            if factor.kind == UnlockFactorKindV2::DeviceSeal {
                found = true;
                println!("profile {profile}: {} ({:?})", factor.id, factor.params);
            }
        }
    }
    if !found {
        println!("(no device-seal factors configured)");
    }
    Ok(())
}

#[cfg(feature = "device-seal")]
pub fn device_authorize(ctx: &CmdContext) -> Result<()> {
    enable_device_seal(ctx)
}

#[cfg(not(feature = "device-seal"))]
pub fn device_authorize(_ctx: &CmdContext) -> Result<()> {
    anyhow::bail!("this sshenv build was compiled without device-seal support")
}

#[cfg(feature = "device-seal")]
pub fn device_remove(ctx: &CmdContext) -> Result<()> {
    let (mut vault, data_key) = crate::commands::load_and_unlock(&ctx.vault_path)?;
    if !vault.disable_device_seal_factor() {
        anyhow::bail!("vault device-seal factor is not enabled");
    }
    save_vault(ctx, &mut vault, &data_key)?;
    eprintln!("Removed vault device-seal factor.");
    Ok(())
}

#[cfg(not(feature = "device-seal"))]
pub fn device_remove(_ctx: &CmdContext) -> Result<()> {
    anyhow::bail!("this sshenv build was compiled without device-seal support")
}

#[derive(Debug, Serialize)]
struct DevicePlanOutput {
    backend: String,
    feature_enabled: bool,
    current_build_backend: String,
    threat_model: Vec<String>,
    implementation_notes: Vec<String>,
    user_flow: Vec<String>,
}

pub fn device_plan(args: DevicePlanArgs) -> Result<()> {
    let output = DevicePlanOutput {
        backend: format!("{:?}", args.backend),
        feature_enabled: cfg!(feature = "device-seal"),
        current_build_backend: device_seal_backend_status().to_string(),
        threat_model: device_backend_threat_model(args.backend),
        implementation_notes: device_backend_implementation_notes(args.backend),
        user_flow: vec![
            "build sshenv with the desired device-seal backend feature".to_string(),
            "run `sshenv security device authorize` on each trusted device".to_string(),
            "use `sshenv security profile-policy apply ... --preset recommended` or paranoid for profile binding".to_string(),
            "remove lost devices with `sshenv security device remove` and rotate affected keys".to_string(),
        ],
    };
    if args.json {
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!("device-seal backend plan");
        println!("========================");
        println!("backend: {}", output.backend);
        println!(
            "device-seal feature: {}",
            enabled_label(output.feature_enabled)
        );
        println!("current build backend: {}", output.current_build_backend);
        println!("threat model:");
        for item in &output.threat_model {
            println!("- {item}");
        }
        println!("implementation notes:");
        for item in &output.implementation_notes {
            println!("- {item}");
        }
        println!("user flow:");
        for item in &output.user_flow {
            println!("- {item}");
        }
    }
    Ok(())
}

fn device_backend_threat_model(backend: DeviceBackendArg) -> Vec<String> {
    match backend {
        DeviceBackendArg::WindowsDpapi => vec![
            "binds secrets to the Windows user/machine DPAPI boundary".to_string(),
            "protects against vault-file theft without the user profile or machine state"
                .to_string(),
            "does not protect against compromise of the logged-in Windows account".to_string(),
        ],
        DeviceBackendArg::LinuxSecretService => vec![
            "binds secrets to the desktop Secret Service collection".to_string(),
            "best for workstation ergonomics, not headless servers".to_string(),
            "security depends on the collection lock policy and session compromise resistance"
                .to_string(),
        ],
        DeviceBackendArg::Tpm => vec![
            "binds secrets to TPM-resident sealed state and optionally PCR policy".to_string(),
            "can improve theft resistance for copied vaults and disks".to_string(),
            "PCR policy must balance tamper detection with OS update recoverability".to_string(),
        ],
        DeviceBackendArg::SecureEnclave => vec![
            "binds secrets to Apple hardware-backed key material where available".to_string(),
            "can require local user presence depending on access-control flags".to_string(),
            "requires a migration/recovery story for hardware replacement".to_string(),
        ],
    }
}

fn device_backend_implementation_notes(backend: DeviceBackendArg) -> Vec<String> {
    match backend {
        DeviceBackendArg::WindowsDpapi => vec![
            "available with the `windows-dpapi` feature on Windows".to_string(),
            "wraps factor bytes with CurrentUser DPAPI via PowerShell ProtectedData".to_string(),
            "stores only DPAPI ciphertext on disk and the backend label in v2 policy metadata".to_string(),
            "requires reauthorization after Windows profile migration or credential loss".to_string(),
        ],
        DeviceBackendArg::LinuxSecretService => vec![
            "available with the `linux-secret-service` feature on Linux".to_string(),
            "stores factor bytes in a named Secret Service item via `secret-tool`".to_string(),
            "persists only the backend label in v2 policy metadata".to_string(),
            "detects missing `secret-tool` or locked/unavailable collections with actionable CLI errors".to_string(),
        ],
        DeviceBackendArg::Tpm => vec![
            "available with the `tpm-device-seal` feature on Linux".to_string(),
            "seals factor bytes with tpm2-tools and stores only TPM public/private blobs plus contexts".to_string(),
            "current implementation uses owner hierarchy without PCR policy; PCR-bound policies remain future work".to_string(),
            "requires backup/recovery guidance before requiring TPM-only unlock".to_string(),
        ],
        DeviceBackendArg::SecureEnclave => vec![
            "available with the `secure-enclave` feature via a command-backed adapter".to_string(),
            "set SSHENV_SECURE_ENCLAVE_DEVICE_SEAL_COMMAND to an adapter that stores/loads factor bytes using Secure Enclave-backed key material".to_string(),
            "the adapter receives secret material on stdin JSON during store; never pass factor bytes in argv".to_string(),
            "surface user-presence prompts before command execution where supported by the platform adapter".to_string(),
        ],
    }
}

#[derive(Debug, Serialize)]
struct HardwareStatusOutput {
    hardware_recipient_feature: bool,
    age_plugin_recipient_feature: bool,
    age_plugin_identity_sources: Vec<String>,
    age_plugin_identity_files: Vec<AgePluginIdentityFileOutput>,
    age_plugin_plugins: BTreeMap<String, usize>,
    age_plugin_binaries: Vec<AgePluginBinaryOutput>,
    known_plans: Vec<String>,
}

#[derive(Debug, Serialize)]
struct AgePluginBinaryOutput {
    plugin: String,
    path: String,
    inferred_kind: String,
}

#[derive(Debug, Serialize)]
struct AgePluginIdentityFileOutput {
    path: String,
    identity_count: usize,
    plugins: BTreeMap<String, usize>,
    invalid_lines: usize,
}

#[derive(Debug, Serialize)]
struct HardwarePlanOutput {
    kind: String,
    plugin: String,
    plugin_binary: String,
    plugin_binary_found: bool,
    recipient_feature_enabled: bool,
    age_plugin_feature_enabled: bool,
    add_recipient_example: String,
    identity_hint: String,
    notes: Vec<String>,
}

#[derive(Debug, Serialize)]
struct HardwareValidateRecipientOutput {
    valid: bool,
    descriptor_kind: String,
    fingerprint: String,
    hardware_recipient: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "kebab-case")]
struct HardwareAdapterRequest<'a> {
    operation: &'a str,
    kind: &'a str,
    plugin: Option<&'a str>,
    id: Option<&'a str>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
struct HardwareAdapterRecipient {
    id: String,
    label: Option<String>,
    kind: Option<String>,
    #[serde(alias = "public_descriptor")]
    public_descriptor: String,
}

#[derive(Debug, Serialize)]
struct HardwareDiscoverOutput {
    command: String,
    kind: String,
    plugin: Option<String>,
    recipients: Vec<HardwareRecipientOutput>,
}

#[derive(Debug, Serialize)]
struct HardwareRecipientOutput {
    id: String,
    label: Option<String>,
    kind: Option<String>,
    public_descriptor: String,
    valid: bool,
    fingerprint: Option<String>,
    descriptor_kind: Option<String>,
    error: Option<String>,
    add_recipient_example: Option<String>,
}

pub fn hardware_status(args: HardwareStatusArgs) -> Result<()> {
    let age_plugin_identity_files = inspect_age_plugin_identity_files();
    let output = HardwareStatusOutput {
        hardware_recipient_feature: cfg!(feature = "hardware-recipient"),
        age_plugin_recipient_feature: cfg!(feature = "age-plugin-recipient"),
        age_plugin_identity_sources: vec![
            "$SSHENV_AGE_PLUGIN_IDENTITIES".to_string(),
            "~/.sshenv/age-plugin-identities".to_string(),
            "~/.sshenv/age-plugin-identities.d/*".to_string(),
        ],
        age_plugin_plugins: age_plugin_plugins_from_files(&age_plugin_identity_files),
        age_plugin_identity_files,
        age_plugin_binaries: discover_age_plugin_binaries(),
        known_plans: vec![
            "age-plugin".to_string(),
            "yubi-key-piv".to_string(),
            "fido-security-key".to_string(),
        ],
    };
    if args.json {
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!("hardware recipient status");
        println!("=========================");
        println!(
            "hardware-recipient feature: {}",
            enabled_label(output.hardware_recipient_feature)
        );
        println!(
            "age-plugin-recipient feature: {}",
            enabled_label(output.age_plugin_recipient_feature)
        );
        println!("age-plugin identity sources:");
        for source in &output.age_plugin_identity_sources {
            println!("- {source}");
        }
        println!(
            "age-plugin identity files: {}",
            output.age_plugin_identity_files.len()
        );
        for file in &output.age_plugin_identity_files {
            println!(
                "- {} (identities: {}, invalid lines: {})",
                file.path, file.identity_count, file.invalid_lines
            );
        }
        if !output.age_plugin_plugins.is_empty() {
            println!("age-plugin identities by plugin:");
            for (plugin, count) in &output.age_plugin_plugins {
                println!("- {plugin}: {count}");
            }
        }
        if !output.age_plugin_binaries.is_empty() {
            println!("age-plugin binaries on PATH:");
            for binary in &output.age_plugin_binaries {
                println!(
                    "- {} ({}) at {}",
                    binary.plugin, binary.inferred_kind, binary.path
                );
            }
        }
    }
    Ok(())
}

fn age_plugin_plugins_from_files(files: &[AgePluginIdentityFileOutput]) -> BTreeMap<String, usize> {
    let mut plugins = BTreeMap::new();
    for file in files {
        for (plugin, count) in &file.plugins {
            *plugins.entry(plugin.clone()).or_default() += count;
        }
    }
    plugins
}

fn discover_age_plugin_binaries() -> Vec<AgePluginBinaryOutput> {
    let mut binaries = BTreeMap::new();
    let Some(path) = std::env::var_os("PATH") else {
        return Vec::new();
    };
    for dir in std::env::split_paths(&path) {
        let Ok(entries) = fs::read_dir(dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
                continue;
            };
            let Some(plugin) = file_name.strip_prefix("age-plugin-") else {
                continue;
            };
            binaries
                .entry(plugin.to_string())
                .or_insert_with(|| AgePluginBinaryOutput {
                    plugin: plugin.to_string(),
                    path: path.display().to_string(),
                    inferred_kind: infer_age_plugin_hardware_kind(plugin).to_string(),
                });
        }
    }
    binaries.into_values().collect()
}

fn infer_age_plugin_hardware_kind(plugin: &str) -> &'static str {
    let lower = plugin.to_ascii_lowercase();
    if lower.contains("yubi") || lower.contains("piv") {
        "yubi-key-piv"
    } else if lower.contains("fido") || lower.contains("sk") || lower.contains("security-key") {
        "fido-security-key"
    } else {
        "age-plugin"
    }
}

#[cfg(feature = "age-plugin-recipient")]
fn inspect_age_plugin_identity_files() -> Vec<AgePluginIdentityFileOutput> {
    discover_age_plugin_identity_paths()
        .into_iter()
        .map(|path| inspect_age_plugin_identity_file(&path))
        .collect()
}

#[cfg(not(feature = "age-plugin-recipient"))]
#[allow(clippy::missing_const_for_fn)]
fn inspect_age_plugin_identity_files() -> Vec<AgePluginIdentityFileOutput> {
    Vec::new()
}

#[cfg(feature = "age-plugin-recipient")]
fn discover_age_plugin_identity_paths() -> Vec<PathBuf> {
    let mut paths = BTreeSet::new();
    if let Some(raw) = std::env::var_os("SSHENV_AGE_PLUGIN_IDENTITIES") {
        for path in std::env::split_paths(&raw) {
            if path.is_file() {
                paths.insert(path);
            }
        }
    }

    if let Some(home) = dirs::home_dir() {
        let file = home.join(".sshenv").join("age-plugin-identities");
        if file.is_file() {
            paths.insert(file);
        }
        let dir = home.join(".sshenv").join("age-plugin-identities.d");
        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    paths.insert(path);
                }
            }
        }
    }

    paths.into_iter().collect()
}

#[cfg(feature = "age-plugin-recipient")]
fn inspect_age_plugin_identity_file(path: &Path) -> AgePluginIdentityFileOutput {
    let mut plugins = BTreeMap::new();
    let mut identity_count = 0;
    let mut invalid_lines = 0;
    if let Ok(content) = fs::read_to_string(path) {
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            match trimmed.parse::<age::plugin::Identity>() {
                Ok(identity) => {
                    identity_count += 1;
                    *plugins.entry(identity.plugin().to_string()).or_default() += 1;
                }
                Err(_) => invalid_lines += 1,
            }
        }
    }
    AgePluginIdentityFileOutput {
        path: path.display().to_string(),
        identity_count,
        plugins,
        invalid_lines,
    }
}

pub fn hardware_discover(args: HardwareDiscoverArgs) -> Result<()> {
    let kind = hardware_kind_label(args.kind).to_string();
    let request = HardwareAdapterRequest {
        operation: "list",
        kind: &kind,
        plugin: args.plugin.as_deref(),
        id: None,
    };
    let recipients: Vec<HardwareAdapterRecipient> =
        invoke_hardware_adapter(&args.command, &request)?;
    let output = HardwareDiscoverOutput {
        command: args.command,
        kind,
        plugin: args.plugin,
        recipients: recipients
            .into_iter()
            .map(hardware_adapter_recipient_output)
            .collect(),
    };
    if args.json {
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else if output.recipients.is_empty() {
        println!("no hardware recipients discovered");
    } else {
        println!("hardware recipients discovered");
        println!("==============================");
        for recipient in &output.recipients {
            println!("id: {}", recipient.id);
            if let Some(label) = &recipient.label {
                println!("label: {label}");
            }
            println!("descriptor: {}", recipient.public_descriptor);
            if let Some(fingerprint) = &recipient.fingerprint {
                println!("fingerprint: {fingerprint}");
            }
            if let Some(example) = &recipient.add_recipient_example {
                println!("add recipient: {example}");
            }
            if let Some(error) = &recipient.error {
                println!("error: {error}");
            }
            println!();
        }
    }
    Ok(())
}

pub fn hardware_enroll(args: HardwareEnrollArgs) -> Result<()> {
    let kind = hardware_kind_label(args.kind).to_string();
    let request = HardwareAdapterRequest {
        operation: "recipient",
        kind: &kind,
        plugin: args.plugin.as_deref(),
        id: Some(&args.id),
    };
    let recipient: HardwareAdapterRecipient = invoke_hardware_adapter(&args.command, &request)?;
    let output = hardware_adapter_recipient_output(recipient);
    if !output.valid {
        anyhow::bail!(
            "hardware adapter returned invalid recipient descriptor for {}: {}",
            output.id,
            output
                .error
                .as_deref()
                .unwrap_or("unknown validation error")
        );
    }
    if args.json {
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!("hardware recipient enrolled");
        println!("===========================");
        println!("id: {}", output.id);
        if let Some(label) = &output.label {
            println!("label: {label}");
        }
        println!("descriptor: {}", output.public_descriptor);
        if let Some(fingerprint) = &output.fingerprint {
            println!("fingerprint: {fingerprint}");
        }
        if let Some(example) = &output.add_recipient_example {
            println!("add recipient: {example}");
        }
    }
    Ok(())
}

fn invoke_hardware_adapter<T: for<'de> Deserialize<'de>>(
    command_path: &str,
    request: &HardwareAdapterRequest<'_>,
) -> Result<T> {
    let input =
        serde_json::to_vec(request).context("failed to serialize hardware adapter request")?;
    let mut child = Command::new(command_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .with_context(|| format!("failed to invoke hardware adapter '{command_path}'"))?;
    {
        let stdin = child
            .stdin
            .as_mut()
            .context("failed to open hardware adapter stdin")?;
        stdin
            .write_all(&input)
            .context("failed to write hardware adapter request")?;
    }
    let output = child
        .wait_with_output()
        .context("failed to wait for hardware adapter")?;
    if !output.status.success() {
        anyhow::bail!(
            "hardware adapter exited unsuccessfully: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    serde_json::from_slice(&output.stdout).context("hardware adapter returned invalid JSON")
}

fn hardware_adapter_recipient_output(
    recipient: HardwareAdapterRecipient,
) -> HardwareRecipientOutput {
    match sshenv_vault::recipient::fingerprint_from_recipient_descriptor(
        &recipient.public_descriptor,
    ) {
        Ok(fingerprint) => {
            let descriptor_kind =
                sshenv_vault::recipient::recipient_descriptor_kind(&recipient.public_descriptor);
            let add_recipient_example = format!(
                "sshenv add-recipient --hardware --key '{}'",
                recipient.public_descriptor
            );
            HardwareRecipientOutput {
                id: recipient.id,
                label: recipient.label,
                kind: recipient.kind,
                public_descriptor: recipient.public_descriptor,
                valid: true,
                fingerprint: Some(fingerprint),
                descriptor_kind: Some(format!("{descriptor_kind:?}")),
                error: None,
                add_recipient_example: Some(add_recipient_example),
            }
        }
        Err(error) => HardwareRecipientOutput {
            id: recipient.id,
            label: recipient.label,
            kind: recipient.kind,
            public_descriptor: recipient.public_descriptor,
            valid: false,
            fingerprint: None,
            descriptor_kind: None,
            error: Some(error.to_string()),
            add_recipient_example: None,
        },
    }
}

const fn hardware_kind_label(kind: HardwareKindArg) -> &'static str {
    match kind {
        HardwareKindArg::AgePlugin => "age-plugin",
        HardwareKindArg::YubiKeyPiv => "yubi-key-piv",
        HardwareKindArg::FidoSecurityKey => "fido-security-key",
    }
}

pub fn hardware_validate_recipient(args: HardwareValidateRecipientArgs) -> Result<()> {
    let kind = sshenv_vault::recipient::recipient_descriptor_kind(&args.descriptor);
    let fingerprint =
        sshenv_vault::recipient::fingerprint_from_recipient_descriptor(&args.descriptor)?;
    let output = HardwareValidateRecipientOutput {
        valid: true,
        descriptor_kind: format!("{kind:?}"),
        fingerprint,
        hardware_recipient: matches!(kind, UnlockFactorKindV2::HardwareRecipient),
    };
    if args.json {
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!("recipient descriptor: valid");
        println!("kind: {}", output.descriptor_kind);
        println!("hardware recipient: {}", yes_no(output.hardware_recipient));
        println!("fingerprint: {}", output.fingerprint);
    }
    Ok(())
}

pub fn hardware_plan(args: HardwarePlanArgs) -> Result<()> {
    let plugin = hardware_plan_plugin(args.kind, args.plugin.as_deref());
    let plugin_binary = format!("age-plugin-{plugin}");
    let plugin_binary_found = command_in_path(&plugin_binary);
    let add_recipient_example = format!("sshenv add-recipient --hardware --key <age1{plugin}...>");
    let mut notes = vec![
        "hardware recipients are added as public age-plugin recipient descriptors".to_string(),
        "store plugin identities outside the vault and point SSHENV_AGE_PLUGIN_IDENTITIES at them"
            .to_string(),
    ];
    match args.kind {
        HardwareKindArg::AgePlugin => {
            notes.push("use the plugin's own tooling to generate an age1... recipient".to_string());
        }
        HardwareKindArg::YubiKeyPiv => {
            notes.push(
                "recommended plugin family: age-plugin-yubikey-compatible tooling".to_string(),
            );
            notes.push(
                "PIV/slot policy and touch/PIN behavior are managed by the plugin/device tooling"
                    .to_string(),
            );
        }
        HardwareKindArg::FidoSecurityKey => {
            notes.push(
                "use an age plugin that exposes a FIDO/security-key-backed age recipient"
                    .to_string(),
            );
            notes.push(
                "resident credential, PIN, and user-presence policy are plugin-specific"
                    .to_string(),
            );
        }
    }
    if !cfg!(feature = "age-plugin-recipient") {
        notes.push(
            "this build needs the age-plugin-recipient feature to wrap to age1... recipients"
                .to_string(),
        );
    }
    if !plugin_binary_found {
        notes.push(format!("{plugin_binary} was not found on PATH"));
    }

    let output = HardwarePlanOutput {
        kind: format!("{:?}", args.kind),
        plugin,
        plugin_binary,
        plugin_binary_found,
        recipient_feature_enabled: cfg!(feature = "hardware-recipient"),
        age_plugin_feature_enabled: cfg!(feature = "age-plugin-recipient"),
        add_recipient_example,
        identity_hint: "put age-plugin identity lines in ~/.sshenv/age-plugin-identities or set SSHENV_AGE_PLUGIN_IDENTITIES".to_string(),
        notes,
    };

    if args.json {
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!("hardware recipient plan");
        println!("=======================");
        println!("kind: {}", output.kind);
        println!("plugin: {}", output.plugin);
        println!("plugin binary: {}", output.plugin_binary);
        println!(
            "plugin binary found: {}",
            yes_no(output.plugin_binary_found)
        );
        println!("add recipient: {}", output.add_recipient_example);
        println!("identity: {}", output.identity_hint);
        println!("notes:");
        for note in &output.notes {
            println!("- {note}");
        }
    }
    Ok(())
}

fn hardware_plan_plugin(kind: HardwareKindArg, explicit: Option<&str>) -> String {
    explicit.map_or_else(
        || match kind {
            HardwareKindArg::AgePlugin => "example".to_string(),
            HardwareKindArg::YubiKeyPiv => "yubikey".to_string(),
            HardwareKindArg::FidoSecurityKey => "fido2".to_string(),
        },
        ToString::to_string,
    )
}

fn command_in_path(command: &str) -> bool {
    std::env::var_os("PATH")
        .is_some_and(|path| std::env::split_paths(&path).any(|dir| dir.join(command).is_file()))
}

#[cfg(feature = "recovery-shares")]
pub fn recovery_list(ctx: &CmdContext, args: RecoveryListArgs) -> Result<()> {
    let (ciphertext, _fps) = load_ciphertext_and_fps(&ctx.vault_path)?;
    let sets = ciphertext
        .policy_metadata
        .as_ref()
        .map_or(&[][..], |metadata| metadata.recovery_share_sets.as_slice());
    if args.json {
        println!("{}", serde_json::to_string_pretty(sets)?);
    } else if sets.is_empty() {
        println!("(no recovery-share metadata)");
    } else {
        for set in sets {
            println!(
                "{} threshold {}/{}{}",
                set.id,
                set.threshold,
                set.shares.len(),
                set.label
                    .as_ref()
                    .map_or_else(String::new, |label| format!(" ({label})"))
            );
        }
    }
    Ok(())
}

#[cfg(not(feature = "recovery-shares"))]
pub fn recovery_list(_ctx: &CmdContext, _args: RecoveryListArgs) -> Result<()> {
    anyhow::bail!("this sshenv build was compiled without recovery-shares support")
}

#[cfg(feature = "recovery-shares")]
pub fn recovery_import(ctx: &CmdContext, args: RecoveryMetadataArgs) -> Result<()> {
    let imported = load_recovery_share_metadata(&args.metadata_path)?;
    sshenv_vault::recovery::validate_recovery_share_set_metadata(&imported)?;
    let (mut vault, data_key) = load_and_unlock_metadata(&ctx.vault_path)?;
    ensure_policy_metadata_v2(&vault)?;
    let metadata = vault.policy_metadata.get_or_insert_with(Default::default);
    let replaced = metadata
        .recovery_share_sets
        .iter()
        .any(|set| set.id == imported.id);
    metadata
        .recovery_share_sets
        .retain(|set| set.id != imported.id);
    let set_id = imported.id.clone();
    metadata.recovery_share_sets.push(imported);
    metadata
        .recovery_share_sets
        .sort_by(|left, right| left.id.cmp(&right.id));
    save_vault(ctx, &mut vault, &data_key)?;
    if args.json {
        println!(
            "{}",
            serde_json::json!({ "imported": set_id, "replaced": replaced })
        );
    } else if replaced {
        eprintln!("Replaced recovery-share metadata set {set_id}.");
    } else {
        eprintln!("Imported recovery-share metadata set {set_id}.");
    }
    Ok(())
}

#[cfg(not(feature = "recovery-shares"))]
pub fn recovery_import(_ctx: &CmdContext, _args: RecoveryMetadataArgs) -> Result<()> {
    anyhow::bail!("this sshenv build was compiled without recovery-shares support")
}

#[cfg(feature = "recovery-shares")]
pub fn recovery_remove(ctx: &CmdContext, args: RecoveryRemoveArgs) -> Result<()> {
    let (mut vault, data_key) = load_and_unlock_metadata(&ctx.vault_path)?;
    ensure_policy_metadata_v2(&vault)?;
    let Some(metadata) = vault.policy_metadata.as_mut() else {
        anyhow::bail!(
            "recovery-share metadata set '{}' is not configured",
            args.set_id
        );
    };
    let before = metadata.recovery_share_sets.len();
    metadata
        .recovery_share_sets
        .retain(|set| set.id != args.set_id);
    if metadata.recovery_share_sets.len() == before {
        anyhow::bail!(
            "recovery-share metadata set '{}' is not configured",
            args.set_id
        );
    }
    save_vault(ctx, &mut vault, &data_key)?;
    eprintln!("Removed recovery-share metadata set {}.", args.set_id);
    Ok(())
}

#[cfg(not(feature = "recovery-shares"))]
pub fn recovery_remove(_ctx: &CmdContext, _args: RecoveryRemoveArgs) -> Result<()> {
    anyhow::bail!("this sshenv build was compiled without recovery-shares support")
}

#[cfg(feature = "shamir-sharing")]
pub fn recovery_split(args: RecoverySplitArgs) -> Result<()> {
    if !args.secret_hex_stdin {
        anyhow::bail!("recovery split requires --secret-hex-stdin to avoid shell-history exposure");
    }
    let config = recovery_split_config(&args)?;
    let mut input = String::new();
    std::io::stdin()
        .read_to_string(&mut input)
        .context("failed to read hex secret from stdin")?;
    let secret = zeroize::Zeroizing::new(
        hex::decode(input.trim()).context("failed to decode hex secret from stdin")?,
    );
    let encoded = split_secret_to_recovery_envelopes(secret.as_slice(), &config)?;
    if args.json {
        println!(
            "{}",
            serde_json::json!({
                "set_id": config.set_id,
                "threshold": config.threshold,
                "share_count": encoded.len(),
                "metadata_verified": config.metadata_verified,
                "shares": encoded,
            })
        );
    } else {
        eprintln!(
            "warning: recovery share envelopes contain secret material; distribute them separately"
        );
        eprintln!("metadata verified: {}", yes_no(config.metadata_verified));
        for share in encoded {
            println!("{share}");
        }
    }
    Ok(())
}

#[cfg(feature = "shamir-sharing")]
pub fn recovery_split_vault_key(ctx: &CmdContext, args: RecoveryVaultKeySplitArgs) -> Result<()> {
    let config = recovery_split_config(&args)?;
    let (_vault, data_key) = crate::commands::load_and_unlock(&ctx.vault_path)?;
    let encoded = split_secret_to_recovery_envelopes(data_key.as_slice(), &config)?;
    if args.json {
        println!(
            "{}",
            serde_json::json!({
                "set_id": config.set_id,
                "threshold": config.threshold,
                "share_count": encoded.len(),
                "metadata_verified": config.metadata_verified,
                "shares": encoded,
            })
        );
    } else {
        eprintln!(
            "warning: recovery share envelopes contain the vault data key; distribute them separately"
        );
        eprintln!("metadata verified: {}", yes_no(config.metadata_verified));
        for share in encoded {
            println!("{share}");
        }
    }
    Ok(())
}

#[cfg(feature = "shamir-sharing")]
fn split_secret_to_recovery_envelopes(
    secret: &[u8],
    config: &RecoverySplitConfig,
) -> Result<Vec<String>> {
    let shares =
        sshenv_vault::recovery::split_secret_shamir(secret, config.threshold, config.share_count)?;
    let envelopes = shares
        .into_iter()
        .map(|share| sshenv_vault::recovery::RecoveryShareEnvelope {
            set_id: config.set_id.clone(),
            threshold: config.threshold,
            share,
        })
        .collect::<Vec<_>>();
    Ok(envelopes
        .iter()
        .map(sshenv_vault::recovery::encode_recovery_share_envelope)
        .collect::<Vec<_>>())
}

#[cfg(not(feature = "shamir-sharing"))]
pub fn recovery_split_vault_key(_ctx: &CmdContext, _args: RecoveryVaultKeySplitArgs) -> Result<()> {
    anyhow::bail!("this sshenv build was compiled without shamir-sharing support")
}

#[cfg(feature = "shamir-sharing")]
struct RecoverySplitConfig {
    set_id: String,
    threshold: u8,
    share_count: u8,
    metadata_verified: bool,
}

#[cfg(feature = "shamir-sharing")]
trait RecoverySplitOptions {
    fn metadata(&self) -> Option<&PathBuf>;
    fn set_id(&self) -> Option<&String>;
    fn threshold(&self) -> Option<u8>;
    fn share_count(&self) -> Option<u8>;
}

#[cfg(feature = "shamir-sharing")]
impl RecoverySplitOptions for RecoverySplitArgs {
    fn metadata(&self) -> Option<&PathBuf> {
        self.metadata.as_ref()
    }

    fn set_id(&self) -> Option<&String> {
        self.set_id.as_ref()
    }

    fn threshold(&self) -> Option<u8> {
        self.threshold
    }

    fn share_count(&self) -> Option<u8> {
        self.share_count
    }
}

#[cfg(feature = "shamir-sharing")]
impl RecoverySplitOptions for RecoveryVaultKeySplitArgs {
    fn metadata(&self) -> Option<&PathBuf> {
        self.metadata.as_ref()
    }

    fn set_id(&self) -> Option<&String> {
        self.set_id.as_ref()
    }

    fn threshold(&self) -> Option<u8> {
        self.threshold
    }

    fn share_count(&self) -> Option<u8> {
        self.share_count
    }
}

#[cfg(feature = "shamir-sharing")]
fn recovery_split_config(args: &impl RecoverySplitOptions) -> Result<RecoverySplitConfig> {
    let mut set_id = args.set_id().cloned();
    let mut threshold = args.threshold();
    let mut share_count = args.share_count();
    let metadata_verified = if let Some(metadata_path) = args.metadata() {
        let metadata = load_recovery_share_metadata(metadata_path)?;
        sshenv_vault::recovery::validate_recovery_share_set_metadata(&metadata)?;
        ensure_optional_match("set-id", set_id.as_deref(), metadata.id.as_str())?;
        ensure_optional_match_u8("threshold", threshold, metadata.threshold)?;
        let metadata_share_count = metadata
            .shamir
            .map_or_else(
                || u8::try_from(metadata.shares.len()),
                |shamir| Ok(shamir.share_count),
            )
            .context("recovery metadata share count exceeds 255")?;
        ensure_optional_match_u8("share-count", share_count, metadata_share_count)?;
        set_id = Some(metadata.id);
        threshold = Some(metadata.threshold);
        share_count = Some(metadata_share_count);
        true
    } else {
        false
    };

    Ok(RecoverySplitConfig {
        set_id: set_id
            .ok_or_else(|| anyhow::anyhow!("recovery split requires --set-id or --metadata"))?,
        threshold: threshold
            .ok_or_else(|| anyhow::anyhow!("recovery split requires --threshold or --metadata"))?,
        share_count: share_count.ok_or_else(|| {
            anyhow::anyhow!("recovery split requires --share-count or --metadata")
        })?,
        metadata_verified,
    })
}

#[cfg(feature = "shamir-sharing")]
fn ensure_optional_match(name: &str, provided: Option<&str>, expected: &str) -> Result<()> {
    if provided.is_some_and(|value| value != expected) {
        anyhow::bail!("recovery split --{name} does not match metadata value '{expected}'");
    }
    Ok(())
}

#[cfg(feature = "shamir-sharing")]
fn ensure_optional_match_u8(name: &str, provided: Option<u8>, expected: u8) -> Result<()> {
    if provided.is_some_and(|value| value != expected) {
        anyhow::bail!("recovery split --{name} does not match metadata value {expected}");
    }
    Ok(())
}

#[cfg(not(feature = "shamir-sharing"))]
pub fn recovery_split(_args: RecoverySplitArgs) -> Result<()> {
    anyhow::bail!("this sshenv build was compiled without shamir-sharing support")
}

#[cfg(feature = "shamir-sharing")]
pub fn recovery_validate_share(args: RecoveryShareFileArgs) -> Result<()> {
    let encoded = fs::read_to_string(&args.share_file).with_context(|| {
        format!(
            "failed to read recovery share {}",
            args.share_file.display()
        )
    })?;
    let envelope = sshenv_vault::recovery::decode_recovery_share_envelope(encoded.trim())?;
    let metadata_verified = if let Some(metadata_path) = args.metadata.as_ref() {
        let metadata = load_recovery_share_metadata(metadata_path)?;
        sshenv_vault::recovery::validate_recovery_share_envelope_metadata(&metadata, &envelope)?;
        true
    } else {
        false
    };
    if args.json {
        println!(
            "{}",
            serde_json::json!({
                "valid": true,
                "metadata_verified": metadata_verified,
                "set_id": envelope.set_id,
                "threshold": envelope.threshold,
                "share_index": envelope.share.index,
                "share_bytes": envelope.share.value.len(),
            })
        );
    } else {
        println!("recovery share envelope: valid");
        println!("metadata verified: {}", yes_no(metadata_verified));
        println!("set id: {}", envelope.set_id);
        println!("threshold: {}", envelope.threshold);
        println!("share index: {}", envelope.share.index);
        println!("share bytes: {}", envelope.share.value.len());
    }
    Ok(())
}

#[cfg(not(feature = "shamir-sharing"))]
pub fn recovery_validate_share(_args: RecoveryShareFileArgs) -> Result<()> {
    anyhow::bail!("this sshenv build was compiled without shamir-sharing support")
}

#[cfg(feature = "shamir-sharing")]
pub fn recovery_combine(args: RecoveryCombineArgs) -> Result<()> {
    let (envelopes, metadata_verified) =
        load_recovery_share_envelopes(&args.share_files, args.metadata.as_ref())?;
    let recovered = zeroize::Zeroizing::new(
        sshenv_vault::recovery::combine_recovery_share_envelopes(&envelopes)?,
    );
    let recovered_hex = hex::encode(recovered.as_slice());
    if args.json {
        println!(
            "{}",
            serde_json::json!({
                "recovered_secret_hex": recovered_hex,
                "share_count": envelopes.len(),
                "metadata_verified": metadata_verified,
            })
        );
    } else {
        eprintln!("warning: recovered break-glass secret is being written to stdout as hex");
        eprintln!("metadata verified: {}", yes_no(metadata_verified));
        println!("{recovered_hex}");
    }
    Ok(())
}

#[cfg(not(feature = "shamir-sharing"))]
pub fn recovery_combine(_args: RecoveryCombineArgs) -> Result<()> {
    anyhow::bail!("this sshenv build was compiled without shamir-sharing support")
}

#[cfg(feature = "shamir-sharing")]
pub fn recovery_recover_recipient(
    ctx: &CmdContext,
    args: RecoveryRecoverRecipientArgs,
) -> Result<()> {
    if args.output.exists() {
        anyhow::bail!(
            "recovery output vault already exists: {}; choose a new path",
            args.output.display()
        );
    }
    let (envelopes, metadata_verified) =
        load_recovery_share_envelopes(&args.share_files, args.metadata.as_ref())?;
    let recovered = zeroize::Zeroizing::new(
        sshenv_vault::recovery::combine_recovery_share_envelopes(&envelopes)?,
    );
    if recovered.len() != sshenv_vault::models::DATA_KEY_LEN {
        anyhow::bail!(
            "recovered secret is {} bytes, expected vault data key length {}",
            recovered.len(),
            sshenv_vault::models::DATA_KEY_LEN
        );
    }
    let mut raw_key = [0_u8; sshenv_vault::models::DATA_KEY_LEN];
    raw_key.copy_from_slice(recovered.as_slice());
    let data_key = zeroize::Zeroizing::new(raw_key);
    let (ciphertext, _fps) = load_ciphertext_and_fps(&ctx.vault_path)?;
    let (mut vault, mut data_key) = sshenv_vault::Vault::unlock_with_data_key_and_passphrase(
        ciphertext,
        data_key,
        args.passphrase.as_deref(),
    )?;
    let entry = vault.add_recipient(&args.recipient_key, &data_key)?;
    let fingerprint = entry.fingerprint.clone();
    let rotated = rotate_recovered_vault_key_if_possible(&mut vault, &mut data_key)?;
    vault.save(&args.output, &data_key)?;
    eprintln!(
        "Recovered vault to {} with new recipient {}. Metadata verified: {}. Data key rotated: {}.",
        args.output.display(),
        fingerprint,
        yes_no(metadata_verified),
        yes_no(rotated)
    );
    Ok(())
}

#[cfg(not(feature = "shamir-sharing"))]
pub fn recovery_recover_recipient(
    _ctx: &CmdContext,
    _args: RecoveryRecoverRecipientArgs,
) -> Result<()> {
    anyhow::bail!("this sshenv build was compiled without shamir-sharing support")
}

#[cfg(all(feature = "shamir-sharing", feature = "rekey"))]
fn rotate_recovered_vault_key_if_possible(
    vault: &mut Vault,
    data_key: &mut DataKey,
) -> Result<bool> {
    let recipient_descriptors = vault
        .recipients
        .iter()
        .map(|recipient| recipient.public_key_line.clone())
        .collect::<Vec<_>>();
    if recipient_descriptors
        .iter()
        .any(|descriptor| descriptor.trim().is_empty())
    {
        return Ok(false);
    }
    *data_key = vault.rotate_data_key(&recipient_descriptors)?;
    Ok(true)
}

#[cfg(all(feature = "shamir-sharing", not(feature = "rekey")))]
#[allow(clippy::missing_const_for_fn, clippy::unnecessary_wraps)]
fn rotate_recovered_vault_key_if_possible(
    _vault: &mut Vault,
    _data_key: &mut DataKey,
) -> Result<bool> {
    Ok(false)
}

#[cfg(feature = "shamir-sharing")]
pub(crate) fn load_recovery_share_envelopes(
    share_files: &[PathBuf],
    metadata_path: Option<&PathBuf>,
) -> Result<(Vec<sshenv_vault::recovery::RecoveryShareEnvelope>, bool)> {
    let envelopes = share_files
        .iter()
        .map(|path| {
            let encoded = fs::read_to_string(path)
                .with_context(|| format!("failed to read recovery share {}", path.display()))?;
            sshenv_vault::recovery::decode_recovery_share_envelope(encoded.trim())
                .map_err(anyhow::Error::from)
        })
        .collect::<Result<Vec<_>>>()?;
    let metadata_verified = if let Some(metadata_path) = metadata_path {
        let metadata = load_recovery_share_metadata(metadata_path)?;
        for envelope in &envelopes {
            sshenv_vault::recovery::validate_recovery_share_envelope_metadata(&metadata, envelope)?;
        }
        true
    } else {
        false
    };
    Ok((envelopes, metadata_verified))
}

#[cfg(feature = "recovery-shares")]
pub fn recovery_validate(args: RecoveryMetadataArgs) -> Result<()> {
    let metadata = load_recovery_share_metadata(&args.metadata_path)?;
    sshenv_vault::recovery::validate_recovery_share_set_metadata(&metadata)?;
    if args.json {
        println!(
            "{}",
            serde_json::json!({
                "valid": true,
                "set_id": metadata.id,
                "threshold": metadata.threshold,
                "share_count": metadata.shares.len(),
                "shamir": metadata.shamir,
            })
        );
    } else {
        println!("recovery metadata: valid");
        println!("set id: {}", metadata.id);
        println!("threshold: {}", metadata.threshold);
        println!("shares: {}", metadata.shares.len());
        println!(
            "shamir: {}",
            if metadata.shamir.is_some() {
                "configured"
            } else {
                "not configured"
            }
        );
    }
    Ok(())
}

#[cfg(not(feature = "recovery-shares"))]
pub fn recovery_validate(_args: RecoveryMetadataArgs) -> Result<()> {
    anyhow::bail!("this sshenv build was compiled without recovery-shares support")
}

#[cfg(feature = "recovery-shares")]
pub fn recovery_plan(args: RecoveryPlanArgs) -> Result<()> {
    let metadata = load_recovery_share_metadata(&args.metadata_path)?;
    if args.break_glass {
        let plan = sshenv_vault::recovery::plan_break_glass_recovery(&metadata, &args.share_ids)?;
        if args.json {
            println!("{}", serde_json::to_string_pretty(&plan)?);
        } else {
            println!("break-glass recovery plan");
            println!("=========================");
            println!("set id: {}", plan.set_id);
            println!("ready: {}", yes_no(plan.ready));
            println!("steps:");
            for step in &plan.steps {
                println!("- {step}");
            }
            println!("warnings:");
            for warning in &plan.warnings {
                println!("- {warning}");
            }
        }
    } else {
        let plan = sshenv_vault::recovery::plan_m_of_n_unlock(&metadata, &args.share_ids)?;
        if args.json {
            println!("{}", serde_json::to_string_pretty(&plan)?);
        } else {
            println!("recovery unlock plan");
            println!("====================");
            println!("set id: {}", plan.set_id);
            println!("threshold: {}", plan.threshold);
            println!("provided valid shares: {}", plan.provided_share_ids.len());
            println!("ignored unknown shares: {}", plan.ignored_share_ids.len());
            for share_id in &plan.ignored_share_ids {
                println!("- {share_id}");
            }
            println!("missing shares: {}", plan.missing_share_count);
            println!("ready: {}", yes_no(plan.ready));
        }
    }
    Ok(())
}

#[cfg(not(feature = "recovery-shares"))]
pub fn recovery_plan(_args: RecoveryPlanArgs) -> Result<()> {
    anyhow::bail!("this sshenv build was compiled without recovery-shares support")
}

#[cfg(feature = "recovery-shares")]
fn load_recovery_share_metadata(
    path: &Path,
) -> Result<sshenv_vault::models::RecoveryShareSetMetadataV2> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("failed to read recovery metadata {}", path.display()))?;
    serde_json::from_str(&content)
        .with_context(|| format!("failed to parse recovery metadata {}", path.display()))
}

#[cfg(feature = "remote-factor")]
pub fn remote_list(ctx: &CmdContext, args: RemoteListArgs) -> Result<()> {
    let (ciphertext, _fps) = load_ciphertext_and_fps(&ctx.vault_path)?;
    let factors = ciphertext
        .policy_metadata
        .as_ref()
        .map_or(&[][..], |metadata| metadata.remote_factors.as_slice());
    if args.json {
        println!("{}", serde_json::to_string_pretty(factors)?);
    } else if factors.is_empty() {
        println!("(no remote/KMS factor metadata)");
    } else {
        for factor in factors {
            println!(
                "{} {:?}{}",
                factor.id,
                factor.backend,
                factor
                    .label
                    .as_ref()
                    .map_or_else(String::new, |label| format!(" ({label})"))
            );
        }
    }
    Ok(())
}

#[cfg(not(feature = "remote-factor"))]
pub fn remote_list(_ctx: &CmdContext, _args: RemoteListArgs) -> Result<()> {
    anyhow::bail!("this sshenv build was compiled without remote-factor support")
}

#[cfg(feature = "remote-factor")]
pub fn remote_import(ctx: &CmdContext, args: RemoteMetadataArgs) -> Result<()> {
    let imported = load_remote_factor_metadata(&args.metadata_path)?;
    sshenv_vault::remote::validate_remote_factor_metadata(&imported).map_err(anyhow::Error::msg)?;
    let (mut vault, data_key) = load_and_unlock_metadata(&ctx.vault_path)?;
    ensure_policy_metadata_v2(&vault)?;
    let metadata = vault.policy_metadata.get_or_insert_with(Default::default);
    let replaced = metadata
        .remote_factors
        .iter()
        .any(|factor| factor.id == imported.id);
    metadata
        .remote_factors
        .retain(|factor| factor.id != imported.id);
    let factor_id = imported.id.clone();
    metadata.remote_factors.push(imported);
    metadata
        .remote_factors
        .sort_by(|left, right| left.id.cmp(&right.id));
    save_vault(ctx, &mut vault, &data_key)?;
    if args.json {
        println!(
            "{}",
            serde_json::json!({ "imported": factor_id, "replaced": replaced })
        );
    } else if replaced {
        eprintln!("Replaced remote/KMS factor metadata {factor_id}.");
    } else {
        eprintln!("Imported remote/KMS factor metadata {factor_id}.");
    }
    Ok(())
}

#[cfg(not(feature = "remote-factor"))]
pub fn remote_import(_ctx: &CmdContext, _args: RemoteMetadataArgs) -> Result<()> {
    anyhow::bail!("this sshenv build was compiled without remote-factor support")
}

#[cfg(feature = "remote-factor")]
pub fn remote_remove(ctx: &CmdContext, args: RemoteRemoveArgs) -> Result<()> {
    let (mut vault, data_key) = load_and_unlock_metadata(&ctx.vault_path)?;
    ensure_policy_metadata_v2(&vault)?;
    let Some(metadata) = vault.policy_metadata.as_mut() else {
        anyhow::bail!("remote/KMS factor metadata '{}' is not configured", args.id);
    };
    let before = metadata.remote_factors.len();
    metadata
        .remote_factors
        .retain(|factor| factor.id != args.id);
    if metadata.remote_factors.len() == before {
        anyhow::bail!("remote/KMS factor metadata '{}' is not configured", args.id);
    }
    save_vault(ctx, &mut vault, &data_key)?;
    eprintln!("Removed remote/KMS factor metadata {}.", args.id);
    Ok(())
}

#[cfg(not(feature = "remote-factor"))]
pub fn remote_remove(_ctx: &CmdContext, _args: RemoteRemoveArgs) -> Result<()> {
    anyhow::bail!("this sshenv build was compiled without remote-factor support")
}

#[derive(Debug, Serialize)]
struct RemotePlanOutput {
    remote_factor_feature_enabled: bool,
    kms_factor_feature_enabled: bool,
    metadata: RemoteFactorMetadataV2,
    import_example: String,
    enable_command_example: String,
    notes: Vec<String>,
}

pub fn remote_plan(args: RemotePlanArgs) -> Result<()> {
    let backend = remote_backend_kind(args.backend);
    let mut params = BTreeMap::new();
    match args.backend {
        RemoteBackendArg::SelfHosted => {
            params.insert(
                "url".to_string(),
                args.url
                    .unwrap_or_else(|| "https://unlock.example.internal".to_string()),
            );
        }
        RemoteBackendArg::CloudKms => {
            params.insert(
                "key".to_string(),
                args.key
                    .unwrap_or_else(|| "alias/sshenv-vault-unlock".to_string()),
            );
        }
        RemoteBackendArg::OidcApproval => {
            params.insert(
                "url".to_string(),
                args.url
                    .unwrap_or_else(|| "https://approvals.example.internal".to_string()),
            );
        }
    }
    if let Some(command) = args.command {
        params.insert("command".to_string(), command);
    }
    let metadata = RemoteFactorMetadataV2 {
        id: args.id,
        backend,
        label: None,
        params,
    };
    let notes = remote_plan_notes(args.backend);
    let output = RemotePlanOutput {
        remote_factor_feature_enabled: cfg!(feature = "remote-factor"),
        kms_factor_feature_enabled: cfg!(feature = "kms-factor"),
        import_example: "sshenv security remote import <metadata.json>".to_string(),
        enable_command_example:
            "sshenv security remote enable-command <metadata.json> <request.json>".to_string(),
        metadata,
        notes,
    };

    if args.json {
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!("remote/KMS factor plan");
        println!("======================");
        println!(
            "remote-factor feature: {}",
            enabled_label(output.remote_factor_feature_enabled)
        );
        println!(
            "kms-factor feature: {}",
            enabled_label(output.kms_factor_feature_enabled)
        );
        println!("metadata template:");
        println!("{}", serde_json::to_string_pretty(&output.metadata)?);
        println!("import: {}", output.import_example);
        println!(
            "enable command-backed factor: {}",
            output.enable_command_example
        );
        println!("notes:");
        for note in &output.notes {
            println!("- {note}");
        }
    }
    Ok(())
}

const fn remote_backend_kind(backend: RemoteBackendArg) -> RemoteFactorBackendKindV2 {
    match backend {
        RemoteBackendArg::SelfHosted => RemoteFactorBackendKindV2::SelfHosted,
        RemoteBackendArg::CloudKms => RemoteFactorBackendKindV2::CloudKms,
        RemoteBackendArg::OidcApproval => RemoteFactorBackendKindV2::OidcApproval,
    }
}

fn remote_plan_notes(backend: RemoteBackendArg) -> Vec<String> {
    let mut notes = vec![
        "remote/KMS metadata is non-secret and does not enable unlock by itself".to_string(),
        "backend wrapping/unwrapping must provide audit logging and replay protection".to_string(),
        "use `enable-command` with a non-secret `command` metadata param to bind the vault payload to an external adapter".to_string(),
    ];
    match backend {
        RemoteBackendArg::SelfHosted => {
            notes.push(
                "self-hosted service should authenticate clients and enforce approval/TTL policy"
                    .to_string(),
            );
            notes.push(
                "command-backed adapters can set a non-secret `command` param and use `remote command-wrap` / `remote command-unwrap`"
                    .to_string(),
            );
        }
        RemoteBackendArg::CloudKms => {
            notes.push(
                "cloud KMS deployments should bind requests to vault identity and operator IAM"
                    .to_string(),
            );
            notes.push(
                "external KMS CLIs can be integrated with a non-secret `command` param plus `remote command-wrap` / `remote command-unwrap`"
                    .to_string(),
            );
        }
        RemoteBackendArg::OidcApproval => {
            notes.push("OIDC approval flows should bind approval subject, device, vault generation, and expiry".to_string());
            notes.push(
                "approval brokers can be integrated with a non-secret `command` param plus `remote command-wrap` / `remote command-unwrap`"
                    .to_string(),
            );
        }
    }
    notes
}

#[cfg(feature = "remote-factor")]
pub fn remote_validate(args: RemoteMetadataArgs) -> Result<()> {
    let metadata = load_remote_factor_metadata(&args.metadata_path)?;
    sshenv_vault::remote::validate_remote_factor_metadata(&metadata).map_err(anyhow::Error::msg)?;
    if args.json {
        println!(
            "{}",
            serde_json::json!({
                "valid": true,
                "id": metadata.id,
                "backend": metadata.backend,
                "label": metadata.label,
                "params": metadata.params,
            })
        );
    } else {
        println!("remote factor metadata: valid");
        println!("id: {}", metadata.id);
        println!("backend: {:?}", metadata.backend);
        println!("params: {}", metadata.params.len());
    }
    Ok(())
}

#[cfg(not(feature = "remote-factor"))]
pub fn remote_validate(_args: RemoteMetadataArgs) -> Result<()> {
    anyhow::bail!("this sshenv build was compiled without remote-factor support")
}

#[cfg(feature = "remote-factor")]
pub fn remote_request_template(args: RemoteRequestTemplateArgs) -> Result<()> {
    let metadata = load_remote_factor_metadata(&args.metadata_path)?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());
    let mut context = BTreeMap::from([
        ("vault-id".to_string(), args.vault_id),
        (
            "request-id".to_string(),
            args.request_id.unwrap_or_else(|| format!("req-{now}")),
        ),
        ("generation".to_string(), args.generation.to_string()),
        (
            "expires-unix".to_string(),
            args.expires_unix.unwrap_or(now + 300).to_string(),
        ),
    ]);
    match metadata.backend {
        RemoteFactorBackendKindV2::SelfHosted => {
            context.insert(
                "client-id".to_string(),
                args.client_id
                    .unwrap_or_else(|| "sshenv-client".to_string()),
            );
        }
        RemoteFactorBackendKindV2::CloudKms => {
            context.insert(
                "encryption-context".to_string(),
                args.encryption_context
                    .unwrap_or_else(|| "sshenv:vault".to_string()),
            );
        }
        RemoteFactorBackendKindV2::OidcApproval => {
            context.insert(
                "subject".to_string(),
                args.subject
                    .unwrap_or_else(|| "user@example.com".to_string()),
            );
            context.insert(
                "audience".to_string(),
                args.audience.unwrap_or_else(|| "sshenv".to_string()),
            );
        }
    }
    let request = sshenv_vault::remote::RemoteFactorRequest {
        factor_id: metadata.id,
        context,
    };
    println!("{}", serde_json::to_string_pretty(&request)?);
    Ok(())
}

#[cfg(not(feature = "remote-factor"))]
pub fn remote_request_template(_args: RemoteRequestTemplateArgs) -> Result<()> {
    anyhow::bail!("this sshenv build was compiled without remote-factor support")
}

#[cfg(feature = "remote-factor")]
pub fn remote_validate_request(args: RemoteRequestArgs) -> Result<()> {
    let metadata = load_remote_factor_metadata(&args.metadata_path)?;
    let request = load_remote_factor_request(&args.request_path)?;
    sshenv_vault::remote::validate_remote_factor_request(&metadata, &request)?;
    let checked_expectations = validate_remote_request_expectations(&request, &args)?;
    if args.json {
        println!(
            "{}",
            serde_json::json!({
                "valid": true,
                "factor_id": request.factor_id,
                "backend": metadata.backend,
                "context_keys": request.context.keys().collect::<Vec<_>>(),
                "checked_expectations": checked_expectations,
            })
        );
    } else {
        println!("remote factor request: valid");
        println!("factor id: {}", request.factor_id);
        println!("backend: {:?}", metadata.backend);
        println!("context keys: {}", request.context.len());
        if !checked_expectations.is_empty() {
            println!("checked expectations: {}", checked_expectations.join(", "));
        }
    }
    Ok(())
}

#[cfg(not(feature = "remote-factor"))]
pub fn remote_validate_request(_args: RemoteRequestArgs) -> Result<()> {
    anyhow::bail!("this sshenv build was compiled without remote-factor support")
}

#[cfg(feature = "remote-factor")]
pub fn remote_command_wrap(args: RemoteCommandWrapArgs) -> Result<()> {
    if !args.payload_key_hex_stdin {
        anyhow::bail!(
            "remote command-wrap requires --payload-key-hex-stdin to avoid shell-history exposure"
        );
    }
    let metadata = load_remote_factor_metadata(&args.metadata_path)?;
    let request = load_remote_factor_request(&args.request_path)?;
    let payload_key = read_hex_secret_from_stdin("payload key")?;
    let backend = sshenv_vault::remote::CommandRemoteFactorBackend::from_metadata(metadata)?;
    let response = backend.wrap_payload_key(&request, payload_key.as_slice())?;
    let wrapped_key_hex = hex::encode(&response.wrapped_key);
    if args.json {
        println!(
            "{}",
            serde_json::json!({
                "wrapped_key_hex": wrapped_key_hex,
                "audit_id": response.audit_id,
            })
        );
    } else {
        if let Some(audit_id) = response.audit_id {
            eprintln!("remote audit id: {audit_id}");
        }
        println!("{wrapped_key_hex}");
    }
    Ok(())
}

#[cfg(not(feature = "remote-factor"))]
pub fn remote_command_wrap(_args: RemoteCommandWrapArgs) -> Result<()> {
    anyhow::bail!("this sshenv build was compiled without remote-factor support")
}

#[cfg(feature = "remote-factor")]
pub fn remote_command_unwrap(args: RemoteCommandUnwrapArgs) -> Result<()> {
    if !args.wrapped_key_hex_stdin {
        anyhow::bail!(
            "remote command-unwrap requires --wrapped-key-hex-stdin to avoid shell-history exposure"
        );
    }
    let metadata = load_remote_factor_metadata(&args.metadata_path)?;
    let request = load_remote_factor_request(&args.request_path)?;
    let wrapped_key = read_hex_secret_from_stdin("wrapped key")?;
    let backend = sshenv_vault::remote::CommandRemoteFactorBackend::from_metadata(metadata)?;
    let payload_key =
        zeroize::Zeroizing::new(backend.unwrap_payload_key(&request, wrapped_key.as_slice())?);
    let payload_key_hex = hex::encode(payload_key.as_slice());
    if args.json {
        println!(
            "{}",
            serde_json::json!({
                "payload_key_hex": payload_key_hex,
            })
        );
    } else {
        eprintln!("warning: recovered remote payload key is being written to stdout as hex");
        println!("{payload_key_hex}");
    }
    Ok(())
}

#[cfg(not(feature = "remote-factor"))]
pub fn remote_command_unwrap(_args: RemoteCommandUnwrapArgs) -> Result<()> {
    anyhow::bail!("this sshenv build was compiled without remote-factor support")
}

#[cfg(feature = "remote-factor")]
pub fn remote_enable_command(ctx: &CmdContext, args: RemoteEnableCommandArgs) -> Result<()> {
    let remote_metadata = load_remote_factor_metadata(&args.metadata_path)?;
    let request = load_remote_factor_request(&args.request_path)?;
    let (mut vault, data_key) = load_and_unlock_metadata(&ctx.vault_path)?;
    ensure_policy_metadata_v2(&vault)?;
    let factor_id = remote_metadata.id.clone();
    vault.enable_remote_command_factor(remote_metadata, &request)?;
    save_vault(ctx, &mut vault, &data_key)?;
    eprintln!(
        "Enabled command-backed remote/KMS factor {factor_id}. Set SSHENV_REMOTE_REQUEST to a fresh request JSON when unlocking."
    );
    Ok(())
}

#[cfg(not(feature = "remote-factor"))]
pub fn remote_enable_command(_ctx: &CmdContext, _args: RemoteEnableCommandArgs) -> Result<()> {
    anyhow::bail!("this sshenv build was compiled without remote-factor support")
}

#[cfg(feature = "remote-factor")]
fn read_hex_secret_from_stdin(label: &str) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    let mut input = String::new();
    std::io::stdin()
        .read_to_string(&mut input)
        .with_context(|| format!("failed to read {label} hex from stdin"))?;
    Ok(zeroize::Zeroizing::new(
        hex::decode(input.trim())
            .with_context(|| format!("failed to decode {label} hex from stdin"))?,
    ))
}

#[cfg(feature = "remote-factor")]
fn validate_remote_request_expectations(
    request: &sshenv_vault::remote::RemoteFactorRequest,
    args: &RemoteRequestArgs,
) -> Result<Vec<String>> {
    let mut checked = Vec::new();
    if let Some(expected) = args.expected_vault_id.as_deref() {
        ensure_remote_context_equals(request, "vault-id", expected)?;
        checked.push("vault-id".to_string());
    }
    if let Some(expected) = args.expected_generation {
        ensure_remote_context_equals(request, "generation", &expected.to_string())?;
        checked.push("generation".to_string());
    }
    if let Some(expected) = args.expected_request_id.as_deref() {
        ensure_remote_context_equals(request, "request-id", expected)?;
        checked.push("request-id".to_string());
    }
    Ok(checked)
}

#[cfg(feature = "remote-factor")]
fn ensure_remote_context_equals(
    request: &sshenv_vault::remote::RemoteFactorRequest,
    key: &str,
    expected: &str,
) -> Result<()> {
    let actual = request
        .context
        .get(key)
        .ok_or_else(|| anyhow::anyhow!("remote request context is missing `{key}`"))?;
    if actual != expected {
        anyhow::bail!(
            "remote request context `{key}` value '{actual}' does not match expected '{expected}'"
        );
    }
    Ok(())
}

#[cfg(feature = "remote-factor")]
fn load_remote_factor_metadata(
    path: &Path,
) -> Result<sshenv_vault::models::RemoteFactorMetadataV2> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("failed to read remote factor metadata {}", path.display()))?;
    serde_json::from_str(&content)
        .with_context(|| format!("failed to parse remote factor metadata {}", path.display()))
}

#[cfg(feature = "remote-factor")]
fn load_remote_factor_request(path: &Path) -> Result<sshenv_vault::remote::RemoteFactorRequest> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("failed to read remote factor request {}", path.display()))?;
    serde_json::from_str(&content)
        .with_context(|| format!("failed to parse remote factor request {}", path.display()))
}

#[cfg(any(feature = "recovery-shares", feature = "remote-factor"))]
fn ensure_policy_metadata_v2(vault: &Vault) -> Result<()> {
    if vault.header.version != VERSION_V2 {
        anyhow::bail!(
            "advanced policy metadata requires v2; run `sshenv migrate-vault --to v2` first"
        );
    }
    Ok(())
}

pub fn profile_policy_backups(ctx: &CmdContext, args: ProfilePolicyBackupsArgs) -> Result<()> {
    let output = build_profile_policy_backups(ctx)?;
    if args.json {
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        print_profile_policy_backups(&output);
    }
    Ok(())
}

pub fn profile_policy_verify_backup(
    _ctx: &CmdContext,
    args: ProfilePolicyVerifyBackupArgs,
) -> Result<()> {
    let output = build_profile_policy_verify_backup(&args.backup_path);
    if args.json {
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        print_profile_policy_verify_backup(&output);
    }
    if !output.readable || !output.unlockable || output.errors.unwrap_or(0) > 0 {
        anyhow::bail!(
            "profile policy backup verification failed for {}",
            output.path
        );
    }
    Ok(())
}

pub fn profile_policy_prune_backups(
    ctx: &CmdContext,
    args: ProfilePolicyPruneBackupsArgs,
) -> Result<()> {
    let dry_run = args.dry_run || !args.confirm;
    let output = build_profile_policy_prune_backups(ctx, args.keep, dry_run)?;
    if args.json {
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        print_profile_policy_prune_backups(&output);
    }
    if !output.errors.is_empty() {
        anyhow::bail!(
            "failed to prune {} profile-policy backup(s)",
            output.errors.len()
        );
    }
    Ok(())
}

fn build_profile_policy_backups(ctx: &CmdContext) -> Result<ProfilePolicyBackupsOutput> {
    let mut backups = profile_policy_backup_candidates(ctx)?
        .into_iter()
        .map(|candidate| candidate.info)
        .collect::<Vec<_>>();
    backups.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(ProfilePolicyBackupsOutput { backups })
}

fn profile_policy_backup_candidates(ctx: &CmdContext) -> Result<Vec<ProfilePolicyBackupCandidate>> {
    let vault_file_name = ctx
        .vault_path
        .file_name()
        .map_or_else(|| "vault".into(), |name| name.to_string_lossy());
    let parent = ctx.vault_path.parent().unwrap_or_else(|| Path::new("."));
    let mut backups = Vec::new();

    if parent.exists() {
        for entry in fs::read_dir(parent)? {
            let entry = entry?;
            let path = entry.path();
            let file_name = entry.file_name();
            let file_name = file_name.to_string_lossy();
            let Some(kind) = profile_policy_backup_kind(&file_name, &vault_file_name) else {
                continue;
            };
            backups.push(profile_policy_backup_candidate(path, kind));
        }
    }

    Ok(backups)
}

fn backup_verification_succeeded(output: &ProfilePolicyVerifyBackupOutput) -> bool {
    output.readable && output.unlockable && output.errors.unwrap_or(0) == 0
}

fn build_profile_policy_restore_backup_preview(
    ctx: &CmdContext,
    backup_path: &Path,
) -> ProfilePolicyRestoreBackupPreviewOutput {
    let current = build_profile_policy_verify_backup(&ctx.vault_path);
    let backup = build_profile_policy_verify_backup(backup_path);
    let generation_rollback = current
        .generation
        .zip(backup.generation)
        .map(|(current, backup)| backup < current);
    let mut error = None;
    if !backup_verification_succeeded(&backup) {
        error = backup
            .error
            .clone()
            .or_else(|| Some("backup verification failed".to_string()));
    } else if !current.readable {
        error = current
            .error
            .clone()
            .or_else(|| Some("current vault is not readable".to_string()));
    }
    let would_restore = error.is_none();
    ProfilePolicyRestoreBackupPreviewOutput {
        current,
        backup,
        would_restore,
        would_create_pre_restore_backup: would_restore,
        would_update_rollback_baseline: would_restore,
        generation_rollback,
        error,
    }
}

fn print_profile_policy_restore_backup_preview(output: &ProfilePolicyRestoreBackupPreviewOutput) {
    println!("profile policy restore-backup preview");
    println!("=====================================");
    println!("would restore: {}", yes_no(output.would_restore));
    println!(
        "would create pre-restore backup: {}",
        yes_no(output.would_create_pre_restore_backup)
    );
    println!(
        "would update rollback baseline: {}",
        yes_no(output.would_update_rollback_baseline)
    );
    println!(
        "generation rollback: {}",
        output.generation_rollback.map_or("unknown", yes_no)
    );
    if let Some(error) = &output.error {
        println!("error: {error}");
    }
    println!();
    println!("current:");
    print_profile_policy_verify_backup(&output.current);
    println!();
    println!("backup:");
    print_profile_policy_verify_backup(&output.backup);
}

fn build_profile_policy_verify_backup(path: &Path) -> ProfilePolicyVerifyBackupOutput {
    let mut output = ProfilePolicyVerifyBackupOutput {
        path: path.display().to_string(),
        readable: false,
        unlockable: false,
        version: None,
        generation: None,
        profiles_checked: None,
        warnings: None,
        errors: None,
        error: None,
    };

    let ciphertext = match Vault::load_ciphertext(path) {
        Ok(ciphertext) => ciphertext,
        Err(error) => {
            output.error = Some(error.to_string());
            return output;
        }
    };
    output.readable = true;
    output.version = Some(ciphertext.header.version);
    output.generation = ciphertext.generation();

    match load_and_unlock_metadata(path) {
        Ok((vault, _key)) => {
            output.unlockable = true;
            let validation = vault.validate_profile_policies();
            output.profiles_checked = Some(validation.profiles.len());
            output.warnings = Some(validation.warnings);
            output.errors = Some(validation.errors);
        }
        Err(error) => output.error = Some(error.to_string()),
    }
    output
}

fn print_profile_policy_verify_backup(output: &ProfilePolicyVerifyBackupOutput) {
    println!("profile policy backup verification");
    println!("==================================");
    println!("path: {}", output.path);
    println!("readable: {}", yes_no(output.readable));
    println!("unlockable: {}", yes_no(output.unlockable));
    println!(
        "version: {}",
        output
            .version
            .map_or_else(|| "unknown".to_string(), |value| value.to_string())
    );
    println!(
        "generation: {}",
        output
            .generation
            .map_or_else(|| "unknown".to_string(), |value| value.to_string())
    );
    println!(
        "profiles checked: {}",
        output
            .profiles_checked
            .map_or_else(|| "unknown".to_string(), |value| value.to_string())
    );
    println!(
        "warnings: {}",
        output
            .warnings
            .map_or_else(|| "unknown".to_string(), |value| value.to_string())
    );
    println!(
        "errors: {}",
        output
            .errors
            .map_or_else(|| "unknown".to_string(), |value| value.to_string())
    );
    if let Some(error) = &output.error {
        println!("error: {error}");
    }
}

fn profile_policy_backup_kind(file_name: &str, vault_file_name: &str) -> Option<&'static str> {
    if file_name.starts_with(&format!("{vault_file_name}.pre-restore.bak.")) {
        Some("pre-restore")
    } else if file_name.starts_with(&format!("{vault_file_name}.bak.")) {
        Some("bulk-backup")
    } else {
        None
    }
}

fn profile_policy_backup_candidate(
    path: PathBuf,
    kind: &'static str,
) -> ProfilePolicyBackupCandidate {
    let metadata_result = fs::metadata(&path);
    let modified = metadata_result
        .as_ref()
        .ok()
        .and_then(|metadata| metadata.modified().ok());
    let modified_unix_seconds = modified
        .and_then(|modified| modified.duration_since(UNIX_EPOCH).ok())
        .map(|duration| duration.as_secs());
    let size = metadata_result.as_ref().ok().map(fs::Metadata::len);

    let (version, generation, parse_error) = match Vault::load_ciphertext(&path) {
        Ok(ciphertext) => (
            Some(ciphertext.header.version),
            ciphertext.generation(),
            None,
        ),
        Err(error) => (None, None, Some(error.to_string())),
    };
    let error = metadata_result
        .err()
        .map(|error| error.to_string())
        .or(parse_error);

    let info = ProfilePolicyBackupInfo {
        path: path.display().to_string(),
        kind,
        modified_unix_seconds,
        size,
        version,
        generation,
        error,
    };
    ProfilePolicyBackupCandidate {
        path,
        modified,
        info,
    }
}

fn build_profile_policy_prune_backups(
    ctx: &CmdContext,
    keep: usize,
    dry_run: bool,
) -> Result<ProfilePolicyPruneBackupsOutput> {
    let mut backups = profile_policy_backup_candidates(ctx)?;
    backups.sort_by(|left, right| {
        right
            .modified
            .cmp(&left.modified)
            .then_with(|| right.path.cmp(&left.path))
    });

    let kept = backups
        .iter()
        .take(keep)
        .map(|candidate| candidate.info.clone())
        .collect::<Vec<_>>();
    let prune_candidates = backups.into_iter().skip(keep).collect::<Vec<_>>();
    let mut pruned = Vec::new();
    let mut errors = Vec::new();

    for candidate in prune_candidates {
        if !dry_run {
            if let Err(error) = fs::remove_file(&candidate.path) {
                errors.push(ProfilePolicyPruneBackupError {
                    path: candidate.info.path.clone(),
                    error: error.to_string(),
                });
                continue;
            }
        }
        pruned.push(candidate.info);
    }

    Ok(ProfilePolicyPruneBackupsOutput {
        keep,
        dry_run,
        kept,
        pruned,
        errors,
    })
}

fn print_profile_policy_backups(output: &ProfilePolicyBackupsOutput) {
    if output.backups.is_empty() {
        println!("profile policy backups: none");
        return;
    }
    println!("profile policy backups");
    println!("======================");
    for backup in &output.backups {
        print_profile_policy_backup_info(backup);
        println!();
    }
}

fn print_profile_policy_prune_backups(output: &ProfilePolicyPruneBackupsOutput) {
    println!("profile policy prune-backups plan");
    println!("==================================");
    println!("keep: {}", output.keep);
    println!("dry-run: {}", yes_no(output.dry_run));
    println!("kept: {}", output.kept.len());
    println!("pruned: {}", output.pruned.len());
    if output.dry_run && !output.pruned.is_empty() {
        println!("planned prune:");
    } else if !output.pruned.is_empty() {
        println!("pruned:");
    }
    for backup in &output.pruned {
        println!();
        print_profile_policy_backup_info(backup);
    }
    if !output.errors.is_empty() {
        println!("errors:");
        for error in &output.errors {
            println!("- {}: {}", error.path, error.error);
        }
    }
}

fn print_profile_policy_backup_info(backup: &ProfilePolicyBackupInfo) {
    println!("path: {}", backup.path);
    println!("kind: {}", backup.kind);
    println!(
        "modified unix seconds: {}",
        backup
            .modified_unix_seconds
            .map_or_else(|| "unknown".to_string(), |value| value.to_string())
    );
    println!(
        "size: {}",
        backup
            .size
            .map_or_else(|| "unknown".to_string(), |value| value.to_string())
    );
    println!(
        "version: {}",
        backup
            .version
            .map_or_else(|| "unknown".to_string(), |value| value.to_string())
    );
    println!(
        "generation: {}",
        backup
            .generation
            .map_or_else(|| "unknown".to_string(), |value| value.to_string())
    );
    if let Some(error) = &backup.error {
        println!("error: {error}");
    }
}

pub fn profile_policy_list(ctx: &CmdContext) -> Result<()> {
    let (vault, _key) = crate::commands::load_and_unlock(&ctx.vault_path)?;
    if vault.profiles.profile_policies.is_empty() {
        eprintln!("(no profile policy metadata)");
        return Ok(());
    }
    for (profile, policy) in &vault.profiles.profile_policies {
        let findings = profile_policy_findings(&vault, policy.preset);
        let requirements = format_profile_requirements(policy);
        if findings.is_empty() {
            println!("{profile}\t{:?}\t{requirements}\tok", policy.preset);
        } else {
            println!(
                "{profile}\t{:?}\t{requirements}\tadvisory-only; unmet: {}",
                policy.preset,
                findings.join(", ")
            );
        }
    }
    Ok(())
}

pub fn profile_policy_status(ctx: &CmdContext, args: ProfilePolicyStatusArgs) -> Result<()> {
    let (vault, _key) = load_and_unlock_metadata(&ctx.vault_path)?;
    let status = build_profile_policy_status(&vault, &args.profile)?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&status)?);
        return Ok(());
    }

    print_profile_policy_status(&status);
    Ok(())
}

pub fn profile_policy_check(ctx: &CmdContext, args: ProfilePolicyCheckArgs) -> Result<()> {
    let (vault, _key) = load_and_unlock_metadata(&ctx.vault_path)?;
    let output = build_profile_policy_check(&vault)?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        print_profile_policy_check(&output);
    }

    if output.errors > 0 {
        anyhow::bail!(
            "profile policy check failed with {} error(s)",
            output.errors
        );
    }
    if args.strict && output.warnings > 0 {
        anyhow::bail!(
            "profile policy check failed with {} warning(s) in strict mode",
            output.warnings
        );
    }
    Ok(())
}

fn print_profile_policy_status(status: &ProfilePolicyStatusOutput) {
    println!("profile: {}", status.profile);
    println!("exists: {}", yes_no(status.exists));
    println!(
        "profile-key mode: {}",
        enabled_disabled(status.profile_key_mode)
    );
    println!(
        "independently encrypted: {}",
        yes_no(status.independently_encrypted)
    );
    println!(
        "policy metadata: {}",
        if status.policy_metadata_present {
            "present"
        } else {
            "absent"
        }
    );

    if let Some(preset) = &status.preset {
        println!("preset: {preset}");
        println!("required: {}", status.required_factors.join(", "));
        println!(
            "profile factor metadata: passphrase={}, device-seal={}",
            yes_no(status.factor_metadata.passphrase),
            status.factor_metadata.device_seal_label
        );
        for requirement in &status.requirements {
            println!("requirement {}: {}", requirement.factor, requirement.source);
        }
    }

    if status.warnings.is_empty() {
        println!("warnings: none");
    } else {
        println!("warnings:");
        for warning in &status.warnings {
            println!("- {warning}");
        }
    }
    if status.errors.is_empty() {
        println!("errors: none");
    } else {
        println!("errors:");
        for error in &status.errors {
            println!("- {error}");
        }
    }
    if let Some(hint) = &status.repair_hint {
        println!("repair: {hint}");
    }
}

#[derive(Debug, Serialize)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "status JSON intentionally exposes independent boolean facts"
)]
struct ProfilePolicyStatusOutput {
    profile: String,
    exists: bool,
    profile_key_mode: bool,
    independently_encrypted: bool,
    policy_metadata_present: bool,
    preset: Option<String>,
    required_factors: Vec<&'static str>,
    factor_metadata: ProfileFactorMetadataStatus,
    requirements: Vec<ProfileRequirementStatus>,
    warnings: Vec<String>,
    errors: Vec<String>,
    findings: Vec<ProfilePolicyFinding>,
    repair_recommended: bool,
    repairable: bool,
    requires_passphrase: bool,
    requires_device_seal: bool,
    requires_recipient_key: bool,
    repair_actions: Vec<String>,
    unrepairable: Vec<String>,
    repair_hint: Option<String>,
}

#[derive(Debug, Serialize)]
struct ProfilePolicyApplyPlanOutput {
    profile: String,
    target_preset: String,
    plan: ProfilePolicyRepairPlan,
}

#[derive(Debug, Serialize)]
struct ProfilePolicyApplyAllPlanOutput {
    target_preset: String,
    profiles_total: usize,
    repairable_count: usize,
    unrepairable_count: usize,
    requires_passphrase_count: usize,
    requires_device_seal_count: usize,
    requires_recipient_key_count: usize,
    profiles: Vec<ProfilePolicyApplyPlanOutput>,
}

#[derive(Debug, Serialize)]
struct ProfilePolicyRepairAllPlanOutput {
    profiles_total: usize,
    repairable_count: usize,
    unrepairable_count: usize,
    requires_passphrase_count: usize,
    requires_device_seal_count: usize,
    requires_recipient_key_count: usize,
    profiles: Vec<ProfilePolicyRepairPlan>,
}

#[derive(Debug, Serialize)]
struct ProfilePolicyBackupsOutput {
    backups: Vec<ProfilePolicyBackupInfo>,
}

#[derive(Clone, Debug, Serialize)]
struct ProfilePolicyBackupInfo {
    path: String,
    kind: &'static str,
    modified_unix_seconds: Option<u64>,
    size: Option<u64>,
    version: Option<u8>,
    generation: Option<u64>,
    error: Option<String>,
}

#[derive(Debug)]
struct ProfilePolicyBackupCandidate {
    path: PathBuf,
    modified: Option<SystemTime>,
    info: ProfilePolicyBackupInfo,
}

#[derive(Debug, Serialize)]
struct ProfilePolicyPruneBackupsOutput {
    keep: usize,
    dry_run: bool,
    kept: Vec<ProfilePolicyBackupInfo>,
    pruned: Vec<ProfilePolicyBackupInfo>,
    errors: Vec<ProfilePolicyPruneBackupError>,
}

#[derive(Debug, Serialize)]
struct ProfilePolicyVerifyBackupOutput {
    path: String,
    readable: bool,
    unlockable: bool,
    version: Option<u8>,
    generation: Option<u64>,
    profiles_checked: Option<usize>,
    warnings: Option<usize>,
    errors: Option<usize>,
    error: Option<String>,
}

#[derive(Debug, Serialize)]
struct ProfilePolicyRestoreBackupPreviewOutput {
    current: ProfilePolicyVerifyBackupOutput,
    backup: ProfilePolicyVerifyBackupOutput,
    would_restore: bool,
    would_create_pre_restore_backup: bool,
    would_update_rollback_baseline: bool,
    generation_rollback: Option<bool>,
    error: Option<String>,
}

#[derive(Debug, Serialize)]
struct ProfilePolicyPruneBackupError {
    path: String,
    error: String,
}

#[derive(Debug, Serialize)]
struct ProfilePolicyCheckOutput {
    profiles_checked: usize,
    warnings: usize,
    errors: usize,
    repair_recommended: usize,
    repairable_profiles: Vec<String>,
    profiles: Vec<ProfilePolicyStatusOutput>,
}

#[derive(Debug, Serialize)]
struct ProfileFactorMetadataStatus {
    passphrase: bool,
    device_seal: bool,
    device_seal_label: String,
}

#[derive(Debug, Serialize)]
struct ProfileRequirementStatus {
    factor: &'static str,
    source: String,
}

fn build_profile_policy_check(vault: &Vault) -> Result<ProfilePolicyCheckOutput> {
    let check = vault.validate_profile_policies();
    let profiles = check
        .profiles
        .keys()
        .map(|profile| build_profile_policy_status(vault, profile))
        .collect::<Result<Vec<_>>>()?;
    let warnings = check.warnings;
    let errors = check.errors;
    let repairable_profiles = profiles
        .iter()
        .filter(|profile| profile.repairable)
        .map(|profile| profile.profile.clone())
        .collect::<Vec<_>>();

    Ok(ProfilePolicyCheckOutput {
        profiles_checked: profiles.len(),
        warnings,
        errors,
        repair_recommended: repairable_profiles.len(),
        repairable_profiles,
        profiles,
    })
}

fn print_profile_policy_check(output: &ProfilePolicyCheckOutput) {
    println!("profile policy check");
    println!("====================");
    println!("profiles checked: {}", output.profiles_checked);
    println!("warnings: {}", output.warnings);
    println!("errors: {}", output.errors);
    println!("repair recommended: {}", output.repair_recommended);

    for profile in &output.profiles {
        if profile.warnings.is_empty() && profile.errors.is_empty() {
            continue;
        }
        println!();
        println!("profile: {}", profile.profile);
        for warning in &profile.warnings {
            println!("warning: {warning}");
        }
        for error in &profile.errors {
            println!("error: {error}");
        }
        if let Some(hint) = &profile.repair_hint {
            println!("repair: {hint}");
        }
    }
}

fn build_profile_policy_status(vault: &Vault, profile: &str) -> Result<ProfilePolicyStatusOutput> {
    let validation = vault.validate_profile_policy(profile);
    if validation.profile_policy_missing() {
        anyhow::bail!("no such profile: {profile}");
    }

    let profile_exists = validation.profile_exists;
    let policy = vault.profiles.profile_policy(profile);
    let independently_encrypted = vault.profiles.profile_entries.contains_key(profile);
    let warnings = validation.warning_messages();
    let errors = validation.error_messages();
    let repair_plan = vault.plan_profile_policy_repair(profile, Some(&validation));
    let repair_actions = repair_plan.action_labels.clone();
    let repairable = repair_plan.repairable && !repair_plan.actions.is_empty();
    let repair_hint =
        policy.and_then(|policy| profile_repair_hint(vault, profile, policy, &validation.findings));

    Ok(ProfilePolicyStatusOutput {
        profile: profile.to_string(),
        exists: profile_exists,
        profile_key_mode: vault.profile_keys_enabled(),
        independently_encrypted,
        policy_metadata_present: policy.is_some(),
        preset: policy.map(|policy| format!("{:?}", policy.preset)),
        required_factors: policy.map_or_else(
            || vec!["none"],
            |policy| {
                if policy.required_factors.is_empty() {
                    return vec!["none"];
                }
                policy
                    .required_factors
                    .iter()
                    .copied()
                    .map(profile_requirement_label)
                    .collect()
            },
        ),
        factor_metadata: policy.map_or_else(
            || ProfileFactorMetadataStatus {
                passphrase: false,
                device_seal: false,
                device_seal_label: "no".to_string(),
            },
            |policy| ProfileFactorMetadataStatus {
                passphrase: profile_has_factor_metadata(policy, UnlockFactorKindV2::Passphrase),
                device_seal: profile_has_factor_metadata(policy, UnlockFactorKindV2::DeviceSeal),
                device_seal_label: profile_device_seal_metadata_label(policy),
            },
        ),
        requirements: policy.map_or_else(Vec::new, |policy| {
            policy
                .required_factors
                .iter()
                .copied()
                .map(|requirement| ProfileRequirementStatus {
                    factor: profile_requirement_label(requirement),
                    source: profile_requirement_source(vault, policy, requirement),
                })
                .collect()
        }),
        errors,
        findings: validation.findings,
        repair_recommended: repair_hint.is_some(),
        repairable,
        requires_passphrase: repair_plan.requires_passphrase,
        requires_device_seal: repair_plan.requires_device_seal,
        requires_recipient_key: repair_plan.requires_recipient_key,
        repair_actions,
        unrepairable: repair_plan.unrepairable,
        repair_hint,
        warnings,
    })
}

/// Print a warning when a profile's advisory policy is stronger than the
/// current vault posture.
pub fn warn_if_high_security_profile_stdout(vault: &Vault, profile: &str, command: &str) {
    let Some(policy) = vault.profiles.profile_policy(profile) else {
        return;
    };
    if policy.preset == ProfilePolicyPreset::Paranoid {
        eprintln!(
            "warning: `{command}` exposes secrets for paranoid profile '{profile}' via stdout; prefer `sshenv run` when possible."
        );
    }
}

pub fn warn_if_profile_policy_unmet(vault: &Vault, profile: &str) {
    let Some(policy) = vault.profiles.profile_policy(profile) else {
        return;
    };
    let findings = profile_policy_findings(vault, policy.preset);
    if findings.is_empty() {
        return;
    }
    eprintln!(
        "warning: profile '{profile}' has advisory policy {:?}, but the current vault posture does not satisfy: {}. Per-profile cryptographic enforcement is planned but not active yet.",
        policy.preset,
        findings.join(", ")
    );
}

/// Enforce explicit profile factor requirements against the current vault
/// posture. This is an opt-in UX enforcement layer until profile keys can be
/// cryptographically bound to per-profile factors.
pub fn ensure_profile_factor_requirements_met(vault: &Vault, profile: &str) -> Result<()> {
    let Some(policy) = vault.profiles.profile_policy(profile) else {
        return Ok(());
    };
    let missing: Vec<&'static str> = policy
        .required_factors
        .iter()
        .copied()
        .filter(|requirement| !profile_requirement_satisfied(vault, policy, *requirement))
        .map(profile_requirement_label)
        .collect();
    if missing.is_empty() {
        return Ok(());
    }
    anyhow::bail!(
        "profile '{profile}' requires enabled vault factor(s): {}. Enable the missing factor(s) or run `sshenv security profile-policy clear-requirements {profile}` to remove this opt-in requirement.",
        missing.join(", ")
    )
}

fn format_profile_requirements(policy: &ProfilePolicy) -> String {
    if policy.required_factors.is_empty() {
        return "required: none".to_string();
    }
    let requirements = policy
        .required_factors
        .iter()
        .copied()
        .map(profile_requirement_label)
        .collect::<Vec<_>>()
        .join(", ");
    format!("required: {requirements}")
}

const fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

const fn enabled_disabled(value: bool) -> &'static str {
    if value { "enabled" } else { "disabled" }
}

fn profile_has_factor_metadata(policy: &ProfilePolicy, kind: UnlockFactorKindV2) -> bool {
    policy
        .factor_metadata
        .iter()
        .any(|factor| factor.kind == kind)
}

fn profile_device_seal_metadata_label(policy: &ProfilePolicy) -> String {
    let Some(factor) = policy
        .factor_metadata
        .iter()
        .find(|factor| factor.kind == UnlockFactorKindV2::DeviceSeal)
    else {
        return "no".to_string();
    };
    factor
        .params
        .get("backend")
        .map_or_else(|| "yes".to_string(), |backend| format!("yes ({backend})"))
}

fn profile_requirement_source(
    vault: &Vault,
    policy: &ProfilePolicy,
    requirement: ProfileFactorRequirement,
) -> String {
    let kind = unlock_factor_kind_for_profile_requirement(requirement);
    if profile_has_factor_metadata(policy, kind) {
        return "profile-specific cryptographic binding".to_string();
    }
    if vault_has_factor(vault, kind) {
        return "vault-level factor binding".to_string();
    }
    "missing".to_string()
}

fn profile_repair_hint(
    vault: &Vault,
    profile: &str,
    policy: &ProfilePolicy,
    findings: &[ProfilePolicyFinding],
) -> Option<String> {
    let has_warning = findings.iter().any(|finding| {
        matches!(
            finding.code,
            ProfilePolicyFindingCode::PolicyForMissingProfile
                | ProfilePolicyFindingCode::ProfileFactorsWithoutProfileKeyMode
                | ProfilePolicyFindingCode::MissingProfileEntry
                | ProfilePolicyFindingCode::UnsatisfiedRequirement
                | ProfilePolicyFindingCode::MissingPresetBinding
        )
    });
    let has_error = findings
        .iter()
        .any(|finding| finding.code == ProfilePolicyFindingCode::UnsupportedFactorMetadata);
    if !has_warning || has_error {
        return None;
    }
    let mut hint = format!("sshenv security profile-policy repair {profile}");
    if vault.header.version != VERSION_V2 {
        hint.push_str(" --recipient-key <path-or-public-key-line>");
    }
    if profile_repair_needs_passphrase(policy) {
        hint.push_str(" --passphrase <value>");
    }
    Some(hint)
}

fn save_profile_policy_vault(
    ctx: &CmdContext,
    vault: &mut Vault,
    data_key: &DataKey,
    profile: &str,
) -> Result<()> {
    validate_profile_policy_for_save(vault, profile)?;
    save_vault(ctx, vault, data_key)
}

fn save_all_profile_policy_vaults(
    ctx: &CmdContext,
    vault: &mut Vault,
    data_key: &DataKey,
) -> Result<()> {
    for profile in vault.validate_profile_policies().profiles.keys() {
        validate_profile_policy_for_save(vault, profile)?;
    }
    save_vault(ctx, vault, data_key)
}

fn validate_profile_policy_for_save(vault: &Vault, profile: &str) -> Result<()> {
    let mut validation = vault.validate_profile_policy(profile);
    if vault.profiles.profiles.contains_key(profile) {
        validation
            .findings
            .retain(|finding| finding.code != ProfilePolicyFindingCode::MissingProfileEntry);
    }
    let errors = validation.error_messages();
    if !errors.is_empty() {
        anyhow::bail!(
            "profile policy has unrecoverable validation error(s): {}",
            errors.join(", ")
        );
    }
    let warnings = validation.warning_messages();
    if warnings.is_empty() {
        return Ok(());
    }

    eprintln!("warning: profile policy for {profile} is not fully consistent:");
    for warning in &warnings {
        eprintln!("- {warning}");
    }
    if let Some(policy) = vault.profiles.profile_policy(profile)
        && let Some(hint) = profile_repair_hint(vault, profile, policy, &validation.findings)
    {
        eprintln!("repair: {hint}");
    }
    Ok(())
}

fn print_profile_policy_apply_all_plan(output: &ProfilePolicyApplyAllPlanOutput) {
    println!("profile policy apply-all plan");
    println!("=============================");
    println!("target preset: {}", output.target_preset);
    println!("profiles total: {}", output.profiles_total);
    println!("repairable: {}", output.repairable_count);
    println!("unrepairable: {}", output.unrepairable_count);
    println!("requires passphrase: {}", output.requires_passphrase_count);
    println!(
        "requires device seal: {}",
        output.requires_device_seal_count
    );
    println!(
        "requires recipient key: {}",
        output.requires_recipient_key_count
    );
    for profile in &output.profiles {
        println!();
        println!("profile: {}", profile.profile);
        print_profile_policy_plan_details(&profile.plan);
    }
}

fn print_profile_policy_repair_all_plan(output: &ProfilePolicyRepairAllPlanOutput) {
    println!("profile policy repair-all plan");
    println!("==============================");
    println!("profiles total: {}", output.profiles_total);
    println!("repairable: {}", output.repairable_count);
    println!("unrepairable: {}", output.unrepairable_count);
    println!("requires passphrase: {}", output.requires_passphrase_count);
    println!(
        "requires device seal: {}",
        output.requires_device_seal_count
    );
    println!(
        "requires recipient key: {}",
        output.requires_recipient_key_count
    );
    for profile in &output.profiles {
        println!();
        println!("profile: {}", profile.profile);
        print_profile_policy_plan_details(profile);
    }
}

fn print_profile_policy_apply_plan(output: &ProfilePolicyApplyPlanOutput) {
    println!("profile policy apply plan");
    println!("=========================");
    println!("profile: {}", output.profile);
    println!("target preset: {}", output.target_preset);
    print_profile_policy_plan_details(&output.plan);
}

fn print_profile_policy_repair_plan(output: &ProfilePolicyRepairPlan) {
    println!("profile policy repair plan");
    println!("==========================");
    println!("profile: {}", output.profile);
    print_profile_policy_plan_details(output);
}

fn print_profile_policy_plan_details(output: &ProfilePolicyRepairPlan) {
    println!("repairable: {}", yes_no(output.repairable));
    println!("already consistent: {}", yes_no(output.already_consistent));
    println!(
        "requires passphrase: {}",
        yes_no(output.requires_passphrase)
    );
    println!(
        "requires device seal: {}",
        yes_no(output.requires_device_seal)
    );
    println!(
        "requires recipient key: {}",
        yes_no(output.requires_recipient_key)
    );
    if output.actions.is_empty() {
        println!("actions: none");
    } else {
        println!("actions:");
        for action in &output.action_labels {
            println!("- {action}");
        }
    }
    if output.unrepairable.is_empty() {
        println!("unrepairable: none");
    } else {
        println!("unrepairable:");
        for item in &output.unrepairable {
            println!("- {item}");
        }
    }
}

fn build_profile_policy_apply_all_plan(
    vault: &Vault,
    preset: ProfilePolicyPreset,
) -> Result<ProfilePolicyApplyAllPlanOutput> {
    let mut profiles = profile_policy_names(vault)
        .into_iter()
        .map(|profile| {
            let plan = build_profile_policy_apply_plan(vault, &profile, preset)?;
            Ok(ProfilePolicyApplyPlanOutput {
                profile,
                target_preset: format!("{preset:?}"),
                plan,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    profiles.sort_by(|left, right| left.profile.cmp(&right.profile));

    let repairable_count = profiles
        .iter()
        .filter(|profile| profile.plan.repairable)
        .count();
    let unrepairable_count = profiles
        .iter()
        .filter(|profile| !profile.plan.unrepairable.is_empty())
        .count();
    let requires_passphrase_count = profiles
        .iter()
        .filter(|profile| profile.plan.requires_passphrase)
        .count();
    let requires_device_seal_count = profiles
        .iter()
        .filter(|profile| profile.plan.requires_device_seal)
        .count();
    let requires_recipient_key_count = profiles
        .iter()
        .filter(|profile| profile.plan.requires_recipient_key)
        .count();

    Ok(ProfilePolicyApplyAllPlanOutput {
        target_preset: format!("{preset:?}"),
        profiles_total: profiles.len(),
        repairable_count,
        unrepairable_count,
        requires_passphrase_count,
        requires_device_seal_count,
        requires_recipient_key_count,
        profiles,
    })
}

fn build_profile_policy_repair_all_plan(vault: &Vault) -> ProfilePolicyRepairAllPlanOutput {
    let profiles = profile_policy_metadata_names(vault)
        .into_iter()
        .map(|profile| vault.plan_profile_policy_repair(&profile, None))
        .collect::<Vec<_>>();

    let repairable_count = profiles.iter().filter(|profile| profile.repairable).count();
    let unrepairable_count = profiles
        .iter()
        .filter(|profile| !profile.unrepairable.is_empty())
        .count();
    let requires_passphrase_count = profiles
        .iter()
        .filter(|profile| profile.requires_passphrase)
        .count();
    let requires_device_seal_count = profiles
        .iter()
        .filter(|profile| profile.requires_device_seal)
        .count();
    let requires_recipient_key_count = profiles
        .iter()
        .filter(|profile| profile.requires_recipient_key)
        .count();

    ProfilePolicyRepairAllPlanOutput {
        profiles_total: profiles.len(),
        repairable_count,
        unrepairable_count,
        requires_passphrase_count,
        requires_device_seal_count,
        requires_recipient_key_count,
        profiles,
    }
}

fn profile_policy_metadata_names(vault: &Vault) -> Vec<String> {
    let mut profiles = vault
        .profiles
        .profile_policies
        .keys()
        .cloned()
        .collect::<Vec<_>>();
    profiles.sort();
    profiles
}

fn profile_policy_names(vault: &Vault) -> Vec<String> {
    let mut profiles: Vec<_> = vault
        .profiles
        .profiles
        .keys()
        .chain(vault.profiles.profile_entries.keys())
        .chain(vault.profiles.profile_policies.keys())
        .cloned()
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();
    profiles.sort();
    profiles
}

fn build_profile_policy_apply_plan(
    vault: &Vault,
    profile: &str,
    preset: ProfilePolicyPreset,
) -> Result<ProfilePolicyRepairPlan> {
    let mut planned_vault = vault.clone();
    apply_profile_policy_preset_metadata(&mut planned_vault, profile, preset)?;
    let validation = planned_vault.validate_profile_policy(profile);
    if validation.profile_policy_missing() {
        anyhow::bail!("no such profile: {profile}");
    }
    let mut plan = planned_vault.plan_profile_policy_repair(profile, Some(&validation));
    if matches!(
        preset,
        ProfilePolicyPreset::Standard | ProfilePolicyPreset::Paranoid
    ) && !plan
        .actions
        .contains(&ProfilePolicyRepairAction::RotateProfileKey)
    {
        plan.actions
            .push(ProfilePolicyRepairAction::RotateProfileKey);
        plan.action_labels.push(
            ProfilePolicyRepairAction::RotateProfileKey
                .label()
                .to_string(),
        );
    }
    Ok(plan)
}

fn add_profile_policy_plan_action(
    plan: &mut ProfilePolicyRepairPlan,
    action: ProfilePolicyRepairAction,
) {
    if !plan.actions.contains(&action) {
        plan.actions.push(action);
        plan.action_labels.push(action.label().to_string());
    }
}

fn apply_profile_policy_preset_metadata(
    vault: &mut Vault,
    profile: &str,
    preset: ProfilePolicyPreset,
) -> Result<()> {
    let mut policy = existing_or_default_profile_policy(vault, profile);
    policy.preset = preset;
    if preset == ProfilePolicyPreset::Standard {
        policy.required_factors.clear();
        policy.factor_metadata.clear();
    }
    vault.profiles.set_profile_policy(profile, policy)?;
    Ok(())
}

fn profile_repair_needs_passphrase(policy: &ProfilePolicy) -> bool {
    let preset_needs_passphrase = profile_preset_expected_requirements(policy.preset)
        .contains(&ProfileFactorRequirement::Passphrase);
    let requirement_needs_passphrase = policy
        .required_factors
        .contains(&ProfileFactorRequirement::Passphrase);
    (preset_needs_passphrase || requirement_needs_passphrase)
        && !profile_has_factor_metadata(policy, UnlockFactorKindV2::Passphrase)
}

const fn profile_policy_preset_rank(preset: ProfilePolicyPreset) -> u8 {
    match preset {
        ProfilePolicyPreset::Standard => 0,
        ProfilePolicyPreset::Recommended => 1,
        ProfilePolicyPreset::Portable => 2,
        ProfilePolicyPreset::Team => 3,
        ProfilePolicyPreset::Paranoid => 4,
    }
}

fn profile_policy_downgrade_notice(
    vault: &Vault,
    profile: &str,
    target: ProfilePolicyPreset,
) -> Option<String> {
    let current = vault.profiles.profile_policy(profile)?;
    let lowers_preset =
        profile_policy_preset_rank(current.preset) > profile_policy_preset_rank(target);
    let clears_factors = target == ProfilePolicyPreset::Standard
        && (!current.required_factors.is_empty() || !current.factor_metadata.is_empty());
    if !(lowers_preset || clears_factors) {
        return None;
    }

    Some(format!(
        "profile '{profile}' is moving from {:?} to {:?}; this may remove profile-specific factor requirements and rotate/regenerate profile key material",
        current.preset, target
    ))
}

fn print_profile_policy_downgrade_walkthrough(notice: &str) {
    eprintln!("warning: {notice}");
    eprintln!("downgrade/opt-out walkthrough:");
    eprintln!("1. Preview first with `--dry-run` and inspect `profile-policy status`.");
    eprintln!("2. Keep the automatic backup, or create one manually before using `--no-backup`.");
    eprintln!("3. Apply the weaker preset intentionally, then run `profile-policy check`.");
}

fn print_bulk_profile_policy_downgrade_walkthrough(vault: &Vault, target: ProfilePolicyPreset) {
    let downgraded = profile_policy_names(vault)
        .into_iter()
        .filter_map(|profile| profile_policy_downgrade_notice(vault, &profile, target))
        .collect::<Vec<_>>();
    if downgraded.is_empty() {
        return;
    }

    eprintln!(
        "warning: {} profile(s) will use a weaker/opt-out policy:",
        downgraded.len()
    );
    for notice in &downgraded {
        eprintln!("- {notice}");
    }
    eprintln!("downgrade/opt-out walkthrough:");
    eprintln!("1. Preview first with `--dry-run` and inspect `profile-policy check`.");
    eprintln!("2. Keep the automatic backup, or create one manually before using `--no-backup`.");
    eprintln!("3. Apply the weaker preset intentionally, then run `profile-policy check`.");
}

fn profile_preset_expected_requirements(
    preset: ProfilePolicyPreset,
) -> Vec<ProfileFactorRequirement> {
    match preset {
        ProfilePolicyPreset::Standard | ProfilePolicyPreset::Team => Vec::new(),
        ProfilePolicyPreset::Portable => vec![ProfileFactorRequirement::Passphrase],
        ProfilePolicyPreset::Recommended => {
            if device_seal_backend_status() == "none" {
                Vec::new()
            } else {
                vec![ProfileFactorRequirement::DeviceSeal]
            }
        }
        ProfilePolicyPreset::Paranoid => {
            let mut requirements = vec![ProfileFactorRequirement::Passphrase];
            if device_seal_backend_status() != "none" {
                requirements.push(ProfileFactorRequirement::DeviceSeal);
            }
            requirements
        }
    }
}

const fn unlock_factor_kind_for_profile_requirement(
    requirement: ProfileFactorRequirement,
) -> UnlockFactorKindV2 {
    match requirement {
        ProfileFactorRequirement::Passphrase => UnlockFactorKindV2::Passphrase,
        ProfileFactorRequirement::DeviceSeal => UnlockFactorKindV2::DeviceSeal,
    }
}

fn profile_requirement_satisfied(
    vault: &Vault,
    policy: &ProfilePolicy,
    requirement: ProfileFactorRequirement,
) -> bool {
    let kind = unlock_factor_kind_for_profile_requirement(requirement);
    vault_has_factor(vault, kind)
        || policy
            .factor_metadata
            .iter()
            .any(|factor| factor.kind == kind)
}

const fn profile_requirement_label(requirement: ProfileFactorRequirement) -> &'static str {
    match requirement {
        ProfileFactorRequirement::Passphrase => "passphrase",
        ProfileFactorRequirement::DeviceSeal => "device-seal",
    }
}

fn profile_policy_findings(vault: &Vault, preset: ProfilePolicyPreset) -> Vec<String> {
    let mut findings = Vec::new();
    let has_v2 = vault.header.version == VERSION_V2;
    let has_passphrase = vault_has_factor(vault, UnlockFactorKindV2::Passphrase);
    let has_device_seal = vault_has_factor(vault, UnlockFactorKindV2::DeviceSeal);

    match preset {
        ProfilePolicyPreset::Standard => {}
        ProfilePolicyPreset::Team => {
            if !has_v2 {
                findings.push("vault is not v2".to_string());
            }
            if vault
                .policy_metadata
                .as_ref()
                .is_none_or(|metadata| metadata.recovery_share_sets.is_empty())
            {
                findings.push("no recovery-share metadata configured".to_string());
            }
        }
        ProfilePolicyPreset::Recommended => {
            if !has_v2 {
                findings.push("vault is not v2".to_string());
            }
            if device_seal_backend_status() != "none" && !has_device_seal {
                findings.push("device-seal factor disabled".to_string());
            }
        }
        ProfilePolicyPreset::Portable => {
            if !has_v2 {
                findings.push("vault is not v2".to_string());
            }
            if !has_passphrase {
                findings.push("passphrase factor disabled".to_string());
            }
        }
        ProfilePolicyPreset::Paranoid => {
            if !has_v2 {
                findings.push("vault is not v2".to_string());
            }
            if !has_passphrase {
                findings.push("passphrase factor disabled".to_string());
            }
            if !has_device_seal {
                findings.push("device-seal factor disabled".to_string());
            }
            if !cfg!(feature = "rollback-protection") {
                findings.push("rollback protection not compiled in".to_string());
            }
            if !cfg!(feature = "runtime-hardening") {
                findings.push("runtime hardening not compiled in".to_string());
            }
        }
    }
    findings
}

fn vault_has_factor(vault: &Vault, kind: UnlockFactorKindV2) -> bool {
    vault
        .policy_metadata
        .as_ref()
        .into_iter()
        .flat_map(|metadata| &metadata.policies)
        .flat_map(|policy| &policy.factors)
        .any(|factor| factor.kind == kind)
}

pub fn profile_policy_migrate(ctx: &CmdContext) -> Result<()> {
    let (mut vault, data_key) = crate::commands::load_and_unlock(&ctx.vault_path)?;
    let changed = vault.enable_profile_keys()?;
    if changed {
        save_all_profile_policy_vaults(ctx, &mut vault, &data_key)?;
        eprintln!("Migrated profiles to independently encrypted v2 profile entries.");
    } else {
        eprintln!("Profiles are already stored as independently encrypted v2 entries.");
    }
    Ok(())
}

pub fn profile_policy_rotate_key(ctx: &CmdContext, args: ProfilePolicyRotateKeyArgs) -> Result<()> {
    let (mut vault, data_key) = load_and_unlock_profile(&ctx.vault_path, &args.profile)?;
    vault.rotate_profile_key(&args.profile)?;
    save_profile_policy_vault(ctx, &mut vault, &data_key, &args.profile)?;
    eprintln!("Rotated profile data key for {}.", args.profile);
    Ok(())
}

#[cfg(feature = "passphrase-factor")]
pub fn profile_policy_require_passphrase(
    ctx: &CmdContext,
    args: ProfilePolicyRequirePassphraseArgs,
) -> Result<()> {
    let passphrase =
        passphrase_arg_or_prompt(args.passphrase, "Enter new sshenv profile passphrase: ")?;
    let (mut vault, data_key) = load_and_unlock_profile(&ctx.vault_path, &args.profile)?;
    vault.require_profile_passphrase(&args.profile, passphrase.as_str())?;
    save_profile_policy_vault(ctx, &mut vault, &data_key, &args.profile)?;
    eprintln!(
        "Required passphrase factor for profile {}. The profile payload is now bound to this passphrase.",
        args.profile
    );
    Ok(())
}

#[cfg(not(feature = "passphrase-factor"))]
pub fn profile_policy_require_passphrase(
    _ctx: &CmdContext,
    _args: ProfilePolicyRequirePassphraseArgs,
) -> Result<()> {
    anyhow::bail!("this sshenv build was compiled without passphrase-factor support")
}

#[cfg(feature = "passphrase-factor")]
pub fn profile_policy_change_passphrase(
    ctx: &CmdContext,
    args: ProfilePolicyChangePassphraseArgs,
) -> Result<()> {
    let new_passphrase =
        passphrase_arg_or_prompt(args.new_passphrase, "Enter new sshenv profile passphrase: ")?;
    let (mut vault, data_key) = crate::commands::load_and_unlock_profile_with_passphrase(
        &ctx.vault_path,
        &args.profile,
        args.old_passphrase.as_deref(),
    )?;
    ensure_profile_policy_editable(&vault, &args.profile)?;
    let Some(policy) = vault.profiles.profile_policy(&args.profile) else {
        anyhow::bail!("profile {} does not require a passphrase", args.profile);
    };
    if !policy
        .factor_metadata
        .iter()
        .any(|factor| factor.kind == UnlockFactorKindV2::Passphrase)
    {
        anyhow::bail!("profile {} does not require a passphrase", args.profile);
    }
    vault.require_profile_passphrase(&args.profile, new_passphrase.as_str())?;
    save_profile_policy_vault(ctx, &mut vault, &data_key, &args.profile)?;
    eprintln!("Changed passphrase factor for profile {}.", args.profile);
    Ok(())
}

#[cfg(not(feature = "passphrase-factor"))]
pub fn profile_policy_change_passphrase(
    _ctx: &CmdContext,
    _args: ProfilePolicyChangePassphraseArgs,
) -> Result<()> {
    anyhow::bail!("this sshenv build was compiled without passphrase-factor support")
}

#[cfg(feature = "passphrase-factor")]
pub fn profile_policy_disable_passphrase(
    ctx: &CmdContext,
    args: ProfilePolicyDisablePassphraseArgs,
) -> Result<()> {
    let (mut vault, data_key) = crate::commands::load_and_unlock_profile_with_passphrase(
        &ctx.vault_path,
        &args.profile,
        args.passphrase.as_deref(),
    )?;
    ensure_profile_policy_editable(&vault, &args.profile)?;
    let mut policy = existing_or_default_profile_policy(&vault, &args.profile);
    let had_passphrase = policy
        .factor_metadata
        .iter()
        .any(|factor| factor.kind == UnlockFactorKindV2::Passphrase)
        || policy
            .required_factors
            .contains(&ProfileFactorRequirement::Passphrase);
    if !had_passphrase {
        anyhow::bail!("profile {} does not require a passphrase", args.profile);
    }
    policy
        .factor_metadata
        .retain(|factor| factor.kind != UnlockFactorKindV2::Passphrase);
    policy
        .required_factors
        .retain(|factor| *factor != ProfileFactorRequirement::Passphrase);
    vault.profiles.set_profile_policy(&args.profile, policy)?;
    save_profile_policy_vault(ctx, &mut vault, &data_key, &args.profile)?;
    eprintln!("Disabled passphrase factor for profile {}.", args.profile);
    Ok(())
}

#[cfg(not(feature = "passphrase-factor"))]
pub fn profile_policy_disable_passphrase(
    _ctx: &CmdContext,
    _args: ProfilePolicyDisablePassphraseArgs,
) -> Result<()> {
    anyhow::bail!("this sshenv build was compiled without passphrase-factor support")
}

#[cfg(feature = "device-seal")]
pub fn profile_policy_require_device_seal(
    ctx: &CmdContext,
    args: ProfilePolicyRequirementArgs,
) -> Result<()> {
    let (mut vault, data_key) = load_and_unlock_profile(&ctx.vault_path, &args.profile)?;
    vault.require_profile_device_seal(&args.profile)?;
    save_profile_policy_vault(ctx, &mut vault, &data_key, &args.profile)?;
    eprintln!(
        "Required device-seal factor for profile {}. The profile payload is now bound to this device.",
        args.profile
    );
    Ok(())
}

#[cfg(not(feature = "device-seal"))]
pub fn profile_policy_require_device_seal(
    _ctx: &CmdContext,
    _args: ProfilePolicyRequirementArgs,
) -> Result<()> {
    anyhow::bail!("this sshenv build was compiled without device-seal support")
}

#[cfg(feature = "device-seal")]
pub fn profile_policy_disable_device_seal(
    ctx: &CmdContext,
    args: ProfilePolicyRequirementArgs,
) -> Result<()> {
    let (mut vault, data_key) = load_and_unlock_profile(&ctx.vault_path, &args.profile)?;
    ensure_profile_policy_editable(&vault, &args.profile)?;
    let mut policy = existing_or_default_profile_policy(&vault, &args.profile);
    let had_device_seal = policy
        .factor_metadata
        .iter()
        .any(|factor| factor.kind == UnlockFactorKindV2::DeviceSeal)
        || policy
            .required_factors
            .contains(&ProfileFactorRequirement::DeviceSeal);
    if !had_device_seal {
        anyhow::bail!("profile {} does not require a device seal", args.profile);
    }
    policy
        .factor_metadata
        .retain(|factor| factor.kind != UnlockFactorKindV2::DeviceSeal);
    policy
        .required_factors
        .retain(|factor| *factor != ProfileFactorRequirement::DeviceSeal);
    vault.profiles.set_profile_policy(&args.profile, policy)?;
    save_profile_policy_vault(ctx, &mut vault, &data_key, &args.profile)?;
    eprintln!("Disabled device-seal factor for profile {}.", args.profile);
    Ok(())
}

#[cfg(not(feature = "device-seal"))]
pub fn profile_policy_disable_device_seal(
    _ctx: &CmdContext,
    _args: ProfilePolicyRequirementArgs,
) -> Result<()> {
    anyhow::bail!("this sshenv build was compiled without device-seal support")
}

pub fn profile_policy_clear_requirements(
    ctx: &CmdContext,
    args: ProfilePolicyRequirementArgs,
) -> Result<()> {
    let (mut vault, data_key) = load_and_unlock_profile(&ctx.vault_path, &args.profile)?;
    ensure_profile_policy_editable(&vault, &args.profile)?;
    let mut policy = existing_or_default_profile_policy(&vault, &args.profile);
    if !policy.required_factors.is_empty() || !policy.factor_metadata.is_empty() {
        print_profile_policy_downgrade_walkthrough(&format!(
            "profile '{}' is clearing all explicit factor requirements",
            args.profile
        ));
    }
    policy.required_factors.clear();
    policy.factor_metadata.clear();
    vault.profiles.set_profile_policy(&args.profile, policy)?;
    save_profile_policy_vault(ctx, &mut vault, &data_key, &args.profile)?;
    eprintln!("Cleared profile factor requirements for {}.", args.profile);
    Ok(())
}

fn ensure_profile_policy_editable(vault: &Vault, profile: &str) -> Result<()> {
    if vault.header.version != VERSION_V2 {
        anyhow::bail!(
            "profile policy metadata requires v2; run `sshenv migrate-vault --to v2` first"
        );
    }
    if !vault.profile_keys_enabled() {
        anyhow::bail!(
            "profile factor requirements require profile-key mode; run `sshenv security profile-policy migrate` first"
        );
    }
    if !vault.profiles.profiles.contains_key(profile) {
        anyhow::bail!("no such profile: {profile}");
    }
    Ok(())
}

fn existing_or_default_profile_policy(vault: &Vault, profile: &str) -> ProfilePolicy {
    vault
        .profiles
        .profile_policy(profile)
        .cloned()
        .unwrap_or(ProfilePolicy {
            preset: ProfilePolicyPreset::Standard,
            required_factors: Vec::new(),
            factor_metadata: Vec::new(),
        })
}

pub fn profile_policy_apply(ctx: &CmdContext, args: ProfilePolicyApplyArgs) -> Result<()> {
    let (mut vault, data_key) = load_and_unlock_profile(&ctx.vault_path, &args.profile)?;
    let preset = profile_policy_preset(args.preset);
    let mut plan = build_profile_policy_apply_plan(&vault, &args.profile, preset)?;
    if args.passphrase.is_some()
        && profile_preset_expected_requirements(preset)
            .contains(&ProfileFactorRequirement::Passphrase)
    {
        add_profile_policy_plan_action(&mut plan, ProfilePolicyRepairAction::BindPassphrase);
        add_profile_policy_plan_action(&mut plan, ProfilePolicyRepairAction::RotateProfileKey);
    }

    let downgrade_notice = profile_policy_downgrade_notice(&vault, &args.profile, preset);
    if args.dry_run || args.json {
        if !args.json
            && let Some(notice) = &downgrade_notice
        {
            print_profile_policy_downgrade_walkthrough(notice);
        }
        let output = ProfilePolicyApplyPlanOutput {
            profile: args.profile,
            target_preset: format!("{preset:?}"),
            plan,
        };
        if args.json {
            println!("{}", serde_json::to_string_pretty(&output)?);
        } else {
            print_profile_policy_apply_plan(&output);
        }
        if !output.plan.unrepairable.is_empty() {
            anyhow::bail!(
                "profile policy apply has unrecoverable validation issue(s): {}",
                output.plan.unrepairable.join(", ")
            );
        }
        return Ok(());
    }

    ensure_profile_policy_plan_inputs_available(
        &plan,
        args.passphrase.as_ref(),
        &args.recipient_keys,
        "profile policy apply",
        args.strict_inputs,
    )?;
    if let Some(notice) = &downgrade_notice {
        print_profile_policy_downgrade_walkthrough(notice);
    }
    apply_profile_policy_preset_metadata(&mut vault, &args.profile, preset)?;
    let (plan_changed, applied_actions) = apply_profile_policy_plan_actions(
        &mut vault,
        &args.profile,
        &args.recipient_keys,
        args.passphrase,
        &plan,
    )?;

    if plan_changed || !plan.already_consistent {
        save_profile_policy_vault(ctx, &mut vault, &data_key, &args.profile)?;
    }
    eprintln!(
        "Applied {:?} profile policy enforcement to {}.",
        preset, args.profile
    );
    for action in applied_actions {
        eprintln!("- {action}");
    }
    Ok(())
}

pub fn profile_policy_apply_all(ctx: &CmdContext, args: ProfilePolicyApplyAllArgs) -> Result<()> {
    let preset = profile_policy_preset(args.preset);
    if args.dry_run {
        let (vault, _key) = load_and_unlock_metadata(&ctx.vault_path)?;
        let output = build_profile_policy_apply_all_plan(&vault, preset)?;

        if !args.json {
            print_bulk_profile_policy_downgrade_walkthrough(&vault, preset);
        }
        if args.json {
            println!("{}", serde_json::to_string_pretty(&output)?);
        } else {
            print_profile_policy_apply_all_plan(&output);
        }
        if output.unrepairable_count > 0 {
            anyhow::bail!(
                "profile policy apply-all plan has {} unrepairable profile(s)",
                output.unrepairable_count
            );
        }
        return Ok(());
    }

    if !matches!(
        preset,
        ProfilePolicyPreset::Standard
            | ProfilePolicyPreset::Portable
            | ProfilePolicyPreset::Recommended
            | ProfilePolicyPreset::Team
            | ProfilePolicyPreset::Paranoid
    ) {
        anyhow::bail!(
            "profile-policy apply-all without --dry-run currently supports --preset standard, portable, recommended, team, or paranoid only"
        );
    }
    ensure_profile_policy_apply_all_preset_supported(preset)?;
    let (mut vault, data_key) = crate::commands::load_and_unlock(&ctx.vault_path)?;
    print_bulk_profile_policy_downgrade_walkthrough(&vault, preset);
    let output = build_profile_policy_apply_all_plan(&vault, preset)?;
    if output.unrepairable_count > 0 {
        anyhow::bail!(
            "profile policy apply-all plan has {} unrepairable profile(s)",
            output.unrepairable_count
        );
    }
    ensure_profile_policy_apply_all_inputs_available(&output, &args)?;
    let bulk_passphrase = bulk_apply_all_passphrase(&output, args.passphrase)?;
    create_bulk_profile_policy_backup_if_requested(
        ctx,
        bulk_backup_enabled(args.backup, args.no_backup),
    )?;
    let mut changed = false;
    let mut applied = Vec::new();

    for profile_output in output.profiles {
        apply_profile_policy_preset_metadata(&mut vault, &profile_output.profile, preset)?;
        let mut plan = profile_output.plan;
        if matches!(
            preset,
            ProfilePolicyPreset::Portable | ProfilePolicyPreset::Paranoid
        ) && bulk_passphrase.is_some()
        {
            add_profile_policy_plan_action(&mut plan, ProfilePolicyRepairAction::BindPassphrase);
            add_profile_policy_plan_action(&mut plan, ProfilePolicyRepairAction::RotateProfileKey);
        }
        if preset == ProfilePolicyPreset::Standard
            && !plan
                .actions
                .contains(&ProfilePolicyRepairAction::RotateProfileKey)
        {
            add_profile_policy_plan_action(&mut plan, ProfilePolicyRepairAction::RotateProfileKey);
        }
        let (_profile_changed, actions) = apply_profile_policy_plan_actions(
            &mut vault,
            &profile_output.profile,
            &args.recipient_keys,
            bulk_passphrase.clone(),
            &plan,
        )?;
        changed = true;
        applied.push((profile_output.profile, actions));
    }

    if changed {
        save_all_profile_policy_vaults(ctx, &mut vault, &data_key)?;
    }
    eprintln!("Applied {preset:?} profile policy enforcement to all profiles.");
    for (profile, actions) in applied {
        eprintln!("{profile}:");
        if actions.is_empty() {
            eprintln!("- set preset metadata to {preset:?}");
        } else {
            for action in actions {
                eprintln!("- {action}");
            }
        }
    }
    Ok(())
}

pub fn profile_policy_repair_all(ctx: &CmdContext, args: ProfilePolicyRepairAllArgs) -> Result<()> {
    if args.dry_run || args.json {
        let (vault, _key) = load_and_unlock_metadata(&ctx.vault_path)?;
        let output = build_profile_policy_repair_all_plan(&vault);
        if args.json {
            println!("{}", serde_json::to_string_pretty(&output)?);
        } else {
            print_profile_policy_repair_all_plan(&output);
        }
        if output.unrepairable_count > 0 {
            anyhow::bail!(
                "profile policy repair-all plan has {} unrepairable profile(s)",
                output.unrepairable_count
            );
        }
        return Ok(());
    }

    let (mut vault, data_key) = crate::commands::load_and_unlock(&ctx.vault_path)?;
    let output = build_profile_policy_repair_all_plan(&vault);
    if output.unrepairable_count > 0 {
        anyhow::bail!(
            "profile policy repair-all plan has {} unrepairable profile(s)",
            output.unrepairable_count
        );
    }
    ensure_profile_policy_repair_all_inputs_available(&output, &args)?;
    let bulk_passphrase = bulk_repair_all_passphrase(&output, args.passphrase)?;
    create_bulk_profile_policy_backup_if_requested(
        ctx,
        bulk_backup_enabled(args.backup, args.no_backup),
    )?;
    let mut changed = false;
    let mut applied = Vec::new();

    for plan in output.profiles {
        let profile = plan.profile.clone();
        let (profile_changed, actions) = apply_profile_policy_plan_actions(
            &mut vault,
            &profile,
            &args.recipient_keys,
            bulk_passphrase.clone(),
            &plan,
        )?;
        changed |= profile_changed;
        applied.push((profile, actions));
    }

    if changed {
        save_all_profile_policy_vaults(ctx, &mut vault, &data_key)?;
    }
    eprintln!("Repaired profile policies for all profiles.");
    for (profile, actions) in applied {
        eprintln!("{profile}:");
        if actions.is_empty() {
            eprintln!("- already consistent");
        } else {
            for action in actions {
                eprintln!("- {action}");
            }
        }
    }
    Ok(())
}

pub fn profile_policy_restore_backup(
    ctx: &CmdContext,
    args: ProfilePolicyRestoreBackupArgs,
) -> Result<()> {
    let current = fs::canonicalize(&ctx.vault_path)?;
    let backup = fs::canonicalize(&args.backup_path)?;
    if current == backup {
        anyhow::bail!("backup path must be different from the current vault path");
    }

    let preview = build_profile_policy_restore_backup_preview(ctx, &backup);
    if args.dry_run || args.json {
        if args.json {
            println!("{}", serde_json::to_string_pretty(&preview)?);
        } else {
            print_profile_policy_restore_backup_preview(&preview);
        }
        if !preview.would_restore {
            anyhow::bail!(
                "profile policy backup restore preview failed for {}",
                preview.backup.path
            );
        }
        return Ok(());
    }
    if !preview.would_restore {
        anyhow::bail!(
            "profile policy backup verification failed for {}",
            preview.backup.path
        );
    }

    let backup_ciphertext = Vault::load_ciphertext(&backup)?;
    let restored_generation = backup_ciphertext.generation();

    let pre_restore_backup = timestamped_vault_backup_path(&ctx.vault_path, "pre-restore.bak")?;
    copy_vault_file(&ctx.vault_path, &pre_restore_backup)?;

    let backup_bytes = fs::read(&backup)?;
    atomic_write(&ctx.vault_path, &backup_bytes, 0o600)?;
    set_rollback(&ctx.vault_path, restored_generation)?;

    eprintln!(
        "Pre-restore backup written to {}",
        pre_restore_backup.display()
    );
    eprintln!("Restored vault from {}", backup.display());
    Ok(())
}

pub fn profile_policy_repair(ctx: &CmdContext, args: ProfilePolicyRepairArgs) -> Result<()> {
    let (mut vault, data_key) = load_and_unlock_profile(&ctx.vault_path, &args.profile)?;
    let initial_validation = vault.validate_profile_policy(&args.profile);
    let plan = vault.plan_profile_policy_repair(&args.profile, Some(&initial_validation));
    if args.dry_run || args.json {
        if args.json {
            println!("{}", serde_json::to_string_pretty(&plan)?);
        } else {
            print_profile_policy_repair_plan(&plan);
        }
        if !plan.unrepairable.is_empty() {
            anyhow::bail!(
                "profile policy has unrecoverable validation issue(s): {}",
                plan.unrepairable.join(", ")
            );
        }
        return Ok(());
    }
    if !plan.unrepairable.is_empty() {
        for item in &plan.unrepairable {
            eprintln!("cannot repair: {item}");
        }
        anyhow::bail!(
            "profile policy has unrecoverable validation issue(s): {}",
            plan.unrepairable.join(", ")
        );
    }
    ensure_repair_inputs_available(&plan, &args)?;

    let (changed, applied_actions) = apply_profile_policy_plan_actions(
        &mut vault,
        &args.profile,
        &args.recipient_keys,
        args.passphrase,
        &plan,
    )?;

    if changed {
        save_profile_policy_vault(ctx, &mut vault, &data_key, &args.profile)?;
        eprintln!("Repaired profile policy for {}.", args.profile);
        for action in applied_actions {
            eprintln!("- {action}");
        }
    } else {
        eprintln!(
            "Profile policy for {} was already consistent.",
            args.profile
        );
    }
    Ok(())
}

const fn bulk_backup_enabled(_backup: bool, no_backup: bool) -> bool {
    !no_backup
}

fn create_bulk_profile_policy_backup_if_requested(
    ctx: &CmdContext,
    enabled: bool,
) -> Result<Option<PathBuf>> {
    if !enabled {
        return Ok(None);
    }
    let backup_path = timestamped_vault_backup_path(&ctx.vault_path, "bak")?;
    copy_vault_file(&ctx.vault_path, &backup_path)?;
    eprintln!("Backup written to {}", backup_path.display());
    Ok(Some(backup_path))
}

fn copy_vault_file(from: &Path, to: &Path) -> Result<()> {
    if let Some(parent) = to.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::copy(from, to)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(to, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

fn timestamped_vault_backup_path(vault_path: &Path, label: &str) -> Result<PathBuf> {
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?;
    let file_name = vault_path
        .file_name()
        .map_or_else(|| "vault".into(), |name| name.to_string_lossy());
    Ok(vault_path.with_file_name(format!(
        "{file_name}.{label}.{}.{:09}",
        timestamp.as_secs(),
        timestamp.subsec_nanos()
    )))
}

fn ensure_profile_policy_repair_all_inputs_available(
    output: &ProfilePolicyRepairAllPlanOutput,
    args: &ProfilePolicyRepairAllArgs,
) -> Result<()> {
    if output.requires_passphrase_count > 0
        && args.passphrase.is_none()
        && !std::io::stdin().is_terminal()
    {
        anyhow::bail!(
            "profile policy repair-all requires --passphrase <value> in non-interactive mode"
        );
    }
    if output.requires_recipient_key_count > 0 && args.recipient_keys.is_empty() {
        if args.strict_inputs {
            anyhow::bail!(
                "profile policy repair-all requires --recipient-key <path-or-public-key-line> in strict-inputs mode"
            );
        }
        eprintln!(
            "note: profile policy repair-all may need --recipient-key <path-or-public-key-line> to migrate this v1 vault"
        );
    }
    Ok(())
}

fn bulk_repair_all_passphrase(
    output: &ProfilePolicyRepairAllPlanOutput,
    passphrase: Option<String>,
) -> Result<Option<String>> {
    if output.requires_passphrase_count == 0 && passphrase.is_none() {
        return Ok(None);
    }
    #[cfg(feature = "passphrase-factor")]
    {
        let passphrase =
            passphrase_arg_or_prompt(passphrase, "Enter new sshenv profile passphrase: ")?;
        Ok(Some(passphrase.to_string()))
    }
    #[cfg(not(feature = "passphrase-factor"))]
    {
        let _ = passphrase;
        anyhow::bail!("this sshenv build was compiled without passphrase-factor support")
    }
}

fn ensure_profile_policy_apply_all_preset_supported(preset: ProfilePolicyPreset) -> Result<()> {
    if matches!(
        preset,
        ProfilePolicyPreset::Recommended | ProfilePolicyPreset::Paranoid
    ) && device_seal_backend_status() == "none"
    {
        anyhow::bail!(
            "profile-policy apply-all --preset {preset:?} requires an available device-seal backend"
        );
    }
    Ok(())
}

fn ensure_profile_policy_apply_all_inputs_available(
    output: &ProfilePolicyApplyAllPlanOutput,
    args: &ProfilePolicyApplyAllArgs,
) -> Result<()> {
    if output.requires_passphrase_count > 0
        && args.passphrase.is_none()
        && !std::io::stdin().is_terminal()
    {
        anyhow::bail!(
            "profile policy apply-all requires --passphrase <value> in non-interactive mode"
        );
    }
    if output.requires_recipient_key_count > 0 && args.recipient_keys.is_empty() {
        if args.strict_inputs {
            anyhow::bail!(
                "profile policy apply-all requires --recipient-key <path-or-public-key-line> in strict-inputs mode"
            );
        }
        eprintln!(
            "note: profile policy apply-all may need --recipient-key <path-or-public-key-line> to migrate this v1 vault"
        );
    }
    Ok(())
}

fn bulk_apply_all_passphrase(
    output: &ProfilePolicyApplyAllPlanOutput,
    passphrase: Option<String>,
) -> Result<Option<String>> {
    if output.requires_passphrase_count == 0 && passphrase.is_none() {
        return Ok(None);
    }
    #[cfg(feature = "passphrase-factor")]
    {
        let passphrase =
            passphrase_arg_or_prompt(passphrase, "Enter new sshenv profile passphrase: ")?;
        Ok(Some(passphrase.to_string()))
    }
    #[cfg(not(feature = "passphrase-factor"))]
    {
        let _ = passphrase;
        anyhow::bail!("this sshenv build was compiled without passphrase-factor support")
    }
}

fn ensure_repair_inputs_available(
    plan: &ProfilePolicyRepairPlan,
    args: &ProfilePolicyRepairArgs,
) -> Result<()> {
    ensure_profile_policy_plan_inputs_available(
        plan,
        args.passphrase.as_ref(),
        &args.recipient_keys,
        "profile policy repair",
        false,
    )
}

fn ensure_profile_policy_plan_inputs_available(
    plan: &ProfilePolicyRepairPlan,
    passphrase: Option<&String>,
    recipient_keys: &[String],
    context: &str,
    strict_inputs: bool,
) -> Result<()> {
    if plan.requires_passphrase && passphrase.is_none() && !std::io::stdin().is_terminal() {
        anyhow::bail!("{context} requires --passphrase <value> in non-interactive mode");
    }
    if plan.requires_recipient_key && recipient_keys.is_empty() {
        if strict_inputs {
            anyhow::bail!(
                "{context} requires --recipient-key <path-or-public-key-line> in strict-inputs mode"
            );
        }
        eprintln!(
            "note: {context} may need --recipient-key <path-or-public-key-line> to migrate this v1 vault"
        );
    }
    Ok(())
}

fn apply_profile_policy_plan_actions(
    vault: &mut Vault,
    profile: &str,
    recipient_keys: &[String],
    passphrase: Option<String>,
    plan: &ProfilePolicyRepairPlan,
) -> Result<(bool, Vec<&'static str>)> {
    let mut changed = false;
    let mut applied_actions = Vec::new();

    if plan
        .actions
        .contains(&ProfilePolicyRepairAction::MigrateToV2)
        && migrate_to_v2_if_needed(vault, recipient_keys)?
    {
        changed = true;
        applied_actions.push(ProfilePolicyRepairAction::MigrateToV2.label());
    }

    let base_result = vault.apply_profile_policy_repair_plan_base(profile, plan)?;
    changed |= base_result.changed;
    applied_actions.extend(
        base_result
            .applied_actions
            .iter()
            .map(|action| action.label()),
    );
    ensure_profile_policy_editable(vault, profile)?;

    for action in &plan.actions {
        match action {
            ProfilePolicyRepairAction::BindPassphrase => {
                if repair_profile_passphrase_if_needed(vault, profile, passphrase.clone())? {
                    changed = true;
                    applied_actions.push(action.label());
                }
            }
            ProfilePolicyRepairAction::BindDeviceSeal => {
                #[cfg(feature = "device-seal")]
                {
                    if repair_profile_device_seal_if_available(vault, profile)? {
                        changed = true;
                        applied_actions.push(action.label());
                    }
                }
                #[cfg(not(feature = "device-seal"))]
                {
                    if repair_profile_device_seal_unavailable() {
                        changed = true;
                        applied_actions.push(action.label());
                    }
                }
            }
            ProfilePolicyRepairAction::MigrateToV2
            | ProfilePolicyRepairAction::EnableProfileKeyMode
            | ProfilePolicyRepairAction::RegenerateProfileEntry
            | ProfilePolicyRepairAction::RotateProfileKey => {}
        }
    }

    Ok((changed, applied_actions))
}

#[cfg(not(feature = "device-seal"))]
fn note_profile_device_seal_unavailable() {
    eprintln!("note: this sshenv build has no device-seal support; skipping profile device seal");
}

#[cfg(feature = "passphrase-factor")]
fn repair_profile_passphrase_if_needed(
    vault: &mut Vault,
    profile: &str,
    passphrase: Option<String>,
) -> Result<bool> {
    let policy = existing_or_default_profile_policy(vault, profile);
    if profile_has_factor_metadata(&policy, UnlockFactorKindV2::Passphrase) && passphrase.is_none()
    {
        return Ok(false);
    }
    let passphrase = passphrase_arg_or_prompt(passphrase, "Enter new sshenv profile passphrase: ")?;
    vault.require_profile_passphrase(profile, passphrase.as_str())?;
    Ok(true)
}

#[cfg(not(feature = "passphrase-factor"))]
fn repair_profile_passphrase_if_needed(
    _vault: &mut Vault,
    _profile: &str,
    _passphrase: Option<String>,
) -> Result<bool> {
    anyhow::bail!("this sshenv build was compiled without passphrase-factor support")
}

#[cfg(feature = "device-seal")]
fn repair_profile_device_seal_if_available(vault: &mut Vault, profile: &str) -> Result<bool> {
    let policy = existing_or_default_profile_policy(vault, profile);
    if profile_has_factor_metadata(&policy, UnlockFactorKindV2::DeviceSeal) {
        return Ok(false);
    }
    if device_seal_backend_status() == "none" {
        eprintln!("note: no device-seal backend is available; skipping profile device seal");
        return Ok(false);
    }
    vault.require_profile_device_seal(profile)?;
    Ok(true)
}

#[cfg(not(feature = "device-seal"))]
fn repair_profile_device_seal_unavailable() -> bool {
    note_profile_device_seal_unavailable();
    false
}

pub fn profile_policy_set(ctx: &CmdContext, args: ProfilePolicySetArgs) -> Result<()> {
    let (mut vault, data_key) = load_and_unlock_profile(&ctx.vault_path, &args.profile)?;
    if vault.header.version != VERSION_V2 {
        anyhow::bail!(
            "profile policy metadata requires v2; run `sshenv migrate-vault --to v2` first"
        );
    }
    let preset = profile_policy_preset(args.preset);
    let mut policy = existing_or_default_profile_policy(&vault, &args.profile);
    policy.preset = preset;
    vault.profiles.set_profile_policy(&args.profile, policy)?;
    save_profile_policy_vault(ctx, &mut vault, &data_key, &args.profile)?;
    eprintln!(
        "Set advisory profile policy for {} to {:?}. Per-profile cryptographic enforcement is planned but not active yet.",
        args.profile, preset
    );
    Ok(())
}

pub fn harden(ctx: &CmdContext, args: HardenArgs) -> Result<()> {
    eprintln!("Applying {:?} hardening preset.", args.preset);
    preset(
        ctx,
        SecurityPresetArgs {
            preset: args.preset,
            recipient_keys: args.recipient_keys,
            passphrase: args.passphrase,
        },
    )
}

pub fn preset(ctx: &CmdContext, args: SecurityPresetArgs) -> Result<()> {
    match args.preset {
        SecurityPresetArg::Team => apply_team_preset(ctx),
        SecurityPresetArg::Standard => {
            eprintln!(
                "Standard preset leaves the vault on SSH-recipient unlock. No changes applied."
            );
            Ok(())
        }
        SecurityPresetArg::Recommended => apply_preset(ctx, args, false, true),
        SecurityPresetArg::Portable => apply_preset(ctx, args, true, false),
        SecurityPresetArg::Paranoid => apply_preset(ctx, args, true, true),
    }
}

fn apply_team_preset(ctx: &CmdContext) -> Result<()> {
    let (mut vault, data_key) = crate::commands::load_and_unlock(&ctx.vault_path)?;
    if vault.header.version != VERSION_V2 {
        anyhow::bail!(
            "team preset requires recovery-share metadata in v2; run `sshenv migrate-vault --to v2` first"
        );
    }
    if vault
        .policy_metadata
        .as_ref()
        .is_none_or(|metadata| metadata.recovery_share_sets.is_empty())
    {
        anyhow::bail!(
            "team preset requires at least one recovery-share metadata set; use `sshenv security recovery import <metadata.json>` first"
        );
    }
    let profiles = profile_policy_names(&vault);
    if profiles.is_empty() {
        anyhow::bail!("team preset found no profiles to update");
    }
    create_bulk_profile_policy_backup_if_requested(ctx, true)?;
    for profile in &profiles {
        apply_profile_policy_preset_metadata(&mut vault, profile, ProfilePolicyPreset::Team)?;
    }
    save_all_profile_policy_vaults(ctx, &mut vault, &data_key)?;
    eprintln!(
        "Applied Team profile-policy metadata to {} profile(s). Break-glass recovery is available through `sshenv security recovery` commands.",
        profiles.len()
    );
    Ok(())
}

const fn profile_policy_preset(preset: SecurityPresetArg) -> ProfilePolicyPreset {
    match preset {
        SecurityPresetArg::Standard => ProfilePolicyPreset::Standard,
        SecurityPresetArg::Recommended => ProfilePolicyPreset::Recommended,
        SecurityPresetArg::Portable => ProfilePolicyPreset::Portable,
        SecurityPresetArg::Team => ProfilePolicyPreset::Team,
        SecurityPresetArg::Paranoid => ProfilePolicyPreset::Paranoid,
    }
}

fn apply_preset(
    ctx: &CmdContext,
    args: SecurityPresetArgs,
    wants_passphrase: bool,
    wants_device_seal: bool,
) -> Result<()> {
    let preset = args.preset;
    let (ciphertext, recipients) = load_ciphertext_and_fps(&ctx.vault_path)?;
    let (mut vault, data_key) = unlock_ciphertext(ciphertext, &recipients)?;
    let mut changed = false;

    changed |= migrate_to_v2_if_needed(&mut vault, &args.recipient_keys)?;

    if wants_passphrase {
        changed |= enable_passphrase_if_needed(&mut vault, args.passphrase)?;
    }

    if wants_device_seal {
        changed |= enable_device_seal_if_available(
            &mut vault,
            matches!(preset, SecurityPresetArg::Paranoid),
        )?;
    }

    if changed {
        save_vault(ctx, &mut vault, &data_key)?;
        eprintln!("Applied {preset:?} security preset.");
    } else {
        eprintln!("{preset:?} security preset was already satisfied.");
    }
    Ok(())
}

fn migrate_to_v2_if_needed(vault: &mut Vault, recipient_keys: &[String]) -> Result<bool> {
    if vault.header.version == VERSION_V2 {
        return Ok(false);
    }
    let public_key_lines =
        crate::commands::rekey::resolve_current_recipient_public_key_lines(vault, recipient_keys)?;
    vault.migrate_to_v2(&public_key_lines)?;
    Ok(true)
}

#[cfg(feature = "passphrase-factor")]
fn enable_passphrase_if_needed(vault: &mut Vault, passphrase: Option<String>) -> Result<bool> {
    if vault.passphrase_factor_enabled() {
        return Ok(false);
    }
    let passphrase = passphrase_arg_or_prompt(passphrase, "Enter new sshenv vault passphrase: ")?;
    vault.enable_passphrase_factor(passphrase.as_str())?;
    Ok(true)
}

#[cfg(not(feature = "passphrase-factor"))]
fn enable_passphrase_if_needed(_vault: &mut Vault, _passphrase: Option<String>) -> Result<bool> {
    anyhow::bail!("this sshenv build was compiled without passphrase-factor support")
}

#[cfg(feature = "device-seal")]
fn enable_device_seal_if_available(vault: &mut Vault, required: bool) -> Result<bool> {
    if vault.device_seal_factor_enabled() {
        return Ok(false);
    }
    if device_seal_backend_status() == "none" {
        if required {
            anyhow::bail!("no device-seal backend is available in this build")
        }
        eprintln!("note: no device-seal backend is available; skipping device seal");
        return Ok(false);
    }
    vault.enable_device_seal_factor()?;
    Ok(true)
}

#[cfg(not(feature = "device-seal"))]
fn enable_device_seal_if_available(_vault: &mut Vault, required: bool) -> Result<bool> {
    if required {
        anyhow::bail!("this sshenv build was compiled without device-seal support")
    }
    eprintln!("note: this sshenv build has no device-seal support; skipping device seal");
    Ok(false)
}

pub fn status(ctx: &CmdContext) -> Result<()> {
    println!("sshenv security status");
    println!("======================");
    println!();

    let vault_recipients = print_vault_status(ctx)?;

    println!();
    print_feature_status();

    println!();
    print_key_status(vault_recipients.as_ref());

    println!();
    print_recommendations(vault_recipients.as_ref());

    Ok(())
}

fn print_vault_status(ctx: &CmdContext) -> Result<Option<HashSet<String>>> {
    println!("Vault");
    println!("-----");
    println!("path: {}", ctx.vault_path.display());

    if !ctx.vault_path.exists() {
        println!("status: missing; run `sshenv init` first");
        return Ok(None);
    }

    let ciphertext = Vault::load_ciphertext(&ctx.vault_path)?;
    let version_label = if ciphertext.header.version == VERSION {
        "v1 current stable format"
    } else if ciphertext.header.version == VERSION_V2 {
        "v2 policy format"
    } else {
        "unknown format"
    };
    println!("format: {version_label}");
    println!(
        "profile keys: {}",
        if ciphertext
            .policy_metadata
            .as_ref()
            .is_some_and(|metadata| metadata.profile_keys_enabled)
        {
            "enabled"
        } else {
            "disabled"
        }
    );
    if let Some(generation) = ciphertext.generation() {
        println!("generation: {generation}");
    }
    println!("recipients: {}", ciphertext.recipients.len());
    match crate::security_state::rotation_recommendation(&ctx.vault_path) {
        Ok(Some(reason)) => println!("data-key rotation: recommended ({reason})"),
        Ok(None) => println!("data-key rotation: no local reminder"),
        Err(error) => println!("data-key rotation: unknown ({error})"),
    }
    println!(
        "passphrase factor: {}",
        if ciphertext_requires_passphrase(&ciphertext) {
            "enabled"
        } else {
            "disabled"
        }
    );
    println!(
        "device-seal factor: {}",
        if ciphertext_requires_device_seal(&ciphertext) {
            "enabled"
        } else {
            "disabled"
        }
    );
    if let Some(metadata) = &ciphertext.policy_metadata {
        println!(
            "recovery-share sets: {}",
            metadata.recovery_share_sets.len()
        );
        println!("remote/KMS factors: {}", metadata.remote_factors.len());
    }

    let mut recipients = HashSet::new();
    for recipient in ciphertext.recipients {
        println!("  - {}", recipient.fingerprint);
        recipients.insert(recipient.fingerprint);
    }

    Ok(Some(recipients))
}

fn ciphertext_requires_passphrase(ciphertext: &sshenv_vault::CiphertextVault) -> bool {
    ciphertext
        .policy_metadata
        .as_ref()
        .into_iter()
        .flat_map(|metadata| &metadata.policies)
        .flat_map(|policy| &policy.factors)
        .any(|factor| factor.kind == sshenv_vault::models::UnlockFactorKindV2::Passphrase)
}

fn ciphertext_requires_device_seal(ciphertext: &sshenv_vault::CiphertextVault) -> bool {
    ciphertext
        .policy_metadata
        .as_ref()
        .into_iter()
        .flat_map(|metadata| &metadata.policies)
        .flat_map(|policy| &policy.factors)
        .any(|factor| factor.kind == sshenv_vault::models::UnlockFactorKindV2::DeviceSeal)
}

fn print_feature_status() {
    println!("Compiled security features");
    println!("--------------------------");
    println!(
        "ssh-hardening: {} ({})",
        enabled_label(cfg!(feature = "ssh-hardening")),
        ssh_hardening_policy_label()
    );
    println!("rekey:          {}", enabled_label(cfg!(feature = "rekey")));
    println!(
        "passphrase:     {}",
        enabled_label(cfg!(feature = "passphrase-factor"))
    );
    println!(
        "device-seal:    {} ({})",
        enabled_label(cfg!(feature = "device-seal")),
        device_seal_backend_status(),
    );
    println!(
        "hardware keys: {}",
        enabled_label(cfg!(feature = "hardware-recipient"))
    );
    println!(
        "age plugins:   {}",
        enabled_label(cfg!(feature = "age-plugin-recipient"))
    );
    println!(
        "runtime:       {} (coredumps off, non-dumpable where supported, best-effort memory lock)",
        enabled_label(cfg!(feature = "runtime-hardening"))
    );
    println!(
        "profile-keys:  {}",
        enabled_label(cfg!(feature = "profile-keys"))
    );
    println!(
        "threshold:     {}",
        enabled_label(cfg!(feature = "threshold-policies"))
    );
    println!(
        "recovery:      {}",
        enabled_label(cfg!(feature = "recovery-shares"))
    );
    println!(
        "remote/KMS:    {}",
        enabled_label(cfg!(feature = "remote-factor") || cfg!(feature = "kms-factor"))
    );
    println!(
        "rollback:       {}",
        enabled_label(cfg!(feature = "rollback-protection"))
    );
}

const fn enabled_label(enabled: bool) -> &'static str {
    if enabled { "enabled" } else { "disabled" }
}

#[cfg(feature = "ssh-hardening")]
fn ssh_hardening_policy_label() -> String {
    crate::config::load().map_or_else(
        |error| format!("config-error: {error}"),
        |config| {
            format!(
                "unencrypted authorized keys: {}",
                config.security.unencrypted_ssh_keys.label()
            )
        },
    )
}

#[cfg(not(feature = "ssh-hardening"))]
fn ssh_hardening_policy_label() -> String {
    "disabled".to_string()
}

const fn device_seal_backend_status() -> &'static str {
    #[cfg(feature = "device-seal")]
    {
        sshenv_vault::device::backend_status()
    }
    #[cfg(not(feature = "device-seal"))]
    {
        "none"
    }
}

fn print_key_status(vault_recipients: Option<&HashSet<String>>) {
    println!("Local SSH private keys");
    println!("----------------------");

    let paths = discover_private_key_paths();
    if paths.is_empty() {
        println!("(none found in ~/.ssh/ or ~/.ssh/config)");
        return;
    }

    for path in paths {
        let fingerprint = public_fingerprint_for_private_key(&path);
        let recipient_status = recipient_status(vault_recipients, fingerprint.as_ref());
        let hardening_status = key_hardening_status(&path);
        println!("{}{}{}", path.display(), recipient_status, hardening_status);
    }
}

fn recipient_status(
    vault_recipients: Option<&HashSet<String>>,
    fingerprint: Option<&String>,
) -> String {
    match (vault_recipients, fingerprint) {
        (Some(recipients), Some(fp)) if recipients.contains(fp) => {
            format!("  {fp}  authorized")
        }
        (Some(_), Some(fp)) => format!("  {fp}  not-a-recipient"),
        (None, Some(fp)) => format!("  {fp}"),
        (_, None) => "  no-.pub-sibling".to_string(),
    }
}

#[cfg(feature = "ssh-hardening")]
fn key_hardening_status(path: &Path) -> String {
    match crate::identity::inspect_private_key_security(path) {
        Ok(status) => {
            if status.is_encrypted() {
                format!("  key:{}", status.label())
            } else {
                format!("  key:{} warning", status.label())
            }
        }
        Err(err) => format!("  key:unknown ({err})"),
    }
}

#[cfg(not(feature = "ssh-hardening"))]
const fn key_hardening_status(_path: &Path) -> String {
    String::new()
}

fn print_recommendations(vault_recipients: Option<&HashSet<String>>) {
    println!("Recommendations");
    println!("---------------");

    if vault_recipients.is_none() {
        println!("- Initialize a vault before hardening policies can be evaluated.");
        return;
    }

    println!("- Keep authorized SSH private keys passphrase-encrypted.");
    println!("- Use per-device SSH keys so a stolen key can be removed independently.");
    if cfg!(feature = "rekey") {
        println!(
            "- Rotate the vault data key after recipient removal with `sshenv rotate-key` or `remove-recipient --rotate`."
        );
    } else {
        println!(
            "- Use a build with the `rekey` feature to rotate data keys after recipient removal."
        );
    }
    println!("- Migrate to the future v2 policy format before enabling multi-factor policies.");
}
