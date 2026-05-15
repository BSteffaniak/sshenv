use std::collections::HashSet;
use std::path::Path;

use anyhow::Result;
use sshenv_cli_models::{
    ChangePassphraseArgs, DisablePassphraseArgs, EnablePassphraseArgs, ProfilePolicySetArgs,
    SecurityPresetArg, SecurityPresetArgs,
};
use sshenv_vault::Vault;
use sshenv_vault::models::{ProfilePolicy, ProfilePolicyPreset, VERSION, VERSION_V2};

use crate::commands::Context as CmdContext;
#[cfg(feature = "passphrase-factor")]
use crate::commands::unlock_ciphertext_with_passphrase;
use crate::commands::{load_ciphertext_and_fps, save_vault, unlock_ciphertext};
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
        None => zeroize::Zeroizing::new(rpassword::prompt_password(prompt)?),
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

pub fn profile_policy_list(ctx: &CmdContext) -> Result<()> {
    let (vault, _key) = crate::commands::load_and_unlock(&ctx.vault_path)?;
    if vault.profiles.profile_policies.is_empty() {
        eprintln!("(no profile policy metadata)");
        return Ok(());
    }
    for (profile, policy) in &vault.profiles.profile_policies {
        let findings = profile_policy_findings(&vault, policy.preset);
        if findings.is_empty() {
            println!("{profile}\t{:?}\tok", policy.preset);
        } else {
            println!(
                "{profile}\t{:?}\tadvisory-only; unmet: {}",
                policy.preset,
                findings.join(", ")
            );
        }
    }
    Ok(())
}

/// Print a warning when a profile's advisory policy is stronger than the
/// current vault posture.
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

fn profile_policy_findings(vault: &Vault, preset: ProfilePolicyPreset) -> Vec<String> {
    let mut findings = Vec::new();
    let has_v2 = vault.header.version == VERSION_V2;
    let has_passphrase =
        vault_has_factor(vault, sshenv_vault::models::UnlockFactorKindV2::Passphrase);
    let has_device_seal =
        vault_has_factor(vault, sshenv_vault::models::UnlockFactorKindV2::DeviceSeal);

    match preset {
        ProfilePolicyPreset::Standard => {}
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

fn vault_has_factor(vault: &Vault, kind: sshenv_vault::models::UnlockFactorKindV2) -> bool {
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
        save_vault(ctx, &mut vault, &data_key)?;
        eprintln!("Migrated profiles to independently encrypted v2 profile entries.");
    } else {
        eprintln!("Profiles are already stored as independently encrypted v2 entries.");
    }
    Ok(())
}

pub fn profile_policy_set(ctx: &CmdContext, args: ProfilePolicySetArgs) -> Result<()> {
    let (mut vault, data_key) = crate::commands::load_and_unlock(&ctx.vault_path)?;
    if vault.header.version != VERSION_V2 {
        anyhow::bail!(
            "profile policy metadata requires v2; run `sshenv migrate-vault --to v2` first"
        );
    }
    let preset = profile_policy_preset(args.preset);
    vault
        .profiles
        .set_profile_policy(&args.profile, ProfilePolicy { preset })?;
    save_vault(ctx, &mut vault, &data_key)?;
    eprintln!(
        "Set advisory profile policy for {} to {:?}. Per-profile cryptographic enforcement is planned but not active yet.",
        args.profile, preset
    );
    Ok(())
}

pub fn preset(ctx: &CmdContext, args: SecurityPresetArgs) -> Result<()> {
    match args.preset {
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

const fn profile_policy_preset(preset: SecurityPresetArg) -> ProfilePolicyPreset {
    match preset {
        SecurityPresetArg::Standard => ProfilePolicyPreset::Standard,
        SecurityPresetArg::Recommended => ProfilePolicyPreset::Recommended,
        SecurityPresetArg::Portable => ProfilePolicyPreset::Portable,
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
        "ssh-hardening: {}",
        enabled_label(cfg!(feature = "ssh-hardening"))
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
    println!("hardware keys:  planned");
    println!(
        "runtime:       {}",
        enabled_label(cfg!(feature = "runtime-hardening"))
    );
    println!(
        "profile-keys:  {}",
        enabled_label(cfg!(feature = "profile-keys"))
    );
    println!("threshold:      planned");
    println!(
        "rollback:       {}",
        enabled_label(cfg!(feature = "rollback-protection"))
    );
}

const fn enabled_label(enabled: bool) -> &'static str {
    if enabled { "enabled" } else { "disabled" }
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
fn key_hardening_status(_path: &Path) -> String {
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
