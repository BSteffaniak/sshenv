use std::collections::HashSet;
use std::io::IsTerminal;
use std::path::Path;

#[cfg(feature = "passphrase-factor")]
use anyhow::Context as AnyhowContext;
use anyhow::Result;
use serde::Serialize;
use sshenv_cli_models::{
    ChangePassphraseArgs, DisablePassphraseArgs, EnablePassphraseArgs, ProfilePolicyApplyArgs,
    ProfilePolicyChangePassphraseArgs, ProfilePolicyCheckArgs, ProfilePolicyDisablePassphraseArgs,
    ProfilePolicyRepairArgs, ProfilePolicyRequirePassphraseArgs, ProfilePolicyRequirementArgs,
    ProfilePolicyRotateKeyArgs, ProfilePolicySetArgs, ProfilePolicyStatusArgs, SecurityPresetArg,
    SecurityPresetArgs,
};
use sshenv_vault::models::{
    ProfileFactorRequirement, ProfilePolicy, ProfilePolicyFinding, ProfilePolicyFindingCode,
    ProfilePolicyPreset, ProfilePolicyRepairAction, ProfilePolicyRepairPlan, UnlockFactorKindV2,
    VERSION, VERSION_V2,
};
use sshenv_vault::{DataKey, Vault};

use crate::commands::Context as CmdContext;
#[cfg(feature = "passphrase-factor")]
use crate::commands::unlock_ciphertext_with_passphrase;
use crate::commands::{
    load_and_unlock_metadata, load_and_unlock_profile, load_ciphertext_and_fps, save_vault,
    unlock_ciphertext,
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
        None => zeroize::Zeroizing::new(
            rpassword::prompt_password(prompt).context("failed to read passphrase")?,
        ),
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

fn print_profile_policy_repair_plan(output: &ProfilePolicyRepairPlan) {
    println!("profile policy repair plan");
    println!("==========================");
    println!("profile: {}", output.profile);
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

fn profile_repair_needs_passphrase(policy: &ProfilePolicy) -> bool {
    let preset_needs_passphrase = profile_preset_expected_requirements(policy.preset)
        .contains(&ProfileFactorRequirement::Passphrase);
    let requirement_needs_passphrase = policy
        .required_factors
        .contains(&ProfileFactorRequirement::Passphrase);
    (preset_needs_passphrase || requirement_needs_passphrase)
        && !profile_has_factor_metadata(policy, UnlockFactorKindV2::Passphrase)
}

fn profile_preset_expected_requirements(
    preset: ProfilePolicyPreset,
) -> Vec<ProfileFactorRequirement> {
    match preset {
        ProfilePolicyPreset::Standard => Vec::new(),
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
    prepare_profile_policy_enforcement(&mut vault, &args.profile, &args.recipient_keys)?;

    let preset = profile_policy_preset(args.preset);
    match preset {
        ProfilePolicyPreset::Standard => {
            let mut policy = existing_or_default_profile_policy(&vault, &args.profile);
            policy.preset = preset;
            policy.required_factors.clear();
            policy.factor_metadata.clear();
            vault.profiles.set_profile_policy(&args.profile, policy)?;
        }
        ProfilePolicyPreset::Portable => {
            apply_profile_passphrase_if_needed(&mut vault, &args.profile, args.passphrase)?;
            set_profile_policy_preset(&mut vault, &args.profile, preset)?;
        }
        ProfilePolicyPreset::Recommended => {
            #[cfg(feature = "device-seal")]
            apply_profile_device_seal_if_available(&mut vault, &args.profile)?;
            #[cfg(not(feature = "device-seal"))]
            note_profile_device_seal_unavailable();
            set_profile_policy_preset(&mut vault, &args.profile, preset)?;
        }
        ProfilePolicyPreset::Paranoid => {
            apply_profile_passphrase_if_needed(&mut vault, &args.profile, args.passphrase)?;
            #[cfg(feature = "device-seal")]
            apply_profile_device_seal_if_available(&mut vault, &args.profile)?;
            #[cfg(not(feature = "device-seal"))]
            note_profile_device_seal_unavailable();
            set_profile_policy_preset(&mut vault, &args.profile, preset)?;
            vault.rotate_profile_key(&args.profile)?;
        }
    }

    save_profile_policy_vault(ctx, &mut vault, &data_key, &args.profile)?;
    eprintln!(
        "Applied {:?} profile policy enforcement to {}.",
        preset, args.profile
    );
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

    let mut changed = false;
    let mut applied_actions = Vec::new();

    if plan
        .actions
        .contains(&ProfilePolicyRepairAction::MigrateToV2)
        && migrate_to_v2_if_needed(&mut vault, &args.recipient_keys)?
    {
        changed = true;
        applied_actions.push(ProfilePolicyRepairAction::MigrateToV2.label());
    }

    let base_result = vault.apply_profile_policy_repair_plan_base(&args.profile, &plan)?;
    changed |= base_result.changed;
    applied_actions.extend(
        base_result
            .applied_actions
            .iter()
            .map(|action| action.label()),
    );
    ensure_profile_policy_editable(&vault, &args.profile)?;

    for action in &plan.actions {
        match action {
            ProfilePolicyRepairAction::BindPassphrase => {
                if repair_profile_passphrase_if_needed(
                    &mut vault,
                    &args.profile,
                    args.passphrase.clone(),
                )? {
                    changed = true;
                    applied_actions.push(action.label());
                }
            }
            ProfilePolicyRepairAction::BindDeviceSeal => {
                #[cfg(feature = "device-seal")]
                {
                    if repair_profile_device_seal_if_available(&mut vault, &args.profile)? {
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

fn ensure_repair_inputs_available(
    plan: &ProfilePolicyRepairPlan,
    args: &ProfilePolicyRepairArgs,
) -> Result<()> {
    if plan.requires_passphrase && args.passphrase.is_none() && !std::io::stdin().is_terminal() {
        anyhow::bail!(
            "profile policy repair requires --passphrase <value> in non-interactive mode"
        );
    }
    if plan.requires_recipient_key && args.recipient_keys.is_empty() {
        eprintln!(
            "note: repair may need --recipient-key <path-or-public-key-line> to migrate this v1 vault"
        );
    }
    Ok(())
}

fn prepare_profile_policy_enforcement(
    vault: &mut Vault,
    profile: &str,
    recipient_keys: &[String],
) -> Result<bool> {
    let was_v2 = vault.header.version == VERSION_V2;
    let had_profile_keys = vault.profile_keys_enabled();
    migrate_to_v2_if_needed(vault, recipient_keys)?;
    if !vault.profile_keys_enabled() {
        vault.enable_profile_keys()?;
    }
    ensure_profile_policy_editable(vault, profile)?;
    Ok(!was_v2 || !had_profile_keys)
}

fn set_profile_policy_preset(
    vault: &mut Vault,
    profile: &str,
    preset: ProfilePolicyPreset,
) -> Result<()> {
    let mut policy = existing_or_default_profile_policy(vault, profile);
    policy.preset = preset;
    vault.profiles.set_profile_policy(profile, policy)?;
    Ok(())
}

#[cfg(feature = "passphrase-factor")]
fn apply_profile_passphrase_if_needed(
    vault: &mut Vault,
    profile: &str,
    passphrase: Option<String>,
) -> Result<()> {
    let passphrase = passphrase_arg_or_prompt(passphrase, "Enter new sshenv profile passphrase: ")?;
    vault.require_profile_passphrase(profile, passphrase.as_str())
}

#[cfg(not(feature = "passphrase-factor"))]
fn apply_profile_passphrase_if_needed(
    _vault: &mut Vault,
    _profile: &str,
    _passphrase: Option<String>,
) -> Result<()> {
    anyhow::bail!("this sshenv build was compiled without passphrase-factor support")
}

#[cfg(feature = "device-seal")]
fn apply_profile_device_seal_if_available(vault: &mut Vault, profile: &str) -> Result<()> {
    if device_seal_backend_status() == "none" {
        eprintln!("note: no device-seal backend is available; skipping profile device seal");
        return Ok(());
    }
    vault.require_profile_device_seal(profile)
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
    if profile_has_factor_metadata(&policy, UnlockFactorKindV2::Passphrase) {
        return Ok(false);
    }
    apply_profile_passphrase_if_needed(vault, profile, passphrase)?;
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
