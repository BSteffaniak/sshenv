use std::collections::HashSet;
use std::fs;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(feature = "passphrase-factor")]
use anyhow::Context as AnyhowContext;
use anyhow::Result;
use serde::Serialize;
use sshenv_cli_models::{
    ChangePassphraseArgs, DisablePassphraseArgs, EnablePassphraseArgs, ProfilePolicyApplyAllArgs,
    ProfilePolicyApplyArgs, ProfilePolicyChangePassphraseArgs, ProfilePolicyCheckArgs,
    ProfilePolicyDisablePassphraseArgs, ProfilePolicyRepairAllArgs, ProfilePolicyRepairArgs,
    ProfilePolicyRequirePassphraseArgs, ProfilePolicyRequirementArgs,
    ProfilePolicyRestoreBackupArgs, ProfilePolicyRotateKeyArgs, ProfilePolicySetArgs,
    ProfilePolicyStatusArgs, SecurityPresetArg, SecurityPresetArgs,
};
use sshenv_vault::models::{
    ProfileFactorRequirement, ProfilePolicy, ProfilePolicyFinding, ProfilePolicyFindingCode,
    ProfilePolicyPreset, ProfilePolicyRepairAction, ProfilePolicyRepairPlan, UnlockFactorKindV2,
    VERSION, VERSION_V2,
};
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
    let preset = profile_policy_preset(args.preset);
    let mut plan = build_profile_policy_apply_plan(&vault, &args.profile, preset)?;
    if args.passphrase.is_some()
        && profile_preset_expected_requirements(preset)
            .contains(&ProfileFactorRequirement::Passphrase)
    {
        add_profile_policy_plan_action(&mut plan, ProfilePolicyRepairAction::BindPassphrase);
        add_profile_policy_plan_action(&mut plan, ProfilePolicyRepairAction::RotateProfileKey);
    }

    if args.dry_run || args.json {
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
            | ProfilePolicyPreset::Paranoid
    ) {
        anyhow::bail!(
            "profile-policy apply-all without --dry-run currently supports --preset standard, portable, recommended, or paranoid only"
        );
    }
    ensure_profile_policy_apply_all_preset_supported(preset)?;
    let (mut vault, data_key) = crate::commands::load_and_unlock(&ctx.vault_path)?;
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

    let backup_ciphertext = Vault::load_ciphertext(&backup)?;
    let restored_generation = backup_ciphertext.generation();
    let recipient_fingerprints = backup_ciphertext
        .recipients
        .iter()
        .map(|recipient| recipient.fingerprint.clone())
        .collect::<HashSet<_>>();
    unlock_ciphertext(backup_ciphertext, &recipient_fingerprints)?;

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
