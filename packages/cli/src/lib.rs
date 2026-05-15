//! sshenv binary crate. All command dispatch lives under
//! [`commands`]; this module exposes a single [`run`] entry point.

#![allow(clippy::multiple_crate_versions)]

pub mod commands;
pub mod identity;
pub mod picker;
pub mod process;
pub mod pubkey;
#[cfg(feature = "rollback-protection")]
pub mod rollback;
#[cfg(feature = "runtime-hardening")]
pub mod runtime_hardening;
pub mod session_registry;

use anyhow::Result;
use sshenv_cli_models::{
    Cli, Command, ProfilePolicyCommand, SecurityCommand, SessionsCommand, ShimsCommand,
};

/// Dispatch a parsed [`Cli`] to the appropriate command handler.
///
/// # Errors
///
/// Propagates the handler's error.
pub fn run(cli: Cli) -> Result<()> {
    let ctx = commands::Context::from_cli(&cli);

    match cli.command {
        Command::Init(args) => commands::init::run(&ctx, args),
        Command::Doctor => commands::doctor::run(&ctx),
        Command::RotateKey(args) => commands::rekey::rotate_key(&ctx, args),
        Command::MigrateVault(args) => commands::migrate::run(&ctx, args),
        Command::Security(sub) => match sub {
            SecurityCommand::Status => commands::security::status(&ctx),
            SecurityCommand::EnablePassphrase(args) => {
                commands::security::enable_passphrase(&ctx, args)
            }
            SecurityCommand::ChangePassphrase(args) => {
                commands::security::change_passphrase(&ctx, args)
            }
            SecurityCommand::DisablePassphrase(args) => {
                commands::security::disable_passphrase(&ctx, args)
            }
            SecurityCommand::EnableDeviceSeal => commands::security::enable_device_seal(&ctx),
            SecurityCommand::Preset(args) => commands::security::preset(&ctx, args),
            SecurityCommand::ProfilePolicy(sub) => match sub {
                ProfilePolicyCommand::List => commands::security::profile_policy_list(&ctx),
                ProfilePolicyCommand::Status(args) => {
                    commands::security::profile_policy_status(&ctx, args)
                }
                ProfilePolicyCommand::Migrate => commands::security::profile_policy_migrate(&ctx),
                ProfilePolicyCommand::RotateKey(args) => {
                    commands::security::profile_policy_rotate_key(&ctx, args)
                }
                ProfilePolicyCommand::RequirePassphrase(args) => {
                    commands::security::profile_policy_require_passphrase(&ctx, args)
                }
                ProfilePolicyCommand::ChangePassphrase(args) => {
                    commands::security::profile_policy_change_passphrase(&ctx, args)
                }
                ProfilePolicyCommand::DisablePassphrase(args) => {
                    commands::security::profile_policy_disable_passphrase(&ctx, args)
                }
                ProfilePolicyCommand::RequireDeviceSeal(args) => {
                    commands::security::profile_policy_require_device_seal(&ctx, args)
                }
                ProfilePolicyCommand::DisableDeviceSeal(args) => {
                    commands::security::profile_policy_disable_device_seal(&ctx, args)
                }
                ProfilePolicyCommand::ClearRequirements(args) => {
                    commands::security::profile_policy_clear_requirements(&ctx, args)
                }
                ProfilePolicyCommand::Apply(args) => {
                    commands::security::profile_policy_apply(&ctx, args)
                }
                ProfilePolicyCommand::Repair(args) => {
                    commands::security::profile_policy_repair(&ctx, args)
                }
                ProfilePolicyCommand::Set(args) => {
                    commands::security::profile_policy_set(&ctx, args)
                }
            },
        },

        Command::AddRecipient(args) => commands::recipient::add(&ctx, args),
        Command::ListRecipients(args) => commands::recipient::list(&ctx, args),
        Command::RemoveRecipient(args) => commands::recipient::remove(&ctx, args),

        Command::Set(args) => commands::profile::set(&ctx, args),
        Command::Unset(args) => commands::profile::unset(&ctx, args),
        Command::List(args) => commands::profile::list(&ctx, args),
        Command::Show(args) => commands::profile::show(&ctx, args),
        Command::RmProfile(args) => commands::profile::rm(&ctx, args),
        Command::RenameProfile(args) => commands::profile::rename(&ctx, args),

        Command::Run(args) => commands::run::run(&ctx, args),
        Command::Export(args) => commands::export::run(&ctx, args),

        Command::Sessions(sub) => match sub {
            SessionsCommand::List(args) => commands::sessions::list(&ctx, args),
            SessionsCommand::Kill(args) => commands::sessions::kill(&ctx, args),
        },

        Command::Shims(sub) => match sub {
            ShimsCommand::Bind(args) => commands::shims::bind(&ctx, args),
            ShimsCommand::Unbind(args) => commands::shims::unbind(&ctx, args),
            ShimsCommand::Rename(args) => commands::shims::rename(&ctx, args),
            ShimsCommand::List => commands::shims::list(&ctx),
            ShimsCommand::Sync => commands::shims::sync(&ctx),
            ShimsCommand::Dir => commands::shims::dir(&ctx),
            ShimsCommand::Path => commands::shims::path(&ctx),
        },
    }
}
