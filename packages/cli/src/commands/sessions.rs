use anyhow::Result;
use sshenv_cli_models::{SessionSignal, SessionsKillArgs, SessionsListArgs};

use crate::commands::Context as CmdContext;
use crate::process::{self, Signal};
use crate::session_registry::{self, SessionRecord};

pub fn list(ctx: &CmdContext, args: SessionsListArgs) -> Result<()> {
    let vault = session_registry::vault_id(&ctx.vault_path);
    let mut registry = session_registry::open_locked()?;
    let removed = registry.gc_stale();
    if removed > 0 {
        registry.save()?;
    }

    let mut sessions: Vec<&SessionRecord> = registry
        .data
        .sessions
        .iter()
        .filter(|session| session.vault == vault)
        .filter(|session| {
            args.profile
                .as_ref()
                .is_none_or(|profile| session.profile == *profile)
        })
        .collect();
    sessions.sort_by(|a, b| {
        a.profile
            .cmp(&b.profile)
            .then_with(|| a.started_at_unix_ms.cmp(&b.started_at_unix_ms))
            .then_with(|| a.pid.cmp(&b.pid))
    });

    if sessions.is_empty() {
        eprintln!("(no tracked sessions)");
        return Ok(());
    }

    let profile_width = sessions
        .iter()
        .map(|session| session.profile.len())
        .max()
        .unwrap_or(7)
        .max(7);
    let command_width = sessions
        .iter()
        .map(|session| session.command.len())
        .max()
        .unwrap_or(7)
        .max(7);

    println!(
        "{:<7}  {:<profile_width$}  {:<command_width$}  STARTED_MS",
        "PID", "PROFILE", "COMMAND"
    );
    println!(
        "{:-<7}  {:-<profile_width$}  {:-<command_width$}  ----------",
        "", "", ""
    );
    for session in sessions {
        println!(
            "{:<7}  {:<profile_width$}  {:<command_width$}  {}",
            session.pid, session.profile, session.command, session.started_at_unix_ms
        );
    }
    Ok(())
}

pub fn kill(ctx: &CmdContext, args: SessionsKillArgs) -> Result<()> {
    let vault = session_registry::vault_id(&ctx.vault_path);
    let signal = signal_from_arg(args.signal);
    let scope = kill_scope(&args);

    let mut registry = session_registry::open_locked()?;
    let removed = registry.gc_stale();
    if removed > 0 {
        registry.save()?;
    }

    let matching: Vec<SessionRecord> = registry
        .data
        .sessions
        .iter()
        .filter(|session| session.vault == vault)
        .filter(|session| match &args.profile {
            Some(profile) => session.profile == *profile,
            None => args.all,
        })
        .cloned()
        .collect();

    if matching.is_empty() {
        eprintln!("No tracked live sessions {scope}.");
        return Ok(());
    }

    let mut signaled = 0_usize;
    let mut skipped = 0_usize;
    for session in matching {
        let Some(pid) = session.pid() else {
            skipped += 1;
            continue;
        };
        if !process::is_same_process(pid, &session.process_token) {
            skipped += 1;
            continue;
        }
        if process::send_signal(pid, signal)? {
            signaled += 1;
        } else {
            skipped += 1;
        }
    }

    eprintln!(
        "Sent {} to {signaled} tracked session(s) {scope}.",
        signal.name()
    );
    if skipped > 0 {
        eprintln!("Skipped {skipped} unverifiable or stale session record(s).");
    }
    Ok(())
}

fn kill_scope(args: &SessionsKillArgs) -> String {
    match &args.profile {
        Some(profile) => format!("for profile '{profile}'"),
        None => "for all profiles in the current vault".to_string(),
    }
}

const fn signal_from_arg(signal: SessionSignal) -> Signal {
    match signal {
        SessionSignal::Term => Signal::Term,
        SessionSignal::Int => Signal::Int,
        SessionSignal::Hup => Signal::Hup,
        SessionSignal::Kill => Signal::Kill,
    }
}
