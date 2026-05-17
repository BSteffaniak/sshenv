//! Process identity and signaling helpers for tracked sessions.
//!
//! A bare PID is not enough to safely signal a process: PIDs can be
//! reused after exit. These helpers build a platform-specific token from
//! the process start time so `sessions kill` can verify that a registry
//! entry still points at the same process before sending a signal.

#[cfg(any(unix, windows))]
use anyhow::Context;
use anyhow::Result;

#[cfg(unix)]
pub type Pid = libc::pid_t;

#[cfg(not(unix))]
pub type Pid = i32;

#[must_use]
pub fn current_pid() -> Pid {
    #[cfg(unix)]
    {
        // SAFETY: `getpid` has no preconditions.
        unsafe { libc::getpid() }
    }
    #[cfg(not(unix))]
    {
        i32::try_from(std::process::id()).unwrap_or(i32::MAX)
    }
}

/// Return a stable-ish process identity token for the current process.
#[must_use]
pub fn current_process_token() -> Option<String> {
    process_token(current_pid())
}

/// Return a stable-ish process identity token for `pid`.
#[must_use]
pub fn process_token(pid: Pid) -> Option<String> {
    platform_process_token(pid)
}

/// True only when `pid` is alive and its current identity equals `token`.
#[must_use]
pub fn is_same_process(pid: Pid, token: &str) -> bool {
    process_token(pid).is_some_and(|current| current == token)
}

/// Send `signal` to `pid`.
///
/// Callers must verify process identity before invoking this function.
/// Returns `Ok(false)` if the process disappeared before the signal could
/// be delivered.
pub fn send_signal(pid: Pid, signal: Signal) -> Result<bool> {
    #[cfg(unix)]
    {
        // SAFETY: `kill` is called with a caller-provided pid and a valid
        // signal number from our enum.
        let rc = unsafe { libc::kill(pid, signal.as_raw()) };
        if rc == 0 {
            Ok(true)
        } else {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::ESRCH) {
                Ok(false)
            } else {
                Err(err).with_context(|| format!("failed to send {} to pid {pid}", signal.name()))
            }
        }
    }

    #[cfg(windows)]
    {
        match signal {
            Signal::Term | Signal::Kill => terminate_windows_process(pid),
            Signal::Int | Signal::Hup => anyhow::bail!(
                "session signal {} is not supported on Windows; use term or kill",
                signal.name()
            ),
        }
    }

    #[cfg(not(any(unix, windows)))]
    {
        let _ = (pid, signal);
        anyhow::bail!("session signaling is not supported on this platform")
    }
}

#[derive(Clone, Copy, Debug)]
pub enum Signal {
    Term,
    Int,
    Hup,
    Kill,
}

impl Signal {
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Term => "TERM",
            Self::Int => "INT",
            Self::Hup => "HUP",
            Self::Kill => "KILL",
        }
    }

    #[cfg(unix)]
    #[must_use]
    const fn as_raw(self) -> libc::c_int {
        match self {
            Self::Term => libc::SIGTERM,
            Self::Int => libc::SIGINT,
            Self::Hup => libc::SIGHUP,
            Self::Kill => libc::SIGKILL,
        }
    }
}

#[cfg(target_os = "linux")]
fn platform_process_token(pid: Pid) -> Option<String> {
    let boot_id = std::fs::read_to_string("/proc/sys/kernel/random/boot_id").ok()?;
    let start_time = linux_process_start_time(pid)?;
    Some(format!("linux:{}:{start_time}", boot_id.trim()))
}

#[cfg(target_os = "linux")]
fn linux_process_start_time(pid: Pid) -> Option<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    parse_linux_stat_start_time(&stat)
}

#[cfg(target_os = "linux")]
fn parse_linux_stat_start_time(stat: &str) -> Option<u64> {
    let end_comm = stat.rfind(')')?;
    let rest = stat.get(end_comm + 1..)?.trim_start();
    // `rest` starts at field 3 (`state`). `starttime` is field 22, so it is
    // token index 19 after removing pid and comm.
    rest.split_whitespace().nth(19)?.parse().ok()
}

#[cfg(target_os = "macos")]
fn platform_process_token(pid: Pid) -> Option<String> {
    let mut info = std::mem::MaybeUninit::<libc::proc_bsdinfo>::zeroed();
    let size = std::mem::size_of::<libc::proc_bsdinfo>();
    let size_i32 = libc::c_int::try_from(size).ok()?;

    // SAFETY: `info` points to a valid writable buffer of `size` bytes, and
    // `PROC_PIDTBSDINFO` asks the kernel to fill exactly a `proc_bsdinfo`.
    let written = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDTBSDINFO,
            0,
            info.as_mut_ptr().cast(),
            size_i32,
        )
    };
    if written != size_i32 {
        return None;
    }

    // SAFETY: `proc_pidinfo` reported that it initialized the full struct.
    let info = unsafe { info.assume_init() };
    Some(format!(
        "macos:{}:{}",
        info.pbi_start_tvsec, info.pbi_start_tvusec
    ))
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
#[allow(clippy::missing_const_for_fn)]
fn platform_process_token(_pid: Pid) -> Option<String> {
    None
}

#[cfg(windows)]
fn platform_process_token(pid: Pid) -> Option<String> {
    use windows_sys::Win32::Foundation::{CloseHandle, FILETIME};
    use windows_sys::Win32::System::Threading::{
        GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    let pid_u32 = u32::try_from(pid).ok()?;
    // SAFETY: `OpenProcess` is called with query-only access and a caller-provided PID.
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid_u32) };
    if handle.is_null() {
        return None;
    }

    let mut creation = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    let mut exit = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    let mut kernel = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    let mut user = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };

    // SAFETY: `handle` is valid when non-null and all FILETIME pointers are writable.
    let ok = unsafe { GetProcessTimes(handle, &mut creation, &mut exit, &mut kernel, &mut user) };
    // SAFETY: `handle` came from `OpenProcess` and is closed exactly once here.
    unsafe {
        CloseHandle(handle);
    }
    if ok == 0 {
        return None;
    }

    let creation_ticks =
        (u64::from(creation.dwHighDateTime) << 32) | u64::from(creation.dwLowDateTime);
    Some(format!("windows:{pid}:{creation_ticks}"))
}

#[cfg(windows)]
fn terminate_windows_process(pid: Pid) -> Result<bool> {
    use windows_sys::Win32::Foundation::{CloseHandle, ERROR_INVALID_PARAMETER, GetLastError};
    use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_TERMINATE, TerminateProcess};

    let pid_u32 = u32::try_from(pid).context("invalid Windows process id")?;
    // SAFETY: `OpenProcess` is called with terminate access and a caller-provided PID.
    let handle = unsafe { OpenProcess(PROCESS_TERMINATE, 0, pid_u32) };
    if handle.is_null() {
        // SAFETY: reads the thread-local last-error set by `OpenProcess`.
        let error = unsafe { GetLastError() };
        if error == ERROR_INVALID_PARAMETER {
            return Ok(false);
        }
        return Err(std::io::Error::from_raw_os_error(
            i32::try_from(error).unwrap_or(i32::MAX),
        ))
        .with_context(|| format!("failed to open pid {pid} for termination"));
    }

    // SAFETY: `handle` is valid and opened for PROCESS_TERMINATE.
    let ok = unsafe { TerminateProcess(handle, 1) };
    // SAFETY: `handle` came from `OpenProcess` and is closed exactly once here.
    unsafe {
        CloseHandle(handle);
    }
    if ok == 0 {
        Err(std::io::Error::last_os_error())
            .with_context(|| format!("failed to terminate pid {pid}"))
    } else {
        Ok(true)
    }
}

#[cfg(not(any(unix, windows)))]
#[allow(clippy::missing_const_for_fn)]
fn platform_process_token(_pid: Pid) -> Option<String> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn parse_linux_stat_handles_comm_with_spaces_and_parens() {
        let fields_after_comm = [
            "S", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13", "14", "15",
            "16", "17", "18", "123456", "20", "21",
        ];
        let stat = format!("42 (weird name)) {}", fields_after_comm.join(" "));
        assert_eq!(parse_linux_stat_start_time(&stat), Some(123_456));
    }

    #[test]
    fn current_process_matches_its_token_when_supported() {
        if let Some(token) = current_process_token() {
            assert!(is_same_process(current_pid(), &token));
        }
    }
}
