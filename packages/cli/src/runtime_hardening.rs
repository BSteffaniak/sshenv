//! Runtime hardening for commands that receive decrypted environment values.

use anyhow::Result;

/// Apply best-effort process hardening before secrets are decrypted/injected.
///
/// This intentionally avoids changing user-visible command ergonomics. On Unix
/// it disables core dumps for the current process, which is inherited by the
/// exec'd child. On Linux it also marks the process non-dumpable where
/// supported. On Windows it applies best-effort crash-dialog and heap-corruption
/// hardening for the process before spawning the child.
///
/// # Errors
///
/// Returns an error only when a platform hardening syscall fails.
pub fn apply_for_secret_runtime() -> Result<()> {
    apply_core_dump_limit()?;
    apply_non_dumpable()?;
    apply_windows_hardening_best_effort();
    apply_memory_lock_best_effort();
    Ok(())
}

#[cfg(unix)]
fn apply_core_dump_limit() -> Result<()> {
    let limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    let rc = unsafe { libc::setrlimit(libc::RLIMIT_CORE, std::ptr::addr_of!(limit)) };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error().into())
    }
}

#[cfg(not(unix))]
#[allow(clippy::missing_const_for_fn, clippy::unnecessary_wraps)]
fn apply_core_dump_limit() -> Result<()> {
    Ok(())
}

#[cfg(target_os = "linux")]
fn apply_non_dumpable() -> Result<()> {
    let rc = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error().into())
    }
}

#[cfg(not(target_os = "linux"))]
#[allow(clippy::missing_const_for_fn, clippy::unnecessary_wraps)]
fn apply_non_dumpable() -> Result<()> {
    Ok(())
}

#[cfg(windows)]
fn apply_windows_hardening_best_effort() {
    apply_windows_error_mode();
    apply_windows_heap_termination_on_corruption();
}

#[cfg(windows)]
fn apply_windows_error_mode() {
    use windows_sys::Win32::System::Diagnostics::Debug::{
        SEM_NOGPFAULTERRORBOX, SEM_NOOPENFILEERRORBOX, SetErrorMode,
    };

    // SAFETY: SetErrorMode only updates process-global error UI behavior.
    unsafe {
        SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
    }
}

#[cfg(windows)]
fn apply_windows_heap_termination_on_corruption() {
    use windows_sys::Win32::System::Memory::{
        HeapEnableTerminationOnCorruption, HeapSetInformation,
    };

    // SAFETY: Passing a null heap handle applies the process default and this
    // information class requires no input buffer.
    let rc = unsafe {
        HeapSetInformation(
            std::ptr::null_mut(),
            HeapEnableTerminationOnCorruption,
            std::ptr::null(),
            0,
        )
    };
    if rc == 0 {
        eprintln!(
            "warning: could not enable Windows heap corruption termination for sshenv runtime hardening: {}",
            std::io::Error::last_os_error()
        );
    }
}

#[cfg(not(windows))]
const fn apply_windows_hardening_best_effort() {}

#[cfg(unix)]
fn apply_memory_lock_best_effort() {
    let rc = unsafe { libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE) };
    if rc != 0 {
        eprintln!(
            "warning: could not lock process memory for sshenv runtime hardening: {}",
            std::io::Error::last_os_error()
        );
    }
}

#[cfg(not(unix))]
const fn apply_memory_lock_best_effort() {}
