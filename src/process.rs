use anyhow::{Result, bail};
use std::time::Duration;

// observe exit without releasing the group leader's PID before group cleanup.
pub async fn exited(pid: u32) -> Result<bool> {
    loop {
        if let Some(success) = exit_status(pid)? {
            return Ok(success);
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}
fn exit_status(pid: u32) -> Result<Option<bool>> {
    let mut status: libc::siginfo_t = unsafe { std::mem::zeroed() };
    let result = unsafe {
        libc::waitid(
            libc::P_PID,
            pid,
            &mut status,
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        )
    };
    if result != 0 {
        if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
            return Ok(None);
        }
        bail!("cannot observe child process exit");
    }
    Ok((unsafe { status.si_pid() } != 0)
        .then(|| status.si_code == libc::CLD_EXITED && unsafe { status.si_status() } == 0))
}
pub fn signal_group(pid: u32, signal: i32) -> Result<()> {
    if unsafe { libc::kill(-(pid as i32), signal) } == 0 {
        return Ok(());
    }
    let error = std::io::Error::last_os_error().raw_os_error();
    if error == Some(libc::ESRCH) {
        return Ok(());
    }
    // macOS returns EPERM when a group contains only an unreaped zombie.
    if error == Some(libc::EPERM) && exit_status(pid)?.is_some() {
        return Ok(());
    }
    bail!("cannot signal owned child process group")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn observing_exit_keeps_the_group_leader_pid_reserved_until_reaped() {
        let mut child = tokio::process::Command::new("/bin/sh")
            .args(["-c", "exit 7"])
            .process_group(0)
            .spawn()
            .unwrap();
        let pid = child.id().unwrap();
        assert!(!exited(pid).await.unwrap());
        assert_eq!(
            unsafe { libc::kill(pid as i32, 0) },
            0,
            "exit observation reaped the group leader"
        );
        assert_eq!(child.wait().await.unwrap().code(), Some(7));
    }
}
