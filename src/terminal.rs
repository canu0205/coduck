use crate::profile::ProfileGuard;
use anyhow::{Result, anyhow, bail};
use std::{
    fs::{File, OpenOptions},
    io::Write,
    os::fd::{AsRawFd, RawFd},
    os::unix::fs::OpenOptionsExt,
    time::Duration,
};
use tokio::{
    process::{Child, Command},
    time::timeout,
};

pub struct Terminal {
    child: Option<Child>,
    group: Option<u32>,
    tty: File,
    foreground: libc::pid_t,
    attributes: libc::termios,
}

impl Terminal {
    pub async fn spawn(mut command: Command, guard: &ProfileGuard) -> Result<Self> {
        if unsafe { libc::isatty(libc::STDIN_FILENO) } != 1 {
            bail!("coduck run requires an interactive terminal");
        }
        let tty = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_CLOEXEC)
            .open("/dev/tty")?;
        let fd = tty.as_raw_fd();
        let foreground = unsafe { libc::tcgetpgrp(fd) };
        if foreground != unsafe { libc::getpgrp() } {
            bail!("run coduck in the foreground of your terminal");
        }
        let mut attributes = unsafe { std::mem::zeroed() };
        if unsafe { libc::tcgetattr(fd, &mut attributes) } != 0 {
            bail!("cannot save terminal settings");
        }
        let mut terminal = Self {
            child: None,
            group: None,
            tty,
            foreground,
            attributes,
        };
        command.process_group(0).kill_on_drop(true);
        unsafe {
            command.pre_exec(move || foreground_group(fd, libc::getpgrp()));
        }
        guard.begin_spawn()?;
        match command.spawn() {
            Ok(child) => {
                terminal.group = child.id();
                terminal.child = Some(child);
            }
            Err(_) => {
                guard.cancel_spawn()?;
                bail!("cannot start Codex terminal");
            }
        }
        if let Err(error) = guard.register_group(terminal.group.unwrap()) {
            let _ = terminal.terminate().await;
            return Err(error);
        }
        Ok(terminal)
    }
    pub async fn wait(&self) -> Result<bool> {
        crate::process::exited(
            self.group
                .ok_or_else(|| anyhow!("terminal already stopped"))?,
        )
        .await
    }
    pub fn interrupt(&self) -> Result<()> {
        self.signal(libc::SIGINT)
    }
    fn signal(&self, signal: i32) -> Result<()> {
        if let Some(group) = self.group {
            crate::process::signal_group(group, signal)?;
        }
        Ok(())
    }
    pub async fn shutdown(&mut self) -> Result<()> {
        // the UI closes its socket before restoring the terminal and printing its footer.
        let exited = timeout(Duration::from_secs(5), self.wait()).await;
        let stopped = self.terminate().await;
        stopped?;
        match exited {
            Ok(Ok(true)) => Ok(()),
            Ok(Ok(false)) => bail!("Codex terminal exited unsuccessfully"),
            Ok(Err(error)) => Err(error),
            Err(_) => bail!("Codex terminal did not finish shutting down"),
        }
    }
    pub async fn terminate(&mut self) -> Result<()> {
        let result = async {
            self.signal(libc::SIGTERM)?;
            if let Some(group) = self.group {
                let _ = timeout(Duration::from_secs(3), crate::process::exited(group)).await;
            }
            self.signal(libc::SIGKILL)?;
            // never signal the saved group after releasing its leader's PID.
            self.group = None;
            if let Some(child) = self.child.as_mut() {
                timeout(Duration::from_secs(3), child.wait())
                    .await
                    .map_err(|_| anyhow!("terminal shutdown timed out"))??;
            }
            Ok(())
        }
        .await;
        self.restore();
        result
    }
    fn restore(&self) {
        let fd = self.tty.as_raw_fd();
        let _ = foreground_group(fd, self.foreground);
        unsafe {
            libc::tcsetattr(fd, libc::TCSANOW, &self.attributes);
        }
        // termios does not restore the emulator's cursor visibility or text style.
        let _ = (&self.tty).write_all(b"\x1b[?25h\x1b[0m");
    }
}
impl Drop for Terminal {
    fn drop(&mut self) {
        let _ = self.signal(libc::SIGKILL);
        self.restore();
    }
}

// block SIGTTOU while handing the terminal between foreground process groups.
fn foreground_group(fd: RawFd, group: libc::pid_t) -> std::io::Result<()> {
    unsafe {
        let mut blocked = std::mem::zeroed();
        let mut previous = std::mem::zeroed();
        libc::sigemptyset(&mut blocked);
        libc::sigaddset(&mut blocked, libc::SIGTTOU);
        if libc::sigprocmask(libc::SIG_BLOCK, &blocked, &mut previous) != 0 {
            return Err(std::io::Error::last_os_error());
        }
        let result = libc::tcsetpgrp(fd, group);
        let error = std::io::Error::last_os_error();
        libc::sigprocmask(libc::SIG_SETMASK, &previous, std::ptr::null_mut());
        if result == 0 { Ok(()) } else { Err(error) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Seek, SeekFrom};
    use std::process::Stdio;
    use tokio::io::AsyncReadExt;

    #[tokio::test]
    async fn shutdown_preserves_the_footer_and_restores_cursor_visibility() {
        let tty = tempfile::tempfile().unwrap();
        let mut captured_tty = tty.try_clone().unwrap();
        let mut child = Command::new("/bin/sh")
            .args([
                "-c",
                "sleep 0.1; printf 'To continue: codex resume test-session\\n'",
            ])
            .process_group(0)
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut output = child.stdout.take().unwrap();
        let mut terminal = Terminal {
            group: child.id(),
            child: Some(child),
            tty,
            foreground: unsafe { libc::getpgrp() },
            attributes: unsafe { std::mem::zeroed() },
        };
        terminal.shutdown().await.unwrap();
        let mut footer = String::new();
        output.read_to_string(&mut footer).await.unwrap();
        assert!(footer.contains("codex resume test-session"));
        captured_tty.seek(SeekFrom::Start(0)).unwrap();
        let mut restored = String::new();
        captured_tty.read_to_string(&mut restored).unwrap();
        assert!(restored.contains("\x1b[?25h"));
    }
}
