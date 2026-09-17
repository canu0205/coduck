use crate::profile::home_directory;
use anyhow::{Result, anyhow, bail};
use std::{
    env,
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};
use tokio::{process::Command, time::timeout};

pub const SUPPORTED_VERSION: &str = "codex-cli 0.154.0";
pub struct Codex {
    executable: PathBuf,
    cwd: PathBuf,
    home: PathBuf,
}
impl Codex {
    pub async fn resolve() -> Result<Self> {
        let executable = match env::var_os("CODUCK_CODEX") {
            Some(path) if !path.is_empty() => find_executable(Path::new(&path))?,
            Some(_) => bail!("CODUCK_CODEX must not be empty"),
            None => find_executable(Path::new("codex"))?,
        };
        let cwd = env::current_dir()?;
        let home = match env::var_os("CODEX_HOME") {
            Some(value) if !value.is_empty() => cwd.join(value),
            Some(_) => bail!("CODEX_HOME must not be empty"),
            None => home_directory()?.join(".codex"),
        };
        let codex = Self {
            executable,
            cwd,
            home,
        };
        let mut command = codex.command(&codex.home, &codex.cwd);
        let output = timeout(
            Duration::from_secs(10),
            command
                .arg("--version")
                .stdin(Stdio::null())
                .stderr(Stdio::null())
                .kill_on_drop(true)
                .output(),
        )
        .await
        .map_err(|_| anyhow!("Codex version check timed out"))?
        .map_err(|_| anyhow!("cannot execute Codex; check CODUCK_CODEX or PATH"))?;
        if !output.status.success() || output.stdout != format!("{SUPPORTED_VERSION}\n").as_bytes()
        {
            bail!("unsupported Codex version; Coduck requires {SUPPORTED_VERSION}");
        }
        Ok(codex)
    }
    fn command(&self, home: &Path, cwd: &Path) -> Command {
        let mut command = Command::new(&self.executable);
        for (key, _) in env::vars_os() {
            let text = key.to_string_lossy();
            if (text.starts_with("CODEX_") && text != "CODEX_CA_CERTIFICATE")
                || text.starts_with("OPENAI_")
            {
                command.env_remove(key);
            }
        }
        command
            .env_remove("RUST_LOG")
            .env("CODEX_HOME", home)
            .env("CODEX_INTERNAL_APP_SERVER_REMOTE_CONTROL_DISABLED", "1")
            .current_dir(cwd);
        command
    }
    pub fn helper(&self, home: &Path) -> Command {
        let mut command = self.command(home, home);
        command.args([
            "-c",
            "cli_auth_credentials_store=\"keyring\"",
            "app-server",
            "--stdio",
        ]);
        command
    }
    pub fn coding(&self) -> Command {
        let mut command = self.command(&self.home, &self.cwd);
        command.args([
            "-c",
            "cli_auth_credentials_store=\"ephemeral\"",
            "app-server",
            "--stdio",
        ]);
        command
    }
    pub fn terminal(&self, socket: &Path, resume: Option<&str>) -> Command {
        let mut command = self.command(&self.home, &self.cwd);
        command
            .args(["-c", "cli_auth_credentials_store=\"ephemeral\"", "--remote"])
            .arg(format!("unix://{}", socket.display()));
        if let Some(session) = resume {
            command.args(["resume", "--", session]);
        }
        command
    }
}
fn find_executable(path: &Path) -> Result<PathBuf> {
    use std::os::unix::fs::PermissionsExt;
    let candidates = if path.components().count() > 1 || path.is_absolute() {
        vec![path.to_path_buf()]
    } else {
        env::split_paths(&env::var_os("PATH").unwrap_or_default())
            .map(|dir| dir.join(path))
            .collect()
    };
    for candidate in candidates {
        if candidate
            .metadata()
            .is_ok_and(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
        {
            return candidate
                .canonicalize()
                .map_err(|_| anyhow!("cannot resolve installed Codex executable"));
        }
    }
    bail!("Codex executable not found; install Codex 0.154.0 and set CODUCK_CODEX or PATH")
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn commands_preserve_custom_ca_certificate_override() {
        let codex = Codex {
            executable: "/fake/codex".into(),
            cwd: "/work/project".into(),
            home: "/shared/codex".into(),
        };
        let command = codex.coding();
        assert!(
            !command
                .as_std()
                .get_envs()
                .any(|(key, _)| key == "CODEX_CA_CERTIFICATE")
        );
    }
    #[test]
    fn commands_keep_helper_isolated_and_coding_home_shared() {
        let codex = Codex {
            executable: "/fake/codex".into(),
            cwd: "/work/project".into(),
            home: "/shared/codex".into(),
        };
        for (command, home, cwd, mode) in [
            (
                codex.helper(Path::new("/private/helper")),
                "/private/helper",
                "/private/helper",
                "keyring",
            ),
            (
                codex.coding(),
                "/shared/codex",
                "/work/project",
                "ephemeral",
            ),
            (
                codex.terminal(Path::new("/private/bridge.sock"), Some("session")),
                "/shared/codex",
                "/work/project",
                "ephemeral",
            ),
        ] {
            let command = command.as_std();
            assert_eq!(command.get_current_dir(), Some(Path::new(cwd)));
            let env: std::collections::HashMap<_, _> = command.get_envs().collect();
            assert_eq!(
                env[std::ffi::OsStr::new("CODEX_HOME")],
                Some(std::ffi::OsStr::new(home))
            );
            assert_eq!(
                env[std::ffi::OsStr::new("CODEX_INTERNAL_APP_SERVER_REMOTE_CONTROL_DISABLED")],
                Some(std::ffi::OsStr::new("1"))
            );
            assert_eq!(env[std::ffi::OsStr::new("RUST_LOG")], None);
            let args: Vec<_> = command
                .get_args()
                .map(|arg| arg.to_string_lossy().to_string())
                .collect();
            assert!(args.contains(&format!("cli_auth_credentials_store=\"{mode}\"")));
        }
    }
}
