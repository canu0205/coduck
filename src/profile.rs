use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use std::{
    env,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Identity {
    pub account_id: String,
    pub user_id: String,
    pub email: Option<String>,
    pub plan_type: String,
}
impl Identity {
    pub fn ensure_same_account(&self, other: &Self) -> Result<()> {
        if self.account_id != other.account_id || self.user_id != other.user_id {
            bail!("profile identity changed; logout and log in again explicitly");
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Metadata {
    pub identity: Identity,
    pub last_verified: u64,
}
impl Metadata {
    pub fn verified(identity: Identity) -> Result<Self> {
        Ok(Self {
            identity,
            last_verified: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
        })
    }
}
pub struct ProfileSummary {
    pub name: String,
    pub metadata: Option<Metadata>,
}
pub struct ProfileStore {
    root: PathBuf,
}
pub struct ProfileGuard {
    directory: PathBuf,
    home: PathBuf,
    _lock: File,
}
#[derive(Default, Serialize, Deserialize)]
struct Runtime {
    pending_spawn: bool,
    groups: Vec<u32>,
}

impl ProfileStore {
    pub fn from_env() -> Result<Self> {
        let root = match env::var_os("CODUCK_HOME") {
            Some(value) if !value.is_empty() => PathBuf::from(value),
            Some(_) => bail!("CODUCK_HOME must not be empty"),
            None => home_directory()?.join(".local/state/coduck"),
        };
        Ok(Self::new(env::current_dir()?.join(root)))
    }
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }
    pub fn lock(&self, name: &str, create: bool) -> Result<ProfileGuard> {
        validate_name(name)?;
        private_dir(&self.root, create)?;
        let profiles = self.root.join("profiles");
        private_dir(&profiles, create)?;
        let directory = profiles.join(name);
        private_dir(&directory, create)?;
        let lock = open_private(&directory.join("lock"), true)?;
        lock.try_lock()
            .map_err(|_| anyhow!("profile is in use; close its running Coduck session first"))?;
        let home = directory.join("home");
        private_dir(&home, create)?;
        let guard = ProfileGuard {
            directory,
            home,
            _lock: lock,
        };
        guard.clear_runtime()?;
        Ok(guard)
    }
    pub fn list(&self) -> Result<Vec<ProfileSummary>> {
        if fs::symlink_metadata(&self.root).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound)
        {
            return Ok(Vec::new());
        }
        check_dir(&self.root)?;
        let profiles = self.root.join("profiles");
        if fs::symlink_metadata(&profiles).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound)
        {
            return Ok(Vec::new());
        }
        check_dir(&profiles)?;
        let mut result = Vec::new();
        for entry in fs::read_dir(profiles)? {
            let entry = entry?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| anyhow!("invalid profile name in state directory"))?;
            validate_name(&name)?;
            check_dir(&entry.path())?;
            result.push(ProfileSummary {
                name,
                metadata: read_json(&entry.path().join("metadata.json"))?,
            });
        }
        result.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(result)
    }
}
impl ProfileGuard {
    pub fn home(&self) -> &Path {
        &self.home
    }
    pub fn metadata(&self) -> Result<Option<Metadata>> {
        read_json(&self.directory.join("metadata.json"))
    }
    pub fn save_metadata(&self, metadata: &Metadata) -> Result<()> {
        write_json(&self.directory.join("metadata.json"), metadata)
    }
    pub fn remove_metadata(&self) -> Result<()> {
        remove_private(&self.directory.join("metadata.json"))
    }
    pub fn begin_spawn(&self) -> Result<()> {
        let mut state: Runtime =
            read_json(&self.directory.join("runtime.json"))?.unwrap_or_default();
        if state.pending_spawn {
            bail!("an unrecorded spawn needs manual cleanup before continuing");
        }
        state.pending_spawn = true;
        write_json(&self.directory.join("runtime.json"), &state)
    }
    pub fn cancel_spawn(&self) -> Result<()> {
        let path = self.directory.join("runtime.json");
        let mut state: Runtime =
            read_json(&path)?.ok_or_else(|| anyhow!("no pending spawn to cancel"))?;
        if !state.pending_spawn {
            bail!("no pending spawn to cancel");
        }
        state.pending_spawn = false;
        write_json(&path, &state)
    }
    pub fn register_group(&self, pid: u32) -> Result<()> {
        if pid == 0 || pid > i32::MAX as u32 {
            bail!("invalid child process group");
        }
        let mut state: Runtime =
            read_json(&self.directory.join("runtime.json"))?.unwrap_or_default();
        if !state.pending_spawn {
            bail!("child spawn was not marked before starting");
        }
        state.groups.push(pid);
        state.pending_spawn = false;
        write_json(&self.directory.join("runtime.json"), &state)
    }
    pub fn clear_runtime(&self) -> Result<()> {
        let path = self.directory.join("runtime.json");
        let Some(state): Option<Runtime> = read_json(&path)? else {
            return Ok(());
        };
        if state.pending_spawn {
            bail!(
                "an interrupted spawn has unknown child state; close leftover Codex processes, then manually remove this profile's runtime.json"
            );
        }
        for pid in state.groups {
            if pid == 0 || pid > i32::MAX as u32 {
                bail!("invalid recorded process group; inspect runtime.json manually");
            }
            let result = unsafe { libc::kill(-(pid as i32), 0) };
            if result == 0 || std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH) {
                bail!(
                    "a previous Coduck child may still be running; close the leftover Codex process before retrying"
                );
            }
        }
        remove_private(&path)
    }
}
pub(crate) fn home_directory() -> Result<PathBuf> {
    env::var_os("HOME")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .ok_or_else(|| anyhow!("HOME must be set and nonempty"))
}
fn validate_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > 48
        || !name.as_bytes()[0].is_ascii_lowercase() && !name.as_bytes()[0].is_ascii_digit()
        || !name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        bail!("profile name must match [a-z0-9][a-z0-9-]{{0,47}}");
    }
    Ok(())
}
fn check_dir(path: &Path) -> Result<()> {
    let meta = fs::symlink_metadata(path).context("cannot inspect profile directory")?;
    if !meta.is_dir() || meta.file_type().is_symlink() {
        bail!("profile directory must be a real directory, not a symlink");
    }
    if meta.permissions().mode() & 0o777 != 0o700 {
        bail!("profile directory must have permissions 0700");
    }
    Ok(())
}
fn private_dir(path: &Path, create: bool) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(_) => check_dir(path),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && create => {
            let mut builder = fs::DirBuilder::new();
            builder
                .recursive(true)
                .mode(0o700)
                .create(path)
                .context("cannot create private profile directory")?;
            check_dir(path)
        }
        Err(_) => bail!("profile does not exist; use coduck login NAME first"),
    }
}
fn open_private(path: &Path, create: bool) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(create)
        .create(create)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file() || meta.permissions().mode() & 0o777 != 0o600 {
        bail!("profile file must be regular with permissions 0600");
    }
    Ok(file)
}
fn read_json<T: for<'a> Deserialize<'a>>(path: &Path) -> Result<Option<T>> {
    let file = match open_private(path, false) {
        Ok(file) => file,
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
        {
            return Ok(None);
        }
        Err(error) => return Err(error.context("cannot read private profile file")),
    };
    let mut bytes = Vec::new();
    file.take(65537).read_to_end(&mut bytes)?;
    if bytes.len() > 65536 {
        bail!("profile file exceeds size limit");
    }
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|_| anyhow!("invalid profile metadata or runtime record"))
}
fn write_json(path: &Path, value: &impl Serialize) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("missing profile directory"))?;
    check_dir(parent)?;
    if fs::symlink_metadata(path).is_ok() {
        open_private(path, false)?;
    }
    let mut temp = tempfile::NamedTempFile::new_in(parent)?;
    temp.as_file()
        .set_permissions(fs::Permissions::from_mode(0o600))?;
    serde_json::to_writer(&mut temp, value)?;
    temp.flush()?;
    temp.as_file().sync_all()?;
    temp.persist(path)
        .map_err(|_| anyhow!("cannot save private profile state"))?;
    File::open(parent)?.sync_all()?;
    Ok(())
}
fn remove_private(path: &Path) -> Result<()> {
    match open_private(path, false) {
        Ok(_) => {
            fs::remove_file(path)?;
            Ok(())
        }
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
        {
            Ok(())
        }
        Err(error) => Err(error),
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    #[test]
    fn living_recorded_process_group_blocks_recovery_until_it_exits() {
        use std::{os::unix::process::CommandExt, process::Command};
        let temp = tempfile::tempdir().unwrap();
        let store = ProfileStore::new(temp.path().join("state"));
        let guard = store.lock("test", true).unwrap();
        guard.begin_spawn().unwrap();
        let mut child = Command::new("/bin/sleep")
            .arg("30")
            .process_group(0)
            .spawn()
            .unwrap();
        guard.register_group(child.id()).unwrap();
        drop(guard);
        let blocked = store.lock("test", false).is_err();
        child.kill().unwrap();
        child.wait().unwrap();
        assert!(blocked);
        let guard = store.lock("test", false).unwrap();
        assert!(!guard.directory.join("runtime.json").exists());
    }
    #[test]
    fn failed_spawn_can_be_cancelled_but_interrupted_spawn_blocks_reuse() {
        let temp = tempfile::tempdir().unwrap();
        let store = ProfileStore::new(temp.path().join("state"));
        let guard = store.lock("test", true).unwrap();
        guard.begin_spawn().unwrap();
        guard.cancel_spawn().unwrap();
        guard.clear_runtime().unwrap();
        guard.begin_spawn().unwrap();
        drop(guard);
        assert!(store.lock("test", false).is_err());
    }
    #[test]
    fn private_profiles_lock_and_keep_only_cached_identity() {
        let temp = tempfile::tempdir().unwrap();
        let store = ProfileStore::new(temp.path().join("state"));
        let guard = store.lock("first", true).unwrap();
        assert!(store.lock("first", false).is_err());
        let other = store.lock("second", true).unwrap();
        let metadata = Metadata::verified(Identity {
            account_id: "account".into(),
            user_id: "user".into(),
            email: None,
            plan_type: "plus".into(),
        })
        .unwrap();
        guard.save_metadata(&metadata).unwrap();
        assert_eq!(guard.metadata().unwrap(), Some(metadata));
        assert!(other.metadata().unwrap().is_none());
        assert_eq!(
            fs::metadata(guard.home()).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(guard.directory.join("metadata.json"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        let list = store.list().unwrap();
        assert_eq!(list.len(), 2);
        assert!(list[1].metadata.is_none());
        guard.remove_metadata().unwrap();
        assert!(guard.home().exists());
        symlink(
            other.directory.join("lock"),
            guard.directory.join("metadata.json"),
        )
        .unwrap();
        assert!(guard.metadata().is_err());
    }
    #[test]
    fn rejects_path_traversal_and_symlink_roots() {
        let temp = tempfile::tempdir().unwrap();
        let store = ProfileStore::new(temp.path().join("state"));
        for name in ["", "../escape", "UPPER", "a/b", "-start"] {
            assert!(store.lock(name, true).is_err());
        }
        symlink(temp.path(), temp.path().join("linked")).unwrap();
        assert!(
            ProfileStore::new(temp.path().join("linked"))
                .lock("name", true)
                .is_err()
        );
    }
}
