use crate::{
    auth::{self, Token},
    bridge::{self, AuthRequest},
    codex::Codex,
    profile::{Metadata, ProfileGuard, ProfileStore, RuntimeGuard, SessionGuard},
    rpc::Rpc,
    terminal::Terminal,
};
use anyhow::{Result, anyhow, bail};
use clap::{Parser, Subcommand};
use serde_json::json;
use std::{os::unix::fs::PermissionsExt, process::Stdio, time::Duration};
use tokio::{
    net::UnixListener,
    process::Command,
    signal::unix::{Signal, SignalKind, signal},
    sync::{mpsc, watch},
    task::JoinSet,
    time::{Instant, timeout, timeout_at},
};

#[derive(Parser)]
#[command(version, about = "Run Codex with a named ChatGPT account")]
pub struct Args {
    #[command(subcommand)]
    command: Action,
}
#[derive(Subcommand)]
enum Action {
    /// save a ChatGPT account in this profile's keyring entry.
    Login { name: String },
    /// show cached profile identities without contacting Codex.
    List,
    /// run the official Codex terminal using this profile.
    Run {
        name: String,
        #[arg(long)]
        resume: Option<String>,
    },
    /// remove this profile's local login.
    Logout { name: String },
}

pub async fn execute(args: Args) -> Result<()> {
    let store = ProfileStore::from_env()?;
    let (name, create) = match &args.command {
        Action::List => {
            print!("{}", list_profiles(&store)?);
            return Ok(());
        }
        Action::Login { name } => (name, true),
        Action::Run { name, .. } | Action::Logout { name } => (name, false),
    };
    let mut signals = Signals::new()?;
    let codex = tokio::select! {
        result = Codex::resolve() => result?,
        _ = signals.recv() => bail!("interrupted"),
    };
    if let Action::Run { resume, .. } = &args.command {
        let session = wait_for_profile_lock(|| store.session(name)).await?;
        let result = run(&codex, &session, resume.as_deref(), &mut signals).await;
        let cleared = clear_runtime(session.runtime()).await;
        let thread = result?;
        cleared?;
        if let Some(thread) = thread {
            println!(
                "To continue this session with Coduck, run:\n  coduck run {name} --resume {thread}"
            );
        }
        return Ok(());
    }
    let guard = wait_for_profile_lock(|| store.lock(name, create)).await?;
    let mut helper = match spawn_rpc(codex.helper(guard.home()), guard.runtime()).await {
        Ok(helper) => helper,
        Err(error) => {
            let _ = clear_runtime(guard.runtime()).await;
            return Err(error);
        }
    };
    let result = async {
        tokio::select! {
            result = auth::initialize(&mut helper) => result?,
            _ = signals.recv() => bail!("interrupted"),
        }
        match &args.command {
            Action::Login {..} => login(&codex, &mut helper, &guard, &mut signals).await,
            Action::Logout {..} => {
                tokio::select! {
                    result = logout(&mut helper, &guard) => result?,
                    _ = signals.recv() => bail!("interrupted; retry logout to confirm local credential removal"),
                }
                println!("Removed local login for {name}.");
                Ok(())
            }
            Action::Run {..} | Action::List => unreachable!(),
        }
    }.await;
    let stopped = helper.shutdown().await;
    let cleared = clear_runtime(guard.runtime()).await;
    result.and(stopped).and(cleared)
}
fn list_profiles(store: &ProfileStore) -> Result<String> {
    enum ProfileRow {
        Complete([String; 4]),
        Incomplete { name: String, message: String },
    }

    let profiles = store.list()?;
    if profiles.is_empty() {
        return Ok("No profiles. Use coduck login NAME.\n".into());
    }
    let headers = [
        "PROFILE",
        "CACHED IDENTITY",
        "PLAN",
        "LAST VERIFIED (UNIX SECONDS)",
    ];
    let mut rows = Vec::with_capacity(profiles.len());
    for profile in profiles {
        let name = profile.name;
        match profile.metadata {
            Some(metadata) => rows.push(ProfileRow::Complete([
                name,
                metadata
                    .identity
                    .email
                    .as_deref()
                    .unwrap_or(&metadata.identity.account_id)
                    .to_owned(),
                metadata.identity.plan_type,
                metadata.last_verified.to_string(),
            ])),
            None => rows.push(ProfileRow::Incomplete {
                message: format!("incomplete; use coduck login {name}"),
                name,
            }),
        }
    }
    let widths = headers.map(str::len);
    let widths = rows.iter().fold(widths, |mut widths, row| {
        if let ProfileRow::Complete(row) = row {
            for (index, value) in row.iter().enumerate() {
                widths[index] = widths[index].max(value.len());
            }
        }
        widths
    });
    let mut output = String::new();
    for (index, header) in headers.iter().enumerate() {
        if index + 1 == headers.len() {
            output.push_str(header);
        } else {
            output.push_str(&format!("{header:<width$}", width = widths[index]));
        }
        if index + 1 != headers.len() {
            output.push_str("  ");
        }
    }
    output.push('\n');
    for row in rows {
        match row {
            ProfileRow::Complete(row) => {
                for (index, value) in row.iter().enumerate() {
                    if index + 1 == row.len() {
                        output.push_str(value);
                    } else {
                        output.push_str(&format!("{value:<width$}", width = widths[index]));
                        output.push_str("  ");
                    }
                }
            }
            ProfileRow::Incomplete { name, message } => {
                output.push_str(&format!("{name:<width$}  {message}", width = widths[0]));
            }
        }
        output.push('\n');
    }
    Ok(output)
}
async fn spawn_rpc(command: Command, guard: &RuntimeGuard) -> Result<Rpc> {
    guard.begin_spawn()?;
    let mut rpc = match Rpc::spawn(command) {
        Ok(rpc) => rpc,
        Err(error) => {
            guard.cancel_spawn()?;
            return Err(error);
        }
    };
    if let Err(error) = guard.register_group(
        rpc.pid()
            .ok_or_else(|| anyhow!("missing child process group"))?,
    ) {
        let _ = rpc.shutdown().await;
        return Err(error);
    }
    Ok(rpc)
}
async fn clear_runtime(guard: &RuntimeGuard) -> Result<()> {
    // orphaned wrapper descendants can take a moment to be reaped by the OS.
    for _ in 0..50 {
        if guard.clear_runtime().is_ok() {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    guard.clear_runtime()
}
async fn verify_profile(rpc: &mut Rpc, guard: &ProfileGuard) -> Result<Token> {
    let token = auth::token(rpc, false).await?;
    if let Some(saved) = guard.metadata()? {
        saved.identity.ensure_same_account(&token.identity)?;
    }
    guard.save_metadata(&Metadata::verified(token.identity.clone())?)?;
    Ok(token)
}
async fn restart_helper(helper: &mut Rpc, command: Command, guard: &ProfileGuard) -> Result<()> {
    helper.shutdown().await?;
    *helper = spawn_rpc(command, guard.runtime()).await?;
    auth::initialize(helper).await
}
async fn login(
    codex: &Codex,
    helper: &mut Rpc,
    guard: &ProfileGuard,
    signals: &mut Signals,
) -> Result<()> {
    let signed_in = tokio::select! {
        result = auth::signed_in(helper) => result?,
        _ = signals.recv() => bail!("login interrupted"),
    };
    if !signed_in {
        let pending = tokio::select! {
            result = auth::begin_login(helper) => result?,
            _ = signals.recv() => bail!("login interrupted"),
        };
        println!("Complete login in your browser:\n{}", pending.auth_url);
        let _ = timeout(
            Duration::from_secs(5),
            Command::new("/usr/bin/open")
                .arg(&pending.auth_url)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .kill_on_drop(true)
                .status(),
        )
        .await;
        let completed = tokio::select! {
            result = auth::wait_login(helper, &pending) => result,
            _ = signals.recv() => Err(anyhow!("login interrupted")),
        };
        match completed {
            Ok(auth::LoginOutcome::Ready) => {}
            Ok(auth::LoginOutcome::Unconfirmed) => {
                // the callback can fail after credentials were saved in Keychain.
                // reload once, then require the same verification as a normal login.
                tokio::select! {
                    result = restart_helper(helper, codex.helper(guard.home()), guard) => result?,
                    _ = signals.recv() => bail!("login verification interrupted; retry coduck login"),
                }
            }
            Err(error) => {
                let _ = timeout(Duration::from_secs(3), auth::cancel_login(helper, &pending)).await;
                return Err(error);
            }
        }
    }
    let token = tokio::select! {
        result = verify_profile(helper, guard) => result?,
        _ = signals.recv() => bail!("login verification interrupted; retry coduck login"),
    };
    println!(
        "Verified {} ({})",
        token
            .identity
            .email
            .as_deref()
            .unwrap_or(&token.identity.account_id),
        token.identity.plan_type
    );
    Ok(())
}
async fn logout(helper: &mut Rpc, guard: &ProfileGuard) -> Result<()> {
    auth::logout(helper).await?;
    guard.remove_metadata()
}
// wait asynchronously so concurrent panes can finish a short credential operation.
async fn wait_for_profile_lock<T>(mut acquire: impl FnMut() -> Result<T>) -> Result<T> {
    timeout(Duration::from_secs(7), async {
        loop {
            match acquire() {
                Ok(guard) => return Ok(guard),
                Err(error) if matches!(error.downcast_ref::<std::fs::TryLockError>(), Some(std::fs::TryLockError::WouldBlock)) => {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                Err(error) => return Err(error),
            }
        }
    }).await.map_err(|_| anyhow!("profile credentials are busy; retry after the other operation finishes (older Coduck sessions must be closed once)"))?
}

struct ManagedAuth {
    rpc: Rpc,
    guard: ProfileGuard,
}
impl ManagedAuth {
    async fn open(codex: &Codex, session: &SessionGuard, logout: bool) -> Result<Self> {
        let guard = wait_for_profile_lock(|| {
            if logout {
                session.logout()
            } else {
                session.auth()
            }
        })
        .await?;
        let rpc = spawn_rpc(codex.helper(guard.home()), guard.runtime()).await?;
        Ok(Self { rpc, guard })
    }
    async fn finish<T>(mut self, result: Result<T>) -> Result<T> {
        let stopped = self.rpc.shutdown().await;
        let cleared = clear_runtime(self.guard.runtime()).await;
        let value = result?;
        stopped?;
        cleared?;
        Ok(value)
    }
}

async fn run(
    codex: &Codex,
    guard: &SessionGuard,
    resume: Option<&str>,
    signals: &mut Signals,
) -> Result<Option<String>> {
    let mut auth = ManagedAuth::open(codex, guard, false).await?;
    let verified = async {
        auth::initialize(&mut auth.rpc).await?;
        verify_profile(&mut auth.rpc, &auth.guard).await
    }
    .await;
    let token = auth.finish(verified).await?;
    let directory = tempfile::Builder::new()
        .prefix("coduck-")
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir_in("/tmp")?;
    let socket = directory.path().join("ui.sock");
    let listener = UnixListener::bind(&socket)?;
    async {
        let mut terminal =
            Terminal::spawn(codex.terminal(&socket, resume), guard.runtime()).await?;
        let result = run_terminal(listener, &mut terminal, codex, guard, token, signals).await;
        let stopped = if result.is_ok() {
            terminal.shutdown().await
        } else {
            terminal.terminate().await
        };
        let session = result?;
        stopped?;
        Ok(session)
    }
    .await
}
async fn run_terminal(
    listener: UnixListener,
    terminal: &mut Terminal,
    codex: &Codex,
    guard: &SessionGuard,
    token: Token,
    signals: &mut Signals,
) -> Result<Option<String>> {
    let (sender, receiver) = mpsc::channel(8);
    let (stop, stopped) = watch::channel(false);
    let (session, last_session) = watch::channel(None);
    let connections = serve_connections(
        listener,
        || codex.coding(),
        guard.runtime(),
        sender,
        stopped.clone(),
        session,
    );
    let authentication = serve_auth(codex, guard, token, receiver, stopped);
    tokio::pin!(connections, authentication);
    let mut connections_done = false;
    let mut authentication_done = false;
    let result = loop {
        tokio::select! {
            result = &mut connections => { connections_done = true; break result; }
            result = &mut authentication => { authentication_done = true; break result; },
            result = terminal.wait() => {
                break result.and_then(|success| {
                    if success { Ok(()) } else { Err(anyhow!("Codex terminal exited unsuccessfully")) }
                });
            }
            signal = signals.recv() => {
                if signal == libc::SIGINT {
                    if let Err(error) = terminal.interrupt() { break Err(error); }
                } else { break Err(anyhow!("interrupted")); }
            }
        }
    };
    let _ = stop.send(true);
    let stopped = if connections_done {
        Ok(())
    } else {
        connections.await
    };
    // finish any in-flight helper request and reap it before releasing its credential lock.
    let authenticated = if authentication_done {
        Ok(())
    } else {
        authentication.await
    };
    result.and(stopped).and(authenticated)?;
    Ok(last_session.borrow().clone())
}

async fn serve_connections(
    listener: UnixListener,
    coding_command: impl Fn() -> Command,
    guard: &RuntimeGuard,
    auth: mpsc::Sender<AuthRequest>,
    mut stopped: watch::Receiver<bool>,
    session: watch::Sender<Option<String>>,
) -> Result<()> {
    let mut clients = JoinSet::new();
    let (cancel, cancelled) = watch::channel(false);
    let connected_deadline = tokio::time::sleep(Duration::from_secs(30));
    tokio::pin!(connected_deadline);
    let mut connected = false;
    let result = loop {
        tokio::select! {
            _ = stopped.changed() => break Ok(()),
            _ = &mut connected_deadline, if !connected => break Err(anyhow!("Codex terminal did not connect")),
            accepted = listener.accept(), if clients.len() < 4 => {
                let stream = match accepted { Ok((stream, _)) => stream, Err(error) => break Err(error.into()) };
                let mut coding = match spawn_rpc(coding_command(), guard).await {
                    Ok(coding) => coding,
                    Err(error) => break Err(error),
                };
                connected = true;
                let auth = auth.clone();
                let session = session.clone();
                let mut cancelled = cancelled.clone();
                clients.spawn(async move {
                    let result = tokio::select! {
                        result = async {
                            let login = bridge::login_params(&auth).await?;
                            bridge::run(stream, &mut coding, login, auth, session).await
                        } => result,
                        _ = cancelled.changed() => Ok(bridge::Exit::Disconnected),
                    };
                    let stopped = coding.shutdown().await;
                    result.and_then(|exit| stopped.map(|_| exit))
                });
            }
            result = clients.join_next(), if !clients.is_empty() => {
                match result {
                    Some(Ok(Ok(bridge::Exit::Disconnected))) => {},
                    Some(Ok(Ok(bridge::Exit::LoggedOut))) => break Ok(()),
                    Some(Ok(Err(error))) => break Err(error),
                    Some(Err(_)) => break Err(anyhow!("coding connection task failed")),
                    None => unreachable!(),
                }
            }
        }
    };
    drop(listener);
    let _ = cancel.send(true);
    let mut cleanup = Ok(());
    while let Some(client) = clients.join_next().await {
        let stopped = client.unwrap_or_else(|_| Err(anyhow!("coding connection task failed")));
        cleanup = cleanup.and(stopped.map(|_| ()));
    }
    result.and(cleanup)
}
async fn serve_auth(
    codex: &Codex,
    session: &SessionGuard,
    mut token: Token,
    mut requests: mpsc::Receiver<AuthRequest>,
    mut stopped: watch::Receiver<bool>,
) -> Result<()> {
    let saved = token.identity.clone();
    loop {
        let request = tokio::select! {
            _ = stopped.changed() => return Ok(()),
            request = requests.recv() => match request { Some(request) => request, None => return Ok(()) },
        };
        let logging_out = matches!(&request, AuthRequest::Logout { .. });
        let deadline = Instant::now() + Duration::from_secs(7);
        // leave one second before the bridge deadline; keep the lock through cleanup.
        let opened = timeout_at(deadline, ManagedAuth::open(codex, session, logging_out))
            .await
            .map_err(|_| anyhow!("profile authentication timed out"))
            .and_then(|result| result);
        let mut managed = None;
        let result = match opened {
            Err(error) => Err(error),
            Ok(mut auth) => {
                let result = timeout_at(deadline, async {
                    auth::initialize(&mut auth.rpc).await?;
                    match &request {
                        AuthRequest::Login { .. } => {
                            let next = verify_profile(&mut auth.rpc, &auth.guard).await?;
                            saved.ensure_same_account(&next.identity)?;
                            token = next;
                            Ok(token.login_params())
                        }
                        AuthRequest::Refresh { params, .. } => {
                            let next = auth::refresh(&mut auth.rpc, &saved, &token, params).await?;
                            auth.guard
                                .save_metadata(&Metadata::verified(next.identity.clone())?)?;
                            token = next;
                            Ok(token.refresh_result())
                        }
                        AuthRequest::Logout { .. } => {
                            logout(&mut auth.rpc, &auth.guard).await.map(|_| json!({}))
                        }
                    }
                })
                .await
                .map_err(|_| anyhow!("profile authentication timed out"))
                .and_then(|result| result);
                managed = Some(auth);
                result
            }
        };
        let logged_out = logging_out && result.is_ok();
        let reply = match request {
            AuthRequest::Login { reply }
            | AuthRequest::Refresh { reply, .. }
            | AuthRequest::Logout { reply } => reply,
        };
        let _ = reply.send(result);
        if let Some(auth) = managed {
            auth.finish(Ok(())).await?;
        }
        if logged_out {
            // the bridge delivers the logout response, then asks all local clients to stop.
            if !*stopped.borrow() {
                let _ = stopped.changed().await;
            }
            return Ok(());
        }
    }
}
struct Signals {
    interrupt: Signal,
    terminate: Signal,
    hangup: Signal,
    quit: Signal,
}
impl Signals {
    fn new() -> Result<Self> {
        Ok(Self {
            interrupt: signal(SignalKind::interrupt())?,
            terminate: signal(SignalKind::terminate())?,
            hangup: signal(SignalKind::hangup())?,
            quit: signal(SignalKind::quit())?,
        })
    }
    async fn recv(&mut self) -> i32 {
        tokio::select! {
            _ = self.interrupt.recv() => libc::SIGINT,
            _ = self.terminate.recv() => libc::SIGTERM,
            _ = self.hangup.recv() => libc::SIGHUP,
            _ = self.quit.recv() => libc::SIGQUIT,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::{Identity, Metadata};
    #[tokio::test]
    async fn picker_connections_authenticate_independently_and_close_without_stopping_main() {
        check_picker_connections(false).await;
    }

    #[tokio::test]
    async fn picker_logout_replies_then_stops_all_authenticated_connections() {
        check_picker_connections(true).await;
    }

    async fn check_picker_connections(logout: bool) {
        use futures_util::{SinkExt, StreamExt};
        use serde_json::Value;
        use tokio::net::UnixStream;
        use tokio_tungstenite::{WebSocketStream, tungstenite::Message};

        async fn request(ui: &mut WebSocketStream<UnixStream>, frame: Value) -> Value {
            ui.send(Message::Text(frame.to_string().into()))
                .await
                .unwrap();
            serde_json::from_str(ui.next().await.unwrap().unwrap().to_text().unwrap()).unwrap()
        }
        async fn connect(socket: &std::path::Path) -> WebSocketStream<UnixStream> {
            let stream = UnixStream::connect(socket).await.unwrap();
            let (mut ui, _) = tokio_tungstenite::client_async("ws://localhost/", stream)
                .await
                .unwrap();
            let response = request(&mut ui, json!({"id":1,"method":"initialize","params":{"clientInfo":{"name":"test-ui","version":"1"}}})).await;
            assert_eq!(response["result"]["userAgent"], "test");
            assert!(!response.to_string().contains("private-token"));
            ui.send(Message::Text(
                json!({"method":"initialized"}).to_string().into(),
            ))
            .await
            .unwrap();
            ui
        }
        let temp = tempfile::tempdir_in("/tmp").unwrap();
        let store = ProfileStore::new(temp.path().join("state"));
        let guard = store.lock("personal", true).unwrap();
        let socket = temp.path().join("ui.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let (auth, mut requests) = mpsc::channel(8);
        let (stop, stopped) = watch::channel(false);
        let host = tokio::spawn(async move {
            let mut logins = 0;
            while let Some(request) = requests.recv().await {
                match request {
                    AuthRequest::Login { reply } => {
                        logins += 1;
                        reply.send(Ok(json!({"type":"chatgptAuthTokens","accessToken":"private-token","chatgptAccountId":"account"}))).unwrap();
                    }
                    AuthRequest::Logout { reply } => {
                        reply.send(Ok(json!({}))).unwrap();
                        break;
                    }
                    _ => panic!("unexpected authentication request"),
                }
            }
            logins
        });
        let connections = tokio::spawn(async move {
            let result = serve_connections(listener, || {
                let mut command = Command::new("/bin/sh");
                command.args(["-c", r#"
                    read -r initialize
                    printf '%s\n' '{"id":"coduck-1","result":{"userAgent":"test"}}'
                    read -r initialized
                    read -r config
                    printf '%s\n' '{"id":"coduck-2","result":{"config":{"cli_auth_credentials_store":"ephemeral","chatgpt_base_url":"https://chatgpt.com/backend-api/","model_providers":{}}}}'
                    read -r login
                    case "$login" in *private-token*) ;; *) exit 1;; esac
                    printf '%s\n' '{"id":"coduck-3","result":{"type":"chatgptAuthTokens"}}'
                    read -r request
                    printf '{"id":"coduck-4","result":{"server":%s}}\n' "$$"
                    read -r request
                    printf '{"id":"coduck-5","result":{"server":%s}}\n' "$$"
                    cat >/dev/null
                "#]);
                command
            }, guard.runtime(), auth, stopped, watch::channel(None).0).await;
            clear_runtime(guard.runtime()).await.unwrap();
            result
        });
        let mut main = connect(&socket).await;
        let mut picker = connect(&socket).await;
        let first = request(
            &mut main,
            json!({"id":7,"method":"thread/list","params":{}}),
        )
        .await;
        let second = request(
            &mut picker,
            json!({"id":7,"method":"thread/list","params":{}}),
        )
        .await;
        assert_eq!(first["id"], 7);
        assert_eq!(second["id"], 7);
        assert_ne!(first["result"]["server"], second["result"]["server"]);
        assert!(store.lock("personal", false).is_err());
        if logout {
            let response = request(
                &mut picker,
                json!({"id":8,"method":"account/logout","params":{}}),
            )
            .await;
            assert_eq!(response, json!({"id":8,"result":{}}));
        } else {
            picker.close(None).await.unwrap();
            let after = request(
                &mut main,
                json!({"id":8,"method":"thread/list","params":{}}),
            )
            .await;
            assert_eq!(after["result"], first["result"]);
            assert!(store.lock("personal", false).is_err());
            main.close(None).await.unwrap();
            let mut reopened = connect(&socket).await;
            request(
                &mut reopened,
                json!({"id":9,"method":"thread/list","params":{}}),
            )
            .await;
            stop.send(true).unwrap();
        }
        timeout(Duration::from_secs(10), connections)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(host.await.unwrap(), if logout { 2 } else { 3 });
        assert!(store.lock("personal", false).is_ok());
        for pid in [
            first["result"]["server"].as_i64().unwrap(),
            second["result"]["server"].as_i64().unwrap(),
        ] {
            assert_eq!(unsafe { libc::kill(pid as i32, 0) }, -1);
        }
    }

    #[tokio::test]
    async fn login_recovery_reaps_old_helper_and_keeps_profile_locked() {
        let temp = tempfile::tempdir().unwrap();
        let store = ProfileStore::new(temp.path().join("state"));
        let guard = store.lock("personal", true).unwrap();
        let mut old = Command::new("/bin/sleep");
        old.arg("60");
        let mut helper = spawn_rpc(old, guard.runtime()).await.unwrap();
        let old_pid = helper.pid().unwrap();
        let mut replacement = Command::new("/bin/sh");
        replacement.args(["-c", r#"
            read -r initialize
            printf '%s\n' '{"id":"coduck-1","result":{}}'
            read -r initialized
            read -r config
            printf '%s\n' '{"id":"coduck-2","result":{"config":{"cli_auth_credentials_store":"keyring","chatgpt_base_url":"https://chatgpt.com/backend-api/"}}}'
            cat >/dev/null
        "#]);
        restart_helper(&mut helper, replacement, &guard)
            .await
            .unwrap();
        assert_ne!(helper.pid(), Some(old_pid));
        assert_eq!(unsafe { libc::kill(old_pid as i32, 0) }, -1);
        assert!(store.lock("personal", false).is_err());
        helper.shutdown().await.unwrap();
        clear_runtime(guard.runtime()).await.unwrap();
        assert!(guard.metadata().unwrap().is_none());
    }
    #[test]
    fn offline_list_reports_cached_identity_and_incomplete_profiles() {
        let temp = tempfile::tempdir().unwrap();
        let store = ProfileStore::new(temp.path().join("profiles"));
        let guard = store.lock("personal", true).unwrap();
        guard
            .save_metadata(&Metadata {
                identity: Identity {
                    account_id: "account".into(),
                    user_id: "user".into(),
                    email: Some("me@example.invalid".into()),
                    plan_type: "plus".into(),
                },
                last_verified: 123,
            })
            .unwrap();
        let work = store.lock("work", true).unwrap();
        work.save_metadata(&Metadata {
            identity: Identity {
                account_id: "work".into(),
                user_id: "user".into(),
                email: Some("work@example.invalid".into()),
                plan_type: "self_serve_business_prolite".into(),
            },
            last_verified: 456,
        })
        .unwrap();
        let _other = store.lock("unfinished", true).unwrap();
        let output = list_profiles(&store).unwrap();
        assert_eq!(
            output,
            "PROFILE   CACHED IDENTITY       PLAN                         LAST VERIFIED (UNIX SECONDS)\n\
             personal  me@example.invalid    plus                         123\n\
             unfinished  incomplete; use coduck login unfinished\n\
             work      work@example.invalid  self_serve_business_prolite  456\n"
        );
    }
    #[test]
    fn command_line_requires_explicit_profile_and_resume_id() {
        assert!(Args::try_parse_from(["coduck", "run"]).is_err());
        assert!(Args::try_parse_from(["coduck", "run", "personal", "--resume"]).is_err());
        assert!(matches!(
            Args::try_parse_from(["coduck", "run", "personal", "--resume", "thread-id"])
                .unwrap()
                .command,
            Action::Run {
                resume: Some(_),
                ..
            }
        ));
    }
    #[tokio::test]
    async fn helper_identity_is_verified_before_cached_identity_changes() {
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
        use serde_json::{Value, json};
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        let temp = tempfile::tempdir().unwrap();
        let store = ProfileStore::new(temp.path().join("state"));
        let guard = store.lock("personal", true).unwrap();
        let original = Metadata {
            identity: Identity {
                account_id: "account".into(),
                user_id: "user".into(),
                email: Some("me@example.invalid".into()),
                plan_type: "plus".into(),
            },
            last_verified: 123,
        };
        guard.save_metadata(&original).unwrap();
        let (client, server) = tokio::io::duplex(16384);
        let mut rpc = crate::rpc::Rpc::test_connection(client);
        let peer = tokio::spawn(async move {
            let (read, mut write) = tokio::io::split(server);
            let mut lines = BufReader::new(read).lines();
            for account in ["other", "account"] {
                let request: Value =
                    serde_json::from_str(&lines.next_line().await.unwrap().unwrap()).unwrap();
                let token = format!("e30.{}.signature", URL_SAFE_NO_PAD.encode(serde_json::to_vec(&json!({"exp":4102444800u64,"email":"me@example.invalid","https://api.openai.com/auth":{"chatgpt_account_id":account,"chatgpt_user_id":"user","chatgpt_plan_type":"pro"}})).unwrap()));
                write.write_all(format!("{}\n",json!({"id":request["id"],"result":{"authMethod":"chatgpt","authToken":token}})).as_bytes()).await.unwrap();
            }
        });
        assert!(verify_profile(&mut rpc, &guard).await.is_err());
        assert_eq!(guard.metadata().unwrap(), Some(original));
        verify_profile(&mut rpc, &guard).await.unwrap();
        assert_eq!(guard.metadata().unwrap().unwrap().identity.plan_type, "pro");
        peer.await.unwrap();
    }
}
