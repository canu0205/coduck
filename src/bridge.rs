use std::{
    collections::{HashMap, HashSet},
    time::Duration,
};

use anyhow::{Result, anyhow, bail};
use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use tokio::{
    net::UnixStream,
    sync::{mpsc, oneshot, watch},
    time::timeout,
};
use tokio_tungstenite::{
    WebSocketStream,
    tungstenite::{Message, protocol::WebSocketConfig},
};

use crate::rpc::{MAX_FRAME, MAX_PENDING, RPC_TIMEOUT, Rpc};

type Socket = WebSocketStream<UnixStream>;

pub enum AuthRequest {
    Login {
        reply: oneshot::Sender<Result<Value>>,
    },
    Refresh {
        params: Value,
        reply: oneshot::Sender<Result<Value>>,
    },
    Logout {
        reply: oneshot::Sender<Result<Value>>,
    },
}

pub async fn login_params(auth: &mpsc::Sender<AuthRequest>) -> Result<Value> {
    let (reply, receiver) = oneshot::channel();
    host_request(auth, AuthRequest::Login { reply }, receiver).await
}

#[derive(Debug, PartialEq, Eq)]
pub enum Exit {
    Disconnected,
    LoggedOut,
}

pub async fn run(
    stream: UnixStream,
    coding: &mut Rpc,
    initial_login: Value,
    auth: mpsc::Sender<AuthRequest>,
    session: watch::Sender<Option<String>>,
) -> Result<Exit> {
    let config = WebSocketConfig::default()
        .max_message_size(Some(MAX_FRAME))
        .max_frame_size(Some(MAX_FRAME))
        .max_write_buffer_size(MAX_FRAME * 2);
    let mut socket = timeout(
        RPC_TIMEOUT,
        tokio_tungstenite::accept_async_with_config(stream, Some(config)),
    )
    .await
    .map_err(|_| anyhow!("UI handshake timed out"))?
    .map_err(|_| anyhow!("UI handshake failed"))?;
    let initialize = timeout(RPC_TIMEOUT, read_ui(&mut socket))
        .await
        .map_err(|_| anyhow!("UI initialization timed out"))??
        .ok_or_else(|| anyhow!("UI disconnected before initialization"))?;
    if initialize["method"] != "initialize" {
        bail!("expected UI initialize request");
    }
    let initialize_id = request_id(&initialize)?;
    let startup = initialize_coding(coding, initialize["params"].clone(), initial_login).await;
    let result = match startup {
        Ok(result) => result,
        Err(_) => {
            write_ui(
                &mut socket,
                rpc_error(initialize_id, "coding session initialization failed"),
            )
            .await?;
            bail!("coding session initialization failed");
        }
    };
    write_ui(&mut socket, json!({"id":initialize_id,"result":result})).await?;
    let initialized = timeout(RPC_TIMEOUT, read_ui(&mut socket))
        .await
        .map_err(|_| anyhow!("UI initialization timed out"))??
        .ok_or_else(|| anyhow!("UI disconnected before initialized"))?;
    if initialized["method"] != "initialized" || initialized.get("id").is_some() {
        bail!("expected UI initialized notification");
    }

    let mut client_requests: HashMap<String, (Value, bool)> = HashMap::new();
    let mut server_requests: HashSet<String> = HashSet::new();
    loop {
        tokio::select! {
            frame = read_ui(&mut socket) => {
                let Some(mut frame) = frame? else { return Ok(Exit::Disconnected); };
                if let Some(method) = frame.get("method").and_then(Value::as_str).map(str::to_owned) {
                    if matches!(method.as_str(), "account/login/start" | "account/login/cancel" | "account/bedrock/setup" | "account/bedrock/discover" | "loginAccount" | "getAuthStatus" | "account/chatgptAuthTokens/refresh" | "initialize") {
                        if frame.get("id").is_some() {
                            let id = request_id(&frame)?;
                            write_ui(&mut socket, rpc_error(id, "authentication is managed by coduck; use coduck login NAME")).await?;
                        }
                        continue;
                    }
                    if changes_auth_routing(&method, &frame["params"]) {
                        if frame.get("id").is_some() {
                            let id = request_id(&frame)?;
                            write_ui(&mut socket, rpc_error(id, "configure authentication and providers outside coduck")).await?;
                        }
                        continue;
                    }
                    if matches!(method.as_str(), "thread/start" | "thread/resume" | "thread/fork")
                        && !thread_config_supported(coding, &auth, &method, &frame["params"]).await? {
                            let id = request_id(&frame)?;
                            write_ui(&mut socket, rpc_error(id, "thread or configuration unavailable or unsupported")).await?;
                            continue;
                    }
                    if method == "account/logout" {
                        let id = request_id(&frame)?;
                        let (reply, receiver) = oneshot::channel();
                        let result = host_request(&auth, AuthRequest::Logout { reply }, receiver).await;
                        let failed = result.is_err();
                        write_ui(&mut socket, auth_response(id, result)).await?;
                        if failed { bail!("host logout failed"); }
                        return Ok(Exit::LoggedOut);
                    }
                    if frame.get("id").is_some() {
                        let original_id = request_id(&frame)?;
                        if client_requests.values().any(|(id, _)| id == &original_id) { bail!("duplicate UI request ID"); }
                        if client_requests.len() >= MAX_PENDING { bail!("too many pending UI requests"); }
                        let upstream_id = coding.next_id();
                        client_requests.insert(id_key(&upstream_id), (original_id, matches!(method.as_str(), "thread/start" | "thread/resume" | "thread/fork")));
                        frame["id"] = upstream_id;
                    }
                    coding.send(frame).await?;
                } else {
                    let id = request_id(&frame)?;
                    if server_requests.remove(&id_key(&id)) {
                        coding.send(frame).await?;
                    }
                }
            }
            frame = coding.recv() => {
                let mut frame = frame?;
                if let Some(method) = frame.get("method").and_then(Value::as_str) {
                    if method == "account/chatgptAuthTokens/refresh" {
                        refresh_tokens(coding, &auth, frame).await?;
                        continue;
                    }
                    if frame.get("id").is_some() {
                        let id = request_id(&frame)?;
                        if server_requests.len() >= MAX_PENDING { bail!("too many pending app-server requests"); }
                        if !server_requests.insert(id_key(&id)) { bail!("duplicate app-server request ID"); }
                    }
                    if method == "serverRequest/resolved" {
                        server_requests.remove(&id_key(&frame["params"]["requestId"]));
                    }
                    write_ui(&mut socket, frame).await?;
                } else {
                    let id = request_id(&frame)?;
                    let (original_id, selects_thread) = client_requests.remove(&id_key(&id)).ok_or_else(|| anyhow!("unknown app-server response ID"))?;
                    // hidden title requests also create threads, but cannot be resumed.
                    if selects_thread && frame.get("error").is_none()
                        && frame["result"]["thread"]["ephemeral"].as_bool() == Some(false)
                        && let Some(id) = frame["result"]["thread"]["id"].as_str().filter(|id| {
                            !id.is_empty() && id.len() <= 128 && id.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
                        }) {
                            session.send_replace(Some(id.to_owned()));
                        }
                    frame["id"] = original_id;
                    write_ui(&mut socket, frame).await?;
                }
            }
        }
    }
}

async fn thread_config_supported(
    coding: &mut Rpc,
    auth: &mpsc::Sender<AuthRequest>,
    method: &str,
    params: &Value,
) -> Result<bool> {
    let stored;
    let cwd = if matches!(method, "thread/resume" | "thread/fork") {
        if params["path"].as_str().is_some_and(|path| !path.is_empty())
            || !params["history"].is_null()
        {
            return Ok(false);
        }
        let Some(thread_id) = params["threadId"].as_str() else {
            return Ok(false);
        };
        stored = match private_request(
            coding,
            auth,
            "thread/read",
            json!({"threadId":thread_id,"includeTurns":false}),
        )
        .await?
        {
            Some(value) => value,
            None => return Ok(false),
        };
        if stored["thread"]["modelProvider"] != "openai" {
            return Ok(false);
        }
        params["cwd"]
            .as_str()
            .or_else(|| stored["thread"]["cwd"].as_str())
    } else {
        params["cwd"].as_str()
    };
    let Some(cwd) = cwd else {
        return Ok(method == "thread/start");
    };
    let Some(config) = private_request(
        coding,
        auth,
        "config/read",
        json!({"includeLayers":false,"cwd":cwd}),
    )
    .await?
    else {
        return Ok(false);
    };
    Ok(validate_config(&config["config"]).is_ok())
}

async fn private_request(
    coding: &mut Rpc,
    auth: &mpsc::Sender<AuthRequest>,
    method: &str,
    params: Value,
) -> Result<Option<Value>> {
    let id = coding.next_id();
    coding
        .send(json!({"id":id,"method":method,"params":params}))
        .await?;
    timeout(RPC_TIMEOUT, async {
        loop {
            let frame = coding.recv_live().await?;
            if frame["method"] == "account/chatgptAuthTokens/refresh" {
                refresh_tokens(coding, auth, frame).await?;
            } else if frame.get("method").is_none() && frame.get("id") == Some(&id) {
                if let Some(error) = frame.get("error") {
                    if frame.get("result").is_some()
                        || !error["code"].is_i64()
                        || !error["message"].is_string()
                    {
                        bail!("invalid private app-server error");
                    }
                    return Ok(None);
                }
                return frame
                    .get("result")
                    .cloned()
                    .map(Some)
                    .ok_or_else(|| anyhow!("invalid private app-server response"));
            } else {
                coding.defer(frame)?;
            }
        }
    })
    .await
    .map_err(|_| anyhow!("private app-server request timed out"))?
}

async fn refresh_tokens(
    coding: &mut Rpc,
    auth: &mpsc::Sender<AuthRequest>,
    frame: Value,
) -> Result<()> {
    let id = request_id(&frame)?;
    let (reply, receiver) = oneshot::channel();
    let result = host_request(
        auth,
        AuthRequest::Refresh {
            params: frame["params"].clone(),
            reply,
        },
        receiver,
    )
    .await;
    let failed = result.is_err();
    coding.send(auth_response(id, result)).await?;
    if failed {
        bail!("host token refresh failed");
    }
    Ok(())
}

fn changes_auth_routing(method: &str, params: &Value) -> bool {
    match method {
        "config/value/write" => sensitive_key(params["keyPath"].as_str().unwrap_or("")),
        "config/batchWrite" => params["edits"].as_array().is_some_and(|edits| {
            edits
                .iter()
                .any(|edit| sensitive_key(edit["keyPath"].as_str().unwrap_or("")))
        }),
        "thread/start" | "thread/resume" | "thread/fork" => {
            (!params["modelProvider"].is_null() && params["modelProvider"] != "openai")
                || params["config"]
                    .as_object()
                    .is_some_and(|config| config.keys().any(|key| sensitive_key(key)))
        }
        _ => false,
    }
}

fn sensitive_key(key: &str) -> bool {
    matches!(
        key.split('.').next().unwrap_or(""),
        "profile"
            | "profiles"
            | "model_provider"
            | "model_providers"
            | "chatgpt_base_url"
            | "cli_auth_credentials_store"
            | "forced_login_method"
            | "forced_chatgpt_workspace_id"
    )
}

async fn initialize_coding(
    coding: &mut Rpc,
    mut params: Value,
    initial_login: Value,
) -> Result<Value> {
    if !params.is_object() {
        bail!("invalid UI initialize params");
    }
    if params.get("capabilities").is_none_or(Value::is_null) {
        params["capabilities"] = json!({});
    }
    if !params["capabilities"].is_object() {
        bail!("invalid UI capabilities");
    }
    params["capabilities"]["experimentalApi"] = json!(true);
    let initialized = coding.initialize(params).await?;
    let cwd = std::env::current_dir().map_err(|_| anyhow!("cannot resolve working directory"))?;
    let config = coding
        .request("config/read", json!({"includeLayers":false,"cwd":cwd}))
        .await?;
    validate_config(&config["config"])?;
    let login = coding.request("account/login/start", initial_login).await?;
    if login["type"] != "chatgptAuthTokens" {
        bail!("unexpected coding authentication mode");
    }
    Ok(initialized)
}

fn validate_config(config: &Value) -> Result<()> {
    if !config.is_object() {
        bail!("missing effective coding configuration");
    }
    if !config["model_provider"].is_null() && config["model_provider"] != "openai" {
        bail!("unsupported model_provider");
    }
    if config["cli_auth_credentials_store"] != "ephemeral" {
        bail!("coding credential storage must be ephemeral");
    }
    if config["model_providers"].get("openai").is_some() {
        bail!("unsupported model_providers.openai override");
    }
    if !matches!(
        config["chatgpt_base_url"].as_str(),
        Some("https://chatgpt.com/backend-api" | "https://chatgpt.com/backend-api/")
    ) {
        bail!("unsupported chatgpt_base_url");
    }
    Ok(())
}

async fn host_request(
    auth: &mpsc::Sender<AuthRequest>,
    request: AuthRequest,
    receiver: oneshot::Receiver<Result<Value>>,
) -> Result<Value> {
    let deadline = match &request {
        AuthRequest::Login { .. } | AuthRequest::Refresh { .. } => Duration::from_secs(8),
        AuthRequest::Logout { .. } => RPC_TIMEOUT,
    };
    timeout(deadline, async {
        auth.send(request)
            .await
            .map_err(|_| anyhow!("authentication host disconnected"))?;
        receiver
            .await
            .map_err(|_| anyhow!("authentication host disconnected"))?
    })
    .await
    .map_err(|_| anyhow!("authentication host timed out"))?
}

fn auth_response(id: Value, result: Result<Value>) -> Value {
    match result {
        Ok(result) => json!({"id":id,"result":result}),
        Err(_) => rpc_error(id, "host authentication request failed"),
    }
}

fn rpc_error(id: Value, message: &str) -> Value {
    json!({"id":id,"error":{"code":-32000,"message":message}})
}

fn request_id(frame: &Value) -> Result<Value> {
    let id = frame
        .get("id")
        .ok_or_else(|| anyhow!("missing RPC request ID"))?;
    if !id.is_string() && !id.is_i64() && !id.is_u64() {
        bail!("invalid RPC request ID");
    }
    Ok(id.clone())
}

fn id_key(id: &Value) -> String {
    id.to_string()
}

async fn read_ui(socket: &mut Socket) -> Result<Option<Value>> {
    loop {
        match socket.next().await {
            Some(Ok(Message::Text(text))) => {
                let value: Value =
                    serde_json::from_str(&text).map_err(|_| anyhow!("invalid UI JSON"))?;
                if !value.is_object() {
                    bail!("invalid UI RPC message");
                }
                return Ok(Some(value));
            }
            Some(Ok(Message::Close(_))) | None => return Ok(None),
            Some(Ok(Message::Ping(_))) | Some(Ok(Message::Pong(_))) => {}
            _ => bail!("UI WebSocket read failed"),
        }
    }
}

async fn write_ui(socket: &mut Socket, value: Value) -> Result<()> {
    let text = value.to_string();
    if text.len() > MAX_FRAME {
        bail!("UI message exceeds size limit");
    }
    timeout(RPC_TIMEOUT, socket.send(Message::Text(text.into())))
        .await
        .map_err(|_| anyhow!("UI WebSocket write timed out"))?
        .map_err(|_| anyhow!("UI WebSocket write failed"))
}
#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::{SinkExt, StreamExt};
    use serde_json::json;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, DuplexStream, ReadHalf, WriteHalf};
    use tokio::time::Instant;
    use tokio_tungstenite::{WebSocketStream, tungstenite::Message};

    type Peer = (
        tokio::io::Lines<BufReader<ReadHalf<DuplexStream>>>,
        WriteHalf<DuplexStream>,
    );
    type Ui = WebSocketStream<UnixStream>;

    async fn receive(peer: &mut Peer) -> Value {
        serde_json::from_str(&peer.0.next_line().await.unwrap().unwrap()).unwrap()
    }
    async fn send(peer: &mut Peer, frame: Value) {
        peer.1
            .write_all(format!("{frame}\n").as_bytes())
            .await
            .unwrap();
    }
    async fn ui_receive(ui: &mut Ui) -> Value {
        serde_json::from_str(ui.next().await.unwrap().unwrap().to_text().unwrap()).unwrap()
    }
    async fn ui_send(ui: &mut Ui, frame: Value) {
        ui.send(Message::Text(frame.to_string().into()))
            .await
            .unwrap();
    }

    async fn start(
        login_succeeds: bool,
    ) -> (
        Ui,
        Peer,
        mpsc::Receiver<AuthRequest>,
        tokio::task::JoinHandle<Result<Exit>>,
        watch::Receiver<Option<String>>,
    ) {
        let (ui_stream, bridge_stream) = UnixStream::pair().unwrap();
        let (coding_stream, peer_stream) = tokio::io::duplex(65536);
        let (reader, writer) = tokio::io::split(peer_stream);
        let mut peer = (BufReader::new(reader).lines(), writer);
        let (auth_tx, auth_rx) = mpsc::channel(4);
        let (session, last_session) = watch::channel(None);
        let bridge = tokio::spawn(async move {
            let mut coding = Rpc::test_connection(coding_stream);
            run(bridge_stream, &mut coding, json!({"type":"chatgptAuthTokens","accessToken":"private-token","chatgptAccountId":"account"}), auth_tx, session).await
        });
        let startup = tokio::spawn(async move {
            let initialize = receive(&mut peer).await;
            assert_eq!(initialize["method"], "initialize");
            assert_eq!(initialize["params"]["clientInfo"]["name"], "test-ui");
            assert_eq!(
                initialize["params"]["capabilities"]["experimentalApi"],
                true
            );
            assert_eq!(initialize["params"]["capabilities"]["other"], true);
            send(&mut peer, json!({"method":"ready","params":{}})).await;
            send(
                &mut peer,
                json!({"id":initialize["id"],"result":{"userAgent":"test"}}),
            )
            .await;
            assert_eq!(receive(&mut peer).await["method"], "initialized");
            let config = receive(&mut peer).await;
            assert_eq!(config["method"], "config/read");
            send(&mut peer, json!({"id":config["id"],"result":{"config":{"cli_auth_credentials_store":"ephemeral","chatgpt_base_url":"https://chatgpt.com/backend-api/","model_providers":{}}}})).await;
            let login = receive(&mut peer).await;
            assert_eq!(login["method"], "account/login/start");
            assert_eq!(login["params"]["accessToken"], "private-token");
            if login_succeeds {
                send(
                    &mut peer,
                    json!({"id":login["id"],"result":{"type":"chatgptAuthTokens"}}),
                )
                .await;
            } else {
                send(
                    &mut peer,
                    json!({"id":login["id"],"error":{"code":-1,"message":"private-token"}}),
                )
                .await;
            }
            peer
        });
        let (mut ui, _) = tokio_tungstenite::client_async("ws://localhost/", ui_stream)
            .await
            .unwrap();
        ui_send(&mut ui, json!({"id":1,"method":"initialize","params":{"clientInfo":{"name":"test-ui","version":"1"},"capabilities":{"other":true}}})).await;
        let response = ui_receive(&mut ui).await;
        assert_eq!(response["id"], 1);
        if login_succeeds {
            assert_eq!(response["result"]["userAgent"], "test");
            ui_send(&mut ui, json!({"method":"initialized"})).await;
            assert_eq!(ui_receive(&mut ui).await["method"], "ready");
        } else {
            assert!(response.get("error").is_some());
            assert!(!response.to_string().contains("private-token"));
        }
        (ui, startup.await.unwrap(), auth_rx, bridge, last_session)
    }

    #[tokio::test(start_paused = true)]
    async fn host_refresh_times_out_before_upstream_deadline() {
        let (auth, _requests) = mpsc::channel(1);
        let (reply, receiver) = oneshot::channel();
        let start = Instant::now();
        let result = host_request(
            &auth,
            AuthRequest::Refresh {
                params: json!({}),
                reply,
            },
            receiver,
        )
        .await;
        assert_eq!(
            result.unwrap_err().to_string(),
            "authentication host timed out"
        );
        assert_eq!(start.elapsed(), Duration::from_secs(8));
    }

    #[test]
    fn blocks_auth_routing_overrides_but_allows_ordinary_settings() {
        for params in [
            json!({"config":{"model_providers":{"openai":{"base_url":"https://other.invalid"}}}}),
            json!({"config":{"model_providers.openai.base_url":"https://other.invalid"}}),
            json!({"modelProvider":"other"}),
            json!({"config":{"profile":"custom"}}),
            json!({"config":{"profiles":{"custom":{"model_provider":"other"}}}}),
        ] {
            assert!(changes_auth_routing("thread/start", &params));
        }
        assert!(changes_auth_routing(
            "config/batchWrite",
            &json!({"edits":[{"keyPath":"model_reasoning_effort","value":"high"},{"keyPath":"chatgpt_base_url","value":"https://other.invalid"}]})
        ));
        assert!(changes_auth_routing(
            "config/value/write",
            &json!({"keyPath":"cli_auth_credentials_store","value":"file"})
        ));
        assert!(!changes_auth_routing(
            "config/value/write",
            &json!({"keyPath":"model_reasoning_effort","value":"high"})
        ));
        assert!(!changes_auth_routing(
            "thread/resume",
            &json!({"modelProvider":"openai","config":{"model_reasoning_effort":"high"}})
        ));
    }

    #[tokio::test]
    async fn continuation_tracks_only_successful_ui_thread_selections() {
        let (mut ui, mut peer, _auth, bridge, session) = start(true).await;
        for method in ["thread/start", "thread/resume", "thread/fork"] {
            ui_send(
                &mut ui,
                json!({"id":2,"method":method,"params":{"threadId":"saved"}}),
            )
            .await;
            if method != "thread/start" {
                let read = receive(&mut peer).await;
                assert_eq!(read["method"], "thread/read");
                send(&mut peer, json!({"id":read["id"],"result":{"thread":{"modelProvider":"openai","cwd":"/tmp"}}})).await;
                let config = receive(&mut peer).await;
                assert_eq!(config["method"], "config/read");
                send(&mut peer, json!({"id":config["id"],"result":{"config":{"cli_auth_credentials_store":"ephemeral","chatgpt_base_url":"https://chatgpt.com/backend-api/"}}})).await;
            }
            let request = receive(&mut peer).await;
            assert_eq!(request["method"], method);
            let selected = method.replace('/', "-");
            send(
                &mut peer,
                json!({"id":request["id"],"result":{"thread":{"id":selected,"ephemeral":false}}}),
            )
            .await;
            assert_eq!(ui_receive(&mut ui).await["id"], 2);
            assert_eq!(session.borrow().as_deref(), Some(selected.as_str()));
        }
        send(
            &mut peer,
            json!({"method":"thread/started","params":{"thread":{"id":"background-agent"}}}),
        )
        .await;
        ui_receive(&mut ui).await;
        assert_eq!(session.borrow().as_deref(), Some("thread-fork"));
        for response in [
            json!({"error":{"code":-1,"message":"failed"}}),
            json!({"result":{"thread":{"id":"unsafe;command","ephemeral":false}}}),
            json!({"result":{"thread":{"id":"temporary-title","ephemeral":true,"path":null}}}),
            json!({"result":{"thread":{"id":"missing-persistence-marker"}}}),
        ] {
            ui_send(&mut ui, json!({"id":3,"method":"thread/start","params":{}})).await;
            let request = receive(&mut peer).await;
            let mut response = response;
            response["id"] = request["id"].clone();
            send(&mut peer, response).await;
            ui_receive(&mut ui).await;
            assert_eq!(session.borrow().as_deref(), Some("thread-fork"));
        }
        ui.close(None).await.unwrap();
        bridge.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn ordinary_requests_can_run_longer_than_five_minutes() {
        let (mut ui, mut peer, _auth, bridge, _session) = start(true).await;
        ui_send(
            &mut ui,
            json!({"id":2,"method":"command/exec","params":{"disableTimeout":true}}),
        )
        .await;
        let request = receive(&mut peer).await;
        tokio::time::pause();
        tokio::time::advance(Duration::from_secs(601)).await;
        tokio::task::yield_now().await;
        tokio::time::resume();
        assert!(
            !bridge.is_finished(),
            "bridge must respect upstream operation timeouts"
        );
        send(
            &mut peer,
            json!({"id":request["id"],"result":{"exitCode":0}}),
        )
        .await;
        assert_eq!(ui_receive(&mut ui).await["id"], 2);
        ui.close(None).await.unwrap();
        bridge.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn missing_resume_target_returns_an_error_without_ending_the_session() {
        let (mut ui, mut peer, _auth, bridge, _session) = start(true).await;
        ui_send(
            &mut ui,
            json!({"id":2,"method":"thread/resume","params":{"threadId":"deleted"}}),
        )
        .await;
        let read = receive(&mut peer).await;
        assert_eq!(read["method"], "thread/read");
        send(
            &mut peer,
            json!({"id":read["id"],"error":{"code":-32602,"message":"private upstream details"}}),
        )
        .await;
        let rejected = ui_receive(&mut ui).await;
        assert_eq!(rejected["id"], 2);
        assert!(
            rejected["error"]["message"]
                .as_str()
                .unwrap()
                .contains("unavailable")
        );
        assert!(!rejected.to_string().contains("private upstream details"));
        ui_send(&mut ui, json!({"id":3,"method":"account/read","params":{}})).await;
        let request = receive(&mut peer).await;
        assert_eq!(request["method"], "account/read");
        send(
            &mut peer,
            json!({"id":request["id"],"result":{"account":null}}),
        )
        .await;
        assert_eq!(
            ui_receive(&mut ui).await,
            json!({"id":3,"result":{"account":null}})
        );
        ui.close(None).await.unwrap();
        bridge.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn resume_and_fork_validate_stored_directory_and_provider() {
        for (method, provider) in [
            ("thread/resume", "openai"),
            ("thread/fork", "openai"),
            ("thread/resume", "other"),
        ] {
            let (mut ui, mut peer, _auth, bridge, _session) = start(true).await;
            ui_send(
                &mut ui,
                json!({"id":2,"method":method,"params":{"threadId":"saved-thread"}}),
            )
            .await;
            let read = receive(&mut peer).await;
            assert_eq!(read["method"], "thread/read");
            assert_eq!(
                read["params"],
                json!({"threadId":"saved-thread","includeTurns":false})
            );
            send(&mut peer, json!({"id":read["id"],"result":{"thread":{"cwd":"/saved-project","modelProvider":provider}}})).await;
            if provider == "openai" {
                let config = receive(&mut peer).await;
                assert_eq!(config["method"], "config/read");
                assert_eq!(config["params"]["cwd"], "/saved-project");
                send(
                    &mut peer,
                    json!({"id":config["id"],"result":{"config":{"model_provider":"other"}}}),
                )
                .await;
            }
            let response = ui_receive(&mut ui).await;
            assert_eq!(response["id"], 2);
            assert!(response.get("error").is_some());
            ui_send(&mut ui, json!({"id":3,"method":"account/read","params":{}})).await;
            assert_eq!(receive(&mut peer).await["method"], "account/read");
            ui.close(None).await.unwrap();
            bridge.await.unwrap().unwrap();
        }
    }

    #[tokio::test]
    async fn routes_out_of_order_ids_and_server_requests_after_authentication() {
        let (mut ui, mut peer, _auth, bridge, _session) = start(true).await;
        ui_send(&mut ui, json!({"id":1,"method":"first","params":{}})).await;
        ui_send(&mut ui, json!({"id":"1","method":"second","params":{}})).await;
        let first = receive(&mut peer).await;
        let second = receive(&mut peer).await;
        assert_ne!(first["id"], second["id"]);
        send(&mut peer, json!({"id":second["id"],"result":"second"})).await;
        send(&mut peer, json!({"id":first["id"],"result":"first"})).await;
        assert_eq!(
            ui_receive(&mut ui).await,
            json!({"id":"1","result":"second"})
        );
        assert_eq!(ui_receive(&mut ui).await, json!({"id":1,"result":"first"}));
        send(&mut peer, json!({"id":1,"method":"approve","params":{}})).await;
        let approval = ui_receive(&mut ui).await;
        ui_send(
            &mut ui,
            json!({"id":approval["id"],"result":{"approved":true}}),
        )
        .await;
        assert_eq!(
            receive(&mut peer).await,
            json!({"id":1,"result":{"approved":true}})
        );
        ui.close(None).await.unwrap();
        bridge.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn resolved_server_requests_keep_ui_ids_and_tolerate_late_answers() {
        let (mut ui, mut peer, _auth, bridge, _session) = start(true).await;
        send(&mut peer, json!({"id":41,"method":"approve","params":{}})).await;
        let approval = ui_receive(&mut ui).await;
        send(&mut peer, json!({"method":"serverRequest/resolved","params":{"threadId":"thread","requestId":41}})).await;
        let resolved = ui_receive(&mut ui).await;
        assert_eq!(resolved["params"]["requestId"], approval["id"]);
        ui_send(
            &mut ui,
            json!({"id":approval["id"],"result":{"approved":true}}),
        )
        .await;
        ui_send(&mut ui, json!({"id":7,"method":"account/read","params":{}})).await;
        assert_eq!(receive(&mut peer).await["method"], "account/read");
        send(&mut peer, json!({"id":42,"method":"approve","params":{}})).await;
        let approval = ui_receive(&mut ui).await;
        ui_send(&mut ui, json!({"id":approval["id"],"result":{}})).await;
        assert_eq!(receive(&mut peer).await["id"], 42);
        send(&mut peer, json!({"method":"serverRequest/resolved","params":{"threadId":"thread","requestId":42}})).await;
        assert_eq!(
            ui_receive(&mut ui).await["params"]["requestId"],
            approval["id"]
        );
        ui.close(None).await.unwrap();
        bridge.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn private_config_read_services_token_refresh_and_preserves_other_events() {
        let (mut ui, mut peer, mut auth, bridge, _session) = start(true).await;
        ui_send(
            &mut ui,
            json!({"id":2,"method":"thread/start","params":{"cwd":"/tmp"}}),
        )
        .await;
        let config = receive(&mut peer).await;
        assert_eq!(config["method"], "config/read");
        send(&mut peer, json!({"method":"updated","params":{}})).await;
        send(&mut peer, json!({"id":42,"method":"account/chatgptAuthTokens/refresh","params":{"reason":"unauthorized"}})).await;
        let request = timeout(Duration::from_millis(100), auth.recv())
            .await
            .expect("refresh must not wait for config/read")
            .unwrap();
        let AuthRequest::Refresh { reply, .. } = request else {
            panic!("expected refresh");
        };
        reply
            .send(Ok(
                json!({"accessToken":"private-token","chatgptAccountId":"account"}),
            ))
            .unwrap();
        assert_eq!(receive(&mut peer).await["id"], 42);
        send(&mut peer, json!({"id":config["id"],"result":{"config":{"cli_auth_credentials_store":"ephemeral","chatgpt_base_url":"https://chatgpt.com/backend-api/","model_providers":{}}}})).await;
        let thread = receive(&mut peer).await;
        assert_eq!(thread["method"], "thread/start");
        assert_eq!(ui_receive(&mut ui).await["method"], "updated");
        ui.close(None).await.unwrap();
        bridge.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn validates_effective_config_before_starting_thread_in_another_directory() {
        let (mut ui, mut peer, _auth, bridge, _session) = start(true).await;
        ui_send(
            &mut ui,
            json!({"id":2,"method":"thread/start","params":{"cwd":"/tmp"}}),
        )
        .await;
        let config = receive(&mut peer).await;
        assert_eq!(config["method"], "config/read");
        assert_eq!(config["params"]["cwd"], "/tmp");
        send(
            &mut peer,
            json!({"id":config["id"],"result":{"config":{"model_provider":"other"}}}),
        )
        .await;
        let response = ui_receive(&mut ui).await;
        assert_eq!(response["id"], 2);
        assert!(response.get("error").is_some());
        ui_send(&mut ui, json!({"id":3,"method":"account/read","params":{}})).await;
        assert_eq!(receive(&mut peer).await["method"], "account/read");
        ui.close(None).await.unwrap();
        bridge.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn refresh_and_logout_stay_with_host_and_token_methods_are_denied() {
        let (mut ui, mut peer, mut auth, bridge, _session) = start(true).await;
        send(&mut peer, json!({"id":4,"method":"account/chatgptAuthTokens/refresh","params":{"reason":"unauthorized"}})).await;
        let AuthRequest::Refresh { params, reply } = auth.recv().await.unwrap() else {
            panic!("expected refresh");
        };
        assert_eq!(params["reason"], "unauthorized");
        reply
            .send(Ok(
                json!({"accessToken":"new-private-token","chatgptAccountId":"account"}),
            ))
            .unwrap();
        assert_eq!(
            receive(&mut peer).await["result"]["accessToken"],
            "new-private-token"
        );
        for method in [
            "account/login/start",
            "loginAccount",
            "getAuthStatus",
            "account/chatgptAuthTokens/refresh",
        ] {
            ui_send(&mut ui, json!({"id":8,"method":method,"params":{}})).await;
            let response = ui_receive(&mut ui).await;
            assert_eq!(response["id"], 8);
            assert!(response.get("error").is_some());
        }
        ui_send(
            &mut ui,
            json!({"id":9,"method":"account/logout","params":{}}),
        )
        .await;
        let AuthRequest::Logout { reply } = auth.recv().await.unwrap() else {
            panic!("expected logout");
        };
        reply.send(Ok(json!({}))).unwrap();
        assert_eq!(ui_receive(&mut ui).await, json!({"id":9,"result":{}}));
        bridge.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn auth_failure_never_releases_initialize_or_private_error() {
        let (_ui, _peer, _auth, bridge, _session) = start(false).await;
        let error = bridge.await.unwrap().unwrap_err().to_string();
        assert!(!error.contains("private-token"));
    }
}
