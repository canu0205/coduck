use crate::process::signal_group;
use std::{collections::VecDeque, process::Stdio, time::Duration};

use anyhow::{Result, anyhow, bail};
use serde_json::{Value, json};
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader},
    process::{Child, Command},
    sync::mpsc,
    task::JoinHandle,
    time::timeout,
};

// match the official terminal remote transport limit.
pub const MAX_FRAME: usize = 128 * 1024 * 1024;
pub const MAX_PENDING: usize = 128;
pub const RPC_TIMEOUT: Duration = Duration::from_secs(30);

pub struct Rpc {
    child: Option<Child>,
    process_group: Option<u32>,
    writer: Box<dyn AsyncWrite + Unpin + Send>,
    incoming: mpsc::Receiver<Result<Value>>,
    reader: JoinHandle<()>,
    pending: VecDeque<Value>,
    sequence: u64,
}

impl Rpc {
    pub fn spawn(mut command: Command) -> Result<Self> {
        command.process_group(0);
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .map_err(|_| anyhow!("cannot start app-server"))?;
        let reader = child
            .stdout
            .take()
            .ok_or_else(|| anyhow!("missing app-server stdout"))?;
        let writer = child
            .stdin
            .take()
            .ok_or_else(|| anyhow!("missing app-server stdin"))?;
        Ok(Self::connect(
            Some(child),
            Box::new(reader),
            Box::new(writer),
        ))
    }

    fn connect(
        child: Option<Child>,
        reader: Box<dyn AsyncRead + Unpin + Send>,
        writer: Box<dyn AsyncWrite + Unpin + Send>,
    ) -> Self {
        let (sender, incoming) = mpsc::channel(MAX_PENDING);
        let reader = tokio::spawn(async move {
            let mut reader = BufReader::new(reader);
            loop {
                let frame = read_frame(&mut reader).await;
                let failed = frame.is_err();
                if sender.send(frame).await.is_err() || failed {
                    break;
                }
            }
        });
        Self {
            process_group: child.as_ref().and_then(Child::id),
            child,
            writer,
            incoming,
            reader,
            pending: VecDeque::new(),
            sequence: 0,
        }
    }

    #[cfg(test)]
    pub(crate) fn test_connection(stream: tokio::io::DuplexStream) -> Self {
        let (reader, writer) = tokio::io::split(stream);
        Self::connect(None, Box::new(reader), Box::new(writer))
    }

    pub fn pid(&self) -> Option<u32> {
        self.process_group
    }

    pub fn next_id(&mut self) -> Value {
        self.sequence += 1;
        json!(format!("coduck-{}", self.sequence))
    }

    pub async fn send(&mut self, value: Value) -> Result<()> {
        let mut bytes =
            serde_json::to_vec(&value).map_err(|_| anyhow!("cannot encode RPC message"))?;
        if bytes.len() > MAX_FRAME {
            bail!("RPC message exceeds size limit");
        }
        bytes.push(b'\n');
        timeout(RPC_TIMEOUT, async {
            self.writer.write_all(&bytes).await?;
            self.writer.flush().await
        })
        .await
        .map_err(|_| anyhow!("app-server write timed out"))?
        .map_err(|_| anyhow!("app-server write failed"))
    }

    pub async fn recv(&mut self) -> Result<Value> {
        if let Some(value) = self.pending.pop_front() {
            return Ok(value);
        }
        self.recv_live().await
    }

    pub(crate) async fn recv_live(&mut self) -> Result<Value> {
        self.incoming
            .recv()
            .await
            .ok_or_else(|| anyhow!("app-server disconnected"))?
    }

    pub(crate) fn defer(&mut self, frame: Value) -> Result<()> {
        if self.pending.len() >= MAX_PENDING {
            bail!("too many buffered app-server messages");
        }
        self.pending.push_back(frame);
        Ok(())
    }

    pub async fn request(&mut self, method: &str, params: Value) -> Result<Value> {
        let id = self.next_id();
        self.send(json!({"id":id,"method":method,"params":params}))
            .await?;
        timeout(RPC_TIMEOUT, async {
            loop {
                let frame = self.recv_live().await?;
                if frame.get("method").is_none() && frame.get("id") == Some(&id) {
                    if frame.get("error").is_some() {
                        bail!("app-server request failed");
                    }
                    return frame
                        .get("result")
                        .cloned()
                        .ok_or_else(|| anyhow!("invalid app-server response"));
                }
                self.defer(frame)?;
            }
        })
        .await
        .map_err(|_| anyhow!("app-server request timed out"))?
    }

    pub async fn initialize(&mut self, params: Value) -> Result<Value> {
        let result = self.request("initialize", params).await?;
        self.send(json!({"method":"initialized"})).await?;
        Ok(result)
    }

    pub async fn shutdown(&mut self) -> Result<()> {
        self.reader.abort();
        if let Some(pid) = self.process_group {
            signal_group(pid, libc::SIGTERM)?;
            let _ = timeout(Duration::from_secs(5), crate::process::exited(pid)).await;
            signal_group(pid, libc::SIGKILL)?;
            // never signal the saved group after releasing its leader's PID.
            self.process_group = None;
        }
        if let Some(child) = self.child.as_mut() {
            timeout(Duration::from_secs(5), child.wait())
                .await
                .map_err(|_| anyhow!("app-server shutdown timed out"))?
                .map_err(|_| anyhow!("app-server shutdown failed"))?;
        }
        self.child = None;
        Ok(())
    }
}

impl Drop for Rpc {
    fn drop(&mut self) {
        self.reader.abort();
        if let Some(pid) = self.pid() {
            let _ = signal_group(pid, libc::SIGKILL);
        }
    }
}

async fn read_frame(reader: &mut BufReader<Box<dyn AsyncRead + Unpin + Send>>) -> Result<Value> {
    let mut bytes = Vec::new();
    loop {
        let chunk = reader
            .fill_buf()
            .await
            .map_err(|_| anyhow!("app-server read failed"))?;
        if chunk.is_empty() {
            bail!("app-server disconnected");
        }
        let end = chunk.iter().position(|byte| *byte == b'\n');
        let length = end.map_or(chunk.len(), |end| end + 1);
        if bytes.len() + length > MAX_FRAME {
            bail!("app-server message exceeds size limit");
        }
        bytes.extend_from_slice(&chunk[..length]);
        reader.consume(length);
        if end.is_some() {
            return serde_json::from_slice(&bytes).map_err(|_| anyhow!("invalid app-server JSON"));
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    #[tokio::test]
    async fn request_preserves_interleaved_notifications_and_server_requests() {
        let (client, server) = tokio::io::duplex(4096);
        let mut rpc = Rpc::test_connection(client);
        let peer = tokio::spawn(async move {
            let (read, mut write) = tokio::io::split(server);
            let mut lines = BufReader::new(read).lines();
            let request: Value =
                serde_json::from_str(&lines.next_line().await.unwrap().unwrap()).unwrap();
            for frame in [
                json!({"method":"updated","params":{}}),
                json!({"id":7,"method":"approve","params":{}}),
                json!({"id":request["id"],"result":{"ok":true}}),
            ] {
                write
                    .write_all(format!("{frame}\n").as_bytes())
                    .await
                    .unwrap();
            }
        });
        assert_eq!(
            rpc.request("test", json!({})).await.unwrap(),
            json!({"ok":true})
        );
        assert_eq!(rpc.recv().await.unwrap()["method"], "updated");
        assert_eq!(rpc.recv().await.unwrap()["method"], "approve");
        peer.await.unwrap();
    }

    #[tokio::test]
    async fn rejects_oversized_jsonl_without_waiting_for_newline() {
        let (client, mut server) = tokio::io::duplex(16384);
        let mut rpc = Rpc::test_connection(client);
        let peer = tokio::spawn(async move {
            let _ = server.write_all(&vec![b'x'; MAX_FRAME + 1]).await;
        });
        assert_eq!(
            rpc.recv().await.unwrap_err().to_string(),
            "app-server message exceeds size limit"
        );
        peer.abort();
    }

    #[tokio::test]
    async fn bounds_messages_buffered_during_private_request() {
        let (client, server) = tokio::io::duplex(16384);
        let mut rpc = Rpc::test_connection(client);
        let peer = tokio::spawn(async move {
            let (read, mut write) = tokio::io::split(server);
            let mut lines = BufReader::new(read).lines();
            lines.next_line().await.unwrap().unwrap();
            for _ in 0..=MAX_PENDING {
                write
                    .write_all(b"{\"method\":\"updated\"}\n")
                    .await
                    .unwrap();
            }
        });
        assert_eq!(
            rpc.request("test", json!({}))
                .await
                .unwrap_err()
                .to_string(),
            "too many buffered app-server messages"
        );
        peer.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn private_requests_have_a_deadline() {
        let (client, _server) = tokio::io::duplex(4096);
        let mut rpc = Rpc::test_connection(client);
        let start = tokio::time::Instant::now();
        assert_eq!(
            rpc.request("test", json!({}))
                .await
                .unwrap_err()
                .to_string(),
            "app-server request timed out"
        );
        assert_eq!(start.elapsed(), RPC_TIMEOUT);
    }

    #[tokio::test]
    async fn shutdown_terminates_wrapper_descendants() {
        let mut command = Command::new("/bin/sh");
        command
            .arg("-c")
            .arg(r#"sleep 60 & printf '{"descendant":%s}\n' "$!"; wait"#);
        let mut rpc = Rpc::spawn(command).unwrap();
        let descendant = rpc.recv().await.unwrap()["descendant"].as_i64().unwrap() as i32;
        rpc.shutdown().await.unwrap();
        let mut alive = true;
        for _ in 0..100 {
            alive = unsafe { libc::kill(descendant, 0) } == 0;
            if !alive {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        if alive {
            unsafe {
                libc::kill(descendant, libc::SIGKILL);
            }
        }
        assert!(!alive, "wrapper descendant survived shutdown");
    }

    #[tokio::test]
    async fn dropping_a_cancelled_shutdown_kills_the_process_group() {
        let mut command = Command::new("/bin/sh");
        command
            .arg("-c")
            .arg(r#"trap '' TERM; sleep 60 & printf '{"descendant":%s}\n' "$!"; wait"#);
        let mut rpc = Rpc::spawn(command).unwrap();
        let descendant = rpc.recv().await.unwrap()["descendant"].as_i64().unwrap() as i32;
        assert!(
            timeout(Duration::from_millis(30), rpc.shutdown())
                .await
                .is_err()
        );
        drop(rpc);
        let mut alive = true;
        for _ in 0..100 {
            alive = unsafe { libc::kill(descendant, 0) } == 0;
            if !alive {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        if alive {
            unsafe {
                libc::kill(descendant, libc::SIGKILL);
            }
        }
        assert!(!alive, "cancelled shutdown left a descendant alive");
    }

    #[tokio::test]
    async fn shutdown_reaps_the_owned_child() {
        let mut rpc = Rpc::spawn(Command::new("/bin/cat")).unwrap();
        assert!(rpc.pid().is_some());
        rpc.shutdown().await.unwrap();
        assert!(rpc.pid().is_none());
    }

    #[tokio::test]
    async fn malformed_input_errors_do_not_contain_frame_contents() {
        let (client, mut server) = tokio::io::duplex(4096);
        let mut rpc = Rpc::test_connection(client);
        server
            .write_all(b"secret-token-is-not-json\n")
            .await
            .unwrap();
        let error = rpc.recv().await.unwrap_err().to_string();
        assert_eq!(error, "invalid app-server JSON");
    }
}
