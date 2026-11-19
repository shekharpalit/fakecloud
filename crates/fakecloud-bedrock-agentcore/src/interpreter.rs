//! Code Interpreter sessions: each session is a container with no network,
//! running a small Python kernel (`kernel.py`) that keeps one module scope
//! across `executeCode` calls, as AgentCore's sandbox does, and answers
//! `executeCommand`, `writeFiles`, `readFiles`, `listFiles` and `removeFiles`.
//! The image is the AWS Lambda Python base image unless
//! `FAKECLOUD_CODE_INTERPRETER_IMAGE` names another (one with the libraries
//! the sandbox's code imports).

use std::collections::HashMap;
use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout};

const KERNEL: &str = include_str!("kernel.py");
const DEFAULT_IMAGE: &str = "public.ecr.aws/lambda/python:3.14";
pub const IMAGE_ENV: &str = "FAKECLOUD_CODE_INTERPRETER_IMAGE";

struct Kernel {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    container: String,
}

struct Session {
    identifier: String,
    name: String,
    created: String,
    timeout: Duration,
    last_used: Instant,
    kernel: Arc<tokio::sync::Mutex<Option<Kernel>>>,
}

pub struct Interpreters {
    cli: Option<String>,
    image: String,
    sessions: Mutex<HashMap<String, Session>>,
}

impl Interpreters {
    pub fn new(cli: Option<String>) -> Arc<Self> {
        let interpreters = Arc::new(Self {
            cli,
            image: std::env::var(IMAGE_ENV).unwrap_or_else(|_| DEFAULT_IMAGE.to_string()),
            sessions: Mutex::new(HashMap::new()),
        });
        let reaper = Arc::downgrade(&interpreters);
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                loop {
                    tokio::time::sleep(Duration::from_secs(15)).await;
                    let Some(interpreters) = reaper.upgrade() else {
                        break;
                    };
                    let expired: Vec<String> = interpreters
                        .sessions
                        .lock()
                        .iter()
                        .filter(|(_, s)| s.last_used.elapsed() >= s.timeout)
                        .map(|(id, _)| id.clone())
                        .collect();
                    for id in expired {
                        interpreters.stop(&id).await;
                    }
                }
            });
        }
        interpreters
    }

    /// `StartCodeInterpreterSession`: the session's id. The kernel starts on first use.
    pub fn start(
        &self,
        identifier: &str,
        name: Option<&str>,
        timeout_seconds: Option<u64>,
    ) -> Value {
        let id = uuid::Uuid::new_v4()
            .simple()
            .to_string()
            .to_ascii_uppercase()[..26]
            .to_string();
        let created = crate::state::now_iso();
        self.sessions.lock().insert(
            id.clone(),
            Session {
                identifier: identifier.to_string(),
                name: name.unwrap_or("session").to_string(),
                created: created.clone(),
                timeout: Duration::from_secs(timeout_seconds.unwrap_or(900)),
                last_used: Instant::now(),
                kernel: Arc::new(tokio::sync::Mutex::new(None)),
            },
        );
        json!({ "codeInterpreterIdentifier": identifier, "sessionId": id, "createdAt": created.clone() })
    }

    pub fn describe(&self, identifier: &str, id: &str) -> Option<Value> {
        let sessions = self.sessions.lock();
        let session = sessions.get(id).filter(|s| s.identifier == identifier)?;
        Some(json!({
            "codeInterpreterIdentifier": session.identifier,
            "sessionId": id,
            "name": session.name,
            "createdAt": session.created,
            "sessionTimeoutSeconds": session.timeout.as_secs(),
            "status": "READY",
        }))
    }

    /// `StopCodeInterpreterSession`; `false` when there was no such session.
    pub async fn stop(&self, id: &str) -> bool {
        let Some(session) = self.sessions.lock().remove(id) else {
            return false;
        };
        let kernel = session.kernel.lock().await.take();
        if let (Some(mut kernel), Some(cli)) = (kernel, self.cli.as_ref()) {
            let _ = tokio::process::Command::new(cli)
                .args(["rm", "-f", &kernel.container])
                .output()
                .await;
            let _ = kernel.child.kill().await;
        }
        true
    }

    /// `InvokeCodeInterpreter`: the tool's `CodeInterpreterResult`, or why the
    /// session cannot answer.
    pub async fn invoke(
        &self,
        identifier: &str,
        id: &str,
        name: &str,
        arguments: &Value,
    ) -> Result<Value, String> {
        let slot = {
            let mut sessions = self.sessions.lock();
            let session = sessions
                .get_mut(id)
                .filter(|s| s.identifier == identifier)
                .ok_or_else(|| format!("Session {id} not found"))?;
            session.last_used = Instant::now();
            session.kernel.clone()
        };
        let mut guard = slot.lock().await;
        if guard.is_none() {
            *guard = Some(self.launch(id).await?);
        }
        let kernel = guard.as_mut().expect("launched above");
        let line = json!({ "name": name, "arguments": arguments }).to_string() + "\n";
        kernel
            .stdin
            .write_all(line.as_bytes())
            .await
            .map_err(|e| format!("The sandbox stopped: {e}"))?;
        kernel
            .stdin
            .flush()
            .await
            .map_err(|e| format!("The sandbox stopped: {e}"))?;
        let mut answer = String::new();
        let read = kernel
            .stdout
            .read_line(&mut answer)
            .await
            .map_err(|e| e.to_string())?;
        if read == 0 {
            *guard = None;
            return Err("The sandbox stopped while running the tool".into());
        }
        serde_json::from_str(&answer).map_err(|e| format!("The sandbox answered badly: {e}"))
    }

    async fn launch(&self, id: &str) -> Result<Kernel, String> {
        let cli = self
            .cli
            .as_ref()
            .ok_or("fakecloud has no container runtime to run Code Interpreter sessions")?;
        let container = format!("fakecloud-codeinterpreter-{}", id.to_ascii_lowercase());
        let mut child = tokio::process::Command::new(cli)
            .args([
                "run",
                "-i",
                "--rm",
                "--name",
                &container,
                "--label",
                "fakecloud-agentcore=1",
                "--network",
                "none",
                "-w",
                "/workspace",
                "--entrypoint",
                "python3",
                &self.image,
                "-u",
                "-c",
                KERNEL,
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| format!("The container runtime could not start the sandbox: {e}"))?;
        let stdin = child.stdin.take().ok_or("the sandbox has no input")?;
        let stdout = BufReader::new(child.stdout.take().ok_or("the sandbox has no output")?);
        Ok(Kernel {
            child,
            stdin,
            stdout,
            container,
        })
    }
}
