//! AgentCore Runtime sessions: each `runtimeSessionId` of a runtime gets its own
//! container running the runtime's code (a zip from S3, run as
//! `python <entryPoint>` in the AWS Lambda Python base image of its runtime
//! version) on port 8080, and every invocation of the session reaches that
//! container's `POST /invocations`. Like AgentCore's microVMs, a session's
//! container keeps running after it answers, until it has been idle for the
//! runtime's `idleRuntimeSessionTimeout` while its `/ping` does not report
//! `HealthyBusy`, or until `maxLifetime`.
//!
//! Callers are checked as AgentCore checks them: a runtime with a
//! `customJWTAuthorizer` takes only a bearer token from a fakecloud Cognito user
//! pool whose issuer its discovery URL names, signed by the pool's key,
//! unexpired, from an allowed client and (when configured) with an allowed
//! scope or audience; any other runtime takes only SigV4 callers. The container
//! receives `Content-Type`, `Accept`, the session id, the headers its
//! `requestHeaderAllowlist` names and `X-Amzn-Bedrock-AgentCore-Runtime-Custom-*`.

use std::collections::HashMap;
use std::io::Read;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use fakecloud_core::auth::{SessionCredentialIssuer, SessionCredentials};
use fakecloud_core::delivery::S3Delivery;
use http::{HeaderMap, StatusCode};
use parking_lot::Mutex;
use serde_json::Value;

const PORT: u16 = 8080;
const START_TIMEOUT: Duration = Duration::from_secs(180);
const INVOKE_TIMEOUT: Duration = Duration::from_secs(900);
pub(crate) const SESSION_HEADER: &str = "x-amzn-bedrock-agentcore-runtime-session-id";
const CUSTOM_HEADER_PREFIX: &str = "x-amzn-bedrock-agentcore-runtime-custom-";

/// Where and how runtime containers run.
pub struct RuntimeHost {
    pub cli: String,
    pub host_alias_arg: Option<String>,
    pub sibling_host: String,
    /// The fakecloud endpoint as a container reaches it (`AWS_ENDPOINT_URL`).
    pub endpoint_url: String,
    pub s3: Option<Arc<dyn S3Delivery>>,
    pub credentials: Option<Arc<dyn SessionCredentialIssuer>>,
    pub cognito: Option<fakecloud_cognito::SharedCognitoState>,
}

struct Session {
    container: String,
    port: u16,
    started: Instant,
    last_used: Instant,
    idle: Duration,
    max: Duration,
    credentials: Option<SessionCredentials>,
    _code: tempfile::TempDir,
}

type SessionKey = (String, String);

/// Every running session, across runtimes.
pub struct Sessions {
    host: Option<RuntimeHost>,
    running: Mutex<HashMap<SessionKey, Arc<tokio::sync::Mutex<Option<Session>>>>>,
    http: reqwest::Client,
}

/// An invocation's outcome, passed through from the container.
pub struct Answer {
    pub status: StatusCode,
    pub content_type: String,
    pub body: Bytes,
}

#[derive(Debug)]
pub enum Refusal {
    /// 401/403: the caller is not admitted.
    Denied(String),
    /// 400: the request is malformed.
    Invalid(String),
    /// 424/500: the runtime could not run or answer.
    Failed(StatusCode, String),
}

fn image_for(runtime: &str) -> Option<String> {
    let version = runtime.strip_prefix("PYTHON_")?.replace('_', ".");
    Some(format!("public.ecr.aws/lambda/python:{version}"))
}

impl Sessions {
    pub fn new(host: Option<RuntimeHost>) -> Arc<Self> {
        let sessions = Arc::new(Self {
            host,
            running: Mutex::new(HashMap::new()),
            http: reqwest::Client::builder()
                .no_proxy()
                .build()
                .expect("a plain HTTP client builds"),
        });
        if sessions.host.is_some() {
            let reaper = Arc::downgrade(&sessions);
            if let Ok(handle) = tokio::runtime::Handle::try_current() {
                handle.spawn(async move {
                    loop {
                        tokio::time::sleep(Duration::from_secs(15)).await;
                        let Some(sessions) = reaper.upgrade() else {
                            break;
                        };
                        sessions.reap().await;
                    }
                });
            }
        }
        sessions
    }

    /// Check the caller of `runtime` from the request headers.
    pub fn authorize(&self, runtime: &Value, headers: &HeaderMap) -> Result<(), Refusal> {
        let authorization = headers
            .get(http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let Some(jwt) = runtime.pointer("/authorizerConfiguration/customJWTAuthorizer") else {
            return if authorization.starts_with("AWS4-HMAC-SHA256") {
                Ok(())
            } else {
                Err(Refusal::Denied(
                    "Authorization method mismatch: this runtime takes SigV4 callers".into(),
                ))
            };
        };
        let token = authorization.strip_prefix("Bearer ").ok_or_else(|| {
            Refusal::Denied(
                "Authorization method mismatch: this runtime takes a bearer token".into(),
            )
        })?;
        let discovery = jwt["discoveryUrl"].as_str().unwrap_or_default();
        let issuer = discovery.trim_end_matches("/.well-known/openid-configuration");
        let pool_id = issuer.rsplit('/').next().unwrap_or_default();
        let pem = self
            .host
            .as_ref()
            .and_then(|h| h.cognito.as_ref())
            .and_then(|state| {
                let accounts = state.read();
                let pem = accounts.iter().find_map(|(_, account)| {
                    account.user_pools.get(pool_id)?.signing_key_pem.clone()
                });
                pem
            })
            .ok_or_else(|| {
                Refusal::Denied(format!(
                    "No fakecloud user pool answers the discovery URL {discovery}"
                ))
            })?;
        let (_, claims) = fakecloud_cognito::jwt::verify_rs256(token, &pem)
            .map_err(|_| Refusal::Denied("The bearer token's signature is not valid".into()))?;
        if claims["iss"].as_str() != Some(issuer) {
            return Err(Refusal::Denied(
                "The bearer token's issuer does not match the authorizer".into(),
            ));
        }
        if claims["exp"]
            .as_i64()
            .is_none_or(|exp| exp <= chrono::Utc::now().timestamp())
        {
            return Err(Refusal::Denied("The bearer token has expired".into()));
        }
        let listed = |member: &str| -> Option<Vec<String>> {
            jwt.get(member).and_then(Value::as_array).map(|items| {
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect()
            })
        };
        if let Some(clients) = listed("allowedClients") {
            let client = claims["client_id"]
                .as_str()
                .or_else(|| claims["aud"].as_str())
                .unwrap_or_default();
            if !clients.iter().any(|c| c == client) {
                return Err(Refusal::Denied(
                    "The bearer token's client is not allowed".into(),
                ));
            }
        }
        if let Some(audiences) = listed("allowedAudience") {
            let audience = claims["aud"].as_str().unwrap_or_default();
            if !audiences.iter().any(|a| a == audience) {
                return Err(Refusal::Denied(
                    "The bearer token's audience is not allowed".into(),
                ));
            }
        }
        if let Some(scopes) = listed("allowedScopes") {
            let granted: Vec<&str> = claims["scope"]
                .as_str()
                .unwrap_or_default()
                .split(' ')
                .collect();
            if !scopes.iter().any(|s| granted.contains(&s.as_str())) {
                return Err(Refusal::Denied(
                    "The bearer token has no allowed scope".into(),
                ));
            }
        }
        Ok(())
    }

    /// Run one invocation of `runtime` in session `session_id`.
    pub async fn invoke(
        &self,
        runtime: &Value,
        account_id: &str,
        region: &str,
        session_id: &str,
        headers: &HeaderMap,
        body: Bytes,
    ) -> Result<Answer, Refusal> {
        let host = self.host.as_ref().ok_or_else(|| {
            Refusal::Failed(
                StatusCode::FAILED_DEPENDENCY,
                "fakecloud has no container runtime to run agent runtimes".into(),
            )
        })?;
        let runtime_id = runtime["agentRuntimeId"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        let slot = {
            let mut running = self.running.lock();
            running
                .entry((runtime_id.clone(), session_id.to_string()))
                .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(None)))
                .clone()
        };
        let mut session = slot.lock().await;
        if session.is_none() {
            *session =
                Some(start(host, &self.http, runtime, account_id, region, session_id).await?);
        }
        let live = session.as_mut().expect("started above");
        live.last_used = Instant::now();
        let url = format!("http://{}:{}/invocations", host.sibling_host, live.port);
        drop(session);

        let mut request = self.http.post(&url).timeout(INVOKE_TIMEOUT).body(body);
        let allowlist: Vec<String> = runtime
            .pointer("/requestHeaderConfiguration/requestHeaderAllowlist")
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_ascii_lowercase)
                    .collect()
            })
            .unwrap_or_default();
        for (name, value) in headers {
            let name = name.as_str();
            let passed = matches!(name, "content-type" | "accept")
                || name == SESSION_HEADER
                || name.starts_with(CUSTOM_HEADER_PREFIX)
                || allowlist.iter().any(|a| a == name);
            if passed {
                request = request.header(name, value);
            }
        }
        if !headers.contains_key(SESSION_HEADER) {
            request = request.header(SESSION_HEADER, session_id);
        }
        let response = request.send().await.map_err(|e| {
            Refusal::Failed(
                StatusCode::FAILED_DEPENDENCY,
                format!("The runtime did not answer: {e}"),
            )
        })?;
        let status = StatusCode::from_u16(response.status().as_u16())
            .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        let content_type = response
            .headers()
            .get(http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("application/json")
            .to_string();
        let body = response.bytes().await.map_err(|e| {
            Refusal::Failed(
                StatusCode::FAILED_DEPENDENCY,
                format!("The runtime's answer was cut off: {e}"),
            )
        })?;
        Ok(Answer {
            status,
            content_type,
            body,
        })
    }

    /// End a session now (`StopRuntimeSession`); `false` when it was not running.
    pub async fn stop(&self, runtime_id: &str, session_id: &str) -> bool {
        let slot = self
            .running
            .lock()
            .remove(&(runtime_id.to_string(), session_id.to_string()));
        let Some(slot) = slot else { return false };
        let session = slot.lock().await.take();
        match (session, self.host.as_ref()) {
            (Some(session), Some(host)) => {
                end(host, session).await;
                true
            }
            _ => false,
        }
    }

    /// Stop every session of a deleted runtime.
    pub async fn stop_runtime(&self, runtime_id: &str) {
        let keys: Vec<SessionKey> = self
            .running
            .lock()
            .keys()
            .filter(|(r, _)| r == runtime_id)
            .cloned()
            .collect();
        for (runtime, session) in keys {
            self.stop(&runtime, &session).await;
        }
    }

    async fn reap(&self) {
        let Some(host) = self.host.as_ref() else {
            return;
        };
        let slots: Vec<(SessionKey, Arc<tokio::sync::Mutex<Option<Session>>>)> = self
            .running
            .lock()
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        for (key, slot) in slots {
            let Ok(mut guard) = slot.try_lock() else {
                continue;
            };
            let Some(session) = guard.as_ref() else {
                continue;
            };
            let expired = session.started.elapsed() >= session.max;
            let idle = session.last_used.elapsed() >= session.idle;
            let ended =
                expired || (idle && !busy(&self.http, &host.sibling_host, session.port).await);
            if ended {
                let session = guard.take().expect("checked above");
                drop(guard);
                self.running.lock().remove(&key);
                tracing::info!(runtime = %key.0, session = %key.1, expired, "ending AgentCore runtime session");
                end(host, session).await;
            }
        }
    }
}

async fn busy(http: &reqwest::Client, host: &str, port: u16) -> bool {
    let url = format!("http://{host}:{port}/ping");
    match http.get(url).timeout(Duration::from_secs(5)).send().await {
        Ok(response) => response
            .json::<Value>()
            .await
            .ok()
            .and_then(|v| v["status"].as_str().map(|s| s == "HealthyBusy"))
            .unwrap_or(false),
        Err(_) => false,
    }
}

async fn end(host: &RuntimeHost, session: Session) {
    let _ = tokio::process::Command::new(&host.cli)
        .args(["rm", "-f", &session.container])
        .output()
        .await;
    if let (Some(issuer), Some(credentials)) =
        (host.credentials.as_ref(), session.credentials.as_ref())
    {
        issuer.revoke(credentials);
    }
}

fn extract(zip_bytes: &[u8]) -> Result<tempfile::TempDir, String> {
    let dir = tempfile::Builder::new()
        .prefix("fakecloud-agentcore-")
        .tempdir()
        .map_err(|e| e.to_string())?;
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(zip_bytes))
        .map_err(|e| format!("the code is not a zip: {e}"))?;
    for index in 0..archive.len() {
        let mut entry = archive.by_index(index).map_err(|e| e.to_string())?;
        let Some(relative) = entry.enclosed_name() else {
            continue;
        };
        let path: PathBuf = dir.path().join(relative);
        if entry.is_dir() {
            std::fs::create_dir_all(&path).map_err(|e| e.to_string())?;
            continue;
        }
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        let mut contents = Vec::with_capacity(entry.size() as usize);
        entry
            .read_to_end(&mut contents)
            .map_err(|e| e.to_string())?;
        std::fs::write(&path, contents).map_err(|e| e.to_string())?;
    }
    Ok(dir)
}

async fn start(
    host: &RuntimeHost,
    http: &reqwest::Client,
    runtime: &Value,
    account_id: &str,
    region: &str,
    session_id: &str,
) -> Result<Session, Refusal> {
    let failed = |message: String| Refusal::Failed(StatusCode::FAILED_DEPENDENCY, message);
    let code = runtime
        .pointer("/agentRuntimeArtifact/codeConfiguration")
        .ok_or_else(|| failed("fakecloud runs code-configured agent runtimes; this runtime uses a container image".into()))?;
    let version = code["runtime"].as_str().unwrap_or_default();
    let image = image_for(version).ok_or_else(|| {
        failed(format!(
            "fakecloud runs Python agent runtimes; this one uses {version}"
        ))
    })?;
    let s3 = &code["code"]["s3"];
    let (bucket, key) = (
        s3["bucket"].as_str().unwrap_or_default(),
        s3["prefix"].as_str().unwrap_or_default(),
    );
    let reader = host
        .s3
        .as_ref()
        .ok_or_else(|| failed("fakecloud has no S3 to read the runtime's code from".into()))?;
    let zip_bytes = reader
        .get_object_version(account_id, bucket, key, s3["versionId"].as_str())
        .map_err(|e| {
            failed(format!(
                "The runtime's code could not be read from s3://{bucket}/{key}: {e}"
            ))
        })?;
    let dir = tokio::task::spawn_blocking(move || extract(&zip_bytes))
        .await
        .map_err(|e| failed(e.to_string()))?
        .map_err(failed)?;
    let entry: Vec<String> = code["entryPoint"]
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .filter(|items: &Vec<String>| !items.is_empty())
        .unwrap_or_else(|| vec!["main.py".to_string()]);

    let runtime_id = runtime["agentRuntimeId"].as_str().unwrap_or_default();
    let session_tag: String = session_id
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .take(12)
        .collect();
    let container = format!(
        "fakecloud-agentcore-{}-{session_tag}",
        runtime_id.to_ascii_lowercase().replace('_', "-")
    );
    let credentials = host.credentials.as_ref().and_then(|issuer| {
        runtime["roleArn"].as_str().map(|role| {
            issuer.issue(
                role,
                &format!("agentcore-{session_tag}"),
                chrono::Duration::hours(12),
            )
        })
    });

    let mut args: Vec<String> = vec![
        "run".into(),
        "-d".into(),
        "--name".into(),
        container.clone(),
        "--label".into(),
        "fakecloud-agentcore=1".into(),
        "-p".into(),
        format!("127.0.0.1::{PORT}"),
        "-v".into(),
        format!("{}:/var/task:ro", dir.path().display()),
        "-w".into(),
        "/var/task".into(),
        "--entrypoint".into(),
        "python3".into(),
    ];
    if let Some(alias) = &host.host_alias_arg {
        args.push("--add-host".into());
        args.push(alias.clone());
    }
    args.extend(fakecloud_core::container_net::workload_extra_host_argv());
    args.extend(fakecloud_core::container_net::workload_ca_bundle_argv());
    let mut env: Vec<(String, String)> = vec![
        ("AWS_ENDPOINT_URL".into(), host.endpoint_url.clone()),
        ("AWS_REGION".into(), region.to_string()),
        ("AWS_DEFAULT_REGION".into(), region.to_string()),
        ("PYTHONUNBUFFERED".into(), "1".into()),
    ];
    if let Some(vars) = runtime["environmentVariables"].as_object() {
        for (name, value) in vars {
            if let Some(value) = value.as_str() {
                env.push((
                    name.clone(),
                    fakecloud_core::container_net::rewrite_loopback_value(
                        value,
                        "host.docker.internal",
                    ),
                ));
            }
        }
    }
    if let Some(creds) = &credentials {
        env.push(("AWS_ACCESS_KEY_ID".into(), creds.access_key_id.clone()));
        env.push((
            "AWS_SECRET_ACCESS_KEY".into(),
            creds.secret_access_key.clone(),
        ));
        env.push(("AWS_SESSION_TOKEN".into(), creds.session_token.clone()));
    }
    for (name, value) in &env {
        args.push("-e".into());
        args.push(format!("{name}={value}"));
    }
    args.push(image);
    args.extend(entry);

    let output = tokio::process::Command::new(&host.cli)
        .args(&args)
        .output()
        .await
        .map_err(|e| {
            failed(format!(
                "The container runtime could not start the session: {e}"
            ))
        })?;
    if !output.status.success() {
        return Err(failed(format!(
            "The runtime's container did not start: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    let port_output = tokio::process::Command::new(&host.cli)
        .args(["port", &container, &PORT.to_string()])
        .output()
        .await
        .map_err(|e| failed(e.to_string()))?;
    let port: u16 = String::from_utf8_lossy(&port_output.stdout)
        .lines()
        .next()
        .and_then(|line| line.rsplit(':').next())
        .and_then(|p| p.trim().parse().ok())
        .ok_or_else(|| failed("The runtime's container published no port".into()))?;

    let deadline = Instant::now() + START_TIMEOUT;
    loop {
        let ping = http
            .get(format!("http://{}:{port}/ping", host.sibling_host))
            .timeout(Duration::from_secs(2))
            .send()
            .await;
        if ping.is_ok_and(|r| r.status().is_success()) {
            break;
        }
        let running = tokio::process::Command::new(&host.cli)
            .args(["inspect", "-f", "{{.State.Running}}", &container])
            .output()
            .await
            .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "true")
            .unwrap_or(false);
        if !running || Instant::now() >= deadline {
            let logs = tokio::process::Command::new(&host.cli)
                .args(["logs", "--tail", "30", &container])
                .output()
                .await
                .map(|o| {
                    format!(
                        "{}{}",
                        String::from_utf8_lossy(&o.stdout),
                        String::from_utf8_lossy(&o.stderr)
                    )
                })
                .unwrap_or_default();
            let _ = tokio::process::Command::new(&host.cli)
                .args(["rm", "-f", &container])
                .output()
                .await;
            return Err(failed(format!(
                "The runtime did not become healthy on port {PORT}: {}",
                logs.trim()
            )));
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    let lifecycle = &runtime["lifecycleConfiguration"];
    tracing::info!(runtime = %runtime_id, session = %session_id, container = %container, "started AgentCore runtime session");
    Ok(Session {
        container,
        port,
        started: Instant::now(),
        last_used: Instant::now(),
        idle: Duration::from_secs(
            lifecycle["idleRuntimeSessionTimeout"]
                .as_u64()
                .unwrap_or(900),
        ),
        max: Duration::from_secs(lifecycle["maxLifetime"].as_u64().unwrap_or(28800)),
        credentials,
        _code: dir,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn python_runtimes_map_to_lambda_base_images() {
        assert_eq!(
            image_for("PYTHON_3_14").as_deref(),
            Some("public.ecr.aws/lambda/python:3.14")
        );
        assert_eq!(image_for("NODE_22"), None);
    }

    #[test]
    fn a_sigv4_runtime_refuses_bearer_callers_and_a_jwt_runtime_refuses_sigv4() {
        let sessions = Sessions::new(None);
        let iam_runtime = serde_json::json!({ "agentRuntimeId": "r" });
        let mut signed = HeaderMap::new();
        signed.insert(
            http::header::AUTHORIZATION,
            "AWS4-HMAC-SHA256 Credential=x".parse().unwrap(),
        );
        let mut bearer = HeaderMap::new();
        bearer.insert(
            http::header::AUTHORIZATION,
            "Bearer eyJ.x.y".parse().unwrap(),
        );
        assert!(sessions.authorize(&iam_runtime, &signed).is_ok());
        assert!(matches!(
            sessions.authorize(&iam_runtime, &bearer),
            Err(Refusal::Denied(_))
        ));
        let jwt_runtime = serde_json::json!({ "agentRuntimeId": "r", "authorizerConfiguration": { "customJWTAuthorizer": {
            "discoveryUrl": "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_pool/.well-known/openid-configuration",
            "allowedClients": ["client"] } } });
        assert!(matches!(
            sessions.authorize(&jwt_runtime, &signed),
            Err(Refusal::Denied(_))
        ));
        assert!(matches!(
            sessions.authorize(&jwt_runtime, &bearer),
            Err(Refusal::Denied(_))
        ));
    }
}
