//! The `bedrock-agentcore` service: one handler for the control plane
//! (`bedrock-agentcore-control.<region>`) and the data plane
//! (`bedrock-agentcore.<region>`), which share the signing name and are told
//! apart by their routes.

use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use http::{HeaderValue, Method, StatusCode};
use serde_json::{json, Value};

use fakecloud_core::service::{AwsRequest, AwsResponse, AwsService, AwsServiceError, ResponseBody};

use crate::control::{self, invalid, not_found, runtime_id_of};
use crate::eventstream::result_frame;
use crate::interpreter::Interpreters;
use crate::sessions::{Refusal, Sessions, SESSION_HEADER};
use crate::state::SharedAgentCoreState;

const ACTIONS: &[&str] = &[
    "CreateAgentRuntime",
    "GetAgentRuntime",
    "UpdateAgentRuntime",
    "DeleteAgentRuntime",
    "ListAgentRuntimes",
    "ListAgentRuntimeVersions",
    "GetAgentRuntimeEndpoint",
    "ListAgentRuntimeEndpoints",
    "CreateMemory",
    "GetMemory",
    "UpdateMemory",
    "DeleteMemory",
    "ListMemories",
    "PutResourcePolicy",
    "GetResourcePolicy",
    "DeleteResourcePolicy",
    "TagResource",
    "UntagResource",
    "ListTagsForResource",
    "InvokeAgentRuntime",
    "StopRuntimeSession",
    "CreateEvent",
    "ListEvents",
    "GetEvent",
    "DeleteEvent",
    "ListSessions",
    "ListActors",
    "StartCodeInterpreterSession",
    "InvokeCodeInterpreter",
    "StopCodeInterpreterSession",
    "GetCodeInterpreterSession",
];

pub struct AgentCoreService {
    state: SharedAgentCoreState,
    sessions: Arc<Sessions>,
    interpreters: Arc<Interpreters>,
}

impl AgentCoreService {
    pub fn new(
        state: SharedAgentCoreState,
        sessions: Arc<Sessions>,
        interpreters: Arc<Interpreters>,
    ) -> Self {
        Self {
            state,
            sessions,
            interpreters,
        }
    }

    fn body(request: &AwsRequest) -> Result<Value, AwsServiceError> {
        if request.body.is_empty() {
            return Ok(json!({}));
        }
        serde_json::from_slice(&request.body)
            .map_err(|e| invalid(format!("The request body is not JSON: {e}")))
    }

    fn header<'a>(request: &'a AwsRequest, name: &str) -> Option<&'a str> {
        request.headers.get(name).and_then(|v| v.to_str().ok())
    }

    fn control(
        &self,
        request: &AwsRequest,
        segments: &[&str],
    ) -> Option<Result<AwsResponse, AwsServiceError>> {
        let account = request.account_id.as_str();
        let region = request.region.as_str();
        let method = &request.method;
        let body = match Self::body(request) {
            Ok(body) => body,
            Err(e) => return Some(Err(e)),
        };
        let mut guard = self.state.write();
        let data = guard.get_or_create(account);
        let result = match (method, segments) {
            (&Method::PUT, ["runtimes"]) => {
                control::create_agent_runtime(data, account, region, &body)
            }
            (&Method::POST, ["runtimes"]) => Ok(control::list_agent_runtimes(data)),
            (&Method::GET, ["runtimes", id]) => control::get_agent_runtime(
                data,
                id,
                request.query_params.get("version").map(String::as_str),
            ),
            (&Method::PUT, ["runtimes", id]) => control::update_agent_runtime(data, id, &body),
            (&Method::DELETE, ["runtimes", id]) => {
                let id = runtime_id_of(id).to_string();
                let sessions = self.sessions.clone();
                let stopping = id.clone();
                tokio::spawn(async move { sessions.stop_runtime(&stopping).await });
                control::delete_agent_runtime(data, &id)
            }
            (&Method::POST, ["runtimes", id, "versions"]) => {
                control::list_agent_runtime_versions(data, id)
            }
            (&Method::GET, ["runtimes", id, "runtime-endpoints", name]) => {
                control::get_agent_runtime_endpoint(data, id, name)
            }
            (&Method::POST, ["runtimes", id, "runtime-endpoints"]) => {
                control::list_agent_runtime_endpoints(data, id)
            }
            (&Method::POST, ["memories", "create"]) => {
                control::create_memory(data, account, region, &body)
            }
            (&Method::POST, ["memories"]) => Ok(control::list_memories(data)),
            (&Method::GET, ["memories", id, "details"]) => control::get_memory(data, id),
            (&Method::PUT, ["memories", id, "update"]) => control::update_memory(data, id, &body),
            (&Method::DELETE, ["memories", id, "delete"]) => control::delete_memory(data, id),
            (&Method::PUT, ["resourcepolicy", arn]) => {
                control::put_resource_policy(data, arn, &body)
            }
            (&Method::GET, ["resourcepolicy", arn]) => control::get_resource_policy(data, arn),
            (&Method::DELETE, ["resourcepolicy", arn]) => {
                control::delete_resource_policy(data, arn)
            }
            (&Method::POST, ["tags", arn]) => Ok(control::tag_resource(data, arn, &body)),
            (&Method::GET, ["tags", arn]) => Ok(control::list_tags(data, arn)),
            (&Method::DELETE, ["tags", arn]) => {
                let keys: Vec<String> = form_values(&request.raw_query, "tagKeys");
                Ok(control::untag_resource(data, arn, &keys))
            }
            (&Method::POST, ["memories", id, "events"]) => control::create_event(data, id, &body),
            (&Method::POST, ["memories", id, "actor", actor, "sessions", session]) => {
                control::list_events(data, id, actor, session, &body)
            }
            (
                &Method::GET,
                ["memories", id, "actor", actor, "sessions", session, "events", event],
            ) => control::get_event(data, id, actor, session, event),
            (
                &Method::DELETE,
                ["memories", id, "actor", actor, "sessions", session, "events", event],
            ) => control::delete_event(data, id, actor, session, event),
            (&Method::POST, ["memories", id, "actor", actor, "sessions"]) => {
                control::list_sessions(data, id, actor, &body)
            }
            (&Method::POST, ["memories", id, "actors"]) => control::list_actors(data, id, &body),
            _ => return None,
        };
        Some(result)
    }

    async fn invoke_runtime(
        &self,
        request: &AwsRequest,
        identifier: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        let runtime = {
            let guard = self.state.read();
            guard
                .get(&request.account_id)
                .and_then(|data| data.runtimes.get(runtime_id_of(identifier)).cloned())
                .ok_or_else(|| not_found(&format!("Agent runtime {identifier}")))?
        };
        let session_id = Self::header(request, SESSION_HEADER)
            .map(str::to_string)
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        if session_id.len() < 33 {
            return Err(invalid(
                "runtimeSessionId must be at least 33 characters long",
            ));
        }
        let answer = match self.sessions.authorize(&runtime, &request.headers) {
            Ok(()) => {
                self.sessions
                    .invoke(
                        &runtime,
                        &request.account_id,
                        &request.region,
                        &session_id,
                        &request.headers,
                        request.body.clone(),
                    )
                    .await
            }
            Err(refusal) => Err(refusal),
        };
        let answer = answer.map_err(|refusal| match refusal {
            Refusal::Denied(message) => {
                AwsServiceError::aws_error(StatusCode::FORBIDDEN, "AccessDeniedException", message)
            }
            Refusal::Invalid(message) => invalid(message),
            Refusal::Failed(status, message) => {
                AwsServiceError::aws_error(status, "RuntimeClientError", message)
            }
        })?;
        let mut response = AwsResponse {
            status: answer.status,
            content_type: answer.content_type,
            body: ResponseBody::Bytes(answer.body),
            headers: http::HeaderMap::new(),
        };
        if let Ok(value) = HeaderValue::from_str(&session_id) {
            response.headers.insert(SESSION_HEADER, value);
        }
        Ok(response)
    }

    async fn code_interpreter(
        &self,
        request: &AwsRequest,
        identifier: &str,
        operation: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        let body = Self::body(request)?;
        let session_query = request.query_params.get("sessionId").map(String::as_str);
        match operation {
            "start" => Ok(AwsResponse::ok_json(self.interpreters.start(
                identifier,
                body["name"].as_str(),
                body["sessionTimeoutSeconds"].as_u64(),
            ))),
            "get" => {
                let id = session_query.ok_or_else(|| invalid("sessionId is required"))?;
                self.interpreters
                    .describe(identifier, id)
                    .map(AwsResponse::ok_json)
                    .ok_or_else(|| not_found(&format!("Session {id}")))
            }
            "stop" => {
                let id = session_query.ok_or_else(|| invalid("sessionId is required"))?;
                if !self.interpreters.stop(id).await {
                    return Err(not_found(&format!("Session {id}")));
                }
                Ok(AwsResponse::ok_json(json!({
                    "codeInterpreterIdentifier": identifier,
                    "sessionId": id,
                    "lastUpdatedAt": crate::state::now_iso(),
                })))
            }
            _ => {
                let id = Self::header(request, "x-amzn-code-interpreter-session-id")
                    .ok_or_else(|| invalid("x-amzn-code-interpreter-session-id is required"))?
                    .to_string();
                let name = body["name"]
                    .as_str()
                    .ok_or_else(|| invalid("name is required"))?;
                let result = self
                    .interpreters
                    .invoke(identifier, &id, name, &body["arguments"])
                    .await
                    .map_err(|message| {
                        if message.ends_with("not found") {
                            not_found(&format!("Session {id}"))
                        } else {
                            AwsServiceError::aws_error(
                                StatusCode::INTERNAL_SERVER_ERROR,
                                "InternalServerException",
                                message,
                            )
                        }
                    })?;
                let mut response = AwsResponse {
                    status: StatusCode::OK,
                    content_type: "application/vnd.amazon.eventstream".to_string(),
                    body: ResponseBody::Bytes(Bytes::from(result_frame(
                        result.to_string().as_bytes(),
                    ))),
                    headers: http::HeaderMap::new(),
                };
                if let Ok(value) = HeaderValue::from_str(&id) {
                    response
                        .headers
                        .insert("x-amzn-code-interpreter-session-id", value);
                }
                Ok(response)
            }
        }
    }
}

fn form_values(query: &str, name: &str) -> Vec<String> {
    query
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .filter(|(key, _)| *key == name)
        .map(|(_, value)| {
            percent_encoding::percent_decode_str(&value.replace('+', " "))
                .decode_utf8_lossy()
                .into_owned()
        })
        .collect()
}

#[async_trait]
impl AwsService for AgentCoreService {
    fn service_name(&self) -> &str {
        "bedrock-agentcore"
    }

    async fn handle(&self, request: AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let segments: Vec<&str> = request.path_segments.iter().map(String::as_str).collect();
        match (&request.method, segments.as_slice()) {
            (&Method::POST, ["runtimes", arn, "invocations"]) => {
                return self.invoke_runtime(&request, arn).await
            }
            (&Method::POST, ["runtimes", arn, "stopruntimesession"]) => {
                let session = Self::header(&request, SESSION_HEADER)
                    .ok_or_else(|| invalid("runtimeSessionId is required"))?;
                if !self.sessions.stop(runtime_id_of(arn), session).await {
                    return Err(not_found(&format!("Runtime session {session}")));
                }
                let mut response = AwsResponse::ok_json(json!({}));
                if let Ok(value) = HeaderValue::from_str(session) {
                    response.headers.insert(SESSION_HEADER, value);
                }
                return Ok(response);
            }
            (&Method::PUT, ["code-interpreters", id, "sessions", op @ ("start" | "stop")])
            | (&Method::GET, ["code-interpreters", id, "sessions", op @ "get"])
            | (&Method::POST, ["code-interpreters", id, "tools", op @ "invoke"]) => {
                return self.code_interpreter(&request, id, op).await
            }
            _ => {}
        }
        self.control(&request, &segments).unwrap_or_else(|| {
            Err(AwsServiceError::aws_error(
                StatusCode::NOT_FOUND,
                "UnknownOperationException",
                format!("Unknown operation: {} {}", request.method, request.raw_path),
            ))
        })
    }

    fn supported_actions(&self) -> &[&str] {
        ACTIONS
    }
}
