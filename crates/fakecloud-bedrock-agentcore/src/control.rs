//! The control plane (`bedrock-agentcore-control`) operations Terraform and
//! the AWS SDKs use for agent runtimes, memories, resource policies and tags,
//! and the short-term memory events of the data plane.

use http::StatusCode;
use serde_json::{json, Map, Value};

use fakecloud_core::service::{AwsResponse, AwsServiceError};

use crate::state::{generated_id, now_epoch, now_iso, AgentCoreData};

pub(crate) fn not_found(what: &str) -> AwsServiceError {
    AwsServiceError::aws_error(
        StatusCode::NOT_FOUND,
        "ResourceNotFoundException",
        format!("{what} not found"),
    )
}

pub(crate) fn invalid(message: impl Into<String>) -> AwsServiceError {
    AwsServiceError::aws_error(
        StatusCode::BAD_REQUEST,
        "ValidationException",
        message.into(),
    )
}

fn conflict(message: impl Into<String>) -> AwsServiceError {
    AwsServiceError::aws_error(StatusCode::CONFLICT, "ConflictException", message.into())
}

fn json_status(status: StatusCode, value: Value) -> AwsResponse {
    AwsResponse::json_value(status, value)
}

fn required<'a>(body: &'a Value, name: &str) -> Result<&'a Value, AwsServiceError> {
    body.get(name)
        .filter(|v| !v.is_null())
        .ok_or_else(|| invalid(format!("{name} is required")))
}

fn set_tags(data: &mut AgentCoreData, arn: &str, tags: Option<&Value>) {
    if let Some(tags) = tags.and_then(Value::as_object) {
        let entry = data.tags.entry(arn.to_string()).or_default();
        for (k, v) in tags {
            if let Some(v) = v.as_str() {
                entry.insert(k.clone(), v.to_string());
            }
        }
    }
}

/// The runtime a path names: by id, or by its ARN (data-plane paths carry the ARN).
pub(crate) fn runtime_id_of(identifier: &str) -> &str {
    identifier.rsplit('/').next().unwrap_or(identifier)
}

const RUNTIME_MEMBERS: [&str; 10] = [
    "agentRuntimeArtifact",
    "networkConfiguration",
    "description",
    "authorizerConfiguration",
    "requestHeaderConfiguration",
    "protocolConfiguration",
    "lifecycleConfiguration",
    "environmentVariables",
    "filesystemConfigurations",
    "metadataConfiguration",
];

pub(crate) fn create_agent_runtime(
    data: &mut AgentCoreData,
    account_id: &str,
    region: &str,
    body: &Value,
) -> Result<AwsResponse, AwsServiceError> {
    let name = required(body, "agentRuntimeName")?
        .as_str()
        .ok_or_else(|| invalid("agentRuntimeName must be a string"))?;
    required(body, "agentRuntimeArtifact")?;
    let role_arn = required(body, "roleArn")?.as_str().unwrap_or_default();
    if data
        .runtimes
        .values()
        .any(|r| r.get("agentRuntimeName").and_then(Value::as_str) == Some(name))
    {
        return Err(conflict(format!(
            "An agent runtime named {name} already exists"
        )));
    }
    let id = generated_id(name);
    let arn = format!("arn:aws:bedrock-agentcore:{region}:{account_id}:runtime/{id}");
    let now = now_iso();
    let mut runtime = Map::new();
    runtime.insert("agentRuntimeArn".into(), json!(arn));
    runtime.insert("agentRuntimeName".into(), json!(name));
    runtime.insert("agentRuntimeId".into(), json!(id));
    runtime.insert("agentRuntimeVersion".into(), json!("1"));
    runtime.insert("createdAt".into(), json!(now));
    runtime.insert("lastUpdatedAt".into(), json!(now));
    runtime.insert("roleArn".into(), json!(role_arn));
    runtime.insert("status".into(), json!("READY"));
    runtime.insert(
        "workloadIdentityDetails".into(),
        json!({ "workloadIdentityArn": format!("arn:aws:bedrock-agentcore:{region}:{account_id}:workload-identity-directory/default/workload-identity/{name}") }),
    );
    runtime.insert(
        "lifecycleConfiguration".into(),
        json!({ "idleRuntimeSessionTimeout": 900, "maxLifetime": 28800 }),
    );
    for member in RUNTIME_MEMBERS {
        if let Some(value) = body.get(member).filter(|v| !v.is_null()) {
            runtime.insert(member.into(), value.clone());
        }
    }
    let runtime = Value::Object(runtime);
    set_tags(data, &arn, body.get("tags"));
    data.runtime_versions
        .insert(id.clone(), vec![runtime.clone()]);
    data.runtimes.insert(id.clone(), runtime.clone());
    Ok(json_status(
        StatusCode::ACCEPTED,
        json!({
            "agentRuntimeArn": arn,
            "agentRuntimeId": id,
            "agentRuntimeVersion": "1",
            "workloadIdentityDetails": runtime["workloadIdentityDetails"],
            "createdAt": now,
            "status": "READY",
        }),
    ))
}

pub(crate) fn get_agent_runtime(
    data: &AgentCoreData,
    id: &str,
    version: Option<&str>,
) -> Result<AwsResponse, AwsServiceError> {
    let id = runtime_id_of(id);
    let runtime = match version {
        Some(version) => data.runtime_versions.get(id).and_then(|all| {
            all.iter()
                .find(|r| r["agentRuntimeVersion"] == json!(version))
        }),
        None => data.runtimes.get(id),
    }
    .ok_or_else(|| not_found(&format!("Agent runtime {id}")))?;
    Ok(AwsResponse::ok_json(runtime.clone()))
}

pub(crate) fn update_agent_runtime(
    data: &mut AgentCoreData,
    id: &str,
    body: &Value,
) -> Result<AwsResponse, AwsServiceError> {
    let id = runtime_id_of(id).to_string();
    let current = data
        .runtimes
        .get(&id)
        .cloned()
        .ok_or_else(|| not_found(&format!("Agent runtime {id}")))?;
    let mut runtime = current.as_object().cloned().unwrap_or_default();
    let version = current["agentRuntimeVersion"]
        .as_str()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(1)
        + 1;
    for member in RUNTIME_MEMBERS {
        match body.get(member) {
            Some(value) if !value.is_null() => {
                runtime.insert(member.into(), value.clone());
            }
            _ if member != "lifecycleConfiguration" => {
                runtime.remove(member);
            }
            _ => {}
        }
    }
    if let Some(role) = body.get("roleArn").and_then(Value::as_str) {
        runtime.insert("roleArn".into(), json!(role));
    }
    let now = now_iso();
    runtime.insert("agentRuntimeVersion".into(), json!(version.to_string()));
    runtime.insert("lastUpdatedAt".into(), json!(now));
    runtime.insert("status".into(), json!("READY"));
    let runtime = Value::Object(runtime);
    data.runtime_versions
        .entry(id.clone())
        .or_default()
        .push(runtime.clone());
    data.runtimes.insert(id.clone(), runtime.clone());
    Ok(json_status(
        StatusCode::ACCEPTED,
        json!({
            "agentRuntimeArn": runtime["agentRuntimeArn"],
            "agentRuntimeId": id,
            "agentRuntimeVersion": version.to_string(),
            "workloadIdentityDetails": runtime["workloadIdentityDetails"],
            "createdAt": runtime["createdAt"],
            "lastUpdatedAt": now,
            "status": "READY",
        }),
    ))
}

pub(crate) fn delete_agent_runtime(
    data: &mut AgentCoreData,
    id: &str,
) -> Result<AwsResponse, AwsServiceError> {
    let id = runtime_id_of(id);
    let runtime = data
        .runtimes
        .remove(id)
        .ok_or_else(|| not_found(&format!("Agent runtime {id}")))?;
    data.runtime_versions.remove(id);
    if let Some(arn) = runtime["agentRuntimeArn"].as_str() {
        data.tags.remove(arn);
        data.policies.remove(arn);
    }
    Ok(json_status(
        StatusCode::ACCEPTED,
        json!({ "status": "DELETING", "agentRuntimeId": id, "agentRuntimeArn": runtime["agentRuntimeArn"] }),
    ))
}

fn summary(runtime: &Value) -> Value {
    json!({
        "agentRuntimeArn": runtime["agentRuntimeArn"],
        "agentRuntimeId": runtime["agentRuntimeId"],
        "agentRuntimeVersion": runtime["agentRuntimeVersion"],
        "agentRuntimeName": runtime["agentRuntimeName"],
        "description": runtime.get("description").cloned().unwrap_or(json!("")),
        "lastUpdatedAt": runtime["lastUpdatedAt"],
        "status": runtime["status"],
    })
}

pub(crate) fn list_agent_runtimes(data: &AgentCoreData) -> AwsResponse {
    AwsResponse::ok_json(
        json!({ "agentRuntimes": data.runtimes.values().map(summary).collect::<Vec<_>>() }),
    )
}

pub(crate) fn list_agent_runtime_versions(
    data: &AgentCoreData,
    id: &str,
) -> Result<AwsResponse, AwsServiceError> {
    let id = runtime_id_of(id);
    let versions = data
        .runtime_versions
        .get(id)
        .ok_or_else(|| not_found(&format!("Agent runtime {id}")))?;
    Ok(AwsResponse::ok_json(
        json!({ "agentRuntimes": versions.iter().rev().map(summary).collect::<Vec<_>>() }),
    ))
}

/// The `DEFAULT` endpoint AgentCore keeps on every runtime's latest version.
fn default_endpoint(runtime: &Value) -> Value {
    let arn = runtime["agentRuntimeArn"].as_str().unwrap_or_default();
    json!({
        "name": "DEFAULT",
        "liveVersion": runtime["agentRuntimeVersion"],
        "agentRuntimeEndpointArn": format!("{}/runtime-endpoint/DEFAULT", arn),
        "agentRuntimeArn": arn,
        "status": "READY",
        "id": "DEFAULT",
        "createdAt": runtime["createdAt"],
        "lastUpdatedAt": runtime["lastUpdatedAt"],
    })
}

pub(crate) fn get_agent_runtime_endpoint(
    data: &AgentCoreData,
    id: &str,
    name: &str,
) -> Result<AwsResponse, AwsServiceError> {
    let runtime = data
        .runtimes
        .get(runtime_id_of(id))
        .ok_or_else(|| not_found(&format!("Agent runtime {id}")))?;
    if name != "DEFAULT" {
        return Err(not_found(&format!("Agent runtime endpoint {name}")));
    }
    Ok(AwsResponse::ok_json(default_endpoint(runtime)))
}

pub(crate) fn list_agent_runtime_endpoints(
    data: &AgentCoreData,
    id: &str,
) -> Result<AwsResponse, AwsServiceError> {
    let runtime = data
        .runtimes
        .get(runtime_id_of(id))
        .ok_or_else(|| not_found(&format!("Agent runtime {id}")))?;
    Ok(AwsResponse::ok_json(
        json!({ "runtimeEndpoints": [default_endpoint(runtime)] }),
    ))
}

pub(crate) fn create_memory(
    data: &mut AgentCoreData,
    account_id: &str,
    region: &str,
    body: &Value,
) -> Result<AwsResponse, AwsServiceError> {
    let name = required(body, "name")?
        .as_str()
        .ok_or_else(|| invalid("name must be a string"))?;
    let expiry = required(body, "eventExpiryDuration")?
        .as_i64()
        .ok_or_else(|| invalid("eventExpiryDuration must be a number"))?;
    if !(3..=365).contains(&expiry) {
        return Err(invalid(
            "eventExpiryDuration must be between 3 and 365 days",
        ));
    }
    if data
        .memories
        .values()
        .any(|m| m.get("name").and_then(Value::as_str) == Some(name))
    {
        return Err(conflict(format!("A memory named {name} already exists")));
    }
    let id = generated_id(name);
    let arn = format!("arn:aws:bedrock-agentcore:{region}:{account_id}:memory/{id}");
    let now = now_epoch();
    let mut memory = Map::new();
    memory.insert("arn".into(), json!(arn));
    memory.insert("id".into(), json!(id));
    memory.insert("name".into(), json!(name));
    memory.insert("eventExpiryDuration".into(), json!(expiry));
    memory.insert("status".into(), json!("ACTIVE"));
    memory.insert("createdAt".into(), json!(now));
    memory.insert("updatedAt".into(), json!(now));
    memory.insert("strategies".into(), json!([]));
    for member in [
        "description",
        "encryptionKeyArn",
        "memoryExecutionRoleArn",
        "indexedKeys",
        "namespaceKeys",
        "streamDeliveryResources",
    ] {
        if let Some(value) = body.get(member).filter(|v| !v.is_null()) {
            memory.insert(member.into(), value.clone());
        }
    }
    if body
        .get("memoryStrategies")
        .and_then(Value::as_array)
        .is_some_and(|s| !s.is_empty())
    {
        return Err(invalid("fakecloud's AgentCore Memory keeps short-term events only; memoryStrategies (long-term extraction) are not supported"));
    }
    let memory = Value::Object(memory);
    set_tags(data, &arn, body.get("tags"));
    data.memories.insert(id.clone(), memory.clone());
    Ok(json_status(
        StatusCode::ACCEPTED,
        json!({ "memory": memory }),
    ))
}

pub(crate) fn get_memory(data: &AgentCoreData, id: &str) -> Result<AwsResponse, AwsServiceError> {
    let memory = data
        .memories
        .get(id)
        .ok_or_else(|| not_found(&format!("Memory {id}")))?;
    Ok(AwsResponse::ok_json(json!({ "memory": memory })))
}

pub(crate) fn update_memory(
    data: &mut AgentCoreData,
    id: &str,
    body: &Value,
) -> Result<AwsResponse, AwsServiceError> {
    let memory = data
        .memories
        .get_mut(id)
        .ok_or_else(|| not_found(&format!("Memory {id}")))?;
    for member in [
        "description",
        "eventExpiryDuration",
        "memoryExecutionRoleArn",
        "streamDeliveryResources",
    ] {
        if let Some(value) = body.get(member).filter(|v| !v.is_null()) {
            memory[member] = value.clone();
        }
    }
    memory["updatedAt"] = json!(now_epoch());
    Ok(json_status(
        StatusCode::ACCEPTED,
        json!({ "memory": memory.clone() }),
    ))
}

pub(crate) fn delete_memory(
    data: &mut AgentCoreData,
    id: &str,
) -> Result<AwsResponse, AwsServiceError> {
    let memory = data
        .memories
        .remove(id)
        .ok_or_else(|| not_found(&format!("Memory {id}")))?;
    data.events.remove(id);
    if let Some(arn) = memory["arn"].as_str() {
        data.tags.remove(arn);
    }
    Ok(json_status(
        StatusCode::ACCEPTED,
        json!({ "memoryId": id, "status": "DELETING" }),
    ))
}

pub(crate) fn list_memories(data: &AgentCoreData) -> AwsResponse {
    let memories: Vec<Value> = data
        .memories
        .values()
        .map(|m| json!({ "arn": m["arn"], "id": m["id"], "status": m["status"], "createdAt": m["createdAt"], "updatedAt": m["updatedAt"] }))
        .collect();
    AwsResponse::ok_json(json!({ "memories": memories }))
}

pub(crate) fn put_resource_policy(
    data: &mut AgentCoreData,
    arn: &str,
    body: &Value,
) -> Result<AwsResponse, AwsServiceError> {
    let policy = required(body, "policy")?
        .as_str()
        .ok_or_else(|| invalid("policy must be a string"))?;
    serde_json::from_str::<Value>(policy).map_err(|_| invalid("policy is not a JSON document"))?;
    data.policies.insert(arn.to_string(), policy.to_string());
    Ok(AwsResponse::ok_json(json!({ "policy": policy })))
}

pub(crate) fn get_resource_policy(
    data: &AgentCoreData,
    arn: &str,
) -> Result<AwsResponse, AwsServiceError> {
    let policy = data
        .policies
        .get(arn)
        .ok_or_else(|| not_found(&format!("Resource policy for {arn}")))?;
    Ok(AwsResponse::ok_json(json!({ "policy": policy })))
}

pub(crate) fn delete_resource_policy(
    data: &mut AgentCoreData,
    arn: &str,
) -> Result<AwsResponse, AwsServiceError> {
    data.policies
        .remove(arn)
        .ok_or_else(|| not_found(&format!("Resource policy for {arn}")))?;
    Ok(AwsResponse::ok_json(json!({})))
}

pub(crate) fn tag_resource(data: &mut AgentCoreData, arn: &str, body: &Value) -> AwsResponse {
    set_tags(data, arn, body.get("tags"));
    AwsResponse::ok_json(json!({}))
}

pub(crate) fn untag_resource(data: &mut AgentCoreData, arn: &str, keys: &[String]) -> AwsResponse {
    if let Some(tags) = data.tags.get_mut(arn) {
        for key in keys {
            tags.remove(key);
        }
    }
    AwsResponse::ok_json(json!({}))
}

pub(crate) fn list_tags(data: &AgentCoreData, arn: &str) -> AwsResponse {
    AwsResponse::ok_json(json!({ "tags": data.tags.get(arn).cloned().unwrap_or_default() }))
}

// ---- short-term memory events (data plane) ----

pub(crate) fn create_event(
    data: &mut AgentCoreData,
    memory_id: &str,
    body: &Value,
) -> Result<AwsResponse, AwsServiceError> {
    if !data.memories.contains_key(memory_id) {
        return Err(not_found(&format!("Memory {memory_id}")));
    }
    let actor = required(body, "actorId")?
        .as_str()
        .unwrap_or_default()
        .to_string();
    let session = body
        .get("sessionId")
        .and_then(Value::as_str)
        .map(str::to_string)
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    let timestamp = required(body, "eventTimestamp")?
        .as_f64()
        .ok_or_else(|| invalid("eventTimestamp must be a timestamp"))?;
    let payload = required(body, "payload")?;
    if !payload.as_array().is_some_and(|p| !p.is_empty()) {
        return Err(invalid("payload must hold at least one item"));
    }
    let event_id = format!(
        "{:019}#{}",
        (timestamp * 1000.0) as i64,
        &uuid::Uuid::new_v4().simple().to_string()[..8]
    );
    let mut event = json!({
        "memoryId": memory_id,
        "actorId": actor,
        "sessionId": session,
        "eventId": event_id,
        "eventTimestamp": timestamp,
        "payload": payload,
    });
    for member in ["branch", "metadata"] {
        if let Some(value) = body.get(member).filter(|v| !v.is_null()) {
            event[member] = value.clone();
        }
    }
    data.events
        .entry(memory_id.to_string())
        .or_default()
        .push(event.clone());
    Ok(json_status(StatusCode::CREATED, json!({ "event": event })))
}

fn page(items: Vec<Value>, body: &Value, key: &str) -> Result<AwsResponse, AwsServiceError> {
    let max = body
        .get("maxResults")
        .and_then(Value::as_u64)
        .unwrap_or(20)
        .clamp(1, 100) as usize;
    let start = match body.get("nextToken").and_then(Value::as_str) {
        Some(token) => token
            .parse::<usize>()
            .map_err(|_| invalid("nextToken is not valid"))?,
        None => 0,
    };
    let slice: Vec<Value> = items.iter().skip(start).take(max).cloned().collect();
    let mut out = json!({ key: slice });
    if start + max < items.len() {
        out["nextToken"] = json!((start + max).to_string());
    }
    Ok(AwsResponse::ok_json(out))
}

pub(crate) fn list_events(
    data: &AgentCoreData,
    memory_id: &str,
    actor: &str,
    session: &str,
    body: &Value,
) -> Result<AwsResponse, AwsServiceError> {
    if !data.memories.contains_key(memory_id) {
        return Err(not_found(&format!("Memory {memory_id}")));
    }
    let include = body
        .get("includePayloads")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    let branch = body.pointer("/filter/branch/name").and_then(Value::as_str);
    let mut events: Vec<Value> = data
        .events
        .get(memory_id)
        .map(|all| {
            all.iter()
                .filter(|e| e["actorId"] == json!(actor) && e["sessionId"] == json!(session))
                .filter(|e| {
                    branch.is_none_or(|b| {
                        e.pointer("/branch/name").and_then(Value::as_str) == Some(b)
                    })
                })
                .cloned()
                .collect()
        })
        .unwrap_or_default();
    events.sort_by(|a, b| {
        a["eventTimestamp"]
            .as_f64()
            .partial_cmp(&b["eventTimestamp"].as_f64())
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    if !include {
        for event in &mut events {
            event["payload"] = json!([]);
        }
    }
    page(events, body, "events")
}

pub(crate) fn get_event(
    data: &AgentCoreData,
    memory_id: &str,
    actor: &str,
    session: &str,
    event_id: &str,
) -> Result<AwsResponse, AwsServiceError> {
    let event = data
        .events
        .get(memory_id)
        .and_then(|all| {
            all.iter().find(|e| {
                e["eventId"] == json!(event_id)
                    && e["actorId"] == json!(actor)
                    && e["sessionId"] == json!(session)
            })
        })
        .ok_or_else(|| not_found(&format!("Event {event_id}")))?;
    Ok(AwsResponse::ok_json(json!({ "event": event })))
}

pub(crate) fn delete_event(
    data: &mut AgentCoreData,
    memory_id: &str,
    actor: &str,
    session: &str,
    event_id: &str,
) -> Result<AwsResponse, AwsServiceError> {
    let events = data
        .events
        .get_mut(memory_id)
        .ok_or_else(|| not_found(&format!("Event {event_id}")))?;
    let before = events.len();
    events.retain(|e| {
        !(e["eventId"] == json!(event_id)
            && e["actorId"] == json!(actor)
            && e["sessionId"] == json!(session))
    });
    if events.len() == before {
        return Err(not_found(&format!("Event {event_id}")));
    }
    Ok(AwsResponse::ok_json(json!({ "eventId": event_id })))
}

pub(crate) fn list_sessions(
    data: &AgentCoreData,
    memory_id: &str,
    actor: &str,
    body: &Value,
) -> Result<AwsResponse, AwsServiceError> {
    if !data.memories.contains_key(memory_id) {
        return Err(not_found(&format!("Memory {memory_id}")));
    }
    let mut seen: Vec<(String, f64)> = Vec::new();
    for event in data
        .events
        .get(memory_id)
        .into_iter()
        .flatten()
        .filter(|e| e["actorId"] == json!(actor))
    {
        let session = event["sessionId"].as_str().unwrap_or_default().to_string();
        let at = event["eventTimestamp"].as_f64().unwrap_or_default();
        match seen.iter_mut().find(|(s, _)| *s == session) {
            Some(entry) => entry.1 = entry.1.min(at),
            None => seen.push((session, at)),
        }
    }
    let sessions = seen
        .into_iter()
        .map(|(session, at)| json!({ "sessionId": session, "actorId": actor, "createdAt": at }))
        .collect();
    page(sessions, body, "sessionSummaries")
}

pub(crate) fn list_actors(
    data: &AgentCoreData,
    memory_id: &str,
    body: &Value,
) -> Result<AwsResponse, AwsServiceError> {
    if !data.memories.contains_key(memory_id) {
        return Err(not_found(&format!("Memory {memory_id}")));
    }
    let mut actors: Vec<String> = data
        .events
        .get(memory_id)
        .into_iter()
        .flatten()
        .filter_map(|e| e["actorId"].as_str().map(str::to_string))
        .collect();
    actors.sort();
    actors.dedup();
    page(
        actors
            .into_iter()
            .map(|a| json!({ "actorId": a }))
            .collect(),
        body,
        "actorSummaries",
    )
}
