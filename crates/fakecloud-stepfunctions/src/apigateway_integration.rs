//! The optimized API Gateway integration, `arn:aws:states:::apigateway:invoke`
//! and its `.waitForTaskToken` form: the task's arguments become one request to
//! the API's execute-api endpoint, served by the registered `apigateway` service
//! exactly as a client's request to `{api-id}.execute-api.{region}.amazonaws.com`.
//!
//! A 2XX response is the task's output (`ResponseBody`, `Headers`, `StatusCode`,
//! `StatusText`); any other status fails the task with `ApiGateway.<status>`
//! and the response body as the cause, as Step Functions reports it.

use std::collections::HashMap;
use std::sync::Arc;

use bytes::Bytes;
use fakecloud_core::registry::ServiceRegistry;
use fakecloud_core::service::{AwsRequest, AwsResponse, ResponseBody};
use http::header::{HeaderName, HeaderValue, CONTENT_TYPE, HOST};
use http::{HeaderMap, Method, StatusCode};
use percent_encoding::{utf8_percent_encode, AsciiSet, NON_ALPHANUMERIC};
use serde_json::{json, Map, Value};

const METHODS: [&str; 7] = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"];
const BODY_METHODS: [&str; 3] = ["PATCH", "POST", "PUT"];
const AUTH_TYPES: [&str; 3] = ["NO_AUTH", "IAM_ROLE", "RESOURCE_POLICY"];
const FORBIDDEN_PREFIXES: [&str; 3] = ["x-forwarded", "x-amz", "x-amzn"];
const FORBIDDEN_HEADERS: [&str; 14] = [
    "authorization",
    "connection",
    "content-md5",
    "expect",
    "host",
    "max-forwards",
    "proxy-authenticate",
    "server",
    "te",
    "transfer-encoding",
    "trailer",
    "upgrade",
    "via",
    "www-authenticate",
];
/// RFC 3986 unreserved characters stay literal in a query component.
const QUERY_COMPONENT: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

type TaskError = (String, String);

fn invalid(message: impl Into<String>) -> TaskError {
    ("States.TaskFailed".to_string(), message.into())
}

/// The parsed task arguments: everything needed to build the request.
struct Invocation {
    api_id: String,
    region: String,
    host: String,
    method: Method,
    raw_path: String,
    query: Vec<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
}

/// Call the API the task's arguments name and shape the result as Step
/// Functions does.
pub(crate) async fn invoke(
    registry: &Arc<ServiceRegistry>,
    input: &Value,
    account_id: &str,
    timeout_seconds: Option<u64>,
) -> Result<Value, TaskError> {
    let invocation = parse(input)?;
    let service = registry.get("apigateway").ok_or_else(|| {
        invalid("API Gateway is not available for the apigateway:invoke integration")
    })?;
    let request = invocation.into_request(account_id);
    let call = service.handle(request);
    let outcome = match timeout_seconds {
        Some(seconds) => tokio::time::timeout(std::time::Duration::from_secs(seconds), call)
            .await
            .map_err(|_| {
                (
                    "States.Timeout".to_string(),
                    format!("Task timed out after {seconds} seconds"),
                )
            })?,
        None => call.await,
    };
    match outcome {
        Ok(response) => into_result(response).await,
        Err(error) => Err((
            format!("ApiGateway.{}", error.status().as_u16()),
            json!({"message": error.message()}).to_string(),
        )),
    }
}

fn parse(input: &Value) -> Result<Invocation, TaskError> {
    let endpoint = input["ApiEndpoint"]
        .as_str()
        .ok_or_else(|| invalid("The field 'ApiEndpoint' is required"))?;
    let (api_id, region) = parse_endpoint(endpoint)?;

    let method_name = input["Method"]
        .as_str()
        .ok_or_else(|| invalid("The field 'Method' is required"))?;
    if !METHODS.contains(&method_name) {
        return Err(invalid(format!(
            "The value '{method_name}' of the field 'Method' must be one of {}",
            METHODS.join(", ")
        )));
    }
    let method = Method::from_bytes(method_name.as_bytes())
        .map_err(|_| invalid(format!("Invalid HTTP method '{method_name}'")))?;

    if let Some(auth) = input.get("AuthType").filter(|v| !v.is_null()) {
        let auth = auth
            .as_str()
            .ok_or_else(|| invalid("The field 'AuthType' must be a string"))?;
        if !AUTH_TYPES.contains(&auth) {
            return Err(invalid(format!(
                "The value '{auth}' of the field 'AuthType' must be one of {}",
                AUTH_TYPES.join(", ")
            )));
        }
    }

    let stage = optional_string(input, "Stage")?;
    let path = optional_string(input, "Path")?.unwrap_or_default();
    let raw_path = join_path(stage.as_deref(), &path);
    let query = parse_multi_map(input, "QueryParameters")?;
    let header_pairs = parse_multi_map(input, "Headers")?;
    let allow_nulls = input["AllowNullValues"].as_bool().unwrap_or(false);

    let mut headers = HeaderMap::new();
    for (name, value) in &header_pairs {
        let lowered = name.to_ascii_lowercase();
        if FORBIDDEN_HEADERS.contains(&lowered.as_str())
            || FORBIDDEN_PREFIXES.iter().any(|p| lowered.starts_with(p))
        {
            return Err(invalid(format!("The header '{name}' is not permitted")));
        }
        let header_name = HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| invalid(format!("Invalid header name '{name}'")))?;
        let header_value = HeaderValue::from_str(value)
            .map_err(|_| invalid(format!("Invalid value for header '{name}'")))?;
        headers.append(header_name, header_value);
    }

    let body = match input.get("RequestBody").filter(|v| !v.is_null()) {
        None => Bytes::new(),
        Some(_) if !BODY_METHODS.contains(&method_name) => {
            return Err(invalid(format!(
                "The field 'RequestBody' is only supported for the {} methods",
                BODY_METHODS.join(", ")
            )));
        }
        Some(Value::String(text)) => Bytes::from(text.clone()),
        Some(value) => {
            let value = if allow_nulls {
                value.clone()
            } else {
                without_nulls(value)
            };
            if !headers.contains_key(CONTENT_TYPE) {
                headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
            }
            Bytes::from(
                serde_json::to_vec(&value).expect("serde_json::Value serialization is infallible"),
            )
        }
    };

    let host = endpoint.to_string();
    let host_value = HeaderValue::from_str(&host)
        .map_err(|_| invalid(format!("Invalid ApiEndpoint '{host}'")))?;
    headers.insert(HOST, host_value);

    Ok(Invocation {
        api_id,
        region,
        host,
        method,
        raw_path,
        query,
        headers,
        body,
    })
}

/// `{api-id}.execute-api.{region}.amazonaws.com[.cn]`, whose API id uses only
/// lowercase letters and digits.
fn parse_endpoint(endpoint: &str) -> Result<(String, String), TaskError> {
    let malformed = || {
        invalid(format!(
            "The value '{endpoint}' of the field 'ApiEndpoint' must have the format \
             <API ID>.execute-api.<region>.amazonaws.com"
        ))
    };
    let mut labels = endpoint.split('.');
    let api_id = labels.next().filter(|id| {
        !id.is_empty()
            && id
                .chars()
                .all(|c| c.is_ascii_digit() || c.is_ascii_lowercase())
    });
    let (Some(api_id), Some("execute-api"), Some(region)) = (api_id, labels.next(), labels.next())
    else {
        return Err(malformed());
    };
    let suffix: Vec<&str> = labels.collect();
    if region.is_empty()
        || !(suffix == ["amazonaws", "com"] || suffix == ["amazonaws", "com", "cn"])
    {
        return Err(malformed());
    }
    Ok((api_id.to_string(), region.to_string()))
}

fn optional_string(input: &Value, field: &str) -> Result<Option<String>, TaskError> {
    match input.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(text)) => Ok(Some(text.clone())),
        Some(_) => Err(invalid(format!("The field '{field}' must be a string"))),
    }
}

/// `Stage` then `Path`, each contributing one leading slash.
fn join_path(stage: Option<&str>, path: &str) -> String {
    let mut joined = String::new();
    if let Some(stage) = stage.map(|s| s.trim_matches('/')).filter(|s| !s.is_empty()) {
        joined.push('/');
        joined.push_str(stage);
    }
    let path = path.trim_start_matches('/');
    if !path.is_empty() {
        joined.push('/');
        joined.push_str(path);
    }
    if joined.is_empty() {
        joined.push('/');
    }
    joined
}

/// `Headers` and `QueryParameters`: each key maps to a list of strings (a
/// single string is read as a one-item list).
fn parse_multi_map(input: &Value, field: &str) -> Result<Vec<(String, String)>, TaskError> {
    let Some(value) = input.get(field).filter(|v| !v.is_null()) else {
        return Ok(Vec::new());
    };
    let entries = value
        .as_object()
        .ok_or_else(|| invalid(format!("The field '{field}' must be an object")))?;
    let mut pairs = Vec::new();
    for (key, values) in entries {
        let list = match values {
            Value::String(text) => vec![text.clone()],
            Value::Array(items) => items
                .iter()
                .map(|item| {
                    item.as_str().map(str::to_string).ok_or_else(|| {
                        invalid(format!("The values of '{field}.{key}' must be strings"))
                    })
                })
                .collect::<Result<_, _>>()?,
            _ => {
                return Err(invalid(format!(
                    "The value of '{field}.{key}' must be a list of strings"
                )))
            }
        };
        pairs.extend(list.into_iter().map(|v| (key.clone(), v)));
    }
    Ok(pairs)
}

/// The request body without its null-valued members, as Step Functions sends
/// it unless `AllowNullValues` is true.
fn without_nulls(value: &Value) -> Value {
    match value {
        Value::Object(members) => Value::Object(
            members
                .iter()
                .filter(|(_, v)| !v.is_null())
                .map(|(k, v)| (k.clone(), without_nulls(v)))
                .collect::<Map<_, _>>(),
        ),
        Value::Array(items) => Value::Array(items.iter().map(without_nulls).collect()),
        other => other.clone(),
    }
}

impl Invocation {
    fn into_request(self, account_id: &str) -> AwsRequest {
        let raw_query = self
            .query
            .iter()
            .map(|(k, v)| {
                format!(
                    "{}={}",
                    utf8_percent_encode(k, QUERY_COMPONENT),
                    utf8_percent_encode(v, QUERY_COMPONENT)
                )
            })
            .collect::<Vec<_>>()
            .join("&");
        let query_params: HashMap<String, String> = self.query.into_iter().collect();
        tracing::debug!(api_id = %self.api_id, host = %self.host, path = %self.raw_path, "apigateway:invoke");
        AwsRequest {
            service: "apigateway".to_string(),
            action: String::new(),
            region: self.region,
            account_id: account_id.to_string(),
            request_id: uuid::Uuid::new_v4().to_string(),
            headers: self.headers,
            query_params,
            body: self.body,
            body_stream: parking_lot::Mutex::new(None),
            path_segments: fakecloud_core::path::split_path_segments(&self.raw_path),
            raw_path: self.raw_path,
            raw_query,
            method: self.method,
            is_query_protocol: false,
            access_key_id: None,
            principal: None,
        }
    }
}

async fn into_result(response: AwsResponse) -> Result<Value, TaskError> {
    let status = response.status;
    let body = read_body(response.body).await?;
    let text = String::from_utf8_lossy(&body).into_owned();
    if !status.is_success() {
        return Err((format!("ApiGateway.{}", status.as_u16()), text));
    }

    let mut headers: Map<String, Value> = Map::new();
    for name in response.headers.keys() {
        let values: Vec<Value> = response
            .headers
            .get_all(name)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .map(|v| Value::String(v.to_string()))
            .collect();
        headers.insert(name.as_str().to_string(), Value::Array(values));
    }
    let content_type = response
        .headers
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
        .unwrap_or(response.content_type);
    if !content_type.is_empty() && !headers.contains_key(CONTENT_TYPE.as_str()) {
        headers.insert(
            CONTENT_TYPE.as_str().to_string(),
            json!([content_type.clone()]),
        );
    }

    let response_body = if content_type.to_ascii_lowercase().contains("json") {
        serde_json::from_slice::<Value>(&body).unwrap_or(Value::String(text))
    } else {
        Value::String(text)
    };
    Ok(json!({
        "ResponseBody": response_body,
        "Headers": headers,
        "StatusCode": status.as_u16(),
        "StatusText": status_text(status),
    }))
}

fn status_text(status: StatusCode) -> String {
    status.canonical_reason().unwrap_or_default().to_string()
}

async fn read_body(body: ResponseBody) -> Result<Bytes, TaskError> {
    match body {
        ResponseBody::Bytes(bytes) => Ok(bytes),
        ResponseBody::File { mut file, .. } => {
            use tokio::io::AsyncReadExt;
            let mut buffer = Vec::new();
            file.read_to_end(&mut buffer).await.map_err(|e| {
                (
                    "ApiGateway.IOException".to_string(),
                    format!("Could not read the response body: {e}"),
                )
            })?;
            Ok(Bytes::from(buffer))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fakecloud_core::service::{AwsService, AwsServiceError};

    /// Records each request and answers with the configured status and body.
    struct RecordingGateway {
        status: StatusCode,
        body: &'static str,
        content_type: &'static str,
        fail: Option<(StatusCode, &'static str, &'static str)>,
        seen: parking_lot::Mutex<
            Vec<(
                String,
                String,
                String,
                String,
                Vec<(String, String)>,
                String,
            )>,
        >,
    }

    impl RecordingGateway {
        fn answering(status: StatusCode, body: &'static str) -> Arc<Self> {
            Arc::new(Self {
                status,
                body,
                content_type: "application/json",
                fail: None,
                seen: parking_lot::Mutex::new(Vec::new()),
            })
        }
    }

    #[async_trait::async_trait]
    impl AwsService for RecordingGateway {
        fn service_name(&self) -> &str {
            "apigateway"
        }

        async fn handle(&self, request: AwsRequest) -> Result<AwsResponse, AwsServiceError> {
            let headers = request
                .headers
                .iter()
                .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap().to_string()))
                .collect();
            self.seen.lock().push((
                request.method.to_string(),
                request.raw_path.clone(),
                request.raw_query.clone(),
                request.region.clone(),
                headers,
                String::from_utf8(request.body.to_vec()).unwrap(),
            ));
            if let Some((status, code, message)) = self.fail {
                return Err(AwsServiceError::aws_error(status, code, message));
            }
            let mut response = AwsResponse::json(self.status, self.body);
            response.content_type = self.content_type.to_string();
            response
                .headers
                .insert("x-custom", HeaderValue::from_static("custom-value"));
            Ok(response)
        }

        fn supported_actions(&self) -> &[&str] {
            &[]
        }
    }

    fn registry_with(gateway: Arc<RecordingGateway>) -> Arc<ServiceRegistry> {
        let mut registry = ServiceRegistry::new();
        registry.register(gateway);
        Arc::new(registry)
    }

    fn run(gateway: Arc<RecordingGateway>, input: Value) -> Result<Value, TaskError> {
        let registry = registry_with(gateway);
        tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap()
            .block_on(invoke(&registry, &input, "123456789012", None))
    }

    #[test]
    fn a_post_reaches_the_stage_path_with_query_headers_and_json_body() {
        let gateway = RecordingGateway::answering(StatusCode::OK, r#"{"submit":true}"#);
        let output = run(
            gateway.clone(),
            json!({
                "ApiEndpoint": "abc123.execute-api.eu-west-1.amazonaws.com",
                "Method": "POST",
                "Stage": "stage",
                "Path": "/api/v1/items/42/launch",
                "QueryParameters": {"tag": ["a b", "c"]},
                "Headers": {"X-Trace": ["t1"]},
                "RequestBody": {"check": {"id": 7}, "dropped": null},
                "AuthType": "IAM_ROLE"
            }),
        )
        .unwrap();

        assert_eq!(
            output,
            json!({
                "ResponseBody": {"submit": true},
                "Headers": {"x-custom": ["custom-value"], "content-type": ["application/json"]},
                "StatusCode": 200,
                "StatusText": "OK"
            })
        );
        let seen = gateway.seen.lock();
        let (method, path, query, region, headers, body) = &seen[0];
        assert_eq!(method, "POST");
        assert_eq!(path, "/stage/api/v1/items/42/launch");
        assert_eq!(query, "tag=a%20b&tag=c");
        assert_eq!(region, "eu-west-1");
        assert!(headers.contains(&(
            "host".to_string(),
            "abc123.execute-api.eu-west-1.amazonaws.com".to_string()
        )));
        assert!(headers.contains(&("x-trace".to_string(), "t1".to_string())));
        assert!(headers.contains(&("content-type".to_string(), "application/json".to_string())));
        assert_eq!(body, r#"{"check":{"id":7}}"#);
    }

    #[test]
    fn null_members_are_sent_when_allowed() {
        let gateway = RecordingGateway::answering(StatusCode::OK, "{}");
        run(
            gateway.clone(),
            json!({
                "ApiEndpoint": "abc123.execute-api.us-east-1.amazonaws.com",
                "Method": "PUT",
                "RequestBody": {"category": null},
                "AllowNullValues": true
            }),
        )
        .unwrap();
        assert_eq!(gateway.seen.lock()[0].5, r#"{"category":null}"#);
    }

    #[test]
    fn a_non_2xx_answer_fails_with_its_status_and_body() {
        let gateway = RecordingGateway::answering(
            StatusCode::BAD_GATEWAY,
            r#"{"message":"Internal server error"}"#,
        );
        let error = run(
            gateway,
            json!({"ApiEndpoint": "abc123.execute-api.us-east-1.amazonaws.com", "Method": "GET", "Stage": "prod"}),
        )
        .unwrap_err();
        assert_eq!(
            error,
            (
                "ApiGateway.502".to_string(),
                r#"{"message":"Internal server error"}"#.to_string()
            )
        );
    }

    #[test]
    fn a_gateway_error_fails_with_its_status_and_message() {
        let gateway = Arc::new(RecordingGateway {
            status: StatusCode::OK,
            body: "",
            content_type: "application/json",
            fail: Some((
                StatusCode::FORBIDDEN,
                "MissingAuthenticationTokenException",
                "Missing Authentication Token",
            )),
            seen: parking_lot::Mutex::new(Vec::new()),
        });
        let error = run(
            gateway,
            json!({"ApiEndpoint": "abc123.execute-api.us-east-1.amazonaws.com", "Method": "GET"}),
        )
        .unwrap_err();
        assert_eq!(
            error,
            (
                "ApiGateway.403".to_string(),
                r#"{"message":"Missing Authentication Token"}"#.to_string()
            )
        );
    }

    #[test]
    fn a_text_answer_is_returned_as_a_string() {
        let gateway = Arc::new(RecordingGateway {
            status: StatusCode::OK,
            body: "plain",
            content_type: "text/plain",
            fail: None,
            seen: parking_lot::Mutex::new(Vec::new()),
        });
        let output = run(
            gateway,
            json!({"ApiEndpoint": "abc123.execute-api.us-east-1.amazonaws.com", "Method": "GET"}),
        )
        .unwrap();
        assert_eq!(output["ResponseBody"], json!("plain"));
    }

    #[test]
    fn invalid_arguments_are_refused_before_any_call() {
        let cases = [
            json!({"Method": "GET"}),
            json!({"ApiEndpoint": "ABC.execute-api.us-east-1.amazonaws.com", "Method": "GET"}),
            json!({"ApiEndpoint": "abc.example.com", "Method": "GET"}),
            json!({"ApiEndpoint": "abc.execute-api.us-east-1.amazonaws.com", "Method": "TRACE"}),
            json!({"ApiEndpoint": "abc.execute-api.us-east-1.amazonaws.com", "Method": "GET", "RequestBody": {}}),
            json!({"ApiEndpoint": "abc.execute-api.us-east-1.amazonaws.com", "Method": "GET", "Headers": {"X-Amz-Date": ["now"]}}),
            json!({"ApiEndpoint": "abc.execute-api.us-east-1.amazonaws.com", "Method": "GET", "Headers": {"Authorization": ["t"]}}),
            json!({"ApiEndpoint": "abc.execute-api.us-east-1.amazonaws.com", "Method": "GET", "AuthType": "COGNITO"}),
            json!({"ApiEndpoint": "abc.execute-api.us-east-1.amazonaws.com", "Method": "GET", "QueryParameters": {"a": [1]}}),
        ];
        for case in cases {
            let gateway = RecordingGateway::answering(StatusCode::OK, "{}");
            let error = run(gateway.clone(), case.clone()).unwrap_err();
            assert_eq!(error.0, "States.TaskFailed", "{case}");
            assert!(gateway.seen.lock().is_empty(), "{case}");
        }
    }

    #[test]
    fn paths_join_stage_and_path_with_one_slash() {
        assert_eq!(join_path(Some("prod"), "/a/b"), "/prod/a/b");
        assert_eq!(join_path(Some("/prod/"), "a"), "/prod/a");
        assert_eq!(join_path(None, "a"), "/a");
        assert_eq!(join_path(Some("prod"), ""), "/prod");
        assert_eq!(join_path(None, ""), "/");
    }
}
