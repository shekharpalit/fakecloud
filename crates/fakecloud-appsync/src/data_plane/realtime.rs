//! The realtime endpoint, `wss://<apiId>.appsync-realtime-api.<region>.amazonaws.com/graphql`,
//! speaking AppSync's `graphql-ws` protocol: the connection's authorization
//! arrives as the `header-<base64url>` subprotocol (or the `header` query
//! parameter); the client sends `connection_init`, then one `start` per
//! subscription, each authorized by its `extensions.authorization` headers;
//! the server answers `connection_ack`, `start_ack` or `error`, sends `ka`
//! keep-alives, `data` for each delivered mutation result, and `complete`
//! after a `stop` or when the subscription is invalidated.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use axum::extract::ws::{Message, WebSocket};
use base64::Engine as _;
use fakecloud_cognito::SharedCognitoState;
use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use tokio::sync::mpsc;

use super::{
    authenticate, delivery, filter, snapshot, subscribe, ApiSnapshot, Caller, Credentials,
    Published, Subscription,
};
use crate::SharedAppSyncState;

/// The subprotocol AppSync's realtime endpoint speaks.
pub const SUBPROTOCOL: &str = "graphql-ws";
const CONNECTION_TIMEOUT_MS: u64 = 300_000;
const KEEP_ALIVE: Duration = Duration::from_secs(60);

struct Registered {
    connection: u64,
    id: String,
    api_id: String,
    caller: Caller,
    subscription: Subscription,
    sender: mpsc::UnboundedSender<Value>,
}

/// Every open subscription, across connections and APIs.
#[derive(Default)]
pub struct Realtime {
    subscriptions: parking_lot::Mutex<Vec<Registered>>,
    next_connection: AtomicU64,
}

impl Realtime {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Deliver mutation results to the API's subscriptions that listen to them.
    pub fn publish(&self, snapshot: &ApiSnapshot, published: &[Published]) {
        let subscriptions = self.subscriptions.lock();
        for registered in subscriptions.iter().filter(|r| r.api_id == snapshot.api_id) {
            for result in published {
                if let Some(payload) = delivery(
                    snapshot,
                    &registered.subscription,
                    result,
                    &registered.caller,
                ) {
                    let _ = registered
                        .sender
                        .send(json!({ "id": registered.id, "type": "data", "payload": payload }));
                }
            }
        }
    }

    /// End the subscriptions an `extensions.invalidateSubscriptions` request
    /// names: those on its `subscriptionField` whose invalidation filter passes
    /// its `payload`.
    pub fn invalidate(&self, api_id: &str, invalidations: &[Value]) {
        if invalidations.is_empty() {
            return;
        }
        let mut subscriptions = self.subscriptions.lock();
        subscriptions.retain(|registered| {
            let ended = registered.api_id == api_id
                && invalidations.iter().any(|request| {
                    request.get("subscriptionField").and_then(Value::as_str)
                        == Some(registered.subscription.field.name.as_str())
                        && registered
                            .subscription
                            .invalidation_filter
                            .as_ref()
                            .is_some_and(|f| {
                                filter::passes(f, request.get("payload").unwrap_or(&Value::Null))
                            })
                });
            if ended {
                let _ = registered
                    .sender
                    .send(json!({ "id": registered.id, "type": "complete" }));
            }
            !ended
        });
    }

    /// How many subscriptions are open on `api_id`.
    pub fn count(&self, api_id: &str) -> usize {
        self.subscriptions
            .lock()
            .iter()
            .filter(|r| r.api_id == api_id)
            .count()
    }

    #[cfg(test)]
    pub(crate) fn register_for_test(
        &self,
        api_id: &str,
        id: &str,
        caller: Caller,
        subscription: Subscription,
        sender: mpsc::UnboundedSender<Value>,
    ) {
        self.subscriptions.lock().push(Registered {
            connection: u64::MAX,
            id: id.to_string(),
            api_id: api_id.to_string(),
            caller,
            subscription,
            sender,
        });
    }

    fn remove(&self, connection: u64, id: Option<&str>) {
        self.subscriptions
            .lock()
            .retain(|r| r.connection != connection || id.is_some_and(|id| r.id != id));
    }
}

/// What one realtime connection needs.
#[derive(Clone)]
pub struct SocketContext {
    pub realtime: Arc<Realtime>,
    pub state: SharedAppSyncState,
    pub cognito: Option<SharedCognitoState>,
    pub api_id: String,
    pub account_id: String,
    pub source_ip: Option<String>,
    /// The connection's authorization headers, decoded from the subprotocol
    /// or the `header` query parameter.
    pub connection_headers: Option<Value>,
}

/// Accept a WebSocket upgrade on `<apiId>.appsync-realtime-api...`, choosing
/// the `graphql-ws` subprotocol, and serve the connection. `base` names the
/// API and the shared state; the client's address and connection headers are
/// read from the request.
pub async fn upgrade(
    request: axum::extract::Request,
    mut base: SocketContext,
) -> axum::response::Response {
    use axum::extract::FromRequestParts;
    use axum::response::IntoResponse;
    let (mut parts, _body) = request.into_parts();
    let protocols: Vec<String> = parts
        .headers
        .get_all(http::header::SEC_WEBSOCKET_PROTOCOL)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(',').map(|p| p.trim().to_string()))
        .collect();
    let query_header = parts.uri.query().and_then(|query| {
        query
            .split('&')
            .filter_map(|pair| pair.split_once('='))
            .find(|(name, _)| *name == "header")
            .map(|(_, value)| {
                percent_encoding::percent_decode_str(value)
                    .decode_utf8_lossy()
                    .into_owned()
            })
    });
    let borrowed: Vec<&str> = protocols.iter().map(String::as_str).collect();
    base.connection_headers = connection_headers(&borrowed, query_header.as_deref());
    base.source_ip = parts
        .extensions
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|info| info.0.ip().to_string());
    match axum::extract::WebSocketUpgrade::from_request_parts(&mut parts, &()).await {
        Ok(ws) => ws
            .protocols([SUBPROTOCOL])
            .on_upgrade(move |socket| serve(socket, base))
            .into_response(),
        Err(rejection) => rejection.into_response(),
    }
}

/// The connection headers a client sent: the `header-<base64url>` subprotocol
/// or the `header` query parameter (base64).
pub fn connection_headers(protocols: &[&str], query_header: Option<&str>) -> Option<Value> {
    let encoded = protocols
        .iter()
        .find_map(|p| p.trim().strip_prefix("header-"))
        .or(query_header)?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded.trim_end_matches('='))
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(encoded))
        .ok()?;
    serde_json::from_slice(&bytes).ok()
}

fn credentials(headers: &Value, context: &SocketContext) -> Credentials {
    let header = |name: &str| {
        headers.as_object().and_then(|h| {
            h.iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(name))
                .and_then(|(_, v)| v.as_str())
                .map(str::to_string)
        })
    };
    Credentials {
        authorization: header("authorization"),
        api_key: header("x-api-key"),
        account_id: context.account_id.clone(),
        access_key_id: None,
        source_ip: context.source_ip.clone(),
    }
}

fn unauthorized(message: &str) -> Value {
    json!({ "errors": [{ "errorType": "UnauthorizedException", "message": message }] })
}

/// Serve one realtime connection until the client closes it.
pub async fn serve(socket: WebSocket, context: SocketContext) {
    let connection = context
        .realtime
        .next_connection
        .fetch_add(1, Ordering::Relaxed);
    let (mut sink, mut stream) = socket.split();
    let (sender, mut outgoing) = mpsc::unbounded_channel::<Value>();
    let writer = tokio::spawn(async move {
        while let Some(message) = outgoing.recv().await {
            if sink
                .send(Message::Text(message.to_string().into()))
                .await
                .is_err()
            {
                break;
            }
        }
        let _ = sink.close().await;
    });

    let connection_caller = snapshot(&context.state, &context.api_id)
        .ok_or("unknown API")
        .and_then(|api| {
            let headers = context
                .connection_headers
                .clone()
                .ok_or("no connection header")?;
            authenticate(
                &api,
                context.cognito.as_ref(),
                &credentials(&headers, &context),
            )
            .map_err(|_| "refused")
        });
    let mut keep_alive: Option<tokio::task::JoinHandle<()>> = None;
    let mut started: HashMap<String, ()> = HashMap::new();

    while let Some(Ok(message)) = stream.next().await {
        let text = match message {
            Message::Text(text) => text.to_string(),
            Message::Close(_) => break,
            _ => continue,
        };
        let Ok(message) = serde_json::from_str::<Value>(&text) else {
            continue;
        };
        match message.get("type").and_then(Value::as_str) {
            Some("connection_init") => {
                if connection_caller.is_err() {
                    let _ = sender.send(json!({
                        "type": "connection_error",
                        "payload": unauthorized("You are not authorized to make this call."),
                    }));
                    break;
                }
                let _ = sender.send(json!({
                    "type": "connection_ack",
                    "payload": { "connectionTimeoutMs": CONNECTION_TIMEOUT_MS },
                }));
                let ka = sender.clone();
                keep_alive.get_or_insert_with(|| {
                    tokio::spawn(async move {
                        loop {
                            tokio::time::sleep(KEEP_ALIVE).await;
                            if ka.send(json!({ "type": "ka" })).is_err() {
                                break;
                            }
                        }
                    })
                });
            }
            Some("start") => {
                let id = message
                    .get("id")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string();
                let answer = start(&context, connection, &id, &message, &sender);
                if answer.is_ok() {
                    started.insert(id.clone(), ());
                }
                let _ = sender.send(match answer {
                    Ok(()) => json!({ "id": id, "type": "start_ack" }),
                    Err(errors) => {
                        json!({ "id": id, "type": "error", "payload": { "errors": errors } })
                    }
                });
            }
            Some("stop") => {
                let id = message
                    .get("id")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string();
                context.realtime.remove(connection, Some(&id));
                if started.remove(&id).is_some() {
                    let _ = sender.send(json!({ "id": id, "type": "complete" }));
                }
            }
            _ => {}
        }
    }
    context.realtime.remove(connection, None);
    if let Some(task) = keep_alive {
        task.abort();
    }
    drop(sender);
    let _ = writer.await;
}

fn start(
    context: &SocketContext,
    connection: u64,
    id: &str,
    message: &Value,
    sender: &mpsc::UnboundedSender<Value>,
) -> Result<(), Value> {
    let errors =
        |error_type: &str, message: &str| json!([{ "errorType": error_type, "message": message }]);
    if id.is_empty() {
        return Err(errors("ValidationError", "A start message needs an id"));
    }
    let api = snapshot(&context.state, &context.api_id)
        .ok_or_else(|| errors("NotFoundException", "The GraphQL API no longer exists"))?;
    let payload = message.get("payload").cloned().unwrap_or(Value::Null);
    let data: Value = payload
        .get("data")
        .and_then(Value::as_str)
        .and_then(|text| serde_json::from_str(text).ok())
        .ok_or_else(|| errors("ValidationError", "The start payload has no data"))?;
    let headers = payload
        .get("extensions")
        .and_then(|e| e.get("authorization"))
        .cloned()
        .or_else(|| context.connection_headers.clone())
        .unwrap_or(Value::Null);
    let caller = authenticate(
        &api,
        context.cognito.as_ref(),
        &credentials(&headers, context),
    )
    .map_err(|message| errors("UnauthorizedException", &message))?;
    let subscription = subscribe(&api, &caller, &data)?;
    context.realtime.subscriptions.lock().push(Registered {
        connection,
        id: id.to_string(),
        api_id: api.api_id.clone(),
        caller,
        subscription,
        sender: sender.clone(),
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_headers_come_from_the_subprotocol_or_the_query() {
        let headers =
            json!({ "host": "abc.appsync-api.us-east-1.amazonaws.com", "Authorization": "token" });
        let url = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(headers.to_string());
        let standard = base64::engine::general_purpose::STANDARD.encode(headers.to_string());
        let subprotocol = format!("header-{url}");
        assert_eq!(
            connection_headers(&["graphql-ws", &subprotocol], None),
            Some(headers.clone())
        );
        assert_eq!(
            connection_headers(&["graphql-ws"], Some(&standard)),
            Some(headers)
        );
        assert_eq!(connection_headers(&["graphql-ws"], None), None);
    }
}
