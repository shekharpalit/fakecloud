//! Account-partitioned state for Amazon Bedrock AgentCore. Resources are kept
//! as the JSON objects requests send, so reads echo what writes stored.

use std::collections::BTreeMap;
use std::sync::Arc;

use fakecloud_core::multi_account::{AccountState, MultiAccountState};
use parking_lot::RwLock;
use serde_json::Value;

#[derive(Debug, Clone, Default)]
pub struct AgentCoreData {
    /// Agent runtimes by id: the `GetAgentRuntime` object of the latest version.
    pub runtimes: BTreeMap<String, Value>,
    /// Every version of each runtime, oldest first.
    pub runtime_versions: BTreeMap<String, Vec<Value>>,
    /// Memories by id: the `Memory` object.
    pub memories: BTreeMap<String, Value>,
    /// Short-term memory events by memory id, in creation order.
    pub events: BTreeMap<String, Vec<Value>>,
    /// Resource policies by resource ARN.
    pub policies: BTreeMap<String, String>,
    /// Tags by resource ARN.
    pub tags: BTreeMap<String, BTreeMap<String, String>>,
}

impl AccountState for AgentCoreData {
    fn new_for_account(_account_id: &str, _region: &str, _endpoint: &str) -> Self {
        Self::default()
    }
}

pub type SharedAgentCoreState = Arc<RwLock<MultiAccountState<AgentCoreData>>>;

pub fn new_state(account_id: &str, region: &str, endpoint: &str) -> SharedAgentCoreState {
    Arc::new(RwLock::new(MultiAccountState::new(
        account_id, region, endpoint,
    )))
}

/// Now as epoch seconds, the restJson1 form of a timestamp.
pub fn now_epoch() -> f64 {
    chrono::Utc::now().timestamp_millis() as f64 / 1000.0
}

/// Now as an ISO 8601 string, the form AgentCore gives its's `DateTimestamp`
/// (agent runtimes, their endpoints and Code Interpreter sessions; Memory and
/// its events use epoch seconds).
pub fn now_iso() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

/// A generated id: `<name>-<10 alphanumerics>`, AgentCore's runtime and memory id form.
pub fn generated_id(name: &str) -> String {
    use rand::Rng;
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut rng = rand::thread_rng();
    let suffix: String = (0..10)
        .map(|_| ALPHABET[rng.gen_range(0..ALPHABET.len())] as char)
        .collect();
    format!("{name}-{suffix}")
}
