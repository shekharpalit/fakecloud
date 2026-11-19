//! Amazon Bedrock AgentCore for fakecloud: the control plane for agent
//! runtimes, memories, resource policies and tags; agent runtime sessions run
//! as containers (see [`sessions`]); short-term memory events; and Code
//! Interpreter sessions in network-less containers (see [`interpreter`]).

pub mod control;
mod eventstream;
pub mod interpreter;
pub mod service;
pub mod sessions;
pub mod state;

pub use service::AgentCoreService;
pub use state::{new_state, SharedAgentCoreState};
