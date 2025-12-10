pub mod types;
pub mod manager;

pub use types::*;
pub use manager::{process_event, get_incidents, get_incident};
