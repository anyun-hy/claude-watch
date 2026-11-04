#![forbid(unsafe_code)]

//! Pure policy functions. No I/O, clocks, process control, account access or launch authority.
//! A matching proxy chain does not establish connection identity or prove absence of leaks.

pub mod audit;
pub mod cli;
pub mod config;
pub mod error;
pub mod guard_event;
pub mod json_value;
pub mod network;
pub mod observation;
pub mod presentation;
pub mod policy;
pub mod process_roots;
pub mod processes;
pub mod receipts;
pub mod region;
pub mod risk;
pub mod session;
pub mod stun;
pub mod tag_config;
pub mod tag_flow;
pub mod tag_policy;
pub mod time_parse;
