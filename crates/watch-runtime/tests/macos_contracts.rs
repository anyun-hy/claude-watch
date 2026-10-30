use claude_watch_core::error::Result;
use claude_watch_runtime::commands::{Output, ReadCommand, ReadRunner};
use claude_watch_runtime::macos::*;
use claude_watch_runtime::network_client::{
    NetworkClient, Request, Response, Transport, TransportError,
};
use claude_watch_runtime::repair::RepairSystem;
use claude_watch_runtime::storage::{Paths, StateStore};
use std::{collections::HashMap, fs, sync::Arc, time::Duration};
struct R;
impl ReadRunner for R {
    fn run(&self, c: ReadCommand, _: &[u8], _: Duration, _: usize) -> Result<Output> {
        match c{ReadCommand::Observer(_)=>Ok(Output{status:0,stderr:vec![],stdout:br#"{"schema":1,"status":"ok","uid":1,"started_at":1,"finished_at":1,"network":{"service":"Wi-Fi","interface":"en0"}}"#.to_vec()}),_=>unreachable!()}
    }
}
struct T;
impl Transport for T {
    fn get(&self, _: &Request) -> std::result::Result<Response, TransportError> {
        Ok(Response {
            status: 200,
            headers: HashMap::new(),
            body: b"ip=1.1.1.1\nloc=JP\n".to_vec(),
        })
    }
}
struct M;
impl Mutator for M {
    fn apply(&mut self, _: &serde_json::Value) -> Result<()> {
        Ok(())
    }
    fn restore(&mut self, _: &serde_json::Value) -> Result<bool> {
        Ok(true)
    }
}
#[test]
fn readonly_adapter_never_delegates_mutation() {
    let root = std::env::temp_dir().join(format!("macos-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir(&root).unwrap();
    let mut m = Macos {
        runner: R,
        network: NetworkClient::new(Arc::new(T), None).unwrap(),
        storage: StateStore::new(Paths::new(&root).unwrap()),
        authority: Authority::ReadOnly,
        mutator: M,
        probes: Arc::new(|| panic!("offline must not probe")),
    };
    assert_eq!(
        RepairSystem::apply(&mut m, &serde_json::json!({"id":"timezone"}))
            .unwrap_err()
            .code,
        "write_not_authorized"
    );
    fs::remove_dir_all(root).unwrap();
}
