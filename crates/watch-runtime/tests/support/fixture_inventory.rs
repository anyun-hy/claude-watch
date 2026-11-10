use claude_watch_core::{error::Result, processes::Identity};
use claude_watch_runtime::{commands::{ObserverAction, Output, ReadCommand, ReadRunner}, native};
use serde_json::{json, Value};
use std::{sync::{Arc, Mutex}, time::Duration};

#[derive(Clone)]
pub struct FixtureProcess {
    pub identity: Identity,
    pub bundle: Option<(String, String)>,
    pub arguments: Vec<String>,
}
#[derive(Clone)]
pub struct FixtureInventory(pub Arc<Mutex<Vec<FixtureProcess>>>);
impl ReadRunner for FixtureInventory {
    fn run(&self, command: ReadCommand, input: &[u8], _: Duration, _: usize) -> Result<Output> {
        let now = native::now();
        let records = self.0.lock().unwrap();
        let mut value = json!({"schema":1,"status":"ok","uid":501,"started_at":now,"finished_at":now});
        if let Some(process) = records.first() { value["uid"] = json!(process.identity.uid); }
        match command {
            ReadCommand::Plist(path) => {
                if !["/private/tmp/", "/private/var/folders/", "/var/folders/"].iter().any(|prefix|path.to_string_lossy().starts_with(prefix)) {
                    return Ok(Output { status:1, stdout:vec![], stderr:vec![] });
                }
                let reader=claude_watch_runtime::commands::SystemRunner::new(native::built_observer_path().unwrap())?;
                return reader.run(ReadCommand::Plist(path), &[], Duration::from_secs(3), 128*1024);
            }
            ReadCommand::Observer(ObserverAction::Inventory) => {
                let rows: Vec<_> = records.iter().map(|r| {
                    let mut row = json!(r.identity);
                    if let Some((path, id)) = &r.bundle { row["bundle_path"] = json!(path); row["bundle_id"] = json!(id); }
                    row
                }).collect();
                value["state"] = json!("ok"); value["truncated"] = json!(false);
                value["requested_count"] = json!(rows.len()); value["processes"] = json!(rows);
                value["unavailable"] = json!([]); value["exited"] = json!([]);
            }
            ReadCommand::Observer(ObserverAction::Arguments) => {
                let request: Value = serde_json::from_slice(input).unwrap();
                value["round_id"] = request["round_id"].clone();
                value["argument_prefixes"] = json!(records.iter().filter(|r| request["targets"].as_array().unwrap().iter().any(|p| p["pid"] == r.identity.pid)).map(|r|
                    json!({"pid":r.identity.pid,"state":"ok","identity":r.identity,"arguments":r.arguments,"cwd":"/fixture","truncated":false})).collect::<Vec<_>>());
            }
            _ => panic!("unexpected fixture inventory command"),
        }
        Ok(Output { status:0, stdout:serde_json::to_vec(&value).unwrap(), stderr:vec![] })
    }
}
