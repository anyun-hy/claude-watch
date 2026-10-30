//! Bounded, read-only activity evidence for the legacy monitor surface.
//!
//! This module deliberately publishes categories and counters, never lsof path
//! names or an assertion that a launchd label belongs to a process.
use crate::{
    commands::{Output, ReadCommand, ReadRunner},
    native::Observer,
};
use claude_watch_core::processes::Identity;
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    time::Duration,
};

const TIMEOUT: Duration = Duration::from_secs(3);
const LIMIT: usize = 512 * 1024;

/// A read may exit cleanly and still write to stderr: `lsof` notes unrelated
/// filesystems it cannot stat (`WARNING: can't stat() apfs …`), `nettop` notes
/// metadata it skipped, and neither concerns the rows we asked for. Demanding
/// an empty stderr turned those notes into a total sampling failure every few
/// seconds, which flipped the snapshot to `degraded` and raised a critical
/// alert each time. The strict verdict is kept for the case that actually
/// matters — nothing usable on stdout — so a genuine failure still reports
/// `unavailable` and is never presented as an empty observation.
fn usable_after_stderr(output: &Output) -> bool {
    output.stderr.is_empty() || !output.stdout.is_empty()
}
/// Collects presentation-safe, identity-bound activity evidence.  A failed
/// read is represented as unavailable, never as an empty or zero observation.
pub fn collect<R: ReadRunner>(
    runner: &R,
    home: &Path,
    targets: &[Identity],
    active: &[u32],
) -> Value {
    let requested: BTreeMap<_, _> = targets
        .iter()
        .filter(|p| p.valid())
        .map(|p| (p.pid, p.clone()))
        .collect();
    if requested.is_empty() {
        return json!({"schema":1,"state":"no_targets","targets":[],"files":{"state":"no_targets","rows":[]},"bytes":{"state":"no_targets","rows":[]},"services":service_sample(runner, active),"unavailable":[]});
    }
    let observer = Observer { runner };
    let mut unavailable = Vec::new();
    let before = match observer.identities(
        &requested.values().cloned().collect::<Vec<_>>(),
        "activity-before",
    ) {
        Ok(value) => value,
        Err(_) => {
            unavailable.push("identity_before_unavailable");
            BTreeMap::new()
        }
    };
    let sampled: Vec<u32> = before.keys().copied().collect();
    let file_pids = sampled
        .iter()
        .copied()
        .filter(|pid| !active.contains(pid))
        .collect::<Vec<_>>();
    let files = if sampled.is_empty() {
        unavailable.push("file_sample_unavailable");
        json!({"state":"unavailable","rows":[]})
    } else if file_pids.is_empty() {
        json!({"state":"no_targets","rows":[]})
    } else {
        file_sample(runner, home, &file_pids)
    };
    let bytes = if sampled.is_empty() {
        unavailable.push("byte_sample_unavailable");
        json!({"state":"unavailable","rows":[]})
    } else {
        byte_sample(runner, &sampled)
    };
    let after = match observer.identities(
        &requested.values().cloned().collect::<Vec<_>>(),
        "activity-after",
    ) {
        Ok(value) => value,
        Err(_) => {
            unavailable.push("identity_after_unavailable");
            BTreeMap::new()
        }
    };
    let stable: BTreeSet<u32> = before
        .iter()
        .filter_map(|(pid, identity)| {
            after
                .get(pid)
                .filter(|later| later.same_process(identity))
                .map(|_| *pid)
        })
        .collect();
    // A target missing from `after` means one of two things that this layer
    // cannot tell apart: the process exited, or its identity changed.
    // `Observer::identities` only returns rows that still match the requested
    // identity, so a reused PID is already dropped there. Both cases are
    // handled safely below — `filter_rows` removes every row without a
    // verified identity, so no unattributed evidence is ever published. What
    // must not happen is calling the whole round untrustworthy: Claude's
    // helpers start and stop constantly, and each of those moments used to
    // flip the snapshot to `degraded` and raise a critical alert.
    if stable.is_empty() && !requested.is_empty() {
        // Nothing was verified for this round, which is not a healthy sample.
        unavailable.push("identity_unverified");
    }
    let files = filter_rows(files, &stable);
    let bytes = filter_rows(bytes, &stable);
    if files["state"] == "unavailable" {
        unavailable.push("file_sample_unavailable");
    }
    if bytes["state"] == "unavailable" {
        unavailable.push("byte_sample_unavailable");
    }
    let target_rows: Vec<_> = requested.values().map(|p| json!({"pid":p.pid,"authorized":active.contains(&p.pid),"identityState":if stable.contains(&p.pid){"stable"}else{"unavailable"}})).collect();
    let services = service_sample(runner, active);
    if services["state"] == "unavailable" {
        unavailable.push("service_sample_unavailable");
    }
    let state = if stable.is_empty() {
        // Nothing was verified for this round: presenting it as healthy would
        // claim evidence the sample does not have.
        "unavailable"
    } else if unavailable.is_empty() {
        "ok"
    } else {
        "partial"
    };
    json!({"schema":1,"state":state,"targets":target_rows,"files":files,"bytes":bytes,"services":services,"unavailable":unavailable})
}

fn filter_rows(mut sample: Value, stable: &BTreeSet<u32>) -> Value {
    if let Some(rows) = sample["rows"].as_array_mut() {
        rows.retain(|row| {
            row["pid"]
                .as_u64()
                .is_some_and(|pid| stable.contains(&(pid as u32)))
        });
    }
    sample
}
fn file_sample<R: ReadRunner>(runner: &R, home: &Path, pids: &[u32]) -> Value {
    let output = match runner.run(
        ReadCommand::LsofFiles {
            pids: pids.to_vec(),
        },
        &[],
        TIMEOUT,
        LIMIT,
    ) {
        Ok(v) if v.status <= 1 && usable_after_stderr(&v) => v,
        _ => return json!({"state":"unavailable","rows":[]}),
    };
    let home = home.to_string_lossy();
    let mut pid = None;
    let mut fd = None;
    let mut access = "?";
    let mut rows = BTreeSet::new();
    let target: BTreeSet<_> = pids.iter().copied().collect();
    let Ok(text) = output.text() else {
        return json!({"state":"unavailable","rows":[]});
    };
    for line in text.lines() {
        if let Some(value) = line.strip_prefix('p') {
            pid = value.parse::<u32>().ok().filter(|p| target.contains(p));
        } else if let Some(value) = line.strip_prefix('f') {
            fd = value.parse::<u32>().ok();
            access = "?";
        } else if let Some(value) = line.strip_prefix('a') {
            access = if value.len() <= 8 && value.bytes().all(|c| c.is_ascii_alphanumeric()) {
                value
            } else {
                "?"
            };
        } else if let Some(name) = line.strip_prefix('n') {
            if let (Some(pid), Some(fd), Some(category)) = (pid, fd, category(&home, name)) {
                rows.insert((pid, fd, access.to_owned(), category));
            }
        }
    }
    let rows: Vec<_> = rows.into_iter().map(|(pid, fd, access, category)| json!({"pid":pid,"fd":fd,"access":access,"category":category})).collect();
    json!({"state":if rows.is_empty(){"empty"}else{"ok"},"rows":rows})
}
fn category(home: &str, name: &str) -> Option<&'static str> {
    [
        ("/.ssh/", "SSH"),
        ("/.aws/", "AWS"),
        ("/.gnupg/", "GPG"),
        ("/Desktop/", "Desktop"),
        ("/Documents/", "Documents"),
        ("/Downloads/", "Downloads"),
        ("/Project/", "Project"),
    ]
    .into_iter()
    .find_map(|(suffix, category)| {
        name.starts_with(&format!("{home}{suffix}"))
            .then_some(category)
    })
}
fn byte_sample<R: ReadRunner>(runner: &R, pids: &[u32]) -> Value {
    let mut totals: BTreeMap<u32, (u64, u64)> = BTreeMap::new();
    for batch in pids.chunks(20) {
        let output = match runner.run(
            ReadCommand::NettopBytes {
                pids: batch.to_vec(),
            },
            &[],
            TIMEOUT,
            LIMIT,
        ) {
            Ok(v) if v.status == 0 && usable_after_stderr(&v) => v,
            _ => return json!({"state":"unavailable","rows":[]}),
        };
        let Ok(text) = output.text() else {
            return json!({"state":"unavailable","rows":[]});
        };
        let Some(rows) = parse_nettop(text, batch) else {
            return json!({"state":"unavailable","rows":[]});
        };
        for (pid, input, output) in rows {
            let e = totals.entry(pid).or_default();
            e.0 = e.0.saturating_add(input);
            e.1 = e.1.saturating_add(output);
        }
    }
    let rows: Vec<_> = totals
        .into_iter()
        .map(|(pid, (input, output))| json!({"pid":pid,"bytesIn":input,"bytesOut":output}))
        .collect();
    json!({"state":if rows.is_empty(){"empty"}else{"ok"},"rows":rows})
}
fn parse_nettop(text: &str, targets: &[u32]) -> Option<Vec<(u32, u64, u64)>> {
    let mut lines = text.lines();
    let header = csv(lines.next()?);
    let input = header.iter().position(|v| v == "bytes_in")?;
    let output = header.iter().position(|v| v == "bytes_out")?;
    let target: BTreeSet<_> = targets.iter().copied().collect();
    let mut result = Vec::new();
    for line in lines {
        let row = csv(line);
        if row.len() <= input.max(output) {
            continue;
        }
        let Some(pid) = row.iter().take(input).find_map(|v| {
            v.rsplit_once('.')
                .and_then(|(_, p)| p.parse::<u32>().ok())
                .filter(|p| target.contains(p))
        }) else {
            continue;
        };
        let (Ok(input), Ok(output)) = (row[input].parse(), row[output].parse()) else {
            continue;
        };
        result.push((pid, input, output));
    }
    Some(result)
}
fn csv(line: &str) -> Vec<String> {
    // nettop CSV permits quoted labels; counters remain plain decimal.
    let mut out = Vec::new();
    let mut field = String::new();
    let mut quoted = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' => {
                if quoted && chars.peek() == Some(&'"') {
                    field.push('"');
                    chars.next();
                } else {
                    quoted = !quoted
                }
            }
            ',' if !quoted => {
                out.push(field);
                field = String::new();
            }
            _ => field.push(c),
        }
    }
    if quoted {
        Vec::new()
    } else {
        out.push(field);
        out
    }
}
fn service_sample<R: ReadRunner>(runner: &R, active: &[u32]) -> Value {
    let output = match runner.run(ReadCommand::LaunchctlList, &[], TIMEOUT, LIMIT) {
        Ok(v) if v.status == 0 && usable_after_stderr(&v) => v,
        _ => return json!({"state":"unavailable","candidates":[]}),
    };
    let Ok(text) = output.text() else {
        return json!({"state":"unavailable","candidates":[]});
    };
    let active: BTreeSet<_> = active.iter().copied().collect();
    let mut rows = BTreeSet::new();
    for line in text.lines().skip(1) {
        let fields: Vec<_> = line.split_whitespace().collect();
        let Some(pid) = fields.first().and_then(|v| v.parse::<u32>().ok()) else {
            continue;
        };
        let Some(label) = fields
            .get(2)
            .filter(|v| v.len() <= 256 && !v.chars().any(char::is_control))
        else {
            continue;
        };
        let lower = label.to_ascii_lowercase();
        if !active.contains(&pid)
            && !lower.starts_with("io.local.claudewatch")
            && ["claude", "anthropic", "codex", "chatgpt", "openai"]
                .iter()
                .any(|needle| lower.contains(needle))
        {
            rows.insert((pid, (*label).to_owned()));
        }
    }
    let candidates: Vec<_> = rows
        .into_iter()
        .map(|(pid, label)| json!({"pid":pid,"label":label,"ownership":"unconfirmed"}))
        .collect();
    json!({"state":"ok","candidates":candidates})
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::{ObserverAction, Output};
    use claude_watch_core::error::{CoreError, Result};
    use std::{
        collections::VecDeque,
        sync::{
            atomic::{AtomicUsize, Ordering},
            Mutex,
        },
    };
    fn id(pid: u32) -> Identity {
        Identity {
            pid,
            parent: 1,
            uid: 501,
            executable: "/Applications/Claude.app/Contents/MacOS/Claude".into(),
            start_seconds: 10,
            start_microseconds: 1,
            start_stamp: "stamp".into(),
        }
    }
    struct Fake {
        replies: Mutex<VecDeque<Result<Output>>>,
    }
    impl ReadRunner for Fake {
        fn run(&self, command: ReadCommand, input: &[u8], _: Duration, _: usize) -> Result<Output> {
            let now = crate::native::now();
            if matches!(command, ReadCommand::Observer(ObserverAction::Identities)) {
                let request: Value = serde_json::from_slice(input).unwrap();
                let round = request["round_id"].clone();
                let identities = request["targets"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|value| json!({"pid":value["pid"],"state":"ok","identity":value}))
                    .collect::<Vec<_>>();
                return Ok(Output { status: 0, stderr: vec![], stdout: serde_json::to_vec(&json!({"schema":1,"status":"ok","uid":501,"started_at":now,"finished_at":now,"round_id":round,"identities":identities})).unwrap() });
            }
            self.replies
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or_else(|| Err(CoreError::new("unexpected", "unexpected")))
        }
    }
    fn out(text: &str) -> Result<Output> {
        Ok(Output {
            status: 0,
            stdout: text.as_bytes().to_vec(),
            stderr: vec![],
        })
    }
    #[test]
    fn safe_samples_keep_categories_and_header_named_counters() {
        let fake = Fake {
            replies: Mutex::new(VecDeque::from([
                out("p7\nf3\nar\nn/Users/a/.ssh/key\n"),
                out("name,bytes_out,bytes_in\nfoo.7,9,4\n"),
                out("PID\tStatus\tLabel\n8\t0\tcom.openai.helper\n"),
            ])),
        };
        let value = collect(&fake, Path::new("/Users/a"), &[id(7)], &[]);
        assert_eq!(value["state"], "ok");
        assert_eq!(
            value["files"]["rows"][0],
            json!({"pid":7,"fd":3,"access":"r","category":"SSH"})
        );
        assert_eq!(value["bytes"]["rows"][0]["bytesIn"], 4);
        assert_eq!(
            value["services"]["candidates"][0]["ownership"],
            "unconfirmed"
        );
        assert!(!value.to_string().contains("/Users/a/.ssh/key"));
    }
    #[test]
    fn no_targets_runs_no_target_reads() {
        let fake = Fake {
            replies: Mutex::new(VecDeque::new()),
        };
        assert_eq!(
            collect(&fake, Path::new("/Users/a"), &[], &[])["state"],
            "no_targets"
        );
    }
    #[test]
    fn read_failure_is_unavailable_not_zero() {
        let fake = Fake {
            replies: Mutex::new(VecDeque::from([
                Err(CoreError::new("x", "x")),
                out("PID Status Label\n"),
            ])),
        };
        let value = collect(&fake, Path::new("/Users/a"), &[id(7)], &[]);
        assert_eq!(value["files"]["state"], "unavailable");
        assert_ne!(value["bytes"]["state"], "ok");
    }
    /// `lsof` and `nettop` write notes about unrelated filesystems or skipped
    /// metadata to stderr while stdout still carries the rows we asked for.
    /// That is a successful sample: discarding it made the activity sample
    /// flap every few seconds, which flipped the whole snapshot to `degraded`
    /// and raised a critical alert each time.
    #[test]
    fn stderr_notes_do_not_discard_a_usable_sample() {
        let noisy = |text: &str| {
            Ok(Output {
                status: 0,
                stdout: text.as_bytes().to_vec(),
                stderr: b"lsof: WARNING: can't stat() apfs file system /System/Volumes/Data\n"
                    .to_vec(),
            })
        };
        let fake = Fake {
            replies: Mutex::new(VecDeque::from([
                noisy("p7\nf3\nar\nn/Users/a/.ssh/key\n"),
                noisy("name,bytes_out,bytes_in\nfoo.7,9,4\n"),
                noisy("PID\tStatus\tLabel\n8\t0\tcom.openai.helper\n"),
            ])),
        };
        let value = collect(&fake, Path::new("/Users/a"), &[id(7)], &[]);
        assert_eq!(value["state"], "ok");
        assert_eq!(value["files"]["state"], "ok");
        assert_eq!(value["files"]["rows"][0]["category"], "SSH");
        assert_eq!(value["bytes"]["rows"][0]["bytesIn"], 4);
    }
    /// The widened guard must not turn a genuine failure into an empty sample:
    /// with nothing on stdout the verdict stays `unavailable`.
    #[test]
    fn a_sample_without_usable_stdout_still_reports_unavailable() {
        let failing = || {
            Ok(Output {
                status: 0,
                stdout: Vec::new(),
                stderr: b"lsof: illegal option\n".to_vec(),
            })
        };
        let fake = Fake {
            replies: Mutex::new(VecDeque::from([failing(), failing(), failing()])),
        };
        let value = collect(&fake, Path::new("/Users/a"), &[id(7)], &[]);
        assert_eq!(value["files"]["state"], "unavailable");
        assert_eq!(value["bytes"]["state"], "unavailable");
        // Identity still verified, so the round is partial rather than absent.
        assert_eq!(value["state"], "partial");
    }
    struct IdentityFake {
        calls: AtomicUsize,
        partial: bool,
    }
    impl ReadRunner for IdentityFake {
        fn run(&self, command: ReadCommand, input: &[u8], _: Duration, _: usize) -> Result<Output> {
            let now = crate::native::now();
            match command {
                ReadCommand::Observer(ObserverAction::Identities) => {
                    let call = self.calls.fetch_add(1, Ordering::SeqCst);
                    let request: Value = serde_json::from_slice(input).unwrap();
                    let mut rows = request["targets"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|value| json!({"pid":value["pid"],"state":"ok","identity":value}))
                        .collect::<Vec<_>>();
                    if call == 1 && self.partial {
                        rows.pop();
                    }
                    if call == 1 && !self.partial {
                        rows[0]["identity"]["start_microseconds"] = json!(2);
                    }
                    Ok(Output { status: 0, stderr: vec![], stdout: serde_json::to_vec(&json!({"schema":1,"status":"ok","uid":501,"started_at":now,"finished_at":now,"round_id":request["round_id"],"identities":rows})).unwrap() })
                }
                ReadCommand::LsofFiles { .. } => out("p7\nf3\nar\nn/Users/a/Desktop/a\n"),
                ReadCommand::NettopBytes { .. } => out("name,bytes_in,bytes_out\nfoo.7,1,2\n"),
                ReadCommand::LaunchctlList => out("PID Status Label\n"),
                _ => Err(CoreError::new("unexpected", "unexpected")),
            }
        }
    }
    #[test]
    fn pid_reuse_discards_samples_after_second_identity_check() {
        let fake = IdentityFake {
            calls: AtomicUsize::new(0),
            partial: false,
        };
        let value = collect(&fake, Path::new("/Users/a"), &[id(7)], &[]);
        assert_eq!(value["state"], "unavailable");
        assert!(value["files"]["rows"].as_array().unwrap().is_empty());
        assert!(value["unavailable"]
            .to_string()
            .contains("identity_unverified"));
    }
    /// A helper that exits between the two identity reads is normal churn, not
    /// a failed sample. Its rows are still dropped and it is still reported as
    /// unavailable, but the round itself stays valid — otherwise every helper
    /// restart interrupted the user with a critical alert.
    #[test]
    fn an_exited_helper_keeps_the_round_valid() {
        let fake = IdentityFake {
            calls: AtomicUsize::new(0),
            partial: true,
        };
        let value = collect(&fake, Path::new("/Users/a"), &[id(7), id(8)], &[]);
        assert_eq!(value["state"], "ok");
        assert_eq!(value["targets"][1]["identityState"], "unavailable");
        assert!(!value["unavailable"]
            .to_string()
            .contains("identity_unverified"));
    }
}
