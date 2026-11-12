//! Authenticated, bounded OS listener transport. The system shell only collects
//! raw observations; all interpretation and authority remain in Rust.
use crate::{
    commands::{Output, ReadCommand, ReadRunner},
    native::{self, Observer},
    sampler::parse_process_table,
    storage::{sha256, StateStore},
};
use claude_watch_core::{
    error::{CoreError, Result},
    processes::Identity,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{BufRead, BufReader, IsTerminal, Read},
    os::unix::fs::{FileTypeExt, MetadataExt},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Condvar, Mutex,
    },
    thread,
    time::Duration,
};

pub const SCRIPT: &str = "watch-native-collector.zsh";
const SCRIPT_BYTES: &[u8] = include_bytes!("../../../monitor/Resources/watch-native-collector.zsh");
const MAX_PART: usize = 4 * 1024 * 1024;
const MAX_TOTAL: usize = 8 * 1024 * 1024;
// A collector round costs a second or two of ps/netstat work before it sleeps,
// the daemon publishes the newest frame it has consumed, and a reader without a
// live stream only sees the published copy. Five seconds left less than a full
// round of margin, so a healthy daemon kept publishing frames that every reader
// then judged stale. Fifteen seconds covers two whole rounds plus scheduling
// jitter while still refusing genuinely abandoned samples.
const MAX_AGE: f64 = 15.0;
/// Internal annotation ignored by netstat-row parsers. Consumers with tighter
/// evidence TTLs must preserve this capture time instead of stamping a reread.
pub(crate) const FRAME_META_PREFIX: &str = "# CW_LISTENER_FRAME ";
fn error(code: &str, detail: &str) -> CoreError {
    CoreError::new(code, detail)
}
fn invalid() -> CoreError {
    error("native_listener_protocol", "系统监听采样帧不完整或超出边界")
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Proof {
    pub supervisor: Identity,
    pub worker: Identity,
    collector: Identity,
    root: PathBuf,
}
#[derive(Clone, Serialize, Deserialize)]
struct Evidence {
    supervisor: u32,
    collector: u32,
    sequence: u64,
    started: f64,
    finished: f64,
    table: String,
    owners: BTreeMap<u32, Value>,
    origins: BTreeMap<u32, Value>,
}
#[derive(Clone, Serialize, Deserialize)]
struct Actor {
    supervisor: Identity,
    worker: Identity,
    root: PathBuf,
}
#[derive(Serialize, Deserialize)]
struct Captured {
    proof: Proof,
    evidence: Evidence,
}
#[derive(Serialize, Deserialize)]
struct Cached {
    schema: u32,
    published_at: f64,
    actor: Actor,
    listener: Option<Captured>,
    error: Option<CoreError>,
}
struct Raw {
    supervisor: u32,
    collector: u32,
    sequence: u64,
    started: f64,
    finished: f64,
    statuses: [i32; 3],
    before: Vec<u8>,
    table: Vec<u8>,
    errors: Vec<u8>,
    after: Vec<u8>,
}

fn frame<R: BufRead>(reader: &mut R) -> Result<Option<Raw>> {
    let mut header = Vec::new();
    if reader
        .take(513)
        .read_until(b'\n', &mut header)
        .map_err(|_| invalid())?
        == 0
    {
        return Ok(None);
    }
    if header.len() > 512 || header.last() != Some(&b'\n') {
        return Err(invalid());
    }
    let text = std::str::from_utf8(&header).map_err(|_| invalid())?;
    let fields = text.split_whitespace().collect::<Vec<_>>();
    if fields.len() != 13 || fields[0] != "CWLISTENER1" {
        return Err(invalid());
    }
    let timestamp = |value: &str| -> Result<f64> {
        if value.len() > 32 || !value.bytes().all(|b| b.is_ascii_digit() || b == b'.') {
            return Err(invalid());
        }
        value.parse::<f64>().ok().filter(|t| t.is_finite() && *t > 0.0).ok_or_else(invalid)
    };
    let started = timestamp(fields[4])?;
    let finished = timestamp(fields[5])?;
    let n = fields[1..4]
        .iter()
        .chain(&fields[6..])
        .map(|v| v.parse::<u64>().map_err(|_| invalid()))
        .collect::<Result<Vec<_>>>()?;
    if n[0] < 2
        || n[1] < 2
        || n[0] > u32::MAX as u64
        || n[1] > u32::MAX as u64
        || n[2] == 0
        || finished < started
        || finished - started > 5.0
        || n[3..6].iter().any(|v| *v > 255)
    {
        return Err(invalid());
    }
    let lengths = n[6..10]
        .iter()
        .map(|v| usize::try_from(*v).map_err(|_| invalid()))
        .collect::<Result<Vec<_>>>()?;
    if lengths.iter().any(|v| *v > MAX_PART) || lengths.iter().sum::<usize>() > MAX_TOTAL {
        return Err(invalid());
    }
    let mut parts = Vec::new();
    for length in lengths {
        let mut part = vec![0; length];
        reader.read_exact(&mut part).map_err(|_| invalid())?;
        parts.push(part);
    }
    let mut end = [0];
    reader.read_exact(&mut end).map_err(|_| invalid())?;
    if end != *b"\n" {
        return Err(invalid());
    }
    let mut parts = parts.into_iter();
    Ok(Some(Raw {
        supervisor: n[0] as u32,
        collector: n[1] as u32,
        sequence: n[2],
        started,
        finished,
        statuses: [n[3] as i32, n[4] as i32, n[5] as i32],
        before: parts.next().unwrap(),
        table: parts.next().unwrap(),
        errors: parts.next().unwrap(),
        after: parts.next().unwrap(),
    }))
}
fn same(a: &Value, b: &Value) -> bool {
    a["uid"] == b["uid"]
        && a["executable"] == b["executable"]
        && a["stamp"]
            .as_str()
            .zip(b["stamp"].as_str())
            .is_some_and(|(x, y)| x.split_whitespace().eq(y.split_whitespace()))
}
fn owner_ids(table: &str) -> Result<BTreeSet<u32>> {
    let mut ids = BTreeSet::new();
    for line in table.lines() {
        let f = line.split_whitespace().collect::<Vec<_>>();
        if f.len() < 6 || !matches!(f[0], "tcp4" | "tcp6" | "tcp46") || f[5] != "LISTEN" {
            return Err(invalid());
        }
        let owners = f[6..]
            .iter()
            .filter_map(|v| {
                let (name, pid) = v.split_once(':')?;
                if name.is_empty() || pid.starts_with('0') {
                    return None;
                }
                pid.parse::<u32>().ok().filter(|p| *p > 1)
            })
            .collect::<Vec<_>>();
        if owners.len() == 1 {
            ids.insert(owners[0]);
        }
    }
    if table.trim().is_empty() {
        return Err(error("native_listener_empty", "系统未提供 TCP 监听记录"));
    }
    Ok(ids)
}
fn normalize(raw: Raw) -> Result<Evidence> {
    if raw.statuses != [0, 0, 0] || !raw.errors.is_empty() {
        return Err(error(
            "native_listener_sample_failed",
            "系统监听或进程采样命令未完成；未视为网络切换",
        ));
    }
    let before = parse_process_table(std::str::from_utf8(&raw.before).map_err(|_| invalid())?)?;
    let after = parse_process_table(std::str::from_utf8(&raw.after).map_err(|_| invalid())?)?;
    let table = String::from_utf8(raw.table).map_err(|_| invalid())?;
    let ids = owner_ids(&table)?;
    let mut owners = BTreeMap::new();
    for pid in ids {
        if let Some((a, b)) = before.get(&pid).zip(after.get(&pid)) {
            if same(a, b) {
                owners.insert(pid, b.clone());
            }
        }
    }
    let mut origins = BTreeMap::new();
    for pid in [raw.supervisor, raw.collector] {
        let (a, b) = before.get(&pid).zip(after.get(&pid)).ok_or_else(invalid)?;
        if !same(a, b) {
            return Err(invalid());
        }
        origins.insert(pid, b.clone());
    }
    Ok(Evidence {
        supervisor: raw.supervisor,
        collector: raw.collector,
        sequence: raw.sequence,
        started: raw.started,
        finished: raw.finished,
        table,
        owners,
        origins,
    })
}
fn resources(root: &Path, uid: u32) -> Result<()> {
    let engine = fs::symlink_metadata(root.join("watch-engine")).map_err(|_| invalid())?;
    if !engine.is_file()
        || engine.file_type().is_symlink()
        || engine.uid() != uid
        || engine.mode() & 0o022 != 0
        || engine.mode() & 0o111 == 0
    {
        return Err(error(
            "native_listener_component_changed",
            "原生运行组件身份不匹配",
        ));
    }
    let script = root.join(SCRIPT);
    let meta = fs::symlink_metadata(&script).map_err(|_| invalid())?;
    if !meta.is_file()
        || meta.file_type().is_symlink()
        || meta.uid() != uid
        || meta.mode() & 0o022 != 0
        || meta.len() > 128 * 1024
        || sha256(&fs::read(&script).map_err(|_| invalid())?) != sha256(SCRIPT_BYTES)
    {
        return Err(error(
            "native_listener_component_changed",
            "系统采样组件身份或内容不匹配",
        ));
    }
    Ok(())
}
fn verify<R: ReadRunner>(p: &Proof, runner: &R, job: bool) -> Result<()> {
    verify_context(
        &p.supervisor,
        &p.worker,
        Some(&p.collector),
        &p.root,
        runner,
        job,
    )
}
fn verify_actor<R: ReadRunner>(p: &Actor, runner: &R, job: bool) -> Result<()> {
    verify_context(&p.supervisor, &p.worker, None, &p.root, runner, job)
}
fn verify_context<R: ReadRunner>(
    supervisor: &Identity,
    worker: &Identity,
    collector: Option<&Identity>,
    root: &Path,
    runner: &R,
    job: bool,
) -> Result<()> {
    let uid = worker.uid;
    if uid == 0
        || !worker.valid()
        || !supervisor.valid()
        || supervisor.uid != uid
        || worker.parent != supervisor.pid
        || supervisor.executable != "/bin/zsh"
        || Path::new(&worker.executable) != root.join("watch-engine")
        || collector.is_some_and(|c| {
            !c.valid()
                || c.uid != uid
                || c.parent != supervisor.pid
                || worker.pid == c.pid
                || c.executable != "/bin/zsh"
        })
    {
        return Err(error(
            "native_listener_origin_invalid",
            "系统采样进程关系未通过核对",
        ));
    }
    resources(root, uid)?;
    let mut expected = vec![supervisor.clone(), worker.clone()];
    if let Some(c) = collector {
        expected.push(c.clone());
    }
    let observer = Observer { runner };
    if expected
        .iter()
        .any(|i| !runner.process_identity(i.pid).is_some_and(|v| v.same_process(i)))
    {
        return Err(error(
            "native_listener_origin_changed",
            "系统采样进程退出或启动身份已变化",
        ));
    }
    let mut arg_targets = vec![supervisor.clone()];
    if let Some(c) = collector {
        arg_targets.push(c.clone());
    }
    let args = observer.arguments(&arg_targets, "native-listener-arguments")?;
    let prefix = vec![
        "/bin/zsh".to_string(),
        "-f".to_string(),
        root.join(SCRIPT).to_string_lossy().into_owned(),
    ];
    for id in &arg_targets {
        let a = args
            .get(&id.pid)
            .filter(|a| !a.truncated)
            .ok_or_else(invalid)?;
        if !a.tokens.starts_with(&prefix)
            || (id.pid != supervisor.pid
                && a.tokens.get(3..)
                    != Some(&["--collect".to_string(), supervisor.pid.to_string()][..]))
        {
            return Err(error(
                "native_listener_origin_invalid",
                "系统采样进程参数与固定组件不符",
            ));
        }
    }
    // Arguments are read between lifetime checks. PID reuse/exec or a replaced
    // collector must not borrow a former source's validated argument prefix.
    if expected.iter().any(|i| !runner.process_identity(i.pid).is_some_and(|v| v.same_process(i))) {
        return Err(error("native_listener_origin_changed", "系统采样来源在参数读取期间变化"));
    }
    if job {
        let mut expected = prefix;
        expected.extend(["daemon".to_string(), "--apply".to_string()]);
        if args
            .get(&supervisor.pid)
            .is_none_or(|v| v.tokens != expected)
        {
            return Err(error(
                "native_listener_origin_invalid",
                "正式采样监督进程的启动参数不匹配",
            ));
        }
        let o = runner.run(
            ReadCommand::LaunchctlGuiAgent { uid },
            &[],
            Duration::from_secs(3),
            256 * 1024,
        )?;
        if o.status != 0
            || crate::commands::loaded_agent_identity(o.text()?)
                != Some(("running", supervisor.pid))
        {
            return Err(error(
                "native_listener_unregistered",
                "系统采样监督进程不是当前固定后台任务",
            ));
        }
    }
    Ok(())
}
fn output<R: ReadRunner>(e: &Evidence, p: &Proof, runner: &R, job: bool) -> Result<Output> {
    let now = native::now();
    if !e.started.is_finite()
        || !e.finished.is_finite()
        || e.started <= 0.0
        || e.sequence == 0
        || e.finished < e.started
        || e.finished - e.started > 5.0
        || !(0.0..=MAX_AGE).contains(&(now - e.finished))
        || e.supervisor != p.supervisor.pid
        || e.collector != p.collector.pid
    {
        return Err(error(
            "native_listener_stale",
            "系统监听采样已过期或来源不匹配",
        ));
    }
    verify(p, runner, job)?;
    for origin in [&p.supervisor, &p.collector] {
        let actual =
            json!({"uid":origin.uid,"executable":origin.executable,"stamp":origin.start_stamp});
        if !e
            .origins
            .get(&origin.pid)
            .is_some_and(|captured| same(captured, &actual))
        {
            return Err(error(
                "native_listener_origin_changed",
                "系统采样来源在采样后重启",
            ));
        }
    }
    let current = runner.run(
        ReadCommand::ProcessTablePids { pids: e.owners.keys().copied().collect() },
        &[],
        Duration::from_secs(3),
        MAX_PART,
    )?;
    if current.status != 0 || !current.stderr.is_empty() {
        return Err(error(
            "native_listener_identity_unavailable",
            "无法复核当前监听进程",
        ));
    }
    let current = parse_process_table(current.text()?)?;
    owner_ids(&e.table)?;
    // Preserve an unverifiable row, including its listening address, but remove
    // its claimed owner. The existing per-port verifier then rejects that port;
    // an unrelated listener's disappearance does not invalidate every port.
    let table = e
        .table
        .lines()
        .map(|line| {
            let mut fields = line
                .split_whitespace()
                .map(str::to_string)
                .collect::<Vec<_>>();
            let claims = fields
                .iter()
                .enumerate()
                .skip(6)
                .filter_map(|(i, v)| {
                    v.split_once(':')
                        .and_then(|(_, p)| p.parse::<u32>().ok())
                        .map(|p| (i, p))
                })
                .collect::<Vec<_>>();
            let verified = claims.len() == 1
                && e.owners
                    .get(&claims[0].1)
                    .zip(current.get(&claims[0].1))
                    .is_some_and(|(a, b)| same(a, b));
            if !verified {
                for (i, _) in claims {
                    fields[i] = "unconfirmed_owner".into();
                }
            }
            fields.join(" ")
        })
        .collect::<Vec<_>>()
        .join("\n");
    if !(0.0..=MAX_AGE).contains(&(native::now() - e.finished)) {
        return Err(error("native_listener_stale", "系统监听采样在复核期间过期"));
    }
    Ok(Output {
        status: 0,
        stdout: format!("{FRAME_META_PREFIX}{}\n{table}", json!({
            "captured_at": e.finished, "sequence": e.sequence,
            "origin_id": format!("{}:{}:{}:{}:{}:{}", p.supervisor.pid,
                p.supervisor.start_seconds, p.supervisor.start_microseconds,
                p.collector.pid, p.collector.start_seconds, p.collector.start_microseconds),
        })).into_bytes(),
        stderr: vec![],
    })
}

pub struct ListenerStream {
    root: PathBuf,
    worker: Identity,
    supervisor: Identity,
    state: Arc<(Mutex<Option<Result<Evidence>>>, Condvar)>,
    revision: Arc<AtomicU64>,
    published_revision: Mutex<Option<u64>>,
    finished: Arc<AtomicBool>,
}
impl ListenerStream {
    pub fn start<R: ReadRunner>(runner: &R, executable: &Path) -> Result<Arc<Self>> {
        if std::io::stdin().is_terminal()
            || !fs::metadata("/dev/fd/0").is_ok_and(|m| m.file_type().is_fifo())
        {
            return Err(error(
                "native_listener_pipe_required",
                "系统监听数据必须来自固定监督进程的管道",
            ));
        }
        let root =
            fs::canonicalize(executable.parent().ok_or_else(invalid)?).map_err(|_| invalid())?;
        let worker = runner.process_identity(std::process::id()).ok_or_else(invalid)?;
        let supervisor = runner.process_identity(worker.parent).ok_or_else(invalid)?;
        resources(&root, worker.uid)?;
        let state = Arc::new((Mutex::new(None), Condvar::new()));
        let shared = state.clone();
        let revision = Arc::new(AtomicU64::new(0));
        let reader_revision = revision.clone();
        let finished = Arc::new(AtomicBool::new(false));
        let reader_finished = finished.clone();
        thread::Builder::new()
            .name("native-listener-input".into())
            .spawn(move || {
                let mut reader = BufReader::new(std::io::stdin());
                let mut sequence = 0;
                loop {
                    let (raw, stop) = match frame(&mut reader) {
                        Ok(Some(raw)) if raw.sequence > sequence => {
                            sequence = raw.sequence;
                            (normalize(raw), false)
                        }
                        Ok(None) => (
                            Err(error("native_listener_closed", "系统采样通道已关闭")),
                            true,
                        ),
                        _ => (Err(invalid()), true),
                    };
                    if let Ok(mut latest) = shared.0.lock() {
                        *latest = Some(raw);
                        reader_revision.fetch_add(1, Ordering::Release);
                        shared.1.notify_all();
                    } else {
                        break;
                    }
                    if stop {
                        break;
                    }
                }
                reader_finished.store(true, Ordering::Release);
            })
            .map_err(|_| error("native_listener_start_failed", "无法启动系统采样读取线程"))?;
        Ok(Arc::new(Self {
            root,
            worker,
            supervisor,
            state,
            revision,
            published_revision: Mutex::new(None),
            finished,
        }))
    }
    pub fn is_finished(&self) -> bool {
        self.finished.load(Ordering::Acquire)
    }
    fn latest_with_timeout(&self, timeout: Duration) -> Result<Evidence> {
        self.publication_snapshot(timeout)?.1
    }
    fn publication_snapshot(&self, timeout: Duration) -> Result<(u64, Result<Evidence>)> {
        let mut state = self.state.0.lock().map_err(|_| invalid())?;
        if state.is_none() {
            state = self
                .state
                .1
                .wait_timeout_while(state, timeout, |s| s.is_none())
                .map_err(|_| invalid())?
                .0;
        }
        let observed = state
            .clone()
            .unwrap_or_else(|| Err(error("native_listener_pending", "尚未收到系统监听采样")));
        Ok((self.revision.load(Ordering::Acquire), observed))
    }
    fn proof<R: ReadRunner>(&self, e: &Evidence, runner: &R) -> Result<Proof> {
        let collector = runner.process_identity(e.collector)
            .ok_or_else(|| error("native_listener_origin_changed", "系统采样进程已退出"))?;
        Ok(Proof {
            supervisor: self.supervisor.clone(),
            worker: self.worker.clone(),
            collector,
            root: self.root.clone(),
        })
    }
    pub fn read<R: ReadRunner>(&self, runner: &R) -> Result<Output> {
        self.read_with_timeout(runner, Duration::from_secs(5))
    }
    pub(crate) fn read_with_timeout<R: ReadRunner>(&self, runner: &R, timeout: Duration) -> Result<Output> {
        let e = self.latest_with_timeout(timeout)?;
        let p = self.proof(&e, runner)?;
        output(&e, &p, runner, false)
    }
    pub fn publish<R: ReadRunner>(&self, store: &StateStore, runner: &R) -> Result<()> {
        let (revision, observed) = self.publication_snapshot(Duration::from_secs(5))?;
        self.publish_observation(store, runner, observed)?;
        *self.published_revision.lock().map_err(|_| invalid())? = Some(revision);
        Ok(())
    }
    fn publish_changed<R: ReadRunner>(&self, store: &StateStore, runner: &R,
        previous: &mut Option<u64>) -> Result<bool> {
        let (revision, observed) = {
            let state = self.state.0.lock().map_err(|_| invalid())?;
            let Some(observed) = state.as_ref() else { return Ok(false); };
            let revision = self.revision.load(Ordering::Acquire);
            if *previous == Some(revision) { return Ok(false); }
            (revision, observed.clone())
        };
        self.publish_observation(store, runner, observed)?;
        *previous = Some(revision);
        Ok(true)
    }
    fn publish_observation<R: ReadRunner>(&self, store: &StateStore, runner: &R,
        observed: Result<Evidence>) -> Result<()> {
        let bounded = crate::commands::DeadlineRunner::new(runner, Duration::from_secs(1));
        let runner = &bounded;
        let actor = Actor {
            supervisor: self.supervisor.clone(),
            worker: self.worker.clone(),
            root: self.root.clone(),
        };
        let value = (|| {
            verify_actor(&actor, runner, false)?;
            let observed = (|| {
                let e = observed?;
                let p = self.proof(&e, runner)?;
                output(&e, &p, runner, false)?;
                Ok(Captured {
                    proof: p,
                    evidence: e,
                })
            })();
            let (listener, failure) = match observed {
                Ok(v) => (Some(v), None),
                Err(e) => (None, Some(e)),
            };
            serde_json::to_value(Cached {
                schema: 2,
                published_at: native::now(),
                actor,
                listener,
                error: failure,
            })
            .map_err(|_| invalid())
        })();
        store.atomic_json(
            &cache_path(store),
            &value
                .unwrap_or_else(|e| json!({"schema":2,"error":e.code,"observed_at":native::now()})),
        )
    }

    /// Publish new native frames independently from UI/process collection.
    /// Identity checks happen only for a changed frame/error; unchanged frames
    /// retain both their original capture time and cache publication time.
    pub fn start_publisher<R: ReadRunner + Send + Sync + 'static>(self: &Arc<Self>,
        store: StateStore, runner: Arc<R>, stop: Arc<AtomicBool>) -> Result<ListenerCachePublisher> {
        let stream = self.clone();
        let failure = Arc::new(Mutex::new(None));
        let thread_failure = failure.clone();
        let thread_stop = stop.clone();
        // The bootstrap publication may already contain the newest frame.
        let mut previous = *self.published_revision.lock().map_err(|_| invalid())?;
        let worker = thread::Builder::new().name("watch-native-cache-publisher".into()).spawn(move || {
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<()> {
                while !thread_stop.load(Ordering::Acquire) {
                    stream.publish_changed(&store, runner.as_ref(), &mut previous)?;
                    if stream.is_finished() {
                        // EOF can arrive during verification of the preceding
                        // frame. Publish its terminal observation before exit.
                        stream.publish_changed(&store, runner.as_ref(), &mut previous)?;
                        return Err(error("native_listener_worker_failed", "系统采样通道已结束，等待后台重新启动"));
                    }
                    thread::sleep(Duration::from_millis(250));
                }
                Ok(())
            })).unwrap_or_else(|_| Err(error("native_listener_publisher_panicked", "系统采样发布线程异常退出")));
            if let Err(ref error) = outcome {
                let _ = store.atomic_json(&store.paths.watch().join("state/native-listener-publisher-error.json"),
                    &json!({"schema":1,"time":native::now(),"code":error.code}));
                if let Ok(mut failure) = thread_failure.lock() { *failure = Some(error.clone()); }
                thread_stop.store(true, Ordering::Release);
            }
            outcome
        }).map_err(|_| error("native_listener_publisher_start_failed", "系统采样发布线程无法启动"))?;
        Ok(ListenerCachePublisher { stop, failure, worker: Some(worker) })
    }
}

pub struct ListenerCachePublisher {
    stop: Arc<AtomicBool>,
    failure: Arc<Mutex<Option<CoreError>>>,
    worker: Option<thread::JoinHandle<Result<()>>>,
}
impl ListenerCachePublisher {
    pub fn check(&self) -> Result<()> {
        match self.failure.lock().map_err(|_| invalid())?.clone() {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
    pub fn finish(&mut self) -> Result<()> {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            worker.join().unwrap_or_else(|_| Err(error("native_listener_publisher_panicked", "系统采样发布线程异常退出")))?;
        }
        self.check()
    }
}
impl Drop for ListenerCachePublisher {
    fn drop(&mut self) { let _ = self.finish(); }
}
fn cache_path(store: &StateStore) -> PathBuf {
    store.paths.watch().join("state/native-listener.json")
}
fn cached(store: &StateStore) -> Result<Cached> {
    let bytes = store
        .read_bytes(&cache_path(store), MAX_TOTAL)?
        .ok_or_else(|| error("native_listener_missing", "后台尚未发布系统监听采样"))?;
    let raw = crate::storage::strict_json(&bytes)?;
    let c: Cached = serde_json::from_value(raw)
        .map_err(|_| error("native_listener_unavailable", "后台系统监听采样当前不可用"))?;
    if c.schema != 2
        || c.actor.root != store.paths.watch().join("runtime")
        || !c.published_at.is_finite()
        || !(0.0..=30.0).contains(&(native::now() - c.published_at))
        || c.listener.is_some() == c.error.is_some()
    {
        return Err(invalid());
    }
    Ok(c)
}
pub fn read_cached<R: ReadRunner>(store: &StateStore, runner: &R) -> Result<Output> {
    let c = cached(store)?;
    let data = c.listener.ok_or_else(|| {
        c.error
            .unwrap_or_else(|| error("native_listener_unavailable", "本轮系统监听采样不可用"))
    })?;
    if !data.proof.worker.same_process(&c.actor.worker)
        || !data.proof.supervisor.same_process(&c.actor.supervisor)
        || data.proof.root != c.actor.root
    {
        return Err(invalid());
    }
    output(&data.evidence, &data.proof, runner, true)
}
pub fn registered_worker<R: ReadRunner>(store: &StateStore, runner: &R, pid: u32) -> bool {
    registered_worker_result(store, runner, pid).is_ok()
}
pub(crate) fn registered_worker_result<R: ReadRunner>(store: &StateStore, runner: &R, pid: u32) -> Result<()> {
    let c = cached(store)?;
    if c.actor.worker.pid != pid {
        return Err(error("native_listener_worker_mismatch", "采样记录中的 worker PID 与心跳 PID 不一致"));
    }
    verify_actor(&c.actor, runner, true)
}
pub fn cache_exists(store: &StateStore) -> bool {
    cache_path(store).exists()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::ObserverAction;
    use std::io::Cursor;

    fn raw() -> Raw {
        let rows=b"100 1 501 Mon Oct 26 20:45:10 2026 /bin/zsh\n101 100 501 Mon Oct 26 20:45:11 2026 /bin/zsh\n102 1 0 Mon Oct 26 20:40:00 2026 /Applications/TAG.app/Contents/Resources/bin/mihomo-tag\n".to_vec();
        Raw {
            supervisor: 100,
            collector: 101,
            sequence: 1,
            started: 1000.,
            finished: 1001.,
            statuses: [0, 0, 0],
            before: rows.clone(),
            table: b"tcp4 0 0 127.0.0.1.7890 *.* LISTEN 0 0 0 0 mihomo:102\n".to_vec(),
            errors: vec![],
            after: rows,
        }
    }
    fn encoded(r: &Raw) -> Vec<u8> {
        let mut data = format!(
            "CWLISTENER1 {} {} {} {} {} {} {} {} {} {} {} {}\n",
            r.supervisor,
            r.collector,
            r.sequence,
            r.started,
            r.finished,
            r.statuses[0],
            r.statuses[1],
            r.statuses[2],
            r.before.len(),
            r.table.len(),
            r.errors.len(),
            r.after.len()
        )
        .into_bytes();
        for p in [&r.before, &r.table, &r.errors, &r.after] {
            data.extend(p);
        }
        data.push(b'\n');
        data
    }
    #[test]
    fn frame_preserves_boundaries_and_rejects_partial_or_oversized_data() {
        let mut sample = raw();
        sample.started = 1000.125;
        sample.finished = 1001.25;
        let mut data = encoded(&sample);
        let r = frame(&mut Cursor::new(&data)).unwrap().unwrap();
        assert_eq!((r.started, r.finished), (1000.125, 1001.25));
        assert_eq!(normalize(r).unwrap().owners.len(), 1);
        data.pop();
        assert!(frame(&mut Cursor::new(data)).is_err());
        assert!(frame(&mut Cursor::new(
            b"CWLISTENER1 100 101 1 1000 1001 0 0 0 999999999 0 0 0\n"
        ))
        .is_err());
        assert!(frame(&mut Cursor::new(
            b"CWLISTENER1 100 101 0 1000 1001 0 0 0 0 0 0 0\n\n"
        ))
        .is_err());
    }
    #[test]
    fn failed_command_and_changed_capture_origin_are_not_success() {
        let mut r = raw();
        r.statuses[1] = 1;
        assert_eq!(
            normalize(r).err().unwrap().code,
            "native_listener_sample_failed"
        );
        let mut r = raw();
        r.after = String::from_utf8(r.after)
            .unwrap()
            .replace("20:45:11", "20:45:12")
            .into_bytes();
        assert_eq!(normalize(r).err().unwrap().code, "native_listener_protocol");
    }
    #[test]
    fn unrelated_missing_owner_does_not_remove_the_target_listener() {
        let mut r = raw();
        r.table
            .extend_from_slice(b"tcp4 0 0 *.9999 *.* LISTEN 0 0 0 0 unknown\n");
        let e = normalize(r).unwrap();
        assert_eq!(e.owners.len(), 1);
        assert!(e.owners.contains_key(&102));
        let mut r = raw();
        r.after = String::from_utf8(r.after)
            .unwrap()
            .replace("20:40:00", "20:40:01")
            .into_bytes();
        assert!(!normalize(r).unwrap().owners.contains_key(&102));
    }
    fn identity(pid: u32, parent: u32, uid: u32, exe: String) -> Identity {
        Identity {
            pid,
            parent,
            uid,
            executable: exe,
            start_seconds: 1000,
            start_microseconds: 1,
            start_stamp: "Mon Oct 26 20:45:10 2026".into(),
        }
    }
    #[test]
    fn missing_first_listener_frame_respects_caller_budget() {
        struct Unused;
        impl ReadRunner for Unused {
            fn run(&self, _: ReadCommand, _: &[u8], _: Duration, _: usize) -> Result<Output> {
                panic!("missing listener frame must not start identity queries");
            }
        }
        let stream = ListenerStream {
            root: PathBuf::from("/fixture"),
            worker: identity(101, 100, 501, "/fixture/worker".into()),
            supervisor: identity(100, 1, 501, "/bin/zsh".into()),
            state: Arc::new((Mutex::new(None), Condvar::new())),
            revision: Arc::new(AtomicU64::new(0)), published_revision: Mutex::new(None),
            finished: Arc::new(AtomicBool::new(false)),
        };
        let started = std::time::Instant::now();
        let error = stream.read_with_timeout(&Unused, Duration::from_millis(40)).err().unwrap();
        assert_eq!(error.code, "native_listener_pending");
        assert!(started.elapsed() < Duration::from_millis(400), "must not wait the old five-second default");
    }
    struct Source {
        proof: Proof,
        job_pid: u32,
        changed: bool,
        extra_supervisor_argument: bool,
    }
    struct PublisherFixture {
        home: PathBuf,
        store: StateStore,
        stream: Arc<ListenerStream>,
        source: Arc<Source>,
    }
    impl PublisherFixture {
        fn new() -> Self {
            use std::os::unix::fs::PermissionsExt;
            let home = std::env::temp_dir().join(format!("cw-independent-listener-{}",uuid::Uuid::new_v4()));
            fs::create_dir(&home).unwrap();
            let store = StateStore::new(crate::storage::Paths::new(&home).unwrap());
            let root = store.paths.watch().join("runtime");
            fs::create_dir_all(&root).unwrap();
            fs::write(root.join(SCRIPT),SCRIPT_BYTES).unwrap();
            fs::write(root.join("watch-engine"),b"fixture").unwrap();
            fs::set_permissions(root.join("watch-engine"),fs::Permissions::from_mode(0o700)).unwrap();
            let uid = fs::metadata(&home).unwrap().uid();
            let mut proof = Proof { supervisor:identity(100,1,uid,"/bin/zsh".into()),
                worker:identity(103,100,uid,root.join("watch-engine").display().to_string()),
                collector:identity(101,100,uid,"/bin/zsh".into()),root:root.clone() };
            proof.collector.start_stamp = "Mon Oct 26 20:45:11 2026".into();
            let source = Arc::new(Source { proof:proof.clone(),job_pid:100,changed:false,extra_supervisor_argument:false });
            let stream = Arc::new(ListenerStream { root,worker:proof.worker,supervisor:proof.supervisor,
                state:Arc::new((Mutex::new(None),Condvar::new())),revision:Arc::new(AtomicU64::new(0)),
                published_revision:Mutex::new(None),finished:Arc::new(AtomicBool::new(false)) });
            let fixture = Self { home,store,stream,source };
            fixture.frame(1);
            fixture
        }
        fn set(&self, observed: Result<Evidence>) {
            let mut state = self.stream.state.0.lock().unwrap();
            *state = Some(observed);
            self.stream.revision.fetch_add(1,Ordering::Release);
        }
        fn frame(&self, sequence: u64) -> f64 {
            let mut raw = raw();
            raw.sequence = sequence; raw.started = native::now()-0.25; raw.finished = raw.started;
            raw.before = String::from_utf8(raw.before).unwrap().replace(" 501 ",&format!(" {} ",self.source.proof.worker.uid)).into_bytes();
            raw.after = raw.before.clone();
            let at = raw.finished;
            self.set(normalize(raw)); at
        }
    }
    impl Drop for PublisherFixture {
        fn drop(&mut self) { let _ = fs::remove_dir_all(&self.home); }
    }
    #[test]
    fn independent_publisher_updates_during_blocked_collection_without_refreshing_the_same_frame() {
        let fixture = PublisherFixture::new();
        fixture.stream.publish(&fixture.store,fixture.source.as_ref()).unwrap();
        let bootstrap = fs::read(cache_path(&fixture.store)).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let mut publisher = fixture.stream.start_publisher(fixture.store.clone(),fixture.source.clone(),stop).unwrap();
        thread::sleep(Duration::from_millis(300));
        assert_eq!(fs::read(cache_path(&fixture.store)).unwrap(),bootstrap,"bootstrap frame must not be republished");
        let (release,blocked) = std::sync::mpsc::channel::<()>();
        let slow_main = thread::spawn(move || blocked.recv_timeout(Duration::from_secs(3)));
        let captured_at = fixture.frame(2);
        let deadline = std::time::Instant::now()+Duration::from_secs(2);
        while cached(&fixture.store).unwrap().listener.unwrap().evidence.sequence != 2
            && std::time::Instant::now()<deadline { thread::sleep(Duration::from_millis(10)); }
        let updated = cached(&fixture.store).unwrap();
        assert_eq!(updated.listener.unwrap().evidence.sequence,2);
        assert!(!slow_main.is_finished(),"cache must advance while the UI collector remains blocked");
        let output = read_cached(&fixture.store,fixture.source.as_ref()).unwrap();
        let metadata: Value = serde_json::from_str(output.text().unwrap().lines().next().unwrap().strip_prefix(FRAME_META_PREFIX).unwrap()).unwrap();
        assert_eq!(metadata["captured_at"],captured_at);
        let bytes = fs::read(cache_path(&fixture.store)).unwrap();
        thread::sleep(Duration::from_millis(550));
        assert_eq!(fs::read(cache_path(&fixture.store)).unwrap(),bytes,"same evidence cannot receive a fresh cache timestamp");
        publisher.finish().unwrap();
        let _ = release.send(()); let _ = slow_main.join();
    }
    #[test]
    fn native_publisher_eof_and_write_failure_stop_workers_and_preserve_terminal_error() {
        for eof in [true,false] {
            let fixture = PublisherFixture::new();
            fixture.stream.publish(&fixture.store,fixture.source.as_ref()).unwrap();
            let stop = Arc::new(AtomicBool::new(false));
            if eof {
                fixture.set(Err(error("native_listener_closed","fixture EOF")));
                fixture.stream.finished.store(true,Ordering::Release);
            } else {
                fs::remove_file(cache_path(&fixture.store)).unwrap();
                fs::create_dir(cache_path(&fixture.store)).unwrap();
                fixture.frame(2);
            }
            let mut publisher = fixture.stream.start_publisher(fixture.store.clone(),fixture.source.clone(),stop.clone()).unwrap();
            let deadline = std::time::Instant::now()+Duration::from_secs(2);
            while !stop.load(Ordering::Acquire) && std::time::Instant::now()<deadline { thread::sleep(Duration::from_millis(10)); }
            assert!(stop.load(Ordering::Acquire));
            assert!(publisher.check().is_err());
            assert!(publisher.finish().is_err());
            let terminal = fixture.store.read_json(&fixture.store.paths.watch().join("state/native-listener-publisher-error.json"),Value::Null).unwrap();
            assert!(terminal["code"].is_string());
            if eof { assert_eq!(read_cached(&fixture.store,fixture.source.as_ref()).err().unwrap().code,"native_listener_closed"); }
        }
    }
    #[test]
    fn native_publication_shares_one_total_validation_budget() {
        struct Slow { source: Arc<Source>, calls: Mutex<Vec<Duration>> }
        impl ReadRunner for Slow {
            fn process_identity(&self,pid:u32)->Option<Identity> { self.source.as_ref().process_identity(pid) }
            fn run(&self,c:ReadCommand,input:&[u8],timeout:Duration,limit:usize)->Result<Output> {
                self.calls.lock().unwrap().push(timeout);
                if timeout < Duration::from_millis(600) {
                    thread::sleep(timeout); return Err(error("command_timeout","fixture bounded timeout"));
                }
                thread::sleep(Duration::from_millis(600));
                self.source.run(c,input,timeout,limit)
            }
        }
        let fixture=PublisherFixture::new();
        let slow=Slow {source:fixture.source.clone(),calls:Mutex::new(vec![])};
        let started=std::time::Instant::now();
        fixture.stream.publish(&fixture.store,&slow).unwrap();
        assert!(started.elapsed()<Duration::from_millis(1500));
        let calls=slow.calls.lock().unwrap();
        assert!(calls.len()>=2,"calls={calls:?}; cache={}",fs::read_to_string(cache_path(&fixture.store)).unwrap());
        assert!(calls[0]<=Duration::from_secs(1));
        assert!(calls[1]<Duration::from_millis(500));
        assert_eq!(cached(&fixture.store).unwrap().error.unwrap().code,"command_timeout");
    }
    impl ReadRunner for Source {
        fn process_identity(&self, pid: u32) -> Option<Identity> {
            let mut identity = [&self.proof.supervisor, &self.proof.worker, &self.proof.collector]
                .into_iter().find(|identity| identity.pid == pid)?.clone();
            if self.changed && pid == self.proof.worker.pid { identity.start_microseconds += 1; }
            Some(identity)
        }
        fn run(&self, c: ReadCommand, input: &[u8], _: Duration, _: usize) -> Result<Output> {
            if let ReadCommand::ProcessTablePids { ref pids } = c {
                let table = String::from_utf8(raw().after).unwrap();
                return Ok(Output {
                    status: 0,
                    stdout: table.lines().filter(|row| row.split_whitespace().next()
                        .and_then(|pid| pid.parse::<u32>().ok()).is_some_and(|pid| pids.contains(&pid)))
                        .collect::<Vec<_>>().join("\n").into_bytes(),
                    stderr: vec![],
                });
            }
            if matches!(c, ReadCommand::LaunchctlGuiAgent { .. }) {
                return Ok(Output {
                    status: 0,
                    stdout: format!("state = running\npid = {}\n", self.job_pid).into_bytes(),
                    stderr: vec![],
                });
            }
            let r: Value = serde_json::from_slice(input).unwrap();
            let now = native::now();
            let mut v = json!({"schema":1,"status":"ok","uid":self.proof.worker.uid,"started_at":now,"finished_at":now,"round_id":r["round_id"]});
            let ids = [
                self.proof.supervisor.clone(),
                self.proof.worker.clone(),
                self.proof.collector.clone(),
            ];
            match c {
                ReadCommand::Observer(ObserverAction::Identities) => {
                    v["identities"] = json!(ids
                        .iter()
                        .filter(|i| r["targets"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .any(|t| t["pid"] == i.pid))
                        .map(|i| {
                            let mut id = i.clone();
                            if self.changed && id.pid == self.proof.worker.pid {
                                id.start_microseconds += 1;
                            }
                            json!({"pid":i.pid,"state":"ok","identity":id})
                        })
                        .collect::<Vec<_>>());
                }
                ReadCommand::Observer(ObserverAction::Arguments) => {
                    v["argument_prefixes"]=json!([(&self.proof.supervisor,false),(&self.proof.collector,true)].iter().filter(|(id,_)|r["targets"].as_array().unwrap().iter().any(|t|t["pid"]==id.pid)).map(|(id,collect)|{let mut args=vec!["/bin/zsh".to_string(),"-f".into(),self.proof.root.join(SCRIPT).display().to_string()];if *collect{args.extend(["--collect".into(),self.proof.supervisor.pid.to_string()]);}else{args.extend(["daemon".into(),"--apply".into()]);if self.extra_supervisor_argument{args.push("--observe-only".into());}}json!({"pid":id.pid,"state":"ok","identity":id,"arguments":args,"cwd":"/tmp","truncated":false})}).collect::<Vec<_>>());
                }
                _ => panic!("unexpected source operation"),
            }
            Ok(Output {
                status: 0,
                stdout: serde_json::to_vec(&v).unwrap(),
                stderr: vec![],
            })
        }
    }
    #[test]
    fn source_requires_fixed_job_live_birth_identity_and_unchanged_component() {
        let root =
            std::env::temp_dir().join(format!("cw-listener-origin-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&root).unwrap();
        fs::write(root.join(SCRIPT), SCRIPT_BYTES).unwrap();
        fs::write(root.join("watch-engine"), b"fixture").unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(root.join("watch-engine"), fs::Permissions::from_mode(0o700))
                .unwrap();
        }
        let uid = fs::metadata(&root).unwrap().uid();
        let p = Proof {
            supervisor: identity(100, 1, uid, "/bin/zsh".into()),
            worker: identity(
                102,
                100,
                uid,
                root.join("watch-engine").display().to_string(),
            ),
            collector: identity(101, 100, uid, "/bin/zsh".into()),
            root: root.clone(),
        };
        let mut r = Source {
            proof: p.clone(),
            job_pid: 100,
            changed: false,
            extra_supervisor_argument: false,
        };
        verify(&p, &r, true).unwrap();
        r.extra_supervisor_argument = true;
        assert_eq!(
            verify(&p, &r, true).unwrap_err().code,
            "native_listener_origin_invalid"
        );
        r.extra_supervisor_argument = false;
        r.job_pid = 999;
        assert_eq!(
            verify(&p, &r, true).unwrap_err().code,
            "native_listener_unregistered"
        );
        r.job_pid = 100;
        r.changed = true;
        assert_eq!(
            verify(&p, &r, true).unwrap_err().code,
            "native_listener_origin_changed"
        );
        r.changed = false;
        // Exercise the actual stream fast path using a read runner that rejects
        // every whole-machine operation. Two reads of one frame retain its
        // capture time and each use just one argv + one targeted ps command.
        struct Counted<'a> { source: &'a Source, calls: std::cell::RefCell<Vec<&'static str>> }
        impl ReadRunner for Counted<'_> {
            fn process_identity(&self, pid: u32) -> Option<Identity> {
                self.calls.borrow_mut().push("fixed_identity");
                self.source.process_identity(pid)
            }
            fn run(&self, command: ReadCommand, input: &[u8], timeout: Duration, limit: usize) -> Result<Output> {
                self.calls.borrow_mut().push(match &command {
                    ReadCommand::Observer(ObserverAction::Arguments) => "fixed_arguments",
                    ReadCommand::ProcessTablePids { pids } => { assert_eq!(pids, &vec![102]); "targeted_ps" },
                    _ => panic!("fast listener path attempted a global/unexpected read: {command:?}"),
                });
                self.source.run(command, input, timeout, limit)
            }
        }
        let mut frame = normalize(raw()).unwrap();
        frame.started = native::now() - 1.0;
        frame.finished = frame.started;
        frame.origins.insert(100, json!({"uid":uid,"executable":"/bin/zsh","stamp":p.supervisor.start_stamp}));
        frame.origins.insert(101, json!({"uid":uid,"executable":"/bin/zsh","stamp":p.collector.start_stamp}));
        let captured_at = frame.finished;
        let stream = ListenerStream { root: root.clone(), supervisor: p.supervisor.clone(), worker: p.worker.clone(),
            state: Arc::new((Mutex::new(Some(Ok(frame))), Condvar::new())), revision: Arc::new(AtomicU64::new(1)),
            published_revision: Mutex::new(None), finished: Arc::new(AtomicBool::new(false)) };
        let counted = Counted { source: &r, calls: std::cell::RefCell::new(Vec::new()) };
        for _ in 0..2 {
            let out = stream.read_with_timeout(&counted, Duration::from_secs(1)).unwrap();
            let metadata = out.text().unwrap().lines().next().unwrap().strip_prefix(FRAME_META_PREFIX).unwrap();
            let metadata: Value = serde_json::from_str(metadata).unwrap();
            assert_eq!(metadata["captured_at"].as_f64(), Some(captured_at));
            assert_eq!(metadata["sequence"], 1);
        }
        let calls = counted.calls.borrow();
        assert_eq!(calls.iter().filter(|&&kind| kind == "fixed_arguments").count(), 2);
        assert_eq!(calls.iter().filter(|&&kind| kind == "targeted_ps").count(), 2);
        assert_eq!(calls.iter().filter(|&&kind| kind == "fixed_identity").count(), 14);
        drop(calls);
        fs::write(root.join(SCRIPT), b"changed").unwrap();
        assert_eq!(
            verify(&p, &r, true).unwrap_err().code,
            "native_listener_component_changed"
        );
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn sampling_failure_does_not_erase_actor_identity_or_yield_listener_data() {
        let home = std::env::temp_dir().join(format!("cw-listener-cache-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&home).unwrap();
        let store = StateStore::new(crate::storage::Paths::new(&home).unwrap());
        let root = store.paths.watch().join("runtime");
        let uid = fs::metadata(&home).unwrap().uid();
        let mut p = Proof {
            supervisor: identity(100, 1, uid, "/bin/zsh".into()),
            worker: identity(
                103,
                100,
                uid,
                root.join("watch-engine").display().to_string(),
            ),
            collector: identity(101, 100, uid, "/bin/zsh".into()),
            root,
        };
        p.collector.start_stamp = "Mon Oct 26 20:45:11 2026".into();
        fs::create_dir_all(&p.root).unwrap();
        fs::write(p.root.join(SCRIPT), SCRIPT_BYTES).unwrap();
        fs::write(p.root.join("watch-engine"), b"fixture").unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(
                p.root.join("watch-engine"),
                fs::Permissions::from_mode(0o700),
            )
            .unwrap();
        }
        let r = Source {
            proof: p.clone(),
            job_pid: 100,
            changed: false,
            extra_supervisor_argument: false,
        };
        let mut e = raw();
        let now = native::now().floor();
        e.started = now;
        e.finished = now;
        e.before = String::from_utf8(e.before)
            .unwrap()
            .replace(" 501 ", &format!(" {uid} "))
            .into_bytes();
        e.after = e.before.clone();
        let mut c = Cached {
            schema: 2,
            published_at: native::now(),
            actor: Actor {
                supervisor: p.supervisor.clone(),
                worker: p.worker.clone(),
                root: p.root.clone(),
            },
            listener: Some(Captured {
                proof: p,
                evidence: normalize(e).unwrap(),
            }),
            error: None,
        };
        let save = |c: &Cached| {
            store
                .atomic_json(&cache_path(&store), &serde_json::to_value(c).unwrap())
                .unwrap()
        };
        save(&c);
        assert!(registered_worker(&store, &r, 103));
        assert!(read_cached(&store, &r).is_ok());
        c.error = Some(error(
            "native_listener_sample_failed",
            "contradictory cache",
        ));
        save(&c);
        assert!(!registered_worker(&store, &r, 103));
        assert!(read_cached(&store, &r).is_err());
        c.error = None;
        let data = c.listener.as_mut().unwrap();
        data.evidence.finished -= 60.0;
        data.evidence.started -= 60.0;
        save(&c);
        assert!(registered_worker(&store, &r, 103));
        assert_eq!(
            read_cached(&store, &r).err().unwrap().code,
            "native_listener_stale"
        );
        c.published_at -= 31.0;
        save(&c);
        assert!(!registered_worker(&store, &r, 103));
        c.published_at = native::now();
        c.listener = None;
        c.error = Some(error("native_listener_sample_failed", "failed source"));
        save(&c);
        assert!(registered_worker(&store, &r, 103));
        assert_eq!(
            read_cached(&store, &r).err().unwrap().code,
            "native_listener_sample_failed"
        );
        let mut r = r;
        r.changed = true;
        assert!(!registered_worker(&store, &r, 103));
        store
            .atomic_json(
                &cache_path(&store),
                &json!({"schema":2,"error":"origin unavailable"}),
            )
            .unwrap();
        assert!(!registered_worker(&store, &r, 103));
        fs::remove_dir_all(home).unwrap();
    }
}
