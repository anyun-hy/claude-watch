//! Capacity is shared by both listeners and survives listener replacement.
use claude_watch_core::channel::BoundProcessToken;
use std::{collections::BTreeMap, sync::{Arc, Mutex}, time::{Duration, Instant}};

pub(crate) const MAX_HTTP_BODY_BYTES: usize = 16 * 1024 * 1024;
pub(crate) const MAX_CHUNK_METADATA_BYTES: usize = 64 * 1024;

type Source = (u32, u32, u64, u32, Option<[u32; 8]>);
fn source(process: &BoundProcessToken) -> Source {
    (process.pid, process.uid, process.start_seconds, process.start_microseconds, process.audit_token)
}

#[derive(Default)]
struct Use {
    connections: usize,
    flows: usize,
    bodies: usize,
    bytes: usize,
}
#[derive(Default)]
struct State {
    all: Use,
    unattributed: usize,
    lookups: usize,
    next_diagnostic: Option<Instant>,
    sources: BTreeMap<Source, Use>,
}

pub(crate) struct Limits {
    pub(crate) connections: usize,
    pub(crate) unattributed: usize,
    pub(crate) lookups: usize,
    pub(crate) flows: usize,
    pub(crate) per_source: usize,
    pub(crate) bytes: usize,
    pub(crate) bytes_per_source: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self { connections: 64, unattributed: 16, lookups: 8, flows: 64, per_source: 16,
            bytes: 64 * 1024 * 1024, bytes_per_source: 32 * 1024 * 1024 }
    }
}

#[derive(Default)]
pub(crate) struct GatewayBudget {
    limits: Limits,
    used: Mutex<State>,
}

#[derive(Clone, Copy)]
enum Kind {
    Connection(Option<Source>),
    Lookup,
    Body(Source, usize),
    Flow(Source),
}
pub(crate) struct Slot {
    budget: Arc<GatewayBudget>,
    kind: Kind,
}
impl GatewayBudget {
    fn slot(self: &Arc<Self>, kind: Kind) -> Slot { Slot { budget: self.clone(), kind } }

    pub(crate) fn connection(self: &Arc<Self>) -> Option<Slot> {
        let mut used = self.used.lock().ok()?;
        if used.all.connections >= self.limits.connections || used.unattributed >= self.limits.unattributed {
            return None;
        }
        used.all.connections += 1;
        used.unattributed += 1;
        Some(self.slot(Kind::Connection(None)))
    }

    pub(crate) fn lookup(self: &Arc<Self>) -> Option<Slot> {
        let mut used = self.used.lock().ok()?;
        if used.lookups >= self.limits.lookups { return None; }
        used.lookups += 1;
        Some(self.slot(Kind::Lookup))
    }

    pub(crate) fn flow(self: &Arc<Self>, process: &BoundProcessToken) -> Option<Slot> {
        let key = source(process);
        let mut used = self.used.lock().ok()?;
        if used.all.flows >= self.limits.flows
            || used.sources.get(&key).is_some_and(|s| s.flows >= self.limits.per_source)
        { return None; }
        used.all.flows += 1;
        used.sources.entry(key).or_default().flows += 1;
        Some(self.slot(Kind::Flow(key)))
    }

    pub(crate) fn diagnostic_allowed(&self) -> bool {
        let Ok(mut used) = self.used.lock() else { return false; };
        let now = Instant::now();
        if used.next_diagnostic.is_some_and(|t| now < t) { return false; }
        used.next_diagnostic = Some(now + Duration::from_secs(1));
        true
    }

    #[cfg(test)]
    pub(crate) fn with_limits(limits: Limits) -> Self { Self { limits, used: Mutex::default() } }

    #[cfg(test)]
    pub(crate) fn connections_in_use(&self) -> usize { self.used.lock().unwrap().all.connections }
}
impl Slot {
    pub(crate) fn bind(&mut self, process: &BoundProcessToken) -> bool {
        let key = source(process);
        match self.kind {
            Kind::Connection(Some(previous)) => return key == previous,
            Kind::Connection(None) => {},
            _ => return false,
        }
        let Ok(mut used) = self.budget.used.lock() else { return false; };
        if used.sources.get(&key).is_some_and(|s| s.connections >= self.budget.limits.per_source) {
            return false;
        }
        used.sources.entry(key).or_default().connections += 1;
        used.unattributed -= 1;
        self.kind = Kind::Connection(Some(key));
        true
    }

    pub(crate) fn body(&self, bytes: usize) -> Option<Slot> {
        let Kind::Connection(Some(key)) = self.kind else { return None; };
        let mut used = self.budget.used.lock().ok()?;
        let current = used.sources.get(&key)?.bytes;
        if used.all.bytes.checked_add(bytes)? > self.budget.limits.bytes
            || current.checked_add(bytes)? > self.budget.limits.bytes_per_source
        { return None; }
        used.all.bytes += bytes;
        let source = used.sources.get_mut(&key)?;
        source.bytes += bytes;
        source.bodies += 1;
        Some(self.budget.slot(Kind::Body(key, bytes)))
    }

    pub(crate) fn grow_body_to(&mut self, capacity: usize) -> bool {
        let Kind::Body(key, previous) = self.kind else { return false; };
        let Some(additional) = capacity.checked_sub(previous) else { return true; };
        let Ok(mut used) = self.budget.used.lock() else { return false; };
        let source = &used.sources[&key];
        if used.all.bytes.saturating_add(additional) > self.budget.limits.bytes
            || source.bytes.saturating_add(additional) > self.budget.limits.bytes_per_source
        { return false; }
        used.all.bytes += additional;
        used.sources.get_mut(&key).unwrap().bytes += additional;
        self.kind = Kind::Body(key, capacity);
        true
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        let mut used = self.budget.used.lock().unwrap_or_else(|e| e.into_inner());
        let key = match self.kind {
            Kind::Connection(key) => {
                used.all.connections -= 1;
                if let Some(k) = key { used.sources.get_mut(&k).unwrap().connections -= 1; }
                else { used.unattributed -= 1; }
                key
            }
            Kind::Lookup => { used.lookups -= 1; None }
            Kind::Body(key, bytes) => {
                used.all.bytes -= bytes;
                let source = used.sources.get_mut(&key).unwrap();
                source.bytes -= bytes;
                source.bodies -= 1;
                Some(key)
            }
            Kind::Flow(key) => {
                used.all.flows -= 1;
                used.sources.get_mut(&key).unwrap().flows -= 1;
                Some(key)
            }
        };
        if let Some(key) = key {
            let s = &used.sources[&key];
            if s.connections == 0 && s.flows == 0 && s.bodies == 0 { used.sources.remove(&key); }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use claude_watch_core::processes::ProcessRole;
    #[test]
    fn gateway_budget_releases_attribution_source_body_and_flow_slots() {
        let budget = Arc::new(GatewayBudget::with_limits(Limits {
            connections: 2, unattributed: 1, lookups: 1, flows: 2,
            per_source: 1, bytes: 8, bytes_per_source: 6,
        }));
        let source = |pid| BoundProcessToken::with_system_identity(pid, 501, 100, 0, ProcessRole::Cli);
        let a = source(101);
        let b = source(102);
        let mut first = budget.connection().unwrap();
        assert!(budget.connection().is_none());
        let lookup = budget.lookup().unwrap();
        assert!(budget.lookup().is_none());
        drop(lookup);
        assert!(budget.lookup().is_some());
        assert!(first.bind(&a));
        let mut second = budget.connection().unwrap();
        assert!(!second.bind(&a) && second.bind(&b));
        assert!(budget.connection().is_none());
        let body = first.body(6).unwrap();
        assert!(first.body(1).is_none());
        assert!(second.body(3).is_none() && second.body(2).is_some());
        let mut chunked = second.body(0).unwrap();
        assert!(!chunked.grow_body_to(3));
        assert!(chunked.grow_body_to(2));
        drop(body);
        assert!(chunked.grow_body_to(6));
        drop(chunked);
        let flow = budget.flow(&a).unwrap();
        assert!(budget.flow(&a).is_none());
        assert!(budget.flow(&b).is_some());
        drop(first);
        assert!(budget.flow(&a).is_none(), "detached relays retain their flow budget");
        drop(flow);
        assert!(budget.flow(&a).is_some() && budget.connection().is_some());
        drop(second);
        assert_eq!(budget.connections_in_use(), 0);
        assert!(budget.used.lock().unwrap().sources.is_empty());
    }
}
