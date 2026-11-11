//! Seatbelt (`nono` capability model) helper registration, post-exec target
//! identity verification, live TCP socket attribution, and gateway server
//! identity gate evaluation (`I01`–`I04`).
//!
//! Safety boundaries:
//! - Helper registration (`I01`) requires kernel peer identity (`LOCAL_PEERTOKEN`)
//!   and dynamic code hash (`sha256_file_hex`) matching the trusted build manifest.
//!   Self-reported PIDs or hashes in the JSON payload are never trusted.
//! - Post-exec verification requires the target process to have executed into
//!   `expected_executable` with a fresh kernel audit token before any data
//!   connection is attributed (`I02`).
//! - Endpoint gate (`I03`): nono permits only the configured localhost port.
//!   The system launchd broker must prove that it owns the listening socket
//!   across worker crashes. This is endpoint non-substitution, not a claim of
//!   cryptographic HTTP proxy authentication. Without an OS-verified listening
//!   descriptor the production backend remains fail-closed.

use crate::storage::StateStore;
use crate::executable_verification::VerificationKey;
use claude_watch_core::{
    channel::{BoundProcessToken, NetworkBackendKind, PolicyVersion},
    controlled_launch::{
        AcceptedConnectionContext, ApprovedScriptCombo, ControlledLaunchRequest, ManagedInstanceState,
        ManagedLaunchInstance, SandboxLaunchEvidence,
    },
    error::{CoreError, Result},
    processes::{LaunchTarget, ProcessRole},
};
use claude_watch_system::{
    attribute_loopback_tcp_peer, effective_uid, inspect_process_identity, list_descendant_pids,
    sha256_bytes_hex, sha256_file_hex, verify_sandbox_helper_peer, SandboxPeerVerifier,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    collections::{BTreeMap, BTreeSet},
    io::{Read, Write},
    net::{Shutdown, SocketAddr},
    os::unix::{
        fs::{DirBuilderExt, PermissionsExt},
        net::{UnixListener, UnixStream},
    },
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread,
    time::Duration,
};
use uuid::Uuid;

///Pinned upstream `nono` commit reference (`nolabs-ai/nono`).
pub const NONO_UPSTREAM_GIT_REV: &str = "e9796cca01eb863a9a83e96c18ae6120aa50beb1";

/// Generates a strict macOS Seatbelt SBPL profile following `nono`'s capability
/// model (`nolabs-ai/nono/crates/nono/src/sandbox/macos.rs`), narrowed for Watch's
/// network supervision boundary:
/// - Denies all outbound/inbound network (`(deny network*)`) including direct
///   public IP, direct VPN port, DNS (53/853), other localhost ports, and
///   arbitrary Unix domain socket network relays.
/// - Permits outbound TCP ONLY to the designated Watch gateway port
///   `(remote tcp "localhost:<gateway_port>")`.
pub fn generate_nono_seatbelt_profile(
    gateway_addr: SocketAddr,
    extra_deny_ports: &[u16],
) -> Result<String> {
    if gateway_addr.ip() != std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST) || gateway_addr.port() == 0 {
        return Err(CoreError::new(
            "invalid_gateway_endpoint",
            "Seatbelt 沙箱仅允许指定非零端口的 127.0.0.1 网关",
        ));
    }
    let port = gateway_addr.port();
    if extra_deny_ports.contains(&port) {
        return Err(CoreError::new(
            "gateway_port_conflicts_with_denied_port",
            "网关端口不得与受禁直连 VPN 端口重合",
        ));
    }
    let mut sbpl = String::new();
    sbpl.push_str("(version 1)\n");
    sbpl.push_str("(allow default)\n");
    sbpl.push_str(";; nono capability restriction: block all direct network, DNS, UDP/QUIC, and Unix socket relays\n");
    sbpl.push_str("(deny network*)\n");
    sbpl.push_str("(allow system-socket)\n");
    for denied in extra_deny_ports {
        if *denied > 0 {
            sbpl.push_str(&format!(
                "(deny network-outbound (remote tcp \"localhost:{denied}\"))\n"
            ));
        }
    }
    sbpl.push_str(&format!(
        "(allow network-outbound (remote tcp \"localhost:{port}\"))\n"
    ));
    Ok(sbpl)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxHelperWireRequest {
    pub request: ControlledLaunchRequest,
    /// Optional self-reported PID (ignored by verifier; tested in I01 to prove
    /// kernel `LOCAL_PEERTOKEN` is authoritative).
    #[serde(default)]
    pub claimed_pid: Option<u32>,
    /// Optional self-reported helper hash (ignored by verifier; tested in I01).
    #[serde(default)]
    pub claimed_helper_sha256: Option<String>,
    pub sandbox_applied: bool,
    pub profile_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxHelperWireResponse {
    pub accepted: bool,
    pub instance_id: Option<String>,
    pub executor_boot_id: String,
    pub error_code: Option<String>,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxGatewayIdentityReport {
    /// I01: Helper Unix peer kernel token + binary SHA-256 verified against manifest.
    pub helper_identity_verified: bool,
    /// I02: Live TCP 4-tuple socket attributed via kernel `PROC_PIDFDSOCKETINFO` + post-exec identity.
    pub tcp_socket_attribution_verified: bool,
    /// Cryptographic client-side server authentication. The launchd backend does
    /// NOT claim this; it supplies a non-substitutable endpoint instead.
    pub gateway_server_identity_verified: bool,
    #[serde(default)]
    pub gateway_endpoint_protection_verified: bool,
    #[serde(default)]
    pub gateway_endpoint_protection_method: Option<String>,
    #[serde(default)]
    pub protected_gateway_endpoint: Option<String>,
    /// I04: Executor `boot_id` + `PolicyVersion` envelope binding rejects stale/replayed commands.
    pub executor_boot_binding_verified: bool,
    pub blocker_code: Option<String>,
    pub blocker_detail: Option<String>,
}

impl SandboxGatewayIdentityReport {
    /// Hard gate: ALL FOUR identity guarantees (`I01`–`I04`) must be verified
    /// before the `seatbelt` backend can be enabled as ready in production.
    pub fn can_enable_production_backend(&self) -> bool {
        self.helper_identity_verified
            && self.tcp_socket_attribution_verified
            && (self.gateway_server_identity_verified || self.gateway_endpoint_protection_verified)
            && self.executor_boot_binding_verified
            && self.blocker_code.is_none()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortTakeoverProbeOutcome {
    pub control_client_forwarded: bool,
    pub sandboxed_client_reconnected: bool,
    pub rogue_gateway_received_headers_or_data: bool,
    pub rogue_captured_bytes_len: usize,
    pub echo_server_received_target_payload: bool,
    pub server_identity_gate_passed: bool,
    pub failure_reason: Option<String>,
}

/// Bound by the Rust inventory resolver, never by the launch helper's payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovedCliSource {
    pub entry_path: String,
    pub target: LaunchTarget,
    pub executable: String,
    pub fingerprint: String,
}
impl ApprovedCliSource {
    fn key(&self) -> String { format!("{:?}:{}", self.target, self.entry_path) }
    fn valid(&self, targets: &BTreeMap<String, String>) -> bool {
        matches!(self.target, LaunchTarget::ClaudeCli | LaunchTarget::CodexCli)
            && Path::new(&self.entry_path).is_absolute()
            && targets.get(&self.executable) == Some(&self.fingerprint)
            && std::fs::canonicalize(&self.entry_path).ok().as_deref() == Some(Path::new(&self.executable))
    }
}

#[derive(Clone)]
struct RetainedCliApproval {
    source_key: String,
    // Only children already verified at the retarget may use the retired image.
    children: BTreeMap<u32, (String, BoundProcessToken)>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ImageStatus { Verified, Pending, Invalid }

#[derive(Clone)]
struct ScriptInstanceApproval {
    combo: ApprovedScriptCombo,
    cdhash: [u8; 20],
    package: VerificationKey,
}

fn combo_key(combo: &ApprovedScriptCombo) -> (String, String) {
    (combo.script_path.clone(), combo.interpreter_path.clone())
}

fn combo_aliases_match(combo: &ApprovedScriptCombo) -> bool {
    std::fs::canonicalize(&combo.entry_path).ok().as_deref() == Some(Path::new(&combo.script_path))
        && std::fs::canonicalize(&combo.interpreter_entry_path).ok().as_deref() == Some(Path::new(&combo.interpreter_path))
}

struct RegistryInner {
    executor_boot_id: String,
    policy_version: PolicyVersion,
    verifier: SandboxPeerVerifier,
    approved_targets: BTreeMap<String, String>,
    approved_child_executables: BTreeMap<String, String>,
    cli_sources: BTreeMap<String, ApprovedCliSource>,
    instance_sources: BTreeMap<String, String>,
    retained_cli_instances: BTreeMap<String, RetainedCliApproval>,
    approval_revision: u64,
    image_approvals: BTreeMap<String, (String, u64)>,
    image_verifications: BTreeMap<VerificationKey, ImageStatus>,
    verification_in_flight: BTreeSet<VerificationKey>,
    content_reads: u64,
    invalidated_families: BTreeSet<String>,
    // Retain only a live kernel exec lifetime for visibility after file evidence
    // fails. These tokens are never consulted by attribution or approvals.
    visibility_tokens: BTreeMap<(String, u32), BoundProcessToken>,
    instances: BTreeMap<String, ManagedLaunchInstance>,
    pid_to_instance: BTreeMap<u32, String>,
    child_identities: BTreeMap<u32, (String, BoundProcessToken)>,
    approved_script_combos: BTreeMap<(String, String), ApprovedScriptCombo>,
    script_instances: BTreeMap<String, ScriptInstanceApproval>,
    used_nonces: BTreeMap<String, f64>,
    endpoint_protection: Option<claude_watch_system::launchd_gateway::GatewayEndpointProtection>,
}

/// Manages helper registration (`I01`), post-exec target identity promotion,
/// and live TCP socket attribution (`I02`) for `nono`/Seatbelt-launched processes.
pub struct SandboxLaunchRegistry {
    inner: Arc<Mutex<RegistryInner>>,
    storage: Option<StateStore>,
}

impl SandboxLaunchRegistry {
    pub fn new(
        executor_boot_id: impl Into<String>,
        policy_version: PolicyVersion,
        verifier: SandboxPeerVerifier,
        storage: Option<StateStore>,
    ) -> Self {
        Self {
            inner: Arc::new(Mutex::new(RegistryInner {
                executor_boot_id: executor_boot_id.into(),
                policy_version,
                verifier,
                approved_targets: BTreeMap::new(),
                approved_child_executables: BTreeMap::new(),
                cli_sources: BTreeMap::new(),
                instance_sources: BTreeMap::new(),
                retained_cli_instances: BTreeMap::new(),
                approval_revision: 0,
                image_approvals: BTreeMap::new(),
                image_verifications: BTreeMap::new(),
                verification_in_flight: BTreeSet::new(),
                content_reads: 0,
                invalidated_families: BTreeSet::new(),
                visibility_tokens: BTreeMap::new(),
                instances: BTreeMap::new(),
                pid_to_instance: BTreeMap::new(),
                child_identities: BTreeMap::new(),
                approved_script_combos: BTreeMap::new(),
                script_instances: BTreeMap::new(),
                used_nonces: BTreeMap::new(),
                endpoint_protection: None,
            })),
            storage,
        }
    }

    pub fn approve_target_executable(
        &self,
        executable_path: impl Into<String>,
        sha256_hex: impl Into<String>,
    ) {
        if let Ok(mut guard) = self.inner.lock() {
            guard
                .approved_targets
                .insert(executable_path.into(), sha256_hex.into());
            Self::rebuild_image_approvals(&mut guard);
        }
        self.refresh_executable_verifications();
    }

    pub fn is_target_approved(&self, executable_path: &str) -> bool {
        self.inner
            .lock()
            .map(|g| g.approved_targets.contains_key(executable_path))
            .unwrap_or(false)
    }

    pub fn approve_child_executable(
        &self,
        executable_path: impl Into<String>,
        sha256_hex: impl Into<String>,
    ) {
        if let Ok(mut guard) = self.inner.lock() {
            guard
                .approved_child_executables
                .insert(executable_path.into(), sha256_hex.into());
            Self::rebuild_image_approvals(&mut guard);
        }
        self.refresh_executable_verifications();
    }

    pub fn script_launch_approval_view(&self) -> (String, Vec<ApprovedScriptCombo>) {
        self.inner
            .lock()
            .map(|g| (g.executor_boot_id.clone(), g.approved_script_combos.values().cloned().collect()))
            .unwrap_or_default()
    }

    /// Atomically replaces the approved target executables and child executables maps.
    /// This ensures that uninstalled or moved target binaries are cleanly revoked
    /// rather than persisting indefinitely in an append-only set.
    pub fn replace_approved_targets(
        &self,
        targets: BTreeMap<String, String>,
        children: BTreeMap<String, String>,
    ) -> Vec<String> {
        // Explicit replacement keeps the original strict removal contract.
        self.replace_approved_targets_with_cli_sources(targets, children, Vec::new())
    }

    pub fn replace_approved_targets_with_cli_sources(
        &self,
        targets: BTreeMap<String, String>,
        children: BTreeMap<String, String>,
        sources: Vec<ApprovedCliSource>,
    ) -> Vec<String> {
        self.replace_discovery_approvals(targets, children, sources, Vec::new())
    }

    pub fn replace_discovery_approvals(
        &self, targets: BTreeMap<String, String>, children: BTreeMap<String, String>,
        sources: Vec<ApprovedCliSource>, combos: Vec<ApprovedScriptCombo>,
    ) -> Vec<String> {
        let current_combos: BTreeMap<_, _> = combos.into_iter().filter(|combo|
            targets.get(&combo.script_path) == Some(&combo.script_fingerprint)
                && !targets.contains_key(&combo.interpreter_path)
                && !children.contains_key(&combo.interpreter_path)
                && combo_aliases_match(combo)
        ).map(|combo| (combo_key(&combo), combo)).collect();
        let mut current_sources = BTreeMap::new();
        let mut conflicts = BTreeSet::new();
        for source in sources {
            let key = source.key();
            if !source.valid(&targets) { conflicts.insert(key); continue; }
            if current_sources.get(&key).is_some_and(|old| old != &source) {
                conflicts.insert(key.clone());
            }
            current_sources.insert(key, source);
        }
        current_sources.retain(|key, _| !conflicts.contains(key));
        {
            let Ok(guard) = self.inner.lock() else { return Vec::new(); };
            if guard.approved_targets == targets && guard.approved_child_executables == children
                && guard.cli_sources == current_sources && guard.approved_script_combos == current_combos { return Vec::new(); }
        }
        // A normal, content-verified B is required before retaining any A.
        // Inventory refresh is the only production caller; the rare transition
        // read runs outside authority locks and is checked again at commit.
        let mut source_proofs = BTreeMap::new();
        for source in current_sources.values() {
            source_proofs.entry(source.executable.clone()).or_insert_with(|| {
                let key = VerificationKey::new(&source.executable, &source.fingerprint, 0);
                let valid = key.as_ref().and_then(VerificationKey::verify) == Some(true);
                (key, valid)
            });
        }
        let Ok(mut guard) = self.inner.lock() else { return Vec::new(); };
        guard.content_reads += source_proofs.len() as u64;
        current_sources.retain(|_, source| source.valid(&targets) && source_proofs.get(&source.executable).is_some_and(|(key, valid)|
            *valid && key.is_some() && *key == VerificationKey::new(&source.executable, &source.fingerprint, 0)));
        if guard.approved_targets == targets && guard.approved_child_executables == children
            && guard.cli_sources == current_sources && guard.approved_script_combos == current_combos { return Vec::new(); }
        let old_targets = std::mem::replace(&mut guard.approved_targets, targets);
        let old_children = std::mem::replace(&mut guard.approved_child_executables, children);
        let old_sources = std::mem::replace(&mut guard.cli_sources, current_sources);
        guard.approved_script_combos = current_combos;
        let ids: Vec<_> = guard.instances.keys().cloned().collect();
        for id in ids {
            let inst = guard.instances[&id].clone();
            if matches!(inst.state, ManagedInstanceState::Failed | ManagedInstanceState::Exited) { continue; }
            let script_current = inst.script_entry.is_some() && Self::script_approval_current(&mut guard, &inst);
            if inst.script_entry.is_some() && !script_current {
                Self::invalidate_instance(&mut guard, &id, "script_approval_changed");
                continue;
            }
            let current_approval = script_current
                || guard.approved_targets.get(&inst.expected_executable) == Some(&inst.expected_fingerprint);
            if !current_approval {
                let existing = guard.retained_cli_instances.get(&id).cloned();
                let source_key = existing.as_ref().map(|r| &r.source_key).or_else(|| guard.instance_sources.get(&id)).cloned();
                let proved_retarget = source_key.as_ref().is_some_and(|key| {
                    let Some(new) = guard.cli_sources.get(key) else { return false; };
                    if new.target != inst.target || new.executable == inst.expected_executable { return false; }
                    existing.is_some() || old_sources.get(key).is_some_and(|old|
                        old.executable == inst.expected_executable && old.fingerprint == inst.expected_fingerprint)
                });
                let still_verified = proved_retarget
                    && inst.has_verified_main_protection(&guard.executor_boot_id, &guard.policy_version)
                    && Self::main_identity_matches(&inst)
                    && Self::image_status(&mut guard, &inst.expected_executable, &inst.expected_fingerprint) == ImageStatus::Verified;
                if !still_verified {
                    Self::invalidate_instance(&mut guard, &id, "target_approval_changed");
                    continue;
                }
                if existing.is_none() {
                    let children = inst.controlled_subtree_pids.iter().filter_map(|pid|
                        guard.child_identities.get(pid).cloned().map(|value| (*pid, value))).collect();
                    guard.retained_cli_instances.insert(id.clone(), RetainedCliApproval { source_key: source_key.unwrap(), children });
                }
            } else { guard.retained_cli_instances.remove(&id); }
            let retained = guard.retained_cli_instances.get(&id).cloned();
            for pid in inst.controlled_subtree_pids {
                let valid = guard.child_identities.get(&pid).is_some_and(|(exe, token)| {
                    let old_sha = old_children.get(exe).or_else(|| old_targets.get(exe));
                    let new_sha = guard.approved_child_executables.get(exe).or_else(|| guard.approved_targets.get(exe));
                    (script_current && exe == &inst.expected_executable)
                        || (old_sha.is_some() && old_sha == new_sha)
                        || retained.as_ref().is_some_and(|r| r.children.get(&pid) == Some(&(exe.clone(), token.clone()))
                            && exe == &inst.expected_executable)
                });
                if !valid {
                    guard.instances.get_mut(&id).unwrap().controlled_subtree_pids.retain(|p| *p != pid);
                    guard.pid_to_instance.remove(&pid);
                    guard.child_identities.remove(&pid);
                    guard.invalidated_families.insert(inst.family.clone());
                }
            }
        }
        Self::rebuild_image_approvals(&mut guard);
        let invalidated = std::mem::take(&mut guard.invalidated_families).into_iter().collect();
        drop(guard);
        self.persist_instances();
        invalidated
    }

    pub fn update_policy_version(&self, policy_version: PolicyVersion) {
        if let Ok(mut guard) = self.inner.lock() {
            if guard.policy_version == policy_version { return; }
            let retired: Vec<_> = guard.retained_cli_instances.keys().cloned().collect();
            for id in retired { Self::invalidate_instance(&mut guard, &id, "retained_policy_changed"); }
            guard.policy_version = policy_version;
            guard.image_approvals.clear();
            Self::rebuild_image_approvals(&mut guard);
        }
    }
    /// Compatibility callers without the Supervisor sender leave work for the
    /// same existing inventory worker. This never emits a network command.
    pub(crate) fn queue_inventory_invalidations(&self, families: Vec<String>) {
        if let Ok(mut guard)=self.inner.lock() { guard.invalidated_families.extend(families); }
    }

    fn main_identity_matches(inst: &ManagedLaunchInstance) -> bool {
        inspect_process_identity(inst.pid).is_some_and(|p| {
            inst.exec_identity.as_ref().is_some_and(|token|
                p.pid == token.pid && p.uid == token.uid && p.start_seconds == token.start_seconds
                    && p.start_microseconds == token.start_microseconds && token.audit_token == Some(p.audit_token))
                && p.executable_path == inst.expected_executable
        })
    }

    fn invalidate_instance(guard: &mut RegistryInner, id: &str, reason: &str) {
        if let Some(inst) = guard.instances.get_mut(id) {
            if let Some(token) = inst.exec_identity.as_ref().filter(|token| token.has_verified_audit_token()) {
                guard.visibility_tokens.insert((id.into(), token.pid), token.clone());
            }
            for pid in &inst.controlled_subtree_pids {
                if let Some((_, token)) = guard.child_identities.get(pid).filter(|(_, token)| token.has_verified_audit_token()) {
                    guard.visibility_tokens.insert((id.into(), *pid), token.clone());
                }
            }
            inst.state = ManagedInstanceState::Failed;
            inst.error_code = Some(reason.into());
            inst.exec_identity = None;
            guard.invalidated_families.insert(inst.family.clone());
            guard.pid_to_instance.remove(&inst.pid);
            for pid in std::mem::take(&mut inst.controlled_subtree_pids) {
                guard.pid_to_instance.remove(&pid);
                guard.child_identities.remove(&pid);
            }
        }
        guard.retained_cli_instances.remove(id);
        guard.script_instances.remove(id);
        guard.instance_sources.remove(id);
    }

    fn script_approval_current(guard: &mut RegistryInner, inst: &ManagedLaunchInstance) -> bool {
        if inst.script_entry.is_none() { return true; }
        let Some(binding) = guard.script_instances.get(&inst.instance_id).cloned() else { return false; };
        let c = &binding.combo;
        guard.approved_script_combos.get(&combo_key(c)) == Some(c)
            && combo_aliases_match(c)
            && Self::image_status(guard, &c.script_path, &c.script_fingerprint) == ImageStatus::Verified
            && Self::image_status(guard, &c.interpreter_path, &c.interpreter_fingerprint) == ImageStatus::Verified
            && binding.package.matches_current()
    }

    fn initial_script_exec_matches(guard: &RegistryInner, inst: &ManagedLaunchInstance,
        live: &claude_watch_system::ProcessKernelIdentity) -> bool {
        inst.script_entry.is_none() || guard.script_instances.get(&inst.instance_id).is_some_and(|binding|
            claude_watch_system::bound_process_cdhash(live) == Some(binding.cdhash)
                && inst.helper_identity.as_ref().is_some_and(|tok| tok.audit_token != Some(live.audit_token)))
    }

    fn rebuild_image_approvals(guard: &mut RegistryInner) {
        let mut desired = guard.approved_child_executables.clone();
        desired.extend(guard.approved_targets.clone());
        for id in guard.retained_cli_instances.keys() {
            if let Some(inst) = guard.instances.get(id) {
                if inst.state == ManagedInstanceState::ExecVerified {
                    desired.insert(inst.expected_executable.clone(), inst.expected_fingerprint.clone());
                }
            }
        }
        for inst in guard.instances.values() {
            if !matches!(inst.state, ManagedInstanceState::Failed | ManagedInstanceState::Exited) {
                if let Some(binding) = guard.script_instances.get(&inst.instance_id) {
                    desired.insert(binding.combo.interpreter_path.clone(), binding.combo.interpreter_fingerprint.clone());
                }
            }
        }
        let mut approvals = BTreeMap::new();
        for (path, sha) in desired {
            let revision = if let Some((old_sha, revision)) = guard.image_approvals.get(&path).filter(|(old, _)| old == &sha) {
                let _ = old_sha;
                *revision
            } else {
                guard.approval_revision = guard.approval_revision.saturating_add(1);
                guard.approval_revision
            };
            approvals.insert(path, (sha, revision));
        }
        guard.image_approvals = approvals;
        guard.image_verifications.retain(|key, _| guard.image_approvals.get(&key.path) == Some(&(key.expected_sha.clone(), key.approval_revision)));
        guard.verification_in_flight.retain(|key| guard.image_verifications.contains_key(key));
    }

    fn image_status(guard: &mut RegistryInner, path: &str, expected_sha: &str) -> ImageStatus {
        let Some((sha, revision)) = guard.image_approvals.get(path) else { return ImageStatus::Invalid; };
        if sha != expected_sha { return ImageStatus::Invalid; }
        let Some(key) = VerificationKey::new(path, sha, *revision) else { return ImageStatus::Invalid; };
        // At most one current key per approved/live image; mutations cannot accumulate history.
        guard.image_verifications.retain(|old, _| old.path != path || old == &key);
        *guard.image_verifications.entry(key).or_insert(ImageStatus::Pending)
    }

    /// Called by the existing target-refresh worker. All file content IO is outside
    /// the authority lock; a superseded revision or changed file cannot commit.
    pub fn refresh_executable_verifications(&self) -> Vec<String> {
        self.refresh_executable_verifications_with(VerificationKey::verify)
    }

    fn refresh_executable_verifications_with(&self, verify: impl Fn(&VerificationKey) -> Option<bool>) -> Vec<String> {
        let work = {
            let Ok(mut guard) = self.inner.lock() else { return Vec::new(); };
            Self::rebuild_image_approvals(&mut guard);
            for (path, (sha, _)) in guard.image_approvals.clone() { let _ = Self::image_status(&mut guard, &path, &sha); }
            let work: Vec<_> = guard.image_verifications.iter().filter(|(key, state)|
                **state == ImageStatus::Pending && !guard.verification_in_flight.contains(*key)).map(|(key, _)| key.clone()).collect();
            guard.verification_in_flight.extend(work.iter().cloned());
            work
        };
        for key in work {
            let result = verify(&key);
            let Ok(mut guard) = self.inner.lock() else { continue; };
            Self::commit_image_verification(&mut guard, key, result);
        }
        // Cheap identity/metadata reconciliation detects missing files too, and
        // hands revocation to Supervisor rather than closing sockets in this registry.
        self.reconcile_process_trees(crate::native::now());
        self.take_invalidated_families()
    }

    fn commit_image_verification(guard: &mut RegistryInner, key: VerificationKey, result: Option<bool>) -> bool {
        guard.content_reads += 1;
        guard.verification_in_flight.remove(&key);
        if guard.image_approvals.get(&key.path) != Some(&(key.expected_sha.clone(), key.approval_revision))
            || VerificationKey::new(&key.path, &key.expected_sha, key.approval_revision).as_ref() != Some(&key) { return false; }
        if let Some(valid) = result { guard.image_verifications.insert(key, if valid { ImageStatus::Verified } else { ImageStatus::Invalid }); }
        true
    }

    pub fn take_invalidated_families(&self) -> Vec<String> {
        self.inner.lock().map(|mut g| std::mem::take(&mut g.invalidated_families).into_iter().collect()).unwrap_or_default()
    }

    #[doc(hidden)]
    pub fn executable_verification_counts(&self) -> (u64, usize, usize) {
        self.inner.lock().map(|g| (g.content_reads, g.image_approvals.len(), g.image_verifications.len())).unwrap_or_default()
    }

    /// Only the OS boundary can construct this proof, after authenticating the
    /// root broker and validating the actual transferred listening descriptor.
    pub fn set_gateway_endpoint_protection(&self, protection: Option<claude_watch_system::launchd_gateway::GatewayEndpointProtection>) {
        if let Ok(mut guard) = self.inner.lock() {
            guard.endpoint_protection = protection;
        }
    }

    pub fn identity_report(
        &self,
        helper_verified: bool,
        tcp_attributed: bool,
        boot_bound: bool,
    ) -> SandboxGatewayIdentityReport {
        let protection = self
            .inner
            .lock()
            .ok().and_then(|g| g.endpoint_protection.clone());
        let (blocker_code, blocker_detail) = if protection.is_none() {
            (
                Some("gateway_server_identity_unverified_i03".into()),
                Some(
                    "尚未取得系统 launchd 托管端点的可信监听句柄；普通 HTTP 代理不提供服务端认证，I03 门禁保持阻断（不得回退自行绑定端口）".into(),
                ),
            )
        } else {
            (None, None)
        };
        SandboxGatewayIdentityReport {
            helper_identity_verified: helper_verified,
            tcp_socket_attribution_verified: tcp_attributed,
            gateway_server_identity_verified: false,
            gateway_endpoint_protection_verified: protection.is_some(),
            gateway_endpoint_protection_method: protection.as_ref().map(|_| "system_launchd_socket".into()),
            protected_gateway_endpoint: protection.as_ref().map(|p| p.endpoint().to_string()),
            executor_boot_binding_verified: boot_bound,
            blocker_code,
            blocker_detail,
        }
    }

    pub fn instances(&self) -> Vec<ManagedLaunchInstance> {
        self.inner
            .lock()
            .map(|g| g.instances.values().cloned().collect())
            .unwrap_or_default()
    }

    /// Handles a single helper registration over a connected Unix domain stream.
    /// Verifies `LOCAL_PEERTOKEN` and helper executable hash against `SandboxPeerVerifier` (`I01`).
    pub fn handle_helper_registration_stream(
        &self,
        mut stream: UnixStream,
        now: f64,
    ) -> Result<SandboxHelperWireResponse> {
        let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
        let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));

        let verifier = self
            .inner
            .lock()
            .map_err(|_| CoreError::new("registry_lock_poisoned", "沙箱注册表锁异常"))?
            .verifier
            .clone();

        // 1. Kernel peer identity + code hash check (`I01`)
        let Some(peer_id) = verify_sandbox_helper_peer(&stream, &verifier) else {
            let resp = SandboxHelperWireResponse {
                accepted: false,
                instance_id: None,
                executor_boot_id: self.executor_boot_id(),
                error_code: Some("untrusted_sandbox_helper_peer".into()),
                message: "Helper 进程未通过内核身份、实时签名或加载防护核验".into(),
            };
            let _ = Self::write_wire_response(&mut stream, &resp);
            return Ok(resp);
        };

        let mut raw = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            match stream.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    raw.extend_from_slice(&buf[..n]);
                    if raw.contains(&b'\n') || raw.len() > 65536 {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        let wire_req: SandboxHelperWireRequest = match serde_json::from_slice(&raw) {
            Ok(r) => r,
            Err(_) => {
                let resp = SandboxHelperWireResponse {
                    accepted: false,
                    instance_id: None,
                    executor_boot_id: self.executor_boot_id(),
                    error_code: Some("invalid_helper_wire_request".into()),
                    message: "Helper 注册请求 JSON 格式无效".into(),
                };
                let _ = Self::write_wire_response(&mut stream, &resp);
                return Ok(resp);
            }
        };

        if verify_sandbox_helper_peer(&stream, &verifier).as_ref() != Some(&peer_id) {
            let resp = SandboxHelperWireResponse {
                accepted: false, instance_id: None, executor_boot_id: self.executor_boot_id(),
                error_code: Some("untrusted_sandbox_helper_peer".into()),
                message: "读取登记请求期间 Helper 的实时身份无法核验".into(),
            };
            let _ = Self::write_wire_response(&mut stream, &resp);
            return Ok(resp);
        }
        let resp = self.process_verified_registration(peer_id, wire_req, now);
        let _ = Self::write_wire_response(&mut stream, &resp);
        Ok(resp)
    }

    fn write_wire_response(stream: &mut UnixStream, resp: &SandboxHelperWireResponse) -> Result<()> {
        if let Ok(mut bytes) = serde_json::to_vec(resp) {
            bytes.push(b'\n');
            let _ = stream.write_all(&bytes);
            let _ = stream.flush();
        }
        let _ = stream.shutdown(Shutdown::Both);
        Ok(())
    }

    fn executor_boot_id(&self) -> String {
        self.inner
            .lock()
            .map(|g| g.executor_boot_id.clone())
            .unwrap_or_default()
    }

    fn process_verified_registration(
        &self,
        peer: claude_watch_system::SandboxPeerIdentity,
        wire: SandboxHelperWireRequest,
        now: f64,
    ) -> SandboxHelperWireResponse {
        let guard = match self.inner.lock() {
            Ok(g) => g,
            Err(_) => {
                return SandboxHelperWireResponse {
                    accepted: false,
                    instance_id: None,
                    executor_boot_id: String::new(),
                    error_code: Some("registry_lock_poisoned".into()),
                    message: "沙箱注册表锁异常".into(),
                };
            }
        };

        // Reject if self-reported PID or helper hash contradicts kernel truth (`I01`)
        if let Some(claimed_pid) = wire.claimed_pid {
            if claimed_pid != peer.process.pid {
                return SandboxHelperWireResponse {
                    accepted: false,
                    instance_id: None,
                    executor_boot_id: guard.executor_boot_id.clone(),
                    error_code: Some("helper_claimed_pid_mismatch".into()),
                    message: "请求自报 PID 与内核 LOCAL_PEERTOKEN 身份不符，已拒绝".into(),
                };
            }
        }
        if let Some(ref claimed_sha) = wire.claimed_helper_sha256 {
            if claimed_sha != &peer.helper_sha256 {
                return SandboxHelperWireResponse {
                    accepted: false,
                    instance_id: None,
                    executor_boot_id: guard.executor_boot_id.clone(),
                    error_code: Some("helper_claimed_hash_mismatch".into()),
                    message: "请求自报哈希与可信清单实际哈希不符，已拒绝".into(),
                };
            }
        }

        if let Err(err) = wire.request.validate() {
            return SandboxHelperWireResponse {
                accepted: false,
                instance_id: None,
                executor_boot_id: guard.executor_boot_id.clone(),
                error_code: Some(err.code),
                message: err.message,
            };
        }

        if guard.endpoint_protection.as_ref().is_some_and(|proof|
            wire.request.gateway_endpoint.parse::<SocketAddr>().ok() != Some(proof.endpoint())) {
            return SandboxHelperWireResponse {
                accepted: false, instance_id: None,
                executor_boot_id: guard.executor_boot_id.clone(),
                error_code: Some("launch_gateway_endpoint_mismatch".into()),
                message: "启动请求没有绑定当前系统托管网关".into(),
            };
        }

        // Verify executor boot_id (`I04`) and policy_version
        if wire.request.executor_boot_id != guard.executor_boot_id {
            return SandboxHelperWireResponse {
                accepted: false,
                instance_id: None,
                executor_boot_id: guard.executor_boot_id.clone(),
                error_code: Some("executor_boot_id_mismatch".into()),
                message: "启动请求绑定的执行器 boot_id 已过期或不匹配".into(),
            };
        }
        if wire.request.policy_version != guard.policy_version {
            return SandboxHelperWireResponse {
                accepted: false,
                instance_id: None,
                executor_boot_id: guard.executor_boot_id.clone(),
                error_code: Some("launch_policy_version_mismatch".into()),
                message: "启动请求的策略版本与当前保存策略不一致".into(),
            };
        }
        if guard.used_nonces.contains_key(&wire.request.launch_nonce) {
            return SandboxHelperWireResponse {
                accepted: false,
                instance_id: None,
                executor_boot_id: guard.executor_boot_id.clone(),
                error_code: Some("launch_nonce_replayed".into()),
                message: "启动请求 nonce 已被使用，拒绝重放".into(),
            };
        }

        // Verify target executable is approved and matches disk SHA-256 fingerprint
        let canon_target = match std::fs::canonicalize(&wire.request.target_executable) {
            Ok(p) => p.to_string_lossy().into_owned(),
            Err(_) => {
                return SandboxHelperWireResponse {
                    accepted: false,
                    instance_id: None,
                    executor_boot_id: guard.executor_boot_id.clone(),
                    error_code: Some("target_executable_missing".into()),
                    message: "目标可执行文件不存在或无法解析".into(),
                };
            }
        };
        let Some(expected_target_sha) = guard.approved_targets.get(&canon_target).cloned() else {
            return SandboxHelperWireResponse {
                accepted: false,
                instance_id: None,
                executor_boot_id: guard.executor_boot_id.clone(),
                error_code: Some("unapproved_target_executable".into()),
                message: "目标程序不在受控 AI 白名单内，拒绝冒充启动".into(),
            };
        };
        let binding = if let (Some(script), Some(interpreter)) = (&wire.request.script_entry, &wire.request.interpreter) {
            let combo = guard.approved_script_combos.get(&(script.clone(), interpreter.clone()))
                .filter(|c| c.matches_request(&wire.request) && c.script_path == canon_target && combo_aliases_match(c)).cloned();
            let Some(combo) = combo else {
                return SandboxHelperWireResponse { accepted: false, instance_id: None, executor_boot_id: guard.executor_boot_id.clone(),
                    error_code: Some("unapproved_script_combination".into()), message: "脚本、解释器或来源修订不匹配".into() };
            };
            Some(combo)
        } else {
            if guard.approved_script_combos.values().any(|c| c.script_path == canon_target) {
                return SandboxHelperWireResponse { accepted: false, instance_id: None, executor_boot_id: guard.executor_boot_id.clone(),
                    error_code: Some("script_launch_contract_required".into()), message: "脚本不能按原生程序注册".into() };
            }
            None
        };
        let revision = guard.image_approvals.get(&canon_target).map(|(_, revision)| *revision).unwrap_or(0);
        let key = VerificationKey::new(&canon_target, &expected_target_sha, revision);
        drop(guard);
        // Registration always performs a real first-use content read, outside
        // the authority lock, even if an inventory proof is already cached.
        let verified = key.as_ref().and_then(VerificationKey::verify) == Some(true);
        let script_checks = binding.as_ref().and_then(|c| {
            let interpreter = VerificationKey::new(&c.interpreter_path, &c.interpreter_fingerprint, 0)?;
            let package = VerificationKey::new_regular(&c.package_path, &c.package_fingerprint)?;
            let cdhash = claude_watch_system::executable_cdhash(Path::new(&c.interpreter_path))?;
            (interpreter.verify() == Some(true) && package.verify() == Some(true)).then_some((interpreter, package, cdhash))
        });

        let mut guard = match self.inner.lock() {
            Ok(guard) => guard,
            Err(_) => return SandboxHelperWireResponse { accepted: false, instance_id: None, executor_boot_id: String::new(),
                error_code: Some("registry_lock_poisoned".into()), message: "沙箱注册表锁异常".into() },
        };
        guard.content_reads += if binding.is_some() { 3 } else { 1 };
        if binding.as_ref().is_some_and(|c| {
            guard.approved_script_combos.get(&combo_key(c)) != Some(c) || !combo_aliases_match(c)
                || script_checks.as_ref().is_none_or(|(interpreter, package, _)|
                    VerificationKey::new(&c.interpreter_path, &c.interpreter_fingerprint, 0).as_ref() != Some(interpreter)
                    || !package.matches_current())
        }) {
            return SandboxHelperWireResponse { accepted: false, instance_id: None, executor_boot_id: guard.executor_boot_id.clone(),
                error_code: Some("script_source_changed_during_verification".into()), message: "启动前脚本、解释器或来源文件变化".into() };
        }
        let current_key = VerificationKey::new(&canon_target, &expected_target_sha, revision);
        if guard.executor_boot_id != wire.request.executor_boot_id || guard.policy_version != wire.request.policy_version
            || guard.used_nonces.contains_key(&wire.request.launch_nonce)
            || guard.approved_targets.get(&canon_target) != Some(&expected_target_sha)
            || guard.image_approvals.get(&canon_target) != Some(&(expected_target_sha.clone(), revision))
            || key.is_none() || key != current_key {
            return SandboxHelperWireResponse { accepted: false, instance_id: None, executor_boot_id: guard.executor_boot_id.clone(),
                error_code: Some("target_approval_changed_during_verification".into()), message: "内容核验期间目标批准或身份已变化".into() };
        }
        guard.image_verifications.insert(key.unwrap(), if verified { ImageStatus::Verified } else { ImageStatus::Invalid });
        let actual_target_sha = if verified { expected_target_sha.clone() } else { String::new() };
        if actual_target_sha != expected_target_sha
            || wire.request.target_fingerprint != expected_target_sha
        {
            return SandboxHelperWireResponse {
                accepted: false,
                instance_id: None,
                executor_boot_id: guard.executor_boot_id.clone(),
                error_code: Some("target_fingerprint_mismatch".into()),
                message: "目标程序磁盘指纹与已批准清单不符".into(),
            };
        }

        if !wire.sandbox_applied {
            return SandboxHelperWireResponse {
                accepted: false,
                instance_id: None,
                executor_boot_id: guard.executor_boot_id.clone(),
                error_code: Some("sandbox_not_applied".into()),
                message: "Helper 尚未完成 nono Seatbelt 沙箱应用，拒绝登记受控实例".into(),
            };
        }

        guard
            .used_nonces
            .insert(wire.request.launch_nonce.clone(), now);

        let helper_token = BoundProcessToken::with_system_identity(
            peer.process.pid,
            peer.process.uid,
            peer.process.start_seconds,
            peer.process.start_microseconds,
            ProcessRole::Child,
        )
        .with_audit_token(peer.process.audit_token);

        let evidence = SandboxLaunchEvidence {
            applied: true,
            backend: NetworkBackendKind::Seatbelt,
            policy_version: wire.request.policy_version.clone(),
            allowed_gateway_endpoint: wire.request.gateway_endpoint.clone(),
            direct_network_blocked: true,
            unix_relay_blocked: true,
            verified_helper_origin: true,
            helper_cdhash: peer.helper_cdhash,
            helper_identity: helper_token.clone(),
            executor_boot_id: guard.executor_boot_id.clone(),
            applied_at: now,
        };

        let instance_id = format!("sandbox-inst-{}", Uuid::new_v4());
        let family = if matches!(
            wire.request.target,
            claude_watch_core::processes::LaunchTarget::CodexDesktop
                | claude_watch_core::processes::LaunchTarget::CodexCli
                | claude_watch_core::processes::LaunchTarget::ChatgptDesktop
        ) {
            "openai".to_string()
        } else {
            "claude".to_string()
        };

        let (expected_exe, expected_sha, script_entry, script_fingerprint) = if let Some(c) = &binding {
            (c.interpreter_path.clone(), c.interpreter_fingerprint.clone(), Some(c.script_path.clone()), Some(c.script_fingerprint.clone()))
        } else {
            (canon_target, expected_target_sha, None, None)
        };

        let instance = ManagedLaunchInstance {
            instance_id: instance_id.clone(),
            entry_id: wire.request.entry_id.clone(),
            family,
            target: wire.request.target,
            launch_nonce: wire.request.launch_nonce,
            executor_boot_id: guard.executor_boot_id.clone(),
            helper_identity: Some(helper_token),
            expected_executable: expected_exe,
            expected_fingerprint: expected_sha,
            exec_identity: None,
            verified_executable: None,
            pid: peer.process.pid,
            uid: peer.process.uid,
            start_seconds: peer.process.start_seconds,
            start_microseconds: peer.process.start_microseconds,
            controlled_subtree_pids: Vec::new(),
            state: ManagedInstanceState::SandboxApplied,
            sandbox_evidence: Some(evidence),
            updated_at: now,
            error_code: None,
            script_entry,
            script_fingerprint,
        };

        let sources: Vec<_> = guard.cli_sources.iter().filter(|(_, source)|
            source.target == instance.target && (
                (source.executable == instance.expected_executable && source.fingerprint == instance.expected_fingerprint)
                || (instance.script_entry.as_ref().is_some_and(|s| &source.executable == s)
                    && instance.script_fingerprint.as_ref().is_some_and(|f| &source.fingerprint == f))
            )
        ).map(|(key, _)| key.clone()).collect();
        if sources.len() == 1 { guard.instance_sources.insert(instance_id.clone(), sources[0].clone()); }
        guard.pid_to_instance.insert(peer.process.pid, instance_id.clone());
        guard.instances.insert(instance_id.clone(), instance);
        if let (Some(combo), Some((mut interpreter, package, cdhash))) = (binding, script_checks) {
            guard.script_instances.insert(instance_id.clone(), ScriptInstanceApproval { combo, cdhash, package });
            Self::rebuild_image_approvals(&mut guard);
            if let Some((_, revision)) = guard.image_approvals.get(&interpreter.path) {
                interpreter.approval_revision = *revision;
                guard.image_verifications.insert(interpreter, ImageStatus::Verified);
            }
        }
        drop(guard);
        self.persist_instances();

        SandboxHelperWireResponse {
            accepted: true,
            instance_id: Some(instance_id),
            executor_boot_id: self.executor_boot_id(),
            error_code: None,
            message: "已核验 Helper 内核身份并记录 pending-exec 沙箱实例".into(),
        }
    }

    fn is_process_definitely_dead(pid: u32) -> bool {
        claude_watch_system::is_process_definitely_dead(pid)
    }

    fn verify_approved_child_executable_fingerprint(
        guard: &mut RegistryInner,
        canon_child: &str,
        child_token: &BoundProcessToken,
        inst: &ManagedLaunchInstance,
        child: &claude_watch_system::ProcessKernelIdentity,
    ) -> bool {
        if inst.script_entry.is_some() {
            return canon_child == inst.expected_executable && Self::script_approval_current(guard, inst)
                && Self::verified_script_fork(guard, inst, child, child_token);
        }
        let current_sha = guard.approved_targets.get(canon_child)
            .or_else(|| guard.approved_child_executables.get(canon_child)).cloned();
        let sha = current_sha.or_else(|| {
            if canon_child == inst.expected_executable {
                Some(inst.expected_fingerprint.clone())
            } else {
                guard.retained_cli_instances.get(&inst.instance_id).and_then(|retained| {
                    (retained.children.get(&child_token.pid) == Some(&(canon_child.into(), child_token.clone())))
                        .then(|| inst.expected_fingerprint.clone())
                })
            }
        });
        sha.is_some_and(|sha| Self::image_status(guard, canon_child, &sha) == ImageStatus::Verified)
    }

    fn verified_script_fork(guard: &RegistryInner, inst: &ManagedLaunchInstance,
        child: &claude_watch_system::ProcessKernelIdentity, token: &BoundProcessToken) -> bool {
        if !claude_watch_system::bound_fork_only(child) || child.uid != inst.uid { return false; }
        if let Some((exe, previous)) = guard.child_identities.get(&child.pid) {
            return exe == &inst.expected_executable && previous == token
                && guard.pid_to_instance.get(&child.pid) == Some(&inst.instance_id);
        }
        let Some(current) = guard.instances.get(&inst.instance_id) else { return false; };
        let mut cursor = child.clone();
        for _ in 0..32 {
            let Some(parent) = inspect_process_identity(cursor.ppid).filter(|parent| {
                parent.uid == inst.uid && parent.executable_path == inst.expected_executable
                    && (parent.start_seconds, parent.start_microseconds) <= (cursor.start_seconds, cursor.start_microseconds)
            }) else { return false; };
            let matches = |token: &BoundProcessToken| token.matches_process(parent.pid, parent.uid,
                parent.start_seconds, parent.start_microseconds, Some(&parent.audit_token));
            if parent.pid == inst.pid {
                return current.has_verified_main_protection(&guard.executor_boot_id, &guard.policy_version)
                    && current.exec_identity.as_ref().is_some_and(matches);
            }
            if !claude_watch_system::bound_fork_only(&parent) { return false; }
            if guard.pid_to_instance.get(&parent.pid) == Some(&inst.instance_id)
                && guard.child_identities.get(&parent.pid).is_some_and(|(_, token)| matches(token))
            { return true; }
            cursor = parent;
        }
        false
    }

    /// Reconciles all managed launch instances and their inherited child process trees (`D03`/`I02`):
    /// - Distinguishes confirmed process exit (`ESRCH`) from transient inspection failure.
    /// - Preserves still-alive verified descendants if the parent exits or reparents them to PID 1.
    /// - Discovers live descendant processes (`fork`/`exec` children), verifies their executable
    ///   path AND SHA-256 fingerprint against `expected_executable` or approved child executables,
    ///   invalidates stale identity on `exec`, updates `controlled_subtree_pids`, and cleans up
    ///   exited or unapproved children.
    pub fn reconcile_process_trees(&self, now: f64) -> Vec<ManagedLaunchInstance> {
        let Ok(mut guard) = self.inner.lock() else {
            return Vec::new();
        };
        let expected_uid = guard.verifier.expected_uid;
        let inst_ids: Vec<String> = guard.instances.keys().cloned().collect();

        for inst_id in inst_ids {
            let Some(inst) = guard.instances.get(&inst_id).cloned() else {
                continue;
            };
            if matches!(
                inst.state,
                ManagedInstanceState::Exited | ManagedInstanceState::Failed
            ) {
                guard.pid_to_instance.remove(&inst.pid);
                for &child_pid in &inst.controlled_subtree_pids {
                    guard.pid_to_instance.remove(&child_pid);
                    guard.child_identities.remove(&child_pid);
                }
                continue;
            }

            if !Self::script_approval_current(&mut guard, &inst) {
                Self::invalidate_instance(&mut guard, &inst_id, "script_source_evidence_changed");
                continue;
            }
            if inst.state == ManagedInstanceState::ExecVerified
                && Self::image_status(&mut guard, &inst.expected_executable, &inst.expected_fingerprint) != ImageStatus::Verified {
                Self::invalidate_instance(&mut guard, &inst_id, "executable_evidence_changed");
                continue;
            }

            let main_kernel_opt = inspect_process_identity(inst.pid);
            let mut main_alive_and_matching = false;
            let mut main_transient_failure = false;

            if let Some(ref main_kernel) = main_kernel_opt {
                if main_kernel.uid == inst.uid
                    && main_kernel.start_seconds == inst.start_seconds
                    && main_kernel.start_microseconds == inst.start_microseconds
                {
                    main_alive_and_matching = true;
                }
            } else if !Self::is_process_definitely_dead(inst.pid) {
                main_transient_failure = true;
            }

            if main_transient_failure {
                // Do not wipe the instance or its verified subtree on a transient kernel read failure.
                continue;
            }

            if main_alive_and_matching {
                let main_kernel = main_kernel_opt.unwrap();
                let canon_main = std::fs::canonicalize(&main_kernel.executable_path)
                    .ok()
                    .map(|p| p.to_string_lossy().into_owned())
                    .unwrap_or_else(|| main_kernel.executable_path.clone());
                let main_sha_ok = Self::image_status(&mut guard, &canon_main, &inst.expected_fingerprint) == ImageStatus::Verified;
                if canon_main == inst.expected_executable && main_sha_ok {
                    let role = match inst.target {
                        claude_watch_core::processes::LaunchTarget::ClaudeDesktop
                        | claude_watch_core::processes::LaunchTarget::CodexDesktop
                        | claude_watch_core::processes::LaunchTarget::ChatgptDesktop => {
                            ProcessRole::DesktopMain
                        }
                        claude_watch_core::processes::LaunchTarget::ClaudeCli
                        | claude_watch_core::processes::LaunchTarget::CodexCli => ProcessRole::Cli,
                    };
                    let tok = BoundProcessToken::with_system_identity(
                        main_kernel.pid,
                        main_kernel.uid,
                        main_kernel.start_seconds,
                        main_kernel.start_microseconds,
                        role,
                    )
                    .with_audit_token(main_kernel.audit_token);
                    if inst.state == ManagedInstanceState::SandboxApplied && !Self::initial_script_exec_matches(&guard, &inst, &main_kernel) {
                        Self::invalidate_instance(&mut guard, &inst_id, "script_interpreter_loaded_identity_mismatch");
                        continue;
                    }
                    if let Some(m) = guard.instances.get_mut(&inst_id) {
                        if m.state == ManagedInstanceState::SandboxApplied {
                            m.exec_identity = Some(tok);
                            m.verified_executable = Some(canon_main);
                            m.state = ManagedInstanceState::ExecVerified;
                            m.updated_at = now;
                        } else if m.state == ManagedInstanceState::ExecVerified
                            && m.exec_identity.as_ref() != Some(&tok)
                        {
                            Self::invalidate_instance(&mut guard, &inst_id, "exec_audit_token_changed");
                            continue;
                        }
                    }
                } else if inst.state == ManagedInstanceState::ExecVerified {
                    Self::invalidate_instance(&mut guard, &inst_id, "unexpected_exec_image_change");
                    continue;
                }
            } else {
                // Main PID has exited or was reused; remove main PID mapping immediately
                guard.pid_to_instance.remove(&inst.pid);
                if let Some(m) = guard.instances.get_mut(&inst_id) {
                    m.exec_identity = None;
                }
            }

            // Reconcile inherited descendant children in the sandboxed subtree.
            // Seed with main_pid (if still alive) PLUS any previously verified child_pid whose
            // birth time still matches its recorded BoundProcessToken (handling reparenting to PID 1).
            let mut seed_roots = Vec::new();
            if main_alive_and_matching {
                seed_roots.push(inst.pid);
            }
            for &prev_child_pid in &inst.controlled_subtree_pids {
                if let Some((_, ref prev_tok)) = guard.child_identities.get(&prev_child_pid) {
                    if let Some(ck) = inspect_process_identity(prev_child_pid) {
                        if ck.uid == prev_tok.uid
                            && ck.start_seconds == prev_tok.start_seconds
                            && ck.start_microseconds == prev_tok.start_microseconds
                        {
                            seed_roots.push(prev_child_pid);
                        }
                    }
                }
            }
            let mut candidate_children = list_descendant_pids(&seed_roots, expected_uid);
            for &root_child in &seed_roots {
                if root_child != inst.pid && !candidate_children.contains(&root_child) {
                    candidate_children.push(root_child);
                }
            }
            candidate_children.sort_unstable();
            candidate_children.dedup();

            let mut valid_children = Vec::new();
            for child_pid in candidate_children {
                let Some(child_kernel) = inspect_process_identity(child_pid) else {
                    if Self::is_process_definitely_dead(child_pid) {
                        guard.pid_to_instance.remove(&child_pid);
                        guard.child_identities.remove(&child_pid);
                    } else if inst.controlled_subtree_pids.contains(&child_pid) {
                        valid_children.push(child_pid);
                    }
                    continue;
                };
                if child_kernel.uid != inst.uid {
                    guard.pid_to_instance.remove(&child_pid);
                    guard.child_identities.remove(&child_pid);
                    continue;
                }
                if let Some((_, ref prev_tok)) = guard.child_identities.get(&child_pid) {
                    if child_kernel.start_seconds != prev_tok.start_seconds
                        || child_kernel.start_microseconds != prev_tok.start_microseconds
                    {
                        // If PID was reused and is NOT a live descendant of main_pid, reject it
                        if !main_alive_and_matching {
                            guard.pid_to_instance.remove(&child_pid);
                            guard.child_identities.remove(&child_pid);
                            continue;
                        }
                    }
                }
                let canon_child = std::fs::canonicalize(&child_kernel.executable_path)
                    .ok()
                    .map(|p| p.to_string_lossy().into_owned())
                    .unwrap_or_else(|| child_kernel.executable_path.clone());
                let child_tok = BoundProcessToken::with_system_identity(
                    child_kernel.pid,
                    child_kernel.uid,
                    child_kernel.start_seconds,
                    child_kernel.start_microseconds,
                    ProcessRole::Child,
                )
                .with_audit_token(child_kernel.audit_token);
                let is_allowed_child = Self::verify_approved_child_executable_fingerprint(
                    &mut guard, &canon_child, &child_tok, &inst, &child_kernel,
                );
                if !is_allowed_child {
                    if guard.child_identities.contains_key(&child_pid) { guard.invalidated_families.insert(inst.family.clone()); }
                    guard.pid_to_instance.remove(&child_pid);
                    guard.child_identities.remove(&child_pid);
                    continue;
                }
                guard.pid_to_instance.insert(child_pid, inst_id.clone());
                guard
                    .child_identities
                    .insert(child_pid, (canon_child, child_tok));
                valid_children.push(child_pid);
            }

            let old_children = if let Some(m) = guard.instances.get_mut(&inst_id) {
                if m.state == ManagedInstanceState::ExecVerified { m.updated_at = now; }
                if !main_alive_and_matching && valid_children.is_empty() {
                    m.state = ManagedInstanceState::Exited;
                    m.updated_at = now;
                }
                std::mem::replace(&mut m.controlled_subtree_pids, valid_children.clone())
            } else {
                Vec::new()
            };
            for old_child in old_children {
                if !valid_children.contains(&old_child) {
                    guard.pid_to_instance.remove(&old_child);
                    guard.child_identities.remove(&old_child);
                }
            }
        }
        let live_ids: BTreeSet<_> = guard.instances.values().filter(|inst|
            !matches!(inst.state, ManagedInstanceState::Exited | ManagedInstanceState::Failed)).map(|inst| inst.instance_id.clone()).collect();
        guard.retained_cli_instances.retain(|id, _| live_ids.contains(id));
        guard.instance_sources.retain(|id, _| live_ids.contains(id));
        guard.visibility_tokens.retain(|_, token| token.audit_token.as_ref().is_some_and(|audit|
            claude_watch_system::process_audit_token_matches(token.pid, token.uid, token.start_seconds, token.start_microseconds, audit)));
        Self::rebuild_image_approvals(&mut guard);
        let out: Vec<ManagedLaunchInstance> = guard.instances.values().cloned().collect();
        drop(guard);
        self.persist_instances();
        out
    }

    /// Returns all currently verified `BoundProcessToken`s (main + verified inherited children)
    /// for `family` so `ChannelSupervisor` can authorize them in `ChannelEnforcementCommand`.
    pub fn verified_family_tokens(&self, family: &str, now: f64) -> Vec<BoundProcessToken> {
        let _ = self.reconcile_process_trees(now);
        let Ok(guard) = self.inner.lock() else {
            return Vec::new();
        };
        let mut tokens = Vec::new();
        for inst in guard.instances.values() {
            if inst.family != family {
                continue;
            }
            if guard.endpoint_protection.as_ref().is_some_and(|proof|
                inst.sandbox_evidence.as_ref().and_then(|ev| ev.allowed_gateway_endpoint.parse::<SocketAddr>().ok()) != Some(proof.endpoint())) {
                continue;
            }
            if inst.has_verified_main_protection(&guard.executor_boot_id, &guard.policy_version) {
                if let Some(ref main_tok) = inst.exec_identity {
                    tokens.push(main_tok.clone());
                }
            }
            if inst.has_verified_subtree_protection(&guard.executor_boot_id, &guard.policy_version) {
                for &child_pid in &inst.controlled_subtree_pids {
                    if let Some((_, child_tok)) = guard.child_identities.get(&child_pid) {
                        tokens.push(child_tok.clone());
                    }
                }
            }
        }
        tokens
    }

    /// Check the already issued member without rediscovering another subtree.
    /// The process worker separately revalidates the live kernel token at signal.
    pub(crate) fn disposition_instance_id(&self, family: &str, token: &BoundProcessToken) -> Option<String> {
        let guard = self.inner.lock().ok()?;
        let id = guard.pid_to_instance.get(&token.pid)?;
        let inst = guard.instances.get(id)?;
        if inst.family != family || inst.state != ManagedInstanceState::ExecVerified { return None; }
        let matches = if inst.pid == token.pid { inst.exec_identity.as_ref() == Some(token) } else {
            inst.controlled_subtree_pids.contains(&token.pid)
                && guard.child_identities.get(&token.pid).is_some_and(|(_, current)| current == token)
        };
        matches.then(|| id.clone())
    }

    pub(crate) fn current_disposition_member(
        &self, intent: &claude_watch_core::channel::ProcessDispositionIntent,
        token: &BoundProcessToken, process: &claude_watch_system::ProcessKernelIdentity, now: f64,
    ) -> bool {
        let Ok(mut guard) = self.inner.lock() else { return false; };
        if guard.executor_boot_id != intent.executor_boot_id || guard.policy_version != intent.policy_version {
            return false;
        }
        let Some(inst) = guard.pid_to_instance.get(&token.pid).and_then(|id| guard.instances.get(id)).cloned()
        else { return false; };
        if inst.family != intent.family || intent.target_instances.get(&token.pid) != Some(&inst.instance_id)
            || !(0.0..10.0).contains(&(now - inst.updated_at))
            || !Self::script_approval_current(&mut guard, &inst)
            || Self::image_status(&mut guard, &inst.expected_executable, &inst.expected_fingerprint) != ImageStatus::Verified
        { return false; }
        if inst.pid == token.pid {
            return inst.has_verified_main_protection(&guard.executor_boot_id, &guard.policy_version)
                && inst.exec_identity.as_ref() == Some(token) && inst.expected_executable == process.executable_path;
        }
        inst.has_verified_subtree_protection(&guard.executor_boot_id, &guard.policy_version)
            && inst.controlled_subtree_pids.contains(&token.pid)
            && guard.child_identities.get(&token.pid).is_some_and(|(exe, stored)| stored == token && exe == &process.executable_path)
            && Self::verify_approved_child_executable_fingerprint(&mut guard, &process.executable_path, token, &inst, process)
    }

    /// Live TCP socket attribution (`I02`) using `AcceptedConnectionContext`.
    ///
    /// - Reconciles the managed process tree (including inherited `fork`/`exec` children).
    /// - Queries kernel `PROC_PIDLISTFDS` + `PROC_PIDFDSOCKETINFO` for the exact
    ///   loopback 4-tuple `(peer_addr, local_addr)` and requires a unique PID match.
    /// - Re-verifies the owning process's birth time, executable path, and post-exec
    ///   kernel `audit_token_t`.
    /// - Never trusts helper pre-exec audit tokens for post-exec target traffic:
    ///   the process must have `exec`ed into `expected_executable` (or be a verified
    ///   child in its process tree with an approved executable).
    pub fn attribute_accepted_connection(
        &self,
        ctx: &AcceptedConnectionContext,
        now: f64,
    ) -> Option<(String, BoundProcessToken)> {
        let (boot_id, policy_version, candidate_pids) = {
            let guard = self.inner.lock().ok()?;
            if !ctx.is_valid_for_listener(&guard.executor_boot_id) {
                return None;
            }
            if guard.pid_to_instance.len() > claude_watch_system::MAX_TCP_PEER_CANDIDATES {
                return None;
            }
            let pids: Vec<u32> = guard.pid_to_instance.keys().copied().collect();
            (
                guard.executor_boot_id.clone(),
                guard.policy_version.clone(),
                pids,
            )
        };
        if candidate_pids.is_empty() {
            return None;
        }

        // Kernel socket tuple lookup across registered candidate PIDs (requires unique match)
        let kernel_id =
            attribute_loopback_tcp_peer(ctx.peer_addr, ctx.local_addr, &candidate_pids)?;

        // Re-verify process identity after socket lookup so a concurrent exit/exec cannot race
        let post_check = inspect_process_identity(kernel_id.pid)?;
        if post_check != kernel_id {
            return None;
        }

        let mut guard = self.inner.lock().ok()?;
        if guard.executor_boot_id != boot_id || guard.policy_version != policy_version { return None; }
        let inst_id = guard.pid_to_instance.get(&kernel_id.pid)?.clone();
        let prev_child = guard.child_identities.get(&kernel_id.pid).cloned();
        let original = guard.instances.get(&inst_id)?.clone();
        if !Self::script_approval_current(&mut guard, &original) {
            Self::invalidate_instance(&mut guard, &inst_id, "script_source_evidence_changed");
            return None;
        }
        if Self::image_status(&mut guard, &original.expected_executable, &original.expected_fingerprint) != ImageStatus::Verified {
            if original.state == ManagedInstanceState::ExecVerified { Self::invalidate_instance(&mut guard, &inst_id, "executable_evidence_changed"); }
            return None;
        }
        let mut inst = original;

        let canon_exec = std::fs::canonicalize(&kernel_id.executable_path)
            .ok()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|| kernel_id.executable_path.clone());

        if inst.pid == kernel_id.pid {
            // Main process attribution
            if inst.uid != kernel_id.uid
                || inst.start_seconds != kernel_id.start_seconds
                || inst.start_microseconds != kernel_id.start_microseconds
            {
                Self::invalidate_instance(&mut guard, &inst_id, "instance_birth_time_mismatch");
                return None;
            }

            if canon_exec != inst.expected_executable {
                // If the process unexpectedly exec'd into an unapproved image, revoke/fail it!
                if inst.state == ManagedInstanceState::ExecVerified {
                    Self::invalidate_instance(&mut guard, &inst_id, "unexpected_exec_image_change");
                }
                return None;
            }

            let role = match inst.target {
                claude_watch_core::processes::LaunchTarget::ClaudeDesktop
                | claude_watch_core::processes::LaunchTarget::CodexDesktop
                | claude_watch_core::processes::LaunchTarget::ChatgptDesktop => {
                    ProcessRole::DesktopMain
                }
                claude_watch_core::processes::LaunchTarget::ClaudeCli
                | claude_watch_core::processes::LaunchTarget::CodexCli => ProcessRole::Cli,
            };
            let verified_token = BoundProcessToken::with_system_identity(
                kernel_id.pid,
                kernel_id.uid,
                kernel_id.start_seconds,
                kernel_id.start_microseconds,
                role,
            )
            .with_audit_token(kernel_id.audit_token);

            if inst.state == ManagedInstanceState::SandboxApplied {
                if !Self::initial_script_exec_matches(&guard, &inst, &kernel_id) {
                    Self::invalidate_instance(&mut guard, &inst_id, "script_interpreter_loaded_identity_mismatch");
                    return None;
                }
                inst.exec_identity = Some(verified_token.clone());
                inst.verified_executable = Some(canon_exec);
                inst.state = ManagedInstanceState::ExecVerified;
                inst.updated_at = now;
            } else if inst.state == ManagedInstanceState::ExecVerified {
                if inst.exec_identity.as_ref() != Some(&verified_token) {
                    Self::invalidate_instance(&mut guard, &inst_id, "exec_audit_token_changed");
                    return None;
                }
            } else {
                return None;
            }

            if !inst.has_verified_protection(&boot_id, &policy_version) {
                return None;
            }

            let family = inst.family.clone();
            guard.instances.insert(inst_id.clone(), inst);
            drop(guard);
            self.persist_instances();
            Some((family, verified_token))
        } else {
            // Inherited child process attribution (`ProcessRole::Child`)
            if !inst.has_verified_subtree_protection(&boot_id, &policy_version)
                || !inst.controlled_subtree_pids.contains(&kernel_id.pid)
                || kernel_id.uid != inst.uid
            {
                return None;
            }
            let instance = inst.clone();
            let child_token = BoundProcessToken::with_system_identity(
                kernel_id.pid, kernel_id.uid, kernel_id.start_seconds,
                kernel_id.start_microseconds, ProcessRole::Child,
            ).with_audit_token(kernel_id.audit_token);
            if !Self::verify_approved_child_executable_fingerprint(&mut guard, &canon_exec, &child_token, &instance, &kernel_id) {
                guard.invalidated_families.insert(instance.family.clone());
                guard.pid_to_instance.remove(&kernel_id.pid);
                guard.child_identities.remove(&kernel_id.pid);
                if let Some(live) = guard.instances.get_mut(&inst_id) { live.controlled_subtree_pids.retain(|pid| *pid != kernel_id.pid); }
                return None;
            }
            if let Some((prev_exec, prev_tok)) = prev_child {
                if prev_exec != canon_exec || prev_tok != child_token {
                    return None;
                }
            }
            let family = instance.family.clone();
            guard
                .child_identities
                .insert(kernel_id.pid, (canon_exec, child_token.clone()));
            drop(guard);
            self.persist_instances();
            Some((family, child_token))
        }
    }

    /// Starts a local Unix domain listener for `watch-sandbox-launcher` helper registration.
    pub fn start_registration_listener(
        self: &Arc<Self>,
        socket_path: &Path,
        stop: Arc<AtomicBool>,
    ) -> Result<thread::JoinHandle<()>> {
        if let Some(parent) = socket_path.parent() {
            let _ = std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(parent);
        }
        let _ = std::fs::remove_file(socket_path);
        let listener = UnixListener::bind(socket_path).map_err(|_| {
            CoreError::new("sandbox_registration_bind_failed", "沙箱注册 Unix 套接字绑定失败")
        })?;
        let _ = std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o600));
        let _ = listener.set_nonblocking(true);
        let reg = Arc::clone(self);
        let path_owned = socket_path.to_path_buf();
        thread::Builder::new()
            .name("sandbox-helper-registration".into())
            .spawn(move || {
                while !stop.load(Ordering::Acquire) {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            let _ = stream.set_nonblocking(false);
                            let _ = reg.handle_helper_registration_stream(
                                stream,
                                crate::native::now(),
                            );
                        }
                        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(20));
                        }
                        Err(_) => {
                            thread::sleep(Duration::from_millis(20));
                        }
                    }
                }
                drop(listener);
                let _ = std::fs::remove_file(path_owned);
            })
            .map_err(|_| {
                CoreError::new(
                    "sandbox_registration_thread_failed",
                    "沙箱注册监听线程启动失败",
                )
            })
    }

    fn persist_instances(&self) {
        let Some(ref store) = self.storage else {
            return;
        };
        if let Ok(mut guard) = self.inner.lock() {
            let mut current = Vec::new();
            for (id, instance) in &guard.instances {
                if let Some(token) = instance.exec_identity.as_ref().filter(|token| token.has_verified_audit_token()) {
                    current.push(((id.clone(), token.pid), token.clone()));
                }
                for pid in &instance.controlled_subtree_pids {
                    if guard.pid_to_instance.get(pid) != Some(id) { continue; }
                    if let Some((_, token)) = guard.child_identities.get(pid).filter(|(_, token)| token.has_verified_audit_token()) {
                        current.push(((id.clone(), *pid), token.clone()));
                    }
                }
            }
            guard.visibility_tokens.extend(current);
            // Projection rechecks the digest against the current kernel lifetime.
            // Do not rescan every process from this per-connection persistence path.
            let observed_at = crate::native::now();
            let list: Vec<_> = guard.instances.iter().map(|(id, instance)| {
                let mut row = json!(instance);
                let members: Vec<_> = guard.visibility_tokens.range((id.clone(), 0)..=(id.clone(), u32::MAX)).map(|((_, pid), token)| {
                    let bytes = token.audit_token.unwrap().iter().map(u32::to_string).collect::<Vec<_>>().join(":");
                    let verified_executable = (instance.state == ManagedInstanceState::ExecVerified).then(|| {
                        if instance.exec_identity.as_ref() == Some(token) {
                            instance.verified_executable.as_deref()
                        } else if instance.controlled_subtree_pids.contains(pid) && guard.pid_to_instance.get(pid) == Some(id) {
                            guard.child_identities.get(pid).filter(|(_, current)| current == token).map(|(exe, _)| exe.as_str())
                        } else {
                            None
                        }
                    }).flatten();
                    json!({"pid":token.pid,"uid":token.uid,"start_seconds":token.start_seconds,"start_microseconds":token.start_microseconds,
                        "audit_identity_digest":sha256_bytes_hex(bytes.as_bytes()),"currently_verified":verified_executable.is_some(),
                        "verified_executable":verified_executable})
                }).collect();
                if !members.is_empty() { row["process_visibility"] = json!({"observed_at":observed_at,"members":members}); }
                row
            }).collect();
            let _ = store.atomic_json(
                &store.paths.watch().join("state/managed-launch-instances.json"),
                &json!(list),
            );
        }
    }
}

/// Helper-side registration client over an already-connected Unix stream.
/// Used by `watch-sandbox-launcher` so the Unix socket connection is established before
/// `(deny network*)` blocks new `AF_UNIX` connects, while the registration payload
/// (`sandbox_applied: true`) is sent only AFTER `apply_macos_seatbelt_profile` succeeds.
pub fn register_helper_over_connected_stream(
    mut stream: UnixStream,
    request: ControlledLaunchRequest,
    sandbox_applied: bool,
    profile_sbpl: &str,
) -> Result<SandboxHelperWireResponse> {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
    let wire_req = SandboxHelperWireRequest {
        request,
        claimed_pid: Some(std::process::id()),
        claimed_helper_sha256: None,
        sandbox_applied,
        profile_digest: sha256_bytes_hex(profile_sbpl.as_bytes()),
    };
    let mut payload = serde_json::to_vec(&wire_req)
        .map_err(|_| CoreError::new("invalid_wire_request", "序列化沙箱注册请求失败"))?;
    payload.push(b'\n');
    stream
        .write_all(&payload)
        .map_err(|_| CoreError::new("sandbox_registration_write_failed", "发送沙箱注册请求失败"))?;
    let _ = stream.flush();
    let _ = stream.shutdown(Shutdown::Write);

    let mut resp_bytes = Vec::new();
    stream
        .read_to_end(&mut resp_bytes)
        .map_err(|_| CoreError::new("sandbox_registration_read_failed", "读取沙箱注册响应失败"))?;
    serde_json::from_slice(&resp_bytes)
        .map_err(|_| CoreError::new("invalid_wire_response", "解析沙箱注册响应失败"))
}

/// Helper-side registration client used by `watch-sandbox-launcher` or tests.
pub fn register_helper_with_daemon(
    registration_socket: &Path,
    request: ControlledLaunchRequest,
    sandbox_applied: bool,
    profile_sbpl: &str,
) -> Result<SandboxHelperWireResponse> {
    let stream = UnixStream::connect(registration_socket).map_err(|_| {
        CoreError::new(
            "sandbox_daemon_unreachable",
            "无法连接 Watch 沙箱注册控制套接字",
        )
    })?;
    register_helper_over_connected_stream(stream, request, sandbox_applied, profile_sbpl)
}

/// SHA-256 and CDHash must come from the same trusted manifest. A present
/// but incomplete primary manifest cannot borrow identity from a fallback.
fn lookup_trusted_helper_pins(dir: &Path) -> (Option<String>, Option<String>) {
    let name = "watch-sandbox-launcher";
    let build_info = dir.join("BuildInfo.plist");
    let pair = if std::fs::symlink_metadata(&build_info).is_ok() {
        let Some(value) = std::process::Command::new("/usr/bin/plutil")
            .args(["-convert", "json", "-o", "-"]).arg(&build_info).output().ok()
            .filter(|o| o.status.success())
            .and_then(|o| serde_json::from_slice::<serde_json::Value>(&o.stdout).ok())
        else { return (None, None); };
        (value["RuntimeHashes"][name].as_str().map(str::to_owned),
         value["RuntimeCDHashes"][name].as_str().map(str::to_owned))
    } else {
        let Some(value) = std::fs::read(dir.join("components.json")).ok()
            .and_then(|raw| serde_json::from_slice::<serde_json::Value>(&raw).ok())
        else { return (None, None); };
        let component = value["components"].get("sandbox_launcher")
            .or_else(|| value["components"].get(name));
        if let Some(component) = component.filter(|c| c.is_object()) {
            (component["sha256"].as_str().map(str::to_owned), component["cdhash"].as_str().map(str::to_owned))
        } else {
            let key = if value["hashes"].get(name).is_some() { name } else { "sandbox_launcher" };
            (component.and_then(serde_json::Value::as_str).or_else(|| value["hashes"][key].as_str()).map(str::to_owned),
             value["cdhashes"][key].as_str().map(str::to_owned))
        }
    };
    let normalized = |value: Option<String>, len| value.map(|v| v.trim().to_ascii_lowercase())
        .filter(|v| v.len() == len && v.bytes().all(|b| b.is_ascii_hexdigit()));
    (normalized(pair.0, 64), normalized(pair.1, 40))
}

/// Reads packaged backend metadata. Seatbelt is the only executable backend;
/// legacy values are returned solely so configuration resolution can report an
/// explicit migration/unsupported-package error instead of inventing support.
pub fn lookup_packaged_network_backend(manifest_dir: &Path) -> Option<NetworkBackendKind> {
    let build_info = manifest_dir.join("BuildInfo.plist");
    if build_info.is_file() {
        let output = std::process::Command::new("/usr/bin/plutil")
            .args(["-convert", "json", "-o", "-"])
            .arg(&build_info)
            .output()
            .ok()?;
        if output.status.success() {
            if let Ok(val) = serde_json::from_slice::<serde_json::Value>(&output.stdout) {
                if let Some(raw) = val.get("NetworkBackend").and_then(serde_json::Value::as_str) {
                    if let Some(kind) = NetworkBackendKind::parse_wire(raw) {
                        return Some(kind);
                    }
                }
            }
        }
    }
    let components_json = manifest_dir.join("components.json");
    if components_json.is_file() {
        if let Ok(bytes) = std::fs::read(&components_json) {
            if let Ok(val) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                if let Some(raw) = val
                    .get("network_backend")
                    .or_else(|| val.get("NetworkBackend"))
                    .and_then(serde_json::Value::as_str)
                {
                    return NetworkBackendKind::parse_wire(raw);
                }
            }
        }
    }
    None
}

/// Builds a production `SandboxPeerVerifier` anchored strictly to a trusted build manifest
/// (`BuildInfo.plist` or `components.json` in `manifest_dir`), never computing the expected
/// hash from the untrusted helper binary on disk (`I01`).
pub fn build_helper_verifier_from_manifest(
    manifest_dir: &Path,
    helper_path: &Path,
) -> Result<SandboxPeerVerifier> {
    let (sha, cdhash) = lookup_trusted_helper_pins(manifest_dir);
    let expected_sha = sha.ok_or_else(|| {
            CoreError::new(
                "helper_manifest_hash_missing",
                "可信构建清单 (BuildInfo.plist / components.json) 缺少 watch-sandbox-launcher 预期哈希",
            )
        })?;
    let canon = std::fs::canonicalize(helper_path).map_err(|_| {
        CoreError::new("helper_binary_missing", "watch-sandbox-launcher 二进制不存在")
    })?;
    let actual_sha = sha256_file_hex(&canon).ok_or_else(|| {
        CoreError::new("helper_hash_unavailable", "无法读取 watch-sandbox-launcher 二进制")
    })?;
    if actual_sha != expected_sha {
        return Err(CoreError::new(
            "helper_manifest_hash_mismatch",
            "watch-sandbox-launcher 实际文件哈希与可信构建清单不符",
        ));
    }
    let expected_helper_cdhash = cdhash.ok_or_else(|| CoreError::new(
        "helper_manifest_cdhash_missing", "可信构建清单缺少最终签名的沙箱 helper CDHash"))?;
    let actual_cdhash = component_cdhash(&canon)?;
    if actual_cdhash != expected_helper_cdhash {
        return Err(CoreError::new("helper_manifest_cdhash_mismatch", "沙箱 helper 最终签名与清单不符"));
    }
    Ok(SandboxPeerVerifier {
        expected_uid: effective_uid(),
        expected_helper_executable: canon.to_string_lossy().into_owned(),
        expected_helper_sha256: expected_sha,
        expected_helper_cdhash,
    })
}

/// Builds a `SandboxPeerVerifier` for the current user and given helper path, preferring
/// a sibling `BuildInfo.plist` / `components.json` manifest when present.
pub fn build_helper_verifier_for_path(helper_path: &Path) -> Result<SandboxPeerVerifier> {
    if let Some(parent) = helper_path.parent() {
        if parent.join("BuildInfo.plist").is_file() || parent.join("components.json").is_file() {
            return build_helper_verifier_from_manifest(parent, helper_path);
        }
    }
    let canon = std::fs::canonicalize(helper_path).map_err(|_| {
        CoreError::new("helper_binary_missing", "watch-sandbox-launcher 二进制不存在")
    })?;
    let sha = sha256_file_hex(&canon).ok_or_else(|| {
        CoreError::new("helper_hash_unavailable", "无法计算 watch-sandbox-launcher 哈希")
    })?;
    Ok(SandboxPeerVerifier {
        expected_uid: effective_uid(),
        expected_helper_executable: canon.to_string_lossy().into_owned(),
        expected_helper_sha256: sha,
        expected_helper_cdhash: component_cdhash(&canon)?,
    })
}

fn component_cdhash(path: &Path) -> Result<String> {
    claude_watch_system::executable_cdhash(path)
        .map(|hash| hash.iter().map(|b| format!("{b:02x}")).collect())
        .ok_or_else(|| CoreError::new("helper_signature_unavailable", "沙箱 helper 文件签名不可核验"))
}

pub fn default_registration_socket_path(watch_dir: &Path) -> PathBuf {
    watch_dir.join("state/sandbox-registration.sock")
}

#[cfg(test)]
mod approval_refresh_tests {
    use super::*;
    use claude_watch_core::processes::LaunchTarget;

    #[test]
    fn content_work_releases_authority_lock_and_superseded_results_cannot_commit() {
        use std::sync::mpsc;
        let file = std::env::temp_dir().join(format!("cw-image-{}", Uuid::new_v4()));
        std::fs::write(&file, b"image-v1").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o755)).unwrap();
        let path = std::fs::canonicalize(&file).unwrap().to_string_lossy().into_owned();
        let sha = sha256_file_hex(&file).unwrap();
        let reg = Arc::new(SandboxLaunchRegistry::new("boot", PolicyVersion { policy_digest:"p".into(), guard_policy_digest:"g".into() },
            SandboxPeerVerifier { expected_uid:effective_uid(), expected_helper_executable:"/fixture/helper".into(), expected_helper_sha256:"h".into(), expected_helper_cdhash:"0".repeat(40) }, None));
        reg.replace_approved_targets(BTreeMap::from([(path.clone(), sha.clone())]), BTreeMap::new());
        let (entered_tx, entered_rx) = mpsc::channel(); let (release_tx, release_rx) = mpsc::channel();
        let worker_registry = reg.clone();
        let worker = thread::spawn(move || worker_registry.refresh_executable_verifications_with(|key| {
            entered_tx.send(()).unwrap(); release_rx.recv_timeout(Duration::from_secs(3)).unwrap(); key.verify()
        }));
        entered_rx.recv_timeout(Duration::from_secs(3)).unwrap();
        // Causal check: authority update completes while the content worker is explicitly paused.
        reg.update_policy_version(PolicyVersion { policy_digest:"new".into(), guard_policy_digest:"g".into() });
        release_tx.send(()).unwrap(); worker.join().unwrap();
        let mut guard = reg.inner.lock().unwrap();
        assert!(SandboxLaunchRegistry::image_status(&mut guard, &path, &sha) != ImageStatus::Verified);
        assert!(guard.image_verifications.values().all(|status| *status != ImageStatus::Verified));
        drop(guard);
        reg.refresh_executable_verifications();
        let mut guard = reg.inner.lock().unwrap();
        assert!(SandboxLaunchRegistry::image_status(&mut guard, &path, &sha) == ImageStatus::Verified);
        let old_key = guard.image_verifications.keys().next().unwrap().clone();
        drop(guard);
        std::fs::write(&file, b"image-v2").unwrap();
        let mut guard = reg.inner.lock().unwrap();
        assert!(SandboxLaunchRegistry::image_status(&mut guard, &path, &sha) == ImageStatus::Pending);
        assert!(!SandboxLaunchRegistry::commit_image_verification(&mut guard, old_key, Some(true)));
        drop(guard); reg.refresh_executable_verifications();
        let mut guard = reg.inner.lock().unwrap();
        assert!(SandboxLaunchRegistry::image_status(&mut guard, &path, &sha) == ImageStatus::Invalid);
        assert!(guard.image_verifications.len() <= guard.image_approvals.len());
        drop(guard);
        std::fs::write(&file, b"image-v1").unwrap(); reg.refresh_executable_verifications();
        let old_key = reg.inner.lock().unwrap().image_verifications.keys().next().unwrap().clone();
        reg.replace_approved_targets(BTreeMap::new(), BTreeMap::new());
        reg.replace_approved_targets(BTreeMap::from([(path.clone(), sha.clone())]), BTreeMap::new());
        let mut guard = reg.inner.lock().unwrap();
        assert!(!SandboxLaunchRegistry::commit_image_verification(&mut guard, old_key, Some(true)));
        assert!(SandboxLaunchRegistry::image_status(&mut guard, &path, &sha) == ImageStatus::Pending);
        drop(guard);
        std::fs::remove_file(file).unwrap();
    }

    #[test]
    fn retained_identity_requires_live_birth_audit_and_current_executable() {
        let live = inspect_process_identity(std::process::id()).unwrap();
        let mut inst = instance("identity", "claude", live.pid, &live.executable_path, "fixture");
        inst.uid = live.uid; inst.start_seconds = live.start_seconds; inst.start_microseconds = live.start_microseconds;
        inst.exec_identity = Some(BoundProcessToken::with_system_identity(live.pid, live.uid, live.start_seconds, live.start_microseconds, ProcessRole::Cli).with_audit_token(live.audit_token));
        assert!(SandboxLaunchRegistry::main_identity_matches(&inst));
        let audit = live.audit_token.iter().map(u32::to_string).collect::<Vec<_>>().join(":");
        let digest = sha256_bytes_hex(audit.as_bytes());
        assert!(claude_watch_system::process_lifetime_audit_digest_matches(live.pid, live.uid, live.start_seconds, live.start_microseconds, &digest));
        assert!(!claude_watch_system::process_lifetime_audit_digest_matches(live.pid, live.uid, live.start_seconds+1, live.start_microseconds, &digest));
        assert!(!claude_watch_system::process_lifetime_audit_digest_matches(live.pid, live.uid, live.start_seconds, live.start_microseconds, &"0".repeat(64)));
        let original = inst.clone();
        inst.exec_identity.as_mut().unwrap().start_seconds += 1;
        assert!(!SandboxLaunchRegistry::main_identity_matches(&inst));
        inst = original.clone(); inst.exec_identity.as_mut().unwrap().audit_token.as_mut().unwrap()[7] ^= 1;
        assert!(!SandboxLaunchRegistry::main_identity_matches(&inst));
        inst = original; inst.expected_executable = "/fixture/changed-image".into();
        assert!(!SandboxLaunchRegistry::main_identity_matches(&inst));
    }

    fn instance(id: &str, family: &str, pid: u32, exe: &str, sha: &str) -> ManagedLaunchInstance {
        ManagedLaunchInstance {
            instance_id: id.into(), entry_id: id.into(), family: family.into(),
            target: LaunchTarget::ClaudeCli, launch_nonce: id.into(), executor_boot_id: "boot".into(),
            helper_identity: None, expected_executable: exe.into(), expected_fingerprint: sha.into(),
            exec_identity: Some(BoundProcessToken::with_system_identity(pid, 501, 10, 0, ProcessRole::Cli)),
            verified_executable: Some(exe.into()), pid, uid: 501, start_seconds: 10, start_microseconds: 0,
            controlled_subtree_pids: Vec::new(), state: ManagedInstanceState::ExecVerified,
            sandbox_evidence: None, updated_at: 1.0, error_code: None,
            script_entry: None, script_fingerprint: None,
        }
    }

    #[test]
    fn replacement_invalidates_removed_targets_and_changed_children_without_touching_other_families() {
        let reg = SandboxLaunchRegistry::new("boot", PolicyVersion { policy_digest: "p".into(), guard_policy_digest: "g".into() },
            SandboxPeerVerifier { expected_uid: 501, expected_helper_executable: "/fixture/helper".into(),
                expected_helper_sha256: "h".into(), expected_helper_cdhash: "0".repeat(40) }, None);
        let a = "/fixture/a".to_string(); let b = "/fixture/b".to_string(); let child = "/fixture/child".to_string();
        let targets = BTreeMap::from([(a.clone(), "a1".into()), (b.clone(), "b1".into())]);
        reg.replace_approved_targets(targets.clone(), BTreeMap::from([(child.clone(), "c1".into())]));
        {
            let mut g = reg.inner.lock().unwrap();
            let mut inst_a = instance("a", "claude", 1001, &a, "a1");
            inst_a.controlled_subtree_pids.push(1002);
            g.instances.insert("a".into(), inst_a);
            g.instances.insert("b".into(), instance("b", "openai", 2001, &b, "b1"));
            for (pid, id) in [(1001, "a"), (1002, "a"), (2001, "b")] { g.pid_to_instance.insert(pid, id.into()); }
            g.child_identities.insert(1002, (child.clone(), BoundProcessToken::with_system_identity(1002, 501, 11, 0, ProcessRole::Child)));
        }
        assert!(reg.replace_approved_targets(targets.clone(), BTreeMap::from([(child.clone(), "c1".into())])).is_empty());
        assert_eq!(reg.replace_approved_targets(targets, BTreeMap::from([(child, "c2".into())])), vec!["claude"]);
        {
            let g = reg.inner.lock().unwrap();
            assert!(g.instances["a"].controlled_subtree_pids.is_empty());
            assert!(!g.child_identities.contains_key(&1002));
            assert!(!g.pid_to_instance.contains_key(&1002));
            assert_eq!(g.instances["b"].state, ManagedInstanceState::ExecVerified);
        }
        assert_eq!(reg.replace_approved_targets(BTreeMap::from([(b, "b1".into())]), BTreeMap::new()), vec!["claude"]);
        let g = reg.inner.lock().unwrap();
        assert_eq!(g.instances["a"].state, ManagedInstanceState::Failed);
        assert_eq!(g.instances["a"].error_code.as_deref(), Some("target_approval_changed"));
        assert!(g.instances["a"].exec_identity.is_none());
        assert!(!g.pid_to_instance.contains_key(&1001));
        assert!(g.pid_to_instance.contains_key(&2001));
    }
}
