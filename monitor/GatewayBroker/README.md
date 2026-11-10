# System-owned gateway listener

The broker only transfers launchd-created listening descriptors to the approved
Rust engine. It does not change VPN, routing, PF, DNS, or system proxy settings.
It is not a NetworkExtension and does not require paid Developer ID signing.

The engine and broker must be signed with `codesign --options runtime,library`
(ad-hoc `--sign -` is sufficient locally), with no exception entitlements.
The gateway port must be in 1–1023 and distinct from the VPN proxy (for example
1021). launchd reserves both IPv4 and IPv6 wildcard listeners. IPv6 is a
non-forwarding reservation; the configured client proxy remains 127.0.0.1.
The broker verifies the descriptors' original kernel owner is root and that
cross-UID sharing and port reuse are disabled. IPv4 non-loopback clients are
rejected by the existing Rust gateway. These conditions close the initial
ordinary-user specific-address prebind window as well as worker-crash takeover.
Prepare the installation artifact **after final signing**, using the engine path
that will actually run:

```sh
watch-gateway-broker --prepare --output /absolute/new/artifact-directory \
  --engine /absolute/final/watch-engine --uid USER_UID --port GATEWAY_PORT
```

Preparation only writes the specified new directory. Review its config, plist,
and `install.sh`. Installation needs separate administrator authorization; never
run it as part of ordinary builds/tests. The installer refuses existing service
files. Do not unload or replace the service while protected AI processes live:
administrator removal is outside the normal-process anti-substitution boundary.

The root configuration pins both executable digests and live code identities;
an engine update/re-sign therefore needs an explicit trusted-config update.
The owner record prevents another live engine taking the same listener, survives
broker restarts, and treats inaccessible old owners as still active.

Component tests of FD transfer are not system-launchd activation acceptance.
During worker downtime, local TCP handshakes may queue in launchd's listener;
the guarantee is no unauthorised external forwarding, not immediate TCP refusal.

## Unified reinstall transaction

`monitor/reinstall.sh` now previews the fixed system gateway before any reset.
It distinguishes a first installation from an existing gateway belonging to the
same user and final engine path. Unknown files, another user's installation or a
loaded job with a different definition stop the flow. The confirmation names
administrator installation/update; no VPN settings are written. Local ad-hoc
signing with `runtime,library` is still the signing requirement; a paid Developer
ID is not required by this backend.

The former gateway keeps its reserved port during packaging. Once the new
runtime is at its final path, installation pins its SHA-256/CDHash and the broker
identity, stages a root-owned rollback record, updates only the fixed Watch
service, and starts socket activation. The final user `runtime/watch-engine`
then runs `gateway-endpoint-check`: it must receive the real root-created IPv4
and IPv6 descriptors through authenticated IPC. File existence or successful
`bootstrap` is insufficient. Only after that check may the user daemon start.
The first installation uses reserved port 1023; updates keep the existing port.
A conflict fails the install and restores the preceding known gateway.

Failure before runtime commit rolls back both installations. After runtime
commit, failure to clean the root transaction is reported as
`gateway_cleanup_pending`; the new runtime/app are retained and no app-only
rollback is attempted. Interrupted transactions are kept for explicit recovery.
Administrator commands hold one root-owned kernel lock; a timeout in the caller
does not permit recovery to race an administrator child that is still running.

The broker supports `--service-preview --uid USER_UID --engine FINAL_ENGINE`
(read-only), and administrator-only `--service-rollback` / `--service-commit`
with the same scope and `--transaction TRANSACTION_ID`. For an already absent
rollback record, `--previous-config` must match the preview's canonical identity
(or `absent`) before a no-op recovery can be acknowledged. Explicit removal is
`--service-remove --uid USER_UID --engine FINAL_ENGINE`; it refuses unknown
content and incomplete transactions. These are recovery capabilities, not an
automatic instruction to execute administrator changes.

Code/isolated transaction tests do not prove actual launchd activation, root to
user descriptor transfer or real AI protection. Those remain installation and
real-host acceptance steps requiring separate authorization.

## Bounded production diagnostics

The administrator install prepares `/Library/Logs/ClaudeWatchGateway` as a
root-owned 0755 directory. The broker writes 0644 JSON-lines files
`events.jsonl`, `events.jsonl.1`, and `events.jsonl.2`, each limited to 1 MiB.
The stable `.write.lock` is private and is not exported. Unknown files, writable
paths, symlinks or hardlinked log files cause logging to refuse that destination;
they are never overwritten. Log failure emits a fixed warning and does not
change an installation result or authorize/deny a connection.

Records contain only schema, timestamp, component/version, PID, operation,
result, stable reason, validated transaction ID and optional numeric OS error.
Raw requests, credentials, full command arguments, destinations and peer
identity records are excluded. Listener events use a bounded nonblocking queue
of 64 records so slow disk I/O cannot delay handoff decisions. Queue overflow
may lose diagnostics and emits `gateway_logging_unavailable`; diagnostics are
not enforcement receipts. Management/startup/failure records use bounded
synchronous writes, and an unavailable logger never replaces the actual error.

The launchd plist shape is unchanged, so existing known installations remain
recognizable during upgrades. Logs live outside the installation transaction
and survive service replacement, rollback and explicit removal. No logs are
created by `--prepare` or unprivileged `--service-preview`.
