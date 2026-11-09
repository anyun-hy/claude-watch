# Unified local test suite

From the logged-in user's macOS Terminal, run:

```bash
bash /Users/anyun/Desktop/bash/tools/test-all.sh
```

Run without `sudo`. The current native desktop fixtures require Apple Silicon,
macOS 26+, Xcode's macOS SDK, the repository's Rust toolchain, Python 3 and Node.
The runner does not install missing tools. It opens temporary fixture windows,
uses local sockets and Seatbelt, and may stop processes created by the tests.
It does not launch real AI applications, modify VPN settings, install services,
or activate the NetworkExtension.

## Results

Each invocation creates a new, Git-ignored directory under
`.agent/test-runs/<timestamp>-<unique-id>/`. It prints the absolute path first.

- `SUMMARY.md`: result, duration, exit code and log link for every step.
- `results.json`: machine-readable results, commands and conditional skips.
- `logs/`: combined stdout/stderr for each step, including build failures.
- `plan.json`: the exact selected commands and dependencies.
- `run-info.json`: runner/manifest hashes and host metadata.
- `artifacts/`, `swift-cache/`: isolated build inputs and compiler cache.
- `tmp/`: link to this run's private short `/private/tmp/cw-t.*` directory;
  keeping socket paths short avoids macOS's Unix socket path-length limit.

The short temporary directory is recorded in `run-info.json` and retained for
inspection. Some existing fixture scripts remove their own files when done; their
stdout/stderr is still retained by this runner. Cargo uses the repository's
ignored `target/` because existing receipt tests require `target/debug`. One
legacy bridge script also uses the ignored `monitor/build/test-module-cache/`.

Failures do not stop unrelated steps. A failed prerequisite blocks only its
dependents. Compiler success, app-launch success and a test assertion pass are
distinct: native bridge scripts must print their actual completion marker and
must not print a failure marker. A failure or blocked step makes the final exit
code nonzero. Ctrl-C records interruption and stops only the active process group
created by the runner. Completed results are written after every step.

Exit codes: `0` selected automatic steps passed (explicit exclusions remain),
`1` one or more steps failed/blocked, `2` invalid runner configuration, `130`
interrupted. Counts are **steps**, not individual assertions or real-host
acceptance scenarios.

## Coverage and exclusions

The plan builds all Rust workspace binaries before running the workspace tests
once. It also covers Python contracts, both routing checks, generated policy
parity, JavaScript probe fixtures, production Swift typechecking, and every
`monitor/tests/*Tests.swift` file through the reviewed
[`unified_swift_tests.json`](../tools/unified_swift_tests.json) recipes. Adding a
Swift test without adding a recipe fails inventory validation rather than
silently omitting the file.

The three normally ignored Rust cases have explicit preparation: read-only
host listener diagnostics, the resident WebKit **fixture** runtime, and an
isolated copy of the gateway peer test executable signed ad hoc with
`runtime,library`. This signing is free, affects only that test copy, and does
not install or validate the production root service. The listener diagnostic
may fail because host listener evidence is unavailable; it is not silently
converted into a pass.

Live external probes, UI preview/image generators, real AI/Finder acceptance,
root service installation, VPN changes and long-running production acceptance
are excluded and listed. The optional `AIProcessControlTests --owned-force-child`
mode is not selected because it still contains PID-only cleanup; the default
policy, owned exec identity and owned-child TERM modes are included. The
Snapshot transport fixture no longer sends a cleanup SIGKILL to an unverified
orphan PID.

Failures remain visible in the original result directory. Corrective reruns
are separate evidence and do not overwrite an earlier whole-suite result.
The graph fixtures now check the existing desktop grouping while retaining
PID, actual connection and independent CLI distinctions. The live listener
diagnostic accepts the production lsof-first/netstat-fallback collection path,
requires usable owner/endpoint records and stable process metadata, and does
not claim TAG authentication, connection reachability or gateway protection.

## Inspect or rerun a narrow selection

```bash
# Read-only: list all steps, commands and mapped Swift files.
bash tools/test-all.sh --list

# Preserve this rerun separately; existing output directories are refused.
bash tools/test-all.sh --only swift.VpnSettingsSaveTests

# Explicit new location for all logs and results.
bash tools/test-all.sh --output /private/tmp/watch-tests-new-run
```

`--only` includes dependencies and is labelled a selected run, never a full
suite pass. Tests requiring Rust-exported fixtures also require the workspace
test step that generates them in the **new** result directory; no old result is
treated as fresh evidence.
