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
