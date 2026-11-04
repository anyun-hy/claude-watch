#!/usr/bin/env python3
from pathlib import Path

root = Path(__file__).resolve().parent.parent
source = (root / "monitor/Sources/SwitcherStore.swift").read_text()

required = [
    "runAccountSwitchWithDNSRefresh(_ args: [String], input: Data?, setupProgress: SetupProgressReader?)",
    "SwitcherCommandRunner.run(args, input: input, dnsRefreshToken: token, setupProgress: setupProgress)",
    'if args.starts(with: ["account", "switch"]) && args.contains("--apply") {',
    "runAccountSwitchWithDNSRefresh(args, input: input, setupProgress: channel)",
    "defer { channel?.finish() }",
]
for needle in required:
    if source.count(needle) != 1:
        raise SystemExit(f"routing contract mismatch: {needle}")

old = "runAccountSwitchWithDNSRefresh(args, input: input)"
if old in source:
    raise SystemExit("legacy account-switch call still bypasses progress channel")

channel_pos = source.find("let channel: SetupProgressReader?")
account_pos = source.find('if args.starts(with: ["account", "switch"]) && args.contains("--apply") {', channel_pos)
if channel_pos < 0 or account_pos < 0 or channel_pos > account_pos:
    raise SystemExit("progress channel must be created before account-switch routing")

print("PASS: account switch --apply shares the bounded progress reader with DNS refresh routing")
