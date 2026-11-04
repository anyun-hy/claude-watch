#!/usr/bin/env python3
"""Static cross-boundary contract for UI and CLI force consent; no app execution."""
from pathlib import Path
root = Path(__file__).resolve().parent.parent
swift = (root / "monitor/Sources/SwitcherStore.swift").read_text()
engine = (root / "crates/watch-engine/src/main.rs").read_text()
cli = (root / "crates/watch-core/src/cli.rs").read_text()
store = (root / "crates/watch-runtime/src/config_store.rs").read_text()
checks = [
    ("UI consent tracked on user selection", "pendingOpenAIForceKeys.insert(setting.key)" in swift),
    ("UI consent removed when deselected", "pendingOpenAIForceKeys.remove(setting.key)" in swift),
    ("UI only forwards selected Force values", 'settings[$0] as? String == "force"' in swift),
    ("UI emits scoped confirmation argument", 'args += ["--confirm-force", approved.joined(separator: ",")]' in swift),
    ("CLI only allows explicit set confirmation", 'request.action.as_deref() != Some("set") || !request.flag("apply")' in cli),
    ("engine forwards confirmation", 'request.value("confirm-force")' in engine),
    ("store reads previous state under operation lock", store.index('self.storage.lock("operation", None)?') < store.index('let raw_before =')),
    ("store refuses confirmation without selected Force", 'incoming.get(key).and_then(Value::as_str) != Some("force")' in store),
    ("store refuses new unapproved Force", '"force_confirmation_required"' in store),
    ("store saves policy and grants together", 'self.storage.atomic_json(&self.storage.paths.config(),&validated.value()?)?' in "".join(store.split())),
]
for label, passed in checks:
    print(("PASS" if passed else "FAIL") + ": " + label)
if not all(passed for _, passed in checks):
    raise SystemExit(1)
