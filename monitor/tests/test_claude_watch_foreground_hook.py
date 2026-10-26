import importlib.util
import io
import json
from pathlib import Path
import plistlib
import subprocess
import tempfile
import unittest
from unittest import mock


SPEC = importlib.util.spec_from_file_location(
    "foreground_hook", Path(__file__).parents[1] / "tools/claude_watch_foreground_hook.py"
)
hook = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(hook)


class ForegroundHookTests(unittest.TestCase):
    def event(self, app="io.local.watchpanel", tool="get_app_state"):
        return {"hook_event_name": "PreToolUse",
                "tool_name": "mcp__computer_use__" + tool, "tool_input": {"app": app}}

    def invoke(self, event):
        with mock.patch("sys.stdin", io.StringIO(json.dumps(event))):
            return hook.main()

    def test_target_aliases_and_actions_activate(self):
        for app in ("io.local.watchpanel", "Claude Watch", "Claude Watch Monitor",
                    "Claude Watch Monitor.app", str(hook.APP), str(hook.APP) + "/"):
            for tool in ("get_app_state", "click", "drag", "perform_secondary_action",
                         "press_key", "scroll", "select_text", "set_value", "type_text"):
                with self.subTest(app=app, tool=tool), mock.patch.object(hook, "activate") as activate:
                    self.assertEqual(self.invoke(self.event(app, tool)), 0)
                    activate.assert_called_once_with()

    def test_unrelated_apps_and_build_copies_are_untouched(self):
        events = [self.event(app) for app in (
            "Claude", "/Applications/Claude.app", "com.apple.finder",
            "/tmp/Claude Watch Monitor.app", "io.local.watchpanel.leak-bridge-tests",
            None, {"app": "io.local.watchpanel"},
        )]
        events += [self.event(tool="list_apps"), None, {},
                   {**self.event(), "hook_event_name": "PostToolUse"},
                   {**self.event(), "tool_name": "Bash"}]
        for event in events:
            with self.subTest(event=event), mock.patch.object(hook, "activate") as activate:
                self.assertEqual(self.invoke(event), 0)
                activate.assert_not_called()

    def test_activation_failure_blocks_the_target_tool(self):
        errors = [OSError("app missing"), ValueError("wrong bundle"),
                  subprocess.CalledProcessError(1, ["open"]),
                  subprocess.TimeoutExpired(["osascript"], 5)]
        for error in errors:
            with self.subTest(error=error), mock.patch.object(hook, "activate", side_effect=error), \
                    mock.patch("sys.stderr", io.StringIO()) as stderr:
                self.assertEqual(self.invoke(self.event()), 2)
                self.assertIn("blocked", stderr.getvalue())

    def test_bundle_identity_is_checked_before_launching(self):
        with tempfile.TemporaryDirectory() as directory:
            app = Path(directory)
            (app / "Contents").mkdir()
            (app / "Contents/Info.plist").write_bytes(
                plistlib.dumps({"CFBundleIdentifier": "another.app"})
            )
            with mock.patch.object(hook, "APP", app), mock.patch.object(hook.subprocess, "run") as run:
                with self.assertRaises(ValueError):
                    hook.activate()
                run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
