#!/usr/bin/env python3
"""Activate the installed Claude Watch before its Computer Use calls."""

import json
from pathlib import Path
import plistlib
import re
import subprocess
import sys


APP = Path("/Applications/Claude Watch Monitor.app")
BUNDLE_ID = "io.local.watchpanel"
TOOLS = re.compile(
    r"mcp__computer[_-]use__(get_app_state|click|drag|perform_secondary_action|"
    r"press_key|scroll|select_text|set_value|type_text)"
)
APP_ALIASES = {
    BUNDLE_ID,
    "claude watch",
    "claude watch monitor",
    "claude watch monitor.app",
    str(APP).casefold(),
}

# Read NSWorkspace directly; do not send Apple Events to System Events or
# change Accessibility, Screen Recording, or Stage Manager permissions.
WAIT_FOR_FOREGROUND = """
ObjC.import('AppKit');
function run() {
    var deadline = Date.now() + 3000;
    while (Date.now() < deadline) {
        var app = $.NSWorkspace.sharedWorkspace.frontmostApplication;
        if (app && ObjC.unwrap(app.bundleIdentifier) === 'io.local.watchpanel') {
            delay(0.5);
            return;
        }
        delay(0.1);
    }
    throw new Error('Claude Watch did not become the foreground application');
}
"""


def matches(event):
    if not isinstance(event, dict) or event.get("hook_event_name") != "PreToolUse":
        return False
    name = event.get("tool_name")
    args = event.get("tool_input")
    if not isinstance(name, str) or TOOLS.fullmatch(name) is None:
        return False
    if not isinstance(args, dict) or not isinstance(args.get("app"), str):
        return False
    return args["app"].strip().rstrip("/").casefold() in APP_ALIASES


def activate():
    with (APP / "Contents/Info.plist").open("rb") as stream:
        info = plistlib.load(stream)
    if info.get("CFBundleIdentifier") != BUNDLE_ID:
        raise ValueError("The installed app has an unexpected bundle identifier")
    subprocess.run(
        ["/usr/bin/open", "-a", str(APP)],
        check=True, timeout=8, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
    )
    subprocess.run(
        ["/usr/bin/osascript", "-l", "JavaScript", "-e", WAIT_FOR_FOREGROUND],
        check=True, timeout=5, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
    )


def main():
    try:
        event = json.load(sys.stdin)
        if matches(event):
            activate()
    except (OSError, ValueError, plistlib.InvalidFileException,
            subprocess.SubprocessError) as exc:
        print("Claude Watch foreground preparation failed; Computer Use call "
              "blocked: " + str(exc), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
