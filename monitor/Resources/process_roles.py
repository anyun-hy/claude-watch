"""Read-only component hints. Never returns command arguments or credentials."""
import argparse
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
try:
    import tomllib
except ImportError:
    tomllib = None

ROLES = {"mcp", "chromium_network", "chromium_renderer", "chromium_gpu", "chromium_crashpad"}

def normalized_stamp(value):
    return " ".join(value.split())

def command_tokens(command, executable):
    # ps may leave spaces in argv[0] unquoted. Remove its independently observed
    # executable prefix first; never look for an MCP-looking substring in data.
    if executable and command.startswith(executable) and command[len(executable):len(executable)+1].isspace():
        command = shlex.quote(executable) + command[len(executable):]
    try:
        return shlex.split(command)
    except ValueError:
        return []

def entrypoint(tokens):
    if not tokens:
        return None
    name = Path(tokens[0]).name.lower()
    if name in {"node", "nodejs", "bun"} or name.startswith("python"):
        rest = tokens[1:]
        while rest and rest[0] in {"--no-warnings", "--enable-source-maps", "-u", "-B", "--"}:
            rest = rest[1:]
        if not rest or rest[0].startswith("-"):
            return None  # -e/-c/--eval, preload and arbitrary argument data
        return rest[0], rest[1:]
    return tokens[0], tokens[1:]

def resolve(command):
    found = command if os.path.isabs(command) else shutil.which(command)
    return os.path.realpath(found) if found else None

def mcp_specs(home):
    result = []
    sources = [(home / ".codex/config.toml", "toml"),
               (home / "Library/Application Support/Claude/claude_desktop_config.json", "json"),
               (home / ".claude.json", "json")]
    for path, kind in sources:
        try:
            if kind == "toml" and tomllib is None:
                continue
            if path.stat().st_size > 2 * 1024 * 1024:
                continue
            data = tomllib.loads(path.read_text()) if kind == "toml" else json.loads(path.read_text())
            servers = data.get("mcp_servers" if kind == "toml" else "mcpServers", {})
            for name, value in servers.items():
                command, args = value.get("command"), value.get("args", [])
                if not isinstance(command, str) or not isinstance(args, list) or not all(isinstance(x, str) for x in args):
                    continue
                executable = resolve(command)
                if not executable:
                    continue
                # An unqualified interpreter with no script cannot identify MCP.
                if not args and Path(command).name in {"node", "nodejs", "bun", "python", "python3", "uvx", "npx"}:
                    continue
                label = re.sub(r"[\x00-\x1f\x7f]", "", str(name))[:64]
                result.append((executable, args, label))
        except (OSError, ValueError, AttributeError, TypeError):
            continue
    return result

def classify(tokens, executable, specs):
    entry = entrypoint(tokens)
    if entry:
        command, arguments = entry
        resolved = resolve(command)
        for known, prefix, name in specs:
            if resolved == known and arguments[:len(prefix)] == prefix:
                return {"runtimeRole": "mcp", "serviceName": name, "roleEvidence": "configured_mcp_entry"}
    if "--utility-sub-type=network.mojom.NetworkService" in tokens:
        return {"runtimeRole": "chromium_network", "serviceName": "Chromium 网络服务", "roleEvidence": "runtime_component"}
    for flag, role, name in [("--type=renderer", "chromium_renderer", "Chromium 渲染器"),
                              ("--type=gpu-process", "chromium_gpu", "Chromium GPU 组件")]:
        if flag in tokens:
            return {"runtimeRole": role, "serviceName": name, "roleEvidence": "runtime_component"}
    if Path(executable).name == "chrome_crashpad_handler":
        return {"runtimeRole": "chromium_crashpad", "serviceName": "Chromium 崩溃报告", "roleEvidence": "runtime_component"}
    return {}

def identities(pids):
    if not pids:
        return {}
    text = subprocess.run(["/bin/ps", "-ww", "-p", ",".join(map(str, pids)), "-o", "pid=,ppid=,uid=,lstart=,comm="],
        capture_output=True, text=True, timeout=3, env={**os.environ, "LC_ALL": "C"}).stdout
    rows = {}
    for line in text.splitlines():
        match = re.match(r"\s*(\d+)\s+(\d+)\s+(\d+)\s+(\w+\s+\w+\s+\d+\s+[\d:]+\s+\d+)\s+(.+)$", line)
        if match:
            pid, parent, uid, stamp, executable = match.groups()
            if int(uid) == os.getuid():
                rows[int(pid)] = (int(parent), normalized_stamp(stamp), executable)
    return rows

def collect(targets, home):
    requested = {}
    for line in targets.splitlines():
        parts = line.split("|")
        if len(parts) == 3 and parts[0].isdigit():
            requested[int(parts[0])] = normalized_stamp(parts[1])
    pids = sorted(requested)[:2048]
    before = identities(pids)
    if not before:
        return {}
    commands = subprocess.run(["/bin/ps", "-ww", "-p", ",".join(map(str, before)), "-o", "pid=,args="],
        capture_output=True, text=True, timeout=3, env={**os.environ, "LC_ALL": "C"}).stdout
    specs = mcp_specs(home)
    output = {}
    for line in commands.splitlines():
        parts = line.strip().split(None, 1)
        if len(parts) != 2 or not parts[0].isdigit():
            continue
        pid = int(parts[0]); identity = before.get(pid)
        if not identity or identity[1] != requested.get(pid):
            continue
        role = classify(command_tokens(parts[1], identity[2]), identity[2], specs)
        if role:
            output[pid] = role
    # Tool children inherit a configured MCP ancestor, not the entire AI app tree.
    for pid in before:
        current, visited = pid, set()
        while current in before and current not in visited and len(visited) < 32:
            visited.add(current)
            if output.get(current, {}).get("runtimeRole") == "mcp":
                if pid != current:
                    output[pid] = {**output[current], "roleEvidence": "configured_mcp_descendant"}
                break
            current = before[current][0]
    after = identities(list(before))
    return {str(pid): {"started": before[pid][1], **role} for pid, role in output.items()
            if before.get(pid) == after.get(pid) and before[pid][1] == requested.get(pid)}

if __name__ == "__main__":
    parser = argparse.ArgumentParser(); parser.add_argument("--targets", required=True)
    args = parser.parse_args()
    try:
        result = collect(Path(args.targets).read_text(), Path.home())
    except (OSError, ValueError, subprocess.SubprocessError):
        result = {}
    print(json.dumps(result, ensure_ascii=False))
