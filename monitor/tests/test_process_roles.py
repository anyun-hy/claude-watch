import importlib.util
import json
from pathlib import Path
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location("process_roles", Path(__file__).parents[1] / "Resources/process_roles.py")
roles = importlib.util.module_from_spec(spec); spec.loader.exec_module(roles)

class ProcessRoleTests(unittest.TestCase):
    def classify(self, tokens, executable="/app/Client.app/Contents/Frameworks/Helper", specs=None):
        with mock.patch.object(roles, "resolve", side_effect=lambda x: x):
            return roles.classify(tokens, executable, specs or [("/tools/rea", ["mcp"], "REA")])

    def test_exact_configured_entry_and_interpreter_entry(self):
        for tokens in [["/tools/rea", "mcp"], ["/usr/bin/python3", "/tools/rea", "mcp"], ["/usr/bin/node", "/tools/rea", "mcp"]]:
            self.assertEqual(self.classify(tokens)["runtimeRole"], "mcp")

    def test_argument_data_and_inline_code_cannot_impersonate_mcp(self):
        for tokens in [["/other/tool", "/tools/rea", "mcp"], ["node", "-e", "/tools/rea mcp"],
                       ["python3", "-c", "/tools/rea mcp"], ["node", "/other/script", "/tools/rea", "mcp"]]:
            self.assertEqual(self.classify(tokens), {})

    def test_stdio_alone_is_not_mcp(self):
        self.assertEqual(self.classify(["/other/language-server", "--stdio"]), {})

    def test_chromium_roles_are_not_mcp(self):
        for flag, role in [("--utility-sub-type=network.mojom.NetworkService", "chromium_network"),
                           ("--type=renderer", "chromium_renderer"), ("--type=gpu-process", "chromium_gpu")]:
            self.assertEqual(self.classify(["/app/Helper", flag])["runtimeRole"], role)

    def test_space_in_executable_and_unparseable_argv(self):
        executable = "/Applications/ChatGPT.app/Contents/MacOS/Codex (Service)"
        tokens = roles.command_tokens(executable + " --type=utility", executable)
        self.assertEqual(tokens, [executable, "--type=utility"])
        self.assertEqual(roles.command_tokens("node 'unfinished", "node"), [])

    def test_descendant_inherits_tool_and_payload_never_returns(self):
        stamps = {10: (1, "Mon Oct 19 18:25:57 2026", "/tools/rea"),
                  11: (10, "Mon Oct 19 18:25:58 2026", "/usr/bin/node")}
        targets = "10|Mon Oct 19 18:25:57 2026|openai-child\n11|Mon Oct 19 18:25:58 2026|openai-child"
        response = mock.Mock(stdout="10 /tools/rea mcp --private-token=DO_NOT_EMIT\n11 node /child.js")
        with mock.patch.object(roles, "identities", return_value=stamps), mock.patch.object(roles.subprocess, "run", return_value=response), \
             mock.patch.object(roles, "mcp_specs", return_value=[("/tools/rea", ["mcp"], "REA")]), \
             mock.patch.object(roles, "resolve", side_effect=lambda x: x):
            out = roles.collect(targets, Path("/mock"))
        self.assertEqual(out["11"]["roleEvidence"], "configured_mcp_descendant")
        self.assertNotIn("DO_NOT_EMIT", json.dumps(out))
        self.assertNotIn("/tools/rea", json.dumps(out))

    def test_reused_pid_hint_is_discarded(self):
        old = {10: (1, "Mon Oct 19 18:25:57 2026", "/tools/rea")}
        new = {10: (1, "Mon Oct 19 18:25:58 2026", "/other/tool")}
        with mock.patch.object(roles, "identities", side_effect=[old, new]), \
             mock.patch.object(roles.subprocess, "run", return_value=mock.Mock(stdout="10 /tools/rea mcp")), \
             mock.patch.object(roles, "mcp_specs", return_value=[("/tools/rea", ["mcp"], "REA")]), \
             mock.patch.object(roles, "resolve", side_effect=lambda x: x):
            self.assertEqual(roles.collect("10|Mon Oct 19 18:25:57 2026|openai-child", Path("/mock")), {})

if __name__ == "__main__": unittest.main()
