"""Private-directory and harmless subprocess coverage for installer logging."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location("cw_reinstall_log",ROOT/"tools/reinstall_log.py")
log=importlib.util.module_from_spec(spec)
spec.loader.exec_module(log)

class ReinstallLogging(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix="cw-reinstall-log-")
        self.root=Path(self.temp.name)
        self.base=self.root/"logs"
    def tearDown(self):
        self.temp.cleanup()
    def init(self):
        return log.initialize(self.root,self.base)
    def test_target_identity_is_validated_without_recording_untrusted_arguments(self):
        first=log.initialize(self.root,self.base,"3.0.0","381")
        value=json.loads((first/"run.json").read_text())
        self.assertEqual((value["target_version"],value["target_build"]),("3.0.0","381"))
        log.update(first,"build","passed",0,0.1,None)
        value=json.loads((first/"run.json").read_text())
        self.assertEqual(value["status"],"running","build success alone is not a completed reinstall")
        self.assertEqual(value["phases"][-1]["status"],"passed")
        second=log.initialize(self.root,self.base,"token=PRIVATE","password=PRIVATE")
        value=json.loads((second/"run.json").read_text())
        self.assertIsNone(value["target_version"]);self.assertIsNone(value["target_build"])
        self.assertNotIn("PRIVATE",json.dumps(value))
    def test_split_credentials_urls_and_accounts_are_not_saved(self):
        run=self.init();saved=log.SavedOutput(run,"build",str(self.root))
        for part in [b"Authoriza",b"tion: Bearer TOPSECRET\n",b"https://user:password@site.test/path?token=SECRET\n",b"alice@example.test ",str(self.root).encode(),b"/project\n"]:
            saved.feed(part)
        saved.feed(b"",final=True)
        value=(run/"build.log").read_text()
        for secret in ("TOPSECRET","SECRET","alice@example.test",str(self.root),"user:password"):
            self.assertNotIn(secret,value)
        self.assertIn("$HOME/project",value)
    def test_rotation_and_finished_run_retention_are_bounded(self):
        run=self.init();saved=log.SavedOutput(run,"build","",limit=180)
        for i in range(40):saved.feed(f"line {i:02d} {'x'*40}\n".encode())
        active=run/"build.log";old=run/"build.log.1"
        self.assertLessEqual(active.stat().st_size+old.stat().st_size,360)
        self.assertIn("line 39",active.read_text());self.assertTrue(saved.rotated)
        log.update(run,"build","failed",2,0.1,saved)
        for _ in range(8):
            run=self.init();log.update(run,"install","passed",0,0.1,None)
        self.assertEqual(len(list(self.base.iterdir())),log.KEEP)
    def test_unknown_artifacts_and_active_runs_are_preserved(self):
        runs=[self.init() for _ in range(log.KEEP)]
        with self.assertRaises(OSError):self.init()
        self.assertTrue(all(run.is_dir() for run in runs))
        (runs[0]/"foreign").write_text("keep")
        with self.assertRaises(OSError):self.init()
        self.assertEqual((runs[0]/"foreign").read_text(),"keep")
    def test_failure_keeps_child_exit_and_safe_summary_without_command_arguments(self):
        run=self.init()
        result=subprocess.run([sys.executable,str(ROOT/"tools/reinstall_log.py"),"--run",str(run),"--phase","build","--",sys.executable,"-c","import sys; print('compiler fixture failed'); print('Cookie: credential'); sys.exit(23)"],capture_output=True,text=True,timeout=10)
        self.assertEqual(result.returncode,23)
        self.assertIn("compiler fixture failed",result.stdout)
        self.assertIn("Cookie: credential",result.stdout,"console stays unchanged")
        self.assertNotIn("credential",(run/"build.log").read_text())
        value=json.loads((run/"run.json").read_text())
        self.assertEqual(value["status"],"failed");self.assertEqual(value["phases"][-1]["exit_code"],23)
        self.assertNotIn("-c",json.dumps(value));self.assertNotIn("Cookie",json.dumps(value))
    def test_unavailable_log_does_not_change_child_exit_or_touch_symlink(self):
        run=self.init();outside=self.root/"outside";outside.write_text("keep")
        (run/"build.log").symlink_to(outside)
        result=subprocess.run([sys.executable,str(ROOT/"tools/reinstall_log.py"),"--run",str(run),"--phase","build","--",sys.executable,"-c","raise SystemExit(17)"],capture_output=True,text=True,timeout=10)
        self.assertEqual(result.returncode,17);self.assertEqual(outside.read_text(),"keep")
        self.assertIn("日志不可用",result.stderr)
    def test_tty_stdin_survives_wrapper_without_becoming_a_pipe(self):
        import pty
        master,slave=pty.openpty()
        try:
            run=self.init()
            result=subprocess.run([sys.executable,str(ROOT/"tools/reinstall_log.py"),"--run",str(run),"--phase","install","--",sys.executable,"-c","import os,sys; print('terminal='+str(os.isatty(0))); sys.exit(0 if os.isatty(0) else 9)"],stdin=slave,capture_output=True,text=True,timeout=10)
            self.assertEqual(result.returncode,0,result.stderr);self.assertIn("terminal=True",result.stdout)
        finally:
            os.close(slave);os.close(master)
