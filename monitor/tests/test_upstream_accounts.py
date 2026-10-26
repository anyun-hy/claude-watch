import hashlib, tempfile, unittest
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"Resources"))
from watch_switcher.common import Paths, atomic_json
from watch_switcher.upstream_accounts import UpstreamAccountAdapter, PINNED_SHA256

class UpstreamAccountsTests(unittest.TestCase):
    def test_vendor_function_block_is_bounded_and_runs_in_workspace(self):
        with tempfile.TemporaryDirectory() as tmp:
            home=Path(tmp)/"home"; home.mkdir(); paths=Paths(home); paths.initialize()
            paths.active.mkdir(parents=True); (paths.active/"x").write_text("A")
            atomic_json(paths.state,{"schema":1,"current":"A"})
            vendor=Path(__file__).resolve().parents[1]/"ThirdParty/ClaudeSwitcher/upstream/core/claude-switch.sh"
            self.assertEqual(hashlib.sha256(vendor.read_bytes()).hexdigest(),PINNED_SHA256)
            run=UpstreamAccountAdapter(paths,vendor).run("B")
            self.assertTrue((run.data).is_dir())
            self.assertTrue((run.accounts/"A").is_dir())
            self.assertTrue(run.launch_requested)
            self.assertEqual((paths.active/"x").read_text(),"A")

if __name__=="__main__": unittest.main()
