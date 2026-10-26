import contextlib
import importlib.util
from pathlib import Path
import plistlib
import subprocess
import tempfile
import unittest
from unittest import mock

SOURCE = Path(__file__).resolve().parents[1]/'Packaging/app_lifecycle.py'
spec = importlib.util.spec_from_file_location('app_lifecycle', SOURCE)
app = importlib.util.module_from_spec(spec)
spec.loader.exec_module(app)

class AppLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.stack = contextlib.ExitStack(); self.addCleanup(self.stack.close)
        self.root = Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
        for key, value in {'APP':self.root/'Applications/Claude Watch Monitor.app',
                           'BASE':self.root/'data', 'PLIST':self.root/'LaunchAgents/watch.plist',
                           'TRASH':self.root/'Trash'}.items():
            self.stack.enter_context(mock.patch.object(app,key,value))
        app.BASE.mkdir(); (app.BASE/'account-A').write_text('retained account fixture')
        app.PLIST.parent.mkdir(); app.PLIST.write_text('retained launch fixture')
        self.source=self.root/'package/Claude Watch Monitor.app'
        for path, version in ((app.APP,'old'),(self.source,'new')):
            (path/'Contents').mkdir(parents=True)
            (path/'Contents/Info.plist').write_bytes(plistlib.dumps({'CFBundleIdentifier':app.BUNDLE,
                'CFBundleExecutable':'ClaudeWatchMonitor','CFBundleShortVersionString':version,'CFBundleVersion':version}))
        self.stack.enter_context(mock.patch.object(app,'validate',side_effect=app.identity))
        self.stack.enter_context(mock.patch.object(app,'stop_own_app'))
        self.stack.enter_context(mock.patch.object(app,'stop_own_agent'))
        self.commands=[]
        def runner(args,check=True):
            self.commands.append([str(x) for x in args])
            if args[0]=='/usr/bin/ditto':
                import shutil; shutil.copytree(args[1],args[2])
            return subprocess.CompletedProcess(args,0,'','')
        self.runner=runner
        self.stack.enter_context(mock.patch.object(app,'run',side_effect=runner))

    def test_replace_resets_only_watch_permission_after_old_app_removed(self):
        calls=[]
        def reset():
            calls.append('reset'); self.assertFalse(app.APP.exists())
            self.assertEqual(len(list(app.TRASH.glob('*/Claude Watch Monitor.app'))),1)
        with mock.patch.object(app,'reset_accessibility',side_effect=reset):app.apply(self.source)
        self.assertEqual(calls,['reset']);self.assertEqual(app.identity(app.APP)['CFBundleVersion'],'new')
        self.assertEqual((app.BASE/'account-A').read_text(),'retained account fixture')
        self.assertTrue(app.PLIST.exists())

    def test_backend_failure_rolls_back_app_and_keeps_data(self):
        def runner(args,check=True):
            if args[0]=='/bin/bash' and app.identity(app.APP)['CFBundleVersion']=='new':
                raise RuntimeError('isolated bootstrap failure')
            return self.runner(args,check)
        with mock.patch.object(app,'run',side_effect=runner), mock.patch.object(app,'reset_accessibility'):
            with self.assertRaisesRegex(RuntimeError,'bootstrap'):app.apply(self.source)
        self.assertEqual(app.identity(app.APP)['CFBundleVersion'],'old')
        self.assertEqual((app.BASE/'account-A').read_text(),'retained account fixture')

    def test_uninstall_removes_app_job_permission_but_not_accounts(self):
        with mock.patch.object(app,'reset_accessibility') as reset:app.apply()
        reset.assert_called_once();self.assertFalse(app.APP.exists());self.assertFalse(app.PLIST.exists())
        self.assertTrue((app.BASE/'account-A').exists())

    def test_wrong_bundle_or_transaction_does_not_reset_permissions(self):
        (app.APP/'Contents/Info.plist').write_bytes(plistlib.dumps({'CFBundleIdentifier':'other.app'}))
        with mock.patch.object(app,'reset_accessibility') as reset:
            with self.assertRaises(ValueError):app.apply(self.source)
            reset.assert_not_called()

    def test_permission_cleanup_is_scoped_to_exact_product(self):
        app.reset_accessibility()
        self.assertEqual(self.commands[0],['/usr/bin/tccutil','reset','Accessibility','io.local.watchpanel'])
        self.assertEqual(self.commands[1],['/usr/bin/defaults','delete','io.local.watchpanel','accessibilityPromptedBuild'])

    def test_same_source_cannot_delete_installed_application(self):
        with mock.patch.object(app,'reset_accessibility') as reset:
            with self.assertRaises(ValueError):app.apply(app.APP)
            reset.assert_not_called()

if __name__=='__main__':unittest.main()
