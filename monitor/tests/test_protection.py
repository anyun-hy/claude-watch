"""Isolated service previews, commit/recovery and actual-vs-desired status."""
import copy
import json
import plistlib
import time
from pathlib import Path
from unittest.mock import patch

from test_switcher import Fixture, FakeSystem
from watch_switcher.common import SwitcherError, load_config, save_config
from watch_switcher.services import guard_tick, service_status, protection_preview, protection_apply, policy_issues
from watch_switcher.system import System
from watch_switcher.onboarding import recover
from watch_switcher.repair import make_plan


class ServiceSystem(FakeSystem):
    def __init__(self):
        super().__init__()
        self.clock = dict(target='Asia/Tokyo', registered=True, last_success=time.time())
        self.jobs = {name: dict(registered=name != 'updater', trusted=True,
                    definition='fixed-' + name, last_exit=0) for name in ('watchdog','updater','original')}
        self.crash_after_change = False
    def watchdog_state(self): return copy.deepcopy(self.clock)
    def service_job(self, name): return copy.deepcopy(self.jobs[name])
    def guard_status(self, config): return config['enabled'] and config['guard_enabled']
    def admin(self, *args):
        super().admin(*args)
        if args[0] == 'watchdog':
            enabled = args[1] != 'off'
            self.clock.update(target=args[1] if enabled else None, registered=enabled)
            self.jobs['watchdog']['registered'] = enabled
            if self.crash_after_change:
                class PowerLoss(BaseException): pass
                raise PowerLoss()


class ProtectionTests(Fixture):
    def test_client_name_cannot_invent_a_routing_failure(self):
        config = dict(self.config, proxy_mode='tag', require_pinned_rules=True)
        self.assertFalse(any(row['id'] == 'routing' for row in policy_issues(config)))
    def setUp(self):
        super().setUp()
        self.system = ServiceSystem()
        self.config.update(timezone_watchdog=True)
        save_config(self.paths,self.config)
        runtime = self.paths.watch/'runtime'
        runtime.mkdir()
        (runtime/'switcher.py').write_text('# fixture only\n')
        (self.paths.watch/'state').mkdir()
        (self.paths.watch/'state/baseline.conf').write_text('original baseline\n')
    def assert_preserved(self):
        self.assertEqual(self.system.local_value['timezone'],'Asia/Tokyo')
        self.assertEqual(self.system.local_value['locale'],'ja_JP')
        self.assertIn('en-JP',self.system.local_value['language'])
        self.assertTrue(self.system.jobs['original']['registered'])
        self.assertEqual((self.paths.watch/'state/baseline.conf').read_text(),'original baseline\n')
    def test_status_separates_all_actual_services_without_writes(self):
        before=self.paths.config.read_bytes()
        result=service_status(self.paths,self.system,self.config)
        states={row['id']:row['state'] for row in result['services']}
        self.assertEqual(states,dict(guard='running',original='scheduled',watchdog='scheduled',updater='unavailable'))
        self.assertEqual(self.paths.config.read_bytes(),before)
        self.assertEqual(self.system.calls,[])
    def test_saved_update_intent_is_not_registered_update_service(self):
        self.config['auto_update']=True
        row=next(row for row in service_status(self.paths,self.system,self.config)['services'] if row['id']=='updater')
        self.assertTrue(row['desired'])
        self.assertEqual(row['state'],'unavailable')
        self.assertFalse(self.system.jobs['updater']['registered'])
    def test_master_policy_dependency_is_visible(self):
        config=dict(self.config,enabled=False)
        row=service_status(self.paths,self.system,config)['services'][0]
        self.assertEqual(row['state'],'error')
        self.assertIn('策略未启用',row['detail'])
    def test_preview_has_values_and_no_side_effects(self):
        plan=protection_preview(self.paths,self.system,{'guard_enabled':False})
        self.assertEqual(plan['actions'][0]['detail'],'开启 → 关闭；原版保镖保持独立运行。')
        self.assertTrue(load_config(self.paths)['guard_enabled'])
        self.assertEqual(self.system.calls,[])
    def test_disable_only_own_guard_keeps_original_and_environment(self):
        self.system.running=True
        changes={'guard_enabled':False}
        plan=protection_preview(self.paths,self.system,changes)
        result=protection_apply(self.paths,self.system,changes,plan['id'])
        self.assertEqual(result['status'],'ok')
        self.assertFalse(load_config(self.paths)['guard_enabled'])
        self.assertTrue(load_config(self.paths)['enabled'])
        self.assertTrue(self.system.running)
        self.assertEqual(self.system.calls,[])
        self.assert_preserved()
    def test_enabling_guard_explains_and_enables_required_policy(self):
        save_config(self.paths,dict(self.config,enabled=False,guard_enabled=False))
        changes={'guard_enabled':True}
        plan=protection_preview(self.paths,self.system,changes)
        self.assertIn('同时启用',plan['actions'][0]['detail'])
        protection_apply(self.paths,self.system,changes,plan['id'])
        self.assertTrue(load_config(self.paths)['enabled'])
        self.assert_preserved()
    def test_clock_target_change_keeps_only_a_fresh_healthy_guard_heartbeat(self):
        receipt = guard_tick(self.paths, self.system)
        self.assertEqual(receipt['status'], 'ok')
        actual = System(self.paths)
        actual.backend_healthy = lambda: True
        changed = dict(self.config, timezone_watchdog=False, country='US', timezone='America/Los_Angeles')
        self.assertTrue(actual.guard_status(changed))
        self.assertFalse(actual.guard_status(dict(changed, proxy_mode='surge')))
        actual.backend_healthy = lambda: False
        self.assertFalse(actual.guard_status(changed))
        actual.backend_healthy = lambda: True
        receipt['status'] = 'degraded'
        (self.paths.base/'guard-heartbeat.json').write_text(json.dumps(receipt))
        self.assertFalse(actual.guard_status(changed))
    def test_timezone_daemon_definition_runs_at_boot_and_remains_periodic(self):
        source = (Path(__file__).resolve().parents[1]/'Resources/watch-admin.sh').read_text()
        plist = source.split("<<'PLIST'\n", 1)[1].split('\nPLIST\n', 1)[0]
        definition = plistlib.loads(plist.encode())
        self.assertEqual(definition['Label'], 'io.local.claudewatch.timezone')
        self.assertTrue(definition['RunAtLoad'])
        self.assertEqual(definition['StartInterval'], 3600)
        self.assertEqual(definition['ProgramArguments'][-1], 'tick')
    def test_disable_clock_keeps_current_system_timezone(self):
        changes={'timezone_watchdog':False}
        plan=protection_preview(self.paths,self.system,changes)
        protection_apply(self.paths,self.system,changes,plan['id'])
        self.assertFalse(self.system.clock['registered'])
        self.assertFalse(load_config(self.paths)['timezone_watchdog'])
        self.assert_preserved()
    def test_changed_task_definition_invalidates_preview(self):
        changes={'timezone_watchdog':False}
        plan=protection_preview(self.paths,self.system,changes)
        self.system.jobs['watchdog']['definition']='changed externally'
        with self.assertRaisesRegex(SwitcherError,'重新预览'):
            protection_apply(self.paths,self.system,changes,plan['id'])
        self.assertEqual(self.system.calls,[])
    def test_cancelled_admin_restores_and_removes_transaction(self):
        changes={'timezone_watchdog':False}
        plan=protection_preview(self.paths,self.system,changes)
        self.system.fail_admin=True
        with self.assertRaises(SwitcherError) as raised:
            protection_apply(self.paths,self.system,changes,plan['id'])
        self.assertEqual(raised.exception.code,'protection_rolled_back')
        self.assertFalse((self.paths.base/'setup-transaction.json').exists())
        self.assertTrue(load_config(self.paths)['timezone_watchdog'])
        self.assert_preserved()
    def test_interrupted_clock_change_uses_existing_recovery(self):
        changes={'timezone_watchdog':False}
        plan=protection_preview(self.paths,self.system,changes)
        self.system.crash_after_change=True
        with self.assertRaises(BaseException): protection_apply(self.paths,self.system,changes,plan['id'])
        self.assertTrue((self.paths.base/'setup-transaction.json').exists())
        self.system.crash_after_change=False
        result=recover(self.paths,self.system)
        self.assertEqual(result['status'],'ok')
        self.assertEqual(self.system.clock['target'],'Asia/Tokyo')
        self.assertTrue(self.system.clock['registered'])
        self.assert_preserved()
    def test_conflicting_external_configuration_is_preserved(self):
        changes={'timezone_watchdog':False}
        plan=protection_preview(self.paths,self.system,changes)
        original=self.system.admin
        def changed(*args):
            original(*args)
            if args==('watchdog','off'):
                self.paths.config.write_text(json.dumps(dict(self.config,guard_enabled=False)))
        self.system.admin=changed
        result=protection_apply(self.paths,self.system,changes,plan['id'])
        self.assertEqual(result['status'],'partial')
        self.assertTrue(result['recovery_required'])
        self.assertFalse(load_config(self.paths)['guard_enabled'])
        self.assertEqual(self.system.clock['target'],'Asia/Tokyo')
        self.assert_preserved()
    def test_source_missing_cannot_enable_an_update_task(self):
        with self.assertRaises(SwitcherError) as raised:
            protection_preview(self.paths,self.system,{'auto_update':True})
        self.assertEqual(raised.exception.code,'update_source_missing')
        self.assertEqual(self.system.calls,[])
    def test_multiple_or_legacy_changes_are_rejected(self):
        for changes in ({'guard_enabled':False,'auto_update':False},{'disable-legacy':True},{'guard_enabled':'false'}):
            with self.subTest(changes=changes),self.assertRaises(SwitcherError):
                protection_preview(self.paths,self.system,changes)
    def test_legacy_dns_allowlist_does_not_create_a_policy_issue(self):
        config=dict(self.config,require_dns=True,expected_resolvers=[])
        self.assertFalse(any(row['id']=='dns' for row in policy_issues(config)))
        self.assertTrue(config['require_dns'])
    def test_repair_does_not_implicitly_enable_a_disabled_guard(self):
        plan=make_plan(self.paths,self.system,dict(self.config,guard_enabled=False))
        self.assertNotIn('guard',[action['id'] for action in plan['actions']])
    def test_legacy_date_reference_is_reviewable_even_if_actual_locale_matches(self):
        plan=make_plan(self.paths,self.system,dict(self.config,locale='en_JP'))
        action=next(row for row in plan['actions'] if row['id']=='reference')
        self.assertEqual((action['before'],action['after']),('en_JP','ja_JP'))

    def test_clock_enable_rejects_a_timezone_outside_accepted_country(self):
        save_config(self.paths,dict(self.config,timezone='America/New_York'))
        with self.assertRaises(SwitcherError) as raised:
            protection_preview(self.paths,self.system,{'timezone_watchdog':True})
        self.assertEqual(raised.exception.code,'reference_required')
        self.assertEqual(self.system.calls,[])

    def update_task(self,paths,system,enable):
        path=paths.home/'Library/LaunchAgents/io.local.claudewatch.update.plist'
        path.parent.mkdir(parents=True,exist_ok=True)
        if enable: path.write_text('isolated scheduled updater')
        elif path.exists(): path.unlink()
        system.jobs['updater']['registered']=enable
        return {'status':'ok','enabled':enable}

    def test_update_task_enable_is_committed_and_keeps_original_guard(self):
        save_config(self.paths,dict(self.config,update_url='https://updates.invalid/release.json',update_public_key='isolated key'))
        changes={'auto_update':True}
        plan=protection_preview(self.paths,self.system,changes)
        with patch('watch_switcher.repair.configure_update_task',side_effect=self.update_task):
            result=protection_apply(self.paths,self.system,changes,plan['id'])
        self.assertEqual(result['status'],'ok')
        self.assertTrue(load_config(self.paths)['auto_update'])
        self.assertTrue(self.system.jobs['updater']['registered'])
        self.assert_preserved()

    def test_update_task_is_rolled_back_when_configuration_commit_fails(self):
        save_config(self.paths,dict(self.config,update_url='https://updates.invalid/release.json',update_public_key='isolated key'))
        changes={'auto_update':True}
        plan=protection_preview(self.paths,self.system,changes)
        with patch('watch_switcher.repair.configure_update_task',side_effect=self.update_task), \
             patch('watch_switcher.onboarding.configure_update_task',side_effect=self.update_task), \
             patch('watch_switcher.repair.atomic_text',side_effect=OSError('isolated write failure')):
            with self.assertRaises(SwitcherError) as raised:
                protection_apply(self.paths,self.system,changes,plan['id'])
        self.assertEqual(raised.exception.code,'protection_rolled_back')
        self.assertFalse(self.system.jobs['updater']['registered'])
        self.assertFalse(load_config(self.paths)['auto_update'])
        self.assertFalse((self.paths.base/'setup-transaction.json').exists())
        self.assert_preserved()

    def test_legacy_invalid_update_intent_has_a_clear_reviewable_difference(self):
        save_config(self.paths,dict(self.config,auto_update=True))
        plan=protection_preview(self.paths,self.system,{'auto_update':False})
        self.assertIn('保存意愿：开启 → 关闭',plan['actions'][0]['detail'])
        self.assertIn('实际任务：关闭 → 关闭',plan['actions'][0]['detail'])

    def test_broken_guard_receipt_does_not_hide_independent_services(self):
        (self.paths.base/'guard-heartbeat.json').write_text('{broken')
        def unavailable(config): raise SwitcherError('invalid_state','isolated bad heartbeat')
        self.system.guard_status=unavailable
        result=service_status(self.paths,self.system,self.config)
        states={row['id']:row['state'] for row in result['services']}
        self.assertEqual(states['guard'],'error')
        self.assertEqual(states['original'],'scheduled')
        self.assertEqual(states['watchdog'],'scheduled')

    def test_legacy_skip_flags_cannot_disable_dns_or_stun_launch_checks(self):
        from watch_switcher.audit import evaluate
        config=dict(self.config,require_dns=False,require_stun=False,expected_resolvers=[])
        online=copy.deepcopy(self.system.online_value)
        online['stun']={'complete':False,'observations':[]}
        result=evaluate(config,self.system.local_value,online)
        rows={row['id']:row for row in result['rows']}
        self.assertTrue(rows['dns']['required'])
        self.assertTrue(rows['stun']['required'])
        self.assertNotIn('dns',result['blocked'])
        self.assertIn('stun',result['blocked'])
        self.assertFalse(result['ready'])
