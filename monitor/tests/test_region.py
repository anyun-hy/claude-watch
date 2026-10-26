"""Regional rules: real egress, date conventions and independent English UI."""
import copy
import json
from unittest.mock import patch

from test_switcher import Fixture
from test_onboarding import SetupSystem
from watch_switcher.audit import evaluate, audit
from watch_switcher.common import SwitcherError, save_config
from watch_switcher.onboarding import observe, detect, preview, apply
from watch_switcher.region import reference, locale_check
from watch_switcher.repair import make_plan
from watch_switcher.repair import region_plan


class RegionTests(Fixture):
    def rows(self, local=None, online=None, config=None):
        receipt = evaluate(config or self.config, local or self.system.local_value,
                           online or self.system.online_value)
        return {row['id']: row for row in receipt['rows']}

    def test_japanese_date_formats_with_english_language_pass(self):
        rows = self.rows()
        self.assertEqual(rows['locale']['state'], 'ok')
        self.assertEqual(rows['timezone']['state'], 'ok')
        self.assertEqual(rows['language']['state'], 'ok')

    def test_matching_jp_suffix_is_insufficient(self):
        self.system.local_value['locale'] = 'en_JP'
        self.assertEqual(self.rows()['locale']['state'], 'fail')
        self.assertEqual(self.rows()['language']['state'], 'ok')

    def test_us_date_override_does_not_pass_with_ja_jp_locale(self):
        dates = self.system.local_value['date_format']
        dates['patterns']['short'] = 'M/d/yy'
        dates['has_custom_formats'] = True
        self.assertEqual(self.rows()['locale']['state'], 'fail')
        with self.assertRaisesRegex(SwitcherError, '自定义日期'):
            make_plan(self.paths, self.system, self.config)

    def test_medium_or_long_custom_format_is_also_checked(self):
        for style in ('medium', 'long'):
            with self.subTest(style=style):
                local = copy.deepcopy(self.system.local_value)
                local['date_format']['patterns'][style] = 'dd/MM/y'
                self.assertEqual(self.rows(local=local)['locale']['state'], 'fail')

    def test_missing_or_malformed_native_date_evidence_stays_unknown(self):
        for evidence in ({}, {'state':'unknown'}, {'state':'available','reference_patterns':[]}):
            with self.subTest(evidence=evidence):
                local = dict(self.system.local_value, date_format=evidence)
                self.assertEqual(self.rows(local=local)['locale']['state'], 'unknown')

    def test_native_snapshot_from_a_different_locale_is_not_promoted(self):
        self.system.local_value['date_format']['configured_locale'] = 'en_US'
        self.assertEqual(self.rows()['locale']['state'], 'unknown')

    def test_japan_ip_cannot_accept_a_valid_new_york_timezone(self):
        online = copy.deepcopy(self.system.online_value)
        online['geo']['timezone'] = 'America/New_York'
        self.assertEqual(self.rows(online=online)['timezone']['state'], 'unknown')
        self.assertIsNone(reference(online['trace'], online['geo'])['timezone'])

    def test_us_timezone_comes_from_measured_city_without_new_york_fallback(self):
        online = copy.deepcopy(self.system.online_value)
        online['trace']['loc'] = 'US'
        online['geo'].update(country='US',timezone='America/Los_Angeles')
        derived = reference(online['trace'], online['geo'])
        self.assertEqual(derived['timezone'], 'America/Los_Angeles')
        self.assertEqual(derived['locale'], 'en_US')

    def test_measured_timezone_replaces_manual_target_but_still_checks_system(self):
        online = copy.deepcopy(self.system.online_value)
        online['trace']['loc'] = 'US'
        online['geo'].update(country='US',timezone='America/Los_Angeles')
        local = dict(self.system.local_value, timezone='America/Los_Angeles')
        config = dict(self.config, country='US',timezone='America/New_York')
        self.assertEqual(self.rows(local=local,online=online,config=config)['timezone']['state'], 'ok')
        # A real system/exit mismatch still blocks, regardless of the old target.
        local['timezone'] = 'Asia/Tokyo'
        self.assertEqual(self.rows(local=local,online=online,config=config)['timezone']['state'], 'fail')

    def test_missing_country_timezone_table_never_accepts_a_guess(self):
        with patch('watch_switcher.region.country_timezones',return_value={}):
            self.assertIsNone(reference(self.system.online_value['trace'],self.system.online_value['geo'])['timezone'])

    def test_unmapped_region_has_no_english_us_fallback(self):
        trace = dict(self.system.online_value['trace'],loc='NL')
        geo = dict(self.system.online_value['geo'],country='NL',timezone='Europe/Amsterdam')
        self.assertIsNone(reference(trace,geo)['locale'])

    def test_existing_explicit_country_exception_remains_separate(self):
        self.system.online_value['geo'].update(country='CN',timezone='Asia/Shanghai')
        self.system.online_value['trace']['loc'] = 'CN'
        self.system.fetch = lambda url,config: (('ip=8.8.8.8\nloc=CN\n',200) if 'cloudflare' in url else
            (json.dumps(self.system.online_value['geo']),200))
        with self.assertRaises(SwitcherError): region_plan(self.paths,self.system,self.config)
        plan = region_plan(self.paths,self.system,self.config,allow_country='CN')
        self.assertEqual(plan['desired_config']['locale'],'zh_CN')

    def test_disagreeing_sources_do_not_validate_saved_region(self):
        online = copy.deepcopy(self.system.online_value)
        online['geo']['ip'] = '1.1.1.1'
        rows = self.rows(online=online)
        self.assertEqual(rows['timezone']['state'], 'unknown')
        self.assertEqual(rows['locale']['state'], 'unknown')

    def test_date_preference_change_during_probe_invalidates_audit(self):
        save_config(self.paths,self.config)
        def changed(config):
            self.system.local_value['date_format']['patterns']['short'] = 'M/d/yy'
            return self.system.online_value
        self.system.online = changed
        result = audit(self.paths,self.system,self.config,online=True,persist=False)
        self.assertFalse(result['ready'])
        self.assertTrue(all(row['state']=='unknown' for row in result['rows'] if row['required']))

    def test_legacy_en_jp_target_gets_a_reviewable_japanese_format_plan(self):
        self.system.local_value['locale'] = 'en_JP'
        plan = make_plan(self.paths,self.system,dict(self.config,locale='en_JP'))
        self.assertEqual(plan['desired_config']['locale'],'ja_JP')
        action = next(a for a in plan['actions'] if a['id']=='locale')
        self.assertEqual((action['before'],action['after']),('en_JP','ja_JP'))
        self.assertFalse(self.system.calls)


class RegionalSetupTests(Fixture):
    def setUp(self):
        super().setUp()
        self.system = SetupSystem()
        self.options = dict(apply_environment=True,enable_policy=True,guard_enabled=False,
                            timezone_watchdog=False,auto_update=False)

    def test_actual_date_verification_failure_restores_locale_and_keeps_english(self):
        self.system.local_value['locale'] = 'en_US'
        self.system.local_value['date_format']['configured_locale'] = 'en_US'
        candidate = detect(self.paths,self.system,online=True)
        plan = preview(self.paths,self.system,candidate['id'],self.options)
        original = self.system.run
        def lose_probe(argv,*args,**kwargs):
            result = original(argv,*args,**kwargs)
            if argv[:3] == ['/usr/bin/defaults','write','-g'] and argv[-1]=='ja_JP':
                self.system.local_value['date_format']['state'] = 'unknown'
            return result
        self.system.run = lose_probe
        with self.assertRaisesRegex(SwitcherError,'已恢复原设置'):
            apply(self.paths,self.system,candidate['id'],self.options,plan['id'])
        self.assertEqual(self.system.local_value['locale'],'en_US')
        self.assertIn('en-JP',self.system.local_value['language'])
        self.assertFalse(self.paths.config.exists())
        self.assertFalse((self.paths.watch/'state/baseline.conf').exists())
        self.assertFalse((self.paths.base/'setup-transaction.json').exists())

    def test_live_detection_uses_measured_format_without_mutating_settings(self):
        self.system.local_value['locale'] = 'en_JP'
        value = observe(self.paths,self.system,online=True)
        row = next(r for r in value['rows'] if r['id']=='locale')
        self.assertEqual(row['state'],'fail')
        self.assertTrue(row['reference'].startswith('ja_JP'))
        self.assertEqual(value['regional_reference']['timezone'],'Asia/Tokyo')
        self.assertFalse(value['grants_launch_permission'])
        self.assertFalse(self.paths.config.exists())

    def test_legacy_update_intent_without_source_does_not_register_task_during_environment_preview(self):
        save_config(self.paths,dict(self.config,auto_update=True))
        self.options['auto_update']=True
        candidate=detect(self.paths,self.system,online=True)
        plan=preview(self.paths,self.system,candidate['id'],self.options)
        self.assertTrue(plan['desired_config']['auto_update'])
        self.assertNotIn('updater',[row['id'] for row in plan['actions']])
        self.assertFalse((self.paths.home/'Library/LaunchAgents/io.local.claudewatch.update.plist').exists())
