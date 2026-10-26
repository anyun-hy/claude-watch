"""Display-only historical evidence cannot replace current launch validation."""
import copy
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'Resources'))
from test_switcher import Fixture
from test_onboarding import SetupSystem
from watch_switcher import onboarding
from watch_switcher.audit import evaluate
from watch_switcher.common import read_json


class EnvironmentResilienceTests(Fixture):
    def setUp(self):
        super().setUp()
        self.system = SetupSystem()
        self.system.online_value['asn'] = dict(number=2516, organization='KDDI', registered_country='JP', result_time='2026-10-21')

    def observe(self):
        return {r['id']: r for r in onboarding.observe(self.paths, self.system, online=True, persist=True)['rows']}

    def lose_geo(self):
        self.system.online_value['geo'] = {}
        self.system.online_value.pop('asn', None)
        self.system.online_value['query_errors'] = {'geo': {'code': 'http_429', 'message': 'IPinfo HTTP 429，请求受到限流'}}

    def test_first_query_failure_keeps_independent_local_and_stun_observations(self):
        self.lose_geo()
        rows = self.observe()
        self.assertEqual(rows['timezone']['state'], 'info')
        self.assertEqual(rows['timezone']['current'], 'Asia/Tokyo')
        self.assertEqual(rows['locale']['state'], 'info')
        for key in ['proxy', 'tun', 'ip_history', 'ipv6', 'stun', 'language']:
            self.assertEqual(rows[key]['state'], 'ok', key)
        self.assertEqual(rows['egress']['state'], 'info')
        self.assertIn('429', rows['egress']['query_error'])
        self.assertIn('429', rows['asn']['query_error'])
        self.assertNotIn('不一致', rows['egress']['detail'])

    def test_previous_valid_values_and_times_survive_repeated_query_failures(self):
        good = self.observe()
        self.lose_geo()
        for _ in range(2):
            rows = self.observe()
            for key in ['egress', 'timezone', 'locale', 'asn']:
                self.assertEqual(rows[key]['state'], 'cached', key)
                self.assertEqual(rows[key]['sampled_at'], good[key]['sampled_at'])
                self.assertEqual(rows[key]['current'], good[key]['current'])
                self.assertIn('429', rows[key]['query_error'])
                self.assertIn('不用于启动', rows[key]['detail'])

    def test_real_conflict_is_not_hidden_by_history(self):
        self.observe()
        self.system.online_value['geo']['ip'] = '1.1.1.1'
        rows = self.observe()
        self.assertEqual(rows['egress']['state'], 'fail')
        self.assertIn('不一致', rows['egress']['detail'])
        self.assertNotEqual(rows['timezone']['state'], 'cached')

    def test_changed_network_or_current_ip_does_not_reuse_previous_data(self):
        self.observe()
        self.lose_geo()
        self.system.local_value['context'] = 'different-proxy'
        rows = self.observe()
        self.assertNotEqual(rows['asn']['state'], 'cached')
        self.assertEqual(rows['timezone']['state'], 'info')

    def test_local_timezone_change_is_not_overwritten_by_historical_value(self):
        self.observe()
        self.lose_geo()
        self.system.local_value['timezone'] = 'America/New_York'
        rows = self.observe()
        self.assertEqual(rows['timezone']['current'], 'America/New_York')
        self.assertNotEqual(rows['timezone']['state'], 'cached')
        self.assertIn('本机值已变化', rows['timezone']['detail'])

    def test_history_does_not_relax_controlled_launch(self):
        self.observe()
        self.lose_geo()
        self.observe()
        result = evaluate(self.config, self.system.local_value, self.system.online_value)
        self.assertFalse(result['ready'])
        self.assertIn('egress', result['blocked'])
        self.assertIn('timezone', result['blocked'])
        self.assertIn('429', result['message'])
        self.assertEqual(read_json(self.paths.base / 'environment-valid-samples.json')['schema'], 1)
