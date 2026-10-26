"""Private cross-process-style metadata cache contracts, without network I/O."""
import concurrent.futures
import importlib.util
import pathlib
import tempfile
import threading
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('coffee_cache', pathlib.Path(__file__).parents[1] / 'Resources/netcoffee_client.py')
c = importlib.util.module_from_spec(spec); spec.loader.exec_module(c)


def receipt(ip='1.1.1.1', *, status='complete', http=None, at=100):
    return {'kind': 'lookup', 'query': ip, 'status': status, 'httpStatus': http,
            'queriedAt': at, 'finishedAt': at + 1, 'data': {'ip': ip} if status == 'complete' else None,
            'raw': '{}' if status == 'complete' else '', 'error': None if status == 'complete' else 'failed'}


class QueryCacheTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='cw-cache-')
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)

    def test_fresh_hit_reuses_original_time_without_calling_loader(self):
        calls = []
        def loader(): calls.append(1); return receipt(at=100)
        first = c.cached_query('lookup:1.1.1.1', loader, cache_dir=self.root, now=101)
        second = c.cached_query('lookup:1.1.1.1', lambda: (_ for _ in ()).throw(AssertionError()), cache_dir=self.root, now=200)
        self.assertEqual((len(calls), first['cache_state'], second['cache_state'], second['queriedAt']), (1, 'miss', 'hit', 100))

    def test_failed_refresh_keeps_last_good_only_as_history_and_backs_off(self):
        c.cached_query('lookup:1.1.1.1', lambda: receipt(at=1), ttl=1, cache_dir=self.root, now=2)
        failed = c.cached_query('lookup:1.1.1.1', lambda: receipt(status='error', at=10), ttl=1, cache_dir=self.root, now=10)
        self.assertEqual(failed['status'], 'error')
        self.assertEqual(failed['last_good']['status'], 'complete')
        backed = c.cached_query('lookup:1.1.1.1', lambda: (_ for _ in ()).throw(AssertionError()), ttl=1, cache_dir=self.root, now=11)
        self.assertEqual((backed['status'], backed['cache_state'], backed['last_good']['queriedAt']), ('error', 'backoff', 1))
        self.assertEqual((backed['raw'], backed['data']), ('', None))

    def test_429_backoff_is_at_least_fifteen_minutes_and_honors_longer_retry_after(self):
        value = receipt(status='error', http=429, at=10); value['retry_after'] = 1800
        first = c.cached_query('risk:1.1.1.1', lambda: value, cache_dir=self.root, now=10)
        second = c.cached_query('risk:1.1.1.1', lambda: (_ for _ in ()).throw(AssertionError()), cache_dir=self.root, now=100)
        self.assertEqual(first['cache_state'], 'miss')
        self.assertGreaterEqual(second['retry_after'], 1710)

    def test_different_ip_keys_do_not_hold_each_others_network_lock(self):
        entered, release, other_done = threading.Event(), threading.Event(), threading.Event()
        def slow():
            entered.set(); release.wait(2); return receipt('1.1.1.1', at=1)
        def fast():
            other_done.set(); return receipt('8.8.8.8', at=1)
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            one = pool.submit(c.cached_query, 'lookup:1.1.1.1', slow, c.CACHE_TTL, self.root, 1)
            self.assertTrue(entered.wait(1))
            two = pool.submit(c.cached_query, 'lookup:8.8.8.8', fast, c.CACHE_TTL, self.root, 1)
            self.assertTrue(other_done.wait(1))
            release.set()
            self.assertEqual((one.result()['status'], two.result()['status']), ('complete', 'complete'))

    def test_same_key_waiter_rechecks_time_after_singleflight_lock(self):
        entered, release = threading.Event(), threading.Event()
        calls = []
        def first():
            calls.append('first'); entered.set(); release.wait(2)
            at = __import__('time').time()
            return {'kind': 'lookup', 'query': '1.1.1.1', 'status': 'complete', 'httpStatus': 200,
                    'queriedAt': at, 'finishedAt': at, 'raw': '{}', 'data': {'ip': '1.1.1.1'}, 'error': None}
        def duplicate():
            calls.append('duplicate'); return receipt('1.1.1.1', at=__import__('time').time())
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            one = pool.submit(c.cached_query, 'lookup:1.1.1.1', first, c.CACHE_TTL, self.root)
            self.assertTrue(entered.wait(1))
            two = pool.submit(c.cached_query, 'lookup:1.1.1.1', duplicate, c.CACHE_TTL, self.root)
            release.set()
            self.assertEqual(one.result()['cache_state'], 'miss')
            self.assertEqual(two.result()['cache_state'], 'hit')
        self.assertEqual(calls, ['first'])

    def test_ipinfo_and_ripe_asn_namespaces_are_isolated_and_validated(self):
        self.assertTrue(c._valid_cache_key('ipinfo:1.1.1.1'))
        self.assertTrue(c._valid_cache_key('ripe-asn:4294967295'))
        self.assertFalse(c._valid_cache_key('ripe-asn:4294967296'))
        self.assertFalse(c._valid_cache_key('ipinfo:127.0.0.1'))
        self.assertEqual(c.cached_query('ripe-asn:2516', lambda: receipt(status='error'), cache_dir=self.root, now=1)['cache_state'], 'miss')

    def test_cooling_429_entry_survives_capacity_pruning(self):
        limited = receipt(status='error', http=429, at=1); limited['retry_after'] = 900
        c.cached_query('ipinfo:1.1.1.1', lambda: limited, cache_dir=self.root, now=1)
        for value in range(1, 40):
            ip = '9.0.0.' + str(value)
            c.cached_query('lookup:' + ip, lambda ip=ip: receipt(ip, at=2), cache_dir=self.root, now=2)
        result = c.cached_query('ipinfo:1.1.1.1', lambda: (_ for _ in ()).throw(AssertionError('429 entry was evicted')),
                                cache_dir=self.root, now=100)
        self.assertEqual((result['cache_state'], result['httpStatus']), ('backoff', 429))

    def test_dns_and_trace_are_never_cached(self):
        calls = []
        with patch.object(c, '_request_uncached', side_effect=lambda kind, query: calls.append((kind, query)) or receipt('1.1.1.1')):
            c.request('trace', '')
            c.request('trace', '')
        self.assertEqual(calls, [('trace', ''), ('trace', '')])


if __name__ == '__main__': unittest.main()
