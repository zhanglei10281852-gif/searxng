# SPDX-License-Identifier: AGPL-3.0-or-later
# pylint: disable=missing-module-docstring,disable=missing-class-docstring,invalid-name

import itertools
import pathlib
import threading
import time
from ipaddress import ip_network

import flask
import valkey

from searx import limiter
from searx import valkeylib
from searx.valkeylib import secret_hash
from searx.botdetection import config as bd_config
from searx.botdetection import failover, ip_limit, link_token, valkeydb
from searx.botdetection.failover import FailoverCoordinator, LocalSlidingWindow
from searx.limiter import LIMITER_CFG_SCHEMA

from tests import SearxTestCase

BROWSER_UA = 'Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0'


class FakeScript:
    """Mimics the relevant behavior of a registered Valkey lua script (only the
    sliding window script INCR_SLIDING_WINDOW is used here)."""

    def __init__(self, db: "FakeValkey", source: str):
        self.db = db
        self.sliding_window = 'ZREMRANGEBYSCORE' in source

    def __call__(self, keys=(), args=()):
        self.db.fail_if_down()
        name = keys[0]
        if self.sliding_window:
            duration = float(args[0])
            now = time.time()
            with self.db.lock:
                zset = self.db.zsets.setdefault(name, [])
                zset[:] = [member for member in zset if member[0] > now - duration]
                member = (now, next(self.db.serial))
                zset.append(member)
                return len(zset)
        raise AssertionError('unexpected lua script call')


class FakeValkey:
    """Minimal stand-in for the Valkey client; ``down`` simulates an outage."""

    def __init__(self):
        self.down = False
        self.ping_count = 0
        self.active_pings = 0
        self.max_active_pings = 0
        self.delete_count = 0
        self.store: dict[str, bytes] = {}
        self.zsets: dict[str, list] = {}
        self.serial = itertools.count()
        self.lock = threading.Lock()
        self.ping_delay = 0.0
        self.error = valkey.exceptions.ConnectionError

    def fail_if_down(self):
        if self.down:
            raise self.error('simulated valkey outage')

    def ping(self):
        with self.lock:
            self.ping_count += 1
            self.active_pings += 1
            self.max_active_pings = max(self.max_active_pings, self.active_pings)
        if self.ping_delay:
            time.sleep(self.ping_delay)
        try:
            self.fail_if_down()
        finally:
            with self.lock:
                self.active_pings -= 1

    def get(self, key):
        self.fail_if_down()
        return self.store.get(key)

    def set(self, key, value, ex=None):  # pylint: disable=unused-argument
        self.fail_if_down()
        if isinstance(value, str):
            # the real valkey client encodes str values and returns bytes
            value = value.encode('UTF-8')
        self.store[key] = value
        return True

    def delete(self, *keys):
        self.fail_if_down()
        removed = 0
        for key in keys:
            removed += 1 if self.store.pop(key, None) is not None else 0
            removed += 1 if self.zsets.pop(key, None) is not None else 0
        self.delete_count += removed
        return removed

    def register_script(self, source):
        return FakeScript(self, source)


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


def get_cfg(upd=None):
    cfg = bd_config.Config.from_toml(LIMITER_CFG_SCHEMA, pathlib.Path('/nonexistent/limiter.toml'), {})
    if upd:
        cfg.update(upd)
    return cfg


class FailoverCoordinatorTestCase(SearxTestCase):

    def setUp(self):
        super().setUp()
        self.db = FakeValkey()
        self.clock = Clock()
        self.coord = FailoverCoordinator(failover_window=300, probe_backoff=(10, 20, 30), clock=self.clock)
        self._old_client = valkeydb.CLIENT
        valkeylib.LUA_SCRIPT_STORAGE.clear()
        valkeydb.set_valkey_client(self.db)
        bd_config.set_global_cfg(get_cfg())
        self.addCleanup(self._cleanup)

    def _cleanup(self):
        valkeydb.CLIENT = self._old_client
        valkeylib.LUA_SCRIPT_STORAGE.clear()

    def test_healthy_requests_go_to_valkey(self):
        counts = [self.coord.incr_sliding_window('window', 20) for _ in range(3)]
        self.assertEqual(counts, [1, 2, 3])
        self.assertFalse(self.coord.is_degraded)
        self.assertEqual(self.db.ping_count, 0)

    def test_outage_switches_to_local_window(self):
        self.assertEqual(self.coord.incr_sliding_window('window', 20), 1)
        self.assertEqual(self.coord.incr_sliding_window('window', 20), 2)

        self.db.down = True
        # the failing request is already counted locally instead of erroring
        self.assertEqual(self.coord.incr_sliding_window('window', 20), 1)
        self.assertEqual(self.coord.incr_sliding_window('window', 20), 2)
        self.assertTrue(self.coord.is_degraded)
        # the shared window in Valkey must not be touched / cleared
        self.assertEqual(len(self.db.zsets['SearXNG_counter_' + secret_hash('window')]), 2)

    def test_local_window_still_enforces_threshold(self):
        self.db.down = True
        counts = [self.coord.incr_sliding_window('burst', 20) for _ in range(16)]
        self.assertEqual(counts, list(range(1, 17)))
        self.assertGreater(counts[-1], ip_limit.BURST_MAX)

    def test_backoff_probe_schedule_single_probe(self):
        self.db.down = True
        self.coord.incr_sliding_window('w', 20)
        # no probe before the first backoff delay
        self.clock.advance(9)
        for _ in range(5):
            self.coord.incr_sliding_window('w', 20)
        self.assertEqual(self.db.ping_count, 0)

        # exactly one (shared) probe when the delay is reached
        self.clock.advance(1)
        self.coord.incr_sliding_window('w', 20)
        self.assertEqual(self.db.ping_count, 1)
        # probe failed: next probe is not due yet
        self.clock.advance(1)
        self.coord.incr_sliding_window('w', 20)
        self.assertEqual(self.db.ping_count, 1)
        self.clock.advance(19)
        self.coord.incr_sliding_window('w', 20)
        self.assertEqual(self.db.ping_count, 2)
        self.assertTrue(self.coord.is_degraded)

    def test_recovery_returns_to_shared_window_without_merge(self):
        # 2 requests counted in the shared window before the outage
        self.coord.incr_sliding_window('w', 20)
        self.coord.incr_sliding_window('w', 20)
        self.db.down = True
        # 5 requests counted locally during the outage
        for _ in range(5):
            self.coord.incr_sliding_window('w', 20)
        self.assertEqual(self.coord._local.count('w'), 5)  # pylint: disable=protected-access

        # Valkey comes back: first probe at t+10 restores the healthy state
        self.db.down = False
        self.clock.advance(10)
        self.coord.incr_sliding_window('w', 20)
        self.assertFalse(self.coord.is_degraded)
        # local counters are discarded, not written back: the shared window
        # continues at 3 (the outage requests are not merged / duplicated)
        self.assertEqual(self.coord.incr_sliding_window('w', 20), 4)
        self.assertEqual(self.coord._local.count('w'), 0)  # pylint: disable=protected-access

    def test_episode_expiry_drops_stale_local_state(self):
        coord = FailoverCoordinator(failover_window=300, probe_backoff=(10000,), clock=self.clock)
        self.db.down = True
        for _ in range(4):
            coord.incr_sliding_window('w', 20)
        self.assertTrue(coord.is_degraded)
        # regular probe is not due for a long time, but the episode expires
        self.clock.advance(300)
        count = coord.incr_sliding_window('w', 20)
        # a fresh empty episode started: stale counters are gone
        self.assertEqual(count, 1)
        self.assertEqual(self.db.ping_count, 1)
        self.assertTrue(coord.is_degraded)

    def test_episode_deadline_is_not_extended_by_repeated_failures(self):
        self.db.down = True
        self.coord.incr_sliding_window('w', 20)
        deadline = self.coord._episode_deadline  # pylint: disable=protected-access
        self.clock.advance(250)
        # another failure within the open episode must not renew the window
        self.coord._enter_degraded(  # pylint: disable=protected-access
            self.clock(), valkey.exceptions.ConnectionError('again')
        )
        self.assertEqual(self.coord._episode_deadline, deadline)  # pylint: disable=protected-access

    def test_non_transient_errors_propagate(self):
        self.db.error = valkey.exceptions.ResponseError
        self.db.down = True
        with self.assertRaises(valkey.exceptions.ResponseError):
            self.coord.get('key')
        with self.assertRaises(valkey.exceptions.ResponseError):
            self.coord.incr_sliding_window('w', 20)
        self.assertFalse(self.coord.is_degraded)

    def test_authentication_error_does_not_fail_open(self):
        self.db.error = valkey.exceptions.AuthenticationError
        self.db.down = True
        with self.assertRaises(valkey.exceptions.AuthenticationError):
            self.coord.incr_sliding_window('w', 20)
        self.assertFalse(self.coord.is_degraded)

    def test_unexpected_probe_error_does_not_lock_future_probes(self):
        self.db.down = True
        self.coord.incr_sliding_window('w', 20)  # opens the degraded episode
        self.clock.advance(10)
        self.db.error = valkey.exceptions.ResponseError
        with self.assertRaises(valkey.exceptions.ResponseError):
            self.coord.incr_sliding_window('w', 20)
        # the probe slot is released, later probes still run / recover
        self.db.error = valkey.exceptions.ConnectionError
        self.db.down = False
        self.clock.advance(10)
        self.assertEqual(self.coord.incr_sliding_window('w', 20), 1)
        self.assertFalse(self.coord.is_degraded)

    def test_drop_counter_healthy_and_degraded(self):
        key = 'SearXNG_counter_' + secret_hash('w')
        self.coord.incr_sliding_window('w', 20)
        self.assertIn(key, self.db.zsets)
        self.coord.drop_counter('w')
        self.assertNotIn(key, self.db.zsets)

        self.db.down = True
        self.coord.incr_sliding_window('w', 20)
        deletes_before = self.db.delete_count
        self.coord.drop_counter('w')  # must not raise
        # the shared counter is left untouched during the outage
        self.assertEqual(self.db.delete_count, deletes_before)
        self.assertEqual(self.coord._local.count('w'), 0)  # pylint: disable=protected-access

    def test_get_and_set_during_outage(self):
        self.assertIsNone(self.coord.get('ping-key'))
        self.assertTrue(self.coord.set('ping-key', b'1', ex=10))
        self.assertEqual(self.coord.get('ping-key'), b'1')

        self.db.down = True
        self.assertIsNone(self.coord.get('ping-key'))
        self.assertFalse(self.coord.set('ping-key', b'1', ex=10))
        self.db.down = False
        # probe is due after the backoff, then Valkey takes over again
        self.clock.advance(10)
        self.assertEqual(self.coord.get('ping-key'), b'1')

    def test_concurrent_probes_are_single_flight(self):
        db = FakeValkey()
        db.ping_delay = 0.02
        db.down = True
        coord = FailoverCoordinator(failover_window=10, probe_backoff=(0.02, 0.02, 0.02))
        valkeydb.set_valkey_client(db)
        errors = []

        def worker():
            for _ in range(30):
                try:
                    coord.incr_sliding_window('shared', 20)
                except Exception as exc:  # pylint: disable=broad-except
                    errors.append(exc)
                time.sleep(0.01)

        threads = [threading.Thread(target=worker) for _ in range(20)]
        for thread in threads:
            thread.start()
        time.sleep(0.2)
        db.down = False
        for thread in threads:
            thread.join()

        self.assertEqual(errors, [])
        # never more than one reconnect attempt at the same time
        self.assertEqual(db.max_active_pings, 1)
        self.assertFalse(coord.is_degraded)
        valkeydb.set_valkey_client(self.db)


class LocalSlidingWindowTestCase(SearxTestCase):

    def test_sliding_window(self):
        window = LocalSlidingWindow()
        clock = Clock()
        self.assertEqual(window.incr('w', 10, clock()), 1)
        self.assertEqual(window.incr('w', 10, clock()), 2)
        self.assertEqual(window.incr('w', 10, clock()), 3)
        clock.advance(11)
        self.assertEqual(window.incr('w', 10, clock()), 1)

    def test_events_are_capped(self):
        window = LocalSlidingWindow(max_events=4)
        counts = [window.incr('w', 10) for _ in range(8)]
        # saturated window keeps returning counts above every rate threshold
        self.assertEqual(counts[-4:], [4, 4, 4, 4])

    def test_number_of_windows_is_capped(self):
        window = LocalSlidingWindow(max_windows=2)
        window.incr('a', 10, now=1)
        window.incr('b', 10, now=2)
        window.incr('c', 10, now=3)  # evicts the least recently used 'a'
        self.assertEqual(window.count('a'), 0)
        self.assertEqual(window.count('b'), 1)
        self.assertEqual(window.count('c'), 1)

    def test_drop_and_clear(self):
        window = LocalSlidingWindow()
        window.incr('a', 10)
        window.incr('b', 10)
        window.drop('a')
        self.assertEqual(window.count('a'), 0)
        window.clear()
        self.assertEqual(window.count('b'), 0)


class LinkTokenTestCase(SearxTestCase):

    def setUp(self):
        super().setUp()
        self.app = flask.Flask(__name__)
        self.db = FakeValkey()
        self.clock = Clock()
        self._old_client = valkeydb.CLIENT
        self._old_coord = failover.coordinator
        valkeylib.LUA_SCRIPT_STORAGE.clear()
        valkeydb.set_valkey_client(self.db)
        failover.coordinator = FailoverCoordinator(failover_window=300, probe_backoff=(10, 20, 30), clock=self.clock)
        bd_config.set_global_cfg(get_cfg())
        self.addCleanup(self._cleanup)

    def _cleanup(self):
        valkeydb.CLIENT = self._old_client
        failover.coordinator = self._old_coord
        valkeylib.LUA_SCRIPT_STORAGE.clear()

    def _ctx(self, path='/search', remote='192.0.2.10'):
        return self.app.test_request_context(
            path,
            headers={'User-Agent': BROWSER_UA, 'Accept-Language': 'en'},
            environ_overrides={'REMOTE_ADDR': remote},
        )

    def test_token_lifecycle(self):
        token = link_token.get_token()
        self.assertNotEqual(token, '12345678')
        self.assertEqual(link_token.get_token(), token)  # cached in DB
        self.assertTrue(link_token.token_is_valid(token))
        self.assertFalse(link_token.token_is_valid('12345678'))

    def test_page_token_keeps_rendering_during_outage(self):
        self.db.down = True
        self.assertEqual(link_token.get_token(), '12345678')
        # still a valid string usable in the rendered template
        self.assertIn('12345678', f'/client{link_token.get_token()}.css')

    def test_ping_is_never_valid_during_outage(self):
        net = ip_network('192.0.2.10/32')
        with self._ctx():
            self.db.down = True

            # no readable token -> invalid, no ping can be stored
            self.assertFalse(link_token.token_is_valid('12345678'))
            link_token.ping(flask.request, '12345678')
            self.assertTrue(link_token.is_suspicious(net, flask.request, True))

            # Valkey is back after the backoff probe: the old ping is absent
            self.db.down = False
            self.clock.advance(10)
            self.assertTrue(link_token.is_suspicious(net, flask.request, True))

            # a fresh ping with the real token works and removes suspicion
            token = link_token.get_token()
            link_token.ping(flask.request, token)
            self.assertFalse(link_token.is_suspicious(net, flask.request, True))

    def test_ping_without_client_is_a_noop(self):
        valkeydb.CLIENT = None
        with self._ctx('/client12345678.css'):
            link_token.ping(flask.request, '12345678')  # must not raise
        self.assertEqual(link_token.get_token(), '12345678')


class IPLimitTestCase(SearxTestCase):

    def setUp(self):
        super().setUp()
        self.app = flask.Flask(__name__)
        self.db = FakeValkey()
        self.clock = Clock()
        self._old_client = valkeydb.CLIENT
        self._old_coord = failover.coordinator
        valkeylib.LUA_SCRIPT_STORAGE.clear()
        valkeydb.set_valkey_client(self.db)
        failover.coordinator = FailoverCoordinator(failover_window=300, probe_backoff=(10, 20, 30), clock=self.clock)
        self.cfg = get_cfg()
        bd_config.set_global_cfg(self.cfg)
        self.addCleanup(self._cleanup)

    def _cleanup(self):
        valkeydb.CLIENT = self._old_client
        failover.coordinator = self._old_coord
        valkeylib.LUA_SCRIPT_STORAGE.clear()

    def _call(self, fmt='html'):
        path = '/search' if fmt == 'html' else f'/search?format={fmt}'
        with self.app.test_request_context(
            path,
            headers={'User-Agent': BROWSER_UA, 'Accept-Language': 'en'},
            environ_overrides={'REMOTE_ADDR': '192.0.2.20'},
        ):
            net = ip_network('192.0.2.20/32')
            return ip_limit.filter_request(net, flask.request, self.cfg)

    def test_burst_limit_healthy(self):
        responses = [self._call() for _ in range(16)]
        self.assertIsNone(responses[-2])
        self.assertEqual(responses[-1].status_code, 429)

    def test_burst_limit_local_window_during_outage(self):
        self.db.down = True
        responses = [self._call() for _ in range(16)]
        self.assertIsNone(responses[-2])
        self.assertEqual(responses[-1].status_code, 429)

    def test_api_limit_during_outage(self):
        self.db.down = True
        responses = [self._call(fmt='json') for _ in range(6)]
        self.assertEqual([r.status_code if r else None for r in responses[:4]], [None] * 4)
        self.assertEqual(responses[4].status_code, 429)


class StaticRulesPriorityTestCase(SearxTestCase):

    def setUp(self):
        super().setUp()
        self.app = flask.Flask(__name__)
        self.db = FakeValkey()
        self.db.down = True  # dynamic counting is impossible
        self._old_client = valkeydb.CLIENT
        valkeydb.set_valkey_client(self.db)
        self._old_cfg = limiter.CFG
        self.addCleanup(self._cleanup)

    def _cleanup(self):
        valkeydb.CLIENT = self._old_client
        limiter.CFG = self._old_cfg

    def _filter(self, remote):
        cfg = get_cfg(
            {
                'botdetection': {
                    'ip_lists': {
                        'pass_searxng_org': False,
                        'pass_ip': ['192.0.2.30'],
                        'block_ip': ['192.0.2.40'],
                    }
                }
            }
        )
        limiter.CFG = cfg
        with self.app.test_request_context(
            '/search',
            headers={'User-Agent': BROWSER_UA, 'Accept-Language': 'en'},
            environ_overrides={'REMOTE_ADDR': remote},
        ):
            return limiter.filter_request(flask.request)

    def test_blocklist_blocks_even_when_valkey_down(self):
        response = self._filter('192.0.2.40')
        self.assertEqual(response.status_code, 429)

    def test_passlist_passes_even_when_valkey_down(self):
        self.assertIsNone(self._filter('192.0.2.30'))

    def test_link_local_passes(self):
        self.assertIsNone(self._filter('169.254.0.1'))
