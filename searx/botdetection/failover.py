# SPDX-License-Identifier: AGPL-3.0-or-later
"""Process-local failover for the Valkey-backed botdetection.

A public instance must keep answering search requests when the connection to
its Valkey database is briefly interrupted: a failing pre-request check must
not bubble up into a HTTP 500 and the link token of the result page must not
take the rendering down.

At the same time the failover must not silently disable rate limiting and it
must not corrupt the state in the shared database once the connection is back.

This module implements a shared coordinator with the following contract:

- As long as Valkey is healthy every operation is passed through unchanged,
  the additional code path is only a cheap state check.
- The first connection-class failure opens a *bounded* degraded episode
  (:py:data:`FAILOVER_WINDOW` seconds).  While an episode is open, dynamic
  counters continue in process-local :py:class:`LocalSlidingWindow`: normal
  traffic is served, but once the existing thresholds are reached the callers
  still return their existing HTTP 429 responses.
- Reads of the ping / token keys fail closed while Valkey is unavailable:
  a request can not obtain a valid ping and ping/token writes are dropped,
  a ping can never be mistaken as valid (see :py:mod:`.link_token`).
- Health probes are coordinated by all concurrent requests: at most one
  probe runs at a time, on the backoff schedule :py:data:`PROBE_BACKOFF`,
  instead of every request trying to reconnect.
- A successful probe returns to Valkey immediately.  The local counters are
  discarded and are never written back, therefore the shared sliding windows
  in Valkey are neither cleared, overwritten nor double counted.
- When the episode deadline expires the local state is dropped; if Valkey is
  still unavailable a fresh, empty episode starts.  The failover can never
  get stuck in degraded mode and stale state can not accumulate.
- All state is process-local, so a worker restart always starts healthy.

The failover only covers dynamic counting and the link token methods / the
static pass- & block-lists, trusted proxies and the probe HTTP headers have
priority and are evaluated before the failover is ever reached (see
:py:obj:`searx.limiter.filter_request`).  The strict startup requirement
(Valkey must be reachable, public instances exit otherwise) is not touched:
without a database connection the limiter is simply not installed.

"""

from __future__ import annotations

import threading
import time
import typing

import valkey

from searx.valkeylib import (
    drop_counter as _valkey_drop_counter,
    incr_sliding_window as _valkey_incr_sliding_window,
)

from ._helpers import logger
from . import valkeydb

logger = logger.getChild('failover')

FAILOVER_WINDOW = 300
"""Maximum lifetime (sec) of one degraded episode / the local failover window.

When the deadline is reached the local counters are dropped.  If Valkey is
still unavailable a new empty episode starts, otherwise the shared windows of
Valkey take over again.
"""

PROBE_BACKOFF = (1, 2, 5, 10, 20, 30)
"""Delay (sec) between the shared health probes while a degraded episode is
open; the last value is reused until the episode deadline is reached."""

MAX_LOCAL_WINDOWS = 1024
"""Maximum number of process-local sliding windows kept in memory (one window
per counter key)."""

MAX_LOCAL_EVENTS = 1024
"""Maximum number of events stored in one process-local sliding window (all
rate-limit thresholds are far below this value, a saturated window keeps
returning counts above the threshold and therefore keeps blocking)."""

HEALTHY = 'healthy'
DEGRADED = 'degraded'

# Authentication / authorization errors look like connection problems (they
# are subclasses of ConnectionError) but they are permanent configuration /
# permission issues and must never trigger the fail-open window.
_AUTH_ERRORS: tuple[type[BaseException], ...] = (
    valkey.exceptions.AuthenticationError,
    valkey.exceptions.AuthorizationError,
)

# Depending on the valkey-py release TimeoutError is either a subclass of
# ConnectionError or of ValkeyError.
_CONNECTION_ERRORS: tuple[type[BaseException], ...] = (
    valkey.exceptions.ConnectionError,
    valkey.exceptions.TimeoutError,
)


def is_connection_failure(exc: BaseException) -> bool:
    """Returns ``True`` for transient connection-class errors.

    Authentication / authorization errors are configuration problems (and
    subclasses of :py:class:`valkey.exceptions.ConnectionError`); failing open
    for them would silently disable the limiter, so they are not treated as a
    transient outage.
    """
    if isinstance(exc, _AUTH_ERRORS):
        return False
    return isinstance(exc, _CONNECTION_ERRORS)


class LocalSlidingWindow:
    """Process-local replacement for the Valkey ``INCR_SLIDING_WINDOW`` lua
    script.

    Counter names are the (already secret-hashed) Valkey counter names.  Each
    window stores at most :py:obj:`max_events` event timestamps and the store
    holds at most :py:obj:`max_windows` windows (the window which was not used
    for the longest time is evicted), so the memory usage is bounded.

    """

    def __init__(self, max_windows: int = MAX_LOCAL_WINDOWS, max_events: int = MAX_LOCAL_EVENTS):
        self._max_windows = max_windows
        self._max_events = max_events
        self._windows: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def incr(self, name: str, duration: int, now: float | None = None) -> int:
        """Adds one event to the sliding window of ``name`` and returns the
        number of events within ``duration`` seconds."""
        if now is None:
            now = time.monotonic()
        with self._lock:
            cutoff = now - duration
            timestamps = self._windows.get(name)
            if timestamps is not None:
                # drop events outside the sliding window (in place, the list
                # stays the value stored in the window dict)
                timestamps[:] = [event for event in timestamps if event > cutoff]
            if not timestamps:
                # new window or all events expired: (re)create the key, bounded
                # by the maximum number of windows
                self._windows.pop(name, None)
                if len(self._windows) >= self._max_windows:
                    # evict the least recently used window (its newest event is
                    # the oldest one)
                    lru_name = min(self._windows, key=lambda key: self._windows[key][-1])
                    del self._windows[lru_name]
                    logger.warning(
                        "local failover holds more than %s windows, evicted counter %s",
                        self._max_windows,
                        lru_name,
                    )
                timestamps = []
                self._windows[name] = timestamps
            if len(timestamps) < self._max_events:
                timestamps.append(now)
            return len(timestamps)

    def drop(self, name: str) -> None:
        with self._lock:
            self._windows.pop(name, None)

    def clear(self) -> None:
        with self._lock:
            self._windows.clear()

    def count(self, name: str) -> int:
        with self._lock:
            return len(self._windows.get(name, ()))


class FailoverCoordinator:
    """Shares the health state, the health probes and the local counters
    between all concurrent requests of one worker process."""

    def __init__(
        self,
        failover_window: int = FAILOVER_WINDOW,
        probe_backoff: tuple[int, ...] = PROBE_BACKOFF,
        local_window: LocalSlidingWindow | None = None,
        clock: typing.Callable[[], float] = time.monotonic,
    ):
        self._failover_window = failover_window
        self._probe_backoff = probe_backoff
        self._clock = clock
        self._lock = threading.Lock()
        self._local = local_window or LocalSlidingWindow()
        self._state: str = HEALTHY
        self._probe_running = False
        self._episode_deadline = 0.0
        self._next_probe_at = 0.0
        self._backoff_index = 0

    @property
    def is_degraded(self) -> bool:
        """``True`` while requests are served from the local failover window."""
        return self._state == DEGRADED

    def reset(self) -> None:
        """Drops the health state and all local counters (fresh worker / tests)."""
        with self._lock:
            self._state = HEALTHY
            self._probe_running = False
            self._episode_deadline = 0.0
            self._next_probe_at = 0.0
            self._backoff_index = 0
            self._local.clear()

    # -- health state machine --------------------------------------------

    def _enter_degraded(self, now: float, exc: BaseException) -> None:
        """Opens a new degraded episode on the first connection failure.  A
        failure within an already open episode does not extend the deadline,
        so a long outage can not turn the local window into a permanent one."""
        with self._lock:
            if self._state == DEGRADED:
                return
            msg = "lost connection to Valkey (%s): local failover window active for at most %s seconds"
            logger.warning(msg, exc, self._failover_window)
            self._state = DEGRADED
            self._probe_running = False
            self._backoff_index = 0
            self._episode_deadline = now + self._failover_window
            self._next_probe_at = now + self._probe_backoff[0]

    def _switch_healthy(self) -> None:
        with self._lock:
            if self._state == DEGRADED:
                logger.info("connection to Valkey restored, shared counters take over again")
            self._state = HEALTHY
            self._probe_running = False
            self._episode_deadline = 0.0
            self._next_probe_at = 0.0
            self._backoff_index = 0
            # discard the local counters: they are never written back to
            # Valkey, so shared windows are not cleared / overwritten / double
            # counted
            self._local.clear()

    def _probe_failed(self, now: float, episode_expired: bool) -> None:
        with self._lock:
            self._probe_running = False
            if episode_expired:
                # the bounded local window is over: drop stale local state and
                # open a fresh, empty episode
                logger.warning("local failover window expired, dropping local counters and reopening window")
                self._local.clear()
                self._backoff_index = 0
                self._episode_deadline = now + self._failover_window
                delay = self._probe_backoff[0]
            else:
                self._backoff_index += 1
                delay = self._probe_backoff[min(self._backoff_index, len(self._probe_backoff) - 1)]
            self._next_probe_at = now + delay

    def _ping_valkey(self) -> bool:
        try:
            valkeydb.get_valkey_client().ping()
        except ValueError:
            # no client at all (limiter got deactivated) - there is nothing to
            # probe, stay in the current state
            return False
        except valkey.exceptions.ValkeyError as exc:
            if not is_connection_failure(exc):
                # an unexpected error must not be swallowed as an outage
                raise
            logger.debug("health probe to Valkey failed: %s", exc)
            return False
        return True

    def _request_state(self, now: float) -> str:
        """Returns the state for the calling request.  When a probe is due the
        calling request performs the single shared probe (all other concurrent
        requests keep using the local window), so no reconnect storm can
        happen."""
        run_probe = False
        episode_expired = False
        with self._lock:
            if self._state == HEALTHY:
                return HEALTHY
            if not self._probe_running and (now >= self._next_probe_at or now >= self._episode_deadline):
                self._probe_running = True
                run_probe = True
                episode_expired = now >= self._episode_deadline
        if run_probe:
            try:
                healthy = self._ping_valkey()
            except BaseException:
                # never leave the shared probe locked, otherwise the failover
                # could never recover
                with self._lock:
                    self._probe_running = False
                raise
            if healthy:
                self._switch_healthy()
                return HEALTHY
            self._probe_failed(now, episode_expired)
            return DEGRADED
        return DEGRADED

    # -- operations used by the botdetection methods ----------------------

    def incr_sliding_window(self, name: str, duration: int) -> int:
        now = self._clock()
        if self._request_state(now) == HEALTHY:
            client = valkeydb.get_valkey_client()
            try:
                return _valkey_incr_sliding_window(client, name, duration)
            except valkey.exceptions.ValkeyError as exc:
                if not is_connection_failure(exc):
                    raise
                self._enter_degraded(now, exc)
        return self._local.incr(name, duration, now)

    def drop_counter(self, name: str) -> None:
        now = self._clock()
        if self._request_state(now) == HEALTHY:
            client = valkeydb.get_valkey_client()
            try:
                _valkey_drop_counter(client, name)
                return
            except valkey.exceptions.ValkeyError as exc:
                if not is_connection_failure(exc):
                    raise
                self._enter_degraded(now, exc)
        # only the local counter is dropped, the shared counter in Valkey is
        # left untouched (it keeps its TTL)
        self._local.drop(name)

    def get(self, name: str) -> bytes | None:
        """Returns the raw value or ``None``.  ``None`` is also returned while
        Valkey is unavailable; callers must evaluate this conservatively (a
        missing ping is a suspicious request)."""
        now = self._clock()
        if self._request_state(now) == HEALTHY:
            client = valkeydb.get_valkey_client()
            try:
                return client.get(name)
            except valkey.exceptions.ValkeyError as exc:
                if not is_connection_failure(exc):
                    raise
                self._enter_degraded(now, exc)
        return None

    def set(self, name: str, value, ex: int | None = None) -> bool:
        """Returns ``True`` when the value was written to Valkey.  During an
        outage the write is dropped (returns ``False``), the local window
        never substitutes ping or token writes."""
        now = self._clock()
        if self._request_state(now) == HEALTHY:
            client = valkeydb.get_valkey_client()
            try:
                return bool(client.set(name, value, ex=ex))
            except valkey.exceptions.ValkeyError as exc:
                if not is_connection_failure(exc):
                    raise
                self._enter_degraded(now, exc)
        return False


coordinator = FailoverCoordinator()
"""Process-wide coordinator shared by all botdetection methods of a worker."""


def incr_sliding_window(name: str, duration: int) -> int:
    return coordinator.incr_sliding_window(name, duration)


def drop_counter(name: str) -> None:
    coordinator.drop_counter(name)


def get(name: str) -> bytes | None:
    return coordinator.get(name)


def set(name: str, value, ex: int | None = None) -> bool:  # pylint: disable=redefined-builtin
    return coordinator.set(name, value, ex=ex)
