# SPDX-License-Identifier: AGPL-3.0-or-later
"""With *command engines* administrators can run engines to integrate arbitrary
shell commands.

.. attention::

   When creating and enabling a ``command`` engine on a public instance, you
   must be careful to avoid leaking private data.

The easiest solution is to limit the access by setting ``tokens`` as described
in section :ref:`private engines`.  The engine base is flexible.  Only your
imagination can limit the power of this engine (and maybe security concerns).

Configuration
=============

The following options are available:

``command``:
  A comma separated list of the elements of the command.  A special token
  ``{{QUERY}}`` tells where to put the search terms of the user. Example:

  .. code:: yaml

     ['ls', '-l', '-h', '{{QUERY}}']

``delimiter``:
  A mapping containing a delimiter ``char`` and the *titles* of each element in
  ``keys``.

``parse_regex``:
  A dict containing the regular expressions for each result key.

``query_type``:

  The expected type of user search terms.  Possible values: ``path`` and
  ``enum``.

  ``path``:
    Checks if the user provided path is inside the working directory.  If not,
    the query is not executed.

  ``enum``:
    Is a list of allowed search terms.  If the user submits something which is
    not included in the list, the query returns an error.

``query_enum``:
  A list containing allowed search terms if ``query_type`` is set to ``enum``.

``working_dir``:
  The directory where the command has to be executed.  Default: ``./``.

``result_separator``:
  The character that separates results. Default: ``\\n``.

``timeout``:
  Maximum runtime in seconds.  When the timeout is reached, or the calling
  search does not wait for the engine anymore, late output is discarded and the
  whole command process group is terminated; if it does not exit within the
  grace period, the process group is force killed.  Default: ``4`` seconds.

Example
=======

The example engine below can be used to find files with a specific name in the
configured working directory:

.. code:: yaml

  - name: find
    engine: command
    command: ['find', '.', '-name', '{{QUERY}}']
    query_type: path
    shortcut: fnd
    delimiter:
        chars: ' '
        keys: ['line']

Process lifecycle
=================

Every search runs its command in a dedicated process group and reads
``stdout`` / ``stderr`` through threads that are bound to that search request.
Results are only published when the command exits with a return code of
``0``; late output is never published.  Failures to start the command, a
non-zero return code, invalid UTF-8 output and output that cannot be parsed
raise the engine exceptions which are turned into *unresponsive engine*
markers, log entries and error metrics by the offline processor -- no thread
or subprocess outlives the search request.

Implementations
===============
"""

import typing as t
import atexit
import os
import queue
import re
import signal
import subprocess
import sys
import threading
import weakref
from collections import deque
from os.path import commonprefix, expanduser, isabs, realpath
from shlex import split as shlex_split
from subprocess import DEVNULL, PIPE, Popen
from threading import Thread
from time import monotonic

from searx import logger
from searx.exceptions import SearxEngineException, SearxEngineResponseException
from searx.result_types import EngineResults

engine_type = 'offline'
paging = True
command = []
delimiter = {}
parse_regex = {}
query_type = ''
query_enum = []
environment_variables = {}
working_dir = realpath('.')
result_separator = '\n'
timeout = 4.0

#: how often the deadline / the "outer search gave up" flag is checked
_POLL_INTERVAL = 0.1
#: time given to the command process group to exit after the polite signal
_TERMINATION_GRACE_PERIOD = 0.5
#: time to wait for a force killed process / taskkill to be reaped
_FORCE_KILL_REAP_TIMEOUT = 1.0
#: maximum time to wait for the stdout/stderr reader threads to finish
_PUMP_THREAD_JOIN_TIMEOUT = 1.0
#: number of stderr lines kept for diagnostic logging
_STDERR_TAIL_MAX_LINES = 100

#: queue item signaling that the command closed its stdout
_STDOUT_EOF = object()

#: command requests that currently run a process; on a clean shutdown of the
#: service their process groups are terminated so no command outlives it
_live_requests: weakref.WeakSet['_CommandRequest'] = weakref.WeakSet()


@atexit.register
def _terminate_live_requests() -> None:
    for request in list(_live_requests):
        request._cleanup()  # pylint: disable=protected-access

_command_logger = logger.getChild('command')
_compiled_parse_regex = {}

# The command is started in its own process group so that the polite signal and
# the force kill reach child processes (and grandchildren) as well.
if sys.platform == 'win32':
    _PROCESS_GROUP_POPEN_KWARGS: dict[str, t.Any] = {
        'creationflags': getattr(subprocess, 'CREATE_NEW_PROCESS_GROUP', 0)
    }
else:
    _PROCESS_GROUP_POPEN_KWARGS = {'start_new_session': True}


def setup(engine_settings: dict[str, t.Any]) -> bool | None:
    check_parsing_options(engine_settings)

    if 'command' not in engine_settings:
        raise ValueError('engine command : missing configuration key: command')

    global command, working_dir, delimiter, parse_regex, environment_variables  # pylint: disable=global-statement

    command = engine_settings['command']

    if 'working_dir' in engine_settings:
        working_dir = engine_settings['working_dir']
        if not isabs(engine_settings['working_dir']):
            working_dir = realpath(working_dir)

    if 'parse_regex' in engine_settings:
        parse_regex = engine_settings['parse_regex']
        for result_key, regex in parse_regex.items():
            _compiled_parse_regex[result_key] = re.compile(regex, flags=re.MULTILINE)
    if 'delimiter' in engine_settings:
        delimiter = engine_settings['delimiter']

    if 'environment_variables' in engine_settings:
        environment_variables = engine_settings['environment_variables']


def search(query, params) -> EngineResults:
    # ``ValueError`` raised by ``_get_command_to_run`` (invalid path / enum
    # value) is an invalid input error and is handled by the offline processor
    # without recording an engine error.
    cmd = _get_command_to_run(query)
    if not cmd:
        return EngineResults()

    # One _CommandRequest owns the process (group), the reader threads and the
    # pipes of exactly this search request.
    return _CommandRequest(cmd, params['pageno']).run()


def _get_command_to_run(query):
    params = shlex_split(query)
    __check_query_params(params)

    cmd = []
    for c in command:
        if c == '{{QUERY}}':
            cmd.extend(params)
        else:
            cmd.append(c)

    return cmd


if sys.platform == 'win32':

    def _terminate_process_group(process: Popen[t.Any]) -> None:
        # CTRL_BREAK_EVENT is delivered to every process of the (new) process
        # group; fall back to TerminateProcess if it cannot be delivered.
        try:
            os.kill(process.pid, getattr(signal, 'CTRL_BREAK_EVENT', 1))
        except OSError:
            try:
                process.terminate()
            except OSError:
                pass

    def _kill_process_group(process: Popen[t.Any]) -> None:
        # "/T" kills the whole process tree, "/F" forces the termination.
        try:
            subprocess.run(
                ['taskkill', '/F', '/T', '/PID', str(process.pid)],
                stdin=DEVNULL,
                stdout=DEVNULL,
                stderr=DEVNULL,
                timeout=_FORCE_KILL_REAP_TIMEOUT,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            try:
                process.kill()
            except OSError:
                pass

else:

    def _signal_process_group(process: Popen[t.Any], sig: int) -> None:
        try:
            pgid = os.getpgid(process.pid)
        except ProcessLookupError:
            return
        try:
            os.killpg(pgid, sig)
        except ProcessLookupError:
            pass

    def _terminate_process_group(process: Popen[t.Any]) -> None:
        _signal_process_group(process, signal.SIGTERM)

    def _kill_process_group(process: Popen[t.Any]) -> None:
        try:
            _signal_process_group(process, signal.SIGKILL)
        except OSError:
            try:
                process.kill()
            except OSError:
                pass


def _stop_process_group(process: Popen[t.Any], cmd: list[str]) -> None:
    """Politely terminate the whole command process group and force kill every
    process that does not exit within the grace period; finally reap the direct
    child process.  This function must not raise.

    Descendants other than the direct child are killed with the group and their
    corpses are reaped by PID 1 (or the configured subreaper), as usual for
    terminated process groups."""

    _terminate_process_group(process)
    try:
        process.wait(timeout=_TERMINATION_GRACE_PERIOD)
        return
    except subprocess.TimeoutExpired:
        pass

    _command_logger.warning(
        'command %r (pid %s) did not exit within %.1f seconds, force killing the process group',
        cmd,
        process.pid,
        _TERMINATION_GRACE_PERIOD,
    )
    _kill_process_group(process)
    try:
        process.wait(timeout=_FORCE_KILL_REAP_TIMEOUT)
    except subprocess.TimeoutExpired:
        _command_logger.error('command %r (pid %s) could not be reaped after force killing', cmd, process.pid)


def _pump_stdout(stream: t.BinaryIO, out_queue: 'queue.Queue[t.Any]') -> None:
    # The main thread is the only consumer: lines read here are the only
    # output that can end up in the result page.  Once the stream closes
    # (process group terminated) the reader thread finishes.
    try:
        while True:
            line = stream.readline()
            if not line:
                break
            out_queue.put(line)
    except Exception:  # pylint: disable=broad-except
        # the stream may have been closed by the main thread during cleanup
        pass
    finally:
        out_queue.put(_STDOUT_EOF)
        try:
            stream.close()
        except Exception:  # pylint: disable=broad-except
            pass


def _pump_stderr(stream: t.BinaryIO, tail: 'deque[str]') -> None:
    # stderr is drained continuously so that a verbose command cannot fill the
    # pipe buffer and deadlock; a bounded tail is kept for diagnostic logging.
    try:
        for raw_line in iter(stream.readline, b''):
            tail.append(raw_line.decode('utf-8', errors='replace').rstrip('\r\n'))
    except Exception:  # pylint: disable=broad-except
        pass
    finally:
        try:
            stream.close()
        except Exception:  # pylint: disable=broad-except
            pass


class _CommandRequest:  # pylint: disable=too-few-public-methods
    """The lifecycle of one command search:

    * the command subprocess is started in its own process group,
    * stdout and stderr are drained by request scoped reader threads,
    * only the results of the requested page are collected while the engine
      ``timeout`` has not been reached and the calling search is still waiting
      (``thread._timeout`` flag set by ``Search.search_multiple_requests``),
    * on timeout / cancellation late output is discarded and the complete
      process group is terminated, force killed and reaped,
    * results are only returned when the command exits with return code 0.
    """

    def __init__(self, cmd: list[str], pageno: int):
        self.cmd = cmd
        self.pageno = pageno
        self.results = EngineResults()
        self.start, self.end = _get_results_limits(pageno)
        self.count = 0
        self.leftover = ''
        self.deadline = monotonic() + timeout
        self.process: Popen[t.Any] | None = None
        self._stdout_queue: queue.Queue[t.Any] = queue.Queue()
        self._stderr_tail: deque[str] = deque(maxlen=_STDERR_TAIL_MAX_LINES)
        self._pump_threads: list[Thread] = []
        self._cleanup_lock = threading.Lock()
        self._cleaned_up = False
        _live_requests.add(self)

    def run(self) -> EngineResults:
        try:
            # the lifecycle (including the process group termination) is managed
            # manually in _cleanup(), therefore no context manager is used here
            self.process = Popen(  # pylint: disable=consider-using-with
                self.cmd,
                stdin=DEVNULL,
                stdout=PIPE,
                stderr=PIPE,
                env=environment_variables,
                **_PROCESS_GROUP_POPEN_KWARGS,
            )
        except OSError as exc:
            raise SearxEngineException(f'failed to start command {self.cmd!r}: {exc}') from exc

        self._start_pump_threads()

        error: BaseException | None = None
        try:
            self._read_requested_page()
            self._wait_for_process_exit()
            if self.process.returncode != 0:
                error = SearxEngineException(
                    f'non-zero return code ({self.process.returncode}) when running command {self.cmd!r}'
                )
        except BaseException as exc:  # pylint: disable=broad-except
            error = exc

        # terminate / reap the group, join reader threads and close the pipes
        # on every exit path (success, failure and cancellation)
        self._cleanup()
        if error is not None:
            self._log_stderr(error)
            raise error
        return self.results

    def _start_pump_threads(self) -> None:
        process = self.process
        assert process is not None and process.stdout is not None and process.stderr is not None
        stdout_thread = Thread(
            target=_pump_stdout,
            args=(process.stdout, self._stdout_queue),
            name=f'searx.command.stdout[{process.pid}]',
            daemon=True,
        )
        stderr_thread = Thread(
            target=_pump_stderr,
            args=(process.stderr, self._stderr_tail),
            name=f'searx.command.stderr[{process.pid}]',
            daemon=True,
        )
        self._pump_threads = [stdout_thread, stderr_thread]
        stdout_thread.start()
        stderr_thread.start()

    def _outer_search_gave_up(self) -> bool:
        # the flag is set on the engine worker thread by
        # Search.search_multiple_requests once it stops waiting for the engine
        return bool(getattr(threading.current_thread(), '_timeout', False))

    def _raise_if_cancelled(self) -> None:
        if self._outer_search_gave_up():
            raise TimeoutError(f'the search does not wait anymore for command {self.cmd!r}')
        if self.deadline - monotonic() <= 0:
            raise TimeoutError(f'command {self.cmd!r} timed out after {timeout} seconds')

    def _read_requested_page(self) -> None:
        while True:
            self._raise_if_cancelled()
            try:
                item = self._stdout_queue.get(timeout=min(_POLL_INTERVAL, max(0.0, self.deadline - monotonic())))
            except queue.Empty:
                continue
            if item is _STDOUT_EOF:
                return
            self._handle_line(item)
            if self.count > self.end:
                # the requested page is complete; wait for a clean exit,
                # further output is not consumed into the result page anymore
                return

    def _handle_line(self, raw_line: bytes) -> None:
        try:
            line = raw_line.decode('utf-8')
        except UnicodeDecodeError as exc:
            raise SearxEngineResponseException(
                f'failed to decode the output of command {self.cmd!r} as UTF-8: {exc}'
            ) from exc

        buf = self.leftover + line
        raw_results = buf.split(result_separator)
        if raw_results[-1]:
            self.leftover = raw_results[-1]
        raw_results = raw_results[:-1]

        for raw_result in raw_results:
            result = _parse_single_result(raw_result)
            if result is None:
                _command_logger.debug('skipped result: %s', raw_result)
                continue

            if self.start <= self.count <= self.end:  # pylint: disable=chained-comparison
                self.results.add(self.results.types.KeyValue(kvmap=result))

            self.count += 1
            if self.end < self.count:
                return

    def _wait_for_process_exit(self) -> None:
        process = self.process
        assert process is not None
        while process.returncode is None:
            self._raise_if_cancelled()
            try:
                process.wait(timeout=min(_POLL_INTERVAL, max(0.0, self.deadline - monotonic())))
            except subprocess.TimeoutExpired:
                pass

    def _cleanup(self) -> None:
        # cleanup must never mask the original exception; the lock makes a
        # shutdown/atexit cleanup and the worker thread cleanup mutually
        # exclusive
        with self._cleanup_lock:
            if self._cleaned_up:
                return
            self._cleaned_up = True

            process = self.process
            if process is None:
                return

            try:
                if process.returncode is None:
                    # the command did not finish in time: stop receiving late
                    # output, terminate the whole group, force kill and reap
                    _stop_process_group(process, self.cmd)
                self._join_pump_threads()
                for stream in (process.stdout, process.stderr):
                    if stream is not None and not stream.closed:
                        try:
                            stream.close()
                        except Exception:  # pylint: disable=broad-except
                            _command_logger.debug(
                                'error while closing a pipe of command %r', self.cmd, exc_info=True
                            )
                if process.returncode is None:
                    try:
                        process.wait(timeout=_FORCE_KILL_REAP_TIMEOUT)
                    except subprocess.TimeoutExpired:
                        _command_logger.error('command %r (pid %s) could not be reaped', self.cmd, process.pid)
            except Exception:  # pylint: disable=broad-except
                _command_logger.exception('error while cleaning up command %r', self.cmd)

    def _join_pump_threads(self) -> None:
        for pump_thread in self._pump_threads:
            pump_thread.join(_PUMP_THREAD_JOIN_TIMEOUT)
        for pump_thread in self._pump_threads:
            if pump_thread.is_alive():
                # the threads are daemonic, so they cannot delay a service
                # shutdown, but no reader thread should survive the cleanup
                _command_logger.error('command %r left a reader thread running: %s', self.cmd, pump_thread.name)

    def _log_stderr(self, error: BaseException) -> None:
        if not self._stderr_tail:
            return
        stderr_text = '\n'.join(self._stderr_tail)[-2000:]
        _command_logger.warning('command %r failed (%s); stderr:\n%s', self.cmd, error, stderr_text)


def _get_results_limits(pageno):
    start = (pageno - 1) * 10
    end = start + 9
    return start, end


def __check_query_params(params):
    if not query_type:
        return

    if query_type == 'path':
        query_path = params[-1]
        query_path = expanduser(query_path)
        if commonprefix([realpath(query_path), working_dir]) != working_dir:
            raise ValueError('requested path is outside of configured working directory')
    elif query_type == 'enum' and len(query_enum) > 0:
        for param in params:
            if param not in query_enum:
                raise ValueError('submitted query params is not allowed', param, 'allowed params:', query_enum)


def check_parsing_options(engine_settings):
    """Checks if delimiter based parsing or regex parsing is configured correctly"""

    if 'delimiter' not in engine_settings and 'parse_regex' not in engine_settings:
        raise ValueError('failed to init settings for parsing lines: missing delimiter or parse_regex')
    if 'delimiter' in engine_settings and 'parse_regex' in engine_settings:
        raise ValueError('failed to init settings for parsing lines: too many settings')

    if 'delimiter' in engine_settings:
        if 'chars' not in engine_settings['delimiter'] or 'keys' not in engine_settings['delimiter']:
            raise ValueError


def _parse_single_result(raw_result):
    """Parses command line output based on configuration.

    Returns ``None`` when the line cannot be parsed with the configured
    delimiter / regular expressions, such lines are skipped (and logged).
    """

    result = {}

    if delimiter:
        elements = raw_result.split(delimiter['chars'], maxsplit=len(delimiter['keys']) - 1)
        if len(elements) != len(delimiter['keys']):
            return None
        for i, element in enumerate(elements):
            result[delimiter['keys'][i]] = element

    if parse_regex:
        for result_key, regex in _compiled_parse_regex.items():
            found = regex.search(raw_result)
            if not found:
                return None
            result[result_key] = raw_result[found.start() : found.end()]

    return result
