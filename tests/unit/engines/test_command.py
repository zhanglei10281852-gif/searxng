# SPDX-License-Identifier: AGPL-3.0-or-later
# pylint: disable=missing-module-docstring,disable=missing-class-docstring,invalid-name

import gc
import os
import sys
import tempfile
import threading
import time
from os.path import realpath

from searx.engines import command as command_engine
from searx.exceptions import SearxEngineException, SearxEngineResponseException
from searx.result_types import KeyValue

from tests import SearxTestCase

PYTHON = sys.executable
_SPACE_DELIMITER = {'chars': ' ', 'keys': ['first', 'second']}

# a child of the command process that simply keeps running, it stays in the
# command's process group / process tree and therefore has to be killed as well
_SLEEPING_CHILD = "import time; time.sleep(300)"

# dispatcher used through the {{QUERY}} token:
#   slow <pidfile>:  spawns a sleeping grandchild, reports the pids and sleeps
#   anything else:   prints one valid result and exits 0
_DISPATCH_CODE = (
    "import os,subprocess,sys,time\n"
    "mode=sys.argv[1]\n"
    "if mode=='slow':\n"
    " pidfile=sys.argv[2]\n"
    " p=subprocess.Popen([sys.executable,'-c'," + repr(_SLEEPING_CHILD) + "])\n"
    " open(pidfile,'w').write(str(os.getpid())+' '+str(p.pid))\n"
    " sys.stdout.buffer.write(b'started x\\n');sys.stdout.buffer.flush()\n"
    " time.sleep(300)\n"
    "else:\n"
    " sys.stdout.buffer.write(b'ok value\\n')\n"
)

# same as the dispatcher above, but the command process (and its child) ignore
# the polite termination signal, so the engine has to force kill the group
_IGNORING_CHILD = (
    "import signal,time\n"
    "try: signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
    "except Exception: pass\n"
    "try: signal.signal(signal.SIGBREAK, signal.SIG_IGN)\n"
    "except Exception: pass\n"
    "time.sleep(300)\n"
)
_IGNORING_DISPATCH_CODE = (
    "import os,subprocess,sys,time,signal\n"
    "pidfile=sys.argv[1]\n"
    "try: signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
    "except Exception: pass\n"
    "try: signal.signal(signal.SIGBREAK, signal.SIG_IGN)\n"
    "except Exception: pass\n"
    "p=subprocess.Popen([sys.executable,'-c'," + repr(_IGNORING_CHILD) + "])\n"
    "open(pidfile,'w').write(str(os.getpid())+' '+str(p.pid))\n"
    "sys.stdout.buffer.write(b'started x\\n');sys.stdout.buffer.flush()\n"
    "time.sleep(300)\n"
)


def _win_pid_alive(pid: int) -> bool:
    import ctypes  # pylint: disable=import-outside-toplevel

    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    STILL_ACTIVE = 259
    handle = ctypes.windll.kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not handle:
        return False
    exit_code = ctypes.c_ulong()
    ok = ctypes.windll.kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code))
    ctypes.windll.kernel32.CloseHandle(handle)
    return bool(ok) and exit_code.value == STILL_ACTIVE


def _posix_pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    # a zombie has already been terminated; only its exit status remains to be
    # reaped by PID 1 (the engine reaps its direct child process itself)
    try:
        with open(f'/proc/{pid}/stat', encoding='ascii') as handle:
            return handle.read().split()[2] != 'Z'
    except (FileNotFoundError, ProcessLookupError):
        return False


def _pid_alive(pid: int) -> bool:
    return _win_pid_alive(pid) if sys.platform == 'win32' else _posix_pid_alive(pid)


def _reset_engine_globals() -> None:
    """reset the module globals of the command engine between tests (its
    configuration is stored in module level globals)."""
    command_engine.command = []
    command_engine.delimiter = {}
    command_engine.parse_regex = {}
    command_engine._compiled_parse_regex.clear()  # pylint: disable=protected-access
    command_engine.query_type = ''
    command_engine.query_enum = []
    command_engine.environment_variables = {}
    command_engine.result_separator = '\n'
    command_engine.working_dir = realpath('.')
    command_engine.timeout = 4.0


def _kvmaps(results) -> list[dict]:
    return [result.kvmap for result in results if isinstance(result, KeyValue)]


def _wait_pids_dead(pids, wait_seconds: float = 8.0) -> bool:
    deadline = time.monotonic() + wait_seconds
    while time.monotonic() < deadline:
        if not any(_pid_alive(pid) for pid in pids):
            return True
        time.sleep(0.05)
    return not any(_pid_alive(pid) for pid in pids)


def _read_pidfile(path: str, wait_seconds: float = 5.0) -> tuple[int, int]:
    deadline = time.monotonic() + wait_seconds
    while time.monotonic() < deadline:
        try:
            with open(path, encoding='ascii') as handle:
                parent_pid, child_pid = handle.read().split()
            return int(parent_pid), int(child_pid)
        except (FileNotFoundError, ValueError):
            time.sleep(0.05)
    raise AssertionError('command did not report its pids: %s' % path)


class TestCommandEngineLifecycle(SearxTestCase):
    """Request lifecycle: process groups, reader threads, pipes and the error
    observation paths.  These tests only rely on a Python interpreter so that
    they run on every platform."""

    def setUp(self):
        super().setUp()
        _reset_engine_globals()

    def _reader_threads_alive(self):
        return [thread for thread in threading.enumerate() if thread.name.startswith('searx.command.')]

    def test_startup_failure_raises_engine_exception(self):
        command_engine.command = ['searxng-command-engine-missing-binary']
        with self.assertRaises(SearxEngineException):
            command_engine.search('', {'pageno': 1})

    def test_non_zero_exit_raises_engine_exception(self):
        command_engine.command = [
            PYTHON,
            '-c',
            "import sys; sys.stderr.write('boom\\n'); sys.exit(3)",
        ]
        command_engine.delimiter = _SPACE_DELIMITER
        with self.assertRaises(SearxEngineException) as ctx:
            command_engine.search('', {'pageno': 1})
        self.assertIn('non-zero return code (3)', str(ctx.exception))

    def test_invalid_encoding_raises_response_exception(self):
        command_engine.command = [
            PYTHON,
            '-c',
            "import sys; sys.stdout.buffer.write(b'a \\xff\\xfe\\n')",
        ]
        command_engine.delimiter = _SPACE_DELIMITER
        with self.assertRaises(SearxEngineResponseException):
            command_engine.search('', {'pageno': 1})

    def test_stderr_is_drained_without_deadlock(self):
        # more output than the pipe buffer on stderr must not block the command
        command_engine.command = [
            PYTHON,
            '-c',
            "import sys\n"
            "sys.stderr.write('x' * 2000000 + '\\n'); sys.stderr.flush()\n"
            "sys.stdout.buffer.write(b'ok value\\n')",
        ]
        command_engine.delimiter = _SPACE_DELIMITER
        results = command_engine.search('', {'pageno': 1})
        self.assertEqual(len(results), 1)
        first = results[0]
        if not isinstance(first, KeyValue):
            self.fail('expected a KeyValue result')
        self.assertEqual(first.kvmap, {'first': 'ok', 'second': 'value'})

    def test_unparseable_lines_are_skipped(self):
        command_engine.command = [
            PYTHON,
            '-c',
            "import sys\nsys.stdout.buffer.write(b'a:1\\ngarbage\\nb:2\\n')",
        ]
        command_engine.delimiter = {'chars': ':', 'keys': ['key', 'value']}
        results = command_engine.search('', {'pageno': 1})
        self.assertEqual(
            _kvmaps(results),
            [{'key': 'a', 'value': '1'}, {'key': 'b', 'value': '2'}],
        )

    def test_unterminated_last_record_is_not_published(self):
        command_engine.command = [PYTHON, '-c', "import sys; sys.stdout.buffer.write(b'ok value')"]
        command_engine.delimiter = _SPACE_DELIMITER
        results = command_engine.search('', {'pageno': 1})
        self.assertEqual(len(results), 0)

    def test_environment_variables_are_passed(self):
        env = dict(os.environ)
        env['SEARXNG_COMMAND_ENGINE_TEST'] = 'present'
        command_engine.environment_variables = env
        command_engine.command = [
            PYTHON,
            '-c',
            "import os,sys\n"
            "sys.stdout.buffer.write(('env ' + os.environ['SEARXNG_COMMAND_ENGINE_TEST'] + '\\n').encode())",
        ]
        command_engine.delimiter = _SPACE_DELIMITER
        results = command_engine.search('', {'pageno': 1})
        first = results[0]
        if not isinstance(first, KeyValue):
            self.fail('expected a KeyValue result')
        self.assertEqual(first.kvmap, {'first': 'env', 'second': 'present'})

    def test_pagination_takes_ten_results_per_page(self):
        command_engine.command = [
            PYTHON,
            '-c',
            "import sys\nfor i in range(1, 26):\n sys.stdout.buffer.write(('v %d\\n' % i).encode())",
        ]
        command_engine.delimiter = _SPACE_DELIMITER

        page1 = command_engine.search('', {'pageno': 1})
        page2 = command_engine.search('', {'pageno': 2})
        page3 = command_engine.search('', {'pageno': 3})

        self.assertEqual(len(page1), 10)
        self.assertEqual(len(page2), 10)
        self.assertEqual(len(page3), 5)
        self.assertEqual(_kvmaps(page1)[0], {'first': 'v', 'second': '1'})
        self.assertEqual(_kvmaps(page1)[-1], {'first': 'v', 'second': '10'})
        self.assertEqual(_kvmaps(page2)[0], {'first': 'v', 'second': '11'})
        self.assertEqual(_kvmaps(page3)[-1], {'first': 'v', 'second': '25'})

    def test_fast_command_finishing_after_full_page(self):
        # the page is complete before EOF, but the command exits 0 right after:
        # the results must still be published (fast success behavior)
        command_engine.command = [
            PYTHON,
            '-c',
            "import sys,time\nfor i in range(1, 13):\n"
            " sys.stdout.buffer.write(('v %d\\n' % i).encode())\n"
            "sys.stdout.buffer.flush()",
        ]
        command_engine.delimiter = _SPACE_DELIMITER
        results = command_engine.search('', {'pageno': 1})
        self.assertEqual(len(results), 10)
        self.assertEqual(_kvmaps(results)[-1], {'first': 'v', 'second': '10'})

    def test_page_full_without_clean_exit_times_out(self):
        # a complete page must not be published while the command keeps running
        command_engine.command = [
            PYTHON,
            '-c',
            "import sys,time\n"
            "for i in range(1, 13):\n"
            " sys.stdout.buffer.write(('v %d\\n' % i).encode())\n"
            "sys.stdout.buffer.flush()\n"
            "time.sleep(300)\n",
        ]
        command_engine.delimiter = _SPACE_DELIMITER
        self.setattr4test(command_engine, 'timeout', 1.0)
        self.setattr4test(command_engine, '_TERMINATION_GRACE_PERIOD', 0.3)
        started = time.monotonic()
        with self.assertRaises(TimeoutError):
            command_engine.search('', {'pageno': 1})
        self.assertLess(time.monotonic() - started, 5.0)
        self.assertEqual(self._reader_threads_alive(), [])

    def test_engine_timeout_kills_the_whole_process_group(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            pidfile = os.path.join(tmp_dir, 'pids.txt')
            command_engine.command = [PYTHON, '-c', _DISPATCH_CODE, '{{QUERY}}']
            command_engine.delimiter = _SPACE_DELIMITER
            self.setattr4test(command_engine, 'timeout', 1.0)
            self.setattr4test(command_engine, '_TERMINATION_GRACE_PERIOD', 0.3)

            started = time.monotonic()
            with self.assertRaises(TimeoutError):
                # single quotes survive the shlex split (also on Windows paths)
                command_engine.search("slow '%s'" % pidfile, {'pageno': 1})
            self.assertLess(time.monotonic() - started, 5.0)

            parent_pid, child_pid = _read_pidfile(pidfile)
            self.assertTrue(_wait_pids_dead([parent_pid, child_pid]))
            self.assertEqual(self._reader_threads_alive(), [])

    def test_command_ignoring_termination_is_force_killed(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            pidfile = os.path.join(tmp_dir, 'pids.txt')
            command_engine.command = [PYTHON, '-c', _IGNORING_DISPATCH_CODE, '{{QUERY}}']
            command_engine.delimiter = _SPACE_DELIMITER
            self.setattr4test(command_engine, 'timeout', 1.0)
            self.setattr4test(command_engine, '_TERMINATION_GRACE_PERIOD', 0.3)

            with self.assertRaises(TimeoutError):
                command_engine.search("'%s'" % pidfile, {'pageno': 1})

            parent_pid, child_pid = _read_pidfile(pidfile)
            self.assertTrue(_wait_pids_dead([parent_pid, child_pid]))
            self.assertEqual(self._reader_threads_alive(), [])

    def test_outer_search_giving_up_kills_the_command(self):
        # simulates Search.search_multiple_requests setting th._timeout once it
        # stops waiting for the engine
        with tempfile.TemporaryDirectory() as tmp_dir:
            pidfile = os.path.join(tmp_dir, 'pids.txt')
            command_engine.command = [PYTHON, '-c', _DISPATCH_CODE, '{{QUERY}}']
            command_engine.delimiter = _SPACE_DELIMITER
            self.setattr4test(command_engine, 'timeout', 30.0)
            self.setattr4test(command_engine, '_TERMINATION_GRACE_PERIOD', 0.3)

            failures: dict[str, BaseException] = {}

            def worker():
                try:
                    command_engine.search("slow '%s'" % pidfile, {'pageno': 1})
                except BaseException as exc:  # pylint: disable=broad-except
                    failures['exc'] = exc

            thread = threading.Thread(target=worker)
            setattr(thread, '_timeout', False)
            thread.start()
            parent_pid, child_pid = _read_pidfile(pidfile)

            time.sleep(0.3)
            setattr(thread, '_timeout', True)
            thread.join(5.0)

            self.assertFalse(thread.is_alive())
            self.assertIsInstance(failures.get('exc'), TimeoutError)
            self.assertTrue(_wait_pids_dead([parent_pid, child_pid]))
            self.assertEqual(self._reader_threads_alive(), [])

    def test_completed_requests_do_not_remain_registered(self):
        command_engine.command = [PYTHON, '-c', "import sys; sys.stdout.buffer.write(b'ok value\\n')"]
        command_engine.delimiter = _SPACE_DELIMITER
        command_engine.search('', {'pageno': 1})
        gc.collect()
        self.assertEqual(
            list(command_engine._live_requests),  # pylint: disable=protected-access
            [],
        )

    def test_service_shutdown_terminates_running_commands(self):
        # the atexit hook must terminate the command groups of in-flight
        # searches so no command outlives the service process
        with tempfile.TemporaryDirectory() as tmp_dir:
            pidfile = os.path.join(tmp_dir, 'pids.txt')
            command_engine.command = [PYTHON, '-c', _DISPATCH_CODE, '{{QUERY}}']
            command_engine.delimiter = _SPACE_DELIMITER
            self.setattr4test(command_engine, 'timeout', 30.0)
            self.setattr4test(command_engine, '_TERMINATION_GRACE_PERIOD', 0.3)

            failures: dict[str, BaseException] = {}

            def worker():
                try:
                    command_engine.search("slow '%s'" % pidfile, {'pageno': 1})
                except BaseException as exc:  # pylint: disable=broad-except
                    failures['exc'] = exc

            thread = threading.Thread(target=worker)
            thread.start()
            parent_pid, child_pid = _read_pidfile(pidfile)

            command_engine._terminate_live_requests()  # pylint: disable=protected-access
            thread.join(5.0)

            self.assertFalse(thread.is_alive())
            self.assertIsInstance(failures.get('exc'), BaseException)
            self.assertTrue(_wait_pids_dead([parent_pid, child_pid]))
            self.assertEqual(self._reader_threads_alive(), [])

    def test_concurrent_searches_are_isolated(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            pidfile_a = os.path.join(tmp_dir, 'pids-a.txt')
            pidfile_b = os.path.join(tmp_dir, 'pids-b.txt')
            command_engine.command = [PYTHON, '-c', _DISPATCH_CODE, '{{QUERY}}']
            command_engine.delimiter = _SPACE_DELIMITER
            self.setattr4test(command_engine, 'timeout', 1.0)
            self.setattr4test(command_engine, '_TERMINATION_GRACE_PERIOD', 0.3)

            slow_failures: list[BaseException] = []
            fast_results: list = []

            def slow(query: str):
                try:
                    command_engine.search(query, {'pageno': 1})
                except BaseException as exc:  # pylint: disable=broad-except
                    slow_failures.append(exc)

            def fast(query: str):
                fast_results.extend(command_engine.search(query, {'pageno': 1}))

            threads = [
                threading.Thread(target=slow, args=("slow '%s'" % pidfile_a,)),
                threading.Thread(target=slow, args=("slow '%s'" % pidfile_b,)),
                threading.Thread(target=fast, args=('fast',)),
            ]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(8.0)
                self.assertFalse(thread.is_alive())

            self.assertEqual(len(slow_failures), 2)
            self.assertTrue(all(isinstance(exc, TimeoutError) for exc in slow_failures))
            self.assertEqual(len(fast_results), 1)
            self.assertEqual(_kvmaps(fast_results), [{'first': 'ok', 'second': 'value'}])

            pids_a = _read_pidfile(pidfile_a)
            pids_b = _read_pidfile(pidfile_b)
            self.assertTrue(_wait_pids_dead([*pids_a, *pids_b]))
            self.assertEqual(self._reader_threads_alive(), [])


class TestCommandEngine(SearxTestCase):

    def setUp(self):
        super().setUp()
        _reset_engine_globals()

    def test_basic_seq_command_engine(self):
        ls_engine = command_engine
        ls_engine.command = ['seq', '{{QUERY}}']
        ls_engine.delimiter = {'chars': ' ', 'keys': ['number']}
        expected_results = [
            KeyValue(kvmap={'number': 1}),
            KeyValue(kvmap={'number': 2}),
            KeyValue(kvmap={'number': 3}),
            KeyValue(kvmap={'number': 4}),
            KeyValue(kvmap={'number': 5}),
        ]
        results = ls_engine.search('5', {'pageno': 1})
        for i, expected in enumerate(expected_results):
            self.assertEqual(results[i].kvmap["number"], str(expected.kvmap["number"]))

    def test_delimiter_parsing(self):
        searx_logs = '''DEBUG:searx.webapp:static directory is /home/n/p/searx/searx/static
DEBUG:searx.webapp:templates directory is /home/n/p/searx/searx/templates
DEBUG:searx.engines:soundcloud engine: Starting background initialization
DEBUG:searx.engines:wolframalpha engine: Starting background initialization
DEBUG:searx.engines:locate engine: Starting background initialization
DEBUG:searx.engines:regex search in files engine: Starting background initialization
DEBUG:urllib3.connectionpool:Starting new HTTPS connection (1): www.wolframalpha.com
DEBUG:urllib3.connectionpool:Starting new HTTPS connection (1): soundcloud.com
DEBUG:searx.engines:find engine: Starting background initialization
DEBUG:searx.engines:pattern search in files engine: Starting background initialization
DEBUG:searx.webapp:starting webserver on 127.0.0.1:8888
WARNING:werkzeug: * Debugger is active!
INFO:werkzeug: * Debugger PIN: 299-578-362'''
        echo_engine = command_engine
        echo_engine.command = ['echo', searx_logs]
        echo_engine.delimiter = {'chars': ':', 'keys': ['level', 'component', 'message']}

        page1 = [
            {
                'component': 'searx.webapp',
                'message': 'static directory is /home/n/p/searx/searx/static',
                'level': 'DEBUG',
            },
            {
                'component': 'searx.webapp',
                'message': 'templates directory is /home/n/p/searx/searx/templates',
                'level': 'DEBUG',
            },
            {
                'component': 'searx.engines',
                'message': 'soundcloud engine: Starting background initialization',
                'level': 'DEBUG',
            },
            {
                'component': 'searx.engines',
                'message': 'wolframalpha engine: Starting background initialization',
                'level': 'DEBUG',
            },
            {
                'component': 'searx.engines',
                'message': 'locate engine: Starting background initialization',
                'level': 'DEBUG',
            },
            {
                'component': 'searx.engines',
                'message': 'regex search in files engine: Starting background initialization',
                'level': 'DEBUG',
            },
            {
                'component': 'urllib3.connectionpool',
                'message': 'Starting new HTTPS connection (1): www.wolframalpha.com',
                'level': 'DEBUG',
            },
            {
                'component': 'urllib3.connectionpool',
                'message': 'Starting new HTTPS connection (1): soundcloud.com',
                'level': 'DEBUG',
            },
            {
                'component': 'searx.engines',
                'message': 'find engine: Starting background initialization',
                'level': 'DEBUG',
            },
            {
                'component': 'searx.engines',
                'message': 'pattern search in files engine: Starting background initialization',
                'level': 'DEBUG',
            },
        ]
        page2 = [
            {
                'component': 'searx.webapp',
                'message': 'starting webserver on 127.0.0.1:8888',
                'level': 'DEBUG',
            },
            {
                'component': 'werkzeug',
                'message': ' * Debugger is active!',
                'level': 'WARNING',
            },
            {
                'component': 'werkzeug',
                'message': ' * Debugger PIN: 299-578-362',
                'level': 'INFO',
            },
        ]

        page1 = [KeyValue(kvmap=row) for row in page1]
        page2 = [KeyValue(kvmap=row) for row in page2]

        expected_results_by_page = [page1, page2]
        for i in [0, 1]:
            results = echo_engine.search('', {'pageno': i + 1})
            page = expected_results_by_page[i]
            for i, expected in enumerate(page):
                self.assertEqual(expected.kvmap["message"], str(results[i].kvmap["message"]))

    def test_regex_parsing(self):
        txt = '''commit 35f9a8c81d162a361b826bbcd4a1081a4fbe76a7
Author: Noémi Ványi <sitbackandwait@gmail.com>
Date:   Tue Oct 15 11:31:33 2019 +0200

first interesting message

commit 6c3c206316153ccc422755512bceaa9ab0b14faa
Author: Noémi Ványi <sitbackandwait@gmail.com>
Date:   Mon Oct 14 17:10:08 2019 +0200

second interesting message

commit d8594d2689b4d5e0d2f80250223886c3a1805ef5
Author: Noémi Ványi <sitbackandwait@gmail.com>
Date:   Mon Oct 14 14:45:05 2019 +0200

third interesting message

commit '''
        git_log_engine = command_engine
        git_log_engine.command = ['echo', txt]
        git_log_engine.result_separator = '\n\ncommit '
        git_log_engine.delimiter = {}
        git_log_engine.parse_regex = {
            'commit': r'\w{40}',
            'author': r'[\w* ]* <\w*@?\w*\.?\w*>',
            'date': r'Date: .*',
            'message': r'\n\n.*$',
        }
        git_log_engine.setup({"command": git_log_engine.command, "parse_regex": git_log_engine.parse_regex})
        expected_results = [
            {
                'commit': '35f9a8c81d162a361b826bbcd4a1081a4fbe76a7',
                'author': ' Noémi Ványi <sitbackandwait@gmail.com>',
                'date': 'Date:   Tue Oct 15 11:31:33 2019 +0200',
                'message': '\n\nfirst interesting message',
            },
            {
                'commit': '6c3c206316153ccc422755512bceaa9ab0b14faa',
                'author': ' Noémi Ványi <sitbackandwait@gmail.com>',
                'date': 'Date:   Mon Oct 14 17:10:08 2019 +0200',
                'message': '\n\nsecond interesting message',
            },
            {
                'commit': 'd8594d2689b4d5e0d2f80250223886c3a1805ef5',
                'author': ' Noémi Ványi <sitbackandwait@gmail.com>',
                'date': 'Date:   Mon Oct 14 14:45:05 2019 +0200',
                'message': '\n\nthird interesting message',
            },
        ]

        expected_results = [KeyValue(kvmap=kvmap) for kvmap in expected_results]
        results = git_log_engine.search('', {'pageno': 1})
        for i, expected in enumerate(expected_results):
            self.assertEqual(expected.kvmap["message"], str(results[i].kvmap["message"]))

    def test_working_dir_path_query(self):
        ls_engine = command_engine
        ls_engine.command = ['ls', '{{QUERY}}']
        ls_engine.result_separator = '\n'
        ls_engine.delimiter = {'chars': ' ', 'keys': ['file']}
        ls_engine.query_type = 'path'

        results = ls_engine.search('.', {'pageno': 1})
        self.assertTrue(len(results) != 0)

        forbidden_paths = [
            '..',
            '../..',
            './..',
            '~',
            '/var',
        ]
        for forbidden_path in forbidden_paths:
            self.assertRaises(ValueError, ls_engine.search, forbidden_path, {'pageno': 1})

    def test_enum_queries(self):
        echo_engine = command_engine
        echo_engine.command = ['echo', '{{QUERY}}']
        echo_engine.query_type = 'enum'
        echo_engine.query_enum = ['i-am-allowed-to-say-this', 'and-that']

        for allowed in echo_engine.query_enum:
            results = echo_engine.search(allowed, {'pageno': 1})
            self.assertTrue(len(results) != 0)

        forbidden_queries = [
            'forbidden',
            'banned',
            'prohibited',
        ]
        for forbidden in forbidden_queries:
            self.assertRaises(ValueError, echo_engine.search, forbidden, {'pageno': 1})
