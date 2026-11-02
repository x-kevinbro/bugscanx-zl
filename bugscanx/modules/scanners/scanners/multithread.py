import os
import sys
import time
import traceback
from collections import Counter
from abc import ABC, abstractmethod
from queue import Queue, Empty
from threading import Thread, RLock, Event


class Logger:
    COLORS = {
        'ORANGE': '\033[33m',
        'MAGENTA': '\033[35m',
        'CYAN': '\033[36m',
        'LGRAY': '\033[37m',
        'GRAY': '\033[90m',
        'RED': '\033[91m',
        'GREEN': '\033[92m',
        'YELLOW': '\033[93m',
        'BLUE': '\033[94m',
    }
    RESET = '\033[0m'
    CLEAR_LINE = '\033[2K'

    def __init__(self):
        self._lock = RLock()

    @classmethod
    def colorize(cls, text, color):
        return f"{cls.COLORS.get(color, '')}{text}{cls.RESET}"

    @staticmethod
    def _columns():
        try:
            return os.get_terminal_size().columns
        except OSError:
            return 80

    def replace(self, message):
        cols = self._columns()
        msg = f"{message[:cols - 3]}..." if len(message) > cols else message
        with self._lock:
            sys.stdout.write(f'{self.CLEAR_LINE}{msg}{self.RESET}\r')
            sys.stdout.flush()

    def log(self, message):
        with self._lock:
            sys.stderr.write(f'\r{self.CLEAR_LINE}{message}{self.RESET}\n')
            sys.stderr.flush()


class CursorManager:
    def __enter__(self):
        print('\033[?25l', end='', flush=True)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        print('\033[?25h', end='', flush=True)


class MultiThread(ABC):
    """
    Queue-based worker pool with a dedicated progress-reporter thread.

    Workers never touch the terminal for progress - one reporter thread
    repaints the status line every REFRESH seconds straight from the shared
    counters. The display therefore updates continuously (it can never sit
    at 0 and then jump), and workers never block on terminal I/O, which
    also makes the scan itself faster.

    Workers shut down via sentinels instead of dying on a 1s empty-queue
    timeout, so the pool keeps its full width for the whole scan.
    """

    REFRESH = 0.25
    _SENTINEL = object()

    def __init__(self, threads=50):
        self._lock = RLock()
        self._stop = Event()
        self._reporter_stop = Event()
        self._queue = Queue(maxsize=5000)

        self._total = 0
        self._scanned = 0
        self._success = []
        self._success_count = 0
        self._current = ''
        self._failures = Counter()
        self._task_errors = 0
        self._start_time = None
        self._reporter = None

        self.threads = threads

        self.logger = Logger()

    def set_total(self, total):
        self._total = total

    # ------------------------------------------------------------------ run

    def start(self):
        print()
        self._start_time = time.monotonic()
        workers = []
        stopped = False
        with CursorManager():
            self._start_reporter()
            try:
                self.init()
                workers = [
                    Thread(target=self._worker, daemon=True)
                    for _ in range(max(1, int(self.threads)))
                ]
                for t in workers:
                    t.start()

                for task in self.generate_tasks():
                    if self._stop.is_set():
                        break
                    self._queue.put(task)

                # normal path only: sentinels go behind the remaining tasks
                # and tell workers to exit once everything is done
                if not self._stop.is_set():
                    for _ in workers:
                        self._queue.put(self._SENTINEL)

                for t in workers:
                    t.join()
            except KeyboardInterrupt:
                # Ctrl+C at ANY point: feeding, sentinel puts, or the join
                stopped = True
                self._stop.set()

            try:
                if stopped:
                    # queue is dropped whole - workers never start new tasks,
                    # they exit as soon as their current request returns
                    self._drain_queue()
                    deadline = time.monotonic() + 4
                    for t in workers:
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            break
                        t.join(timeout=max(0.1, remaining))
                    self._stop_reporter()
                    self.interrupted()
                else:
                    self._stop_reporter()
                    self.complete()
            except KeyboardInterrupt:
                pass  # second Ctrl+C: force-quit immediately
            self._stop_reporter()
        print()

    def _drain_queue(self):
        while True:
            try:
                self._queue.get_nowait()
            except Empty:
                break
            else:
                self._queue.task_done()

    # -------------------------------------------------------------- workers

    def _worker(self):
        while not self._stop.is_set():
            try:
                task = self._queue.get(timeout=0.5)
            except Empty:
                continue
            if task is self._SENTINEL:
                self._queue.task_done()
                return
            try:
                self.task(task)
            except Exception as exc:
                self._record_task_error(task, exc)
            finally:
                with self._lock:
                    self._scanned += 1
                self._queue.task_done()

    # ------------------------------------------------------------- failures

    DEBUG_ENV = 'BUGSCANX_DEBUG'
    DEBUG_LOG = 'bugscanx-debug.log'

    @classmethod
    def debug_enabled(cls):
        return os.environ.get(cls.DEBUG_ENV, '').strip().lower() in ('1', 'true', 'yes', 'on')

    def record_failure(self, reason, detail=None):
        """Count an expected network-level failure (timeout, refused, DNS,
        TLS ...). These are normal while scanning, but they are reported
        separately from "no result" so a broken network or a dead data
        source is visible instead of looking like an empty scan."""
        with self._lock:
            self._failures[reason or 'error'] += 1
        if detail is not None and self.debug_enabled():
            self._debug_write(f"[failure] {reason}: {detail}")

    def _record_task_error(self, task, exc):
        """Unexpected exception inside task() - a bug, not a network miss."""
        with self._lock:
            self._task_errors += 1
            first = self._task_errors == 1
        if self.debug_enabled():
            self._debug_write(
                f"[task error] task={task!r}\n"
                + ''.join(traceback.format_exception(type(exc), exc, exc.__traceback__)))
        elif first:
            self.logger.log(self.logger.colorize(
                f"Internal error while scanning: {type(exc).__name__}: {exc} "
                f"(set {self.DEBUG_ENV}=1 for full tracebacks in {self.DEBUG_LOG})",
                'RED'))

    def _debug_write(self, text):
        try:
            with self._lock:
                with open(self.DEBUG_LOG, 'a', encoding='utf-8') as f:
                    f.write(text.rstrip('\n') + '\n')
        except OSError:
            pass

    def failure_summary(self):
        with self._lock:
            failures = dict(self._failures)
            task_errors = self._task_errors
        parts = [f"{name} {count}" for name, count in
                 sorted(failures.items(), key=lambda kv: -kv[1])]
        if task_errors:
            parts.append(f"internal errors {task_errors}")
        return ', '.join(parts)

    def _log_failure_summary(self):
        summary = self.failure_summary()
        if summary:
            self.logger.log(self.logger.colorize(
                f"Failures: {summary}", 'GRAY'))

    # ------------------------------------------------------------- progress

    def progress(self, *extra):
        """Record what a worker is doing right now (no terminal I/O here).
        The reporter thread renders it on the next refresh tick."""
        if extra:
            text = ' '.join(str(x) for x in extra if x)
            with self._lock:
                self._current = text

    def _snapshot(self):
        with self._lock:
            return self._scanned, self._total, self._success_count, self._current

    def _start_reporter(self):
        self._reporter_stop.clear()
        self._reporter = Thread(target=self._report_loop, daemon=True)
        self._reporter.start()

    def _stop_reporter(self):
        self._reporter_stop.set()
        if self._reporter is not None:
            self._reporter.join(timeout=1)
            self._reporter = None

    def _report_loop(self):
        while not self._reporter_stop.wait(self.REFRESH):
            try:
                self.render_progress()
            except Exception:
                pass

    def render_progress(self, extra_parts=None):
        scanned, total, hits, current = self._snapshot()
        elapsed = max(0.001, time.monotonic() - (self._start_time or time.monotonic()))
        pct = scanned / max(1, total) * 100
        rate = scanned / elapsed * 60

        parts = [
            self.logger.colorize(f"{pct:.2f}%", 'CYAN'),
            f"{scanned} / {total}",
            self.logger.colorize(f"{hits} hits", 'GREEN'),
            f"{rate:.0f}/min",
        ]
        if scanned and scanned < total:
            remaining = (total - scanned) / (scanned / elapsed)
            parts.append(f"ETA {self._fmt_duration(remaining)}")
        if extra_parts:
            parts.extend(str(p) for p in extra_parts if p)
        if current:
            parts.append(self.logger.colorize(current[:40], 'GRAY'))
        self.logger.replace(' - '.join(parts))

    @staticmethod
    def _fmt_duration(seconds):
        seconds = max(0, int(seconds))
        h, rem = divmod(seconds, 3600)
        m, s = divmod(rem, 60)
        return f"{h:02d}:{m:02d}:{s:02d}" if h else f"{m:02d}:{s:02d}"

    # -------------------------------------------------------------- results

    def success(self, item):
        with self._lock:
            self._success.append(item)
            self._success_count += 1

    def add_success(self, count=1):
        """Count successes without storing items (memory-friendly)."""
        with self._lock:
            self._success_count += count

    def get_success(self):
        return self._success

    def sleep(self, seconds):
        """Interruptible backoff generator: yields in 0.1s steps and stops
        early when the scan is stopped with Ctrl+C."""
        deadline = time.monotonic() + seconds
        while not self._stop.is_set():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return
            time.sleep(min(0.1, remaining))
            yield

    # ---------------------------------------------------------------- hooks

    def complete(self):
        scanned, total, hits, _ = self._snapshot()
        elapsed = time.monotonic() - (self._start_time or time.monotonic())
        self.logger.log(self.logger.colorize(
            f"Scan completed in {self._fmt_duration(elapsed)} - "
            f"{scanned}/{total} scanned - {hits} hits", "GREEN"))
        self._log_failure_summary()

    def interrupted(self):
        scanned, total, hits, _ = self._snapshot()
        self.logger.log(self.logger.colorize(
            f"Scan stopped by user (Ctrl+C) - "
            f"{scanned}/{total} scanned, {hits} hits so far", "YELLOW"))
        self._log_failure_summary()

    @abstractmethod
    def generate_tasks(self): pass

    @abstractmethod
    def init(self): pass

    @abstractmethod
    def task(self, task): pass
