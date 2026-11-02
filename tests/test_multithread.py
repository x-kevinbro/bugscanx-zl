import time

from bugscanx.modules.scanners.scanners.multithread import MultiThread


class Pool(MultiThread):
    def __init__(self, tasks, **kw):
        super().__init__(**kw)
        self.tasks = tasks
        self.set_total(len(tasks))
        self.was_interrupted = False
        self.was_completed = False

    def generate_tasks(self):
        for t in self.tasks:
            if t == "ctrl-c":
                raise KeyboardInterrupt
            yield t

    def init(self):
        pass

    def task(self, t):
        if t == "boom":
            raise RuntimeError("bug in task")
        if t == "timeout":
            self.record_failure("timeout")
        if t == "ok":
            self.add_success()

    def complete(self):
        self.was_completed = True
        super().complete()

    def interrupted(self):
        self.was_interrupted = True
        super().interrupted()


def test_failures_and_task_errors_are_counted():
    p = Pool(["ok", "timeout", "timeout", "boom", "ok"], threads=3)
    p.start()
    assert p.was_completed
    assert p._scanned == 5
    assert p._success_count == 2
    summary = p.failure_summary()
    assert "timeout 2" in summary
    assert "internal errors 1" in summary


def test_clean_run_has_empty_summary():
    p = Pool(["ok"] * 10, threads=4)
    p.start()
    assert p.failure_summary() == ""


def test_ctrl_c_stops_scan_quickly():
    p = Pool(["ok"] * 5 + ["ctrl-c"] + ["ok"] * 1000, threads=2)
    t0 = time.monotonic()
    p.start()
    assert p.was_interrupted
    assert not p.was_completed
    assert p._scanned <= 5
    assert time.monotonic() - t0 < 6


def test_debug_log_written(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("BUGSCANX_DEBUG", "1")
    p = Pool(["boom"], threads=1)
    p.start()
    log = (tmp_path / MultiThread.DEBUG_LOG).read_text(encoding="utf-8")
    assert "RuntimeError: bug in task" in log
