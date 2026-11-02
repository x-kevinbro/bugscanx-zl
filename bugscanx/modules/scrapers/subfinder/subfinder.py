import os
import threading
import time

from bugscanx.modules.scanners.scanners.multithread import MultiThread
from bugscanx.utils.files import check_output_path, resolve_output_mode
from bugscanx.utils.prompts import get_confirm, get_input
from .logger import SubFinderConsole
from .sources import get_sources
from .utils import DomainValidator, STOP, all_limiters, reset_limiters

# reasons that mean "ask again later", not "this source has nothing"
DEFERRABLE = ('rate limited', 'busy')
# reasons after which a source is skipped for the rest of the run
DEAD_REASONS = ('daily limit reached', 'needs API key', 'quota used up')

# One worker pool wide enough that every (domain, source) query runs at
# once. 150 workers x ~1s average source response ~= 1000+ domains/minute.
DEFAULT_THREADS = 150


class SubFinderEngine(MultiThread):
    """
    Flat (domain x source) task pool.

    The old engine ran only 3 domains at a time and each domain waited for
    its slowest source (10s timeout), so big lists crawled. Here every
    single source query is its own task in one wide pool: a slow or dead
    source only occupies its own worker for a few seconds (3s connect /
    6s read hard timeout) and never stalls the run. Results are saved per
    domain the moment its last source answers, and a Ctrl+C still keeps
    everything found so far.
    """

    def __init__(self, domains, sources, output_file, threads=DEFAULT_THREADS,
                 mode='w', retry_rounds=None, retry_wait=None):
        super().__init__(threads=threads)
        fast = bool(sources) and all(getattr(src, 'fast', False) for src in sources)
        self.retry_rounds = (1 if fast else 2) if retry_rounds is None else int(retry_rounds)
        # time budget of ONE retry round (waiting for cooldowns + lookups)
        self.retry_wait = (45 if fast else 180) if retry_wait is None else float(retry_wait)
        self._round = 0
        self._deferred = []
        self._errors = {d: {} for d in domains}
        self._dead_logged = set()
        if mode not in ('w', 'a'):
            raise ValueError("mode must be 'w' or 'a'")
        self.domains = domains
        self.sources = sources
        self.output_file = output_file
        self.mode = mode
        self._results = {d: set() for d in domains}
        self._pending = {d: len(sources) for d in domains}
        self._domains_done = 0
        self._all = set()
        self._save_lock = threading.Lock()
        self.set_total(len(domains) * max(1, len(sources)))

    def generate_tasks(self):
        for domain in self.domains:
            for source in self.sources:
                yield (domain, source)
        # retry rounds: lookups a source refused with "too many requests"
        for round_no in range(1, self.retry_rounds + 1):
            while self._queue.unfinished_tasks and not self._stop.is_set():
                time.sleep(0.2)
            with self._lock:
                batch, self._deferred = self._deferred, []
                self._round = round_no
            if not batch or self._stop.is_set():
                break
            deadline = time.monotonic() + self.retry_wait
            for lim in all_limiters():
                lim.max_wait = self.retry_wait
                lim.deadline = deadline
            names = sorted({src.name for _, src in batch})
            self.logger.log(self.logger.colorize(
                f"Retry round {round_no}: {len(batch)} lookup(s) were rate limited "
                f"({', '.join(names)}) - retrying for up to {self.retry_wait:.0f}s...",
                'CYAN'))
            with self._lock:
                self._total += len(batch)
            for task in batch:
                yield task
        # anything still deferred is final now
        with self._lock:
            leftover, self._deferred = self._deferred, []
        for domain, source in leftover:
            self._finish(domain, source, 'rate limited')

    def init(self):
        STOP.clear()
        os.makedirs(os.path.dirname(self.output_file) or '.', exist_ok=True)
        if self.mode == 'w':
            # only reached after the caller confirmed overwriting
            with self._save_lock:
                with open(self.output_file, 'w', encoding='utf-8'):
                    pass

    def task(self, payload):
        domain, source = payload
        self.progress(f"{source.name} {domain}")

        clear = getattr(source, 'clear_error', None)
        if clear:
            clear()
        parse_error = None
        try:
            found = source.fetch(domain)
            found = DomainValidator.filter_valid_subdomains(found, domain)
        except Exception as exc:
            found = set()
            parse_error = repr(exc)

        err = None
        if parse_error:
            err = 'parse error'
        elif not found:
            err = getattr(source, 'last_error', lambda: None)()
        if found:
            # saved + counted the moment a source answers: the progress line
            # shows real hits and nothing waits for the slowest source
            with self._lock:
                known = self._results.setdefault(domain, set())
                new = found - known - self._all
                known.update(new)
                self._all.update(new)
                self._success_count += len(new)
            self._save_domain(new)
        elif err in DEFERRABLE and self._round < self.retry_rounds \
                and not self._stop.is_set():
            with self._lock:
                self._deferred.append((domain, source))
            return
        if err in DEAD_REASONS and source.name not in self._dead_logged:
            self._dead_logged.add(source.name)
            self.logger.log(self.logger.colorize(
                f"{source.name}: {err} - skipped for the rest of this run", 'YELLOW'))
        self._finish(domain, source, err)

    def _finish(self, domain, source, err):
        if err and err != 'stopped':
            # counted once, when final - a lookup that was rate limited and
            # then answered in a retry round is not a failure
            self.record_failure(f"{source.name}: {err}", domain)
            with self._lock:
                self._errors.setdefault(domain, {})[source.name] = err
        save_now = None
        with self._lock:
            if domain not in self._pending:
                return
            self._pending[domain] -= 1
            if self._pending[domain] == 0:
                self._domains_done += 1
                save_now = self._results.pop(domain, set())
                errors = self._errors.pop(domain, {})
        if save_now is None:
            return
        msg = f"{domain}: {len(save_now)} subdomains"
        if errors:
            msg += " (no answer: " + ', '.join(
                f"{name} {why}" for name, why in sorted(errors.items())) + ")"
        self.logger.log(self.logger.colorize(msg, 'GREEN' if save_now else 'YELLOW'))

    def render_progress(self):
        super().render_progress(
            extra_parts=[f"{self._domains_done}/{len(self.domains)} domains"])

    def _save_domain(self, subdomains):
        if not subdomains:
            return
        with self._save_lock:
            with open(self.output_file, 'a', encoding='utf-8') as f:
                f.write('\n'.join(sorted(subdomains)) + '\n')

    def _flush_partial(self):
        """Ctrl+C path: keep whatever in-flight domains already found."""
        # results are written as each source answers - nothing to flush
        with self._lock:
            self._results.clear()

    def complete(self):
        super().complete()
        self.logger.log(self.logger.colorize(
            f"Total: {len(self._all)} subdomains - saved to {self.output_file}",
            'GREEN'))

    def interrupted(self):
        STOP.set()
        self._flush_partial()
        super().interrupted()
        self.logger.log(self.logger.colorize(
            f"Partial results kept: {len(self._all)} subdomains - "
            f"saved to {self.output_file}", 'YELLOW'))


class SubFinder:
    def __init__(self):
        self.console = SubFinderConsole()

    def run(self, domains, output_file, sources, threads=DEFAULT_THREADS,
            mode='w'):
        domains = [d for d in dict.fromkeys(domains)
                   if DomainValidator.is_valid_domain(d)]
        if not domains:
            self.console.print_error("No valid domains provided")
            return set()

        if len(domains) > 1000:
            self.console.print(
                f"[yellow] {len(domains):,} domains: the free sources only allow a few "
                f"requests per minute each, so this can take many hours. Use a "
                f"shorter list of the domains you really need, or Fast mode.[/yellow]")
        reset_limiters()
        engine = SubFinderEngine(domains, sources, output_file,
                                 threads=threads, mode=mode)
        try:
            engine.start()
        finally:
            STOP.set()          # release any worker still waiting on a source
        return set(engine._all)


def ask_source_mode():
    choice = get_input(
        "Select search mode",
        input_type="choice",
        choices=[
            "Thorough - all sources, waits for slow ones (most subdomains)",
            "Fast - short timeouts, skips Wayback (quicker, can miss some)",
        ],
    )
    return "fast" if choice.startswith("Fast") else "thorough"


def main():
    domains = []
    file_path = None
    input_type = get_input("Select input mode", input_type="choice", choices=["Manual", "File"])
    if input_type == "Manual":
        domain_input = get_input("Enter domain(s)", validators="required")
        domains = [d.strip().lower() for d in domain_input.split(',') if DomainValidator.is_valid_domain(d.strip())]
        default_output = f"{domains[0]}_subdomains.txt" if domains else "subdomains.txt"
    else:
        file_path = get_input("Enter filename", input_type="file", validators="file")
        with open(file_path, 'r') as f:
            domains = [d.strip().lower() for d in f if DomainValidator.is_valid_domain(d.strip())]
        default_output = f"{file_path.rsplit('.', 1)[0]}_subdomains.txt"

    while True:
        output_file = get_input("Enter output filename", default=default_output, validators="required")
        error = check_output_path(output_file, input_files=[file_path])
        if error:
            print(f" {error}")
            continue  # e.g. output == input file: ask again
        mode = resolve_output_mode(output_file, input_files=[file_path])
        if mode is None:
            print(" Cancelled - nothing was written.")
            return
        break
    sources = get_sources(ask_source_mode())
    brute = get_confirm(
        " Also DNS-check common names (www, api, mail, ...) to find hosts "
        "missing from public records?", default=False)
    threads = get_input("Enter threads", validators="number", default=str(DEFAULT_THREADS))
    print()
    subfinder = SubFinder()
    found = subfinder.run(domains, output_file, sources,
                          threads=int(threads or DEFAULT_THREADS), mode=mode) or set()
    if brute and domains:
        from .wildcard import expand_wildcards
        extra = expand_wildcards(domains, drop_dns_wildcards=True) - found
        if extra:
            with open(output_file, 'a', encoding='utf-8') as f:
                f.write('\n'.join(sorted(extra)) + '\n')
        print(f" DNS check added {len(extra)} new host(s) -> {output_file}")
