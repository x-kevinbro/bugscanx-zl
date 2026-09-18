import os
import threading

from bugscanx.modules.scanners.scanners.multithread import MultiThread
from bugscanx.utils.prompts import get_input
from .logger import SubFinderConsole
from .sources import get_sources
from .utils import DomainValidator

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

    def __init__(self, domains, sources, output_file, threads=DEFAULT_THREADS):
        super().__init__(threads=threads)
        self.domains = domains
        self.sources = sources
        self.output_file = output_file
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

    def init(self):
        os.makedirs(os.path.dirname(self.output_file) or '.', exist_ok=True)
        with self._save_lock:
            with open(self.output_file, 'w', encoding='utf-8'):
                pass  # start every run with a fresh output file

    def task(self, payload):
        domain, source = payload
        self.progress(f"{source.name} {domain}")

        try:
            found = source.fetch(domain)
            found = DomainValidator.filter_valid_subdomains(found, domain)
        except Exception:
            found = set()

        if found:
            with self._lock:
                self._results[domain].update(found)

        save_now = None
        with self._lock:
            self._pending[domain] -= 1
            if self._pending[domain] == 0:
                self._domains_done += 1
                save_now = self._results.pop(domain)
                self._all.update(save_now)
                self._success_count += len(save_now)

        if save_now:
            self._save_domain(save_now)
            self.logger.log(self.logger.colorize(
                f"{domain}: {len(save_now)} subdomains", 'GREEN'))

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
        with self._lock:
            remaining = [subs for subs in self._results.values() if subs]
            self._results.clear()
        for subs in remaining:
            self._all.update(subs)
            self._save_domain(subs)

    def complete(self):
        super().complete()
        self.logger.log(self.logger.colorize(
            f"Total: {len(self._all)} subdomains - saved to {self.output_file}",
            'GREEN'))

    def interrupted(self):
        self._flush_partial()
        super().interrupted()
        self.logger.log(self.logger.colorize(
            f"Partial results kept: {len(self._all)} subdomains - "
            f"saved to {self.output_file}", 'YELLOW'))


class SubFinder:
    def __init__(self):
        self.console = SubFinderConsole()

    def run(self, domains, output_file, sources, threads=DEFAULT_THREADS):
        domains = [d for d in dict.fromkeys(domains)
                   if DomainValidator.is_valid_domain(d)]
        if not domains:
            self.console.print_error("No valid domains provided")
            return set()

        engine = SubFinderEngine(domains, sources, output_file, threads=threads)
        engine.start()
        return set(engine._all)


def main():
    domains = []
    sources = get_sources()
    input_type = get_input("Select input mode", input_type="choice", choices=["Manual", "File"])
    if input_type == "Manual":
        domain_input = get_input("Enter domain(s)", validators="required")
        domains = [d.strip() for d in domain_input.split(',') if DomainValidator.is_valid_domain(d.strip())]
        default_output = f"{domains[0]}_subdomains.txt" if domains else "subdomains.txt"
    else:
        file_path = get_input("Enter filename", input_type="file", validators="file")
        with open(file_path, 'r') as f:
            domains = [d.strip() for d in f if DomainValidator.is_valid_domain(d.strip())]
        default_output = f"{file_path.rsplit('.', 1)[0]}_subdomains.txt"

    output_file = get_input("Enter output filename", default=default_output, validators="required")
    threads = get_input("Enter threads", validators="number", default=str(DEFAULT_THREADS))
    print()
    subfinder = SubFinder()
    subfinder.run(domains, output_file, sources, threads=int(threads or DEFAULT_THREADS))
