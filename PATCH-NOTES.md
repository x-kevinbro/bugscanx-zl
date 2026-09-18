# BugScanX - continuation patch ("ZL" update)

Community continuation of the discontinued bugscanx host checker.

## What was fixed

1. **Scanner freeze ("stuck when scanning")**
   - Root cause: `socket.gethostbyname()` was called with no timeout in
     `direct.py` and `ssl.py`. A hung/dead DNS resolver (common on Termux
     and mobile hotspots) froze worker threads forever, and the task queue
     never emptied -> the whole scan looked dead.
   - Fix: new `bugscanx/utils/domains.py::resolve_host()` resolves DNS in a
     daemon thread with a hard timeout. Worst case per host is now a few
     seconds, then the scan moves on.

2. **Progress crash on non-tty shells**
   - `os.get_terminal_size()` raised `OSError` when stdout was not a
     terminal; because `progress()` ran before each request, every task
     died silently in non-tty sessions (pipes, `nohup`, some CI).
   - Fix: falls back to 80 columns when there is no terminal.

3. **SSL scanner modernized**
   - `ssl.PROTOCOL_TLS` (deprecated, fails against some modern servers)
     replaced with a proper default context with verification disabled,
     so TLS-1.3-only hosts handshake correctly for SNI probing.

4. **Ctrl+C now actually stops the scan**
   - Root cause: the worker threads are daemons; the first Ctrl+C only
     returned to the menu while up to 5,000 queued tasks kept scanning
     in the background ("it won't stop").
   - Fix: a stop event + instant queue drain - one Ctrl+C halts the scan
     immediately, in every scanner mode.

## New feature: auto subfinder on host files (host checker)

When you select a hosts txt file in HOST SCANNER (any mode):

1. Each line is normalized (`https://m.instagram.com:443/x` ->
   `m.instagram.com`).
2. The MAIN domain is extracted per line (`m.instagram.com` ->
   `instagram.com`, public-suffix aware).
3. Every main domain is enumerated **only once** - if the file contains
   `m.instagram.com` and `login.instagram.com`, `instagram.com` is scanned
   one time and the second line is reported as skipped.
4. Subdomains are saved to `<name>_subdomains.txt` and the merged scan list
   (your hosts + found subdomains, de-duplicated) is written to
   `<name>_expanded.txt`, which the scanner then uses as its input.
5. The step is optional - a yes/no prompt lets you skip it and scan the
   raw file exactly like before.

## Version

1.3.0-zl1

## ZL2 update - subdomain engine speed + live progress

1. **SubFinder rebuilt for speed (~1000 domains/min)**
   - Old engine: only 3 domains at a time, each waiting for its slowest
     source (10s timeout) -> ~18 domains/min worst case.
   - New engine: every (domain x source) query is one task in a single
     150-thread pool (default, adjustable). A slow source occupies only its
     own worker for a few seconds - hard 3s connect / 6s read timeouts -
     and never stalls the run.
   - One keep-alive HTTP session per worker thread (thread-local), so
     hundreds of workers fetch concurrently without session races.

2. **Progress display can never freeze again (all scanners)**
   - A dedicated reporter thread repaints the status line every 0.25s
     straight from the counters: percent, done/total, hits, tasks/min, ETA,
     current item. Workers no longer write to the terminal mid-task (that
     lock contention both froze the display and slowed the scan).
   - Workers no longer die on a 1s empty-queue timeout - sentinel shutdown
     keeps the pool at full width for the whole scan (this caused the
     "stuck at 0 -> jumps to 20000 -> complete" pattern).

3. **Ctrl+C truly instant everywhere**
   - Stop at any point (feeding, joining, mid-request) <= ~1s, partial
     subdomain results are flushed to the output file, no traceback.

4. **Bug fixes**
   - SSL scanner: added the missing `import socket` - SSL mode was
     silently scanning nothing at all.
   - ProxyRoute: added missing `DEFAULT_RETRY` and interruptible `sleep()`
     (retry path crashed every failed request); user timeout now respected.
   - Direct scanner: per-thread keep-alive sessions instead of one fresh
     connection per request.
   - Default host-scanner threads prompt raised 50 -> 100.

5. **One output file for subdomain expansion**
   - `<name>_subdomains.txt` is no longer created. SubFinder streams new
     finds straight into `<name>_expanded.txt` and your original hosts are
     merged in at the end (de-duplicated, wildcards removed) - one file,
     nothing extra to clean up.

## Version

1.3.0-zl2
