# BugScanX - continuation patch ("ZL" update)

Community continuation of the discontinued bugscanx host checker.

## 1.5.1 - subdomain finder: no more "only the first domains get results"

Free sources (crt.sh, CertSpotter, urlscan, RapidDNS, Wayback ...) block an
IP that sends dozens of parallel queries. The finder fired all of them at
once, so after the first 10-30 domains every source answered "429 Too Many
Requests" and the rest of the list came back empty - silently.

- **Per-source pacing**: each source has its own limit on parallel requests
  and a minimum gap between requests (urlscan: 30/min, etc.).
- **429 = cooldown, not retry-in-place**: `Retry-After` is honoured; the
  source pauses and the lookup is **retried later** instead of being lost.
- **Retry rounds**: lookups refused with "rate limited" or "busy" are re-run
  after the main pass, once the sources have cooled down (Thorough: 2 rounds of up
  to 3 min each, Fast: 1 round of 45 s).
- **Busy-source breaker**: after 4 timeouts / 5xx in a row a source (usually
  crt.sh) pauses and its remaining lookups move to the retry round instead of
  each wasting minutes now. crt.sh timeout 90 s -> 60 s (it gives up at 60 s
  on its side anyway).
- **Dead sources are skipped**: HackerTarget "API count exceeded" (daily free
  quota), AlienVault "anonymous access is limited" and a quota that keeps
  answering with a long Retry-After (CertSpotter) disable that source for the
  run, with one message instead of hundreds of failed requests.
- Responses have a total time cap (a trickling response can no longer hold a
  worker for many minutes).
- **Every domain is reported**, including 0-result ones, with the reason:
  `coinbase.com: 0 subdomains (no answer: Crt.sh busy, Hackertarget daily limit reached)`.
- **Live results**: subdomains are saved and counted the moment any source
  answers (the hits counter moves immediately; Ctrl+C keeps everything).
- **Optional API keys**: `OTX_API_KEY`, `CERTSPOTTER_API_KEY`, `URLSCAN_API_KEY`,
  `C99_API_KEY` (adds C99.nl via its official API; the free web form is
  protected against automation, so it is not scraped).
  AlienVault is only used when `OTX_API_KEY` is set.
- Warning when a list has more than 1,000 domains (free sources make that
  take many hours).

## 1.5.0 - ZL Scanner suite (menu 10)

New main-menu entry **[10] ZL SCANNER** with nine scanners:

1. **IP scanner** - one prompt takes an IP, CIDR (`104.18.0.0/16`), a
   comma list, or a `file.txt` of CIDRs; shows the IP count before scanning.
2. **Reverse IP** - IP -> hostnames. Two new sources: HackerTarget reverse
   IP API and local PTR lookup (works when the web sources are down).
   Fixed a hang: the YouGetSignal request had no timeout.
3. **Subdomain scanner** - file of domains -> subdomains (deduplicated by main
   domain, Thorough/Fast source mode).
4. **Normal domain scanner** - file of domains -> code / server / IP per domain.
5. **Proxy scanner** - file of `ip:port` proxies; tests HTTP GET through the
   proxy and/or a CONNECT tunnel (what SSH apps use) and lists the working
   ones with response time. Accepts `http://`, `user:pass@` and IPv6 forms.
6. **Unlimited scanner** - for ISPs that freeze while scanning: uses
   `hostname : ip` input (no DNS during the scan), low concurrency, optional
   per-request delay, and a freeze guard that pauses, waits for the network to
   return and re-tests everything that failed during the freeze. A run of dead
   hosts on a working network is detected as a false alarm and does not pause.
7. **Normal domain scanner (alt method)** - same goal as 4 using raw sockets
   (no requests pool, no body download, hard timeouts).
8. **Hostname : IP creator** - resolves a domain list into a
   `hostname : ip` file for option 6 (first IP or all IPs, duplicates removed).
9. **TLS scanner** - TLS/SNI handshake on 443; accepts plain hosts or
   `hostname : ip` lines (handshake goes straight to that IP with the host as SNI).

All of them use the shared engine: live progress, one Ctrl+C stops, failure
summary, Append/Overwrite/Cancel for existing output files. 32 new tests
(local HTTP server + fake proxy + simulated network freeze).

## 1.4.0 - accuracy, coverage and speed

Package renamed to **`bugscanx-zl`** (was `bugscan-x`) so updates can no
longer replace ZL with the original PyPI release. Requires **Python 3.9+**.
Uninstall the old package first: `pip uninstall bugscan-x`.

### Subdomain finder (menu 2 and the host-scanner expansion step)

1. **crt.sh actually returns results now**
   - crt.sh, usually the biggest source, needs 20-60 s for mid-size domains.
     The ZL2 3 s/6 s timeout made it silently return nothing for exactly the
     domains with the most subdomains. The "~1000 domains/min" figure in
     ZL2 was reached largely because of that.
   - It now gets a 90 s timeout, two retries when busy (502/503) and a
     lighter unexpired-certificates fallback.
   - Live test: tesla.com went from 139 to 651 subdomains, hackerone.com
     from 22 to 30.
2. **Sources**: added Wayback Machine and urlscan; CertSpotter reads up to
   10 pages; AnubisDB removed (jldc.me now returns 403). HackerTarget's
   "API count exceeded" text is no longer treated as a result.
3. **Thorough / Fast modes**: Thorough waits for slow sources (most
   subdomains); Fast uses short timeouts and skips Wayback (much quicker,
   can miss names).
4. **Optional DNS check** of ~90 common names (menu 2), ignoring domains
   that answer for any name.
5. Results are lowercased and cleaned (trailing dots, e-mail addresses and
   other junk removed). Failed or rate-limited sources are listed at the end.
6. Domain grouping uses the Public Suffix List (`tldextract`, offline), so
   e.g. `a.example.com.lk` -> `example.com.lk`; bare suffixes such as
   `co.uk` or `github.io` are never enumerated. The domain list is shown
   before enumeration starts.

### Host scanner

1. **Response checks ~45x faster**: Direct and ProxyRoute read only the
   status line and headers instead of downloading every page body. Each
   host is resolved once instead of once per port and method. Local
   benchmark: 120 hosts 49.7 s -> 1.1 s; 4,000 checks in 4.5 s with
   identical results.
2. **HTTP / HTTPS choice**: Auto (HTTPS on 443, 8443, 2053, 2083, 2087,
   2096, 9443), HTTP or HTTPS. Previously only port 443 used HTTPS.
3. **ProxyTest kept losing 101 results**: it read until the server closed
   the socket; websocket upgrades stay open, so the read timed out and the
   hit was dropped. It now stops at the end of the headers.
4. **Accurate progress totals**: blank/comment/wildcard lines are skipped,
   a missing final newline no longer drops the last host, CIDR /31, /32 and
   IPv6 ranges are counted correctly.
5. **Failures are visible**: timeouts, refused connections, DNS, TLS and
   proxy errors are summarised at the end; internal errors are reported.
   `BUGSCANX_DEBUG=1` writes details to `bugscanx-debug.log`.
6. SSL mode states that certificates aren't verified and offers a
   trusted-certificates-only option; Ping and SSL work over IPv6.
7. Fixed a crash when no input file or CIDR range was given; port lists
   such as `80, 443` are trimmed.

### Other

- **Port scanner** now includes port 65535; Ctrl+C stops immediately.
- **No silent overwrites**: existing output files prompt Append /
  Overwrite / Cancel; output can't be the same file as the input.
- **Updater** pulls only from this repository (`git pull` in a clone,
  otherwise `pip install git+...`). `GITHUB_TOKEN` is needed while the repo
  is private.
- Subdomain data sources are now checked with TLS certificate verification
  (`BUGSCANX_INSECURE_SOURCES=1` to disable).
- 70 automated tests, run by GitHub Actions on Python 3.9-3.13.

## Version

1.4.0

---

## Earlier ZL releases

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
     merged in at the end (de-duplicated) - one file,
     nothing extra to clean up.

6. **Wildcard expansion**
   - `*.example.com` cert finds (and literal `*.` lines already sitting in
     your hosts file) are no longer dropped. For every wildcard base the
     tool DNS-probes ~90 common prefixes (www, api, m, dev, vpn, cdn, ...)
     and whatever resolves is added to the expanded list as a real,
     scannable host.
   - Bases that resolve even for a random name are flagged in the output
     as DNS wildcards (every name answers there).

## Version

1.3.0-zl2
