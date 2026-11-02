<div align="center">
    <img src="https://raw.githubusercontent.com/FreeNetLabs/bugscanx/refs/heads/main/assets/logo.png" width="128" height="128"/>
    <h1>BugScanX-ZL</h1>
    <p><b>All-in-One Tool for Finding SNI Bug Hosts</b></p>
    <p><sub>Community continuation ("ZL") of <a href="https://github.com/FreeNetLabs/bugscanx">BugScanX</a> by Ayan Rajpoot</sub></p>
</div>

<p align="center">
    <img src="https://img.shields.io/badge/version-1.5.0-8ccf7e?labelColor=1e2528&style=for-the-badge"/>
    <img src="https://img.shields.io/badge/python-3.9%2B-67b0e8?labelColor=1e2528&style=for-the-badge"/>
    <img src="https://img.shields.io/badge/license-MIT-f39c12?labelColor=1e2528&style=for-the-badge"/>
</p>

## 🎯 Overview

**BugScanX-ZL** is a bug host discovery tool for finding working SNI/HTTP hosts suitable for tunneling applications. It continues the original BugScanX with scanner fixes, much better subdomain coverage and faster response checks. See [PATCH-NOTES.md](PATCH-NOTES.md) for every change.

## ✨ Features

### 🎯 Host Scanner

- **Direct / DirectNon302**: HTTP/HTTPS checks with any HTTP method. Choose **Auto / HTTP / HTTPS** (Auto uses HTTPS on 443, 8443, 2053, 2083, 2087, 2096, 9443). Only response headers are read, so big or slow pages don't slow the scan.
- **SSL/SNI**: TLS handshake check, with an optional "trusted certificates only" mode.
- **ProxyTest**: Custom payloads (e.g. websocket upgrade); `101` responses are detected even when the connection stays open.
- **ProxyRoute**: Requests through your own HTTP proxy, with optional authentication.
- **Ping**: TCP connectivity check (IPv4 and IPv6).
- **Auto subdomain expansion**: Pick a hosts file and it finds subdomains of each main domain first (each domain once, public-suffix aware), then scans the merged list.
- End-of-scan summary of failed checks (timeouts, refused, DNS, TLS…), so a broken connection never looks like "no results".

### 🔍 Subdomain Finder

- **Sources**: crt.sh, CertSpotter, RapidDNS, HackerTarget, AlienVault, urlscan and the Wayback Machine.
- **Thorough mode**: waits for slow sources such as crt.sh and retries when they're busy, so it finds the most subdomains.
- **Fast mode**: short timeouts and skips Wayback. Much quicker for big lists, but can miss names.
- **Optional DNS check** of ~90 common names (www, api, mail…) to find hosts missing from public records, ignoring DNS-wildcard domains.
- Never overwrites an existing file without asking (Append / Overwrite / Cancel).

> No tool can find every subdomain. Passive sources only know names that appear in public records (certificates, archives, past scans).

### 🌐 IP Lookup, 🚪 Port Scanner, 🔎 DNS & Host Info, 📁 File Toolkit

Reverse-IP lookup and CIDR processing, a port scanner (common ports or all 1–65535), DNS records, host/CDN/TLS details, and file split/merge/dedupe tools.

### 🧰 ZL Scanner (menu 10)

Nine focused scanners in one sub-menu. Pick an option, enter the IP / CIDR /
proxy or the path to your `file.txt`, and read the results on screen (they are
saved to a file too).

| # | Scanner | Input | Output |
|---|---------|-------|--------|
| 1 | IP scanner | single IP / CIDR (eg `104.18.0.0/16`) or a file with many CIDRs | IPs answering HTTP(S) |
| 2 | Reverse IP | an IP address (or file of IPs) | hostnames linked to that IP (RapidDNS, HackerTarget, YouGetSignal, PTR) |
| 3 | Subdomain scanner | file with domains | subdomains |
| 4 | Normal domain scanner | file with domains | status / server per domain |
| 5 | Proxy scanner | file with proxies, eg `172.22.2.38:80` (use your own ISP proxy) | which proxies work (HTTP GET and/or CONNECT tunnel) |
| 6 | Unlimited scanner | `hostname : ip` file (from option 8) | scan results - for ISPs that freeze while scanning |
| 7 | Normal domain scanner (alt) | file with domains | same goal as 4, raw-socket method |
| 8 | Hostname : IP creator | file with domains | ready-to-use `hostname : ip` file for option 6 |
| 9 | TLS scanner | hosts found by the scanner | TLS/SNI handshake result on port 443 - no extra setup |

**Unlimited scanner (6)** connects straight to the IP from the `hostname : ip`
list (no DNS while scanning), uses low concurrency and hard timeouts, and has a
**freeze guard**: when many probes fail in a row it pauses, waits until the
network answers again, then re-tests every probe that failed during the freeze.

## ⚡ Installation

Requires **Python 3.9+** (works on Termux).

```bash
# 1. Remove the original package if you have it - both provide the
#    same "bugscanx" module and would conflict
pip uninstall -y bugscan-x

# 2. Install BugScanX-ZL from GitHub
pip install git+https://github.com/x-kevinbro/bugscanx-zl.git@main
```

> ⚠️ Do **not** run `pip install bugscan-x` - that installs the original BugScanX from PyPI and replaces ZL.

From a local clone (for development):

```bash
git clone https://github.com/x-kevinbro/bugscanx-zl.git
cd bugscanx-zl
pip install -e ".[test]"
pytest
```

## 🎮 Usage

```bash
bugscanx      # or: bugscan-x, bx
```

**Updating**: use menu **9 UPDATE**. It updates from this repository only (`git pull` in a clone, otherwise `pip install git+…`). While the repository is private, set `GITHUB_TOKEN` so the version check can read it.

## ⚙️ Environment variables

| Variable | Effect |
|---|---|
| `BUGSCANX_DEBUG=1` | Write full error details to `bugscanx-debug.log` |
| `BUGSCANX_INSECURE_SOURCES=1` | Don't verify TLS certificates of subdomain data sources (only behind a proxy you trust) |
| `GITHUB_TOKEN` | Lets the updater read a private repository |
| `BUGSCANX_ZL_REPO` / `BUGSCANX_ZL_BRANCH` | Update from a different repository or branch |

---

<div align="center">
    <p>
        Original project: <a href="https://github.com/FreeNetLabs/bugscanx">FreeNetLabs/bugscanx</a> •
        <a href="https://github.com/Ayanrajpoot10">👨‍💻 Original developer</a> •
        <a href="https://t.me/BugScanX">💬 Telegram</a>
    </p>
    <p><sub>⚠️ This tool is intended for educational and authorized testing purposes only. Only scan hosts you own or have permission to test. Use responsibly and legally.</sub></p>
</div>
