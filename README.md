<div align="center">
    <img src="https://raw.githubusercontent.com/FreeNetLabs/bugscanx/refs/heads/main/assets/logo.png" width="128" height="128"/>
    <h1>BugScanX</h1>
    <p><b>All-in-One Tool for Finding SNI Bug Hosts</b></p>
</div>

<p align="center">
    <img src="https://img.shields.io/github/stars/FreeNetLabs/bugscanx?color=e57474&labelColor=1e2528&style=for-the-badge"/>
    <img src="https://img.shields.io/pypi/dm/bugscan-x?color=67b0e8&labelColor=1e2528&style=for-the-badge"/>
    <img src="https://img.shields.io/pypi/v/bugscan-x?color=8ccf7e&labelColor=1e2528&style=for-the-badge"/>
    <img src="https://img.shields.io/github/license/FreeNetLabs/bugscanx?color=f39c12&labelColor=1e2528&style=for-the-badge"/>
</p>

## 🎯 Overview

**BugScanX** is a specialized bug host discovery tool designed for finding working SNI/HTTP hosts suitable for tunneling applications. It enables users to discover bug hosts that can be used to create configurations for various tunneling and VPN applications, providing unrestricted internet access.

## ✨ Features

### 🎯 Host Scanner

Advanced multi-mode bug host scanning with specialized capabilities:

- **Direct Scanning**: HTTP/HTTPS bug host discovery with custom methods
- **DirectNon302**: Specialized scanning that excludes redirect responses (essential for bug hosts)
- **SSL/SNI Analysis**: TLS/SSL configuration analysis for SNI bug hosts
- **Proxy Testing**: Comprehensive proxy validation for tunneling compatibility
- **Ping Scanning**: Connectivity testing for discovered hosts
- Support for all HTTP methods and custom payload injection
- Multi-threaded concurrent processing

### 🔍 Subdomain Enumeration

Professional subdomain discovery for expanding bug host lists:

- **Passive Discovery**: Leverages multiple API providers and search engines
- **Batch Processing**: Mass domain enumeration from target lists

### 🌐 IP Lookup & Reverse DNS

Comprehensive IP intelligence for bug host clustering:

- **Reverse IP Lookup**: Discover all domains hosted on target IPs
- **CIDR Range Processing**: Bulk analysis of IP ranges
- **Multi-Source Aggregation**: Combines data from multiple sources

### 🚪 Port Scanner

Advanced port scanning for service discovery with common tunneling ports (80, 443, 8080, 8443).

### 🔎 DNS & SSL Analysis

Comprehensive analysis for SNI bug hosts including DNS records and SSL certificate validation.

### 📁 File Management & Processing

Professional-grade file processing with smart splitting, merging, deduplication, and filtering tools.

## ⚡ Quick Start

### 🚀 Installation

```bash
# Install from PyPI
pip install bugscan-x
```

### 🎮 Launch BugScanX

```bash
# Primary command
bugscanx

# Alternative commands
bugscan-x
bx
```

---

<div align="center">
    <h3>Built with ❤️ for the Free Internet Community</h3>
    <p>
        <a href="https://github.com/Ayanrajpoot10">👨‍💻 Developer</a> •
        <a href="https://t.me/BugScanX">💬 Telegram</a> •
        <a href="https://pypi.org/project/bugscan-x/">📦 PyPI</a>
    </p>
    <p><sub>⚠️ This tool is intended for educational and authorized testing purposes only. Use responsibly and legally.</sub></p>
</div>