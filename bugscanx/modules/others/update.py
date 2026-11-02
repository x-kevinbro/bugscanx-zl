"""Self-update for the BugScanX-ZL fork.

The original updater ran `pip install --upgrade bugscan-x`, i.e. it pulled
the *upstream* package from PyPI and silently replaced every ZL change. This
version only ever updates from the ZL fork's own Git repository:

- running from a git clone  -> `git pull --ff-only` in that clone
- installed with pip        -> `pip install --upgrade git+<fork repo>@<branch>`

Override the source with BUGSCANX_ZL_REPO / BUGSCANX_ZL_BRANCH. For a
private repository set GITHUB_TOKEN so the version check can read it.
"""

import os
import subprocess
import sys
import time
from dataclasses import dataclass
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

from packaging.version import InvalidVersion, parse as parse_version
from rich.console import Console

from bugscanx.utils.prompts import get_confirm

PACKAGE_NAME = "bugscanx-zl"
UPSTREAM_PACKAGE = "bugscan-x"
DEFAULT_REPO = "https://github.com/x-kevinbro/bugscanx-zl"
DEFAULT_BRANCH = "main"


def _strip_git(url):
    return url[:-4] if url.endswith(".git") else url


def repo_url():
    return _strip_git(os.environ.get("BUGSCANX_ZL_REPO", DEFAULT_REPO).rstrip("/"))


def repo_branch():
    return os.environ.get("BUGSCANX_ZL_BRANCH", DEFAULT_BRANCH)


def raw_version_url(repo=None, branch=None):
    """https://github.com/owner/name -> raw VERSION file URL (GitHub only)."""
    repo = _strip_git((repo or repo_url()).rstrip("/"))
    branch = branch or repo_branch()
    prefix = "https://github.com/"
    if not repo.startswith(prefix):
        return None
    owner_name = repo[len(prefix):]
    return f"https://raw.githubusercontent.com/{owner_name}/{branch}/VERSION"


def git_checkout_root():
    """Repo root if bugscanx is running from a git clone, else None."""
    root = Path(__file__).resolve().parents[3]
    return root if (root / ".git").exists() else None


@dataclass
class VersionInfo:
    current_version: str
    latest_version: str = None


class VersionManager:
    def __init__(self, package_name=PACKAGE_NAME):
        self.package_name = package_name
        self.console = Console()

    def current_version(self):
        root = git_checkout_root()
        if root and (root / "VERSION").is_file():
            return (root / "VERSION").read_text(encoding="utf-8").strip()
        try:
            return version(self.package_name)
        except PackageNotFoundError:
            return "0"

    def upstream_installed(self):
        try:
            version(UPSTREAM_PACKAGE)
            return True
        except PackageNotFoundError:
            return False

    def fetch_latest_version(self):
        import requests

        url = raw_version_url()
        if not url:
            return None
        headers = {}
        token = os.environ.get("GITHUB_TOKEN")
        if token:
            headers["Authorization"] = f"token {token}"
        try:
            resp = requests.get(url, headers=headers, timeout=10)
        except requests.RequestException as exc:
            self.console.print(f"[red] Could not reach GitHub: {exc}")
            return None
        if resp.status_code == 200:
            return resp.text.strip()
        if resp.status_code == 404:
            self.console.print(
                "[red] Could not read the remote VERSION file. If the repository is "
                "private, set GITHUB_TOKEN and try again.")
        else:
            self.console.print(f"[red] Version check failed (HTTP {resp.status_code})")
        return None

    def check_updates(self):
        if self.upstream_installed():
            self.console.print(
                f"[yellow] Warning: the upstream '{UPSTREAM_PACKAGE}' package is also "
                f"installed and provides the same 'bugscanx' module. Remove it with: "
                f"pip uninstall {UPSTREAM_PACKAGE}")

        current = self.current_version()
        with self.console.status("[yellow]Checking for updates...", spinner="dots"):
            latest = self.fetch_latest_version()
        if not latest:
            return None
        try:
            newer = parse_version(latest) > parse_version(current)
        except InvalidVersion:
            self.console.print(f"[red] Unrecognised version string: {latest!r}")
            return None
        if not newer:
            self.console.print(f"[green] You're up to date: {current}")
            return None
        return VersionInfo(current_version=current, latest_version=latest)

    def update_commands(self):
        root = git_checkout_root()
        if root:
            return [["git", "-C", str(root), "pull", "--ff-only"]]
        return [[
            sys.executable, "-m", "pip", "install", "--upgrade",
            f"git+{repo_url()}.git@{repo_branch()}",
        ]]

    def install_update(self):
        try:
            with self.console.status("[yellow]Installing update...", spinner="point"):
                for cmd in self.update_commands():
                    subprocess.run(cmd, capture_output=True, text=True,
                                   check=True, timeout=180)
            self.console.print("[green] Update successful!")
            return True
        except subprocess.CalledProcessError as e:
            detail = (e.stderr or e.stdout or "").strip().splitlines()[-1:] or [str(e)]
            self.console.print(f"[red] Installation failed: {detail[0]}")
        except Exception as e:
            self.console.print(f"[red] Installation failed: {e}")
        return False

    def restart_application(self):
        self.console.print("[yellow] Restarting application...")
        time.sleep(1)
        os.execv(sys.executable, [sys.executable] + sys.argv)


def main():
    manager = VersionManager()
    try:
        info = manager.check_updates()
        if not info:
            return
        manager.console.print(
            f"[yellow] Update available: {info.current_version} → {info.latest_version}"
            f" [dim](from {repo_url()} @ {repo_branch()})[/dim]")
        if not get_confirm(" Update now"):
            return
        if manager.install_update():
            manager.restart_application()
    except KeyboardInterrupt:
        manager.console.print("[yellow] Update cancelled by user.")
    except Exception as e:
        manager.console.print(f"[red] Error during update process: {e}")
