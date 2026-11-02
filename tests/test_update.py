from bugscanx.modules.others import update


def test_raw_version_url_for_fork():
    assert update.raw_version_url("https://github.com/x-kevinbro/bugscanx-zl", "main") == \
        "https://raw.githubusercontent.com/x-kevinbro/bugscanx-zl/main/VERSION"
    assert update.raw_version_url("https://github.com/x-kevinbro/bugscanx-zl.git", "dev") == \
        "https://raw.githubusercontent.com/x-kevinbro/bugscanx-zl/dev/VERSION"
    assert update.raw_version_url("https://gitlab.com/x/y", "main") is None


def test_pip_update_targets_the_fork_not_pypi(monkeypatch):
    monkeypatch.setattr(update, "git_checkout_root", lambda: None)
    monkeypatch.delenv("BUGSCANX_ZL_REPO", raising=False)
    monkeypatch.delenv("BUGSCANX_ZL_BRANCH", raising=False)
    (cmd,) = update.VersionManager().update_commands()
    assert cmd[-1] == "git+https://github.com/x-kevinbro/bugscanx-zl.git@main"
    assert "bugscan-x" not in cmd


def test_git_checkout_uses_git_pull(monkeypatch, tmp_path):
    monkeypatch.setattr(update, "git_checkout_root", lambda: tmp_path)
    (cmd,) = update.VersionManager().update_commands()
    assert cmd[:2] == ["git", "-C"] and cmd[-2:] == ["pull", "--ff-only"]


def test_package_name_is_distinct_from_upstream():
    assert update.PACKAGE_NAME != update.UPSTREAM_PACKAGE
