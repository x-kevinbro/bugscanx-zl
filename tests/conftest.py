import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))


import pytest as _pytest


@_pytest.fixture(autouse=True)
def _fresh_source_limiters():
    from bugscanx.modules.scrapers.subfinder.utils import reset_limiters
    reset_limiters()
    yield
    reset_limiters()
