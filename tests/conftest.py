"""Test-wide fixtures.

The engine retries a transient failure with a backoff sleep between attempts. A test exercises
that path to prove a run still closes and stays loud, so the sleep is zeroed suite-wide, the retry
logic still runs, it just does not wait, and the suite does not spend real seconds sleeping.
"""

from __future__ import annotations

import time

import pytest


@pytest.fixture(autouse=True)
def _no_backoff_sleep(monkeypatch):
    monkeypatch.setattr(time, "sleep", lambda *args, **kwargs: None)
