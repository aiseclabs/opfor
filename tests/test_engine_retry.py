"""The engine retries a transient failure and bounds a hung task with a wall-clock.

A transient failure, a rate limit or a timeout, is a momentary blip, so a bounded retry recovers it
rather than dropping the whole result. A real failure is not retried and stays loud. A task that
never returns is abandoned at a deadline so it cannot stall the run, invariant 3 and 5.
"""

from __future__ import annotations

import threading
import urllib.error

import pytest

from opfor.core import Done, Failed, Task, World
from opfor.core.engine import _attempt
from opfor.core.transient import is_transient

_TASK = Task(capability="x", node="n")


class _Cap:
    """A fake capability that returns or raises a scripted outcome per call, last one repeating."""

    def __init__(self, outcomes) -> None:
        self._outcomes = list(outcomes)
        self.calls = 0

    def run(self, task, world):
        self.calls += 1
        outcome = self._outcomes[min(self.calls - 1, len(self._outcomes) - 1)]
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome


def _http(code):
    return urllib.error.HTTPError("u", code, "m", {}, None)


def test_is_transient_classifies_blips_not_real_errors():
    assert is_transient(_http(429)) and is_transient(_http(503))
    assert not is_transient(_http(404))
    assert is_transient(TimeoutError()) and is_transient(ConnectionResetError())
    assert not is_transient(ValueError("real"))


def test_a_transient_failure_is_retried_then_succeeds():
    cap = _Cap([Failed(reason="429", transient=True), Failed(reason="429", transient=True), Done(facts=())])
    out = _attempt(cap, _TASK, World(), max_retries=2, timeout=5.0, backoff=0.0)
    assert isinstance(out, Done) and cap.calls == 3


def test_a_transient_failure_that_never_recovers_is_terminal_and_loud():
    cap = _Cap([Failed(reason="429 too many", transient=True)])
    out = _attempt(cap, _TASK, World(), max_retries=2, timeout=5.0, backoff=0.0)
    assert isinstance(out, Failed) and not out.transient
    assert "429 too many" in out.reason and "attempts" in out.reason and cap.calls == 3


def test_a_real_failure_is_not_retried():
    cap = _Cap([Failed(reason="refused, not a blip")])
    out = _attempt(cap, _TASK, World(), max_retries=2, timeout=5.0, backoff=0.0)
    assert isinstance(out, Failed) and cap.calls == 1


def test_a_transient_exception_is_retried_then_becomes_a_terminal_failure():
    cap = _Cap([TimeoutError("certspotter slow")])
    out = _attempt(cap, _TASK, World(), max_retries=1, timeout=5.0, backoff=0.0)
    assert isinstance(out, Failed) and "attempts" in out.reason and cap.calls == 2


def test_a_real_exception_propagates_as_a_task_error():
    cap = _Cap([ValueError("a bug, not a blip")])
    with pytest.raises(ValueError):
        _attempt(cap, _TASK, World(), max_retries=2, timeout=5.0, backoff=0.0)
    assert cap.calls == 1


def test_a_hung_task_is_abandoned_at_the_wall_clock_and_fails_loud():
    release = threading.Event()

    class Hang:
        def run(self, task, world):
            release.wait()  # never returns before the deadline

    out = _attempt(Hang(), _TASK, World(), max_retries=1, timeout=0.05, backoff=0.0)
    release.set()  # let the abandoned daemon threads exit
    assert isinstance(out, Failed) and "attempts" in out.reason
