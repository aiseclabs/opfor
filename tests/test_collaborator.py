import urllib.request

import pytest

from opfor.engine.collaborator import Collaborator


@pytest.fixture
def collab():
    c = Collaborator().start()
    try:
        yield c
    finally:
        c.stop()


def test_token_is_unique_and_unguessable(collab):
    a, b = collab.register(), collab.register()
    assert a != b
    assert len(a) > 16  # not a trivially guessable counter


def test_unhit_token_is_not_confirmed(collab):
    token = collab.register()
    assert collab.was_hit(token) is False


def test_callback_to_token_url_is_recorded(collab):
    # Simulate a vulnerable target fetching the OOB URL we injected.
    token = collab.register("ssrf")
    url = collab.url_for(token)
    urllib.request.urlopen(url, timeout=5).read()
    assert collab.was_hit(token) is True
    assert collab.hits(token)[0]["method"] == "GET"


def test_only_the_hit_token_is_confirmed(collab):
    hit, miss = collab.register(), collab.register()
    urllib.request.urlopen(collab.url_for(hit), timeout=5).read()
    assert collab.was_hit(hit) is True
    assert collab.was_hit(miss) is False


def test_public_base_overrides_local_address():
    c = Collaborator(public_base="https://oob.example.net").start()
    try:
        token = c.register()
        assert c.url_for(token) == f"https://oob.example.net/{token}"
    finally:
        c.stop()
