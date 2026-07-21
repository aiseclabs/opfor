"""Deterministic product fingerprinting, the identify seam's first pass before the model.

A high-signal marker names a known product without a model call, and a version header gives
its exact version. A miss returns empty so the caller falls to the model, and a version that
no longer looks like one is dropped rather than reported wrong, so a stale table identifies
less, never wrong.
"""

from __future__ import annotations

import re
from pathlib import Path

from opfor.scenarios.attacksurface.assets.domain import KNOWLEDGE
from opfor.scenarios.attacksurface.assets.domain.sources import fingerprint, load_services
from opfor.scenarios.attacksurface.assets.domain.sources.fingerprint import Fingerprint

_TABLE = load_services(KNOWLEDGE / "technologies" / "services")


def test_shipped_table_loads():
    assert _TABLE, "the shipped fingerprints/ tree should load a non-empty service table"


def test_jenkins_header_gives_product_and_version():
    got = fingerprint("host ci.example.com\nheader x-jenkins: 2.426.1\n", _TABLE)
    assert got["product"] == "Jenkins"
    assert got["cpe"] == "jenkins:jenkins"
    assert got["version"] == "2.426.1"


def test_kibana_identifies_by_name_header_and_versions_from_status():
    # Kibana 8.x dropped the kbn-version response header, so it is identified by the kbn-name
    # header and versioned from the /api/status JSON its probe_paths reach, as captured real.
    got = fingerprint('header kbn-name: node-1\nheader kbn-license-sig: abc\n'
                      'path /api/status body: {"version":{"number":"8.15.0","build_number":76360}}', _TABLE)
    assert got["product"] == "Kibana"
    assert got["cpe"] == "elastic:kibana"
    assert got["version"] == "8.15.0"


def test_marker_match_without_a_version_is_product_only():
    got = fingerprint('header x-gitlab-meta: {"correlation_id":"abc","version":"1"}', _TABLE)
    assert got["product"] == "GitLab"
    assert got["version"] == ""


def test_a_bare_product_word_in_body_text_does_not_misidentify():
    # a page that merely mentions a product must not be fingerprinted as running it, which would
    # feed a wrong CPE to the CVE lookup and short-circuit the model, so markers stay high-signal
    assert fingerprint("title Blog\nbody head: we monitor with grafana and deploy via gitlab", _TABLE) == {}


def test_a_host_that_matches_nothing_returns_empty():
    assert fingerprint("host app.example.com\nserver nginx\ntitle Welcome", _TABLE) == {}


def test_matching_is_case_insensitive():
    got = fingerprint("HEADER X-JENKINS: 2.426.1", _TABLE)
    assert got["product"] == "Jenkins"


def test_a_version_capture_that_is_not_a_version_is_dropped():
    # A marker matches but the version pattern captures a value that no longer looks like a
    # version, so the product is reported without a version rather than with a wrong one.
    table = (Fingerprint(name="Widget", cpe="acme:widget", markers=("widget",),
                         version=re.compile(r"widget[- ](\d+)")),)
    got = fingerprint("server widget-7", table)
    assert got == {"product": "Widget", "version": "", "cpe": "acme:widget"}


def test_a_missing_file_is_an_empty_table():
    assert load_services(Path("/no/such/fingerprints")) == ()


def test_first_match_wins_by_table_order():
    table = (
        Fingerprint(name="Specific", cpe="a:specific", markers=("acme dashboard",)),
        Fingerprint(name="General", cpe="a:general", markers=("acme",)),
    )
    assert fingerprint("title Acme Dashboard", table)["product"] == "Specific"


def test_compose_falls_to_the_model_on_a_miss():
    # The identify seam tries the table first, then the model. A table hit is used whole, a
    # miss falls through to the model, mirroring the wrap the domain class builds in assemble.
    def model(evidence):
        return {"product": "Bespoke", "version": "", "cpe": ""}

    def identify(evidence):
        return fingerprint(evidence, _TABLE) or model(evidence)

    assert identify("header x-jenkins: 2.426.1")["product"] == "Jenkins"
    assert identify("server nginx\ntitle Home")["product"] == "Bespoke"
