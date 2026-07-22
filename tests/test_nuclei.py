"""Consume a real vendored Nuclei template and evaluate its matchers, offline and deterministic.

The point is that opfor reads the actual upstream template as data and reproduces its fire condition
with its own matcher evaluation, so the template drives the check without the Nuclei binary. The
unsupported cases prove a template opfor cannot yet drive is reported loud, never half-loaded.
"""

from __future__ import annotations

from opfor.scenarios.attacksurface.assets.domain import PATHS
from opfor.scenarios.attacksurface.assets.domain.nuclei import (
    NucleiTemplate,
    UnsupportedTemplate,
    concrete_paths,
    load_templates,
    matcher_summary,
    matches,
    parse_template,
)

_PASSWD = "root:x:0:0:root:/root:/bin/ash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
_TEXT_PLAIN = (("Content-Type", "text/plain; charset=utf-8"),)


def _grafana_template() -> NucleiTemplate:
    template = parse_template((PATHS.nuclei / "CVE-2021-43798.yaml").read_text(encoding="utf-8"))
    assert isinstance(template, NucleiTemplate)
    return template


def test_the_vendored_grafana_template_parses_into_opfor_shapes():
    t = _grafana_template()
    assert t.cve == "CVE-2021-43798" and t.severity == "HIGH"
    assert len(t.requests) == 1
    req = t.requests[0]
    assert req.method == "GET"
    # the three traversal targets the upstream template carries, /etc/passwd first
    assert len(req.paths) == 3 and req.paths[0].endswith("/etc/passwd")
    # status, word (Content-Type header), and regex body matchers, combined with `and`
    assert req.matchers_condition == "and"
    kinds = {m.type for m in req.matchers}
    assert kinds == {"status", "word", "regex"}
    # a GET-only template needs the read-only intrusive tier, not the exploit tier
    assert not t.writes and t.tier == "intrusive"


def test_the_template_matcher_fires_on_a_real_file_read_response():
    req = _grafana_template().requests[0]
    # the affected instance returns /etc/passwd with a text/plain content type and 200
    assert matches(req, status=200, headers=_TEXT_PLAIN, body=_PASSWD)


def test_the_template_matcher_does_not_fire_when_any_and_clause_is_missing():
    req = _grafana_template().requests[0]
    # a 404 fails the status matcher
    assert not matches(req, status=404, headers=_TEXT_PLAIN, body=_PASSWD)
    # a 200 whose body carries no traversal signal fails the regex matcher
    assert not matches(req, status=200, headers=_TEXT_PLAIN, body="<html>login</html>")
    # a 200 with the file body but an html content type fails the header word matcher, so a
    # single-page-app shell answering every path does not read as a hit
    assert not matches(req, status=200, headers=(("Content-Type", "text/html"),), body=_PASSWD)


def test_concrete_paths_interpolate_the_in_scope_target():
    req = _grafana_template().requests[0]
    urls = concrete_paths(req, "http://localhost:3083")
    assert urls[0] == ("http://localhost:3083/public/plugins/alertlist/"
                       + "../" * 19 + "etc/passwd")


def test_the_matcher_summary_is_faithful_not_a_lossy_substring():
    summary = matcher_summary(_grafana_template().requests[0])
    # the summary carries every clause the template checks, so the finding and the confirm judge
    # see the full fire condition rather than one hand-picked marker
    assert "text/plain" in summary and "root:" in summary and "status" in summary


def test_load_templates_splits_supported_from_unsupported():
    supported, unsupported = load_templates(PATHS.nuclei)
    assert any(t.cve == "CVE-2021-43798" for t in supported)
    assert unsupported == []


def test_a_code_protocol_template_is_refused_outright():
    # consuming a code or javascript protocol would run template-authored code on the scanner, so
    # it is refused rather than driven, whatever else it declares
    template = parse_template(
        "id: CVE-2099-0001\n"
        "info:\n  name: x\n  severity: high\n  classification:\n    cve-id: CVE-2099-0001\n"
        "code:\n  - engine: [python]\n    source: 'print(1)'\n")
    assert isinstance(template, UnsupportedTemplate)
    assert "code" in template.reason


def test_a_dsl_matcher_is_reported_unsupported_with_a_reason():
    template = parse_template(
        "id: CVE-2099-0002\n"
        "info:\n  name: x\n  severity: high\n  classification:\n    cve-id: CVE-2099-0002\n"
        "http:\n  - method: GET\n    path: ['{{BaseURL}}/']\n"
        "    matchers:\n      - type: dsl\n        dsl: ['status_code==200']\n")
    assert isinstance(template, UnsupportedTemplate)
    assert "dsl" in template.reason and template.cve == "CVE-2099-0002"


def test_a_payload_sweep_is_reported_unsupported():
    template = parse_template(
        "id: CVE-2099-0003\n"
        "info:\n  name: x\n  severity: high\n  classification:\n    cve-id: CVE-2099-0003\n"
        "http:\n  - method: GET\n    path: ['{{BaseURL}}/{{fuzz}}']\n"
        "    payloads:\n      fuzz: [a, b]\n"
        "    matchers:\n      - type: status\n        status: [200]\n")
    assert isinstance(template, UnsupportedTemplate)
    assert "payload" in template.reason
