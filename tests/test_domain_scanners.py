from __future__ import annotations

import json

import pytest

from opfor.core import Budget, MockProvider, Node, Phase, Scope, World, run
from opfor.core.result import CLOSED
from opfor.scenarios.attacksurface import build
from opfor.scenarios.attacksurface.triage import TriageError, _finding_from_dict
from opfor.scenarios.attacksurface.types import Org

from tests.surface_fixtures import *


def test_endpoints_enumerated_and_auth_classified():
    world = _seed()
    _run(world)
    eps = {n.id: n.payload for n in world.nodes("endpoint")}
    assert "endpoint:admin.example.com/.git/config" in eps
    assert eps["endpoint:admin.example.com/metrics"].auth_required is True
    assert eps["endpoint:admin.example.com/.env"].auth_required is False


def test_nvd_cves_parses_id_score_severity_and_summary():
    from opfor.scenarios.attacksurface.classes.domain import sources as domains

    reply = {
        "vulnerabilities": [
            {"cve": {
                "id": "CVE-2021-39226",
                "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}],
                            "cvssMetricV2": [{"cvssData": {"baseScore": 5.0}, "baseSeverity": "MEDIUM"}]},
                "descriptions": [{"lang": "es", "value": "ignore"}, {"lang": "en", "value": "auth bypass"}],
                "references": [{"url": "https://advisory.example/GHSA-1"}, {"url": "https://nvd.example/CVE-2021-39226"}],
            }},
            {"cve": {"id": "", "metrics": {}, "descriptions": []}},
        ]
    }
    cves = domains.cves_from_nvd(reply)
    assert len(cves) == 1
    # the strongest metric wins, v3.1 over v2, the english description is taken, and the
    # advisory links are kept so an exploit poc is anchored to a real source
    assert cves[0] == {
        "id": "CVE-2021-39226", "cvss": 9.8, "severity": "CRITICAL", "summary": "auth bypass",
        "references": ["https://advisory.example/GHSA-1", "https://nvd.example/CVE-2021-39226"]}


def test_nvd_cves_returns_nothing_for_an_unidentified_product():
    from opfor.scenarios.attacksurface.classes.domain import sources as domains

    # no product means nothing to query, an empty list without a network call
    assert domains.nvd_cves("", "1.0") == []


def test_nvd_keyword_search_uses_the_product_alone_not_the_version(monkeypatch):
    """NVD keyword search matches the description text, where a version rarely appears, so
    the query is the product alone, or a version-bearing product would return nothing."""
    from opfor.scenarios.attacksurface.classes.domain import passive as domains

    queries = []
    monkeypatch.setattr(domains, "_nvd_fetch", lambda q: queries.append(q) or [])
    domains.nvd_cves("litellm", "1.90.0")
    assert queries == ["keywordSearch=litellm"]


def test_nvd_falls_back_to_a_product_keyword_when_the_cpe_match_is_empty(monkeypatch):
    """A wrong vendor guess or a cve not tagged with the cpe yields an empty cpe match, so
    the query falls back to a product keyword rather than missing a real advisory."""
    from opfor.scenarios.attacksurface.classes.domain import passive as domains

    queries = []

    def fake_fetch(query):
        queries.append(query)
        if query.startswith("virtualMatchString"):
            return []
        return [{"id": "CVE-2026-40217"}]

    monkeypatch.setattr(domains, "_nvd_fetch", fake_fetch)
    result = domains.nvd_cves("litellm", "1.90.0", cpe="berriai:litellm")
    assert result == [{"id": "CVE-2026-40217"}]
    assert len(queries) == 2
    assert queries[0].startswith("virtualMatchString")
    assert queries[1] == "keywordSearch=litellm"


def test_nvd_cpe_match_with_results_does_not_fall_back(monkeypatch):
    from opfor.scenarios.attacksurface.classes.domain import passive as domains

    queries = []
    monkeypatch.setattr(domains, "_nvd_fetch",
                        lambda q: queries.append(q) or [{"id": "CVE-2020-0001"}])
    result = domains.nvd_cves("grafana", "9.0.0", cpe="grafana:grafana")
    assert result == [{"id": "CVE-2020-0001"}]
    assert len(queries) == 1
    assert queries[0].startswith("virtualMatchString")


def test_nvd_throttle_serializes_calls_to_stay_under_the_rate_limit(monkeypatch):
    from opfor.scenarios.attacksurface.classes.domain import passive as domains

    clock = {"t": 100.0}
    slept = []
    monkeypatch.setattr(domains.time, "monotonic", lambda: clock["t"])
    monkeypatch.setattr(domains.time, "sleep", lambda s: slept.append(s))
    domains._nvd_next[0] = 0.0

    # the first call does not wait, it only schedules the next slot
    domains._nvd_wait(6.0)
    assert slept == []
    # a second call before the interval has passed blocks until the slot opens
    domains._nvd_wait(6.0)
    assert slept and abs(slept[-1] - 6.0) < 0.01


def test_cve_scan_records_the_identified_product_and_its_cves():
    # the identify seam names the product, the cve seam looks it up, and the scan records
    # both as a raw fact, the agent-driven identification feeding the mechanical lookup
    def identify(evidence):
        assert "host" in evidence
        return {"product": "grafana", "version": "8.0.0", "cpe": "grafana:grafana"}

    def cves(product, version, cpe=""):
        assert (product, version, cpe) == ("grafana", "8.0.0", "grafana:grafana")
        return [{"id": "CVE-2021-39226", "cvss": 9.8, "severity": "CRITICAL", "summary": "auth bypass"}]

    report, _scenario, world = _run_capturing(identify_fn=identify, cve_fn=cves)
    scans = [f.payload for f in world.facts("cve_scanned") if f.payload.product]
    assert scans, "expected a cve_scanned fact carrying a product"
    assert scans[0].product == "grafana" and scans[0].version == "8.0.0"
    assert any(c.id == "CVE-2021-39226" and c.severity == "CRITICAL" for c in scans[0].cves)


def test_source_map_parser_detects_inlined_source_and_paths_only():
    from opfor.scenarios.attacksurface.classes.domain import sources as domains

    inlined = json.dumps({"version": 3, "sources": ["../src/app.ts", "../src/api.ts"],
                          "sourcesContent": ["export const x = 1", ""]})
    r = domains.source_map_from_text(inlined)
    assert r["has_sources_content"] is True
    assert r["sources_count"] == 2
    assert "../src/app.ts" in r["sample_sources"]

    # a map that lists paths but inlines no content is a lesser leak, not None
    paths_only = json.dumps({"version": 3, "sources": ["../src/app.ts"], "sourcesContent": [None]})
    assert domains.source_map_from_text(paths_only)["has_sources_content"] is False

    # ordinary json and an empty body are not source maps
    assert domains.source_map_from_text('{"hello": "world"}') is None
    assert domains.source_map_from_text("") is None


def test_source_map_scan_flags_an_inlined_map():
    home = '<script src="/assets/app.abc.js"></script>'
    mapdoc = json.dumps({"version": 3, "sources": ["../src/secret.ts"],
                         "sourcesContent": ["const API_KEY = 'x'"]})

    def fetch_doc(name, path):
        if path == "/":
            return {"text": home}
        if path.endswith(".map"):
            return {"text": mapdoc}
        return {"text": ""}

    report, _scenario, world = _run_capturing(fetch_doc_fn=fetch_doc)
    leaks = [f.payload for f in world.facts("source_maps") if f.payload.leaks]
    assert leaks, "expected a source_maps fact carrying a leak"
    leak = leaks[0].leaks[0]
    assert leak.has_sources_content is True
    assert leak.url.endswith("/assets/app.abc.js.map")


def test_secrets_in_text_matches_patterns_and_redacts():
    from opfor.scenarios.attacksurface.classes.domain import sources as domains

    patterns = [
        {"id": "aws-access-key-id", "regex": "AKIA[0-9A-Z]{16}", "note": "an AWS access key id"},
        {"id": "never", "regex": "ZZZZ[0-9]{40}", "note": "no match"},
    ]
    body = "const k = 'AKIAIOSFODNN7EXAMPLE'; const ok = 1;"
    hits = domains.secrets_in_text(body, patterns)
    assert len(hits) == 1
    assert hits[0]["pattern"] == "aws-access-key-id"
    # the sample is redacted, a prefix and a length, never the full key
    assert "AKIAIOSFODNN7EXAMPLE" not in hits[0]["sample"]
    assert hits[0]["sample"].startswith("AKIAIO")


def test_secret_scan_flags_a_key_in_a_bundle_and_redacts_it():
    home = '<script src="/static/main.js"></script>'
    bundle = "var cfg={awsKey:'AKIAIOSFODNN7EXAMPLE'};"
    patterns = [{"id": "aws-access-key-id", "regex": "AKIA[0-9A-Z]{16}", "note": "an AWS access key id"}]

    def fetch_doc(name, path):
        if path == "/":
            return {"text": home}
        if path == "/static/main.js":
            return {"text": bundle}
        return {"text": ""}

    report, _scenario, world = _run_capturing(fetch_doc_fn=fetch_doc)
    # the planner hands the real patterns from secret_patterns.yaml, which includes the aws
    # key shape, so the scan matches without the test injecting patterns
    hits = [f.payload for f in world.facts("secrets_in_js") if f.payload.matches]
    assert hits, "expected a secrets_in_js fact carrying a match"
    match = hits[0].matches[0]
    assert match.pattern == "aws-access-key-id"
    assert "AKIAIOSFODNN7EXAMPLE" not in match.sample


def test_backup_candidates_derives_twins_and_skips_directories():
    from opfor.scenarios.attacksurface.classes.domain import sources as domains

    twins = domains.backup_candidates(
        "/app/config.php", append=(".bak", "~"), rename=(".zip",), swap=(".{file}.swp",))
    assert "/app/config.php.bak" in twins
    assert "/app/config.php~" in twins
    assert "/app/config.zip" in twins           # the extension is replaced, an archive twin
    assert "/app/.config.php.swp" in twins      # the vim swap dotfile over the filename
    # a directory or a bare root has no filename to derive from
    assert domains.backup_candidates("/app/", append=(".bak",)) == []
    assert domains.backup_candidates("/", append=(".bak",)) == []
    # a file with no extension takes an append twin but no extension-rename twin
    assert domains.backup_candidates("/README", append=("~",), rename=(".zip",)) == ["/README~"]


def test_backup_scan_finds_a_twin_of_an_observed_file():
    home = '<html><body><a href="/config.php">cfg</a></body></html>'
    source = "<?php $db_pass='s3cr3t'; ?>"

    def fetch(name, addresses, path):
        url = f"https://{name}{path}"
        miss = {"status": 404, "url": url, "content_type": "", "server": "", "title": "", "body": ""}
        if name != "admin.example.com":
            return miss
        if path == "/config.php":
            return {"status": 200, "url": url, "content_type": "text/html",
                    "server": "nginx", "title": "", "body": "rendered page"}
        if path == "/config.php.bak":
            return {"status": 200, "url": url, "content_type": "text/plain",
                    "server": "nginx", "title": "", "body": source}
        return miss

    def fetch_doc(name, path):
        if name == "admin.example.com" and path == "/":
            return {"status": 200, "content_type": "text/html", "text": home}
        return {"status": None, "content_type": "", "text": ""}

    report, _scenario, world = _run_capturing(fetch_fn=fetch, fetch_doc_fn=fetch_doc)
    hits = [h for f in world.facts("backups") for h in f.payload.hits]
    assert any(h.url.endswith("/config.php.bak") and h.size > 0 for h in hits), \
        "expected a backups fact carrying the config.php.bak twin"


def test_cloud_bucket_from_url_recognizes_provider_forms():
    from opfor.scenarios.attacksurface.classes.domain import sources as domains

    s3v = domains.cloud_bucket_from_url("https://my-bucket.s3.amazonaws.com/key.txt")
    assert s3v["provider"] == "s3" and s3v["bucket"] == "my-bucket"
    s3r = domains.cloud_bucket_from_url("https://s3.eu-west-1.amazonaws.com/other-bucket/x")
    assert s3r["provider"] == "s3" and s3r["bucket"] == "other-bucket"
    gcs = domains.cloud_bucket_from_url("https://storage.googleapis.com/data-bucket/o")
    assert gcs["provider"] == "gcs" and gcs["bucket"] == "data-bucket"
    # a bare host, the shape a CNAME takes, is recognized without a scheme
    cname = domains.cloud_bucket_from_url("assets-bucket.s3.us-east-2.amazonaws.com")
    assert cname["provider"] == "s3" and cname["bucket"] == "assets-bucket"
    az = domains.cloud_bucket_from_url("https://acct.blob.core.windows.net/container/blob")
    assert az["provider"] == "azure" and az["bucket"] == "acct/container"
    # an azure account with no container cannot be listed, so it is not a bucket here
    assert domains.cloud_bucket_from_url("acct.blob.core.windows.net") is None
    # a non-cloud url is not a bucket
    assert domains.cloud_bucket_from_url("https://example.com/path") is None
    # the reference extractor keeps only cloud-storage hosts
    refs = domains.cloud_refs_in_text('a="https://x.s3.amazonaws.com/k"; b="https://example.com/y"')
    assert refs == ["https://x.s3.amazonaws.com/k"]
    # a public object listing is told apart from a generic 200 page
    assert domains.bucket_listable("<ListBucketResult><Contents>x</Contents></ListBucketResult>")
    assert not domains.bucket_listable("<html>welcome</html>")


def test_bucket_scan_checks_buckets_the_target_reveals_by_cname():
    listing = "<ListBucketResult><Contents><Key>dump.sql</Key></Contents></ListBucketResult>"

    def resolve(name):
        base = _resolve(name)
        if name == "admin.example.com":
            return {**base, "cnames": ("example-backup.s3.amazonaws.com",)}
        if name == "www.example.com":
            return {**base, "cnames": ("example-private.s3.amazonaws.com",)}
        return base

    def probe_url(url):
        if "example-backup.s3" in url:
            return {"status": 200, "url": url, "content_type": "application/xml", "body": listing}
        if "example-private.s3" in url:
            return {"status": 403, "url": url, "content_type": "application/xml", "body": ""}
        return {"status": 404, "url": url, "content_type": "", "body": ""}

    report, _scenario, world = _run_capturing(resolve_fn=resolve, probe_url_fn=probe_url)
    buckets = [b for f in world.facts("buckets") for b in f.payload.buckets]
    listable = [b for b in buckets if b.state == "listable"]
    assert any(b.name == "example-backup" and b.provider == "s3"
               and b.evidence == "CNAME from admin.example.com" for b in listable), \
        "expected the listable example-backup S3 bucket discovered by CNAME"
    assert any(b.name == "example-private" and b.state == "private" for b in buckets), \
        "expected the private example-private bucket"


def test_endpoint_probe_records_a_coverage_gap_when_a_path_errors():
    # one candidate path errors on the probe. The scan still returns the endpoints it
    # reached, but the dropped path is recorded as a coverage gap and surfaced as an INFO
    # finding, so a partial probe is never read as a clean, complete negative, invariant 5.
    def fetch(name, addresses, path):
        if name == "admin.example.com" and path == "/.git/config":
            raise TimeoutError("probe timed out")
        return _fetch(name, addresses, path)

    report, _scenario, world = _run_capturing(fetch_fn=fetch)
    gaps = [f.payload for f in world.facts("coverage_gap") if f.payload.scan == "domain_endpoints"]
    assert any(g.host == "admin.example.com" and g.failed >= 1 for g in gaps), \
        "a probe error must record a coverage_gap fact rather than be silently dropped"
    gap_findings = [f for f in report.findings if f.data.get("kind") == "coverage_gap"]
    assert any(f.severity == "INFO" and "admin.example.com" in f.where for f in gap_findings), \
        "the coverage gap must surface as an INFO finding, so a partial scan reads as partial"
    assert "TimeoutError" in "".join(f.evidence for f in gap_findings)


def test_backup_scan_records_a_coverage_gap_when_a_twin_errors():
    home = '<html><body><a href="/config.php">cfg</a></body></html>'

    def fetch(name, addresses, path):
        url = f"https://{name}{path}"
        miss = {"status": 404, "url": url, "content_type": "", "server": "", "title": "", "body": ""}
        if name != "admin.example.com":
            return miss
        if path == "/config.php":
            return {"status": 200, "url": url, "content_type": "text/html",
                    "server": "nginx", "title": "", "body": "rendered page"}
        if path == "/config.php.bak":
            raise ConnectionResetError("reset during backup twin probe")
        return miss

    def fetch_doc(name, path):
        if name == "admin.example.com" and path == "/":
            return {"status": 200, "content_type": "text/html", "text": home}
        return {"status": None, "content_type": "", "text": ""}

    _report, _scenario, world = _run_capturing(fetch_fn=fetch, fetch_doc_fn=fetch_doc)
    gaps = [f.payload for f in world.facts("coverage_gap") if f.payload.scan == "backup_scan"]
    assert any(g.failed >= 1 and any("ConnectionResetError" in r for r in g.reasons) for g in gaps), \
        "a backup twin probe error must record a coverage_gap rather than vanish"


def test_bucket_scan_records_a_coverage_gap_when_a_probe_errors():
    listing = "<ListBucketResult><Contents><Key>dump.sql</Key></Contents></ListBucketResult>"

    def resolve(name):
        base = _resolve(name)
        if name == "admin.example.com":
            return {**base, "cnames": ("example-backup.s3.amazonaws.com",)}
        if name == "www.example.com":
            return {**base, "cnames": ("example-private.s3.amazonaws.com",)}
        return base

    def probe_url(url):
        if "example-backup.s3" in url:
            return {"status": 200, "url": url, "content_type": "application/xml", "body": listing}
        if "example-private.s3" in url:
            raise TimeoutError("bucket probe timed out")
        return {"status": 404, "url": url, "content_type": "", "body": ""}

    report, _scenario, world = _run_capturing(resolve_fn=resolve, probe_url_fn=probe_url)
    # the reachable bucket is still reported, the errored one is a coverage gap, not a silent drop
    buckets = [b for f in world.facts("buckets") for b in f.payload.buckets]
    assert any(b.name == "example-backup" for b in buckets)
    gaps = [f.payload for f in world.facts("coverage_gap") if f.payload.scan == "bucket_scan"]
    assert any(g.failed >= 1 for g in gaps), \
        "an errored bucket probe must record a coverage_gap rather than be silently skipped"
    assert any(f.data.get("kind") == "coverage_gap" and f.data.get("scan") == "bucket_scan"
               for f in report.findings)


def test_cve_scan_fails_loud_when_identification_errors():
    # a model or lookup error is a loud Failed, never a silent empty result, invariant 5
    def boom(evidence):
        raise RuntimeError("model down")

    report, _scenario, _world = _run_capturing(identify_fn=boom)
    assert any("cve_scan" in note and "model down" in note for note in report.notes)


def test_probe_list_includes_product_identity_and_version_paths():
    from opfor.scenarios.attacksurface.classes import domain as domain_class
    from opfor.scenarios.attacksurface.classes.domain import planner

    # the product identity and version endpoints are data in paths.yaml, probed by the
    # existing endpoint capability, so a later step can read the version for a cve match
    probe_paths = planner.load_plan_config(domain_class.KNOWLEDGE).probe_paths
    for path in ("/actuator/info", "/version", "/.well-known/openid-configuration", "/nacos/"):
        assert path in probe_paths


def test_batch_one_exposure_coverage_is_loaded():
    from opfor.scenarios.attacksurface.classes import domain as domain_class
    from opfor.scenarios.attacksurface.classes.domain import planner
    from opfor.scenarios.attacksurface.triage import _load_classes, _load_clues

    # new fixed-path leaks are probed, pure data in paths.yaml, no code
    probe_paths = planner.load_plan_config(domain_class.KNOWLEDGE).probe_paths
    for path in ("/.ssh/id_rsa", "/web.config", "/backup.sql", "/.git/index", "/.npmrc"):
        assert path in probe_paths

    knowledge = domain_class.KNOWLEDGE
    # new deterministic clues direct the model at the buried signals
    clue_ids = {c["id"] for c in _load_clues(knowledge / "exposures.yaml")}
    assert {"exposed-private-key", "exposed-htpasswd", "exposed-sql-dump"} <= clue_ids
    # new judgment families the model can reach for
    class_ids = {c["id"] for c in _load_classes(knowledge / "classes")}
    assert {"cors-misconfiguration", "verbose-error-disclosure"} <= class_ids


def test_static_assets_are_never_probed_into_endpoints():
    # admin's script names /main.css, a static asset, so it must not become an endpoint
    world = _seed()
    _run(world)
    assert world.node("endpoint:admin.example.com/main.css") is None


def test_soft_200_host_yields_only_its_real_interface():
    # spa answers 200 for every path, so the catch-all filter must keep only the real spec
    world = _seed()
    _run(world)
    spa = sorted(n.id for n in world.nodes("endpoint") if "spa.example.com" in n.id)
    assert spa == ["endpoint:spa.example.com/openapi.json"]


def test_html_posing_as_swagger_is_not_an_endpoint():
    world = _seed()
    _run(world)
    assert world.node("endpoint:spa.example.com/swagger.json") is None


def test_openapi_spec_is_expanded_into_its_operations():
    world = _seed()
    _run(world)
    specs = [f.payload for f in world.facts("api_spec")]
    hit = [s for s in specs if s.base == "https://spa.example.com/openapi.json"]
    assert hit and hit[0].count == 2
    assert "GET /users" in hit[0].paths


def test_graphql_introspection_fact_reads_query_and_mutation():
    world = _seed()
    _run(world)
    schemas = [f.payload for f in world.facts("graphql")]
    hit = [s for s in schemas if s.enabled and s.count == 3]
    assert hit and "query:me" in hit[0].operations


def test_spec_fetch_failure_still_closes_and_is_loud():
    def boom(name, path):
        raise TimeoutError("spec slow")

    scenario = _make(fetch_doc_fn=boom)
    world = _seed()
    report = run(scenario, world, scope=Scope(max_tier="recon", hosts=(ROOT,)), budget=Budget(2000))
    assert report.closed
    assert any("failed" in n and "endpoint_expand_spec" in n for n in report.notes)


def test_paths_from_openapi_names_methods():
    from opfor.scenarios.attacksurface.classes.domain.sources import paths_from_openapi

    doc = {"paths": {"/a": {"get": {}, "post": {}}, "/b": {"get": {}}}}
    assert set(paths_from_openapi(doc)) == {"GET,POST /a", "GET /b"}
    assert paths_from_openapi({}) == []
    assert paths_from_openapi({"paths": "not a map"}) == []


def test_operations_from_introspection_reads_query_and_mutation():
    from opfor.scenarios.attacksurface.classes.domain.sources import operations_from_introspection

    data = {"__schema": {"queryType": {"fields": [{"name": "me"}]},
                         "mutationType": {"fields": [{"name": "login"}]}}}
    assert operations_from_introspection(data) == ["mutation:login", "query:me"]
    assert operations_from_introspection({}) == []


def test_javascript_endpoint_extraction_finds_a_hidden_api():
    # /api/secret is only named inside a script bundle, never linked, so finding it proves
    # the endpoint discovery reads the app's own JavaScript
    world = _seed()
    _run(world)
    assert world.node("endpoint:admin.example.com/api/secret") is not None


def test_cross_host_javascript_path_is_probed_on_the_sibling_host():
    # /v2/balance is named only by a full url inside admin.example.com's script, and it
    # points at api.example.com, so finding it there proves cross-host harvest
    world = _seed()
    _run(world)
    assert world.node("endpoint:api.example.com/v2/balance") is not None


def test_wayback_passive_urls_become_candidates():
    world = _seed()
    _run(world)
    assert world.node("endpoint:www.example.com/legacy") is not None


def test_robots_disallow_paths_become_candidates():
    world = _seed()
    _run(world)
    assert world.node("endpoint:example.com/secret-panel") is not None


def test_javascript_and_url_parsing():
    from opfor.scenarios.attacksurface.classes.domain.sources import (
        paths_in_javascript,
        same_host_path,
        script_sources,
        urls_in_javascript,
    )

    js = 'fetch("/api/v1/users");const a="/static/x.js";x("//cdn/y");u("https://api.h/z")'
    got = paths_in_javascript(js)
    assert "/api/v1/users" in got and "/static/x.js" in got
    assert not any(p.startswith("//") for p in got)
    assert urls_in_javascript(js) == ["https://api.h/z"]
    assert script_sources('<script src="/a.js"></script><script src="https://cdn/b.js">', "h.test") == ["/a.js"]
    assert same_host_path("/p?q=1", "h.test") == "/p"
    assert same_host_path("https://h.test/x", "h.test") == "/x"
    assert same_host_path("https://other/x", "h.test") is None


def test_robots_and_sitemap_parsing():
    from opfor.scenarios.attacksurface.classes.domain.sources import robots_entries, sitemap_paths

    paths, sitemaps = robots_entries("User-agent: *\nDisallow: /admin\nAllow: /public\nSitemap: https://h/sm.xml")
    assert paths == ["/admin", "/public"]
    assert sitemaps == ["https://h/sm.xml"]
    assert sitemap_paths("<urlset><url><loc>https://h.test/a</loc></url></urlset>", "h.test") == ["/a"]


def test_split_operation_separates_methods_from_path():
    from opfor.scenarios.attacksurface.classes.domain.sources import split_operation

    assert split_operation("GET,POST /widgets") == (("GET", "POST"), "/widgets")
    assert split_operation("DELETE,GET /jobs/{job_id}") == (("DELETE", "GET"), "/jobs/{job_id}")
    assert split_operation("/bare-path") == ((), "/bare-path")


def test_probe_spec_verifies_reads_defers_writes_and_skips_templated():
    """A declared operation is not a reachable one, so ProbeSpec fetches each concrete GET
    and leaves write and templated operations for an authorized confirmation."""
    from opfor.core import Fact, Node, Task, World
    from opfor.scenarios.attacksurface.classes.domain.capabilities import ProbeSpec
    from opfor.scenarios.attacksurface.classes.domain.types import (
        APISpec, DomainData, Endpoint, Resolved,
    )

    calls = []

    def fetch(name, addresses, path):
        calls.append(path)
        if path.startswith("/opfor-baseline") or path.startswith("/does-not-exist"):
            return {"status": 404, "content_type": "", "body": "", "location": ""}
        if path == "/config/all":
            return {"status": 200, "content_type": "application/json",
                    "body": '{"ok":true}', "location": ""}
        if path == "/users":
            return {"status": 401, "content_type": "", "body": "", "location": ""}
        return {"status": 404, "content_type": "", "body": "", "location": ""}

    world = World()
    world.add(Node(id="domain:api.example.com", type="domain",
                   payload=DomainData(name="api.example.com", root="example.com", source="crt")))
    world.absorb([Fact(kind="resolved", about="domain:api.example.com",
                       payload=Resolved(resolvable=True, addresses=("203.0.113.5",), cnames=()))])
    ep_id = "endpoint:api.example.com/openapi.json"
    world.add(Node(id=ep_id, type="endpoint",
                   payload=Endpoint(url="https://api.example.com/openapi.json", path="/openapi.json",
                                    status=200, auth_required=False, content_type="application/json")))
    world.absorb([Fact(kind="api_spec", about=ep_id, payload=APISpec(
        base="https://api.example.com/openapi.json",
        paths=("GET /config/all", "GET /users", "POST /process", "DELETE,GET /jobs/{job_id}"),
        count=4))])

    out = ProbeSpec(fetch).run(Task(capability="endpoint_probe_spec", node=ep_id), world)

    facts = [f for f in out.facts if f.kind == "spec_audit"]
    assert len(facts) == 1
    ops = {op.path: op for op in facts[0].payload.operations}

    assert ops["/config/all"].verified and ops["/config/all"].status == 200
    assert not ops["/config/all"].auth_required and ops["/config/all"].distinct
    assert ops["/users"].verified and ops["/users"].auth_required
    assert not ops["/process"].verified and "write" in ops["/process"].reason
    assert not ops["/jobs/{job_id}"].verified and "templated" in ops["/jobs/{job_id}"].reason
    # A write operation and a templated path are never sent.
    assert "/process" not in calls
    assert "/jobs/{job_id}" not in calls


def test_info_from_openapi_reads_title_and_version():
    from opfor.scenarios.attacksurface.classes.domain.sources import info_from_openapi

    doc = {"openapi": "3.1.0", "info": {"title": "litellm api", "version": "1.90.0"}, "paths": {}}
    assert info_from_openapi(doc) == ("litellm api", "1.90.0")
    assert info_from_openapi({"swagger": "2.0", "info": {"title": "x"}}) == ("x", "")
    assert info_from_openapi({"paths": {}}) == ("", "")
    assert info_from_openapi("not a doc") == ("", "")


def test_cve_evidence_surfaces_the_spec_version_from_the_endpoint_body():
    """The CVE identification reads a specification's declared version from the endpoint's
    own body head, before any separate parse runs, so a version-bearing spec is not missed."""
    from opfor.core import Node, Task, World
    from opfor.scenarios.attacksurface.classes.domain.capabilities import CveScan
    from opfor.scenarios.attacksurface.classes.domain.types import DomainData, Endpoint

    captured = {}

    def identify(evidence):
        captured["evidence"] = evidence
        return {"product": "", "version": "", "cpe": ""}

    def cves(product, version, cpe=""):
        return []

    world = World()
    world.add(Node(id="domain:api.example.com", type="domain",
                   payload=DomainData(name="api.example.com", root="example.com", source="crt")))
    ep_id = "endpoint:api.example.com/openapi.json"
    body = '{"openapi":"3.1.0","info":{"title":"litellm api","version":"1.90.0"},"paths":{}}'
    world.add(Node(id=ep_id, type="endpoint",
                   payload=Endpoint(url="https://api.example.com/openapi.json", path="/openapi.json",
                                    status=200, auth_required=False,
                                    content_type="application/json", body=body)))

    out = CveScan(identify, cves).run(Task(capability="cve_scan", node="domain:api.example.com"), world)
    assert out.facts
    assert "1.90.0" in captured["evidence"]
    assert "litellm api" in captured["evidence"]


def test_endpoint_probe_records_a_coverage_gap_on_a_transport_failure_not_only_a_raise():
    # the real fetch seam swallows a connection error and returns status None rather than
    # raising, so the gap must be recorded from a None status too, else a WAF-blocked or
    # timed-out probe reads as a clean negative, invariant 5
    def fetch(name, addresses, path):
        if name == "admin.example.com" and path == "/.git/config":
            return {"status": None, "url": f"https://{name}{path}", "content_type": "",
                    "server": "", "title": "", "body": ""}
        return _fetch(name, addresses, path)

    _report, _scenario, world = _run_capturing(fetch_fn=fetch)
    gaps = [f.payload for f in world.facts("coverage_gap") if f.payload.scan == "domain_endpoints"]
    assert any(g.host == "admin.example.com" and any("no response" in r for r in g.reasons)
               for g in gaps), "a transport failure must record a coverage_gap, not vanish"


def test_graphql_capability_marks_an_errored_introspection_failed_not_disabled():
    from opfor.core import Failed, Task
    from opfor.scenarios.attacksurface.classes.domain.capabilities.specs import GraphQLIntrospect
    from opfor.scenarios.attacksurface.classes.domain.types import Endpoint

    world = World()
    world.add(Node(id="endpoint:h/graphql", type="endpoint",
                   payload=Endpoint(url="https://h/graphql", path="/graphql", status=200)))

    def introspect(host, path):
        raise RuntimeError("graphql introspection errored, HTTP 500")

    outcome = GraphQLIntrospect(introspect).run(
        Task(capability="endpoint_graphql", node="endpoint:h/graphql"), world)
    # an errored probe is a loud Failed, never a clean graphql-disabled fact
    assert isinstance(outcome, Failed) and "500" in outcome.reason


def test_source_map_scan_tolerates_a_bundle_error_and_still_records_the_gap():
    from opfor.core import Done, Task
    from opfor.scenarios.attacksurface.classes.domain.capabilities.artifacts import SourceMapScan
    from opfor.scenarios.attacksurface.classes.domain.types import DomainData

    world = World()
    world.add(Node(id="domain:h", type="domain", payload=DomainData(name="h", root="h", source="s")))
    home = '<script src="/a.js"></script><script src="/b.js"></script>'

    def fetch_doc(name, path):
        if path == "/":
            return {"status": 200, "text": home}
        if path == "/a.js.map":
            raise TimeoutError("map fetch failed")
        if path == "/b.js.map":
            return {"status": 200,
                    "text": '{"version":3,"sources":["x.ts"],"sourcesContent":["code"]}'}
        return {"status": None, "text": ""}

    outcome = SourceMapScan(fetch_doc).run(Task(capability="source_map_scan", node="domain:h"), world)
    assert isinstance(outcome, Done)
    kinds = {f.kind for f in outcome.facts}
    # the good bundle's leak is kept, and the errored bundle is a coverage gap, not a whole
    # scan Failed that would discard what was already found
    assert "source_maps" in kinds and "coverage_gap" in kinds
    leaks = [f for f in outcome.facts if f.kind == "source_maps"][0].payload.leaks
    assert len(leaks) == 1


def test_expand_spec_fails_loud_on_transport_failure_and_on_a_malformed_body():
    from opfor.core import Failed, Task
    from opfor.scenarios.attacksurface.classes.domain.capabilities.specs import ExpandSpec
    from opfor.scenarios.attacksurface.classes.domain.types import Endpoint

    world = World()
    world.add(Node(id="endpoint:h/openapi.json", type="endpoint",
                   payload=Endpoint(url="https://h/openapi.json", path="/openapi.json",
                                    status=200, content_type="application/json")))
    task = Task(capability="endpoint_expand_spec", node="endpoint:h/openapi.json")

    no_answer = ExpandSpec(lambda h, p: {"status": None, "text": ""}).run(task, world)
    assert isinstance(no_answer, Failed) and "no response" in no_answer.reason
    bad_json = ExpandSpec(lambda h, p: {"status": 200, "text": "<html>not a spec"}).run(task, world)
    assert isinstance(bad_json, Failed) and "not JSON" in bad_json.reason


def test_secret_scan_reports_multiple_distinct_matches_not_only_the_first():
    from opfor.scenarios.attacksurface.classes.domain.javascript import secrets_in_text
    body = "a=sk-aaaaaaaaaaaaaaaaaaaa b=sk-bbbbbbbbbbbbbbbbbbbb"
    patterns = [{"id": "token", "regex": r"sk-[a-z]{20}", "note": "token"}]
    found = secrets_in_text(body, patterns)
    # both distinct tokens surface, not just the first, and they are deduped by sample
    assert len(found) == 2 and len({f["sample"] for f in found}) == 2


def test_a_malformed_secret_pattern_fails_loud_at_load(tmp_path):
    from opfor.scenarios.attacksurface.classes.domain import planner
    (tmp_path / "secret_patterns.yaml").write_text(
        "patterns:\n  - id: bad\n    regex: '([unclosed'\n    note: broken\n", encoding="utf-8")
    # a broken regex must fail the run at load, not silently disable the whole secret class
    with pytest.raises(RuntimeError):
        planner.load_plan_config(tmp_path)


def test_endpoint_probe_reports_truncation_when_the_candidate_cap_is_hit():
    from opfor.core import Done, Task
    from opfor.scenarios.attacksurface.classes.domain.capabilities.http import Endpoints
    from opfor.scenarios.attacksurface.classes.domain.types import DomainData

    world = World()
    world.add(Node(id="domain:h", type="domain", payload=DomainData(name="h", root="h", source="s")))
    paths = [f"/p{i}" for i in range(500)]

    def fetch(name, addresses, path):
        return {"status": 404, "url": f"https://{name}{path}", "content_type": "",
                "server": "", "title": "", "body": "", "location": ""}

    outcome = Endpoints(fetch).run(
        Task(capability="domain_endpoints", node="domain:h", params={"paths": paths}), world)
    assert isinstance(outcome, Done)
    gaps = [f.payload for f in outcome.facts if f.kind == "coverage_gap"]
    # the 400-candidate cap is surfaced, not a silent bound read as the whole surface
    assert gaps and any("cap" in r for r in gaps[0].reasons)


def test_distinct_treats_a_differing_redirect_location_as_a_real_endpoint():
    from opfor.scenarios.attacksurface.classes.domain.capabilities.common import _distinct
    # a host that answers a blanket 302 to /login for unknown paths still hides a real /admin
    # that redirects to its own dashboard, so a differing location is distinct
    baseline = {"status": 302, "location": "https://h/login", "content_type": "", "body": ""}
    same = {"status": 302, "location": "https://h/login"}
    other = {"status": 302, "location": "https://h/admin/dashboard"}
    assert _distinct(same, baseline) is False
    assert _distinct(other, baseline) is True


def test_openapi_paths_apply_the_declared_base_path():
    from opfor.scenarios.attacksurface.classes.domain.parsers import paths_from_openapi
    # Swagger 2 basePath and OpenAPI 3 servers url both move an operation off the host root,
    # so the real unauthenticated surface is probed rather than a 404 at /users
    swagger = {"basePath": "/api/v2", "paths": {"/users": {"get": {}}}}
    assert "GET /api/v2/users" in paths_from_openapi(swagger)
    oas3 = {"servers": [{"url": "https://h/api/v3"}], "paths": {"/orders": {"get": {}}}}
    assert any(p.endswith("/api/v3/orders") and "GET" in p for p in paths_from_openapi(oas3))


def test_openapi_path_item_without_verbs_is_a_get_candidate_not_a_write():
    from opfor.scenarios.attacksurface.classes.domain.parsers import (
        paths_from_openapi, split_operation)
    ops = paths_from_openapi({"paths": {"/ref-path": {"$ref": "#/components/x"}}})
    assert ops == ["GET /ref-path"]
    methods, path = split_operation(ops[0])
    assert "GET" in methods and path == "/ref-path"


def test_distinct_ignores_a_path_echoing_login_redirect_query():
    from opfor.scenarios.attacksurface.classes.domain.capabilities.common import _distinct
    # a login wall that echoes the requested path in ?next= gives every path a different raw
    # location, but it is one catch-all, so not distinct
    baseline = {"status": 302, "location": "https://h/login?next=/x", "content_type": "", "body": ""}
    echoed = {"status": 302, "location": "https://h/login?next=/admin"}
    assert _distinct(echoed, baseline) is False
    # a real redirect to a genuinely different path is still distinct
    assert _distinct({"status": 302, "location": "https://h/admin/dashboard"}, baseline) is True


def test_endpoint_probe_flags_when_the_baseline_cannot_be_established():
    from opfor.core import Done, Task
    from opfor.scenarios.attacksurface.classes.domain.capabilities.http import Endpoints
    from opfor.scenarios.attacksurface.classes.domain.types import DomainData

    world = World()
    world.add(Node(id="domain:h", type="domain", payload=DomainData(name="h", root="h", source="s")))

    def fetch(name, addresses, path):
        # only the real path answers, the baseline catch-all probes get no response
        if path == "/real":
            return {"status": 200, "url": f"https://{name}{path}", "content_type": "text/html",
                    "server": "", "title": "", "body": "x", "location": ""}
        return {"status": None, "url": f"https://{name}{path}", "content_type": "",
                "server": "", "title": "", "body": "", "location": ""}

    outcome = Endpoints(fetch).run(
        Task(capability="domain_endpoints", node="domain:h", params={"paths": ["/real"]}), world)
    assert isinstance(outcome, Done)
    gaps = [f.payload for f in outcome.facts if f.kind == "coverage_gap"]
    # a baseline that could not be established is flagged, so an unfiltered surface is loud
    assert gaps and any("baseline" in r for r in gaps[0].reasons)
