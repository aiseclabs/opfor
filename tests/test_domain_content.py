from __future__ import annotations

import json

import pytest

from opfor.core import Node, World

from tests.surface_fixtures import *


def test_javascript_and_url_parsing():
    from opfor.scenarios.attacksurface.assets.domain.sources import (
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

def test_urls_in_javascript_extracts_an_explicit_port():
    from opfor.scenarios.attacksurface.assets.domain.sources.javascript import urls_in_javascript
    body = 'const api = "https://api.host.com:8443/v1/users";'
    assert "https://api.host.com:8443/v1/users" in urls_in_javascript(body)

def test_javascript_extraction_dedups_and_caps_a_hostile_bundle():
    # a bundle packing far more distinct quoted paths than the cap must be read out in bounded
    # time and bounded length, not grow an unbounded list on a quadratic membership scan
    from opfor.scenarios.attacksurface.assets.domain.sources.javascript import (
        _MAX_JS_STRINGS,
        paths_in_javascript,
        urls_in_javascript,
    )

    paths = "".join(f'"/a{i}x"' for i in range(_MAX_JS_STRINGS + 500))
    got = paths_in_javascript(paths)
    assert len(got) == _MAX_JS_STRINGS
    # a repeated path is deduped rather than counted twice
    assert paths_in_javascript('"/same" "/same" "/same"') == ["/same"]

    urls = "".join(f'"https://h/u{i}"' for i in range(_MAX_JS_STRINGS + 500))
    assert len(urls_in_javascript(urls)) == _MAX_JS_STRINGS

def test_source_map_parser_detects_inlined_source_and_paths_only():
    from opfor.scenarios.attacksurface.assets.domain import sources as domains

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

def test_source_map_scan_tolerates_a_bundle_error_and_still_records_the_gap():
    from opfor.core import Done, Task
    from opfor.scenarios.attacksurface.assets.domain.capabilities.artifacts import SourceMapScan
    from opfor.scenarios.attacksurface.assets.domain.types import DomainData

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

def test_secrets_in_text_matches_patterns_and_redacts():
    from opfor.scenarios.attacksurface.assets.domain import sources as domains

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

def test_secrets_in_text_keeps_two_keys_sharing_a_prefix_and_length():
    # two distinct AWS keys with the same six-char prefix and identical length must both be
    # reported, not collapsed to one by a redaction-keyed dedup that loses a real secret
    from opfor.scenarios.attacksurface.assets.domain import sources as domains

    patterns = [{"id": "aws-access-key-id", "regex": "AKIA[0-9A-Z]{16}", "note": "key"}]
    body = "a='AKIA000000000000AAAA'; b='AKIA000000000000BBBB';"
    hits = domains.secrets_in_text(body, patterns)
    assert len(hits) == 2

def test_secret_scan_flags_a_key_in_a_bundle_and_redacts_it():
    home = '<script src="/static/main.js"></script>'
    bundle = "var cfg={awsKey:'AKIAIOSFODNN7EXAMPLE'};"

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

def test_secret_scan_reports_multiple_distinct_matches_not_only_the_first():
    from opfor.scenarios.attacksurface.assets.domain.sources.javascript import secrets_in_text
    body = "a=sk-aaaaaaaaaaaaaaaaaaaa b=sk-bbbbbbbbbbbbbbbbbbbb"
    patterns = [{"id": "token", "regex": r"sk-[a-z]{20}", "note": "token"}]
    found = secrets_in_text(body, patterns)
    # both distinct tokens surface, not just the first, and they are deduped by sample
    assert len(found) == 2 and len({f["sample"] for f in found}) == 2

def test_a_malformed_secret_pattern_fails_loud_at_load(tmp_path):
    from opfor.scenarios.attacksurface.assets.domain import planner
    (tmp_path / "secret_patterns.yaml").write_text(
        "patterns:\n  - id: bad\n    regex: '([unclosed'\n    note: broken\n", encoding="utf-8")
    # a broken regex must fail the run at load, not silently disable the whole secret class
    with pytest.raises(RuntimeError):
        planner.load_plan_config(tmp_path)

def test_backup_candidates_derives_twins_and_skips_directories():
    from opfor.scenarios.attacksurface.assets.domain import sources as domains

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

def test_sql_dump_clue_covers_every_probed_sql_path():
    import yaml

    from opfor.scenarios.attacksurface.assets import domain as domain_class
    data = yaml.safe_load((domain_class.KNOWLEDGE / "exposures.yaml").read_text(encoding="utf-8"))
    sql = [c for c in data["clues"] if c.get("id") == "exposed-sql-dump"]
    # a suffix path so /dump.sql, /db.sql, /database.sql all match, not only /backup.sql
    assert sql and sql[0]["path"] == ".sql"

def test_cloud_bucket_from_url_recognizes_provider_forms():
    from opfor.scenarios.attacksurface.assets.domain import sources as domains

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

def test_wayback_passive_urls_become_candidates():
    world = _seed()
    _run(world)
    assert world.node("endpoint:www.example.com/legacy") is not None

def test_robots_disallow_paths_become_candidates():
    world = _seed()
    _run(world)
    assert world.node("endpoint:example.com/secret-panel") is not None

def test_robots_and_sitemap_parsing():
    from opfor.scenarios.attacksurface.assets.domain.sources import robots_entries, sitemap_paths

    paths, sitemaps = robots_entries("User-agent: *\nDisallow: /admin\nAllow: /public\nSitemap: https://h/sm.xml")
    assert paths == ["/admin", "/public"]
    assert sitemaps == ["https://h/sm.xml"]
    assert sitemap_paths("<urlset><url><loc>https://h.test/a</loc></url></urlset>", "h.test") == ["/a"]
