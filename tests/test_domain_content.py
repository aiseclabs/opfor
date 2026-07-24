from __future__ import annotations

from opfor.core import Node, World

from opfor.scenarios.attacksurface.assets.domain.sources.observations import Response
from tests.surface_fixtures import (
    _run,
    _run_capturing,
    _seed,
)

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

    def fetch(name, addresses, path, *, body_limit=None):
        url = f"https://{name}{path}"
        miss = Response(status=404, url=url)
        if name != "admin.example.com":
            return miss
        if path == "/config.php":
            return Response(status=200, url=url, content_type="text/html",
                            server="nginx", body="rendered page")
        if path == "/config.php.bak":
            return Response(status=200, url=url, content_type="text/plain",
                            server="nginx", body=source)
        return miss

    def fetch_doc(name, path):
        if name == "admin.example.com" and path == "/":
            return Response(status=200, content_type="text/html", body=home)
        return Response(status=None)

    report, _scenario, world = _run_capturing(fetch_fn=fetch, fetch_doc_fn=fetch_doc)
    hits = [h for f in world.facts("backups") for h in f.payload.hits]
    assert any(h.url.endswith("/config.php.bak") and h.size > 0 for h in hits), \
        "expected a backups fact carrying the config.php.bak twin"

def test_backup_scan_records_a_coverage_gap_when_a_twin_errors():
    home = '<html><body><a href="/config.php">cfg</a></body></html>'

    def fetch(name, addresses, path, *, body_limit=None):
        url = f"https://{name}{path}"
        miss = Response(status=404, url=url)
        if name != "admin.example.com":
            return miss
        if path == "/config.php":
            return Response(status=200, url=url, content_type="text/html",
                            server="nginx", body="rendered page")
        if path == "/config.php.bak":
            raise ConnectionResetError("reset during backup twin probe")
        return miss

    def fetch_doc(name, path):
        if name == "admin.example.com" and path == "/":
            return Response(status=200, content_type="text/html", body=home)
        return Response(status=None)

    _report, _scenario, world = _run_capturing(fetch_fn=fetch, fetch_doc_fn=fetch_doc)
    gaps = [f.payload for f in world.facts("coverage_gap") if f.payload.scan == "backup_scan"]
    assert any(g.failed >= 1 and any("ConnectionResetError" in r for r in g.reasons) for g in gaps), \
        "a backup twin probe error must record a coverage_gap rather than vanish"

def test_sql_dump_clue_covers_every_probed_sql_path():
    from opfor.scenarios.attacksurface.assets import domain as domain_class
    from opfor.scenarios.attacksurface.lifecycle.triage import _load_clues
    clues = _load_clues(domain_class.KNOWLEDGE / "findings")
    sql = [c for c in clues if c.get("id") == "exposed-sql-dump"]
    # a suffix path so /dump.sql, /db.sql, /database.sql all match, not only /backup.sql
    assert sql and sql[0]["path"] == ".sql"

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
