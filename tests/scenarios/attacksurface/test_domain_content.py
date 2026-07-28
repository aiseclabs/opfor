from __future__ import annotations

from tests.scenarios.attacksurface.fixtures import (
    _run,
    _seed,
)

def test_javascript_and_url_parsing():
    from opfor.scenarios.attacksurface.sources import (
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
    from opfor.scenarios.attacksurface.sources.javascript import urls_in_javascript
    body = 'const api = "https://api.host.com:8443/v1/users";'
    assert "https://api.host.com:8443/v1/users" in urls_in_javascript(body)

def test_javascript_extraction_dedups_and_caps_a_hostile_bundle():
    # a bundle packing far more distinct quoted paths than the cap must be read out in bounded
    # time and bounded length, not grow an unbounded list on a quadratic membership scan
    from opfor.scenarios.attacksurface.sources.javascript import (
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

def test_wayback_passive_urls_become_candidates():
    world = _seed()
    _run(world)
    assert world.node("endpoint:www.example.com/legacy") is not None

def test_robots_disallow_paths_become_candidates():
    world = _seed()
    _run(world)
    assert world.node("endpoint:example.com/secret-panel") is not None

def test_robots_and_sitemap_parsing():
    from opfor.scenarios.attacksurface.sources import robots_entries, sitemap_paths

    paths, sitemaps = robots_entries("User-agent: *\nDisallow: /admin\nAllow: /public\nSitemap: https://h/sm.xml")
    assert paths == ["/admin", "/public"]
    assert sitemaps == ["https://h/sm.xml"]
    assert sitemap_paths("<urlset><url><loc>https://h.test/a</loc></url></urlset>", "h.test") == ["/a"]
