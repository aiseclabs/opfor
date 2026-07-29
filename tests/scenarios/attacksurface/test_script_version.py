"""Version extraction from a host's own JavaScript bundles, the two techniques the harvester runs.

Technique A reads a version literal a bundle's content declares, an anchor only that library emits,
so a self-hosted build that prints no version in its home page is still versioned. Technique B is a
bounded fallback, a source map whose `sources` paths embed a version under a pnpm layout, read only
when the content named none. Both feed one `script_version` fact the profiler joins to the
frameworks it classifies. The source functions are tested apart from the network, and the harvester
is driven with a fetch fake that dispatches by path.
"""

from __future__ import annotations

import re
from pathlib import Path

from opfor.core import Done, Fact, Node, Task, World
from opfor.scenarios.attacksurface.assets.domain.capabilities.http import HarvestPaths
from opfor.scenarios.attacksurface.assets.domain.classifiers import (
    classify_frameworks,
    load_frameworks,
)
from opfor.scenarios.attacksurface.assets.domain.sources.javascript import (
    sourcemap_exposure,
    sourcemap_targets,
    versions_in_script,
    versions_in_sourcemap,
)
from opfor.scenarios.attacksurface.assets.domain.sources.observations import Response
from opfor.scenarios.attacksurface.assets.domain.types import (
    DomainData,
    Framework,
    HTTPProbe,
    Resolved,
)

_FRAMEWORK_DIR = Path("opfor/scenarios/attacksurface/assets/domain/knowledge/guides/frameworks")

# The real anchors, compiled the same way the loader does, so the tests bind to the shipped
# knowledge rather than a private copy that could drift from it.
_REACT = re.compile(r'reconcilerVersion["\s:]{1,4}([0-9]+\.[0-9]+\.[0-9]+)', re.IGNORECASE)
_VUE = re.compile(r'vue v([0-9]+\.[0-9]+\.[0-9]+)', re.IGNORECASE)
_PATTERNS = {"React": _REACT, "Vue": _VUE}
_NPM = {"React": "react", "Vue": "vue", "Angular": "@angular/core"}


def test_a_reads_a_version_literal_a_bundle_declares():
    # bodies arrive lowercased from the document fetch, and the patterns are case-insensitive, so
    # the anchor still matches. The noisy canary `version:"...-next-..."` is not the anchor.
    react = 'x={bundletype:0,version:"18.2.0-next-9e3b772b8",reconcilerversion:"18.2.0"};'
    assert versions_in_script(react, _PATTERNS) == {"React": "18.2.0"}
    assert versions_in_script("/**\n* vue v3.4.21\n*/", _PATTERNS) == {"Vue": "3.4.21"}
    assert versions_in_script("a bundle that names no version", _PATTERNS) == {}


def test_b_resolves_a_relative_map_reference_against_the_script_directory():
    body = "code();\n//# sourceMappingURL=main.abc.js.map"
    assert sourcemap_targets(body, "h", "/static/js/main.abc.js") == ["/static/js/main.abc.js.map"]
    # an absolute reference is kept, a data-uri inline map is skipped, a cross-host map is dropped
    assert sourcemap_targets("//# sourceMappingURL=/s/x.js.map", "h", "/a.js") == ["/s/x.js.map"]
    assert sourcemap_targets("//# sourceMappingURL=data:application/json;base64,z", "h", "/a.js") == []
    assert sourcemap_targets("//# sourceMappingURL=https://cdn.other/x.map", "h", "/a.js") == []


def test_b_reads_a_version_only_from_a_pnpm_source_path():
    # a pnpm layout writes `.../<package>@<version>/...`, so the version rides in the path
    pnpm = '{"version":3,"sources":["../.pnpm/vue@3.4.21/dist/x.js","../react@18.2.0/i.js"]}'
    assert versions_in_sourcemap(pnpm, _NPM) == {"React": "18.2.0", "Vue": "3.4.21"}
    # a flat npm layout carries no version in the path, so nothing is claimed rather than guessed
    flat = '{"version":3,"sources":["webpack://app/src/main.js"]}'
    assert versions_in_sourcemap(flat, _NPM) == {}
    # a body that is not a source map yields nothing rather than raising
    assert versions_in_sourcemap("<html>not json</html>", _NPM) == {}


def test_sourcemap_exposure_reads_only_a_real_source_map_and_grades_by_what_it_leaks():
    # a real source map carrying original source, the strong form, reports the count and the embed
    embedded = ('{"version":3,"sources":["src/a.js","src/b.js"],'
                '"sourcesContent":["const a=1","const b=2"],"mappings":"AAAA"}')
    assert sourcemap_exposure(embedded) == (2, True)
    # a map that names files but embeds no contents leaks the layout, not the source
    names_only = '{"version":3,"sources":["src/a.js"],"mappings":"AAAA"}'
    assert sourcemap_exposure(names_only) == (1, False)
    # an empty sourcesContent is not an embed, so it is not read as the strong form
    empty_content = '{"version":3,"sources":["src/a.js"],"sourcesContent":[""],"mappings":""}'
    assert sourcemap_exposure(empty_content) == (1, False)
    # a body that is not a source map is None, so a 404 page or an app shell is never an exposure
    assert sourcemap_exposure("<html>not found</html>") is None
    assert sourcemap_exposure("") is None
    # JSON that is not an object, or an object with no sources, is not a source map
    assert sourcemap_exposure('["a","b"]') is None
    assert sourcemap_exposure('{"foo":"bar"}') is None
    # an object with a sources array but no version or mappings is not mistaken for a map
    assert sourcemap_exposure('{"sources":["x"]}') is None


def test_harvest_records_a_reachable_source_map_it_confirmed():
    world = _seed_live_host()
    pages = {
        "/": '<html><script src="/static/app.js"></script></html>',
        "/static/app.js": 'boot();\n//# sourceMappingURL=app.js.map',
        "/static/app.js.map": ('{"version":3,"sources":["src/a.js","src/b.js"],'
                               '"sourcesContent":["x","y"],"mappings":"AAAA"}'),
    }
    out = _harvester(pages).run(Task(capability="domain_harvest", node="domain:h"), world)
    assert isinstance(out, Done)
    maps = next(f.payload for f in out.facts if f.kind == "source_map").maps
    assert len(maps) == 1
    assert maps[0].path == "/static/app.js.map"
    assert maps[0].sources == 2 and maps[0].embeds_source is True


def test_harvest_records_no_source_map_fact_when_the_map_is_not_served():
    world = _seed_live_host()
    pages = {
        "/": '<html><script src="/static/app.js"></script></html>',
        # the bundle advertises a map, but the path answers a catch-all shell, not a source map
        "/static/app.js": 'boot();\n//# sourceMappingURL=app.js.map',
        "/static/app.js.map": '<html>single page app shell</html>',
    }
    out = _harvester(pages).run(Task(capability="domain_harvest", node="domain:h"), world)
    assert not any(f.kind == "source_map" for f in out.facts)


def _seed_live_host() -> World:
    world = World()
    world.add(Node(id="domain:h", type="domain", payload=DomainData(name="h", root="h", source="s")))
    world.absorb([Fact(kind="resolved", about="domain:h",
                       payload=Resolved(resolvable=True, addresses=("1.2.3.4",)))])
    return world


def _harvester(pages: dict) -> HarvestPaths:
    # a fetch_document fake that dispatches by path, lowercasing the body the way the real fetch
    # does, wired with the shipped framework table so the bundle anchors are the real ones
    frameworks = load_frameworks(_FRAMEWORK_DIR)

    def fetch_doc(name, path):
        return Response(status=200, body=pages.get(path, "").lower())

    def fetch(name, addresses, path, **kw):
        return Response(status=404)

    return HarvestPaths(fetch, fetch_doc, lambda *a: set(), frameworks=frameworks)


def test_harvest_records_the_version_a_bundle_declares():
    world = _seed_live_host()
    pages = {
        "/": '<html><script src="/static/app.js"></script></html>',
        "/static/app.js": 'x={reconcilerVersion:"18.2.0"};',
    }
    out = _harvester(pages).run(Task(capability="domain_harvest", node="domain:h"), world)
    assert isinstance(out, Done)
    sv = next(f.payload for f in out.facts if f.kind == "script_version")
    assert dict(sv.versions) == {"React": "18.2.0"}


def test_harvest_falls_back_to_a_source_map_for_the_version():
    world = _seed_live_host()
    pages = {
        "/": '<html><script src="/static/app.js"></script></html>',
        # the bundle names no version but points at a map whose pnpm path embeds one
        "/static/app.js": 'boot();\n//# sourceMappingURL=app.js.map',
        "/static/app.js.map": '{"version":3,"sources":["../.pnpm/vue@3.4.21/dist/x.js"]}',
    }
    out = _harvester(pages).run(Task(capability="domain_harvest", node="domain:h"), world)
    sv = next(f.payload for f in out.facts if f.kind == "script_version")
    assert dict(sv.versions) == {"Vue": "3.4.21"}


def test_harvest_records_no_version_fact_when_no_bundle_declares_one():
    world = _seed_live_host()
    pages = {
        "/": '<html><script src="/static/app.js"></script></html>',
        "/static/app.js": 'a bespoke bundle with no version and no map',
    }
    out = _harvester(pages).run(Task(capability="domain_harvest", node="domain:h"), world)
    assert not any(f.kind == "script_version" for f in out.facts)


def test_classify_prefers_the_home_page_version_then_the_bundle_then_a_cdn_url():
    frameworks = load_frameworks(_FRAMEWORK_DIR)

    def http(body):
        return HTTPProbe(alive=True, status=200, url="https://h/", server="", title="",
                         body=body.lower(), location="", headers=())

    # a self-hosted React build prints no version in the page, so the bundle version fills it
    react = classify_frameworks(http("<div data-reactroot></div>"), frameworks, {"React": "18.2.0"})
    assert react == [Framework(name="React", version="18.2.0", npm="react")]

    # Angular's own ng-version in the page wins over any bundle version, the more authoritative source
    ng = classify_frameworks(http('<app ng-version="16.2.0"></app>'), frameworks, {"Angular": "9.9.9"})
    assert ng[0].name == "Angular" and ng[0].version == "16.2.0"
