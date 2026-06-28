from opfor.engine.budget import Budget
from opfor.engine.control import ControlShell
from opfor.engine.graph import SituationGraph
from opfor.engine.scope import Scope
from opfor.engine.state import Workspace
from opfor.engine.tasks import Task
from opfor.model import Domain, Host, Service, Target
from opfor.scenarios.recon.executors import (
    DnsExecutor,
    FaviconExecutor,
    HttpCheckExecutor,
    HttpProbeExecutor,
    RootKeywordExecutor,
    RootPivotExecutor,
    SubdomainExecutor,
    _check_finding,
)
from opfor.scenarios.recon.planner import ReconPlanner

_GIT_CHECK = {
    "id": "git-config-exposed",
    "path": "/.git/config",
    "severity": "high",
    "title": "Exposed .git/config",
    "match": {"status": 200, "body_contains": "[core]"},
}


def _task(cap, target, **params):
    return Task(id=f"{cap}:{target}", capability=cap, target=target, params=params, scope_host=target)


# --- executors --------------------------------------------------------------


def test_subdomain_executor_merges_sources_and_filters_in_scope():
    def good(d):
        return ["api.example.com", "WWW.example.com", "*.api.example.com"]

    def flaky(d):
        raise OSError("down")

    def other(d):
        return ["mail.example.com", "unrelated.org"]

    ex = SubdomainExecutor(sources=[("good", good), ("flaky", flaky), ("other", other)])
    obs = ex.run(_task("subdomains", "example.com"), None)
    facts = ex.perceive(obs)
    discovered = {e.id for f in facts for e in f.yields}
    assert discovered == {"api.example.com", "www.example.com", "mail.example.com"}
    assert obs.raw["sources"]["flaky"].startswith("error:")


def test_dns_executor_marks_live_and_dead():
    def resolver(d):
        if d == "live.example.com":
            return ["1.2.3.4"]
        raise OSError("nx")

    ex = DnsExecutor(resolve_fn=resolver)
    live = ex.perceive(ex.run(_task("dns_resolve", "live.example.com"), None))
    dead = ex.perceive(ex.run(_task("dns_resolve", "gone.example.com"), None))
    assert [h for f in live for h in f.yields][0].props["live"] is True
    assert [h for f in dead for h in f.yields][0].props["live"] is False


def test_http_probe_fingerprints(stub_server):
    ex = HttpProbeExecutor()
    facts = ex.perceive(ex.run(_task("http_probe", "probe.example.com", url=stub_server), None))
    yielded = [e for f in facts for e in f.yields]
    assert any(e.kind == "service" and e.props["status"] == 200 for e in yielded)
    assert any(e.kind == "technology" for e in yielded)  # stub sends a Server header


def test_http_probe_falls_back_to_http_when_https_dead(monkeypatch):
    from opfor.scenarios.recon import executors as ex_mod

    seen = []

    def fake_get(url, *a, **k):
        seen.append(url)
        if url.startswith("https://"):
            return {"url": url, "status": None, "error": "connection refused"}
        return {"url": url, "status": 200, "headers": {"Server": "nginx"}, "body": ""}

    monkeypatch.setattr(ex_mod, "http_get", fake_get)
    ex = ex_mod.HttpProbeExecutor()
    obs = ex.run(_task("http_probe", "http-only.example.com", url="https://http-only.example.com/"), None)
    assert obs.raw["status"] == 200
    assert obs.raw["url"].startswith("http://")
    assert seen == ["https://http-only.example.com/", "http://http-only.example.com/"]


def test_http_probe_keeps_https_when_it_responds(monkeypatch):
    from opfor.scenarios.recon import executors as ex_mod

    seen = []

    def fake_get(url, *a, **k):
        seen.append(url)
        return {"url": url, "status": 200, "headers": {}, "body": ""}

    monkeypatch.setattr(ex_mod, "http_get", fake_get)
    ex = ex_mod.HttpProbeExecutor()
    obs = ex.run(_task("http_probe", "ok.example.com", url="https://ok.example.com/"), None)
    assert obs.raw["url"] == "https://ok.example.com/"
    assert seen == ["https://ok.example.com/"]  # no http fallback when https answers


def test_http_check_fires_and_clears(stub_server):
    ex = HttpCheckExecutor()
    hit = ex.perceive(ex.run(_task("http_check", "h", url=stub_server, path="/.git/config", check=_GIT_CHECK), None))
    assert [e for f in hit for e in f.yields][0].kind == "finding"
    miss = {**_GIT_CHECK, "path": "/nope"}
    clean = ex.perceive(ex.run(_task("http_check", "h", url=stub_server, path="/nope", check=miss), None))
    assert clean[0].kind == "check-clean"


def test_check_negative_matcher_kills_html_false_positive():
    dotenv = {"id": "dotenv-exposed", "match": {
        "status": 200, "body_contains": "=", "content_type_excludes": "text/html",
        "body_not_contains": ["<html", "<!doctype"]}}
    html = {"status": 200, "url": "https://x/.env", "domain": "x",
            "headers": {"Content-Type": "text/html"}, "body": "<!doctype html>a=b", "check": dotenv}
    assert _check_finding(html) is None
    real = {"status": 200, "url": "https://x/.env", "domain": "x",
            "headers": {"Content-Type": "text/plain"}, "body": "K=v", "check": dotenv}
    assert _check_finding(real) is not None


def test_root_executors_yield_candidates():
    kw = RootKeywordExecutor(search=lambda o: ["example.cn"])
    cands = [e for f in kw.perceive(kw.run(_task("root_keyword", "example"), None)) for e in f.yields]
    assert cands[0].props["candidate"] and cands[0].props["source"] == "keyword"
    pv = RootPivotExecutor(pivot=lambda r: ["1example.com"])
    sib = [e for f in pv.perceive(pv.run(_task("root_pivot", "example.com"), None)) for e in f.yields]
    assert sib[0].props["source"] == "cert-san"


# --- planner ----------------------------------------------------------------


def test_planner_emits_recon_dag_as_surface_grows():
    planner = ReconPlanner(checks=[_GIT_CHECK])
    g = SituationGraph()
    g.add_target(Target(id="example.com", kind="domain", props={"host": "example.com"}))

    ids = {t.id for t in planner.expand(g)}
    assert {"subs:example.com", "pivot:example.com", "dns:example.com"} <= ids
    assert not any(t.capability == "http_probe" for t in planner.expand(g))

    # A candidate root is recorded but never expanded.
    g.add_entity(Domain(id="cand.com", props={"candidate": True}))
    assert "dns:cand.com" not in {t.id for t in planner.expand(g)}

    # A live host earns a probe; a service earns checks + favicon.
    g.add_entity(Host(id="host:example.com", props={"domain": "example.com", "live": True}))
    assert any(t.capability == "http_probe" for t in planner.expand(g))
    g.add_entity(Service(id="https://example.com/", props={"domain": "example.com", "status": 200}))
    caps = {t.capability for t in planner.expand(g)}
    assert "http_check" in caps and "favicon" in caps


def test_planner_emits_root_keyword_for_org():
    planner = ReconPlanner(checks=[])
    g = SituationGraph()
    g.add_target(Target(id="acme", kind="org"))
    assert any(t.capability == "root_keyword" for t in planner.expand(g))


# --- full control-shell recon loop, offline --------------------------------


def test_recon_runs_on_control_shell_and_finds(stub_server, tmp_path):
    executors = {
        "root_keyword": RootKeywordExecutor(search=lambda o: []),
        "root_pivot": RootPivotExecutor(pivot=lambda r: []),
        "subdomains": SubdomainExecutor(sources=[]),
        "dns_resolve": DnsExecutor(resolve_fn=lambda d: ["127.0.0.1"]),
        "http_probe": HttpProbeExecutor(),
        "http_check": HttpCheckExecutor(),
        "favicon": FaviconExecutor(),
    }
    shell = ControlShell(
        executors=executors,
        planner=ReconPlanner(checks=[_GIT_CHECK]),
        scope=Scope(hosts=("probe.example.com",), max_tier="probe"),
        workspace=Workspace(tmp_path / "run"),
        budget=Budget(200),
    )
    graph = SituationGraph()
    graph.add_target(Target(id="probe.example.com", kind="domain",
                            props={"host": "probe.example.com", "url": stub_server}))
    result = shell.run(graph)

    findings = result.graph.entities("finding")
    assert any(f.id.startswith("finding:git-config-exposed") for f in findings)
    assert any(s.props["status"] == 200 for s in result.graph.entities("service"))
