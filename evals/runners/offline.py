"""The offline deterministic gate, the CI tier.

It drives the real engine over every recorded benchmark in a suite with no model and no network,
and grades the deterministic capabilities the domain class must get right: identify what a host
runs, determine its version, mint the known vulnerabilities that identity carries, select the
protocols a surface makes ride, and recover a root's subdomains from its recorded passive sources.
The identify seam is forced to the fingerprint table and the triage provider is a stub, so a result
is what a real scan concludes deterministically, gradable at a hard floor. A regression on any axis
fails the run, and an empty suite fails loud rather than scoring a vacuous 100%, invariant 5.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from evals.registry import Benchmark, all_benchmarks
from evals.runners.discovery import run_discovery
from evals.runners.replay import load_cassette, run_cassette
from evals.scorers.cve import CVEGrade, grade_cves
from evals.scorers.discovery import DiscoveryGrade, grade_discovery
from evals.scorers.identify import IdentityGrade, grade_identity, negative_fire
from evals.scorers.protocol import ProtocolGrade, grade_protocols
from evals.suites import Suite, load_suite, select


@dataclass(kw_only=True)
class BenchmarkRun:
    """The grades one benchmark produced. A host carries identity and cve grades, a negative a fire
    check and a cve grade, a surface a protocol grade, so the aggregate reads each capability."""

    benchmark: Benchmark
    identity: IdentityGrade | None = None
    cve: CVEGrade | None = None
    protocol: ProtocolGrade | None = None
    discovery: DiscoveryGrade | None = None
    fired: str | None = None


def run_benchmark(bench: Benchmark) -> BenchmarkRun:
    key = bench.key()
    if bench.kind == "surface":
        surface = json.loads(bench.evidence.read_text(encoding="utf-8")).get("surface", "")
        return BenchmarkRun(benchmark=bench, protocol=grade_protocols(surface, key))
    if bench.kind == "discovery":
        return BenchmarkRun(benchmark=bench, discovery=grade_discovery(run_discovery(bench), key))
    cassette = load_cassette(bench.evidence)
    world, report = run_cassette(cassette)
    profile = world.latest("host_profile", f"domain:{cassette['host']}")
    payload = profile.payload if profile is not None else None
    cve = grade_cves(report, key)
    if bench.kind == "negative":
        return BenchmarkRun(benchmark=bench, cve=cve, fired=negative_fire(payload, key))
    return BenchmarkRun(benchmark=bench, identity=grade_identity(payload, key), cve=cve)


def run(benchmarks) -> dict:
    """Run every benchmark and fold the grades into one aggregate the gate reads."""
    runs = [run_benchmark(b) for b in benchmarks]
    return score(runs)


def score(runs: list[BenchmarkRun]) -> dict:
    hosts = [r for r in runs if r.benchmark.kind == "host"]
    negatives = [r for r in runs if r.benchmark.kind == "negative"]
    surfaces = [r for r in runs if r.benchmark.kind == "surface"]
    discoveries = [r for r in runs if r.benchmark.kind == "discovery"]

    identity = [r.identity for r in hosts if r.identity is not None]
    prod = [g for g in identity if g.product_expected]
    prod_ok = [g for g in prod if g.product_ok]
    ver = [g for g in identity if g.version_expected]
    ver_ok = [g for g in ver if g.version_ok]
    id_problems = [p for g in identity for p in g.problems]

    cve_grades = [r.cve for r in (*hosts, *negatives) if r.cve is not None]
    cve_expecting = [g for g in cve_grades if g.expected]
    cve_problems = [p for g in cve_grades for p in (*g.missing, *g.spurious, *g.severity_wrong)]

    fires = [r.fired for r in negatives if r.fired]

    protocols = [r.protocol for r in surfaces if r.protocol is not None]
    graded = [g for g in protocols if g.graded]
    pos_labels = sum(len(g.positive) for g in protocols)
    neg_labels = sum(len(g.negative) for g in protocols)
    p_missed = [m for g in protocols for m in g.missed]
    p_fires = [w for g in protocols for w in g.wrong_fires]

    disc = [r.discovery for r in discoveries if r.discovery is not None]
    disc_expected = sum(len(g.expected) for g in disc)
    disc_problems = [p for g in disc for p in (*g.missing, *g.extra, *([g.failed] if g.failed else []))]

    return {
        "hosts": len(hosts),
        "negatives": len(negatives),
        "surfaces": len(surfaces),
        "discoveries": len(discoveries),
        "identify_expected": len(prod),
        "identify_recall": len(prod_ok) / len(prod) if prod else 1.0,
        "version_expected": len(ver),
        "version_accuracy": len(ver_ok) / len(ver) if ver else 1.0,
        "identify_problems": id_problems,
        "cve_benchmarks_with_expectation": len(cve_expecting),
        "cve_minted_total": sum(len(g.minted_version) for g in cve_grades),
        "cve_problems": cve_problems,
        "negative_fires": fires,
        "protocol_graded": len(graded),
        "protocol_positive_labels": pos_labels,
        "protocol_negative_labels": neg_labels,
        "protocol_recall": (pos_labels - len(p_missed)) / pos_labels if pos_labels else 1.0,
        "protocol_missed": p_missed,
        "protocol_wrong_fires": p_fires,
        "discovery_expected": disc_expected,
        "discovery_recall": (disc_expected - len([p for g in disc for p in g.missing]))
        / disc_expected if disc_expected else 1.0,
        "discovery_problems": disc_problems,
    }


def gate(result: dict) -> list[str]:
    """The failures that block a passing offline run. The offline tier is deterministic, so the
    floors are 100%: a host that stops being identified, a version that stops being extracted, a CVE
    that stops being minted or is minted wrong, a negative that fires, or a protocol that misfires,
    is a regression, not noise. An empty suite scores a vacuous 100%, so each axis requires a real
    sample rather than let a missing tree pass as clean, invariant 5."""
    fails: list[str] = []
    if result["hosts"] == 0:
        fails.append("no host benchmarks, an empty suite cannot gate identification")
    if result["negatives"] == 0:
        fails.append("no negative benchmarks, an empty suite cannot gate precision")
    if result["surfaces"] == 0:
        fails.append("no surface benchmarks, an empty suite cannot gate protocol selection")
    if result["discoveries"] == 0:
        fails.append("no discovery benchmarks, an empty suite cannot gate subdomain recall")
    if result["identify_recall"] < 1.0:
        fails.append(f"identify recall {result['identify_recall']:.0%} below 100%, "
                     f"{'; '.join(p for p in result['identify_problems'] if 'product' in p)}")
    if result["version_accuracy"] < 1.0:
        fails.append(f"version accuracy {result['version_accuracy']:.0%} below 100%, "
                     f"{'; '.join(p for p in result['identify_problems'] if 'version' in p)}")
    if result["cve_problems"]:
        fails.append(f"known-vulnerability minting regressed: {'; '.join(result['cve_problems'])}")
    if result["negative_fires"]:
        fails.append(f"a product was identified on a non-product page: {'; '.join(result['negative_fires'])}")
    if result["protocol_missed"]:
        fails.append(f"a protocol stopped riding its own surface: {', '.join(result['protocol_missed'])}")
    if result["protocol_wrong_fires"]:
        fails.append(f"a protocol rode a surface it must not: {', '.join(result['protocol_wrong_fires'])}")
    if result["discovery_problems"]:
        fails.append(f"passive subdomain recall regressed: {'; '.join(result['discovery_problems'])}")
    return fails


def format_report(result: dict) -> str:
    lines = [
        "=== offline deterministic gate ===",
        f"  {result['hosts']} hosts, {result['negatives']} negatives, {result['surfaces']} surfaces, "
        f"{result['discoveries']} discoveries",
        f"  identify recall  {result['identify_recall']:.0%} over {result['identify_expected']} hosts",
        f"  version accuracy {result['version_accuracy']:.0%} over {result['version_expected']} versioned hosts",
        f"  cve minting      {result['cve_minted_total']} findings over "
        f"{result['cve_benchmarks_with_expectation']} hosts with a keyed CVE, "
        f"{len(result['cve_problems'])} problems",
        f"  protocol recall  {result['protocol_recall']:.0%} over {result['protocol_positive_labels']} "
        f"positive labels, {result['protocol_negative_labels']} negative labels",
        f"  discovery recall {result['discovery_recall']:.0%} over {result['discovery_expected']} "
        f"expected subdomains, {len(result['discovery_problems'])} problems",
    ]
    return "\n".join(lines)


def run_suite(suite: str | Suite = "offline") -> dict:
    """Run the named offline suite over the discovered benchmarks, the CLI entry."""
    s = suite if isinstance(suite, Suite) else load_suite(suite)
    return run(select(s, all_benchmarks().values()))


def _load_result(path: str | Path) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))
