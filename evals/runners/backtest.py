"""The live backtest, Tier B, the "考 AI" runbook that grades the model-identify capability.

The offline tier forces the deterministic fingerprint table, so it grades only the 14 catalogued
products. What identifies everything else is the model fallback in the composed identify seam,
`fingerprint(evidence) or model_identify(evidence)`, and that path is never exercised offline. This
tier drives the same real engine over `benchmarks/unknown/` hosts, whose product is not in the
table, so the fingerprint misses and the live model must name the product from the recorded
evidence. The identify seam is the live model, the triage provider stays a stub, so this tier grades
model-identify alone and mints nothing else, the scope locked for it.

A model run is not deterministic, so a single run is noise. Each benchmark runs N times and the runs
fold by strict majority, a product counts as identified only when more than half the runs name it,
mirroring the way a non-deterministic review folds. The bar is a floor, not the offline 100%, since
naming an obscure product from recon evidence is genuinely hard and a floor measures the capability
without pretending it is deterministic. The result is a baseline the compare tool reads to name what
a prompt or knowledge change moved.

This tier is a runbook, not CI. It calls a live model, so pytest never runs it live, the one-run
seam is monkeypatched in tests to fold canned results with no model or network. An empty suite fails
loud rather than scoring a vacuous 100%, invariant 5, so a corpus with no recorded unknown host says
so instead of reading as a clean pass.
"""

from __future__ import annotations

from evals.registry import Benchmark, all_benchmarks
from evals.results import Result, SuiteResult
from evals.runners.replay import load_cassette, run_cassette
from evals.suites import Suite, load_suite, select
from opfor.scenarios.attacksurface.assets.domain.identify import identify_service


def _norm(product: str) -> str:
    """Fold a product name for comparison, since the model may vary the casing or spacing of a name
    the key states one way. Names match on the folded form, so Grafana and grafana are one product."""
    return " ".join(product.strip().lower().split())


def _matches(got: str, want: str) -> bool:
    """Whether the model's product names the keyed one. An exact folded match, or the keyed name as a
    phrase inside a more verbose reply, counts, so a model that answers Apache CouchDB for CouchDB is
    not marked wrong for being fuller."""
    g, w = _norm(got), _norm(want)
    return bool(w) and (g == w or w in g)


def _live_identify(provider, model):
    """The identify seam for the live tier, the model with no table shortcut of its own. The class
    still wraps it with the fingerprint fallback at assemble, so an off-table host falls through to
    this model, which is the path the tier grades."""
    def identify_fn(evidence):
        return identify_service(provider, model, evidence)
    return identify_fn


def run_once(bench: Benchmark, *, provider, model) -> Result:
    """One live run of one benchmark, scored as the single identity token the model had to name. The
    engine runs with the live model identify and a stub triage, so the only thing graded is whether
    the profiled product names the keyed one. A run that names the product finds it, a run that names
    a different product both misses the expected token and flags the wrong one, and a run that names
    nothing misses with no report, so the fold reads a wrong answer apart from a blank one."""
    key = bench.key()
    want = key.identity.product
    expected = f"product:{_norm(want)}"
    cassette = load_cassette(bench.evidence)
    world, _report = run_cassette(cassette, identify_fn=_live_identify(provider, model))
    profile = world.latest("host_profile", f"domain:{cassette['host']}")
    got = getattr(profile.payload, "product", "") if profile is not None else ""
    result = Result(target=key.target, n_expected=1, n_reports=1 if got else 0)
    if got and _matches(got, want):
        result.found = [expected]
    else:
        result.missed = [expected]
        if got:
            result.false_positives = [f"product:{_norm(got)}"]
    return result


def backtest(benchmarks, *, runs: int, provider, model) -> dict[str, SuiteResult]:
    """Run each benchmark N times and fold the runs by strict majority, keyed by target. This is the
    testable core, so a test folds canned single-run results by monkeypatching `run_once` and never
    touches a model."""
    if runs < 1:
        raise ValueError("a backtest needs at least one run per benchmark")
    out: dict[str, SuiteResult] = {}
    for b in benchmarks:
        target = b.key().target
        out[target] = SuiteResult.from_runs(target, [run_once(b, provider=provider, model=model)
                                                     for _ in range(runs)])
    return out


def score(results: dict[str, SuiteResult]) -> dict:
    """Fold the per-target suite results into the aggregate the runbook reads. `identify_rate` is the
    share of targets whose product a strict majority of runs named, the capability this tier measures.
    The flat `found`/`missed`/`false_positives` fields are target-qualified so `compare` and `gate`
    read one backtest baseline directly, naming exactly which host moved."""
    targets = list(results.values())
    identified = [r for r in targets if r.recall >= 1.0]
    found = [f"{t}:{i}" for t, r in results.items() for i in r.found]
    missed = [f"{t}:{i}" for t, r in results.items() for i in r.missed]
    fps = [f"{t}:{i}" for t, r in results.items() for i in r.false_positives]
    n_expected = sum(r.n_expected for r in targets)
    return {
        "targets": len(targets),
        "identified": len(identified),
        "identify_rate": len(identified) / len(targets) if targets else 0.0,
        "errors": sum(r.errors for r in targets),
        "found": sorted(found),
        "missed": sorted(missed),
        "false_positives": sorted(fps),
        "n_expected": n_expected,
        "recall": len(found) / n_expected if n_expected else 0.0,
        "results": {t: r.to_dict() for t, r in results.items()},
    }


def gate(result: dict, *, floor: float = 0.5) -> list[str]:
    """The failures that block the live tier. Unlike the offline tier the bar is a floor, not 100%,
    since a model naming an obscure product is genuinely hard. An empty corpus fails loud rather than
    scoring a vacuous pass, invariant 5, and an errored run is never a clean pass."""
    fails: list[str] = []
    if result["targets"] == 0:
        fails.append("no unknown benchmarks recorded, an empty corpus cannot measure model-identify")
        return fails
    if result["errors"]:
        fails.append(f"{result['errors']} runs errored, a failed run is not a clean pass")
    if result["identify_rate"] < floor:
        fails.append(f"model-identify rate {result['identify_rate']:.0%} below the {floor:.0%} floor")
    return fails


def format_report(result: dict) -> str:
    lines = [
        "=== live model-identify backtest ===",
        f"  {result['identified']}/{result['targets']} unknown hosts identified by strict majority "
        f"({result['identify_rate']:.0%})",
    ]
    for target, r in result["results"].items():
        verdict = "identified" if r["recall"] >= 1.0 else "missed"
        lines.append(f"  {target}: {verdict}, {r['n_reports']} of {r['runs']} runs named a product")
    if result["errors"]:
        lines.append(f"  {result['errors']} runs errored")
    return "\n".join(lines)


def run_suite(suite: str | Suite = "identify-live", *, runs: int = 5,
              provider=None, model=None) -> dict:
    """Run the live backtest over an unknown-host suite, the runbook entry. Benchmarks are selected
    before any provider is built, so an empty corpus fails loud without a model call. A live provider
    from the environment identifies, keyless on the operator's subscription by default."""
    from opfor.core import default_model, make_provider

    s = suite if isinstance(suite, Suite) else load_suite(suite)
    benches = select(s, all_benchmarks().values())
    if not benches:
        raise ValueError(f"suite {getattr(s, 'name', suite)!r} selected no benchmarks, record an "
                         "unknown host under evals/benchmarks/unknown per BACKTEST.md before running")
    provider = provider or make_provider()
    model = model or default_model()
    return score(backtest(benches, runs=runs, provider=provider, model=model))
