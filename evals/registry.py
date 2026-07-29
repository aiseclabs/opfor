"""Benchmark discovery: every case the repository ships under `evals/benchmarks`, found by walking
the tree for an `answer-key.yaml` and pairing it with the evidence file beside it.

A benchmark is a directory holding an `answer-key.yaml`. Its evidence is a `cassette.json` of
recorded HTTP responses for a host or a negative, or a `surface.json` of one rendered recon surface.
The id is the answer key's `target`, so two benchmarks with the same target fail loud rather than
one silently shadowing the other, invariant 4 applied to discovery. `find_benchmark` fails loud with
the known names, so a typo is obvious rather than a silently empty score.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from evals.schema import AnswerKey, load_answer_key

_HERE = Path(__file__).resolve().parent
BENCHMARKS = _HERE / "benchmarks"


@dataclass(frozen=True, kw_only=True)
class Benchmark:
    """One benchmark the registry knows about. `evidence` is the cassette or surface fed to the
    engine, `answer_key` the golden beside it. `kind` and `tags` drive suite selection."""

    id: str
    kind: str
    evidence: Path
    answer_key: Path
    tags: tuple[str, ...]

    def key(self) -> AnswerKey:
        return load_answer_key(self.answer_key)


_EVIDENCE = {"surface": "surface.json", "discovery": "sources.json"}


def _evidence_for(directory: Path, kind: str) -> Path:
    """The evidence file beside an answer key, named by kind. A surface fixture carries a
    `surface.json`, a discovery fixture the recorded passive-source `sources.json`, a host or
    negative a `cassette.json`, so a missing one fails loud rather than reading as an empty run,
    invariant 5."""
    name = _EVIDENCE.get(kind, "cassette.json")
    evidence = directory / name
    if not evidence.is_file():
        raise ValueError(f"benchmark {directory} declares kind {kind!r} but has no {name}")
    return evidence


def _tags(bench_dir: Path, root: Path, kind: str) -> tuple[str, ...]:
    """The selection tags a benchmark carries: its kind, and each grouping directory between the
    benchmarks root and the leaf, so a suite can select all hosts, all surfaces, or one product."""
    parts = bench_dir.relative_to(root).parts[:-1]
    return (kind, *parts)


def all_benchmarks(root: Path = BENCHMARKS) -> dict[str, Benchmark]:
    """Every benchmark under the root, keyed by target. A duplicate target fails loud."""
    found: dict[str, Benchmark] = {}
    for key_path in sorted(root.rglob("answer-key.yaml")):
        answer = load_answer_key(key_path)
        evidence = _evidence_for(key_path.parent, answer.kind)
        tags = _tags(key_path.parent, root, answer.kind)
        if answer.target in found:
            raise ValueError(
                f"two benchmarks share the target {answer.target!r}, at "
                f"{found[answer.target].answer_key} and {key_path}. Rename one.")
        found[answer.target] = Benchmark(id=answer.target, kind=answer.kind, evidence=evidence,
                                         answer_key=key_path, tags=tags)
    return found


def find_benchmark(name: str, root: Path = BENCHMARKS) -> Benchmark:
    """Resolve a benchmark by target, failing loud with the known names so a typo or an unbuilt
    tree is obvious rather than a silent empty score, invariant 5."""
    benches = all_benchmarks(root)
    if name not in benches:
        known = ", ".join(sorted(benches)) or "none"
        raise ValueError(f"no benchmark {name!r}. Known: {known}")
    return benches[name]
