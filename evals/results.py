"""The scored result, and the suite result that folds N repeated runs by frequency.

A single run is one Result. Because the model is not deterministic, a benchmark repeats and
folds the runs into a SuiteResult, crediting a planted issue only when a strict majority of
runs caught it and counting a false positive only when a majority raised it, so one lucky or
unlucky run cannot move the verdict.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field


@dataclass(kw_only=True)
class Result:
    target: str
    found: list[str] = field(default_factory=list)
    missed: list[str] = field(default_factory=list)
    false_positives: list[str] = field(default_factory=list)
    extra: list[str] = field(default_factory=list)
    n_planted: int = 0
    n_reports: int = 0
    # engine steps that failed, counted rather than hidden, invariant 5
    errors: int = 0

    @property
    def recall(self) -> float:
        return len(self.found) / self.n_planted if self.n_planted else 0.0

    @property
    def precision_known(self) -> float:
        """Real reports over reports that landed on a known entry, planted or safe. An extra
        report is excluded, since the key cannot say whether it is a real issue it misses."""
        known = len(self.found) + len(self.false_positives)
        return len(self.found) / known if known else 1.0

    def to_dict(self) -> dict:
        d = asdict(self)
        d["runs"] = 1
        d["recall"] = round(self.recall, 4)
        d["precision_known"] = round(self.precision_known, 4)
        return d


@dataclass(kw_only=True)
class SuiteResult:
    target: str
    runs: int
    found_freq: dict[str, int]
    fp_freq: dict[str, int]
    n_planted: int = 0
    reports_total: int = 0
    errors: int = 0

    @classmethod
    def from_runs(cls, target: str, runs: list[Result]) -> "SuiteResult":
        if not runs:
            raise ValueError("no runs to aggregate")
        found_freq: dict[str, int] = {}
        fp_freq: dict[str, int] = {}
        for r in runs:
            for i in (*r.found, *r.missed):
                found_freq.setdefault(i, 0)
            for i in r.found:
                found_freq[i] += 1
            for i in r.false_positives:
                fp_freq[i] = fp_freq.get(i, 0) + 1
        return cls(target=target, runs=len(runs), found_freq=found_freq, fp_freq=fp_freq,
                   n_planted=max(r.n_planted for r in runs),
                   reports_total=sum(r.n_reports for r in runs),
                   errors=sum(r.errors for r in runs))

    def _majority(self, count: int) -> bool:
        return count * 2 > self.runs

    @property
    def found(self) -> list[str]:
        return sorted(i for i, c in self.found_freq.items() if self._majority(c))

    @property
    def missed(self) -> list[str]:
        caught = set(self.found)
        return sorted(i for i in self.found_freq if i not in caught)

    @property
    def false_positives(self) -> list[str]:
        return sorted(i for i, c in self.fp_freq.items() if self._majority(c))

    @property
    def n_reports(self) -> int:
        return self.reports_total

    @property
    def recall(self) -> float:
        return len(self.found) / self.n_planted if self.n_planted else 0.0

    @property
    def precision_known(self) -> float:
        known = len(self.found) + len(self.false_positives)
        return len(self.found) / known if known else 1.0

    def to_dict(self) -> dict:
        return {"target": self.target, "runs": self.runs, "found": self.found,
                "missed": self.missed, "false_positives": self.false_positives,
                "found_freq": dict(sorted(self.found_freq.items())),
                "fp_freq": dict(sorted(self.fp_freq.items())),
                "n_planted": self.n_planted, "n_reports": self.n_reports, "errors": self.errors,
                "recall": round(self.recall, 4), "precision_known": round(self.precision_known, 4)}
