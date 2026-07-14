"""The score: match every report against the answer key and tally the result.

A planted issue is found when some report matches it. A report on a safe lookalike is a
false positive. A report on neither is extra, kept but unscored, since the key cannot say
whether it is a real issue the key misses.
"""

from __future__ import annotations

from evals.match import category_match, where_match
from evals.results import Result
from evals.schema import AnswerKey, KeyEntry, Report


def _matches(report: Report, entry: KeyEntry, *, safe: bool = False) -> bool:
    """Whether a report matches a key entry. A planted entry matches on where alone, since
    where is the precise anchor and the model's class label is noisy, so gating a real catch
    on the class would drop recall. A safe entry with a category also requires the class to
    agree, so the anchor guards one class on that where and an adjacent finding stays
    uncounted."""
    if not where_match(report.where, entry.where):
        return False
    if safe and entry.category:
        return category_match(report.category, entry.category)
    return True


def score(key: AnswerKey, reports: list[Report]) -> Result:
    res = Result(target=key.target, n_planted=len(key.planted), n_reports=len(reports))
    matched: set[str] = set()
    for planted in key.planted:
        # credit one report to one planted entry only, so a single report cannot satisfy two
        # entries that share a host anchor and inflate recall
        hit = next((r for r in reports if r.name not in matched and _matches(r, planted)), None)
        if hit is not None:
            res.found.append(planted.id)
            matched.add(hit.name)
        else:
            res.missed.append(planted.id)
    # a report matching any planted entry found a real issue, so it is never a false positive
    # on a safe anchor, even when it also matches a safe entry on the same host
    finds_planted = {r.name for r in reports if any(_matches(r, p) for p in key.planted)}
    for safe in key.safe:
        for r in reports:
            if r.name in matched or r.name in finds_planted:
                continue
            if _matches(r, safe, safe=True):
                res.false_positives.append(r.name)
                matched.add(r.name)
    res.extra = [r.name for r in reports if r.name not in matched]
    return res
