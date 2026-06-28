"""Checkpoint and resume.

Invariant 3: the loop must be able to suspend and resume, including across a
process restart, because results can arrive hours or days later. A Workspace is
a run directory holding the checkpoint, the ledger, and the report. The loop
writes a full checkpoint after every step, so a resume picks up exactly where it
left off.
"""

from __future__ import annotations

import json
from pathlib import Path


class Workspace:
    """A run directory. Owns the paths the engine reads and writes."""

    def __init__(self, run_dir: str | Path) -> None:
        self.dir = Path(run_dir)
        self.dir.mkdir(parents=True, exist_ok=True)

    @property
    def state_file(self) -> Path:
        return self.dir / "state.json"

    @property
    def ledger_file(self) -> Path:
        return self.dir / "ledger.jsonl"

    @property
    def report_file(self) -> Path:
        return self.dir / "report.md"

    def has_state(self) -> bool:
        return self.state_file.exists()

    def save_state(self, payload: dict) -> None:
        """Write the checkpoint atomically so a crash cannot truncate it."""
        tmp = self.state_file.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(payload, indent=2))
        tmp.replace(self.state_file)

    def load_state(self) -> dict:
        if not self.has_state():
            raise FileNotFoundError(f"no checkpoint at {self.state_file}")
        return json.loads(self.state_file.read_text())
