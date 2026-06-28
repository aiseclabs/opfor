"""The audit ledger, an append-only record of everything the engine did.

Invariant 4: every act, and every scope decision, is recorded. The ledger is
append-only JSONL so a run can be reconstructed and audited after the fact. Each
entry carries a sequence number and the hash of the previous entry, a light
tamper-evident chain. A stronger signed chain is a future seam.
"""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any

_GENESIS = "0" * 64


class Ledger:
    """Append-only JSONL ledger with a hash chain over entries."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._seq, self._prev_hash = self._tail()

    def _tail(self) -> tuple[int, str]:
        """Resume the chain from an existing file, or start fresh."""
        if not self.path.exists():
            return 0, _GENESIS
        last = None
        for line in self.path.read_text().splitlines():
            line = line.strip()
            if line:
                last = json.loads(line)
        if last is None:
            return 0, _GENESIS
        return last["seq"] + 1, last["hash"]

    def append(self, kind: str, **fields: Any) -> dict:
        """Append one entry, return it. The hash chains to the previous entry."""
        entry = {
            "seq": self._seq,
            "ts": time.time(),
            "kind": kind,
            "prev": self._prev_hash,
            **fields,
        }
        digest = hashlib.sha256(
            json.dumps(entry, sort_keys=True).encode()
        ).hexdigest()
        entry["hash"] = digest
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a") as fh:
            fh.write(json.dumps(entry) + "\n")
        self._seq += 1
        self._prev_hash = digest
        return entry

    def entries(self) -> list[dict]:
        if not self.path.exists():
            return []
        out = []
        for line in self.path.read_text().splitlines():
            line = line.strip()
            if line:
                out.append(json.loads(line))
        return out

    def verify(self) -> bool:
        """Re-walk the chain and confirm no entry was altered or removed."""
        prev = _GENESIS
        for entry in self.entries():
            if entry.get("prev") != prev:
                return False
            recorded = entry.get("hash")
            recomputed = {k: v for k, v in entry.items() if k != "hash"}
            digest = hashlib.sha256(
                json.dumps(recomputed, sort_keys=True).encode()
            ).hexdigest()
            if digest != recorded:
                return False
            prev = recorded
        return True
