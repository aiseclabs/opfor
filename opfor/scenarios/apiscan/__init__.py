"""The apiscan scenario, self-built active vulnerability checks.

Active, payload-sending checks (LFI, command injection, SSTI, SQLi, open
redirect, secret exposure) driven entirely by data templates, no external tool.
The engine is generic, the templates are the knowledge. This is the "build it
ourselves" path: our own miniature of a templated scanner, fully in Python.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from opfor.scenarios.apiscan.executors import default_executors
from opfor.scenarios.apiscan.planner import ApiscanPlanner
from opfor.scenarios.base import ControlScenario

_TEMPLATES = yaml.safe_load((Path(__file__).resolve().parent / "templates.yaml").read_text())

APISCAN = ControlScenario(
    name="apiscan",
    content_root=Path(__file__).resolve().parent,
    executors=default_executors(),
    planner=ApiscanPlanner(_TEMPLATES),
)
