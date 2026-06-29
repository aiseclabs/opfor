"""The prompt-probe executor: send one injection prompt, judge by the canary.

A non-web attack surface on the same engine. The executor sends one crafted
prompt to an LLM endpoint and structures the reply. If the injection's canary
appears in the reply, the model obeyed the injected instruction, which is a clean
oracle that the injection worked, so the finding is confirmed in band (LLM replies
are stochastic, so re-running is unreliable; the canary's specificity is the
guard instead). No attack logic lives here, the techniques are data.
"""

from __future__ import annotations

import json
import urllib.parse

from opfor.model import Fact, Finding, Observation
from opfor.plugins.base import Executor
from opfor.scenarios.apiscan.executors import _do


class PromptProbeExecutor(Executor):
    capability = "prompt_probe"

    def run(self, task, graph) -> Observation:
        tpl = task.params["template"]
        field = task.params.get("prompt_field", "prompt")
        raw = _do(task.params["base_url"], "POST", task.params.get("path", "/"),
                  body=json.dumps({field: tpl["payload"]}), content_type="application/json")
        raw["template"] = tpl
        raw["base_url"] = task.params["base_url"]
        return Observation(entrypoint_id=task.id, action="prompt_probe", raw=raw)

    def perceive(self, observation) -> list[Fact]:
        raw = observation.raw
        tpl = raw["template"]
        body = raw.get("body") or ""
        if raw.get("error") or tpl["canary"] not in body:
            return [Fact(kind="check-clean", about=observation.entrypoint_id, data={"id": tpl["id"]})]
        netloc = urllib.parse.urlsplit(raw.get("base_url") or "").netloc
        finding = Finding(
            id=f"finding:{tpl['id']}:{netloc}",
            props={
                "title": tpl.get("title", tpl["id"]), "severity": tpl.get("severity", "medium"),
                "domain": netloc, "url": raw.get("base_url"),
                "evidence": f"the model emitted the injected canary '{tpl['canary']}'",
                "body_snippet": body[:240],
            },
        )
        # The canary in the reply is the proof: confirmed in band, no replay.
        return [
            Fact(kind="vuln", about=observation.entrypoint_id, data={"id": tpl["id"], "severity": tpl.get("severity")}, yields=(finding,)),
            Fact(kind="verdict", about=finding.id, data={"finding": finding.id, "verdict": "confirmed",
                                                         "reason": "the model emitted the injected canary token"}),
        ]


def default_executors() -> dict[str, Executor]:
    return {"prompt_probe": PromptProbeExecutor()}
