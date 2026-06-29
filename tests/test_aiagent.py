from opfor.engine.graph import SituationGraph
from opfor.model import Target
from opfor.scenarios.aiagent import AIAGENT, _INJECTIONS
from opfor.scenarios.aiagent.executors import PromptProbeExecutor
from opfor.scenarios.aiagent.planner import AiAgentPlanner
from opfor.model import Observation


def test_scenario_is_registered_and_generic():
    from opfor.scenarios.registry import get_scenario
    s = get_scenario("aiagent")
    assert "prompt_probe" in s.executors
    assert _INJECTIONS  # knowledge is data


def test_planner_emits_one_probe_per_injection_per_agent():
    graph = SituationGraph()
    graph.add_target(Target(id="bot", kind="ai_agent", props={"url": "http://h/chat", "host": "h"}))
    graph.add_target(Target(id="web", kind="web_host", props={"host": "h"}))  # not an ai_agent
    tasks = AiAgentPlanner(_INJECTIONS).expand(graph)
    assert len(tasks) == len(_INJECTIONS)
    assert all(t.capability == "prompt_probe" and t.tier == "intrusive" for t in tasks)


def _perceive(body: str):
    ex = PromptProbeExecutor()
    tpl = _INJECTIONS[0]
    obs = Observation(entrypoint_id="t", action="prompt_probe",
                      raw={"template": tpl, "base_url": "http://h/", "body": body})
    return ex.perceive(obs), tpl


def test_canary_in_reply_confirms_the_injection():
    tpl = _INJECTIONS[0]
    facts, tpl = _perceive(f"sure: {tpl['canary']}")
    findings = [e for f in facts for e in f.yields]
    verdicts = {f.data["finding"]: f.data["verdict"] for f in facts if f.kind == "verdict"}
    assert findings and verdicts[findings[0].id] == "confirmed"


def test_no_canary_is_clean():
    facts, _ = _perceive("I cannot help with that.")
    assert all(f.kind == "check-clean" for f in facts)
