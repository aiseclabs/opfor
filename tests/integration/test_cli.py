"""The command line: listing scenarios, and resolving a run seed from flags or the env.

The engine run itself is not driven here, it would touch the network and the model. The
seed resolution is, since it is the operator-facing contract, a flag wins over the
environment, a file folds through the same normalization, and an empty seed fails loud.
"""

from __future__ import annotations

import json

import pytest

from opfor.cli import main
from opfor.report import _report_json, _slug_target, default_output, persist
from opfor.scenarios.attacksurface import prepare_run


def _clear(monkeypatch):
    for var in ("OPFOR_ROOTS_FILE", "OPFOR_HOSTS_FILE", "OPFOR_TARGET"):
        monkeypatch.delenv(var, raising=False)


def test_scenarios_command_lists_the_registry(capsys):
    assert main(["scenarios"]) == 0
    assert "attacksurface" in capsys.readouterr().out


def test_prepare_run_seed_from_inline_flags(monkeypatch):
    _clear(monkeypatch)
    name, world, scope, _ = prepare_run(roots=("example.com",), hosts=("api.dev.example.com",))
    org = world.node("org:example.com").payload
    assert org.domains == ("example.com",)
    assert org.hosts == ("api.dev.example.com",)
    assert name == "example.com"
    # the host authorizes by its registrable root, which folds into the root already present
    assert set(scope.matcher.hosts) == {"example.com"}


def test_prepare_run_root_flag_folds_to_registrable_root(monkeypatch):
    _clear(monkeypatch)
    # a subdomain passed as a root flag folds to its registrable root, so it enumerates
    # example.com rather than www.example.com, which the certificate logs do not index as a root
    name, world, scope, _ = prepare_run(roots=("www.example.com", "API.example.com"))
    org = world.node(f"org:{name}").payload
    assert org.domains == ("example.com",)
    assert name == "example.com"
    assert set(scope.matcher.hosts) == {"example.com"}


def test_prepare_run_seed_from_files_normalizes(tmp_path, monkeypatch):
    _clear(monkeypatch)
    (tmp_path / "r.txt").write_text("example.com\nwww.example.net\n", encoding="utf-8")
    (tmp_path / "h.txt").write_text("api.dev.example.com\n*.sandbox.example.com\n", encoding="utf-8")
    name, world, scope, _ = prepare_run(
        roots_file=str(tmp_path / "r.txt"), hosts_file=str(tmp_path / "h.txt"))
    org = world.node(f"org:{name}").payload
    assert set(org.domains) == {"example.com", "example.net"}          # a subdomain folds to its root
    assert set(org.hosts) == {"api.dev.example.com", "sandbox.example.com"}  # a wildcard base is a host
    assert set(scope.matcher.hosts) >= {"example.com", "example.net"}


def test_prepare_run_flag_beats_env_and_env_is_the_fallback(tmp_path, monkeypatch):
    _clear(monkeypatch)
    (tmp_path / "env.txt").write_text("fromenv.com\n", encoding="utf-8")
    monkeypatch.setenv("OPFOR_ROOTS_FILE", str(tmp_path / "env.txt"))
    monkeypatch.setenv("OPFOR_TARGET", "acme")
    # no roots flag, so the env file is used, and the env target names the run
    name, world, _, _ = prepare_run()
    assert world.node("org:acme").payload.domains == ("fromenv.com",)
    assert name == "acme"


def test_prepare_run_without_a_seed_fails_loud(monkeypatch):
    _clear(monkeypatch)
    with pytest.raises(ValueError):
        prepare_run()


def test_chain_and_contract_are_aliases_for_root_and_host(monkeypatch):
    # the CLI stays scenario-agnostic, but onchain reads a root as a chain and a host as a contract,
    # so --chain and --contract are aliases onto the same generic slots and must parse there
    _clear(monkeypatch)
    captured: dict = {}
    monkeypatch.setattr("opfor.cli._run", lambda args: captured.update(vars(args)) or 0)
    main(["run", "onchain", "--chain", "arbitrum", "--contract", "0xABC", "--contract", "0xDEF"])
    assert captured["root"] == ["arbitrum"]
    assert captured["host"] == ["0xABC", "0xDEF"]


def test_run_rejects_a_scenario_with_no_seed_builder(monkeypatch):
    _clear(monkeypatch)
    # mock is a kernel fixture with no run seed, so the run command says so rather than crash
    with pytest.raises(SystemExit):
        main(["run", "mock", "--root", "example.com"])


# --- the run output artifacts, findings.json and report.md ------------------------------


def _report_with_findings():
    from opfor.core.phase import Phase
    from opfor.core.result import CLOSED, Finding, Report
    findings = (
        Finding(id="f1", title="Open spec", severity="MEDIUM", where="https://h/openapi.json",
                evidence="a spec answered 200",
                poc="UNVERIFIED, not executed against the target. Run the generated PoC script `poc/open-spec-h.py`",
                data={"poc_request": {"method": "GET", "url": "https://h/openapi.json",
                                      "expect": "HTTP 200", "source": "endpoint:h",
                                      "script": "poc/open-spec-h.py"},
                      "poc_script": "#!/usr/bin/env python3\nimport sys\nsys.exit(1)\n"}),
        Finding(id="f2", title="Dangling host", severity="LOW", where="old.h", evidence="e"),
    )
    return Report(scenario="attacksurface", status=CLOSED, reached=Phase.TRIAGE,
                  terminal=Phase.TRIAGE, findings=findings, notes=("a caveat",))


def test_report_json_carries_the_closure_contract_and_a_summary():
    obj = _report_json(_report_with_findings())
    assert obj["status"] == "closed"
    assert obj["reached"] == "TRIAGE" and obj["terminal"] == "TRIAGE"
    assert obj["summary"]["MEDIUM"] == 1 and obj["summary"]["LOW"] == 1
    assert obj["notes"] == ["a caveat"]
    # findings are ranked most severe first, and the grounded poc request rides the finding
    assert [f["id"] for f in obj["findings"]] == ["f1", "f2"]
    assert obj["findings"][0]["data"]["poc_request"]["url"] == "https://h/openapi.json"


def test_persist_writes_findings_json_and_report_md(tmp_path):
    outdir = persist(_report_with_findings(), None, "example.com", str(tmp_path / "run"))
    assert outdir is not None
    loaded = json.loads((outdir / "findings.json").read_text(encoding="utf-8"))
    assert loaded["status"] == "closed" and len(loaded["findings"]) == 2
    md = (outdir / "report.md").read_text(encoding="utf-8")
    assert "# opfor attacksurface run" in md
    assert "[MEDIUM] Open spec" in md and "grounded poc: GET https://h/openapi.json" in md
    assert "poc script: poc/open-spec-h.py" in md
    # a grounded finding's PoC script is written as its own runnable file under the run directory
    script = (outdir / "poc" / "open-spec-h.py").read_text(encoding="utf-8")
    assert script.startswith("#!/usr/bin/env python3")


def test_default_output_is_user_private_under_xdg_state(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    out = default_output("example.com")
    assert out == tmp_path / "opfor" / "runs" / "example.com"


def test_slug_target_makes_a_filesystem_safe_name():
    assert _slug_target("api/../weird name") == "api-..-weird-name"
    assert _slug_target("///") == "run"
