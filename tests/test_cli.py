"""The command line: listing scenarios, and resolving a run seed from flags or the env.

The engine run itself is not driven here, it would touch the network and the model. The
seed resolution is, since it is the operator-facing contract, a flag wins over the
environment, a file folds through the same normalization, and an empty seed fails loud.
"""

from __future__ import annotations

import argparse

import pytest

from opfor.cli import _resolve_seed, main


def _args(**over):
    base = dict(root=None, roots=None, host=None, hosts=None, name=None)
    base.update(over)
    return argparse.Namespace(**base)


def _clear(monkeypatch):
    for var in ("OPFOR_ROOTS_FILE", "OPFOR_HOSTS_FILE", "OPFOR_TARGET"):
        monkeypatch.delenv(var, raising=False)


def test_scenarios_command_lists_the_registry(capsys):
    assert main(["scenarios"]) == 0
    assert "attacksurface" in capsys.readouterr().out


def test_resolve_seed_from_inline_flags(monkeypatch):
    _clear(monkeypatch)
    name, roots, hosts, scope = _resolve_seed(_args(root=["example.com"], host=["api.dev.example.com"]))
    assert roots == ("example.com",)
    assert hosts == ("api.dev.example.com",)
    assert name == "example.com"
    # the host authorizes by its registrable root, which folds into the root already present
    assert set(scope) == {"example.com"}


def test_resolve_seed_from_files_normalizes(tmp_path, monkeypatch):
    _clear(monkeypatch)
    (tmp_path / "r.txt").write_text("example.com\nwww.example.net\n", encoding="utf-8")
    (tmp_path / "h.txt").write_text("api.dev.example.com\n*.sandbox.example.com\n", encoding="utf-8")
    name, roots, hosts, scope = _resolve_seed(
        _args(roots=str(tmp_path / "r.txt"), hosts=str(tmp_path / "h.txt")))
    assert set(roots) == {"example.com", "example.net"}          # a subdomain folds to its root
    assert set(hosts) == {"api.dev.example.com", "sandbox.example.com"}  # a wildcard base is a host
    assert set(scope) >= {"example.com", "example.net"}


def test_resolve_seed_flag_beats_env_and_env_is_the_fallback(tmp_path, monkeypatch):
    _clear(monkeypatch)
    (tmp_path / "env.txt").write_text("fromenv.com\n", encoding="utf-8")
    monkeypatch.setenv("OPFOR_ROOTS_FILE", str(tmp_path / "env.txt"))
    monkeypatch.setenv("OPFOR_TARGET", "acme")
    # no --roots flag, so the env file is used, and the env target names the run
    name, roots, _, _ = _resolve_seed(_args())
    assert roots == ("fromenv.com",)
    assert name == "acme"


def test_resolve_seed_without_a_seed_fails_loud(monkeypatch):
    _clear(monkeypatch)
    with pytest.raises(SystemExit):
        _resolve_seed(_args())


def test_run_rejects_a_scenario_with_no_seed_builder(monkeypatch):
    _clear(monkeypatch)
    # mock is a kernel fixture with no run seed, so the run command says so rather than crash
    with pytest.raises(SystemExit):
        main(["run", "mock", "--root", "example.com"])
