import json

from opfor.engine.ledger import Ledger


def test_append_assigns_sequence_and_verifies(tmp_path):
    ledger = Ledger(tmp_path / "l.jsonl")
    ledger.append("act", x=1)
    ledger.append("act", x=2)
    entries = ledger.entries()
    assert [e["seq"] for e in entries] == [0, 1]
    assert ledger.verify()


def test_chain_resumes_across_instances(tmp_path):
    path = tmp_path / "l.jsonl"
    Ledger(path).append("a")
    second = Ledger(path)
    second.append("b")
    assert len(second.entries()) == 2
    assert second.verify()


def test_tampering_is_detected(tmp_path):
    path = tmp_path / "l.jsonl"
    ledger = Ledger(path)
    ledger.append("a", x=1)
    ledger.append("b", x=2)
    lines = path.read_text().splitlines()
    altered = json.loads(lines[0])
    altered["x"] = 999
    lines[0] = json.dumps(altered)
    path.write_text("\n".join(lines) + "\n")
    assert not Ledger(path).verify()
