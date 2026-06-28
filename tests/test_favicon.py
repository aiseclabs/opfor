from opfor.engine.graph import SituationGraph
from opfor.engine.ledger import Ledger
from opfor.model import Fact, Service
from opfor.report import render
from opfor.scenarios.recon.favicon import favicon_hash, murmur3_32


def test_murmur3_known_vector_and_determinism():
    # Empty input hashes to 0 in MurmurHash3 x86 32-bit.
    assert murmur3_32(b"") == 0
    assert murmur3_32(b"opfor") == murmur3_32(b"opfor")
    assert murmur3_32(b"opfor") != murmur3_32(b"other")


def test_favicon_hash_is_stable_and_distinguishes():
    a = favicon_hash(b"\x00icon-bytes-A")
    b = favicon_hash(b"\x00icon-bytes-B")
    assert isinstance(a, int)
    assert a == favicon_hash(b"\x00icon-bytes-A")
    assert a != b


def test_report_clusters_hosts_by_favicon(tmp_path):
    graph = SituationGraph()
    # Two hosts share a favicon, one stands alone.
    graph.add_entity(Service(id="https://a.example.com/", props={"domain": "a.example.com", "status": 200}))
    for d, h in [("a.example.com", 111), ("b.example.com", 111), ("c.example.com", 222)]:
        graph.absorb([Fact(kind="favicon", about=d, data={"domain": d, "url": f"https://{d}/", "hash": h})])

    text = render(graph, Ledger(tmp_path / "l.jsonl"), stopped_reason="done")
    assert "Favicon clusters" in text
    assert "http.favicon.hash:111" in text
    # The 2-host cluster is listed before the 1-host one.
    assert text.index("hash 111") < text.index("hash 222")
