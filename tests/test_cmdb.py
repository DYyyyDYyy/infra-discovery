from __future__ import annotations

from pathlib import Path

from infra_discovery.cmdb import CMDB
from infra_discovery.dsl import Rule
from infra_discovery.engine import analyze
from infra_discovery.graph import Graph, build_graph
from infra_discovery.models import RawScan

ALL = {"web", "db", "cache", "app"}


def lab_graph(rules: list[Rule], raws: dict[str, RawScan], **overrides: RawScan) -> Graph:
    return build_graph([analyze(overrides.get(h, r), rules) for h, r in raws.items()])


def test_repeated_scan_is_idempotent(tmp_path: Path, rules: list[Rule], raws: dict[str, RawScan]) -> None:
    db = CMDB(tmp_path / "c.sqlite")
    g = lab_graph(rules, raws)
    s1, first = db.record(g, ALL, ["t"])
    s2, second = db.record(lab_graph(rules, raws), ALL, ["t"])
    assert len(first) == len(g.nodes) + len(g.edges)
    assert all(c.op == "added" for c in first)
    assert second == []
    assert db.diff() == []
    assert len(db.diff(0, s2)) == len(first)
    assert len(db.nodes()) == len(g.nodes)
    assert len(db.edges()) == len(g.edges)
    assert [s["id"] for s in db.scans()] == [s1, s2]


def test_change_remove_and_readd(tmp_path: Path, rules: list[Rule], raws: dict[str, RawScan]) -> None:
    db = CMDB(tmp_path / "c.sqlite")
    db.record(lab_graph(rules, raws), ALL, ["t"])

    web = raws["web"]
    upgraded = web.model_copy(
        update={"outputs": {**web.outputs, "packages": web.outputs["packages"].replace("nginx 1.26.3", "nginx 1.28.0")}}
    )
    _, changes = db.record(lab_graph(rules, raws, web=upgraded), ALL, ["t"])
    assert [str(c) for c in changes] == ["~ node software:web/nginx (version: '1.26.3' -> '1.28.0')"]

    stopped = web.model_copy(
        update={"outputs": {**web.outputs, "ps": web.outputs["ps"].replace("nginx: master process", "x")}}
    )
    _, changes = db.record(lab_graph(rules, raws, web=stopped), ALL, ["t"])
    removed = {c.key for c in changes if c.op == "removed"}
    assert "software:web/nginx" in removed
    assert "host:web -runs-> software:web/nginx" in removed
    assert "software:web/nginx" not in {n.key for n in db.nodes()}
    # port 80 is still open, now owned by the host instead of nginx
    assert any(c.op == "added" and c.key == "host:web -listens_on-> listener:web/tcp/80" for c in changes)

    _, changes = db.record(lab_graph(rules, raws), ALL, ["t"])
    assert {c.key for c in changes if c.op == "added"} >= {"software:web/nginx", "host:web -runs-> software:web/nginx"}
    assert db.nodes("software")


def test_unscanned_hosts_are_kept(tmp_path: Path, rules: list[Rule], raws: dict[str, RawScan]) -> None:
    db = CMDB(tmp_path / "c.sqlite")
    db.record(lab_graph(rules, raws), ALL, ["t"])
    only_web = build_graph([analyze(raws["web"], rules)])
    _, changes = db.record(only_web, {"web"}, ["web"])
    assert changes == []
    assert {n.host for n in db.nodes("host")} == ALL
