from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from infra_discovery.api import create_app
from infra_discovery.cli import main

from .conftest import FIXTURES, HOSTS, RULES

FILES = [str(FIXTURES / f"{h}.json") for h in HOSTS]


def run(db: Path, *args: str) -> int:
    return main(["--db", str(db), "--rules", str(RULES), *args])


def test_analyze_diff_graph(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    db = tmp_path / "c.sqlite"
    assert run(db, "analyze", *FILES) == 0
    out = capsys.readouterr().out
    assert "scan #1: 4/4 hosts" in out
    assert "+ node software:web/nginx" in out

    assert run(db, "analyze", *FILES, "--expect-no-changes") == 0
    assert "diff: no changes" in capsys.readouterr().out

    assert run(db, "diff", "--from", "0", "--to", "1") == 0
    assert "+ edge software:app/psql -connects_to-> software:db/postgresql" in capsys.readouterr().out

    assert run(db, "graph") == 0
    mermaid = capsys.readouterr().out
    assert mermaid.startswith("graph LR") and "process" not in mermaid
    assert run(db, "graph", "--processes") == 0
    assert 'web/nginx"]' in capsys.readouterr().out

    assert run(db, "graph", "--format", "json") == 0
    data = json.loads(capsys.readouterr().out)
    assert len(data["nodes"]) == 29


def test_expect_no_changes_fails_on_first_scan(tmp_path: Path) -> None:
    assert run(tmp_path / "c.sqlite", "analyze", *FILES, "--expect-no-changes") == 3


def test_rule_error_exit_code(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    (tmp_path / "bad.rule").write_text("rule x { kind host }")
    assert main(["--db", str(tmp_path / "c.sqlite"), "--rules", str(tmp_path), "analyze", *FILES]) == 2
    assert "rule error" in capsys.readouterr().err


def test_scan_unreachable(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    key = tmp_path / "key"
    key.write_text("unused")
    raw_dir = tmp_path / "raw"
    rc = run(
        tmp_path / "c.sqlite", "scan", "127.0.0.1:1", "--key", str(key), "--timeout", "2", "--save-raw", str(raw_dir)
    )
    assert rc == 1
    assert "connect" in capsys.readouterr().err
    assert (raw_dir / "127.0.0.1_1.json").exists()


def test_wait(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert run(tmp_path / "c.sqlite", "wait", "127.0.0.1:1", "--timeout", "0.5") == 1
    assert "not reachable: 127.0.0.1:1" in capsys.readouterr().err


def test_api(tmp_path: Path) -> None:
    db = tmp_path / "c.sqlite"
    run(db, "analyze", *FILES)
    client = TestClient(create_app(db))
    assert "cytoscape" in client.get("/").text
    hosts = client.get("/hosts").json()
    assert {h["name"] for h in hosts} == set(HOSTS)
    assert next(h for h in hosts if h["name"] == "db")["os_name"] == "Rocky Linux"
    graph = client.get("/graph").json()
    assert {"src": "software:app/redis-cli", "kind": "connects_to", "dst": "software:cache/redis"} in graph["edges"]
    assert len(client.get("/diff", params={"from_scan": 0}).json()) == len(graph["nodes"]) + len(graph["edges"])
    assert client.get("/diff").json() == client.get("/diff", params={"from_scan": 0, "to_scan": 1}).json()
    assert client.get("/scans").json()[0]["id"] == 1
