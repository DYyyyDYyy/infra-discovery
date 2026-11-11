"""SQLite-backed CMDB graph with change history.

Every scan is reconciled against the stored state of the hosts it covered:
new keys are ``added``, changed attributes are ``changed``, missing keys are
``removed`` (soft delete). Unchanged items only get ``last_scan`` bumped, so a
repeated scan of an unchanged estate records no changes.
"""

from __future__ import annotations

import getpass
import json
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

from .graph import Edge, Graph, Node

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, actor TEXT NOT NULL, targets TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS nodes (
    key TEXT PRIMARY KEY, kind TEXT NOT NULL, host TEXT NOT NULL, attrs TEXT NOT NULL,
    first_scan INTEGER NOT NULL, last_scan INTEGER NOT NULL, removed INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS edges (
    src TEXT NOT NULL, kind TEXT NOT NULL, dst TEXT NOT NULL, host TEXT NOT NULL,
    first_scan INTEGER NOT NULL, last_scan INTEGER NOT NULL, removed INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (src, kind, dst)
);
CREATE TABLE IF NOT EXISTS changes (
    id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id INTEGER NOT NULL REFERENCES scans(id),
    entity TEXT NOT NULL, key TEXT NOT NULL, op TEXT NOT NULL, before TEXT, after TEXT
);
"""


@dataclass(frozen=True)
class Change:
    scan_id: int
    entity: str  # node | edge
    key: str
    op: str  # added | changed | removed
    before: dict[str, str] | None
    after: dict[str, str] | None

    def __str__(self) -> str:
        sign = {"added": "+", "changed": "~", "removed": "-"}[self.op]
        if self.op == "changed" and self.before is not None and self.after is not None:
            b, a = self.before, self.after
            parts = [f"{k}: {b.get(k)!r} -> {a.get(k)!r}" for k in sorted(set(b) | set(a)) if b.get(k) != a.get(k)]
            return f"{sign} {self.entity} {self.key} ({'; '.join(parts)})"
        return f"{sign} {self.entity} {self.key}"

    def as_dict(self) -> dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "entity": self.entity,
            "key": self.key,
            "op": self.op,
            "before": self.before,
            "after": self.after,
        }


def _actor() -> str:
    try:
        return getpass.getuser()
    except (KeyError, OSError):  # e.g. a container running under an arbitrary uid
        return "unknown"


def _load(text: str | None) -> dict[str, str] | None:
    return json.loads(text) if text is not None else None


class CMDB:
    def __init__(self, path: Path | str) -> None:
        self.db = sqlite3.connect(str(path), check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SCHEMA)

    def close(self) -> None:
        self.db.close()

    # -- writes -----------------------------------------------------------
    def record(self, graph: Graph, hosts: set[str], targets: list[str]) -> tuple[int, list[Change]]:
        """Store one scan; ``hosts`` are the hosts that were successfully scanned."""
        with self.db:
            cur = self.db.execute(
                "INSERT INTO scans (ts, actor, targets) VALUES (?, ?, ?)",
                (datetime.now(UTC).isoformat(timespec="seconds"), _actor(), ",".join(targets)),
            )
            scan_id = int(cur.lastrowid or 0)
            changes = self._reconcile_nodes(scan_id, graph.nodes, hosts) + self._reconcile_edges(
                scan_id, graph.edges, hosts
            )
            self.db.executemany(
                "INSERT INTO changes (scan_id, entity, key, op, before, after) VALUES (?, ?, ?, ?, ?, ?)",
                [
                    (
                        c.scan_id,
                        c.entity,
                        c.key,
                        c.op,
                        json.dumps(c.before, sort_keys=True) if c.before is not None else None,
                        json.dumps(c.after, sort_keys=True) if c.after is not None else None,
                    )
                    for c in changes
                ],
            )
        return scan_id, changes

    def _reconcile_nodes(self, scan_id: int, nodes: dict[str, Node], hosts: set[str]) -> list[Change]:
        changes: list[Change] = []
        stored = {r["key"]: r for r in self.db.execute("SELECT * FROM nodes")}
        for key, n in nodes.items():
            row = stored.get(key)
            if row is None or row["removed"]:
                op = "added"
                before = None
            else:
                before = json.loads(row["attrs"])
                op = "changed" if before != n.attrs else ""
            if op:
                changes.append(Change(scan_id, "node", key, op, before, n.attrs))
            self.db.execute(
                "INSERT INTO nodes (key, kind, host, attrs, first_scan, last_scan) VALUES (?, ?, ?, ?, ?, ?)"
                " ON CONFLICT(key) DO UPDATE SET attrs=excluded.attrs, host=excluded.host,"
                " last_scan=excluded.last_scan, removed=0,"
                " first_scan=CASE WHEN nodes.removed THEN excluded.first_scan ELSE nodes.first_scan END",
                (key, n.kind, n.host, json.dumps(n.attrs, sort_keys=True), scan_id, scan_id),
            )
        for key, row in stored.items():
            if key not in nodes and not row["removed"] and row["host"] in hosts:
                changes.append(Change(scan_id, "node", key, "removed", json.loads(row["attrs"]), None))
                self.db.execute("UPDATE nodes SET removed=1, last_scan=? WHERE key=?", (scan_id, key))
        return changes

    def _reconcile_edges(self, scan_id: int, edges: dict[str, Edge], hosts: set[str]) -> list[Change]:
        changes: list[Change] = []
        stored = {f"{r['src']} -{r['kind']}-> {r['dst']}": r for r in self.db.execute("SELECT * FROM edges")}
        for key, e in edges.items():
            row = stored.get(key)
            if row is None or row["removed"]:
                changes.append(Change(scan_id, "edge", key, "added", None, None))
            self.db.execute(
                "INSERT INTO edges (src, kind, dst, host, first_scan, last_scan) VALUES (?, ?, ?, ?, ?, ?)"
                " ON CONFLICT(src, kind, dst) DO UPDATE SET last_scan=excluded.last_scan,"
                " host=excluded.host, removed=0",
                (e.src, e.kind, e.dst, e.host, scan_id, scan_id),
            )
        for key, row in stored.items():
            if key not in edges and not row["removed"] and row["host"] in hosts:
                changes.append(Change(scan_id, "edge", key, "removed", None, None))
                self.db.execute(
                    "UPDATE edges SET removed=1, last_scan=? WHERE src=? AND kind=? AND dst=?",
                    (scan_id, row["src"], row["kind"], row["dst"]),
                )
        return changes

    # -- reads ------------------------------------------------------------
    def nodes(self, kind: str | None = None) -> list[Node]:
        q, args = "SELECT * FROM nodes WHERE removed=0", cast("tuple[str, ...]", ())
        if kind:
            q, args = q + " AND kind=?", (kind,)
        return [
            Node(r["key"], r["kind"], r["host"], json.loads(r["attrs"]))
            for r in self.db.execute(q + " ORDER BY key", args)
        ]

    def edges(self) -> list[Edge]:
        rows = self.db.execute("SELECT * FROM edges WHERE removed=0 ORDER BY src, kind, dst")
        return [Edge(r["src"], r["kind"], r["dst"], r["host"]) for r in rows]

    def scans(self) -> list[dict[str, Any]]:
        return [dict(r) for r in self.db.execute("SELECT * FROM scans ORDER BY id")]

    def last_scan_id(self) -> int:
        row = self.db.execute("SELECT MAX(id) FROM scans").fetchone()
        return int(row[0] or 0)

    def diff(self, from_scan: int | None = None, to_scan: int | None = None) -> list[Change]:
        """Changes after ``from_scan`` up to and including ``to_scan`` (default: the last scan only)."""
        to_scan = to_scan if to_scan is not None else self.last_scan_id()
        from_scan = from_scan if from_scan is not None else to_scan - 1
        rows = self.db.execute(
            "SELECT * FROM changes WHERE scan_id > ? AND scan_id <= ? ORDER BY id", (from_scan, to_scan)
        )
        return [
            Change(r["scan_id"], r["entity"], r["key"], r["op"], _load(r["before"]), _load(r["after"])) for r in rows
        ]
