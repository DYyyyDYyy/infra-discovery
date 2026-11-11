"""Command line: ``discover scan|analyze|diff|graph|serve|wait``."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

from . import collector
from .cmdb import CMDB, Change
from .dsl import RuleError, load_rules
from .engine import analyze
from .graph import build_graph, to_mermaid
from .models import RawScan


def _record(args: argparse.Namespace, raws: list[RawScan]) -> int:
    try:
        rules = load_rules(args.rules)
    except RuleError as exc:
        print(f"rule error: {exc}", file=sys.stderr)
        return 2
    ok = [r for r in raws if "connect" not in r.errors]
    for r in raws:
        for source, err in r.errors.items():
            print(f"warning: {r.target}: {source}: {err}", file=sys.stderr)
    inventories = [analyze(r, rules) for r in ok]
    graph = build_graph(inventories)
    cmdb = CMDB(args.db)
    scan_id, changes = cmdb.record(graph, {i.host.name for i in inventories}, [r.target for r in raws])
    print(f"scan #{scan_id}: {len(ok)}/{len(raws)} hosts, {len(graph.nodes)} nodes, {len(graph.edges)} edges")
    for inv in inventories:
        sw = ", ".join(f"{s.name} {s.version or '?'}" for s in inv.software)
        print(f"  {inv.host.name:<8} {inv.host.attrs.get('os_name', '?')} {inv.host.attrs.get('os_version', '')}: {sw}")
    _print_changes(changes)
    cmdb.close()
    if len(ok) < len(raws):
        return 1
    if getattr(args, "expect_no_changes", False) and changes:
        print("expected no changes", file=sys.stderr)
        return 3
    return 0


def _print_changes(changes: list[Change]) -> None:
    print(f"diff: {len(changes)} change(s)" if changes else "diff: no changes")
    for c in changes:
        print(f"  {c}")


def cmd_scan(args: argparse.Namespace) -> int:
    targets = [collector.Target.parse(t, args.user) for t in args.targets]
    creds = collector.Credentials(args.key, args.timeout, args.timeout)
    raws = asyncio.run(collector.scan_many(targets, creds, args.concurrency))
    if args.save_raw:
        collector.save_raw(raws, args.save_raw)
    return _record(args, raws)


def cmd_analyze(args: argparse.Namespace) -> int:
    return _record(args, [collector.load_raw(p) for p in args.files])


def cmd_diff(args: argparse.Namespace) -> int:
    cmdb = CMDB(args.db)
    _print_changes(cmdb.diff(args.from_scan, args.to_scan))
    return 0


def cmd_graph(args: argparse.Namespace) -> int:
    cmdb = CMDB(args.db)
    nodes, edges = cmdb.nodes(), cmdb.edges()
    if args.format == "mermaid":
        if not args.processes:
            nodes = [n for n in nodes if n.kind != "process"]
        print(to_mermaid(nodes, edges), end="")
    else:
        print(json.dumps({"nodes": [n.__dict__ for n in nodes], "edges": [e.__dict__ for e in edges]}, indent=2))
    return 0


def cmd_serve(args: argparse.Namespace) -> int:  # pragma: no cover - runs a server
    import uvicorn

    from .api import create_app

    uvicorn.run(create_app(args.db), host=args.host, port=args.port)
    return 0


def cmd_wait(args: argparse.Namespace) -> int:
    targets = [collector.Target.parse(t) for t in args.targets]
    missing = asyncio.run(collector.wait_for_ssh(targets, args.timeout))
    if missing:
        print("not reachable: " + " ".join(map(str, missing)), file=sys.stderr)
        return 1
    if args.settle:
        asyncio.run(asyncio.sleep(args.settle))  # let services behind sshd finish starting
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="discover", description="Agentless software discovery and mini CMDB")
    p.add_argument("--db", type=Path, default=Path("cmdb.sqlite"), help="CMDB SQLite file")
    p.add_argument("--rules", type=Path, default=Path("rules"), help="directory with *.rule files")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="scan targets over SSH and update the CMDB")
    s.add_argument("targets", nargs="+", help="[user@]host[:port]")
    s.add_argument("--key", type=Path, required=True, help="private key for SSH")
    s.add_argument("--user", default="root")
    s.add_argument("--concurrency", type=int, default=10)
    s.add_argument("--timeout", type=float, default=10.0)
    s.add_argument("--save-raw", type=Path, help="also write raw outputs as JSON to this directory")
    s.add_argument("--expect-no-changes", action="store_true", help="exit 3 if the scan changed the CMDB")
    s.set_defaults(func=cmd_scan)

    a = sub.add_parser("analyze", help="run rules on saved raw JSON (no SSH) and update the CMDB")
    a.add_argument("files", nargs="+", type=Path)
    a.add_argument("--expect-no-changes", action="store_true")
    a.set_defaults(func=cmd_analyze)

    d = sub.add_parser("diff", help="show changes (default: of the last scan)")
    d.add_argument("--from", dest="from_scan", type=int)
    d.add_argument("--to", dest="to_scan", type=int)
    d.set_defaults(func=cmd_diff)

    g = sub.add_parser("graph", help="print the current graph")
    g.add_argument("--format", choices=["mermaid", "json"], default="mermaid")
    g.add_argument("--processes", action="store_true", help="include process nodes in mermaid output")
    g.set_defaults(func=cmd_graph)

    v = sub.add_parser("serve", help="REST API + graph page")
    v.add_argument("--host", default="127.0.0.1")
    v.add_argument("--port", type=int, default=8000)
    v.set_defaults(func=cmd_serve)

    w = sub.add_parser("wait", help="wait until targets accept SSH connections")
    w.add_argument("targets", nargs="+")
    w.add_argument("--timeout", type=float, default=60.0)
    w.add_argument("--settle", type=float, default=0.0, help="extra seconds to wait afterwards")
    w.set_defaults(func=cmd_wait)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.func(args))
