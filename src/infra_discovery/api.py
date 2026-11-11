"""REST API and a single-page graph view."""

from __future__ import annotations

from importlib.resources import files
from pathlib import Path
from typing import Any

from fastapi import FastAPI
from fastapi.responses import HTMLResponse

from .cmdb import CMDB


def create_app(db_path: Path | str) -> FastAPI:
    app = FastAPI(title="infra-discovery", version="0.1.0")
    cmdb = CMDB(db_path)

    @app.get("/", response_class=HTMLResponse)
    def index() -> str:
        return files("infra_discovery").joinpath("graph.html").read_text()

    @app.get("/hosts")
    def hosts() -> list[dict[str, Any]]:
        return [{"name": n.host, "key": n.key, **n.attrs} for n in cmdb.nodes("host")]

    @app.get("/graph")
    def graph() -> dict[str, Any]:
        return {
            "nodes": [{"key": n.key, "kind": n.kind, "host": n.host, "attrs": n.attrs} for n in cmdb.nodes()],
            "edges": [{"src": e.src, "kind": e.kind, "dst": e.dst} for e in cmdb.edges()],
        }

    @app.get("/scans")
    def scans() -> list[dict[str, Any]]:
        return cmdb.scans()

    @app.get("/diff")
    def diff(from_scan: int | None = None, to_scan: int | None = None) -> list[dict[str, Any]]:
        return [c.as_dict() for c in cmdb.diff(from_scan, to_scan)]

    return app
