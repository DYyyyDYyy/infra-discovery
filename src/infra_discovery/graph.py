"""Build a CMDB graph (nodes + relationships) from per-host inventories.

Node keys are stable identities, so repeated scans map onto the same nodes:
``host:web``, ``software:web/nginx``, ``process:web/nginx``, ``listener:web/tcp/80``.
Volatile data (pids, ephemeral ports) never goes into keys or attributes.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .models import Inventory, Process


@dataclass(frozen=True)
class Node:
    key: str
    kind: str
    host: str
    attrs: dict[str, str]


@dataclass(frozen=True, order=True)
class Edge:
    src: str
    kind: str
    dst: str
    host: str = field(compare=False, default="")

    @property
    def key(self) -> str:
        return f"{self.src} -{self.kind}-> {self.dst}"


@dataclass
class Graph:
    nodes: dict[str, Node] = field(default_factory=dict)
    edges: dict[str, Edge] = field(default_factory=dict)

    def add_node(self, node: Node) -> None:
        self.nodes[node.key] = node

    def add_edge(self, src: str, kind: str, dst: str, host: str) -> None:
        e = Edge(src, kind, dst, host)
        self.edges[e.key] = e


def _main_process(procs: list[Process], name: str) -> Process | None:
    matching = [p for p in procs if p.name == name]
    return min(matching, key=lambda p: p.pid) if matching else None


def build_graph(inventories: list[Inventory]) -> Graph:
    g = Graph()
    ip_owner: dict[str, str] = {}
    # (host, port) -> node that owns the listening socket
    port_owner: dict[tuple[str, int], str] = {}
    # (host, process name) -> software key
    proc_software: dict[tuple[str, str], str] = {}
    # (host, well-known port) -> software key; fallback when ss cannot see the owning process
    port_software: dict[tuple[str, int], str] = {}

    for inv in inventories:
        h = inv.host
        hkey = f"host:{h.name}"
        g.add_node(Node(hkey, "host", h.name, {**h.attrs, "ips": ",".join(sorted(h.ips)), "target": h.target}))
        for ip in h.ips:
            ip_owner[ip] = h.name

        for sw in inv.software:
            skey = f"software:{h.name}/{sw.name}"
            attrs = {**sw.attrs, "name": sw.name}
            if sw.version:
                attrs["version"] = sw.version
            g.add_node(Node(skey, "software", h.name, attrs))
            g.add_edge(hkey, "runs", skey, h.name)
            for p in sw.attrs.get("ports", "").split(","):
                if p.strip().isdigit():
                    port_software[(h.name, int(p))] = skey
            if sw.process:
                proc_software[(h.name, sw.process)] = skey
                proc = _main_process(inv.processes, sw.process)
                if proc:
                    pkey = f"process:{h.name}/{proc.name}"
                    g.add_node(Node(pkey, "process", h.name, {"user": proc.user, "cmd": proc.cmd}))
                    g.add_edge(skey, "has_process", pkey, h.name)

        by_port: dict[int, list[str]] = {}
        procs: dict[int, str | None] = {}
        for lst in inv.listeners:
            if lst.address.startswith("127.") or lst.address == "::1":
                continue  # loopback-only services are not reachable dependencies
            by_port.setdefault(lst.port, []).append(lst.address)
            procs[lst.port] = procs.get(lst.port) or lst.process
        for port, addrs in sorted(by_port.items()):
            lkey = f"listener:{h.name}/tcp/{port}"
            proc_name = procs[port]
            attrs = {"port": str(port), "addresses": ",".join(sorted(set(addrs)))}
            if proc_name:
                attrs["process"] = proc_name
            g.add_node(Node(lkey, "listener", h.name, attrs))
            owner = proc_software.get((h.name, proc_name or "")) or port_software.get((h.name, port), hkey)
            g.add_edge(owner, "listens_on", lkey, h.name)
            port_owner[(h.name, port)] = owner if owner != hkey else lkey

    # client -> server, from established TCP connections that land on a known listener
    for inv in inventories:
        name = inv.host.name
        for c in inv.connections:
            server_host = ip_owner.get(c.peer_ip)
            if server_host is None or server_host == name:
                continue
            server = port_owner.get((server_host, c.peer_port))
            if server is None:
                continue
            client = proc_software.get((name, c.process or ""), f"host:{name}")
            g.add_edge(client, "connects_to", server, name)
    return g


def to_mermaid(nodes: list[Node], edges: list[Edge]) -> str:
    ids = {n.key: f"n{i}" for i, n in enumerate(sorted(nodes, key=lambda n: n.key))}
    lines = ["graph LR"]
    for n in sorted(nodes, key=lambda n: n.key):
        label = n.key.split(":", 1)[1]
        if n.kind == "host":
            label += f"<br/>{n.attrs.get('os_name', '')} {n.attrs.get('os_version', '')}".rstrip()
        elif n.kind == "software" and "version" in n.attrs:
            label += f" {n.attrs['version']}"
        shape = {"host": ('[["', '"]]'), "software": ('("', '")'), "listener": ('>"', '"]')}.get(n.kind, ('["', '"]'))
        lines.append(f"  {ids[n.key]}{shape[0]}{label}{shape[1]}")
    for e in sorted(edges):
        if e.src in ids and e.dst in ids:
            arrow = "==>" if e.kind == "connects_to" else "-->"
            lines.append(f"  {ids[e.src]} {arrow}|{e.kind}| {ids[e.dst]}")
    return "\n".join(lines) + "\n"
